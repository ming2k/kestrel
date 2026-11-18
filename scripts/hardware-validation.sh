#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Hardware smoke test: kestrel-daemon against a real radio, the real
# wpa_supplicant (or iwd), and the system's systemd-networkd.
#
# DESTRUCTIVE: it takes the interface away from NetworkManager for the
# duration and restores it afterwards. Run it from a console or over a
# management path that does not use the interface under test.

set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/release"

usage() {
    cat <<'EOF'
Usage (as your normal user; sudo is used internally):

  KESTREL_HW_PSK='...' ./scripts/hardware-validation.sh \
      --interface wlp0s20f3 --ssid test-ap --security wpa-personal --yes

Options:
  -i, --interface NAME   wireless interface (required)
  -s, --ssid SSID        test network (required)
      --security MODE    open | owe | wpa-personal | wpa3-personal (default wpa-personal)
  -b, --backend NAME     wpa-supplicant | iwd (default wpa-supplicant)
      --artifacts DIR    where logs and evidence go (default: ./hw-artifacts-<time>)
      --keep-manager     do not stop NetworkManager (quick check only)
      --yes              confirm you understand the interface is taken over
EOF
}

IFACE= SSID= SECURITY=wpa-personal BACKEND=wpa-supplicant YES=0 KEEP=0
ARTIFACTS="$PWD/hw-artifacts-$(date +%Y%m%d-%H%M%S)"
while [ $# -gt 0 ]; do
    case "$1" in
        -i|--interface) IFACE=$2; shift 2 ;;
        -s|--ssid) SSID=$2; shift 2 ;;
        --security) SECURITY=$2; shift 2 ;;
        -b|--backend) BACKEND=$2; shift 2 ;;
        --artifacts) ARTIFACTS=$2; shift 2 ;;
        --keep-manager) KEEP=1; shift ;;
        --yes) YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
done
[ -n "$IFACE" ] && [ -n "$SSID" ] || { usage >&2; exit 2; }
[ "$YES" = 1 ] || { echo "refusing to run without --yes" >&2; exit 2; }
case "$SECURITY" in open|owe) ;; *) [ -n "${KESTREL_HW_PSK:-}" ] || { echo "set KESTREL_HW_PSK" >&2; exit 2; } ;; esac
[ -e "/sys/class/net/$IFACE/wireless" ] || { echo "$IFACE is not a wireless interface" >&2; exit 2; }
[ -f /usr/share/dbus-1/system.d/com.hihusky.Kestrel.conf ] || [ -f /etc/dbus-1/system.d/com.hihusky.Kestrel.conf ] || {
    echo "install data/com.hihusky.Kestrel.conf to /usr/share/dbus-1/system.d/ and reload dbus first" >&2
    exit 2
}
sudo test -e /var/lib/systemd/credential.secret || { echo "run 'sudo systemd-creds setup' first" >&2; exit 2; }
systemctl is-active --quiet kestrel 2>/dev/null && { echo "stop kestrel.service first" >&2; exit 2; }
systemctl is-active --quiet systemd-networkd || { echo "systemd-networkd must be running" >&2; exit 2; }

mkdir -p "$ARTIFACTS"
STATE=$(sudo mktemp -d /run/kestrel-hw.XXXXXX)
cargo build --release -p kestrel-daemon -p kestrel-cli
NM_WAS_ACTIVE=0
systemctl is-active --quiet NetworkManager 2>/dev/null && NM_WAS_ACTIVE=1

restore() {
    set +e
    echo "== restoring"
    [ -n "${DAEMON_PID:-}" ] && sudo kill -TERM "$DAEMON_PID" && wait "$DAEMON_PID"
    sudo chown -R "$(id -u):$(id -g)" "$ARTIFACTS"
    ls /run/systemd/network/10-kestrel-* >/dev/null 2>&1 && echo "LEAK: Kestrel units left behind" | tee -a "$ARTIFACTS/result.txt"
    sudo rm -rf "$STATE"
    [ "$KEEP" = 1 ] || [ "$NM_WAS_ACTIVE" = 0 ] || sudo systemctl start NetworkManager 2>/dev/null
}
trap restore EXIT

[ "$KEEP" = 1 ] || [ "$NM_WAS_ACTIVE" = 0 ] || sudo systemctl stop NetworkManager 2>/dev/null || true
cat > "$ARTIFACTS/kestrel.toml" <<EOF
[wireless]
backend = "$BACKEND"
[storage]
profiles = "$STATE/profiles"
secrets = "$STATE/secrets"
certs = "$STATE/certs"
p2p_groups = "$STATE/p2p-groups"
history = "$STATE/history.jsonl"
state = "$STATE/state.toml"
EOF

echo "== starting kestrel-daemon"
sudo env KESTREL_LOG=debug "$BIN/kestrel-daemon" --config "$ARTIFACTS/kestrel.toml" >"$ARTIFACTS/kestrel-daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 100); do
    grep -q ' ready' "$ARTIFACTS/kestrel-daemon.log" && break
    sudo kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.1
done
grep -q ' ready' "$ARTIFACTS/kestrel-daemon.log" || {
    echo "FAIL: kestrel-daemon did not become ready" | tee "$ARTIFACTS/result.txt"
    cat "$ARTIFACTS/kestrel-daemon.log" >&2
    exit 1
}
CTL="sudo $BIN/kestrel"

echo "== profile"
case "$SECURITY" in
    open|owe)
        $CTL profile add --ssid "$SSID" --security "$SECURITY"
        ;;
    *)
        printf '%s\n' "$KESTREL_HW_PSK" | $CTL profile add --ssid "$SSID" --security "$SECURITY" --secret-stdin
        ;;
esac

echo "== waiting for connection (autoconnect)"
for _ in $(seq 60); do
    $CTL --json wifi status "$IFACE" | grep -q '"state": "connected"' && break
    sleep 1
done
$CTL status | tee "$ARTIFACTS/status-connected.txt"
networkctl status "$IFACE" --no-pager | tee "$ARTIFACTS/networkctl-connected.txt"
$CTL --json wifi status "$IFACE" | grep -q '"state": "connected"' || { echo "FAIL: not connected" | tee "$ARTIFACTS/result.txt"; exit 1; }

echo "== disconnect releases L3 and L2"
$CTL wifi disconnect "$IFACE"
sleep 3
networkctl status "$IFACE" --no-pager | tee "$ARTIFACTS/networkctl-released.txt"
ls /run/systemd/network/10-kestrel-"$IFACE".network 2>/dev/null && { echo "FAIL: unit not removed" | tee "$ARTIFACTS/result.txt"; exit 1; }

echo "== reconnect, then a graceful stop must leave nothing"
$CTL wifi connect "$IFACE" "$SSID"
for _ in $(seq 60); do $CTL --json wifi status "$IFACE" | grep -q '"state": "connected"' && break; sleep 1; done
$CTL --json wifi status "$IFACE" | grep -q '"state": "connected"' || { echo "FAIL: reconnect timed out" | tee "$ARTIFACTS/result.txt"; exit 1; }
sudo kill -TERM "$DAEMON_PID"; wait "$DAEMON_PID" || true; DAEMON_PID=
ls /run/systemd/network/10-kestrel-* >/dev/null 2>&1 && { echo "FAIL: units left after shutdown" | tee "$ARTIFACTS/result.txt"; exit 1; }
echo "PASS" | tee "$ARTIFACTS/result.txt"

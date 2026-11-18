#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Kernel-radio validation via mac80211_hwsim: runs real wpa_supplicant,
# kestrel-daemon, kestrel, and systemd-networkd across virtual kernel radios
# (SoftAP hotspot + station client association + DHCP + teardown cleanup).
#
# Usage:
#   ./scripts/hwsim-validation.sh [--artifacts DIR] [--keep-manager]

set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/release"
ARTIFACTS="${ARTIFACTS:-$PWD/hwsim-artifacts-$(date +%Y%m%d-%H%M%S)}"
KEEP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --artifacts) ARTIFACTS="$2"; shift 2 ;;
        --keep-manager|--keep-nm) KEEP=1; shift ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

command -v wpa_supplicant >/dev/null || { echo "wpa_supplicant is required" >&2; exit 2; }
command -v iw >/dev/null || { echo "iw is required" >&2; exit 2; }
modinfo mac80211_hwsim >/dev/null 2>&1 || { echo "mac80211_hwsim kernel module not available" >&2; exit 2; }
[ -f /usr/share/dbus-1/system.d/com.hihusky.Kestrel.conf ] || [ -f /etc/dbus-1/system.d/com.hihusky.Kestrel.conf ] || {
    echo "install data/com.hihusky.Kestrel.conf to /usr/share/dbus-1/system.d/ and reload dbus first" >&2
    exit 2
}
sudo test -e /var/lib/systemd/credential.secret || { echo "run 'sudo systemd-creds setup' first" >&2; exit 2; }
systemctl is-active --quiet kestrel 2>/dev/null && { echo "stop kestrel.service first" >&2; exit 2; }
systemctl is-active --quiet systemd-networkd || { echo "systemd-networkd must be running" >&2; exit 2; }

mkdir -p "$ARTIFACTS"
STATE=$(sudo mktemp -d /run/kestrel-hwsim.XXXXXX)
(cd "$ROOT" && cargo build --release -p kestrel-daemon -p kestrel-cli)

NM_WAS_ACTIVE=0
systemctl is-active --quiet NetworkManager 2>/dev/null && NM_WAS_ACTIVE=1
LOADED_HWSIM=0
DAEMON_PID=""

cleanup() {
    set +e
    [ -n "$DAEMON_PID" ] && sudo kill -TERM "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
    [ "$LOADED_HWSIM" = 1 ] && sudo modprobe -r mac80211_hwsim 2>/dev/null
    sudo chown -R "$(id -u):$(id -g)" "$ARTIFACTS" 2>/dev/null || true
    if ls /run/systemd/network/10-kestrel-* >/dev/null 2>&1; then
        echo "LEAK: Kestrel units left behind" | tee -a "$ARTIFACTS/result.txt"
    fi
    sudo rm -rf "$STATE"
    [ "$KEEP" = 1 ] || [ "$NM_WAS_ACTIVE" = 0 ] || sudo systemctl start NetworkManager 2>/dev/null || true
}
trap cleanup EXIT

[ "$KEEP" = 1 ] || [ "$NM_WAS_ACTIVE" = 0 ] || sudo systemctl stop NetworkManager 2>/dev/null || true

if ! lsmod | grep -q '^mac80211_hwsim'; then
    sudo modprobe mac80211_hwsim radios=2
    LOADED_HWSIM=1
fi

mapfile -t RADIOS < <(for d in /sys/class/ieee80211/*; do
    if grep -q hwsim "$d/device/modalias" 2>/dev/null || readlink -f "$d/device/driver" 2>/dev/null | grep -q mac80211_hwsim; then
        ls "$d/device/net" 2>/dev/null | head -n1
    fi
done)

if [ "${#RADIOS[@]}" -lt 2 ]; then
    echo "expected at least 2 mac80211_hwsim interfaces, found: ${RADIOS[*]}" >&2
    exit 1
fi
AP_IF="${RADIOS[0]}"
STA_IF="${RADIOS[1]}"
echo "Using kernel hwsim interfaces: AP=$AP_IF STA=$STA_IF" | tee "$ARTIFACTS/radios.txt"

cat > "$ARTIFACTS/kestrel.toml" <<EOF
[wireless]
backend = "wpa-supplicant"
enabled = true

[l3]
backend = "networkd"

[storage]
profiles = "$STATE/profiles"
secrets = "$STATE/secrets"
certs = "$STATE/certs"
p2p_groups = "$STATE/p2p-groups"
history = "$STATE/history.jsonl"
state = "$STATE/state.toml"
secret_backend = "systemd-creds"
EOF

sudo env KESTREL_LOG=debug "$BIN/kestrel-daemon" --config "$ARTIFACTS/kestrel.toml" >"$ARTIFACTS/kestrel-daemon.log" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 30); do
    grep -q ' ready' "$ARTIFACTS/kestrel-daemon.log" && break
    sudo kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.5
done
grep -q ' ready' "$ARTIFACTS/kestrel-daemon.log" || {
    echo "FAIL: kestrel-daemon did not become ready" | tee "$ARTIFACTS/result.txt"
    exit 1
}

CTL="sudo $BIN/kestrel"
$CTL status | tee "$ARTIFACTS/status-initial.txt"

printf 'hwsim-hotspot-passphrase\n' | $CTL hotspot start "$AP_IF" \
    --ssid kestrel-hwsim-ap --security wpa-personal --secret-stdin

for _ in $(seq 30); do
    $CTL --json hotspot status "$AP_IF" | grep -q '"state": "active"' && break
    sleep 0.5
done
$CTL hotspot status "$AP_IF" | tee "$ARTIFACTS/hotspot-active.txt"
$CTL --json hotspot status "$AP_IF" | grep -q '"state": "active"' || {
    echo "FAIL: hotspot did not become active" | tee "$ARTIFACTS/result.txt"
    exit 1
}

echo "== associating station $STA_IF to hotspot on $AP_IF"
printf 'hwsim-hotspot-passphrase\n' | $CTL wifi join "$STA_IF" kestrel-hwsim-ap \
    --security wpa-personal --secret-stdin --timeout 30 | tee "$ARTIFACTS/sta-joined.txt"
$CTL --json wifi status "$STA_IF" | tee "$ARTIFACTS/sta-status.json" | grep -q '"state": "connected"' || {
    echo "FAIL: station did not connect to hwsim hotspot" | tee "$ARTIFACTS/result.txt"
    exit 1
}
$CTL --json wifi status "$STA_IF" | grep -q '"192\.168\.49\.' || {
    echo "FAIL: station did not receive a DHCP lease from hwsim hotspot" | tee "$ARTIFACTS/result.txt"
    exit 1
}

$CTL wifi disconnect "$STA_IF"
$CTL hotspot stop "$AP_IF"
for _ in $(seq 30); do
    $CTL --json hotspot status "$AP_IF" | grep -q '"state": "stopped"' && break
    sleep 0.5
done
$CTL --json hotspot status "$AP_IF" | grep -q '"state": "stopped"' || {
    echo "FAIL: hotspot did not stop cleanly" | tee "$ARTIFACTS/result.txt"
    exit 1
}

sudo kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || true
DAEMON_PID=""

if ls /run/systemd/network/10-kestrel-* >/dev/null 2>&1; then
    echo "FAIL: units left after shutdown" | tee "$ARTIFACTS/result.txt"
    exit 1
fi

echo "PASS" | tee "$ARTIFACTS/result.txt"

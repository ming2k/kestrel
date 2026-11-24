#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Validates the files in data/ against the real tools, without root:
#   - the unit passes systemd-analyze verify and keeps its exposure score;
#   - the D-Bus policy loads into a dbus-daemon running the stock system
#     configuration, and denies the name to non-root;
#   - the polkit policy and D-Bus XML are well-formed;
#   - the tmpfiles snippet is accepted;
#   - kestrel-daemon runs under the unit's sandbox (every option a user manager
#     can apply), stores a secret, connects, and stops cleanly.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
WORK=$(mktemp -d /tmp/kestrel-check.XXXXXX)
chmod 700 "$WORK"
BUSPID= SYSBUS_PID= FAKE=
cleanup() {
    [ -n "$FAKE" ] && kill "$FAKE" 2>/dev/null || true
    [ -n "$BUSPID" ] && kill "$BUSPID" 2>/dev/null || true
    [ -n "$SYSBUS_PID" ] && kill "$SYSBUS_PID" 2>/dev/null || true
    systemctl --user stop kestrel-sandbox-check.service 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "check-system-files: $*" >&2; exit 1; }

cargo build -q -p kestrel-daemon -p kestrel-cli -p kestrel-e2e --bins
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug"

echo "== unit"
sed "s#/usr/libexec/kestrel-daemon#$BIN/kestrel-daemon#" data/kestrel.service > "$WORK/kestrel.service"
out=$(systemd-analyze verify "$WORK/kestrel.service" 2>&1) || fail "verify: $out"
[ -z "$out" ] || fail "verify: $out"
score=$(systemd-analyze security --offline=true "$WORK/kestrel.service" 2>/dev/null \
    | sed -n 's/.*Overall exposure level for kestrel.service: \([0-9.]*\).*/\1/p')
echo "exposure $score"
awk "BEGIN { exit !($score <= 1.5) }" || fail "exposure regressed to $score (budget 1.5)"

echo "== tmpfiles"
systemd-tmpfiles --dry-run --create data/kestrel.tmpfiles.conf >/dev/null

echo "== XML"
xmllint --noout --nonet data/com.hihusky.Kestrel.conf data/com.hihusky.kestrel.policy

echo "== D-Bus activation service"
grep -qx 'Name=com.hihusky.Kestrel' data/com.hihusky.Kestrel.service \
    || fail "com.hihusky.Kestrel.service has wrong Name="
dbus_svc=$(sed -n 's/^SystemdService=//p' data/com.hihusky.Kestrel.service)
unit_alias=$(sed -n 's/^Alias=//p' data/kestrel.service)
[ -n "$dbus_svc" ] && [ "$dbus_svc" = "$unit_alias" ] \
    || fail "D-Bus SystemdService ($dbus_svc) does not match kestrel.service Alias ($unit_alias)"

echo "== D-Bus policy under the stock system configuration"
mkdir "$WORK/system.d"
cp data/com.hihusky.Kestrel.conf "$WORK/system.d/"
sed -e "s#<listen>.*</listen>#<listen>unix:path=$WORK/system_bus</listen>#" \
    -e "s#<includedir>system.d</includedir>#<includedir>$WORK/system.d</includedir>#" \
    -e '/<user>/d' -e '/<pidfile>/d' -e '/servicehelper/d' \
    -e '/standard_system_servicedirs/d' -e '/<includedir>\/etc/d' \
    /usr/share/dbus-1/system.conf > "$WORK/system.conf"
dbus-daemon --config-file="$WORK/system.conf" --fork --print-pid=1 > "$WORK/system.pid" 2>"$WORK/system.err" \
    || fail "dbus-daemon rejected the policy: $(cat "$WORK/system.err")"
SYSBUS_PID=$(cat "$WORK/system.pid")
if busctl --address="unix:path=$WORK/system_bus" call org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus RequestName su com.hihusky.Kestrel 0 >/dev/null 2>&1; then
    fail "a non-root user could own com.hihusky.Kestrel"
fi
# Verify the default policy never grants wildcard send_destination and
# explicitly denies the internal iwd agent interface.
if xmllint --xpath '//policy[@context="default"]/allow[@send_destination="com.hihusky.Kestrel" and not(@send_interface)]' \
    data/com.hihusky.Kestrel.conf >/dev/null 2>&1; then
    fail "default D-Bus policy must not grant wildcard send_destination"
fi
xmllint --xpath '//policy[@context="default"]/deny[@send_destination="com.hihusky.Kestrel" and @send_interface="net.connman.iwd.Agent"]' \
    data/com.hihusky.Kestrel.conf >/dev/null 2>&1 \
    || fail "default D-Bus policy must deny net.connman.iwd.Agent"
kill "$SYSBUS_PID" 2>/dev/null || true
SYSBUS_PID=

echo "== sandboxed run"
case "$(systemctl --user is-system-running 2>/dev/null || true)" in
    running|degraded) ;;
    *) echo "skipped: no user service manager"; exit 0 ;;
esac
dbus-daemon --session --fork --print-address=1 --print-pid=1 > "$WORK/bus"
ADDRESS=$(sed -n 1p "$WORK/bus")
BUSPID=$(sed -n 2p "$WORK/bus")
"$BIN/kestrel-fake-wpa" "$ADDRESS" wlan0 > "$WORK/fake.out" 2>&1 &
FAKE=$!
i=0
until grep -q ready "$WORK/fake.out" 2>/dev/null; do
    kill -0 "$FAKE" 2>/dev/null || fail "kestrel-fake-wpa exited early: $(cat "$WORK/fake.out")"
    i=$((i + 1)); [ $i -lt 100 ] || fail "kestrel-fake-wpa timed out"
    sleep 0.1
done
busctl --address="$ADDRESS" call fi.w1.wpa_supplicant1 /com/hihusky/Kestrel/testing \
    com.hihusky.Kestrel.Testing.FakeWpa AddAccessPoint sss home "correct horse battery" wpa2
cat > "$WORK/kestrel.toml" <<EOF
[wireless]
backend = "wpa-supplicant"
[l3]
backend = "none"
[storage]
profiles = "$WORK/profiles"
secrets = "$WORK/secrets"
certs = "$WORK/certs"
p2p_groups = "$WORK/p2p-groups"
history = "$WORK/history.jsonl"
state = "$WORK/state.toml"
secret_backend = "systemd-creds-user"
[api]
authorization = "bus-policy"
EOF
# Every option of data/kestrel.service that an unprivileged user manager
# can enforce. (Capability, device, mount, and IP-firewall options need a
# system manager; systemd-analyze above covers their syntax.)
for key in Type NotifyAccess WatchdogSec UMask NoNewPrivileges RestrictAddressFamilies \
    RestrictNamespaces RestrictRealtime RestrictSUIDSGID LockPersonality \
    MemoryDenyWriteExecute SystemCallArchitectures SystemCallFilter \
    SystemCallErrorNumber ProtectProc RemoveIPC; do
    grep "^$key=" data/kestrel.service > "$WORK/$key.props"
done
set --
for file in "$WORK"/*.props; do
    while IFS= read -r line; do set -- "$@" -p "$line"; done < "$file"
done
systemd-run --user --unit=kestrel-sandbox-check --collect -q "$@" \
    "$BIN/kestrel-daemon" --bus "$ADDRESS" --config "$WORK/kestrel.toml"
CTL="$BIN/kestrel --bus $ADDRESS"
printf 'correct horse battery\n' | $CTL profile add home --security wpa-personal \
    --l3 unmanaged --secret-stdin >/dev/null
i=0
until $CTL --json status | grep -q '"state": "connected"'; do
    i=$((i + 1)); [ $i -lt 80 ] || fail "sandboxed kestrel-daemon did not connect"
    sleep 0.25
done
grep -q horse "$WORK"/secrets/*.cred && fail "secret stored in plaintext"
systemctl --user stop kestrel-sandbox-check.service
journalctl --user -u kestrel-sandbox-check --no-pager -o cat | grep -q 'stopped cleanly' \
    || fail "sandboxed kestrel-daemon did not stop cleanly"
echo "ok"

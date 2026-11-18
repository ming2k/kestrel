#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# End-to-end suite: real kestrel-daemon + kestrel + systemd-networkd in an
# unprivileged namespace, with a fake wpa_supplicant. No root needed.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

for tool in unshare nsenter dbus-daemon ip busctl networkctl systemd-creds; do
    command -v "$tool" >/dev/null || { echo "e2e: missing $tool" >&2; exit 1; }
done
[ -x /usr/lib/systemd/systemd-networkd ] || { echo "e2e: missing systemd-networkd" >&2; exit 1; }
id systemd-network >/dev/null 2>&1 || { echo "e2e: missing the systemd-network user" >&2; exit 1; }
grep -q "^$(id -un):" /etc/subuid || { echo "e2e: no subordinate UIDs for $(id -un) in /etc/subuid" >&2; exit 1; }

cargo build -p kestrel-daemon -p kestrel-cli -p kestrel-e2e --bins
KESTREL_BIN_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/debug" KESTREL_E2E=1 cargo test -p kestrel-e2e -- --test-threads=1 "$@"
KESTREL_BIN_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/debug" KESTREL_E2E=1 cargo test -p kestrel-tests --test e2e -- --test-threads=1 "$@"

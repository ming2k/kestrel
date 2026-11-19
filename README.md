# Kestrel

Kestrel is a lightweight **control-plane orchestrator** for Linux wireless
networking. It sits between the system's network daemons and whatever wants
to drive them: a desktop shell, a settings panel, a casting service, a CLI.

- It is **not** a network manager. It never assigns addresses, runs DHCP,
  edits routes, or writes resolver configuration. It declares what a link
  should be, and **systemd-networkd** (with systemd-resolved) does it.
- It is **backend-agnostic**. `wpa_supplicant` and iwd are swappable L2
  providers, and networkd is one L3 provider behind a port. Each daemon is a
  stateless executor.
- It **owns its state**: saved networks, priorities, autoconnect policy,
  credentials (encrypted at rest with `systemd-creds`), and a bounded
  connection history.
- It **orchestrates Wi-Fi Direct** end to end: discovery, WPS, GO
  negotiation or an autonomous group, and then L3 by the negotiated role.
  As Group Owner it serves a subnet with a DHCP server; as client it runs a
  DHCP client. On any exit it tears everything down. Groups can be saved and
  reconnected without WPS.
- It **runs a hotspot (SoftAP)** on an AP-capable device and hands the radio
  back to the station when it stops. L3 stays with networkd; there is no
  netlink socket, no NAT code, and no capability.
- It **handles 802.1X**: public certificates are imported into its own
  store, private keys are sealed with `systemd-creds`, and
  `wpa_supplicant` receives them as in-memory blobs.

Status: **v0.0.2.** Station, P2P, SoftAP, and 802.1X paths are implemented
and tested end to end against the real systemd-networkd. Real-radio
validation is the open gate: see
[docs/hardware-validation.md](docs/hardware-validation.md).

## Layout

| Crate | Role |
|---|---|
| `kestrel-model` | Validated value types: SSIDs, profiles, secrets (zeroized, redacted), P2P types, certificates, enterprise EAP, hotspot, failure codes. No I/O. |
| `kestrel-machines` | Pure sans-IO state machines (station + candidate policy, P2P session, hotspot). No async, no I/O. |
| `kestrel-ports` | Southbound and northbound traits: `WlanProvider`, `P2pProvider`, `ApProvider`, `L3Provider`, `Agent`, `ProfileRepository`, `SecretStore`, `CertStore`, `P2pGroupStore`, `HistoryStore`, `StateStore`. |
| `kestrel-catalog` | Persisted profile, credential, certificate, persistent P2P group, and history catalog with referential integrity and events. |
| `kestrel-controller` | Live radio controller: drives `kestrel-machines` against ports and catalog, allocates shared L3 subnets, runs per-entity FIFO executors, and sweeps leftovers at start and stop. |
| `kestrel-store` | Profile, certificate, and persistent-group directories (atomic, 0600) and the `systemd-creds` secret store. |
| `kestrel-wlan-wpa` | `wpa_supplicant` adapter (station, P2P, SoftAP, 802.1X blobs; signal-driven), plus a fake for tests. |
| `kestrel-wlan-iwd` | iwd adapter (station and AP mode), plus a fake for tests. |
| `kestrel-l3-networkd` | systemd-networkd adapter: runtime `.network` units plus `Reload`/`ReconfigureLink`/`Describe`. |
| `kestrel-api` | `com.hihusky.Kestrel` D-Bus server (ObjectManager, polkit, agents) and typed client. |
| `kestrel-daemon` | `kestrel-daemon`: settings and composition root. |
| `kestrel-cli` | `kestrel`: a task-oriented consumer of the public API. |
| `kestrel-testkit` | In-memory fakes of every port. |
| `kestrel-e2e` | Lab: real `kestrel-daemon`, `kestrel`, and systemd-networkd in an unprivileged namespace. |
| `kestrel-tests` (`tests/`) | Workspace-level CLI, API, and multi-subsystem integration suites. |

## Documentation

Start at the **[Documentation Hub](docs/index.md)**, or jump directly to a section:

- **[Getting Started](docs/tutorials/getting-started.md)**: build Kestrel, verify with the unprivileged e2e lab, install system files, and join your first Wi-Fi network.
- **[How-To Guides](docs/how-to/index.md)**:
  - [Install, Switch Backends, and Uninstall](docs/how-to/install-and-migrate.md) (systemd, `wpa_supplicant`/`iwd`, NetworkManager migration, `.network.d/` drop-ins, rollback)
  - [Wi-Fi and Network Profiles](docs/how-to/wifi-and-profiles.md) (daily Wi-Fi, priorities, static IP/DNS, unmanaged L3)
  - [802.1X Enterprise Wi-Fi and Certificates](docs/how-to/enterprise-8021x.md) (PEAP, TTLS, EAP-TLS, EAP-PWD, certificate store)
  - [Run a Hotspot (SoftAP)](docs/how-to/hotspot.md)
  - [Wi-Fi Direct (P2P) and Miracast](docs/how-to/p2p-and-miracast.md)
  - [Scripting, Agents, and Polkit](docs/how-to/scripting-and-agents.md)
  - [Troubleshooting](docs/how-to/troubleshooting.md)
- **[Reference](docs/reference/index.md)**: [CLI & Daemon Commands](docs/reference/commands.md), [Configuration & Storage](docs/reference/configuration.md), [Failures, Errors, and Capabilities](docs/reference/failures-and-errors.md), [State Model](docs/reference/state-model.md), and [D-Bus API](docs/dbus-api.md).
- **[Explanation](docs/explanation/index.md)**: [Architecture Overview](docs/explanation/architecture-overview.md), [Ownership & Crash Safety](docs/explanation/ownership-and-crash-safety.md), and [Power & rfkill](docs/explanation/power-and-rfkill.md).
- **[Architecture & ADRs](ARCHITECTURE.md)**: system design, [Roadmap](ROADMAP.md), and [Architecture Decision Records](docs/adr/README.md).
- **[Contributor Docs](docs/dev/subsystems.md)**: [Subsystem Architecture](docs/dev/subsystems.md), [Build & Run](docs/dev/build-and-run.md), [Testing](docs/dev/testing.md), and [Hardware Validation](docs/hardware-validation.md).

## Build and test

```sh
cargo build
cargo test --workspace --all-features     # unit, property, adapter, API tests
./crates/kestrel-e2e/run.sh               # end to end against real systemd-networkd
./scripts/check-system-files.sh           # data/ files against real systemd and dbus tools
```

The e2e lab needs `unshare --map-auto` (subordinate IDs for your user),
`nsenter`, `dbus-daemon`, `iproute2`, systemd-networkd with its
`systemd-network` user, and `systemd-creds --user`. It needs no root.

## Install

Build and install the binaries, systemd unit, tmpfiles snippet, D-Bus and
polkit policies, example configuration, and documentation with `Makefile`
(honors `PREFIX` and `DESTDIR`):

```sh
make build
sudo make install
sudo systemd-tmpfiles --create kestrel.conf   # /run/systemd/network
sudo systemd-creds setup                      # credential host key, once
sudo systemctl reload dbus
sudo systemctl enable --now kestrel           # also enables D-Bus activation
```

Prerequisites (see [Install, Switch Backends, and Uninstall](docs/how-to/install-and-migrate.md) for full details and rollback):
- `kestrel.service` declares `Conflicts=NetworkManager.service connman.service`; disable them before enabling Kestrel.
- `systemd-networkd` and `systemd-resolved` running.
- Either `wpa_supplicant` with D-Bus control (`wpa_supplicant -u`) and no saved networks, or `iwd` with `EnableNetworkConfiguration=false`.
- Optional administrator `.network.d/` drop-ins for `<link>` go in `/etc/systemd/network/10-kestrel-<link>.network.d/*.conf`.

The unit runs `kestrel-daemon` as root with **no capabilities**, a syscall
allow-list, `AF_UNIX` sockets only, and a read-only system except
`/var/lib/kestrel` and `/run/systemd/network`. `systemd-analyze security`
rates its exposure 1.3. `scripts/check-system-files.sh`
re-verifies every file in `data/` and runs the daemon inside the unit's
sandbox.

## Use

```sh
kestrel status
kestrel wifi status wlp0s20f3
kestrel wifi scan wlp0s20f3

# Join a network: scan, infer security, prompt for the passphrase,
# create or update the profile, connect, and wait for an address.
kestrel wifi join wlp0s20f3 home

# Later, connect to a saved profile (id, name, or SSID).
kestrel wifi connect wlp0s20f3 home

# Autoconnect state and recent history.
kestrel wifi autoconnect wlp0s20f3 off
kestrel wifi autoconnect wlp0s20f3 on
kestrel wifi history
kestrel wifi forget home

kestrel agent                          # answer prompts in this terminal
kestrel p2p find wlp0s20f3
kestrel p2p connect wlp0s20f3 02:11:22:33:44:55 --go-intent 15 --wait
kestrel p2p start-group wlp0s20f3 --frequency 2412 --wait   # autonomous GO
kestrel p2p connect wlp0s20f3 02:11:22:33:44:55 --persistent --wait
kestrel p2p groups list                # saved groups, reconnect without WPS
kestrel p2p reconnect wlp0s20f3 <group> --peer 02:11:22:33:44:55 --wait
kestrel p2p sessions

kestrel hotspot start wlp0s20f3 --ssid kestrel-ap   # SoftAP; station hands over
kestrel hotspot status wlp0s20f3
kestrel hotspot stop wlp0s20f3

kestrel certificate add ./corp-ca.pem --name "Corp CA"   # 802.1X CA material
kestrel certificate list
```

`wlp0s20f3` is this host's interface; Kestrel discovers device names from the
backend, so replace it with yours (`iw dev`, `networkctl list`). An
autonomous group arms WPS push-button for one client; close it and start a
new group for another.

`wifi join` waits for `connected` by default; add `--no-wait` for scripts.
`--json` is supported across `status`, `monitor` (NDJSON), `wifi`,
`profile`, `certificate`, `p2p`, and `hotspot` subcommands. Secrets and WPS
PINs are read from a no-echo prompt or from stdin (`--secret-stdin`,
`--pin-stdin`, `--private-key-password-stdin`), never from argv.
`kestrel-daemon` logs to stderr: plain lines under systemd (the journal
stamps them), coloured on a terminal. `KESTREL_LOG` sets the filter (default
`info`).

## License

LGPL-2.1-or-later. See [LICENSE](LICENSE).

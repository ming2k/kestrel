# Subsystem Architecture

This document maps the Kestrel Cargo workspace, crate boundaries, and extension points for contributors.

---

## 1. Crate Topology

The workspace in [`Cargo.toml`](../../Cargo.toml) contains 15 members (14 crates under `crates/` plus `tests`) organized in strict layers:

| Crate | Layer | Responsibility |
| :--- | :--- | :--- |
| `kestrel-model` | Domain | Validated value types (`Ssid`, `Profile`, `Secret`, P2P types, certificates, enterprise EAP, hotspot, failure codes). Zero I/O, zero async. |
| `kestrel-machines` | Domain | Pure sans-IO state machines (`Station` with `station::policy`, `P2pSession`, `Hotspot`). Depends only on `kestrel-model`. |
| `kestrel-ports` | Boundary | Southbound and interactive agent traits: `WlanProvider`, `P2pProvider`, `ApProvider`, `L3Provider`, `Agent`, `ProfileRepository`, `SecretStore`, `CertStore`, `P2pGroupStore`, `HistoryStore`, `StateStore`. |
| `kestrel-catalog` | Application | Persisted profile, secret, certificate, persistent P2P group, and history catalog enforcing referential integrity and emitting `CatalogEvent`s. |
| `kestrel-controller` | Application | Live radio coordinator, generic per-entity FIFO `Executor`, station/p2p/hotspot drivers, `SubnetAllocator`, startup/shutdown `sweep()`, and domain control handles (`StationControl`, `HotspotControl`, `P2pControl`, `RadioControl`). |
| `kestrel-store` | Adapter (Storage) | Atomic profile, certificate, and persistent-group directories (`0600` files in `0700` dirs), `history.jsonl`, `state.toml`, and the `systemd-creds` secret store. |
| `kestrel-wlan-wpa` | Adapter (L2/P2P/AP) | `wpa_supplicant` D-Bus adapter (`fi.w1.wpa_supplicant1`) for station, P2P, and SoftAP, plus a test fake. |
| `kestrel-wlan-iwd` | Adapter (L2/AP) | `iwd` D-Bus adapter (`net.connman.iwd`) for station and AP mode, plus a test fake. |
| `kestrel-l3-networkd` | Adapter (L3) | `systemd-networkd` adapter (`org.freedesktop.network1`): writes `/run/systemd/network/10-kestrel-<link>.network`, invokes `Reload`/`ReconfigureLink`/`Describe`. |
| `kestrel-api` | Northbound API | `com.hihusky.Kestrel` D-Bus server (`server` feature: `ObjectManager`, polkit, agent bridge) and typed client (`client` feature, default). |
| `kestrel-daemon` | Composition Root | `kestrel-daemon` binary: settings loading, `systemd-logind` sleep listener, `/sys/class/rfkill` watcher, backend wiring, `sd_notify`. |
| `kestrel-cli` | Client | `kestrel` binary: task-oriented CLI consuming `kestrel-api::client`. |
| `kestrel-testkit` | Test Support | In-memory fakes for every trait in `kestrel-ports`. |
| `kestrel-e2e` | Verification | Unprivileged namespace e2e lab running `kestrel-daemon`, `kestrel`, real `systemd-networkd`, and a fake `wpa_supplicant`. |
| `kestrel-tests` (`tests/`) | Verification | Workspace-level cross-crate integration and CLI-to-daemon end-to-end test suites. |

---

## 2. Dependency Rules (Red-Lines)

1. **No async or I/O in `kestrel-model` or `kestrel-machines`**: `kestrel-machines` depends solely on `kestrel-model` and contains only `handle(now, input) -> Vec<Command>` state machines.
2. **Catalog & controller isolation**: `kestrel-catalog` depends only on `kestrel-model` and `kestrel-ports`; `kestrel-controller` depends on `kestrel-machines`, `kestrel-catalog`, `kestrel-model`, and `kestrel-ports`, never on a concrete adapter crate.
3. **API isolation**: `kestrel-api` depends on `kestrel-controller`, `kestrel-catalog`, `kestrel-ports`, and `kestrel-model` (behind the `server` feature), never on `kestrel-machines` or a concrete adapter.
4. **Single composition root**: `kestrel-daemon` is the only crate that names concrete adapters (`kestrel-wlan-wpa`, `kestrel-wlan-iwd`, `kestrel-l3-networkd`, `kestrel-store`).
5. **Zero L3 competition**: No crate opens netlink sockets, implements DHCP, parses RAs, writes sysctls, or modifies `/etc/resolv.conf` ([ADR-0001](../adr/0001-control-plane-orchestrator-zero-l3.md)).
6. **Memory safety**: `unsafe_code = "forbid"` is enforced workspace-wide in [`Cargo.toml`](../../Cargo.toml).

---

## 3. Extension Points

- **New L2 or L3 backend**: Implement `WlanProvider` / `P2pProvider` / `ApProvider` or `L3Provider` in a new adapter crate and wire it in `kestrel-daemon`. `kestrel-machines`, `kestrel-catalog`, `kestrel-controller`, and `kestrel-api` require no changes.
- **New profile or metadata kind**: Add a `kestrel-ports` store trait and a `kestrel-store` implementation, then extend `kestrel-catalog` and the D-Bus server. The certificate and persistent-group stores are the worked examples.
- **Miracast / WFD**: `P2pDeviceConfig.wfd_subelements` advertises WFD Information Elements, and discovered peers expose theirs over D-Bus so a casting service can drive a P2P session and run RTSP over `PeerIp`.

For the full architectural rationale, see [`ARCHITECTURE.md`](../../ARCHITECTURE.md) and [`docs/explanation/architecture-overview.md`](../explanation/architecture-overview.md).

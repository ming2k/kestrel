# Testing & Verification

Kestrel uses a six-layer testing pyramid covering sans-IO logic, async runtime orchestration, D-Bus adapters, public API contracts, real `systemd-networkd` e2e namespaces, and physical hardware.

---

## 1. Automated Test Layers

| Layer | Crates / Location | Mechanism |
| :--- | :--- | :--- |
| **Model & Machines** | `kestrel-model`, `kestrel-machines` | Unit tests and `proptest` over random event sequences (512 station cases, 1,024 P2P session cases, 512 hotspot cases per run) asserting resource-release invariants. |
| **Catalog & Controller** | `kestrel-catalog`, `kestrel-controller` | Uses `kestrel-testkit` in-memory fakes with failure injection and paused `tokio::time`. |
| **Adapters** | `kestrel-wlan-wpa`, `kestrel-wlan-iwd`, `kestrel-l3-networkd` | Production adapters tested against fake D-Bus daemons on a private `dbus-daemon`; `networkd` JSON parsing tested against captures from systemd 261. |
| **API** | `kestrel-api` (`tests/dbus.rs`) | Real D-Bus server, typed client, and client-side agent on a private bus, plus mechanical verification that [`docs/dbus-api.md`](../dbus-api.md) matches every exported interface member. |
| **Workspace Integration** | `kestrel-tests` (`tests/`) | End-to-end CLI-to-D-Bus-to-controller integration suites over private `dbus-daemon` instances with both in-memory and real disk stores. |
| **System Files** | `scripts/check-system-files.sh` | Validates `data/` unit, tmpfiles, D-Bus, and polkit files with real systemd/D-Bus tools and runs `kestrel-daemon` inside the unit sandbox. |
| **E2E Lab** | `crates/kestrel-e2e/run.sh` | Unprivileged user/network/mount namespace running real `kestrel-daemon`, `kestrel`, **real `systemd-networkd`**, and a fake `wpa_supplicant` across DHCP leases, P2P GO/client, SoftAP handover, crash (`SIGKILL`) sweep, and clean shutdown. |

---

## 2. Running Tests

```sh
# Unit, property, adapter, and API tests
cargo test --workspace --all-features

# Validate systemd/D-Bus/polkit packaging files
./scripts/check-system-files.sh

# Run the unprivileged namespace end-to-end lab
./crates/kestrel-e2e/run.sh
```

---

## 3. Hardware Validation Gate

Real-radio validation cannot run in CI namespaces. Before releasing or marking hardware-dependent features complete, execute and record the physical matrix in [`docs/hardware-validation.md`](../hardware-validation.md) (assisted by `scripts/hardware-validation.sh`).

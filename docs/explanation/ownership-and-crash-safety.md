# Ownership and Crash Safety

If a wireless orchestrator crashes (`SIGKILL` / `kill -9`), it can leave behind temporary `systemd-networkd` units, active DHCP leases, or `wpa_supplicant` network blocks. Kestrel eliminates stale state without maintaining a separate on-disk ledger file.

---

## 1. Why No Ledger File?

A separate ledger file (recording which `.network` files or `wpa_supplicant` networks Kestrel created) introduces a second source of truth that can fall out of sync with the external daemons if a crash occurs mid-operation.

Instead, every resource Kestrel creates carries a **self-describing ownership tag** directly inside the external daemon's resource ([ADR-0002](../adr/0002-sans-io-machines-and-self-describing-ownership.md)):

| Backend | Ownership Tag | What `sweep()` Removes |
| :--- | :--- | :--- |
| `systemd-networkd` | Unit filename `10-kestrel-<link>.network` in `/run/systemd/network` | Every matching unit, followed by `Reload` and `ReconfigureLink`. |
| `wpa_supplicant` | Network block `id_str="kestrel"`, `blob://kestrel-*` blobs, P2P groups | Every tagged station/AP network block, every `blob://kestrel-*` 802.1X blob, every active P2P group interface, and `wpa_supplicant`'s internal persistent-group table. |
| `iwd` | `KnownNetwork.AutoConnect=false` (set by Kestrel) & AP device mode | Every Kestrel-tagged known network; stops any active AP and resets AP-mode devices back to `station`. |

---

## 2. Startup and Shutdown Sweeps

`kestrel-controller` invokes each adapter's `sweep()` at two points:
1. **At startup**, before any `Station`, `P2pSession`, or `Hotspot` machine is started. Any leftover configuration from a previous `kill -9` is cleaned up before orchestration begins.
2. **At graceful shutdown**, after every state machine has released its held resources in reverse acquisition order.

This ensures both clean exits and abrupt crashes converge to the same clean baseline.

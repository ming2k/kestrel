# Architecture Overview

Kestrel is a **control-plane orchestrator** for Linux wireless networking. Rather than competing with existing Linux networking daemons, it coordinates them across strict crate and process boundaries.

---

## 1. Zero L3 Competition

Traditional network managers combine Wi-Fi association, DHCPv4/v6 clients, router-advertisement parsing, routing table management, and `resolv.conf` generation in a single privileged process. On systems running `systemd-networkd` and `systemd-resolved`, a second L3 stack causes netlink races, split-brain DNS, and unnecessary privilege surface ([ADR-0001](../adr/0001-control-plane-orchestrator-zero-l3.md)).

Kestrel never opens netlink sockets, sends DHCP packets, or writes resolver configuration:
- **Southbound L2**: `wpa_supplicant` (`kestrel-wlan-wpa`) or `iwd` (`kestrel-wlan-iwd`) act as stateless L2 executors behind `WlanProvider`, `P2pProvider`, and `ApProvider` (SoftAP).
- **Southbound L3**: `kestrel-l3-networkd` translates an `L3Intent` (`DhcpClient`, `Static`, or `SharedSubnet`) into a runtime `.network` unit for `systemd-networkd` and reads link status back via `Describe()`.

Because `kestrel-daemon` delegates all packet and kernel work, `kestrel.service` runs with an empty capability set, `RestrictAddressFamilies=AF_UNIX`, and `IPAddressDeny=any`.

---

## 2. Layered Crate Topology

```text
   desktop shell · settings panel · casting service · kestrel
                         │  com.hihusky.Kestrel (D-Bus) / kestrel_api::client
┌────────────────────────▼──────────────────────────────────────────────┐
│ kestrel-api       ObjectManager tree, polkit, agent bridge             │
├────────────────────────┬───────────────────────────────────────────────┤
│ kestrel-controller     │ kestrel-catalog                               │
│ coordinator · drivers  │ profiles · secrets · certs · P2P groups ·     │
│ FIFO Executor · sweep  │ history (referential integrity + events)      │
├────────────────────────┤                                               │
│ kestrel-machines       │                                               │
│ Station · P2pSession · │                                               │
│ Hotspot   (sans-IO)    │                                               │
├────────────────────────┴────┬──────────────────────┬───────────────────┤
│ kestrel-ports  (traits)     │ kestrel-model        │ kestrel-store     │
└───────▲───────────▲─────────┴──────────────────────┴───────▲───────────┘
        │           │                                        │
 kestrel-wlan-wpa  kestrel-wlan-iwd   kestrel-l3-networkd    systemd-creds
```

- `kestrel-model` and `kestrel-machines` contain zero async and zero I/O.
- `kestrel-catalog` depends only on `kestrel-model` and `kestrel-ports`.
- `kestrel-controller` depends only on `kestrel-machines`, `kestrel-catalog`, `kestrel-model`, and `kestrel-ports` traits—never on a concrete adapter.
- `kestrel-api` depends on `kestrel-controller`, `kestrel-catalog`, `kestrel-ports`, and `kestrel-model`, never on `kestrel-machines` or concrete adapters.
- `kestrel-daemon` is the single composition root that wires concrete adapters together.

---

## 3. Sans-IO Machines + Ordered Executors

In `kestrel-controller`, one radio coordinator task owns all `Station`, `P2pSession`, and `Hotspot` state machines and never awaits I/O. Each device (shared by station and hotspot) and each P2P session has a dedicated `Executor` task that runs emitted commands strictly in order.

This design gives two guarantees ([ADR-0002](../adr/0002-sans-io-machines-and-self-describing-ownership.md)):
1. A slow or wedged backend on one interface never blocks another interface or D-Bus API responsiveness.
2. Teardown commands can never be reordered ahead of or behind setup commands.

See [`ARCHITECTURE.md`](../../ARCHITECTURE.md) for the complete architectural diagram and module summary.

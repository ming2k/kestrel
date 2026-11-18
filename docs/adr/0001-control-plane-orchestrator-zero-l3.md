# ADR 0001: Control-plane orchestrator with zero L3 competition

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

Traditional Linux network managers bundle wireless association, DHCPv4/v6 clients, router-advertisement parsing, route table manipulation, and resolver configuration into one privileged daemon. On systems that already run `systemd-networkd` and `systemd-resolved`, a second L3 implementation creates split-brain state, netlink races, and duplicated attack surface.

## Decision

1. **Kestrel is strictly a control-plane orchestrator.** No crate in this workspace opens a netlink socket, sends or parses DHCP/RA packets, modifies kernel routing tables, writes sysctls, or edits `/etc/resolv.conf`.
2. **L3 is declarative.** `kestrel-controller` expresses L3 requirements as an `L3Intent` (`DhcpClient`, `Static`, or `SharedSubnet`) on the `L3Provider` port. `kestrel-l3-networkd` renders runtime `.network` units into `/run/systemd/network`, triggers `Reload` and `ReconfigureLink`, and reads link readiness, addresses, gateways, DNS servers, DHCP leases, and `OnlineState` back from `systemd-networkd`'s `Describe()` JSON.
3. **L2 is backend-agnostic.** `wpa_supplicant` (`kestrel-wlan-wpa`) and `iwd` (`kestrel-wlan-iwd`) implement the `WlanProvider` (and optional `P2pProvider`) port as stateless executors. Kestrel owns all profile state, priorities, autoconnect policy, and `systemd-creds` encrypted secrets.
4. **Strict crate boundaries:**
   - `kestrel-model` and `kestrel-machines` have zero async runtime and zero I/O.
   - `kestrel-catalog` depends only on `kestrel-model` and `kestrel-ports`.
   - `kestrel-controller` depends only on `kestrel-machines`, `kestrel-catalog`, `kestrel-model`, and `kestrel-ports`.
   - `kestrel-api` depends on `kestrel-controller`, `kestrel-catalog`, `kestrel-ports`, and `kestrel-model` (when the `server` feature is enabled), never on `kestrel-machines` or a concrete adapter.
   - `kestrel-daemon` is the sole composition root.
   - `unsafe` is forbidden workspace-wide.

## Consequences

- `kestrel.service` runs with `CapabilityBoundingSet=`, `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, and `ProtectSystem=strict`, achieving a `systemd-analyze security` exposure score of 1.3.
- Wired interfaces, VPNs, bridges, bonds, and VLANs remain natively managed by `systemd-networkd` without interference.
- The entire stack (including real `systemd-networkd` DHCP client/server and crash recovery) runs deterministically in an unprivileged user/network/mount namespace (`kestrel-e2e`).

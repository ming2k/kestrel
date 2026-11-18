# ADR 0005: SoftAP / hotspot orchestration

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

Users and embedded appliances need a wireless Access Point (SoftAP / hotspot) mode that shares an uplink via NAT and serves DHCP/DNS to connected clients without breaking Kestrel's zero-L3-competition invariant or systemd sandbox (`CapabilityBoundingSet=`, `IPAddressDeny=any`). On a single wireless PHY, SoftAP also competes directly with station association and Wi-Fi Direct sessions for the underlying interface.

## Decision

1. **Sans-IO `Hotspot` state machine (`kestrel-machines`).**
   - `Hotspot` follows the same sans-IO pattern as `Station` and `P2pSession` (`Stopped -> Starting -> ConfiguringL3 -> Active`), recording held resources (`Ap`, `L3Binding`) and releasing them in strict reverse order on every exit path, verified by `proptest` invariants. The controller allocates and frees the `/24` subnet alongside `L3Binding`.
   - `StationInput::SetHotspotActive(bool)` cleanly disables station orchestration on a device while a hotspot owns the radio, preserving `autoconnect_held` and restoring station operation when the hotspot stops. Active P2P sessions and hotspot activation on the same device are mutually exclusive (`Busy`).
2. **`ApProvider` sub-port (`kestrel-ports`).**
   - `WlanProvider::ap(&self) -> Option<Arc<dyn ApProvider>>` exposes `start_ap`, `stop_ap`, and `ApEvent` (`Started`, `Stopped`, `Failed`, `ClientConnected`, `ClientDisconnected`).
   - `kestrel-wlan-wpa` implements `ApProvider` via `wpa_supplicant` `mode=2` network blocks tagged `id_str="kestrel"` and `StaAuthorized`/`StaDeauthorized` signals, detecting `ap` mode support from `Interface.Capabilities.Modes`.
   - `kestrel-wlan-iwd` implements `ApProvider` by toggling `net.connman.iwd.Device.Mode` between `"station"` and `"ap"` and calling `net.connman.iwd.AccessPoint.Start`/`Stop` without persisting `/var/lib/iwd/ap/` files. Device identity is anchored on `net.connman.iwd.Device` rather than `Station` so mode switches do not emit spurious `DeviceRemoved` events. Because `iwd`'s D-Bus `AccessPoint.Start(ssid, psk)` accepts WPA2-PSK only, `open` and `wpa3-personal` hotspot requests return `NotSupported` on `iwd`.
3. **L3 delegation via `SharedSubnet`.**
   - Hotspot binds `L3Intent::SharedSubnet { emit_router: true, masquerade: true }` on a conflict-free `/24` from `SubnetAllocator`, delegating DHCP serving, default router/DNS advertisement, and `IPMasquerade=ipv4` entirely to `systemd-networkd`.
4. **Northbound API (`com.hihusky.Kestrel.Hotspot`).**
   - Exported on AP-capable `Device` objects (`/com/hihusky/Kestrel/Device/<name>`), exposing `State`, `Ssid`, `Security`, `Frequency`, `Gateway`, `Leases`, `ConnectedClients`, `Failure`, `FailureDetail`, `Start(settings, secret)`, and `Stop()`, authorized by `com.hihusky.kestrel.hotspot`.

## Consequences

- Hotspot NAT and DHCP require zero netlink sockets, zero iptables/nftables code, and zero Linux capabilities in `kestrel-daemon`.
- SoftAP blocks left behind by a crash are automatically swept by `id_str="kestrel"` (`wpa_supplicant`), `Device.Mode = "station"` reset (`iwd`), and `10-kestrel-*.network` removal (`systemd-networkd`).

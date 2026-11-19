# Roadmap

Last updated: 2026-11-19

A milestone is done when its code, tests (unit, property, adapter, API, e2e
where applicable), and docs are complete. Anything that needs real radios is
marked **needs hardware** until [the hardware gate](docs/hardware-validation.md)
has been run with evidence kept.

## v0.0.2: D-Bus monitor resilience, wire-faithful wpa_supplicant, and user docs (done)

- Non-blocking D-Bus signal drain/worker split across `kestrel-wlan-wpa`,
  `kestrel-wlan-iwd`, `kestrel-l3-networkd`, `kestrel-daemon/power`, and
  `kestrel-cli/agent` with interface/path-scoped `MatchRule`s and unique bus
  owner verification ([ADR-0009](docs/adr/0009-non-blocking-dbus-signal-monitors-and-wire-faithful-adapters.md)).
- Wire-faithful `wpa_supplicant` adapter and `FakeWpa`: native
  `fi.w1.wpa_supplicant1.Interface.PropertiesChanged(a{sv})`, integer
  `GONegotiationSuccess["role_go"]`, and single-RTT `Properties.GetAll` for
  BSS and P2P peer reads.
- Bounded graceful shutdown budgets in `kestrel-controller` and `kestrel-api`.
- CLI improvements in `kestrel wifi join` (skip redundant profile updates on
  unchanged saved profiles and track rapid state transitions in wait loops).
- Restructured user documentation under [docs/index.md](docs/index.md) with
  end-to-end getting started, NetworkManager migration/rollback, 802.1X,
  scripting/agents/polkit, troubleshooting, and failure/capability references.

## v0.0.1: initial release (done)

- Sans-IO station, P2P session, and SoftAP hotspot state machines with
  property-tested rollback invariants.
- Ports and adapters for `wpa_supplicant` (station, P2P, SoftAP, 802.1X blobs,
  signal-driven), `iwd` (station and AP mode), and `systemd-networkd`
  (runtime units, `Describe()` status, DHCP server leases).
- Profiles with priorities and autoconnect, plus 802.1X / WPA-Enterprise
  (EAP-TLS/PEAP/TTLS/PWD), a managed public certificate store, and sealed
  secrets (`systemd-creds` bound to their profile or P2P group).
- End-to-end Wi-Fi Direct orchestration: peer discovery, WPS, GO negotiation,
  autonomous GO (`P2P.StartGroup`), WFD subelements, and Kestrel-owned
  persistent groups (reconnect without WPS).
- SoftAP / hotspot orchestration (`com.hihusky.Kestrel.Hotspot`) delegating
  DHCP and NAT to `systemd-networkd` with zero capabilities.
- Explicit device security capability contract (`Device.SupportedSecurity`).
- Self-describing ownership tags, swept at startup and shutdown.
- `com.hihusky.Kestrel` (API version 1): `ObjectManager` tree, polkit,
  agents, client/server feature-split `kestrel-api`, compositor properties
  (`OnlineState`, `WirelessHardwareEnabled`, `Frequency`, `Security`, `Dns`,
  profile-matched `GetScanResults`), and task-oriented `kestrel` CLI.
- Power and radio resilience: `systemd-logind` `PrepareForSleep` with sleep
  delay inhibitor, `/sys/class/rfkill` hardware state, persistent software
  wireless toggle (`/var/lib/kestrel/state.toml`), and self-healing
  `systemd-creds` decryption fallback.
- E2E lab against the real `systemd-networkd` in an unprivileged namespace.

## Next: hardware validation gate (needs hardware)

Run and record the full matrix in
[docs/hardware-validation.md](docs/hardware-validation.md): WPA2, transition,
WPA3-only, OWE, hidden SSIDs, roaming, suspend/resume, rfkill, crash
recovery, P2P GO/client against Android and a Miracast sink, persistent
group reinvocation, SoftAP with a real client, and 802.1X against a RADIUS
server.

## Not planned without a concrete user

- An L3 provider other than networkd (the port allows it; nobody has asked).
- VPN, WWAN, bonds, VLANs: these belong to the L3 daemon, not to Kestrel.

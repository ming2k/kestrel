# ADR 0007: Persistent Wi-Fi Direct groups and device security capability contract

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

Two operational requirements needed first-class control-plane support:

1. **Ephemeral-only P2P groups:** Reconnecting to a paired phone or Miracast sink required repeating WPS push-button or PIN negotiation on every session. Storing persistent groups inside `wpa_supplicant`'s config violates Kestrel's stateless-backend invariant and leaves unencrypted PSKs in backend state.
2. **Opaque security enforcement limits:** Backends differ in which L2 security modes they can strictly enforce (`iwd` cannot enforce WPA3-only, OWE-only, or dynamic 802.1X over D-Bus; drivers vary in SAE/OWE/802.1X support). Consumers discovered these limits only after attempting a connection.

## Decision

1. **Kestrel-owned persistent P2P groups (`P2pGroupStore`).**
   - `P2pGroupProfile` records (`id`, `name`, `peer`, `role`, `ssid`, `go_address`, `last_connected`) are persisted atomically (`0600` in `/var/lib/kestrel/p2p-groups/`), with the negotiated group PSK sealed in `systemd-creds` under `kestrel-p2p-<uuid>` (`SecretKey::P2pGroup`).
   - `wpa_supplicant`'s internal persistent group table is cleared on `sweep()` (`RemoveAllPersistentGroups`). During a persistent session, `kestrel-wlan-wpa` materializes a transient `PersistentGroup` object (`AddPersistentGroup`), invokes `Invite` or `GroupAdd`, and calls `RemovePersistentGroup` when the session closes.
   - Persistent groups are exported on D-Bus at `/com/hihusky/Kestrel/P2pGroup/<id>` (`com.hihusky.Kestrel.P2pGroup`), provisioned via `P2P.Connect(..., persistent)` / `P2P.StartGroup(..., persistent)`, and re-established via `P2P.ConnectPersistent` / `P2P.StartPersistentGroup`.
2. **Explicit `Device.SupportedSecurity` contract.**
   - `WlanDevice` and `com.hihusky.Kestrel.Device` expose `SupportedSecurity` (`as`), reflecting the exact set of profile security modes (`open`, `owe`, `wpa-personal`, `wpa3-personal`, `wpa-enterprise`, `wpa3-enterprise`) enforceable by the active backend and interface capabilities.

## Consequences

- Reconnecting paired Wi-Fi Direct devices skips WPS while keeping `wpa_supplicant` stateless and group credentials encrypted at rest.
- Desktop shells and settings panels can disable or warn on unsupported security modes (such as WPA3-only or 802.1X on `iwd`) directly from D-Bus properties.

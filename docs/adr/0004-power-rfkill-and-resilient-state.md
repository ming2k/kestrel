# ADR 0004: Power lifecycle, hardware rfkill, persistent radio toggle, and credential recovery

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

In production desktop deployments, four operational edge cases must be handled deterministically:

1. **System suspend/resume:** When the kernel suspends, PCIe/USB wireless NICs may reset or drop carrier before `wpa_supplicant` or `iwd` notices, causing false `link-lost` backoff or stale scan caches after wake.
2. **Hardware rfkill vs software toggle:** Desktop shells must distinguish a user-toggled software `wifi off` from a physical killswitch (`rfkill` hard block), and the user's software toggle must survive daemon restarts and reboots.
3. **Host/TPM credential key rotation:** Secrets are sealed via `systemd-creds` bound to `kestrel-wifi-<uuid>`. If `/var/lib/systemd/credential.secret` is regenerated or a motherboard/TPM is replaced, existing `.cred` files fail decryption. Failing permanently with a backend storage error wedges autoconnect until the user deletes and recreates the profile.

## Decision

1. **Suspend and resume (`PrepareForSleep`).**
   - `kestrel-machines::station::StationInput` includes `SetSuspended(bool)`.
   - On suspend (`true`), active P2P sessions close and stations release their L3 binding and L2 association cleanly into `Disabled` without recording a failure event and without altering `user_hold`.
   - On resume (`false`), stations clear pre-sleep failure cooldowns and stale scan caches (`visible`), returning to `Idle` and immediately scanning/autoconnecting if wireless is enabled and not held by a prior user disconnect.
   - `kestrel-daemon` subscribes to `org.freedesktop.login1.Manager.PrepareForSleep` on the bus and forwards transitions to `RadioControl::set_suspended`.
2. **Hardware rfkill (`WirelessHardwareEnabled`) and persistent software toggle (`StateStore`).**
   - `WlanProvider` reports hardware rfkill state (`hardware_enabled()` and `WlanEvent::HardwareEnabled(bool)`), backed by `/sys/class/rfkill` (readable under `ProtectSystem=strict` with zero capabilities) and controllable in test fakes.
   - When hardware rfkill blocks the radio, stations suspend/disable cleanly while preserving the software `WirelessEnabled` preference.
   - `kestrel-store::StateFile` persists the software `wireless_enabled` boolean atomically in `/var/lib/kestrel/state.toml` (mode `0600`). On startup, `Controller` restores the persisted toggle, falling back to `kestrel.toml`'s `[wireless].enabled`.
3. **Self-healing credential unsealing (`PortError::CorruptSecret`).**
   - When `systemd-creds decrypt` rejects an existing `.cred` file (wrong key, TPM policy mismatch, or corruption), `SystemdCredsStore` quarantines the file to `<uuid>.cred.invalid` and returns `PortError::CorruptSecret`.
   - `Catalog::has_secret` treats `CorruptSecret` as `Ok(false)`, and the station driver maps it to `FailureReason::SecretsRequired`, prompting the registered Agent for a fresh passphrase instead of wedging the profile.

## Consequences

- Suspend/resume and hardware airplane-mode transitions are clean, race-free, and preserve user intent (`autoconnect_held` and `WirelessEnabled`).
- `kestrel radio off` persists across `kestrel-daemon` restarts and system reboots.
- Credential key resets degrade gracefully to a standard password prompt while preserving the quarantined `.cred.invalid` file for audit.

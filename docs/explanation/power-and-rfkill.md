# Power, rfkill, and Credential Resilience

Wireless daemons on desktop and laptop systems must survive sleep/resume cycles, hardware radio kill switches, and host credential resets without losing user intent or getting stuck in retry loops ([ADR-0004](../adr/0004-power-rfkill-and-resilient-state.md)).

---

## 1. Suspend and Resume (`PrepareForSleep`)

`kestrel-daemon` subscribes to `org.freedesktop.login1.Manager.PrepareForSleep` on the D-Bus system bus:
- **Before sleep (`true`)**: Active P2P sessions close cleanly, and stations release L3 and L2 into `Disabled` while preserving `autoconnect_held`.
- **On resume (`false`)**: Stations clear pre-sleep failure cooldowns and stale scan caches, then immediately trigger a scan and autoconnect so connectivity recovers without waiting for stale backoff timers.

---

## 2. Hardware `rfkill` vs. Software `WirelessEnabled`

Kestrel distinguishes physical radio blocks from the user's software preference:
- **Hardware rfkill**: `kestrel-daemon` monitors `/sys/class/rfkill` (requiring no Linux capabilities) and exposes `Manager.WirelessHardwareEnabled` over D-Bus. A hardware block suspends station orchestration without overwriting the user's software toggle.
- **Software toggle**: `Manager.WirelessEnabled` is persisted atomically to `/var/lib/kestrel/state.toml` (`0600`) so `kestrel wifi off` survives daemon restarts and reboots.

---

## 3. `systemd-creds` Quarantine and Self-Healing

Passphrases are stored in `/var/lib/kestrel/secrets/<uuid>.cred`, encrypted by `systemd-creds` and bound to the credential name `kestrel-wifi-<uuid>` (preventing a credential file from being copied to another profile).

If a stored credential cannot be unsealed—for example after a TPM2 clear or `/var/lib/systemd/credential.secret` rotation—`SystemdCredsStore` quarantines the unreadable file to `*.cred.invalid` and transitions the profile to `secrets-required`, prompting the registered D-Bus agent for a fresh passphrase.

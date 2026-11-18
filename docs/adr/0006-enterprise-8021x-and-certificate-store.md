# ADR 0006: 802.1X / WPA-Enterprise and sealed certificate storage

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

Enterprise Wi-Fi (802.1X / WPA2-Enterprise / WPA3-Enterprise using EAP-TLS, PEAP, TTLS, or PWD) requires X.509 CA and client certificates, server identity verification constraints, EAP passwords, and client private keys. Under `kestrel.service`'s sandbox (`ProtectHome=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`), passing user-home file paths to `kestrel-daemon` fails, and writing unencrypted private keys to `/tmp` or `/var/lib/kestrel` violates Kestrel's secret-protection invariants.

## Decision

1. **Managed public certificate store (`CertStore`).**
   - Public X.509 PEM certificates (CA bundles and client certificates) are imported over D-Bus via `Manager.ImportCertificate(name, pem_bytes) -> o` (the CLI/compositor reads user files locally and sends PEM text over D-Bus) and exported at `/com/hihusky/Kestrel/Certificate/<id>` (`com.hihusky.Kestrel.Certificate`).
   - Certificates are validated on import (valid PEM `CERTIFICATE` block, ASN.1 sequence header, bounded size, SHA-256 fingerprint) and stored atomically (`0600` in `/var/lib/kestrel/certs/`). `Certificate.Delete()` rejects removal with `Busy` while referenced by any saved profile.
2. **Structured sealed credentials (`ProfileSecrets`).**
   - `SecretStore` is broken cleanly from a single passphrase string to `ProfileSecrets` (`passphrase`, `private_key`, `private_key_password`), stored in a single `systemd-creds` sealed `.cred` file bound to `kestrel-wifi-<uuid>` (`Zeroizing` in memory, redacted in `Debug`, never `Serialize`).
3. **In-memory D-Bus blob provisioning for `wpa_supplicant`.**
   - `kestrel-wlan-wpa` provisions CA certificates, client certificates, and private keys via `fi.w1.wpa_supplicant1.Interface.AddBlob` (`blob://kestrel-...`), removing them on `disconnect()` and `sweep()`. Plaintext keys and certificates never touch temporary files.
   - Server verification enforces `ca_cert` (or explicit `system_ca = true`) with optional `domain_suffix_match` and `altsubject_match`. `wpa3-enterprise` enforces `WPA-EAP-SHA256` / `WPA-EAP-SUITE-B-192` with `ieee80211w = 2` and never downgrades to legacy `WPA-EAP`.
   - `EAP` D-Bus signals (`completion` failures and certificate verification errors) map deterministically to `WlanEvent::AuthFailed`.
4. **Explicit `iwd` backend boundary.**
   - `iwd` does not support dynamic D-Bus 802.1X provisioning without writing `.8021x` files into `/var/lib/iwd/` (disallowed by `ProtectSystem=strict` and backend statelessness). `kestrel-wlan-iwd` rejects enterprise profiles with `NotSupported` and omits enterprise modes from `Device.SupportedSecurity`.

## Consequences

- 802.1X private keys remain encrypted at rest with `systemd-creds` and travel solely over authenticated D-Bus memory buffers (`AddBlob`).
- `kestrel.service` retains `ProtectHome=yes`, `ProtectSystem=strict`, and `PrivateTmp=yes` unchanged.

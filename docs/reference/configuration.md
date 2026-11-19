# Configuration & Storage Reference

Kestrel separates read-only administrator settings (`/etc/kestrel/kestrel.toml`) from daemon-managed persistent state (`/var/lib/kestrel/`). Saved wireless networks are never written in `kestrel.toml`; they are managed through `kestrel` or the D-Bus API.

---

## 1. Administrator Settings (`/etc/kestrel/kestrel.toml`)

- Every table and key is optional. If `/etc/kestrel/kestrel.toml` does not exist, all built-in defaults apply.
- Field names use `snake_case`; enum values use `kebab-case`.
- Unknown keys and out-of-range values are rejected at startup before any radio orchestration begins (`deny_unknown_fields`).
- See [`config.example.toml`](../../config.example.toml) for the canonical template (verified by unit tests to match compiled defaults).

### `[wireless]`

| Key | Default | Valid Values / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `backend` | `"auto"` | `"auto"`, `"wpa-supplicant"`, `"iwd"` | L2 wireless backend. `"auto"` checks if `fi.w1.wpa_supplicant1` is on the bus, then `net.connman.iwd`, and defaults to waiting for `wpa_supplicant` if neither is running. |
| `enabled` | `true` | `true`, `false` | Initial software `WirelessEnabled` state when `/var/lib/kestrel/state.toml` does not yet exist. |

### `[l3]`

| Key | Default | Valid Values / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `backend` | `"networkd"` | `"networkd"`, `"none"` | L3 provider. `"none"` runs L2 only (every profile must use `l3 = unmanaged`; P2P and hotspot L3 are unavailable). |
| `unit_dir` | `"/run/systemd/network"` | Directory path | Directory where runtime `10-kestrel-<link>.network` units are written. Must exist before `kestrel.service` starts. |

### `[storage]`

| Key | Default | Valid Values / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `profiles` | `"/var/lib/kestrel/profiles"` | Directory path | Directory for `<uuid>.toml` saved profile files. |
| `secrets` | `"/var/lib/kestrel/secrets"` | Directory path | Directory for encrypted `<uuid>.cred` and `p2p-<uuid>.cred` credential files. |
| `certs` | `"/var/lib/kestrel/certs"` | Directory path | Directory for imported public X.509 certificate records (`<uuid>.toml`). |
| `p2p_groups` | `"/var/lib/kestrel/p2p-groups"` | Directory path | Directory for saved persistent Wi-Fi Direct group records (`<uuid>.toml`). |
| `history` | `"/var/lib/kestrel/history.jsonl"` | File path | Bounded JSON Lines connection history log. |
| `state` | `"/var/lib/kestrel/state.toml"` | File path | Persistent software radio toggle (`WirelessEnabled`). |
| `secret_backend` | `"systemd-creds"` | `"systemd-creds"`, `"systemd-creds-user"` | `"systemd-creds"` uses the host key / TPM2 (requires root). `"systemd-creds-user"` uses `systemd-creds --user` for unprivileged test/dev instances. |

### `[api]`

| Key | Default | Valid Values / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `authorization` | `"polkit"` | `"polkit"`, `"bus-policy"` | `"polkit"` authorizes every mutating D-Bus call through polkit (production setting). `"bus-policy"` skips polkit and relies solely on D-Bus policy (for private/session-bus testing). |

### `[p2p]`

| Key | Default | Valid Values / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `device_name` | `"Kestrel"` | 1..=32 bytes, no control characters | P2P device name advertised to nearby peers. |
| `go_intent` | `7` | `0..=15` | Default Group Owner intent when a caller does not specify `--go-intent`. |
| `subnet_pool` | `192.168.49.0/24`, `10.49.0.0/24`..`10.49.15.0/24` | Non-empty array of IPv4 CIDRs, prefix length ≤ `/30` | Shared pool of subnets allocated to both P2P Group Owner sessions and SoftAP hotspots. |

### `[timeouts]` (seconds)

| Key | Default | Valid Range | Description |
| :--- | :--- | :--- | :--- |
| `scan` | `15` | `1..=3600` | Active Wi-Fi scan timeout. |
| `association` | `30` | `1..=3600` | L2 association timeout. |
| `l3` | `30` | `1..=3600` | L3 readiness timeout (station, P2P, and hotspot). |
| `link_grace` | `10` | `0..=600` | Grace period for backend roaming on link drop before releasing L3. |
| `negotiation` | `120` | `1..=3600` | P2P GO negotiation timeout. |
| `group_formation` | `30` | `1..=3600` | P2P group formation timeout. |
| `agent` | `120` | `1..=120` | Interactive agent call timeout (capped at `120` to stay within the daemon's D-Bus method timeout). |

---

## 2. Persistent State (`/var/lib/kestrel/`)

All state directories are created with mode `0700` and all state files with mode `0600`. Writes use atomic replacement (temporary file, `fsync`, rename, directory `fsync`).

| Path | Mode | Contents, Limits & Resilience |
| :--- | :--- | :--- |
| `profiles/<uuid>.toml` | `0600` | Schema-versioned TOML for saved Wi-Fi profiles (never contains secrets). Corrupt or unreadable files are quarantined as `*.invalid` without blocking other profiles. |
| `secrets/<uuid>.cred`, `secrets/p2p-<uuid>.cred` | `0600` | Sealed by `systemd-creds`, cryptographically bound to credential name `kestrel-wifi-<uuid>` (profiles) or `kestrel-p2p-<uuid>` (persistent P2P groups). A profile secret bundle holds optional `passphrase`, `private_key`, and `private_key_password`. Unseal failures quarantine the file to `*.cred.invalid` and mark the profile `secrets-required`. |
| `certs/<uuid>.toml` | `0600` | Imported public X.509 certificates or CA bundles (max 1 MiB PEM at import). Private keys are never stored here. Deleting a certificate referenced by any profile is refused (`Busy`). |
| `p2p-groups/<uuid>.toml` | `0600` | Saved persistent Wi-Fi Direct groups: SSID, role, group owner address, peer address, and last connected timestamp. The group PSK lives in `secrets/p2p-<uuid>.cred`. |
| `history.jsonl` | `0600` | Bounded JSON Lines connection log (retains up to 256 most recent entries on disk; 4 MiB read guard). Diagnostic only; malformed lines are skipped and logged. |
| `state.toml` | `0600` | Schema-versioned TOML persisting the software `WirelessEnabled` toggle across daemon restarts and reboots. |

---

## 3. Runtime Units (`/run/systemd/network/`)

Kestrel writes ephemeral `systemd-networkd` units named `10-kestrel-<link>.network` while a station link, P2P group interface, or hotspot is active, and removes them on disconnect, session close, hotspot stop, clean shutdown, and startup crash-recovery sweeps.

Administrator drop-ins placed in `/etc/systemd/network/10-kestrel-<link>.network.d/*.conf` are preserved across Kestrel unit rewrites and merged by `systemd-networkd`.

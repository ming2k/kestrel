# Configuration & Storage Reference

Kestrel separates read-only administrator settings (`/etc/kestrel/kestrel.toml`) from daemon-managed persistent state (`/var/lib/kestrel/`).

---

## 1. Administrator Settings (`/etc/kestrel/kestrel.toml`)

Every key is optional. Unknown keys are rejected at startup. See [`config.example.toml`](../../config.example.toml) for the canonical template.

### `[wireless]`

| Key | Default | Values / Description |
| :--- | :--- | :--- |
| `backend` | `"auto"` | `"auto"`, `"wpa-supplicant"`, or `"iwd"`. |
| `enabled` | `true` | Initial software wireless state when no `state.toml` exists yet. |

### `[l3]`

| Key | Default | Values / Description |
| :--- | :--- | :--- |
| `backend` | `"networkd"` | `"networkd"` or `"none"` (L2 only). |
| `unit_dir` | `"/run/systemd/network"` | Directory where runtime `.network` units are written. |

### `[storage]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `profiles` | `"/var/lib/kestrel/profiles"` | Directory for `<uuid>.toml` profile files. |
| `secrets` | `"/var/lib/kestrel/secrets"` | Directory for `<uuid>.cred` and `p2p-<uuid>.cred` encrypted secrets. |
| `certs` | `"/var/lib/kestrel/certs"` | Directory for imported public X.509 certificates (`<uuid>.toml`). |
| `p2p_groups` | `"/var/lib/kestrel/p2p-groups"` | Directory for saved persistent Wi-Fi Direct groups (`<uuid>.toml`). |
| `history` | `"/var/lib/kestrel/history.jsonl"` | Bounded connection history log. |
| `state` | `"/var/lib/kestrel/state.toml"` | Persistent software radio toggle (`WirelessEnabled`). |
| `secret_backend` | `"systemd-creds"` | `"systemd-creds"` or `"systemd-creds-user"`. |

### `[api]`

| Key | Default | Values / Description |
| :--- | :--- | :--- |
| `authorization` | `"polkit"` | `"polkit"` or `"bus-policy"`. |

### `[p2p]`

| Key | Default | Description |
| :--- | :--- | :--- |
| `device_name` | `"Kestrel"` | P2P device name advertised to peers. |
| `go_intent` | `7` | Default Group Owner intent (`0..=15`). |
| `subnet_pool` | `192.168.49.0/24`, `10.49.0.0/24`..`10.49.15.0/24` | Pool of `/24` subnets allocated to P2P Group Owner sessions **and** hotspots. |

### `[timeouts]` (seconds)

| Key | Default | Description |
| :--- | :--- | :--- |
| `scan` | `15` | Active Wi-Fi scan timeout. |
| `association` | `30` | L2 association timeout. |
| `l3` | `30` | L3 readiness timeout. |
| `link_grace` | `10` | Grace period for backend roaming on link drop before releasing L3. |
| `negotiation` | `120` | P2P GO negotiation timeout. |
| `group_formation` | `30` | P2P group formation timeout. |
| `agent` | `120` | Interactive agent prompt timeout (at most `120` to stay within D-Bus call timeout). |

---

## 2. Persistent State (`/var/lib/kestrel/`)

| Path | Mode | Format & Resilience |
| :--- | :--- | :--- |
| `profiles/<uuid>.toml` | `0600` (in `0700` dir) | Schema-versioned TOML, written atomically (temp file, `fsync`, rename, dir `fsync`). Invalid files are quarantined as `*.invalid` without blocking other profiles. |
| `secrets/<uuid>.cred`, `secrets/p2p-<uuid>.cred` | `0600` | Encrypted by `systemd-creds`, bound to the credential name `kestrel-wifi-<uuid>` (profiles) or `kestrel-p2p-<uuid>` (persistent groups). A sealed value holds the passphrase, an EAP-TLS private key, and the key's own passphrase. Unseal failures quarantine to `*.cred.invalid` and mark the profile `secrets-required`. |
| `certs/<uuid>.toml` | `0600` (in `0700` dir) | Imported public X.509 certificates or CA bundles. Private keys are never stored here. Deleting one that a profile references is refused. |
| `p2p-groups/<uuid>.toml` | `0600` (in `0700` dir) | Saved persistent Wi-Fi Direct groups: SSID, role, group owner address, peer, and last connection. The group PSK is a sealed secret. |
| `history.jsonl` | `0600` | Bounded JSON lines recording time, device, SSID, profile, outcome, and stable failure code. Diagnostic only. |
| `state.toml` | `0600` | Schema-versioned TOML persisting the software `WirelessEnabled` toggle across restarts and reboots. |

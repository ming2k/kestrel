# CLI & Daemon Reference

Authoritative command, option, default, constraint, and environment-variable reference for `kestrel-daemon` and `kestrel`.

---

## 1. `kestrel-daemon`

```text
kestrel-daemon [--config <PATH>] [--bus <BUS>]
```

| Flag | Env Var | Default | Description |
| :--- | :--- | :--- | :--- |
| `--config <PATH>` | `KESTREL_CONFIG` | `/etc/kestrel/kestrel.toml` | Read-only administrator settings file. A missing file uses built-in defaults. |
| `--bus <BUS>` | `KESTREL_BUS` | `system` | D-Bus bus for the API and backends (`system`, `session`, or a D-Bus address such as `unix:path=...`). |

### Logging & Signals

- `KESTREL_LOG` controls the `tracing` filter expression (default `info`, e.g., `KESTREL_LOG=debug` or `KESTREL_LOG=kestrel_controller=debug,info`).
- Logs go to `stderr`. When `JOURNAL_STREAM` is set (under systemd), timestamps and ANSI color codes are omitted; on a terminal, ANSI colors are enabled.
- Handles `SIGTERM` and `SIGINT` by notifying systemd (`STOPPING=1`), stopping the D-Bus server, tearing down active links/sessions/hotspots, and running backend sweeps before exiting `0`.
- Installed at `/usr/libexec/kestrel-daemon` and managed by `kestrel.service`.

---

## 2. `kestrel` (CLI Client)

### Global Flags & Exit Codes

| Flag | Env Var | Default | Description |
| :--- | :--- | :--- | :--- |
| `--bus <BUS>` | `KESTREL_BUS` | `system` | Target D-Bus (`system`, `session`, or a D-Bus address). |
| `--json` | — | `false` | Emit machine-readable JSON output where supported. |
| `--version` / `-V` | — | — | Print version and exit. |
| `--help` / `-h` | — | — | Print help for the command or subcommand. |

Exit codes: `0` on success, `1` on error (errors print `kestrel: <ErrorName>: <message>` to `stderr`).

Secrets, passphrases, WPS PINs, and private-key passphrases are never accepted in `argv`; they are read from a no-echo terminal prompt or from the first line of `stdin`.

---

### Top-Level Commands

| Command | Description |
| :--- | :--- |
| `kestrel status [--watch]` | Overview of wireless enabled state, hardware rfkill, online state, and every wireless device. `--watch` redraws once per second until `Ctrl-C` and cannot be combined with `--json`. |
| `kestrel agent` | Register an interactive terminal agent (`com.hihusky.Kestrel.Agent`) for secret prompts, incoming P2P authorization, and WPS PIN display. Requires a TTY on `stdin`. Automatically re-registers if `kestrel-daemon` restarts. |
| `kestrel monitor` | Stream D-Bus signals from `com.hihusky.Kestrel` until `Ctrl-C`. With `--json`, emits one JSON object per line (NDJSON). |

---

### `kestrel wifi`

| Command | Description |
| :--- | :--- |
| `wifi status [device]` | Detailed state of one wireless device, or the first wireless device if omitted (supports `--json`). |
| `wifi scan <device> [--all]` | Trigger an active scan and print results. `--all` prints every BSS instead of the strongest BSS per SSID (supports `--json`). |
| `wifi list <device> [--all]` | Print cached scan results without triggering a scan (supports `--json`). |
| `wifi join <device> <ssid> [OPTIONS]` | Scan, infer security, create or update a profile, connect, and wait for `connected` (supports `--json`). |
| `wifi connect <device> <profile> [OPTIONS]` | Connect to an existing saved profile by UUID, UUID prefix, name, or SSID (supports `--json`). |
| `wifi disconnect <device>` | Disconnect and set `AutoconnectHeld = true` until an explicit `wifi connect` or `wifi autoconnect <device> on` (supports `--json`). |
| `wifi forget <profile> [--yes]` | Delete a saved network and its sealed secret; `--yes` skips confirmation (supports `--json`). |
| `wifi autoconnect <device> <on\|off>` | Enable or disable autoconnect on a device without changing the current link (supports `--json`). |
| `wifi on` | Set `WirelessEnabled = true` and persist to `state.toml` (supports `--json`). |
| `wifi off` | Set `WirelessEnabled = false` and persist to `state.toml` (supports `--json`). |
| `wifi history [--limit <N>]` | Show recent connection events, newest first. Default `--limit` is `20` (server caps at `500`; `0` returns empty; supports `--json`). |

#### `wifi join` and `wifi connect` Options

| Option | Commands | Default / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `--security <MODE>` | `join` | Inferred from scan | `open`, `owe`, `wpa-personal`, or `wpa3-personal` (use `profile add` for 802.1X enterprise). |
| `--name <NAME>` | `join` | — | Human-readable profile label. |
| `--priority <I32>` | `join` | `0` | Autoconnect priority (allows negative integers; higher wins). |
| `--hidden` | `join` | `false` | Hidden SSID; requires `--security`. |
| `--ask-secret` | `join`, `connect` | `false` | Prompt for passphrase even if one is already stored. Mutually exclusive with `--secret-stdin`. |
| `--secret-stdin` | `join`, `connect` | `false` | Read passphrase from first line of `stdin`. |
| `--no-wait` | `join`, `connect` | `false` | Return immediately after the request is accepted instead of waiting for `connected`. |
| `--timeout <SECONDS>` | `join`, `connect` | `30` | Seconds to wait for `connected` when `--no-wait` is not set. |

---

### `kestrel profile`

| Command | Description |
| :--- | :--- |
| `profile list` | List saved networks sorted by highest priority first, then SSID (supports `--json`). |
| `profile show <profile>` | Show full non-secret details of a profile by UUID, UUID prefix, name, or SSID (supports `--json`). |
| `profile add [OPTIONS]` | Create a saved network. `--ssid` and `--security` are required (supports `--json`). |
| `profile edit <profile> [OPTIONS] [--clear-secret]` | Update a saved network. Changing `--security` or `--eap` clears a kept secret. `--clear-secret` conflicts with `--ask-secret`, `--secret-stdin`, `--private-key-file`, and `--private-key-password-stdin` (supports `--json`). |
| `profile delete <profile> [--yes]` | Delete a saved network and its sealed secret; disconnects if active. `--yes` skips confirmation (supports `--json`). |

#### General & L3 Profile Options (`add` / `edit`)

| Option | Values / Notes |
| :--- | :--- |
| `--ssid <SSID>` | 1–32 UTF-8 bytes (required on `add`). |
| `--security <MODE>` | `open`, `owe`, `wpa-personal`, `wpa3-personal`, `wpa-enterprise`, `wpa3-enterprise` (required on `add`). |
| `--name <NAME>` | Optional label. |
| `--priority <I32>` | Autoconnect priority (allows negative values; higher wins). |
| `--hidden <BOOL>` | `true` or `false`. |
| `--autoconnect <BOOL>` | `true` or `false`. |
| `--bssid <MAC\|"">` | Pin to a specific access point MAC; `""` clears the pin. |
| `--l3 <MODE>` | `dhcp`, `static`, or `unmanaged`. |
| `--ipv6 <MODE>` | `auto` or `disabled` (applies with `--l3 dhcp`). |
| `--address <CIDR>` | Static IPv4/IPv6 CIDR address (repeatable; with `--l3 static`). |
| `--gateway4 <IP>` / `--gateway6 <IP>` | Static IPv4/IPv6 default gateway (`""` clears). |
| `--dns <IP>` / `--clear-dns` | Static DNS servers (repeatable; mutually exclusive with `--clear-dns`). |
| `--domain <NAME>` / `--clear-domains` | Static DNS search domains (repeatable; mutually exclusive with `--clear-domains`). |
| `--ask-secret` / `--secret-stdin` | Provide passphrase interactively or via `stdin` (mutually exclusive). |

#### 802.1X Enterprise Profile Options (`add` / `edit`)

| Option | Values / Notes |
| :--- | :--- |
| `--eap <METHOD>` | `tls`, `peap`, `ttls`, or `pwd`. |
| `--identity <NAME>` | Outer EAP identity (for example `user@realm`). |
| `--anonymous-identity <NAME>` | Optional outer identity sent before inner authentication. |
| `--phase2 <METHOD>` | Inner authentication for PEAP/TTLS: `mschapv2`, `pap`, `chap`, `mschap`, or `gtc`. |
| `--ca-cert <CERT>` | Imported CA certificate (UUID, 8+ char prefix, or name; `""` clears). Mutually exclusive with `--system-ca true`. |
| `--system-ca [true\|false]` | Trust the host CA store (`--system-ca` alone implies `true`). |
| `--client-cert <CERT>` | Imported client certificate for EAP-TLS (UUID, 8+ char prefix, or name; `""` clears). |
| `--domain-suffix-match <DOMAIN>` | Required RADIUS server certificate domain suffix (`""` clears). |
| `--altsubject-match <PATTERN>` / `--clear-altsubject-match` | Accepted RADIUS `SubjectAltName` patterns (repeatable; mutually exclusive with `--clear-altsubject-match`). |
| `--private-key-file <PATH>` | Local PEM private key file for EAP-TLS (max 256 KiB); sent over D-Bus as a sealed secret, never stored in `/var/lib/kestrel/certs/`. |
| `--private-key-password-stdin` | Read encrypted private key's passphrase from first line of `stdin`. Requires `--private-key-file`; conflicts with `--secret-stdin`. |

---

### `kestrel certificate`

| Command | Description |
| :--- | :--- |
| `certificate list` | List imported public X.509 certificates and SHA-256 fingerprints (supports `--json`). |
| `certificate add <file\|-> --name <NAME>` | Import a public PEM certificate or CA bundle (`-` reads `stdin`; max 1 MiB; `--json` outputs `{"id": "..."}`). |
| `certificate show <certificate>` | Show certificate metadata by UUID, 8+ char prefix, or name (supports `--json`). |
| `certificate delete <certificate> [--yes]` | Delete a certificate; fails with `Busy` if referenced by any saved profile (supports `--json`). |

---

### `kestrel p2p`

| Command | Description |
| :--- | :--- |
| `p2p find <device> [--timeout <SECONDS>]` | Discover P2P peers and print them as they appear (default `--timeout 30`; supports `--json`). |
| `p2p peers <device>` | List currently known P2P peers and any WFD subelements (supports `--json`). |
| `p2p wfd <device> <HEX\|clear>` | Set or clear Wi-Fi Display (Miracast) subelements advertised on `<device>`. Hex ignores `:`, `-`, and whitespace (max 1024 bytes). `clear` or `none` disables advertisement (supports `--json`). |
| `p2p connect <device> <peer> [OPTIONS]` | Connect to peer MAC via GO negotiation (supports `--json`). |
| `p2p start-group <device> [OPTIONS]` | Start an autonomous GO group without GO negotiation and arm WPS PBC for one client (supports `--json`). |
| `p2p groups list` | List saved persistent P2P groups (supports `--json`). |
| `p2p groups show <group>` | Show one saved persistent group by UUID, prefix, name, or SSID (supports `--json`). |
| `p2p groups delete <group> [--yes]` | Delete a saved persistent group and its sealed PSK (supports `--json`). |
| `p2p reconnect <device> <group> [OPTIONS]` | Reconnect a saved persistent group without WPS. Pass `--peer <MAC>` to invite that peer; omit `--peer` to restart autonomously as owner (supports `--json`). |
| `p2p sessions` | List active P2P sessions including role, group interface, and peer IP (supports `--json`). |
| `p2p close <session>` | Close an active session by numeric session ID (e.g. `1`) or full D-Bus path (supports `--json`). |

#### P2P Session Options

| Option | Commands | Default / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `--keypad` | `connect` | `false` | Prompt on terminal (no echo) for peer's WPS PIN. Conflicts with `--display`, `--pin-stdin`. |
| `--pin-stdin` | `connect` | `false` | Read peer's WPS PIN from first line of `stdin`. Conflicts with `--display`. |
| `--display` | `connect` | `false` | Generate a PIN and deliver it to the registered agent (`kestrel agent`). |
| `--go-intent <0..=15>` | `connect` | `[p2p].go_intent` (`7`) | Group Owner intent (`15` strongly prefers GO, `0` prefers client). |
| `--frequency <MHZ>` | `start-group`, `reconnect` | Backend automatic | Operating channel frequency in MHz. |
| `--peer <MAC>` | `reconnect` | — | Peer MAC to invite into the saved group. |
| `--persistent` | `connect`, `start-group` | `false` | Persist the formed group and seal its PSK for WPS-free reconnects. |
| `--wait` | `connect`, `start-group`, `reconnect` | `false` | Block until the session reaches `ready` or `closed`. |
| `--timeout <SECONDS>` | `connect`, `start-group`, `reconnect` | `60` | Seconds to wait when `--wait` is set. |

---

### `kestrel hotspot`

| Command | Description |
| :--- | :--- |
| `hotspot start <device> --ssid <SSID> [OPTIONS]` | Start a SoftAP hotspot on `<device>` (supports `--json`). |
| `hotspot stop <device>` | Stop the hotspot and restore station orchestration (supports `--json`). |
| `hotspot status [device]` | Show hotspot status, gateway, leases, and connected clients for one device or every AP-capable device (supports `--json`). |

#### `hotspot start` Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `--ssid <SSID>` | *(required)* | Hotspot SSID (1–32 bytes). |
| `--security <MODE>` | `wpa-personal` | `open`, `wpa-personal` (WPA2-PSK), or `wpa3-personal` (SAE only). |
| `--frequency <MHZ>` | Backend automatic | Operating channel frequency in MHz. |
| `--hidden` | `false` | Do not broadcast the SSID. |
| `--ask-secret` | `false` | Prompt for passphrase interactively (automatic on a TTY when security is not `open`). Conflicts with `--secret-stdin`. |
| `--secret-stdin` | `false` | Read passphrase from first line of `stdin` (required in non-interactive scripts when security is not `open`). |

`hotspot status --json` objects contain: `device`, `state`, `ssid`, `security`, `frequency`, `gateway`, `leases`, `connected_clients`, `failure`, and `failure_detail`.

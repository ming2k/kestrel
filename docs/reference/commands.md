# CLI & Daemon Reference

Authoritative command, option, default, constraint, exit-code, and environment-variable reference for `kestrel-daemon` and `kestrel` (see [ADR-0010](../adr/0010-cli-grammar-and-interaction-contract.md)).

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

### Global Flags, Device Resolution, and Exit Codes

| Flag | Env Var | Default | Description |
| :--- | :--- | :--- | :--- |
| `--bus <BUS>` | `KESTREL_BUS` | `system` | Target D-Bus (`system`, `session`, or a D-Bus address). |
| `--json` | — | `false` | Emit machine-readable JSON output where supported. |
| `--version` / `-V` | — | — | Print version and exit. |
| `--help` / `-h` | — | — | Print help for the command or subcommand. |

#### Device Selection (`-d, --device <IFACE>` / `KESTREL_DEVICE`)

All single-device subcommands accept `-d, --device <IFACE>` (defaulting to `KESTREL_DEVICE` when set). When omitted:

1. If exactly one device advertises the required capability (`access-point` for `hotspot`, `p2p` for `p2p`, any wireless device for `wifi`), it is selected automatically.
2. If no capable device exists, `kestrel` exits `1` with an error.
3. If two or more capable devices exist, `kestrel` refuses to guess and lists the candidate interface names.

#### Output Streams, Secrets, and Exit Codes

- Structured data, tables, and JSON go to `stdout`; prompts, scan progress, empty-list notices, and errors go to `stderr`.
- Secrets, passphrases, WPS PINs, and private-key passphrases are never accepted in `argv`; they are read from a no-echo terminal prompt or from the first line of `stdin`.
- Exit codes:
  - `0`: success
  - `1`: runtime, validation, authorization, or D-Bus error (`kestrel: <ErrorName>: <message>` on `stderr`)
  - `2`: CLI argument usage error
  - `124`: wait timeout elapsed
  - `130`: interrupted by `Ctrl-C` while waiting

---

### Top-Level Commands

| Command | Description |
| :--- | :--- |
| `kestrel status [DEVICE] [-w, --watch]` | Overview of radio state, hardware rfkill, online state, and all devices, or detailed status of one `DEVICE`. `--watch` redraws once per second until `Ctrl-C` and cannot be combined with `--json`. |
| `kestrel radio [on\|off]` | Query global software radio and hardware rfkill state (when omitted), or set `WirelessEnabled` persistently in `state.toml` (`on` / `off`; supports `--json`). |
| `kestrel agent` | Register an interactive terminal agent (`com.hihusky.Kestrel.Agent`) for secret prompts, incoming P2P authorization, and WPS PIN display. Requires a TTY on `stdin`. Automatically re-registers if `kestrel-daemon` restarts. |
| `kestrel monitor` | Stream D-Bus signals from `com.hihusky.Kestrel` until `Ctrl-C`. With `--json`, emits one JSON object per line (NDJSON). |
| `kestrel completions <SHELL>` | Print shell completions (`bash`, `zsh`, `fish`, `elvish`, `powershell`) to `stdout` without connecting to D-Bus. |

---

### `kestrel wifi`

| Command | Description |
| :--- | :--- |
| `wifi scan [-d <IFACE>] [-a, --all] [--cached]` | Trigger an active scan and print results, or print cached results with `--cached`. `--all` prints every BSS instead of the strongest BSS per SSID (supports `--json`). |
| `wifi connect <TARGET> [-d <IFACE>] [OPTIONS]` | Connect to a saved profile (by UUID, 8+ char prefix, name, or SSID) or, if no profile matches, scan, infer security, create a profile, and connect. Waits for `connected` by default (supports `--json`). |
| `wifi disconnect [-d <IFACE>] [--no-wait] [-t, --timeout <15>]` | Disconnect and hold autoconnect (`AutoconnectHeld = true`) until an explicit `wifi connect` or `wifi autoconnect on`. Waits until idle by default (supports `--json`). |
| `wifi autoconnect [on\|off] [-d <IFACE>]` | Query station autoconnect and hold state (when omitted) or enable/disable autoconnect without changing the current link (supports `--json`). |
| `wifi history [-d <IFACE>] [-n, --limit <20>]` | Show recent Wi-Fi station connection events, newest first, optionally filtered by `-d <IFACE>`. Default `--limit` is `20` (server caps at `500`; `0` returns empty; supports `--json`). |

#### `wifi connect` Options

| Option | Default / Constraints | Description |
| :--- | :--- | :--- |
| `-d, --device <IFACE>` | Auto / `KESTREL_DEVICE` | Target wireless interface. |
| `--security <MODE>` | Inferred from scan | `open`, `owe`, `wpa-personal`, or `wpa3-personal` (use `profile add` for 802.1X enterprise). |
| `--name <NAME>` | — | Human-readable profile label. |
| `--priority <I32>` | `0` | Autoconnect priority (allows negative integers; higher wins). |
| `--hidden` | `false` | Hidden SSID; requires `--security` for new networks. |
| `--ask-secret` | `false` | Prompt for passphrase even if one is already stored. Conflicts with `--secret-stdin`. |
| `--secret-stdin` | `false` | Read passphrase from first line of `stdin`. |
| `--no-wait` | `false` | Return immediately after the request is accepted instead of waiting for `connected`. |
| `-t, --timeout <SECONDS>` | `30` | Seconds to wait for `connected` when `--no-wait` is not set. |

---

### `kestrel profile`

| Command | Description |
| :--- | :--- |
| `profile list` | List saved networks sorted by highest priority first, then SSID (supports `--json`). |
| `profile show <PROFILE>` | Show full non-secret details of a profile by UUID, 8+ char prefix, name, or SSID (supports `--json`). |
| `profile add <SSID> --security <MODE> [OPTIONS]` | Create a saved network profile (`--json` outputs `{"id": "..."}`). |
| `profile edit <PROFILE> [OPTIONS]` | Update a saved network profile. Changing `--security` or `--eap` clears a kept secret. Supports `--clear-<field>` flags (supports `--json`). |
| `profile delete <PROFILE> [-y, --yes]` | Delete a saved network and its sealed secret; disconnects if active. `-y`/`--yes` skips confirmation (supports `--json`). |

#### General Options (`profile add` / `profile edit`)

| Option | Commands | Values / Notes |
| :--- | :--- | :--- |
| `<SSID>` / `--ssid <SSID>` | `add` (positional) / `edit` (flag) | 1–32 UTF-8 bytes. |
| `--security <MODE>` | `add` (required) / `edit` | `open`, `owe`, `wpa-personal`, `wpa3-personal`, `wpa-enterprise`, `wpa3-enterprise`. |
| `--name <NAME>` | `add`, `edit` | Optional human-readable label. |
| `--priority <I32>` | `add`, `edit` | Autoconnect priority (allows negative values; higher wins). |
| `--hidden` / `--hidden <BOOL>` | `add` (flag) / `edit` (`true\|false`) | Hidden SSID setting. |
| `--no-autoconnect` / `--autoconnect <BOOL>` | `add` (flag) / `edit` (`true\|false`) | Autoconnect setting (defaults to enabled on `add`). |
| `--bssid <MAC>` / `--clear-bssid` | `add`, `edit` / `edit` | Pin to a specific access point MAC; `--clear-bssid` removes the pin. |

#### L3 / IP Options (`profile add` / `profile edit`)

| Option | Values / Notes |
| :--- | :--- |
| `--l3 <MODE>` | `dhcp`, `static`, or `unmanaged`. |
| `--ipv6 <MODE>` | `auto` or `disabled` (applies with `--l3 dhcp`). |
| `--address <CIDR>` | Static IPv4/IPv6 CIDR address (repeatable; with `--l3 static`). |
| `--gateway4 <IP>` / `--clear-gateway4` | Static IPv4 default gateway (`--clear-gateway4` on `edit`). |
| `--gateway6 <IP>` / `--clear-gateway6` | Static IPv6 default gateway (`--clear-gateway6` on `edit`). |
| `--dns <IP>` / `--clear-dns` | Static DNS servers (repeatable; `--clear-dns` on `edit`). |
| `--domain <NAME>` / `--clear-domains` | Static DNS search domains (repeatable; `--clear-domains` on `edit`). |

#### 802.1X Enterprise Options (`profile add` / `profile edit`)

| Option | Values / Notes |
| :--- | :--- |
| `--eap <METHOD>` | `tls`, `peap`, `ttls`, or `pwd`. |
| `--identity <NAME>` | Outer EAP identity (for example `user@realm`). |
| `--anonymous-identity <NAME>` / `--clear-anonymous-identity` | Optional outer identity sent before inner authentication. |
| `--phase2 <METHOD>` / `--clear-phase2` | Inner authentication for PEAP/TTLS: `mschapv2`, `pap`, `chap`, `mschap`, or `gtc`. |
| `--ca-cert <CERT>` / `--clear-ca-cert` | Imported CA certificate (UUID, 8+ char prefix, or name). Mutually exclusive with `--system-ca` on `add`. |
| `--system-ca` / `--system-ca <BOOL>` | Trust the host CA store (pure flag on `add`; explicit `true\|false` on `edit`). |
| `--client-cert <CERT>` / `--clear-client-cert` | Imported client certificate for EAP-TLS (UUID, 8+ char prefix, or name). |
| `--domain-suffix-match <DOMAIN>` / `--clear-domain-suffix-match` | Required RADIUS server certificate domain suffix. |
| `--altsubject-match <PATTERN>` / `--clear-altsubject-match` | Accepted RADIUS `SubjectAltName` patterns (repeatable). |

#### Credentials (`profile add` / `profile edit`)

| Option | Values / Notes |
| :--- | :--- |
| `--ask-secret` / `--secret-stdin` | Provide passphrase interactively or via `stdin` (mutually exclusive). |
| `--private-key-file <PATH>` | Local PEM private key file for EAP-TLS (max 256 KiB); sent over D-Bus as a sealed secret, never stored in `/var/lib/kestrel/certs/`. |
| `--private-key-password-stdin` | Read encrypted private key's passphrase from first line of `stdin`. Requires `--private-key-file`; conflicts with `--secret-stdin`. |
| `--clear-secret` (`edit` only) | Remove the stored secret bundle. Conflicts with all credential input flags. |

---

### `kestrel certificate` (alias: `cert`)

| Command | Description |
| :--- | :--- |
| `certificate list` | List imported public X.509 certificates and SHA-256 fingerprints (supports `--json`). |
| `certificate show <CERT>` | Show certificate metadata by UUID, 8+ char prefix, or name (supports `--json`). |
| `certificate add <FILE\|-> [--name <NAME>]` | Import a public PEM certificate or CA bundle (`-` reads `stdin`; max 1 MiB). When reading from a file, `--name` defaults to the filename stem (`--name` is required for `-`). |
| `certificate delete <CERT> [-y, --yes]` | Delete a certificate; fails with `Busy` if referenced by any saved profile (supports `--json`). |

---

### `kestrel hotspot`

| Command | Description |
| :--- | :--- |
| `hotspot status [-d <IFACE>]` | Show hotspot status for every AP-capable device (table / JSON array), or detailed status for one device with `-d` (key-value / JSON object). |
| `hotspot start <SSID> [-d <IFACE>] [OPTIONS]` | Start a SoftAP hotspot and wait for `active` by default (supports `--json`). |
| `hotspot stop [-d <IFACE>] [--no-wait] [-t, --timeout <15>]` | Stop the hotspot, wait for `stopped` by default, and restore station orchestration (supports `--json`). |

#### `hotspot start` Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `-d, --device <IFACE>` | Auto / `KESTREL_DEVICE` | Target AP-capable wireless interface. |
| `--security <MODE>` | `wpa-personal` | `open`, `wpa-personal` (WPA2-PSK), or `wpa3-personal` (SAE only). |
| `-f, --frequency <MHZ>` | Backend automatic | Operating channel frequency in MHz. |
| `--hidden` | `false` | Do not broadcast the SSID. |
| `--ask-secret` | `false` | Prompt for passphrase interactively (automatic on a TTY when security is not `open`). Conflicts with `--secret-stdin`. |
| `--secret-stdin` | `false` | Read passphrase from first line of `stdin` (required in non-interactive scripts when security is not `open`). |
| `--no-wait` | `false` | Return immediately after `Start` is accepted instead of waiting for `active`. |
| `-t, --timeout <SECONDS>` | `30` | Seconds to wait for `active` when `--no-wait` is not set. |

`hotspot status --json` objects contain: `device`, `state`, `ssid`, `security`, `frequency`, `gateway`, `leases`, `connected_clients`, `failure`, and `failure_detail`.

---

### `kestrel p2p`

| Command | Description |
| :--- | :--- |
| `p2p peer find [-d <IFACE>] [-t, --timeout <30>]` | Discover P2P peers and print them as they appear (default `--timeout 30`; supports `--json`). |
| `p2p peer list [-d <IFACE>]` | List currently known P2P peers and any WFD subelements (supports `--json`). |
| `p2p connect <PEER> [-d <IFACE>] [OPTIONS]` | Connect to peer MAC via GO negotiation; waits until `ready` by default (supports `--json`). |
| `p2p start-group [-d <IFACE>] [OPTIONS]` | Start an autonomous GO group without GO negotiation and arm WPS PBC for one client; waits until `ready` by default (supports `--json`). |
| `p2p reconnect <GROUP> [-d <IFACE>] [OPTIONS]` | Reconnect a saved persistent group without WPS. Pass `--peer <MAC>` to invite that peer; omit `--peer` to restart autonomously as owner. Waits until `ready` by default (supports `--json`). |
| `p2p wfd set <HEX> [-d <IFACE>]` | Advertise hex-encoded Wi-Fi Display (Miracast) subelements (ignores `:`, `-`, and spaces; max 1024 bytes; supports `--json`). |
| `p2p wfd clear [-d <IFACE>]` | Stop advertising Wi-Fi Display subelements (supports `--json`). |
| `p2p session list` | List active P2P sessions including numeric ID, device, role, group interface, and peer IP (supports `--json`). |
| `p2p session show <SESSION>` | Show details of one active P2P session by numeric ID (e.g. `1`) or full D-Bus path (supports `--json`). |
| `p2p session close <SESSION>` | Close an active P2P session by numeric ID or full D-Bus path (supports `--json`). |
| `p2p group list` | List saved persistent P2P groups (supports `--json`). |
| `p2p group show <GROUP>` | Show one saved persistent group by UUID, 8+ char prefix, name, or SSID (supports `--json`). |
| `p2p group delete <GROUP> [-y, --yes]` | Delete a saved persistent group and its sealed PSK (supports `--json`). |

#### P2P Session Options

| Option | Commands | Default / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `-d, --device <IFACE>` | `connect`, `start-group`, `reconnect` | Auto / `KESTREL_DEVICE` | Target P2P-capable wireless interface. |
| `--wps <METHOD>` | `connect` | `pbc` | `pbc`, `keypad` (TTY prompt), or `display` (deliver PIN to agent). |
| `--pin-stdin` | `connect` | `false` | Read peer's WPS PIN from first line of `stdin` (implies `--wps keypad`). |
| `--go-intent <0..=15>` | `connect` | `[p2p].go_intent` (`7`) | Group Owner intent (`15` strongly prefers GO, `0` prefers client). |
| `-f, --frequency <MHZ>` | `start-group`, `reconnect` | Backend automatic | Operating channel frequency in MHz. |
| `--peer <MAC>` | `reconnect` | — | Peer MAC to invite into the saved group. |
| `--persistent` | `connect`, `start-group` | `false` | Persist the formed group and seal its PSK for WPS-free reconnects. |
| `--no-wait` | `connect`, `start-group`, `reconnect` | `false` | Return immediately with the session ID instead of waiting for `ready`. |
| `-t, --timeout <SECONDS>` | `connect`, `start-group`, `reconnect` | `60` | Seconds to wait for `ready` when `--no-wait` is not set. |

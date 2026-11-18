# CLI & Daemon Reference

Authoritative command, flag, and environment-variable reference for `kestrel` and `kestrel-daemon`.

---

## 1. `kestrel-daemon` (Daemon)

```text
kestrel-daemon [--config <PATH>] [--bus <BUS>]
```

| Flag | Env Var | Default | Description |
| :--- | :--- | :--- | :--- |
| `--config <PATH>` | `KESTREL_CONFIG` | `/etc/kestrel/kestrel.toml` | Path to read-only administrator settings file. |
| `--bus <BUS>` | `KESTREL_BUS` | `system` | D-Bus bus for the API and backends (`system`, `session`, or a D-Bus address). |

Logging filter is controlled via `KESTREL_LOG` (default `info`). Logs are written to `stderr` (plain lines under systemd when `JOURNAL_STREAM` is set, colored on a terminal).

The installed unit starts it from `/usr/libexec/kestrel-daemon` as `kestrel.service`.

---

## 2. `kestrel` (CLI Client)

### Global Flags

| Flag | Env Var | Default | Description |
| :--- | :--- | :--- | :--- |
| `--bus <BUS>` | `KESTREL_BUS` | `system` | Target D-Bus (`system`, `session`, or a D-Bus address). |
| `--json` | — | `false` | Emit machine-readable JSON output where supported. |

### Top-Level Commands

| Command | Description |
| :--- | :--- |
| `kestrel status [--watch]` | Overview of every wireless device (`--watch` redraws once per second; supports `--json`). |
| `kestrel agent` | Run an interactive agent in this terminal for secret prompts, peer requests, and PIN display. |
| `kestrel monitor` | Print raw D-Bus changes as they happen (supports `--json` NDJSON output). |

### `kestrel wifi`

| Command | Description |
| :--- | :--- |
| `wifi status [device]` | Detailed state of one device (or the first wireless device; supports `--json`). |
| `wifi scan <device> [--all]` | Scan and print results (`--all` shows every BSS instead of strongest per SSID; supports `--json`). |
| `wifi list <device> [--all]` | Print the latest scan results without triggering a scan (supports `--json`). |
| `wifi join <device> <ssid> [OPTIONS]` | Scan, infer security, create or update profile, connect, and wait for an address. |
| `wifi connect <device> <profile> [OPTIONS]` | Connect to an existing saved profile (by UUID, name, or SSID). |
| `wifi disconnect <device>` | Disconnect and hold autoconnect until an explicit connect or `autoconnect on`. |
| `wifi forget <profile> [--yes]` | Delete a saved network (`--yes` skips confirmation). |
| `wifi autoconnect <device> <on\|off>` | Enable or disable autoconnect without changing the current link. |
| `wifi on` | Turn software wireless state on. |
| `wifi off` | Turn software wireless state off. |
| `wifi history [--limit <N>]` | Show recent connection events, newest first (default limit `20`; supports `--json`). |

Key options for `wifi join` and `wifi connect`:
- `--security <open|owe|wpa-personal|wpa3-personal>` (`join` only; inferred from scan when omitted; use `profile add` for enterprise 802.1X profiles)
- `--name <NAME>`, `--priority <I32>`, `--hidden` (`join` only; `--hidden` requires `--security`)
- `--ask-secret`, `--secret-stdin` (mutually exclusive; secrets never pass in `argv`)
- `--no-wait`, `--timeout <SECONDS>` (default `30`)

### `kestrel profile`

| Command | Description |
| :--- | :--- |
| `profile list` | List saved networks, highest priority first (supports `--json`). |
| `profile show <profile>` | Show one saved network by UUID, name, or SSID (supports `--json`). |
| `profile add [OPTIONS]` | Create a saved network (supports `--json`). |
| `profile edit <profile> [OPTIONS] [--clear-secret]` | Update a saved network (`--clear-secret` removes the stored credentials; supports `--json`). |
| `profile delete <profile> [--yes]` | Delete a saved network (supports `--json`). |

Profile options (`add` / `edit`): `--ssid`, `--security`, `--name`, `--priority`, `--hidden <bool>`, `--autoconnect <bool>`, `--bssid <MAC|"">`, `--l3 <dhcp|static|unmanaged>`, `--ipv6 <auto|disabled>`, `--address <CIDR>` (repeatable), `--gateway4 <IP>`, `--gateway6 <IP>`, `--dns <IP>` (repeatable), `--clear-dns`, `--domain <NAME>` (repeatable), `--clear-domains`, `--ask-secret`, `--secret-stdin`.

802.1X options (`add` / `edit`): `--eap <tls|peap|ttls|pwd>`, `--identity <NAME>`, `--anonymous-identity <NAME>`, `--phase2 <mschapv2|pap|chap|mschap|gtc>`, `--ca-cert <certificate>`, `--system-ca [true|false]`, `--client-cert <certificate>` (EAP-TLS), `--domain-suffix-match <DOMAIN>`, `--altsubject-match <PATTERN>` (repeatable), `--clear-altsubject-match`, `--private-key-file <PATH>` (read locally and sent over D-Bus as a sealed secret), `--private-key-password-stdin` (requires `--private-key-file`). `--ca-cert` and `--client-cert` accept an id, an 8+ character id prefix, or a certificate name; run `kestrel certificate add` first.

### `kestrel certificate`

| Command | Description |
| :--- | :--- |
| `certificate list` | List imported X.509 certificates and their SHA-256 fingerprints (supports `--json`). |
| `certificate add <file\|-> --name <NAME>` | Import a public PEM certificate or CA bundle (`-` reads stdin; `--json` prints the new id). |
| `certificate show <certificate>` | Show one certificate by id, id prefix, or name (supports `--json`). |
| `certificate delete <certificate> [--yes]` | Delete a certificate; refused while a saved profile references it (supports `--json`). |

### `kestrel p2p`

| Command | Description |
| :--- | :--- |
| `p2p find <device> [--timeout <SECONDS>]` | Discover P2P peers (default `30`s; supports `--json`). |
| `p2p peers <device>` | List discovered P2P peers and any WFD subelements (supports `--json`). |
| `p2p wfd <device> <HEX\|clear>` | Set or clear Wi-Fi Display (Miracast) subelements advertised on a device (supports `--json`). |
| `p2p connect <device> <peer> [OPTIONS]` | Connect to a peer (`--keypad`, `--pin-stdin`, `--display`, `--go-intent <0..=15>`, `--persistent`, `--wait`, `--timeout <SECONDS>`; supports `--json`). |
| `p2p start-group <device> [--frequency <MHZ>] [--persistent] [--wait] [--timeout <SECONDS>]` | Start an autonomous GO group without GO negotiation (supports `--json`). |
| `p2p sessions` | List active P2P sessions (supports `--json`). |
| `p2p close <session>` | Close an active P2P session (supports `--json`). |
| `p2p groups list` | List saved persistent groups (supports `--json`). |
| `p2p groups show <group>` | Show one saved group by id, id prefix, name, or SSID (supports `--json`). |
| `p2p groups delete <group> [--yes]` | Delete a saved group and its sealed PSK (supports `--json`). |
| `p2p reconnect <device> <group> [--peer <MAC>] [--frequency <MHZ>] [--wait] [--timeout <SECONDS>]` | Reconnect a saved group without WPS; `--peer` invites that peer, otherwise the group restarts as owner (supports `--json`). |

### `kestrel hotspot`

| Command | Description |
| :--- | :--- |
| `hotspot start <device> --ssid <SSID> [OPTIONS]` | Start a SoftAP. Options: `--security <open|wpa-personal|wpa3-personal>` (default `wpa-personal`), `--frequency <MHZ>`, `--hidden`, `--ask-secret`, `--secret-stdin`. |
| `hotspot stop <device>` | Stop the hotspot and restore station operation. |
| `hotspot status [device]` | Show hotspot state, SSID, gateway, leases, and clients for one device or every AP-capable device (supports `--json`). |

The JSON rows carry `device`, `state`, `ssid`, `security`, `frequency`, `gateway`, `leases`, `connected_clients`, `failure`, and `failure_detail`.

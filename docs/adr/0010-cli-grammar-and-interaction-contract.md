# ADR 0010: CLI Grammar, Device Resolution, and Interaction Contract

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Earlier revisions of `kestrel` mirrored the underlying D-Bus interfaces almost one-to-one. That produced recurring usability and consistency problems:

1. **Mandatory positional `<device>` arguments** on everyday station, hotspot, and P2P commands forced single-radio hosts (the common case) to repeat interface names such as `wlp0s20f3` on every invocation, while `wifi status` and `hotspot status` silently allowed omitting `<device>` and guessed the first device.
2. **Overlapping verbs and mixed namespaces**: connecting to Wi-Fi was split between `wifi join` and `wifi connect`; profile deletion existed both as `wifi forget` and `profile delete`; device status existed both at top-level `status` and `wifi status`; and the global radio switch lived under `wifi on/off` even though it disables hotspot and P2P as well.
3. **Conflicting async wait defaults**: `wifi join`/`connect` waited by default (`--no-wait`), `p2p connect`/`start-group`/`reconnect` returned immediately by default (`--wait`), and `hotspot start`/`stop` could not wait at all.
4. **Inconsistent argument syntax**: singular top-level nouns (`profile`, `certificate`) vs. plural P2P nouns (`groups`, `sessions`, `peers`); four distinct boolean styles; three ways to clear fields (`""`, `--clear-*`, and magic string `clear`); a single 28-flag struct shared by `profile add` and `profile edit` with runtime-only required checks; and raw D-Bus object paths printed in human output.

## Decision

The `kestrel` CLI (`crates/kestrel-cli`) adopts a strict, task-oriented grammar and interaction contract without backwards-compatibility aliases for the legacy layout:

### 1. Orthogonal Command Grammar

- **Top-level global operations**:
  - `kestrel status [DEVICE] [-w, --watch]`: unified overview (all devices + radio + online state) and single-device detail view, both supporting `--watch`.
  - `kestrel radio [on | off]`: global wireless radio state query and persistent switch.
  - `kestrel agent`, `kestrel monitor`, `kestrel completions <SHELL>`.
- **Task-oriented station namespace (`kestrel wifi`)**:
  - `wifi scan [-d <IFACE>] [-a, --all] [--cached]` (replaces `wifi scan` + `wifi list`).
  - `wifi connect <TARGET> [-d <IFACE>] [...]` (unifies `wifi join` and `wifi connect`: resolves a unique saved profile first, or scans and creates a profile for a new SSID; fails explicitly on ambiguous matches).
  - `wifi disconnect [-d <IFACE>] [--no-wait] [-t, --timeout <S>]`.
  - `wifi autoconnect [on | off] [-d <IFACE>]` (query when omitted; mutate when given).
  - `wifi history [-d <IFACE>] [-n, --limit <N>]` (station connection history, optionally filtered by device).
- **Uniform singular `<resource> <verb>` namespaces**:
  - `profile {list, show, add, edit, delete}` — `add` and `edit` use distinct argument structs with `clap` `help_heading` sections (`General Options`, `L3 / IP Options`, `802.1X Enterprise Options`, `Credentials`) and `ValueEnum` types for all constrained domains.
  - `certificate` (alias: `cert`) `{list, show, add, delete}` — `add <FILE | -> [--name <NAME>]` derives the default label from the filename when reading a file.
  - `hotspot {status, start, stop}`.
  - `p2p` with `peer {find, list}`, `connect`, `start-group`, `reconnect`, `wfd {set, clear}`, `session {list, show, close}`, and `group {list, show, delete}`.

### 2. Zero-Boilerplate, Ambiguity-Safe Device Resolution

- Single-device commands accept `-d, --device <IFACE>` (bound to `KESTREL_DEVICE`).
- When omitted, the CLI filters available devices by the capability required by the subcommand (`access-point` for hotspot, `p2p` for Wi-Fi Direct, any wireless device for station):
  - Exactly 1 capable device → auto-selected.
  - 0 capable devices → explicit error.
  - 2 or more capable devices → explicit error listing the candidate interface names and instructing the caller to pass `-d/--device` (never silently picking the first device).

### 3. Wait-by-Default Asynchronous Semantics

- Every state-transition command (`wifi connect`, `wifi disconnect`, `hotspot start`, `hotspot stop`, `p2p connect`, `p2p start-group`, `p2p reconnect`) subscribes to D-Bus property changes before issuing the mutation and waits for the terminal state by default.
- Callers opt out via `--no-wait` and tune deadlines via `-t, --timeout <SECONDS>`.

### 4. Uniform Argument Syntax & Clean Output Boundaries

- **Primary subject is positional**: `<SSID>` on `profile add` and `hotspot start`, `<TARGET>` on `wifi connect`, `<PEER>` on `p2p connect`, `<GROUP>` on `p2p reconnect`.
- **Two boolean conventions**: `on | off` for radio/autoconnect state toggles; pure boolean flags on create/action commands (`--hidden`, `--no-autoconnect`, `--system-ca`, `--persistent`) and explicit `<true|false>` for tri-state patches on `profile edit`.
- **Single field-clearing convention**: explicit `--clear-<field>` flags on `profile edit` (conflicting with their setter flags) and `p2p wfd clear` for WFD subelements. Empty-string magic values are not part of the CLI contract.
- **No D-Bus path leakage in human output**: profiles display readable names/short IDs and P2P sessions display their numeric IDs (`--json` preserves object paths for programmatic consumers).
- **Strict `stdout`/`stderr` separation and semantic exit codes**: structured data and tables write to `stdout`; prompts, scan progress, confirmations, empty-table notices, and errors write to `stderr`. Secrets are never accepted via `argv`. Exit codes are `0` (success), `1` (runtime/D-Bus error), `2` (CLI usage error), `124` (wait timeout), and `130` (interrupted by `Ctrl-C`).

## Consequences

- Single-radio interactive usage drops boilerplate device arguments while multi-radio hosts remain explicit and safe from accidental cross-device mutations.
- All resource subcommands share predictable grammar, strong `clap` validation, grouped help text, and shell completion via `clap_complete`.
- Breaking changes to the pre-1.0 CLI require updating workspace integration tests, end-to-end tests, validation scripts, and documentation in the same change set.

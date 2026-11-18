# ADR 0002: Sans-IO state machines and self-describing resource ownership

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

Wireless station lifecycle (scanning, candidate ranking, association, L3 binding, roaming grace, exponential backoff, secret prompting) and Wi-Fi Direct sessions (peer discovery, GO negotiation, autonomous GO, WPS provisioning, role-dependent L3, teardown) involve concurrent timers and fallible external daemons. Interleaving state transitions with async I/O and maintaining a separate on-disk ledger of held resources leads to race conditions and stale state after a crash (`SIGKILL`).

## Decision

1. **Sans-IO state machines (`kestrel-machines`).**
   - `Station` and `P2pSession` are plain structs with `handle(&mut self, now: Instant, input: Input) -> Vec<Command>`.
   - Time is an explicit input. Timers are requested via `StartTimer { kind, token, after }`, and stale `TimerToken` expiries are ignored without requiring async timer cancellation.
   - Held resources (`Association`, `L3Binding`, `Negotiation`, `Group`) are recorded in acquisition order and released in strict reverse order on every exit path. Property tests (`proptest`) over random event sequences assert that no resource is ever acquired twice, L3 is never bound without L2, and idle/closed machines hold nothing.
2. **Per-entity command serialization (`kestrel-controller`).**
   - A single coordinator task owns all state machines without awaiting I/O.
   - Each device and each P2P session has a dedicated `Executor` task that runs its commands strictly in order, ensuring a slow backend never stalls other devices and teardown commands never reorder.
3. **Self-describing ownership tags instead of a ledger file.**
   - Every resource Kestrel creates in an external daemon carries an intrinsic ownership tag:
     - `systemd-networkd`: runtime unit filename prefix `10-kestrel-<link>.network` in `/run/systemd/network`.
     - `wpa_supplicant`: network block `id_str="kestrel"` and P2P group interfaces.
     - `iwd`: `KnownNetwork` with `AutoConnect=false`.
   - Each adapter implements `sweep()`, executed before starting machines at startup and after releasing resources at shutdown.

## Consequences

- A `kill -9 kestrel-daemon` cannot leak networkd units, DHCP leases, or `wpa_supplicant` network blocks past the next daemon start, and there is no separate ledger file that can drift from reality.
- Core state transitions are fast, deterministic, and exhaustively testable without mocks or async runtimes.

# ADR 0008: Domain-bounded crates: catalog, controller, and sans-IO machines

- **Status:** Accepted
- **Date:** 2026-11-19

## Context

Separating workspace crates solely along a technical "pure vs. async" axis (`kestrel-core` for all non-I/O code and `kestrel-runtime` for all async code) turned both crates into unfocused catch-alls ("junk drawers"):

1. **`kestrel-core` mixed state machines with unrelated helpers.** It held `Station`, `P2pSession`, and `Hotspot` alongside `SubnetAllocator`—an IPv4 address-pool helper never called by any state machine—and exposed `StationState` directly to `kestrel-api`.
2. **`kestrel-runtime` mixed four distinct responsibilities.** It placed the northbound interactive `Agent` port trait inside an async implementation crate, duplicated in-memory mirrors of persisted certificates and P2P groups inside a 2,185-line `Orchestrator` alongside live radio coordination, coupled profile/certificate CRUD to the radio loop via a 40-method `Handle`, and embedded domain-specific secret/enterprise resolution inside a generic `Executor`.

## Decision

1. **Rename and constrain `kestrel-machines` (replacing `kestrel-core`).**
   - `kestrel-machines` contains **strictly** sans-IO state machines (`Station`, including `station::policy`, `P2pSession`, `Hotspot`) and their `TimerToken` primitive, each conforming to `handle(now, input) -> Vec<Command>`.
   - Code that does not maintain lifecycle state or emit commands (such as `SubnetAllocator`) is barred from `kestrel-machines`.
   - `kestrel-machines` depends solely on `kestrel-model` and contains zero async runtime and zero I/O.
2. **Consolidate all port boundaries in `kestrel-ports`.**
   - `kestrel_ports::agent` (`Agent`, `SecretRequest`, `PeerRequest`, `PinDisplay`) lives alongside southbound L2, P2P, AP, L3, and storage port traits.
3. **Extract persisted asset management into `kestrel-catalog`.**
   - `Catalog` is the single source of truth for saved `WifiProfile`s, `ProfileSecrets`, imported `Certificate`s, `P2pGroupProfile`s, and `ConnectionEvent` history.
   - `Catalog` serializes mutations against `kestrel_ports::store` traits, enforces cross-asset referential integrity (such as rejecting deletion of referenced certificates and rolling back orphaned secrets), and broadcasts `CatalogEvent` notifications.
   - `kestrel-catalog` depends only on `kestrel-model` and `kestrel-ports`—never on `kestrel-machines` or live radio providers.
4. **Refocus `kestrel-controller` (replacing `kestrel-runtime`) on live radio orchestration.**
   - `Controller` drives `kestrel-machines` against `WlanProvider`, `P2pProvider`, `ApProvider`, `L3Provider`, `StateStore`, and `Catalog`.
   - Internally it separates a generic FIFO `Executor<J>`, shared L3/subnet execution (`l3`, `subnet`), per-machine domain drivers (`station`, `p2p`, `hotspot`), and a lean `RadioCoordinator` enforcing cross-radio mutual exclusion, `rfkill`, and system sleep.
   - Northbound callers receive focused sub-handles (`StationControl`, `HotspotControl`, `P2pControl`, `RadioControl`) from `ControllerHandle`, and `kestrel-controller` re-exports `StationState` so `kestrel-api` never depends on `kestrel-machines`.
5. **Break clean with zero legacy aliases.**
   - `kestrel-core` and `kestrel-runtime` are removed from the workspace rather than retained as compatibility shims.

## Consequences

- `kestrel-api` (`server` feature) talks directly to `Catalog` for profile/certificate/group/history operations and to `ControllerHandle` for live radio operations, removing catalog CRUD from the radio event loop and eliminating `kestrel-api`'s dependency on the state-machine crate.
- Each crate has an enforceable admission test: pure value types belong in `kestrel-model`, trait boundaries in `kestrel-ports`, `handle(now, input) -> Vec<Command>` machines in `kestrel-machines`, persisted asset lifecycle in `kestrel-catalog`, and live radio driving in `kestrel-controller`.

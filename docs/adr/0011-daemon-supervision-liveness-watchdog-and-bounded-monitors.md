# ADR 0011: Production Daemon Supervision, Liveness Watchdog, and Bounded Signal Drains

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Running `kestrel-daemon` as a long-lived system service on headless hosts, laptops, and multi-radio workstations requires fault containment beyond startup/shutdown sweeps (ADR-0002) and non-blocking signal monitors (ADR-0009):

1. **Silent livelock risk without active watchdog probing.** `kestrel.service` used `Type=notify` and `Restart=on-failure`, but had no `WatchdogSec=`. If the `RadioCoordinator` event loop or the daemon's D-Bus connection wedged, `systemd` had no signal to detect the hang and restart the service.
2. **Zombie daemon on bus/name/sync loss.** `kestrel-daemon` waited solely on `SIGTERM` and `SIGINT`. If the system D-Bus broker restarted, `com.hihusky.Kestrel` name ownership was lost, or the internal D-Bus object synchronization task exited, the daemon remained alive as an inert process instead of failing fast so `Restart=on-failure` could recover it.
3. **Unbounded memory growth and silent stream termination in signal monitors.** ADR-0009 decoupled `zbus::MessageStream` polling from async RPC work using unbounded `tokio::sync::mpsc` channels. While non-blocking, an unbounded queue has no memory cap under a runaway signal storm. Additionally, loops written with `while let Some(Ok(message)) = stream.next().await` silently terminated on a single malformed stream error.
4. **Leaked suppression counters and CLI/adapter state races.** `kestrel-wlan-wpa::add_persistent_group` decremented `suppress_persistent_added` manually rather than via RAII, risking permanent suppression on error or cancellation, and `interface_removed` left stale `known_groups` entries behind. In `kestrel-cli`, `wait_session` queried a freshly unexported P2P session object without falling back to cached failure properties, and `wifi connect` could spawn a second `pkttyagent` when both `connect` and `modify-profiles` required interactive polkit authentication.

## Decision

Establish four binding production-supervision invariants across `kestrel-daemon`, `kestrel-api`, `kestrel-wlan-wpa`, `kestrel-wlan-iwd`, `kestrel-l3-networkd`, `kestrel-cli`, and `data/kestrel.service`:

1. **Active-liveness systemd watchdog (`WatchdogSec=30s`).**
   - `data/kestrel.service` enables `WatchdogSec=30s`.
   - `kestrel-daemon` implements `sd_watchdog_enabled(3)` (`WATCHDOG_USEC` and optional `WATCHDOG_PID` verification) in pure standard Rust without `unsafe`.
   - At half the watchdog interval, the watchdog task executes a real liveness probe against **both** `RadioCoordinator` (`radio().wireless_enabled()`) and the D-Bus connection (`org.freedesktop.DBus.GetId`) within a bounded probe budget (`clamp(interval / 4, 1s, 5s)`). It sends `WATCHDOG=1` **only** when both probes succeed; blind timer petting is forbidden.
   - Lifecycle status is reported via `STATUS=running` on readiness and `STOPPING=1\nSTATUS=stopping` on shutdown.
2. **Fail-fast supervision on fatal API/bus faults.**
   - `kestrel_api::Server` monitors `NameOwnerChanged` for `com.hihusky.Kestrel`, D-Bus stream closure, and unexpected termination of its `Sync` task, exposing a cancel-safe `Server::wait_fault()` future. `Server::Drop` aborts all background server tasks so no tasks leak even without an explicit `stop()`.
   - `kestrel-daemon` selects over `SIGTERM`, `SIGINT`, and `server.wait_fault()`. Clean signals perform graceful teardown and exit `0`; a fatal runtime fault performs bounded teardown and exits non-zero so `systemd` restarts the unit and startup sweep reconciles L2/L3 state.
3. **Bounded, non-blocking, error-resilient signal drains.**
   - Every `zbus::MessageStream` drain replaces unbounded `mpsc` channels with a bounded `mpsc::channel(CAPACITY)` fed strictly by non-blocking `try_send()` (preserving ADR-0009's zero-deadlock guarantee while bounding memory).
   - Queue saturation sets an atomic `lagged` flag and wakes the worker to execute full state resynchronization (`discover()` in `kestrel-wlan-wpa`, `attach()` in `kestrel-wlan-iwd`).
   - `kestrel-l3-networkd` watches `NameOwnerChanged` for `org.freedesktop.network1` alongside link property changes, clearing cached link status when `systemd-networkd` departs and immediately triggering reconciliation when it returns.
   - No signal drain may exit on a single `Err` item; malformed stream errors are logged and skipped.
4. **RAII state guards and CLI safety.**
   - `kestrel-wlan-wpa` protects `suppress_persistent_added` with an RAII drop guard and cleans `known_groups` on `InterfaceRemoved`.
   - `kestrel-cli` shares a single `PolkitGuard` per command invocation (preventing duplicate `pkttyagent` processes during `wifi connect`), zeroizes imported private key material, and falls back to cached session properties in `wait_session` if a failed P2P session object is unexported before an uncached read completes.

## Consequences

- `systemd` automatically detects and recovers from both event-loop deadlocks (via active watchdog) and bus/name/sync faults (via non-zero fail-fast exit), with startup sweeps guaranteeing zero leaked L2/L3 state.
- Signal monitors simultaneously guarantee zero `zbus` socket-reader deadlocks and bounded memory under pathological D-Bus bursts.
- `systemd-networkd` restarts reconcile immediately without waiting for poll intervals, and persistent-group suppression counters cannot leak on errors or task cancellation.
- `kestrel.service` retains its hardened sandbox exposure score (`1.3`, within the `1.5` budget) and `scripts/check-system-files.sh` validates `WatchdogSec=30s` inside the sandboxed run.

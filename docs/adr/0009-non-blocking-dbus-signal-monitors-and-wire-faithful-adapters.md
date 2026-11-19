# ADR 0009: Non-Blocking D-Bus Signal Monitors and Wire-Faithful Adapters

- **Status:** Accepted
- **Date:** 2026-11-19

## Context

Real-hardware testing against `wpa_supplicant` v2.12 and `zbus` 6.3 exposed three tightly coupled defects in Kestrel's D-Bus signal monitors and test fakes:

1. **Shared-connection `zbus::MessageStream` deadlock.** `zbus`'s socket reader delivers matching signals into each `MessageStream`'s bounded channel (64 slots by default) via an async `broadcast().await`. When a monitor task awaits D-Bus method calls on the same `zbus::Connection` inside its `stream.next().await` loop—for example, `kestrel-wlan-wpa` reading dozens of `BSS` objects after `ScanDone`, `kestrel-l3-networkd` calling `Describe()` during `PropertiesChanged`, or `kestrel-wlan-iwd` calling `GetManagedObjects()`—any burst of more than 64 matching signals fills the stream channel and stalls `zbus`'s socket reader. Because the socket reader can no longer read method replies off the bus, every D-Bus call on the daemon's connection hangs until the 120-second method timeout (`I/O error: timed out`) and `SIGTERM` shutdown times out into `SIGKILL`.
2. **Unfiltered well-known sender `MatchRule`s.** `zbus`'s client-side `MatchRule::matches` cannot match well-known bus names against message headers (which carry unique bus names) and therefore treats `BusName::WellKnown` as a wildcard. Subscribing broadly to `MatchRule::builder().msg_type(Type::Signal).sender(SERVICE)` both instructed `dbus-daemon` to forward noisy `fi.w1.wpa_supplicant1.BSS` beacon churn and caused client-side cross-stream delivery (for example, `NameOwnerChanged` delivered to both `signals` and `owner`, firing `discover()` twice).
3. **`wpa_supplicant` wire-protocol divergence masked by test fakes.** Real `wpa_supplicant` D-Bus v1 emits its native `fi.w1.wpa_supplicant1.Interface.PropertiesChanged(a{sv})` signal (a single dictionary) for `State` and `CurrentBSS` updates and encodes `GONegotiationSuccess["role_go"]` as an `i32` (`1` / `0`). Because `FakeWpa` in `kestrel-wlan-wpa::testkit` relied on `zbus`'s `#[zbus(property)]` helpers—which emit `org.freedesktop.DBus.Properties.PropertiesChanged(s, a{sv}, as)`—and sent string `"GO"` for `role_go`, every automated test passed while real `wpa_supplicant` station associations timed out after 30 seconds despite associating in 3 seconds.

## Decision

Establish three binding red-lines across all D-Bus adapters, monitors, and test fakes:

1. **Strict drain/worker separation for every `zbus::MessageStream`.** No task polling `MessageStream::next().await` may perform async D-Bus RPCs on the shared `zbus::Connection` inline. Every signal monitor splits into:
   - a non-blocking **drain task** that reads messages off `MessageStream` and immediately forwards them into an unbounded `tokio::sync::mpsc` channel (for ordered event monitors in `kestrel-wlan-wpa`, `kestrel-wlan-iwd`, `kestrel-daemon/power`, and `kestrel-cli/agent`) or coalesces wakeups into a `tokio::sync::Notify` (for `kestrel-l3-networkd`);
   - an ordered **worker task** that performs async D-Bus RPCs sequentially in arrival order.
   Every adapter owns `AbortHandle`s for its monitor tasks and aborts them in `Drop` so no background tasks leak.
2. **Interface- and path-scoped `MatchRule`s with unique-owner verification.** Signal monitors must subscribe only to the exact interfaces and object path namespaces they consume (excluding `fi.w1.wpa_supplicant1.BSS` churn at the bus daemon) and must verify `header.sender()` against the tracked unique bus owner (`wpa_owner` / `iwd_owner`) for non-`NameOwnerChanged` signals.
3. **Wire-faithful `wpa_supplicant` adapter and test fake.**
   - `kestrel-wlan-wpa` handles native `fi.w1.wpa_supplicant1.Interface.PropertiesChanged(a{sv})` (while retaining `org.freedesktop.DBus.Properties.PropertiesChanged` as a fallback), parses `GONegotiationSuccess["role_go"]` as an integer (`i32`/`u32`/`bool`, with `"GO"` fallback), and reads each `BSS` with a single `org.freedesktop.DBus.Properties.GetAll` call instead of seven sequential `Get` round-trips.
   - `FakeWpa` in `kestrel-wlan-wpa::testkit` emits native `fi.w1.wpa_supplicant1.Interface.PropertiesChanged(a{sv})` and integer `role_go` so unit, adapter, and e2e tests exercise the real daemon wire protocol.

## Consequences

- `zbus`'s socket reader can never stall under real-world Wi-Fi scan or networkd property bursts, eliminating 120-second D-Bus timeouts and `SIGTERM` shutdown hangs.
- Real `wpa_supplicant` station, roaming, SoftAP, and P2P state transitions are received immediately without timing out, and scanning dense RF environments requires 7x fewer D-Bus round-trips.
- `NameOwnerChanged` and backend signals no longer cross-deliver or trigger duplicate `discover()` runs.
- Regression tests in `kestrel-wlan-wpa` now stress-test signal bursts (>200 signals concurrent with an 80-BSS scan) and native `Interface.PropertiesChanged` delivery directly.

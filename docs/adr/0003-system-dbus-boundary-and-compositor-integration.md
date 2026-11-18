# ADR 0003: System D-Bus boundary and compositor integration

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

Desktop compositors (Wayland shells in Rust or C/C++), settings panels, casting services, and the `kestrel` CLI all need to observe wireless state, trigger scans and connections, and answer interactive credential/WPS prompts. We evaluated three integration boundaries:

1. **System D-Bus (`com.hihusky.Kestrel`)** with `org.freedesktop.DBus.ObjectManager` and `PropertiesChanged`.
2. **In-process shared library (`libkestrel.so`)** linked into the compositor.
3. **Custom Unix domain socket protocol.**

Linking the orchestrator into a compositor violates privilege separation (the compositor runs as an unprivileged user; wireless/networkd orchestration requires root/system bus privileges), couples the network control plane's survival to the UI process, and prevents multiple consumers (shell, CLI, casting service) from sharing state. A custom Unix socket forces re-invention of service activation, polkit authorization, object discovery, property change broadcasting, and standard introspection/debugging tools (`busctl`, `gdbus`).

## Decision

1. **System D-Bus (`com.hihusky.Kestrel`, API version 1) is the sole northbound IPC boundary.**
   - Root object `/com/hihusky/Kestrel` exports `org.freedesktop.DBus.ObjectManager` and `com.hihusky.Kestrel.Manager`.
   - Every mutating method is authorized via polkit (`com.hihusky.kestrel.*`). Secrets are write-only and never returned over the bus.
   - Interactive secret requests, P2P peer authorization, and WPS PIN display are routed to a single registered `com.hihusky.Kestrel.Agent` object, automatically unregistered if its owner leaves the bus.
2. **Client-first Cargo features on `kestrel-api`.**
   - `kestrel-api` defaults to `features = ["client"]`, compiling only the typed `zbus` client proxies, path helpers, and model conversions without pulling in `kestrel-controller`, `kestrel-catalog`, `kestrel-machines`, or `kestrel-ports`.
   - The `server` feature enables the D-Bus object server, polkit authorizer, and controller/catalog bridge for `kestrel-daemon`.
3. **First-class compositor properties on `Manager` and `Device`.**
   - `Manager` exposes `Version`, `WirelessEnabled` (software toggle), `WirelessHardwareEnabled` (rfkill hardware state), and `OnlineState` (`offline`, `partial`, `online`, `unknown`).
   - `Device` exposes `Frequency` (MHz of the active BSS), `Security` (active security mode), `Dns` (configured DNS servers from L3), and `OnlineState` alongside `Ssid`, `Bssid`, `Signal`, `Addresses`, `Gateways`, and `L3Phase`.
   - `Device.GetScanResults()` returns `a(ssunso)`: `(ssid, bssid, frequency_mhz, signal_dbm, security, profile_path)`, directly linking each visible BSS to its highest-priority matching saved profile (or `/` when unsaved) so compositors never re-implement profile matching rules.
4. **Consumer subscription contract.**
   - Non-Rust consumers (GDBus/QtDBus) subscribe to `InterfacesAdded`, `InterfacesRemoved`, and `PropertiesChanged` **before** calling `GetManagedObjects()`, and re-synchronize on `NameOwnerChanged`.

## Consequences

- Rust compositors depend on `kestrel-api` with minimal compile-time footprint; C/C++ compositors use standard GDBus/QtDBus against a self-describing, drift-checked D-Bus schema.
- Desktop network menus can render Wi-Fi status, frequency band, DNS, online/portal state, hardware airplane-mode lockouts, and saved-network badges directly from D-Bus properties without polling or secondary tools.

# Reference

Technical specifications for Kestrel's CLI, daemon, configuration file, on-disk storage, failure codes, backend capabilities, state machines, and D-Bus API.

---

## Specifications & Catalogs

| Reference | Scope & Coverage |
| :--- | :--- |
| [CLI & Daemon Commands](commands.md) | `kestrel` subcommands, flags, defaults, constraints, exit codes, environment variables, and `kestrel-daemon` options. |
| [Configuration & Storage](configuration.md) | `/etc/kestrel/kestrel.toml` schema, defaults, validation bounds, and `/var/lib/kestrel/` persistence layout. |
| [Failures, Errors, and Capabilities](failures-and-errors.md) | Stable `FailureReason` codes, D-Bus errors, polkit action defaults, and the `wpa_supplicant` vs. `iwd` capability matrix. |
| [State Model & Transitions](state-model.md) | Sans-IO `Station`, `P2pSession`, and `Hotspot` state machines, D-Bus state values, resource rollback order, and timers. |
| [D-Bus API](../dbus-api.md) | `com.hihusky.Kestrel` ObjectManager tree, interfaces, properties, methods, signals, errors, and agent contract. |

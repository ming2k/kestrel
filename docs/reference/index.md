# Reference

Technical descriptions of Kestrel's CLI, daemon flags, configuration schema, D-Bus API, and state machines.

---

## Specifications & Catalogs

| Reference | Scope & Coverage |
| :--- | :--- |
| [CLI & Daemon Commands](commands.md) | `kestrel` subcommands, flags, environment variables, and `kestrel-daemon` options. |
| [Configuration & Storage](configuration.md) | `/etc/kestrel/kestrel.toml` schema, defaults, and `/var/lib/kestrel/` persistence layout. |
| [D-Bus API](../dbus-api.md) | `com.hihusky.Kestrel` ObjectManager tree, interfaces, properties, methods, signals, errors, and polkit actions. |
| [State Model & Transitions](state-model.md) | Sans-IO `Station`, `P2pSession`, and `Hotspot` state machines, resource rollback order, and timers. |

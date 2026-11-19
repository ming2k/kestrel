# Kestrel Documentation

Kestrel is a control-plane orchestrator for Linux wireless networking. It coordinates an L2 wireless daemon (`wpa_supplicant` or `iwd`) and an L3 network daemon (`systemd-networkd` with `systemd-resolved`) over D-Bus without competing with either.

---

## Choose Your Path

| If you want to… | Start here |
| :--- | :--- |
| Build, install, and join your first Wi-Fi network | [Getting Started](tutorials/getting-started.md) |
| Install Kestrel, switch from NetworkManager, or uninstall cleanly | [Install, Switch Backends, and Uninstall](how-to/install-and-migrate.md) |
| Connect to Wi-Fi, tune autoconnect, or set static IP/DNS | [Wi-Fi and Network Profiles](how-to/wifi-and-profiles.md) |
| Connect to a corporate 802.1X / WPA-Enterprise network | [802.1X Enterprise Wi-Fi and Certificates](how-to/enterprise-8021x.md) |
| Turn a wireless adapter into a SoftAP hotspot | [Run a Hotspot (SoftAP)](how-to/hotspot.md) |
| Use Wi-Fi Direct (P2P) or Miracast / Wi-Fi Display | [Wi-Fi Direct (P2P) and Miracast](how-to/p2p-and-miracast.md) |
| Automate with `--json`, run `kestrel agent`, or customize polkit | [Scripting, Agents, and Polkit](how-to/scripting-and-agents.md) |
| Diagnose a connection, L3, credential, or permission failure | [Troubleshooting](how-to/troubleshooting.md) |
| Look up CLI flags, TOML keys, failure codes, or D-Bus members | [Reference](reference/index.md) |
| Understand the architecture, crash safety, or rfkill/sleep handling | [Explanation](explanation/index.md) |

---

## Documentation Map

Public documentation follows the Diátaxis four-quadrant layout:

- **[Tutorials](tutorials/index.md)**: end-to-end walkthrough from a clean checkout to a working wireless connection.
- **[How-To Guides](how-to/index.md)**: task-focused procedures for installation, daily Wi-Fi, 802.1X, hotspots, P2P, scripting, and troubleshooting.
- **[Reference](reference/index.md)**: exact specifications for [CLI & Daemon Commands](reference/commands.md), [Configuration & Storage](reference/configuration.md), [Failures, Errors, and Capabilities](reference/failures-and-errors.md), [State Model](reference/state-model.md), and the [D-Bus API](dbus-api.md).
- **[Explanation](explanation/index.md)**: design rationale covering [Architecture Overview](explanation/architecture-overview.md), [Ownership and Crash Safety](explanation/ownership-and-crash-safety.md), and [Power, rfkill, and Credential Resilience](explanation/power-and-rfkill.md).

---

## Project & Contributor Docs

- **[Project README](../README.md)** and **[Roadmap](../ROADMAP.md)** (note: Kestrel is at v0.0.2; real-radio validation is tracked in [Hardware Validation](hardware-validation.md)).
- **[Architecture](../ARCHITECTURE.md)** and **[Architecture Decision Records](adr/README.md)**.
- **[Contributor Documentation](dev/build-and-run.md)**: [Build & Run](dev/build-and-run.md), [Testing](dev/testing.md), [Subsystems](dev/subsystems.md), and [Documentation Standards](dev/standards/taxonomy.md).

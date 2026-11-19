# How-To Guides

Task-oriented procedures for end users, system administrators, and desktop/script integrators.

---

## Installation & System Integration

| Guide | What it covers |
| :--- | :--- |
| [Install, Switch Backends, and Uninstall](install-and-migrate.md) | Prerequisites, `make install` layout, `systemd-tmpfiles` and `systemd-creds`, configuring `wpa_supplicant` or `iwd`, migrating from NetworkManager/ConnMan, `.network.d/` drop-ins, and uninstalling cleanly. |

## Wireless Workflows

| Guide | What it covers |
| :--- | :--- |
| [Wi-Fi and Network Profiles](wifi-and-profiles.md) | Daily station control, scanning, joining, autoconnect and priorities, hidden SSIDs, BSSID pinning, static IPv4/IPv6/DNS, `unmanaged` L3, and secret rotation. |
| [802.1X Enterprise Wi-Fi and Certificates](enterprise-8021x.md) | Importing public PEM certificates, configuring PEAP/TTLS/EAP-TLS/PWD profiles, sealing private keys with `systemd-creds`, and verifying RADIUS server identities. |
| [Run a Hotspot (SoftAP)](hotspot.md) | Turning an AP-capable adapter into a hotspot, configuring uplink forwarding, monitoring DHCP leases and clients, and restoring station mode. |
| [Wi-Fi Direct (P2P) and Miracast](p2p-and-miracast.md) | Discovering peers, WPS/GO negotiation, autonomous GO groups, persistent groups without WPS, and Miracast / Wi-Fi Display subelements. |

## Automation & Operations

| Guide | What it covers |
| :--- | :--- |
| [Scripting, Agents, and Polkit](scripting-and-agents.md) | Machine-readable `--json` output, NDJSON `monitor` streaming, non-interactive secret input, running `kestrel agent`, and customizing polkit authorization rules. |
| [Troubleshooting](troubleshooting.md) | Diagnostic checklist, enabling debug logs, and resolving common startup, permission, L2/L3, credential, hotspot, and rfkill issues. |

For exhaustive syntax, defaults, and error tables, see the [Reference](../reference/index.md).

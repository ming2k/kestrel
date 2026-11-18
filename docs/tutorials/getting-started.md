# Getting Started with Kestrel

This tutorial walks you through building Kestrel, verifying that the unprivileged end-to-end lab works on your machine, and connecting a wireless interface to a Wi-Fi network.

---

## 1. Build the Workspace

Clone the repository and build both `kestrel-daemon` (the orchestrator daemon) and `kestrel` (the CLI client):

```sh
cargo build --release
```

The binaries are placed in `target/release/kestrel-daemon` and `target/release/kestrel`.

---

## 2. Verify with the Unprivileged E2E Lab (No Root Needed)

Before touching your host's wireless configuration, you can run Kestrel against a real `systemd-networkd` inside an unprivileged user/network/mount namespace:

```sh
./crates/kestrel-e2e/run.sh
```

If all e2e scenarios pass, your host has the required `systemd-networkd` and `systemd-creds` tooling.

---

## 3. Check Prerequisites on Your Host

Kestrel is a control-plane orchestrator: it expects `systemd-networkd` and `systemd-resolved` to handle IP addressing and DNS, and either `wpa_supplicant` (D-Bus mode `-u` with no saved networks) or `iwd` (`EnableNetworkConfiguration=false`) to handle L2 radio association.

Discover your wireless interface name (for example `wlp0s20f3`):

```sh
networkctl list
```

---

## 4. Inspect Devices and Scan

Once `kestrel-daemon` is running (see [Deploy with systemd](../how-to/deploy-systemd.md) for system installation), check the overall status:

```sh
kestrel status
```

Inspect a specific wireless device and scan for nearby networks:

```sh
kestrel wifi status wlp0s20f3
kestrel wifi scan wlp0s20f3
```

---

## 5. Join a Wi-Fi Network

Join a network by SSID. Kestrel scans to infer the security type, prompts for the passphrase without echoing it to the terminal, encrypts the secret with `systemd-creds`, creates a profile, associates over L2, hands L3 configuration to `systemd-networkd`, and waits until an IP address is ready:

```sh
kestrel wifi join wlp0s20f3 "MyNetwork"
```

Confirm the link is connected and view recent connection events:

```sh
kestrel wifi status wlp0s20f3
kestrel wifi history
```

---

## Next Steps

- [Manage Profiles](../how-to/manage-profiles.md) to configure priorities, static IPv4/IPv6, 802.1X certificates, or forget networks.
- [Wi-Fi Direct (P2P) and Miracast](../how-to/p2p-and-miracast.md) to discover peers, form P2P groups, and save persistent groups.
- [Run a Hotspot](../how-to/hotspot.md) to share the radio as a SoftAP and hand it back to the station.
- [CLI & Daemon Reference](../reference/commands.md) for all available commands and flags.

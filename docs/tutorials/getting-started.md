# Getting Started with Kestrel

This tutorial walks you from a fresh clone of Kestrel to a working wireless connection on a Linux host—and shows how to verify your environment safely before changing your host's network configuration.

> **Before switching your host's Wi-Fi:** Kestrel replaces NetworkManager or ConnMan for wireless control (`kestrel.service` declares `Conflicts=NetworkManager.service connman.service`). Perform Steps 3–5 from a local console or over a wired Ethernet link so you do not lock yourself out over SSH.

---

## 1. Check What You Need

Kestrel coordinates existing Linux daemons rather than replacing them:

- **Build toolchain**: Rust 1.89+ (Edition 2024; see [`rust-toolchain.toml`](../../rust-toolchain.toml)) and `make`.
- **L3 & DNS**: `systemd-networkd` and `systemd-resolved`.
- **Credential sealing**: `systemd-creds` (part of `systemd`).
- **IPC & authorization**: system D-Bus (`dbus`) and `polkit`.
- **One L2 wireless daemon**:
  - **`wpa_supplicant` (recommended)**: supports all features (WPA2/WPA3-only, OWE, 802.1X enterprise, SoftAP hotspots in all security modes, and Wi-Fi Direct / Miracast).
  - **`iwd`**: supports station (`open` and `wpa-personal` with automatic WPA2/WPA3 negotiation) and WPA2-PSK hotspots, with `EnableNetworkConfiguration=false`.

See [Backend Capability Matrix](../reference/failures-and-errors.md#4-backend-capability-matrix) for the exact feature comparison.

---

## 2. Build and Verify Without Touching Your Host

Clone the repository and build the release binaries (`kestrel-daemon` and `kestrel`):

```sh
make build
```

Binaries are placed in `target/release/kestrel-daemon` and `target/release/kestrel`.

Before changing any host services, run the unprivileged end-to-end lab. It starts a real `kestrel-daemon`, `kestrel`, and **real `systemd-networkd`** inside an isolated user/network/mount namespace with no root privileges:

```sh
./crates/kestrel-e2e/run.sh
```

If every scenario passes, your machine has working `systemd-networkd` and `systemd-creds` support. (The lab additionally requires `unshare --map-auto` with subordinate UID/GID ranges, `nsenter`, `dbus-daemon`, and `iproute2`; if you are only installing on a host without user namespaces, you can skip this check and continue to Step 3.)

---

## 3. Install System Files and Initialize State

Install the binaries, systemd unit, tmpfiles snippet, D-Bus policy/activation files, polkit actions, example config, and documentation:

```sh
sudo make install
```

Create `/run/systemd/network` and initialize the `systemd-creds` host key (required once per host):

```sh
sudo systemd-tmpfiles --create kestrel.conf
sudo systemd-creds setup
```

`kestrel-daemon` works with zero configuration file; defaults apply automatically. To customize settings (such as forcing `backend = "iwd"` or adjusting timeouts), copy the template first:

```sh
sudo cp /etc/kestrel/kestrel.toml.example /etc/kestrel/kestrel.toml
```

---

## 4. Prepare L3 and L2 Services

1. Stop any conflicting network manager (skip if not installed):

   ```sh
   sudo systemctl disable --now NetworkManager
   ```

2. Ensure `systemd-networkd` and `systemd-resolved` are running:

   ```sh
   sudo systemctl enable --now systemd-networkd systemd-resolved
   ```

3. Start your chosen L2 backend so it does not fight Kestrel over saved networks or IP addresses:

   - **With `wpa_supplicant`**: enable the stock D-Bus service (`wpa_supplicant -u`) with no saved networks configured for your wireless interface:

     ```sh
     sudo systemctl enable --now wpa_supplicant
     ```

   - **With `iwd`**: ensure `/etc/iwd/main.conf` disables iwd's built-in DHCP/IP stack:

     ```ini
     [General]
     EnableNetworkConfiguration=false
     ```

     Then restart `iwd`:

     ```sh
     sudo systemctl enable --now iwd
     sudo systemctl restart iwd
     ```

4. Reload D-Bus so the new policy and activation files take effect, then enable and start Kestrel:

   ```sh
   sudo systemctl reload dbus
   sudo systemctl enable --now kestrel
   ```

Verify the daemon is active:

```sh
systemctl status kestrel
```

---

## 5. Discover Your Interface and Join a Network

List wireless devices detected by Kestrel:

```sh
kestrel status
```

Find your wireless interface name in the `IFACE` column (for example `wlp0s20f3` or `wlan0`; you can also check `networkctl list`). Replace `wlp0s20f3` in the commands below with your interface name.

Scan for nearby networks:

```sh
kestrel wifi scan wlp0s20f3
```

Join a network by SSID. Kestrel scans to infer the security mode, prompts for the passphrase without echoing it, seals the secret with `systemd-creds`, saves a profile, associates over L2, hands L3 configuration to `systemd-networkd`, and waits until an IP address is configured:

```sh
kestrel wifi join wlp0s20f3 "MyNetwork"
```

> Polkit authorizes active local console sessions to connect without a password prompt. Creating or modifying a saved profile (`wifi join` for a new network, `profile add/edit/delete`) prompts for administrator authentication (`auth_admin_keep`).

Confirm your link status, IP address, DNS, and recent connection history:

```sh
kestrel wifi status wlp0s20f3
kestrel wifi history
resolvectl status wlp0s20f3
```

---

## 6. Rolling Back (If You Are Only Testing)

To remove Kestrel and return to your previous network manager at any time:

```sh
sudo systemctl disable --now kestrel
sudo make uninstall
sudo systemctl enable --now NetworkManager
```

Your saved profiles and encrypted secrets remain in `/var/lib/kestrel/` until you explicitly remove that directory.

---

## Next Steps

- [Install, Switch Backends, and Uninstall](../how-to/install-and-migrate.md): detailed backend setup, `.network.d/` drop-ins, staging with `DESTDIR`/`PREFIX`, and full cleanup.
- [Wi-Fi and Network Profiles](../how-to/wifi-and-profiles.md): priorities, autoconnect control, hidden networks, static IPv4/IPv6, custom DNS, and forgetting networks.
- [802.1X Enterprise Wi-Fi and Certificates](../how-to/enterprise-8021x.md): importing CA/client certificates and configuring PEAP, TTLS, EAP-TLS, or EAP-PWD.
- [Run a Hotspot (SoftAP)](../how-to/hotspot.md): sharing your wireless adapter as an access point.
- [Wi-Fi Direct (P2P) and Miracast](../how-to/p2p-and-miracast.md): peer discovery, GO negotiation, persistent groups, and WFD subelements.
- [Troubleshooting](../how-to/troubleshooting.md): diagnosing startup, permission, credential, and L3 issues.

# Wi-Fi and Network Profiles

This guide covers everyday wireless station tasks: inspecting devices, scanning, connecting to new or saved networks, managing profiles, configuring L3 addressing and DNS, controlling autoconnect, and rotating passphrases.

For 802.1X / WPA-Enterprise profiles and certificates, see [802.1X Enterprise Wi-Fi and Certificates](enterprise-8021x.md).

> On hosts with a single wireless adapter, `kestrel` selects it automatically. On multi-radio hosts, pass `-d <iface>` (or export `KESTREL_DEVICE=<iface>`).

---

## 1. Inspect Devices and Scan

Show an overview of every wireless device, or detailed status for a single device (both support `-w` / `--watch` to refresh once per second):

```sh
kestrel status
kestrel status -w
kestrel status wlp0s20f3
kestrel status wlp0s20f3 -w
```

Trigger an active scan, or display the cached scan results without rescanning (`--cached`). Pass `-a` / `--all` to show every individual BSS instead of the strongest BSS per SSID:

```sh
kestrel wifi scan
kestrel wifi scan --cached --all
```

---

## 2. Connect to a Wi-Fi Network

`kestrel wifi connect <target>` handles both saved profiles and new networks:

- If `<target>` matches a unique saved profile (by UUID, 8+ character prefix, name, or SSID), Kestrel connects to it directly.
- Otherwise, Kestrel treats `<target>` as a new SSID, scans to infer the security mode, prompts for a passphrase (without echoing it), saves a profile, connects, and waits up to 30 seconds for `connected`:

```sh
kestrel wifi connect "HomeWiFi"
```

Useful options:

- **Hidden network**: pass `--hidden` and specify `--security` explicitly (`open`, `owe`, `wpa-personal`, or `wpa3-personal`):

  ```sh
  kestrel wifi connect "HiddenNet" --hidden --security wpa3-personal
  ```

- **Custom label and priority**:

  ```sh
  kestrel wifi connect "HomeWiFi" --name "Home 5GHz" --priority 50
  ```

- **Return immediately without waiting for IP**:

  ```sh
  kestrel wifi connect "HomeWiFi" --no-wait
  ```

- **Force a new passphrase prompt** (even if a secret is already stored):

  ```sh
  kestrel wifi connect "HomeWiFi" --ask-secret
  ```

> `wpa3-personal` enforces SAE-only authentication and never downgrades to WPA2. Use `wpa-personal` for WPA2 or WPA2/WPA3 transition networks (and whenever using the `iwd` backend).

---

## 3. Disconnect, Autoconnect, Radio, and History

Disconnect from the current network and wait until the device is idle. Disconnecting also holds autoconnect (`AutoconnectHeld = true`) so the radio does not immediately reconnect:

```sh
kestrel wifi disconnect
```

Query, pause, or resume autoconnect on a device without changing the current link:

```sh
kestrel wifi autoconnect
kestrel wifi autoconnect off
kestrel wifi autoconnect on
```

Query or toggle the global software radio switch across all devices (persisted in `/var/lib/kestrel/state.toml` across restarts and reboots):

```sh
kestrel radio
kestrel radio off
kestrel radio on
```

View recent station connection events (newest first, default 20; pass `-d <iface>` to filter to one device):

```sh
kestrel wifi history
kestrel wifi history -n 50 -d wlp0s20f3
```

---

## 4. Create and Inspect Profiles Offline

Saved networks live under `/var/lib/kestrel/profiles/<uuid>.toml`, with secrets encrypted separately under `/var/lib/kestrel/secrets/<uuid>.cred`.

List all saved profiles (sorted by priority, highest first) and inspect one:

```sh
kestrel profile list
kestrel profile show "HomeWiFi"
```

Create a profile without immediately connecting:

```sh
kestrel profile add "OfficeGuest" \
  --security wpa-personal \
  --priority 10 \
  --ask-secret
```

Provide a passphrase non-interactively via stdin (secrets are never passed in `argv`):

```sh
printf '%s\n' "$PASSPHRASE" | kestrel profile add "OfficeGuest" \
  --security wpa-personal \
  --secret-stdin
```

Pin a profile to a specific access point BSSID (and unpin later with `--clear-bssid`):

```sh
kestrel profile edit "OfficeGuest" --bssid aa:bb:cc:dd:ee:ff
kestrel profile edit "OfficeGuest" --clear-bssid
```

---

## 5. Configure Autoconnect Priority

Higher integer `--priority` values are preferred during autoconnect (negative values are accepted). Tie-breaking prefers visible over hidden profiles, stronger security, stronger signal, and more recently connected profiles:

```sh
kestrel profile edit "HomeWiFi" --priority 100 --autoconnect true
kestrel profile edit "CoffeeShop" --priority -10 --autoconnect false
```

When creating a profile with `profile add`, pass `--no-autoconnect` to disable automatic connections from the start.

---

## 6. Configure L3 Addressing, IPv6, and DNS

Kestrel passes each profile's L3 policy to `systemd-networkd` through a runtime `.network` unit.

### Static IPv4/IPv6 and Custom DNS

```sh
kestrel profile edit "HomeWiFi" \
  --l3 static \
  --address 192.168.10.50/24 \
  --gateway4 192.168.10.1 \
  --dns 1.1.1.1 \
  --dns 9.9.9.9 \
  --domain home.arpa
```

Repeat `--address`, `--dns`, or `--domain` for multiple values. Clear configured static gateways, DNS servers, or search domains with `--clear-gateway4`, `--clear-gateway6`, `--clear-dns`, or `--clear-domains`.

### DHCP (Default) and IPv6 Control

Switch back to DHCP with automatic IPv6, or disable IPv6 on a DHCP profile:

```sh
kestrel profile edit "HomeWiFi" --l3 dhcp --ipv6 auto
kestrel profile edit "HomeWiFi" --l3 dhcp --ipv6 disabled
```

### Unmanaged L3 (Administrator-Owned `.network` Unit)

To let Kestrel handle only L2 Wi-Fi association while your own static `/etc/systemd/network/*.network` unit manages L3:

```sh
kestrel profile edit "LabNet" --l3 unmanaged
```

With `--l3 unmanaged`, Kestrel installs no runtime `.network` unit for that connection.

---

## 7. Update, Clear, or Delete Credentials and Profiles

Replace or clear a stored passphrase:

```sh
kestrel profile edit "HomeWiFi" --ask-secret
kestrel profile edit "HomeWiFi" --clear-secret
```

Note that changing a profile's `--security` mode automatically clears any kept secret so stale credentials are never reused across security types.

Delete a saved network (disconnects it if active, removes the profile file and its sealed `.cred` file):

```sh
kestrel profile delete "HomeWiFi"
# Non-interactive equivalent:
kestrel profile delete "HomeWiFi" -y
```

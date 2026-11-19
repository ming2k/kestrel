# Wi-Fi and Network Profiles

This guide covers everyday wireless station tasks: inspecting devices, scanning, joining networks, managing saved profiles, configuring L3 addressing and DNS, controlling autoconnect, and rotating passphrases.

For 802.1X / WPA-Enterprise profiles and certificates, see [802.1X Enterprise Wi-Fi and Certificates](enterprise-8021x.md).

---

## 1. Inspect Devices and Scan

Show an overview of every wireless device (add `--watch` to refresh once per second):

```sh
kestrel status
kestrel status --watch
```

Inspect one device in detail (omit `<device>` to inspect the first wireless device):

```sh
kestrel wifi status wlp0s20f3
```

Trigger an active scan or display the cached scan results without rescanning. Pass `--all` to show every individual BSS instead of the strongest BSS per SSID:

```sh
kestrel wifi scan wlp0s20f3
kestrel wifi list wlp0s20f3 --all
```

---

## 2. Join a Wi-Fi Network

`wifi join` scans for the SSID, infers the security mode, prompts for a passphrase (without echoing it), saves or updates the profile, connects, and waits up to 30 seconds for `connected`:

```sh
kestrel wifi join wlp0s20f3 "HomeWiFi"
```

Useful options:

- **Hidden network**: pass `--hidden` and specify `--security` explicitly (`open`, `owe`, `wpa-personal`, or `wpa3-personal`):

  ```sh
  kestrel wifi join wlp0s20f3 "HiddenNet" --hidden --security wpa3-personal
  ```

- **Custom label and priority**:

  ```sh
  kestrel wifi join wlp0s20f3 "HomeWiFi" --name "Home 5GHz" --priority 50
  ```

- **Return immediately without waiting for IP**:

  ```sh
  kestrel wifi join wlp0s20f3 "HomeWiFi" --no-wait
  ```

- **Force a new passphrase prompt** (even if a secret is already stored):

  ```sh
  kestrel wifi join wlp0s20f3 "HomeWiFi" --ask-secret
  ```

> `wpa3-personal` enforces SAE-only authentication and never downgrades to WPA2. Use `wpa-personal` for WPA2 or WPA2/WPA3 transition networks (and whenever using the `iwd` backend).

---

## 3. Connect, Disconnect, and Control Autoconnect

Connect to an existing saved profile by UUID, UUID prefix, profile name, or SSID:

```sh
kestrel wifi connect wlp0s20f3 "HomeWiFi"
```

Disconnect from the current network. Disconnecting also holds autoconnect (`AutoconnectHeld = true`) so the radio does not immediately reconnect:

```sh
kestrel wifi disconnect wlp0s20f3
```

Pause or resume autoconnect on a device without changing the current link:

```sh
kestrel wifi autoconnect wlp0s20f3 off
kestrel wifi autoconnect wlp0s20f3 on
```

Toggle software wireless state across all devices (persisted in `/var/lib/kestrel/state.toml` across restarts and reboots):

```sh
kestrel wifi off
kestrel wifi on
```

View recent connection events (newest first, default 20):

```sh
kestrel wifi history
kestrel wifi history --limit 50
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
kestrel profile add \
  --ssid "OfficeGuest" \
  --security wpa-personal \
  --priority 10 \
  --ask-secret
```

Provide a passphrase non-interactively via stdin (secrets are never passed in `argv`):

```sh
printf '%s\n' "$PASSPHRASE" | kestrel profile add \
  --ssid "OfficeGuest" \
  --security wpa-personal \
  --secret-stdin
```

Pin a profile to a specific access point BSSID (pass `--bssid ""` later to unpin):

```sh
kestrel profile edit "OfficeGuest" --bssid aa:bb:cc:dd:ee:ff
kestrel profile edit "OfficeGuest" --bssid ""
```

---

## 5. Configure Autoconnect Priority

Higher integer `--priority` values are preferred during autoconnect (negative values are accepted). Tie-breaking prefers visible over hidden profiles, stronger security, stronger signal, and more recently connected profiles:

```sh
kestrel profile edit "HomeWiFi" --priority 100 --autoconnect true
kestrel profile edit "CoffeeShop" --priority -10 --autoconnect false
```

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

Repeat `--address`, `--dns`, or `--domain` for multiple values. Clear configured static DNS servers or search domains with `--clear-dns` or `--clear-domains`.

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

## 7. Update, Clear, or Forget Credentials and Profiles

Replace or clear a stored passphrase:

```sh
kestrel profile edit "HomeWiFi" --ask-secret
kestrel profile edit "HomeWiFi" --clear-secret
```

Note that changing a profile's `--security` mode automatically clears any kept secret so stale credentials are never reused across security types.

Forget a saved network (disconnects it if active, removes the profile file and its sealed `.cred` file):

```sh
kestrel wifi forget "HomeWiFi"
# Non-interactive equivalent:
kestrel profile delete "HomeWiFi" --yes
```

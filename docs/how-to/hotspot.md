# Run a Hotspot (SoftAP)

Kestrel turns an AP-capable wireless adapter into a SoftAP hotspot while keeping `systemd-networkd` in charge of L3: Kestrel allocates a `/24` subnet from `[p2p].subnet_pool`, and `systemd-networkd` serves DHCP, advertises the router, and masquerades the uplink. `kestrel-daemon` opens no netlink socket and requires no Linux capabilities.

> **Radio handover & exclusion:** Starting a hotspot takes the radio away from station mode—any active Wi-Fi connection is torn down and station autoconnect is held until the hotspot stops. A hotspot and a Wi-Fi Direct (P2P) session cannot share one device (`Busy`).

---

## 1. Verify Device AP Capability

```sh
kestrel --json status | jq '.devices[] | {interface, capabilities}'
```

Any device listing `access-point` in `capabilities` exports `com.hihusky.Kestrel.Hotspot` and can run a hotspot. When only one AP-capable device exists, `kestrel` selects it automatically; otherwise pass `-d <iface>`.

---

## 2. Start a Hotspot

`hotspot start` waits until the hotspot reaches `active` by default (pass `--no-wait` to return immediately):

```sh
# WPA2-PSK (default) with an interactive, no-echo passphrase prompt (8..=63 chars)
kestrel hotspot start "kestrel-ap"

# Open hotspot on channel 6 (2437 MHz)
kestrel hotspot start "kestrel-ap" --security open -f 2437

# WPA3-SAE hotspot with hidden SSID on a specific device
kestrel hotspot start "kestrel-ap" -d wlp0s20f3 --security wpa3-personal --hidden

# Non-interactive script: passphrase read from the first line of stdin
printf '%s\n' "$AP_PASSPHRASE" | kestrel hotspot start "kestrel-ap" --secret-stdin
```

Security mode support by backend:

| `--security` | `wpa_supplicant` | `iwd` |
| :--- | :--- | :--- |
| `wpa-personal` (default, WPA2-PSK) | Supported | Supported |
| `open` | Supported | Rejected (`NotSupported`) |
| `wpa3-personal` (SAE only) | Supported (requires driver SAE AP support) | Rejected (`NotSupported`) |

---

## 3. Enable Uplink Internet Forwarding

Kestrel writes `IPMasquerade=ipv4` into the hotspot's runtime `.network` unit (`10-kestrel-<link>.network`). For hotspot clients to reach the internet through another interface (for example wired Ethernet `enp3s0`):

1. On `systemd-networkd` 256+, ensure your **uplink** `.network` unit enables IPv4 forwarding:

   ```ini
   # /etc/systemd/network/20-wired.network (or a .network.d/ drop-in)
   [Network]
   IPv4Forwarding=yes
   ```

   Reload networkd with `sudo networkctl reload`.

2. If your host runs a restrictive firewall (`nftables`, `firewalld`, `ufw`), allow DHCP (UDP ports 67/68) on the wireless interface and forwarding from the hotspot subnet (allocated from `[p2p].subnet_pool`, starting at `192.168.49.0/24`).

---

## 4. Inspect Status, Leases, and Clients

```sh
kestrel hotspot status                 # table of every AP-capable device
kestrel hotspot status -d wlp0s20f3    # detailed view including DHCP leases
kestrel --json hotspot status
```

The hotspot progresses through `starting` → `configuring-l3` → `active`:

- `gateway`: CIDR of the served `/24` subnet (`.1` assigned to the AP interface).
- `leases`: DHCPv4 leases (`address`, `client`) handed out by `systemd-networkd`.
- `connected_clients`: currently associated station MAC addresses.

---

## 5. Stop the Hotspot and Restore Station Mode

```sh
kestrel hotspot stop
```

`hotspot stop` waits until the hotspot reaches `stopped` by default. Stopping tears down L3, stops the AP, and restores station orchestration so autoconnect resumes automatically (unless station autoconnect was already held before the hotspot started).

If `kestrel-daemon` is killed abruptly (`kill -9`), the next startup sweep removes tagged `wpa_supplicant` AP blocks, resets `iwd` AP-mode devices back to `station`, and deletes the runtime `.network` unit.

---

## 6. Failure Handling

A failed start always rolls back the AP before returning to `stopped`, restoring station mode automatically.

| `Failure` | Meaning |
| :--- | :--- |
| `not-supported` | Device or backend cannot run an AP with the requested settings (for example `open` or `wpa3-personal` on `iwd`). |
| `no-subnet` | `[p2p].subnet_pool` in `/etc/kestrel/kestrel.toml` has no free `/24` subnet. |
| `l3-failed` | `systemd-networkd` failed to configure the shared subnet or DHCP server. |
| `backend` | The L2 backend failed to bring up the AP; inspect `failure_detail` and `journalctl -u kestrel`. |

# Run a Hotspot (SoftAP)

Kestrel can turn an AP-capable wireless device into a hotspot while keeping
`systemd-networkd` in charge of addressing: Kestrel asks for a shared
subnet, and networkd serves DHCP, advertises the router, and masquerades the
uplink. No netlink socket is opened and `kestrel-daemon` needs no
capabilities.

> Starting a hotspot takes the radio away from the station: any current
> connection is torn down and autoconnect is paused until the hotspot stops.
> A hotspot and a Wi-Fi Direct session cannot share one device (`Busy`).

---

## 1. Check that the device can do it

```sh
kestrel status --json | jq '.devices[] | {interface, capabilities}'
```

A device with `access-point` in `capabilities` exports
`com.hihusky.Kestrel.Hotspot`.

---

## 2. Start a hotspot

```sh
# WPA2 with a prompted passphrase (8..=63 characters)
kestrel hotspot start wlp0s20f3 --ssid "kestrel-ap"

# Open network, channel 6
kestrel hotspot start wlp0s20f3 --ssid "kestrel-ap" --security open --frequency 2437

# Non-interactively: the passphrase comes from stdin, never argv
printf '%s\n' "$AP_PASSPHRASE" | kestrel hotspot start wlp0s20f3 --ssid "kestrel-ap" --secret-stdin
```

`--security` accepts `open`, `wpa-personal` (WPA2-PSK), and
`wpa3-personal` (SAE only). `iwd` supports WPA2-PSK hotspots only; the
others fail with `NotSupported`.

---

## 3. Inspect clients and leases

```sh
kestrel hotspot status wlp0s20f3
kestrel hotspot status --json          # every AP-capable device
```

The state moves through `starting` → `configuring-l3` → `active`. `gateway`
shows the served subnet in CIDR form, `leases` lists the DHCP addresses
networkd handed out, and `connected_clients` lists associated MACs.

> On `systemd-networkd` 256+, `IPMasquerade=ipv4` on the hotspot unit enables
> forwarding on the AP link; ensure your uplink `.network` unit also permits
> IPv4 forwarding (`IPv4Forwarding=yes`) if clients need internet access.

---

## 4. Stop and restore the station

```sh
kestrel hotspot stop wlp0s20f3
```

Stopping releases L3 and the AP, then re-enables station orchestration so
autoconnect can pick the saved profile back up. A `kill -9` leaves nothing
behind: the next start sweeps `wpa_supplicant` AP blocks, resets the `iwd`
device mode to `station`, and removes the runtime `.network` unit.

---

## 5. Failure handling

| `Failure` | Meaning |
|---|---|
| `not-supported` | the device or backend cannot run an AP with these settings (for example `wpa3-personal` on iwd) |
| `no-subnet` | `[p2p].subnet_pool` had no free `/24` |
| `l3-failed` | networkd did not bring the shared subnet up |
| `backend` | the AP itself failed; `FailureDetail` has the backend message |

A failed start always rolls back the AP before reporting, so the device
returns to station mode.

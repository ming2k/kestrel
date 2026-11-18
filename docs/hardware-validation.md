# Hardware validation

The automated suites prove the orchestration logic (unit and property
tests), the adapters (fake `wpa_supplicant`/iwd on a private bus), and the
whole stack against the **real systemd-networkd** (the e2e lab). They cannot
prove driver behaviour. This gate is run by a person with real hardware, and
its evidence is kept.

## Preconditions

- A spare wireless NIC, reached over a console or another interface: the
  test takes it over.
- `systemd-networkd` and `systemd-resolved` running. No other `.network`
  unit matching the test interface with a lower number than `10-`.
- `wpa_supplicant` started with D-Bus control and **no saved networks** for
  the interface (the stock `wpa_supplicant.service` running `wpa_supplicant -u`,
  or `wpa_supplicant -u -i wlp0s20f3 -c /dev/null`), or iwd with
  `EnableNetworkConfiguration=false`.
- Kestrel's system files installed as described in the README's *Install*
  section (D-Bus policy, polkit actions, tmpfiles), and the credential host
  key created with `systemd-creds setup`. `kestrel.service` must **not**
  be running: the script starts its own instance with temporary storage.
  It runs `kestrel` as root, which polkit always authorizes. To test the
  polkit prompts themselves, use `kestrel` as a normal user against an
  installed `kestrel.service` (rows S1 and P4 are good candidates).
- Test APs: WPA2-PSK, WPA2/WPA3 transition, WPA3-SAE only, open, OWE, and a
  hidden SSID. For P2P: an Android phone (Wi-Fi Direct settings) and, if
  available, a Miracast sink.

## One-command smoke test

```sh
KESTREL_HW_PSK='…' ./scripts/hardware-validation.sh \
    --interface wlp0s20f3 --ssid lab-wpa2 --security wpa-personal --yes
```

It builds release binaries, stops NetworkManager, and starts `kestrel-daemon` with
temporary storage. It then adds the profile, waits for autoconnect, and
records `networkctl status`. Next it checks that disconnect removes the unit
and that a graceful stop leaves nothing behind. Last, it restores
NetworkManager. Logs and evidence go to `hw-artifacts-<time>/`.

For virtual kernel-radio validation (two `mac80211_hwsim` radios driving a SoftAP
hotspot, station association, and DHCP without physical hardware):

```sh
./scripts/hwsim-validation.sh
```

## Manual matrix

Record the result, `kestrel --json status`, `networkctl status <if>`, and
the daemon log excerpt for each row. Run every row with
`--backend wpa-supplicant`, and the station rows with `--backend iwd` as well.

### Station

| # | Case | Expected |
|---|------|----------|
| S1 | WPA2-PSK, DHCP | `connected`; address from the AP; DNS visible in `resolvectl status <if>` |
| S2 | Transition AP with a `wpa3-personal` profile (wpa_supplicant) | Associates with SAE (`wpa_cli status` shows `key_mgmt=SAE`) |
| S3 | WPA2-only AP with a `wpa3-personal` profile | Never associates (no downgrade); profile stays eligible, no PSK attempt |
| S4 | Wrong passphrase | `last_failure = auth-failed`; agent prompted once; no retry loop |
| S5 | Hidden SSID (`--hidden true`) | Connects without the SSID in the scan |
| S6 | Static profile (`--l3 static --address … --gateway4 …`) | networkd applies exactly the given values |
| S7 | `--l3 unmanaged` with an admin `.network` file | Kestrel associates and installs no unit |
| S8 | Two profiles, different priorities, both in range | Higher priority wins; after 3 failures of it, the other is used |
| S9 | Roam between two APs with the same SSID | Stays `connected` or briefly `reconnecting`; no L3 rebind |
| S10 | AP powered off for 30 s | `reconnecting`, then `waiting`, then reconnects when the AP returns |
| S11 | Suspend/resume | Reconnects after resume; no duplicate units or network blocks |
| S12 | `rfkill block wifi`, then unblock | Device disappears or goes idle cleanly; returns after unblock |
| S13 | `kill -9 kestrel-daemon` while connected, then restart | Log shows the sweep; one unit and one network block afterwards |
| S14 | `kestrel wifi off`, then `on` | Everything released, then reconnects |
| S15 | `kestrel wifi join <if> <ssid>` (new network) | Profile created/updated, connection reaches `connected`, `kestrel wifi status` shows SSID/address, `wifi history` has a `connected` event |
| S16 | `kestrel wifi autoconnect <if> off`, then `on` | Link stays up; `AutoconnectEnabled` flips false/true; a later drop reconnects only when on |
| S17 | `kestrel wifi forget <ssid> --yes` | Disconnects if active, removes the profile and its secret, history records `disconnected` |

### Wi-Fi Direct (wpa_supplicant only)

| # | Case | Expected |
|---|------|----------|
| P1 | `kestrel p2p find wlp0s20f3` with the phone discoverable | Phone listed with its name and device type |
| P2 | `p2p connect wlp0s20f3 … --go-intent 15`, accept on the phone | Role `group-owner`; `192.168.49.1/24` on `p2p-*`; phone gets a lease; `peer_ip` set |
| P3 | `p2p connect wlp0s20f3 … --go-intent 0` | Role `client`; address from the phone; `peer_ip` is the phone's |
| P4 | Phone-initiated connection with `kestrel agent` running | Agent prompt; accepting creates an incoming session |
| P5 | PIN display (`--display`) | PIN shown by the agent only; phone accepts it |
| P6 | Phone disconnects | Session closes with `peer-disconnected`; unit removed; group gone |
| P7 | Reject on the phone / time out | Session closes with `negotiation-failed` or `timeout`; nothing left |
| P8 | Station connected **and** P2P group active | Both work; tearing one down leaves the other intact |
| P9 | Miracast sink (WFD subelements configured) | Session `ready`; `peer_ip` usable by a casting client |
| P10 | `kestrel p2p start-group wlp0s20f3 --frequency 2412 --wait`, then join from the phone | Role `group-owner`, `autonomous=true`, `peer` empty, `192.168.49.1/24`; phone gets a lease; close removes the group |
| P11 | `p2p connect … --persistent --wait`, close, then `p2p groups list` and `p2p reconnect wlp0s20f3 <group> --peer <mac>` | Group saved with a sealed PSK; the reconnect becomes `ready` without any WPS prompt |
| P12 | `p2p groups delete <group> --yes` while the group is closed | Group and its `.cred` file are gone; `secrets/` keeps no orphan |

### Hotspot (SoftAP)

| # | Case | Expected |
|---|------|----------|
| H1 | `kestrel hotspot start <if> --ssid kestrel-ap --secret-stdin` with a WPA2 client | State `active`; gateway `/24`; client gets a lease from networkd; `connected_clients` lists it; uplink `ping` works through the masquerade |
| H2 | `hotspot status` during H1 | `leases` and `connected_clients` match `networkctl`/the client |
| H3 | `kestrel hotspot stop <if>` | State `stopped`; the station reconnects to its saved profile; no `10-kestrel-*` unit for the AP link remains |
| H4 | Hotspot while a saved profile autoconnects | The station goes `disabled`, autoconnect stays held, and the station returns after the stop |
| H5 | `hotspot start --security open` and `--security wpa3-personal` (both backends) | Both work on `wpa_supplicant` (when the driver supports SAE in AP mode); on `iwd`, every non-`wpa-personal` mode fails with `not-supported` and leaves the AP off |
| H6 | `kill -9` during an active hotspot, then start the daemon | Log shows the sweep; `Device.Mode` is `station` again (iwd) or the AP block is gone (wpa_supplicant); the station reconnects |

### 802.1X / WPA-Enterprise (wpa_supplicant only)

| # | Case | Expected |
|---|------|----------|
| E1 | `certificate add corp-ca.pem --name "Corp CA"`, then `profile add --ssid corp-wifi --security wpa-enterprise --eap peap --identity … --phase2 mschapv2 --ca-cert "Corp CA" --ask-secret` | `connected`; RADIUS accepts; `resolvectl` shows the served address |
| E2 | `certificate delete <id>` while the profile exists | Fails with `Busy`; succeeds once the profile is deleted |
| E3 | Profile setting both `enterprise.ca_cert` and `enterprise.system_ca = true` | Rejected at profile validation (`InvalidArgument`); `wpa_supplicant` never sees a half-configured server-verification policy |
| E4 | `profile add --ssid corp-wifi --security wpa3-enterprise --eap tls --identity … --ca-cert … --client-cert … --private-key-file alice.key` | `connected`; `wpa_cli` shows the TLS method; no key material appears in `/var/lib/kestrel` or in `journalctl -u kestrel` |
| E5 | `wpa3-enterprise` profile against a WPA2-Enterprise-only AP | Never associates (no downgrade); failure recorded in history |
| E6 | Enterprise profile on the iwd backend | `NotSupported`; `Device.SupportedSecurity` omits the enterprise modes |
| E7 | Host key reset (`systemd-creds setup` forced) with an EAP-TLS profile | Credential quarantined as `*.cred.invalid`; profile reports `secrets-required`; the agent supplies a fresh key |

## Pass/fail rules

- Every row's expected outcome holds.
- After every row: `ls /run/systemd/network/10-kestrel-*` lists only
  bindings for live connections, and `wpa_cli list_networks` shows only
  `id_str=kestrel` blocks for live connections.
- No secret appears in any log, in `kestrel --json` output, or in
  `/var/lib/kestrel/profiles`, `/var/lib/kestrel/certs`, or
  `/var/lib/kestrel/p2p-groups`.
- After the P2P and hotspot rows: `kestrel p2p sessions` and
  `kestrel hotspot status` show nothing left active, and no `kestrel-*`
  blobs remain in `wpa_supplicant` (`wpa_cli` has no `blob://kestrel-*`).

## Known limitations to record

- iwd cannot enforce WPA3-only, OWE-only, or any 802.1X mode; such profiles
  are rejected with `NotSupported` (S2/S3/E6 apply to wpa_supplicant only),
  and iwd hotspots accept `wpa-personal` only.
- A hotspot and a Wi-Fi Direct session cannot share one device: the second
  request fails with `Busy` until the first is torn down.
- With some drivers and older `wpa_supplicant`, a wrong SAE password does
  not raise `PskMismatch`. It then surfaces as an association timeout, not
  `auth-failed`. Record the version if seen.
- `DHCPServer.PersistLeases=runtime` needs systemd ≥ 257. On older versions
  the key is ignored, and the GO's DHCP server may wait for persistent
  storage.

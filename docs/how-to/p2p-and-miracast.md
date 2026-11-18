# Use Wi-Fi Direct (P2P) and Miracast

Kestrel orchestrates Wi-Fi Direct (P2P) end to end when using the `wpa_supplicant` backend: peer discovery, WPS, GO negotiation or autonomous Group Owner (GO), and role-appropriate L3 configuration via `systemd-networkd`.

---

## 1. Discover Peers

Scan for nearby P2P peers on a wireless interface:

```sh
kestrel p2p find wlp0s20f3 --timeout 30
```

List currently known peers without starting a new scan:

```sh
kestrel p2p peers wlp0s20f3
```

---

## 2. Connect to a Peer (GO Negotiation)

Connect to a peer by its P2P device address using `--go-intent` (`0..=15`, higher prefers becoming Group Owner):

```sh
kestrel p2p connect wlp0s20f3 02:11:22:33:44:55 --go-intent 15 --wait
```

Interactive WPS methods:
- `--keypad`: prompt on the terminal (no echo) for a PIN shown by the peer.
- `--pin-stdin`: read the peer's PIN from the first line of standard input (for scripts; PINs never pass in `argv`).
- `--display`: generate a PIN and deliver it to the registered agent (for example `kestrel agent` running in another terminal).
- Omit all three for WPS push-button (PBC).

---

## 3. Start an Autonomous Group (GO)

To start a P2P group directly as Group Owner without GO negotiation:

```sh
kestrel p2p start-group wlp0s20f3 --frequency 2412 --wait
```

When the group starts:
- Kestrel allocates a `/24` subnet from `[p2p].subnet_pool`, assigns `.1` to the GO interface, and configures `systemd-networkd` as a DHCP server (offering no default route).
- Kestrel arms WPS push-button on the group interface for one client. To accept another client later, close the group and start a new one.

---

## 4. Save a Persistent Group (Reconnect Without WPS)

Add `--persistent` to either command to keep the group after the session
ends:

```sh
kestrel p2p connect wlp0s20f3 02:11:22:33:44:55 --go-intent 15 --persistent --wait
kestrel p2p start-group wlp0s20f3 --frequency 2412 --persistent --wait
```

Kestrel seals the group PSK with `systemd-creds` and saves the group's SSID,
role, and group owner address under `/var/lib/kestrel/p2p-groups/`. Later
reconnects skip WPS entirely:

```sh
kestrel p2p groups list
kestrel p2p reconnect wlp0s20f3 <group>                       # re-start as owner
kestrel p2p reconnect wlp0s20f3 <group> --peer 02:11:22:33:44:55  # invite a peer
kestrel p2p groups delete <group> --yes                       # forget it
```

`wpa_supplicant` is cleared of any internal persistent-group table at start
and shutdown, so Kestrel's store is the only source of truth.

---

## 5. Inspect and Close Sessions

```sh
# List active P2P sessions (including role, group interface, and peer IP)
kestrel p2p sessions --json

# Tear down a session (releases L3 and removes the P2P group interface)
kestrel p2p close <session_id>
```

For Miracast / Wi-Fi Display (WFD) consumers, advertise or clear WFD subelements with `kestrel p2p wfd <device> <HEX|clear>` (or `P2P.SetWfdSubelements` over D-Bus). `kestrel-api` exposes `PeerIp` on `com.hihusky.Kestrel.Session` and WFD subelements on `GetPeers()` and `PeerFound`.

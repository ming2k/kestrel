# Wi-Fi Direct (P2P) and Miracast

Kestrel orchestrates Wi-Fi Direct (P2P) end to end: peer discovery, WPS provisioning, Group Owner (GO) negotiation or autonomous GO creation, persistent groups for WPS-free reconnection, and role-appropriate L3 configuration via `systemd-networkd`.

> **Backend requirement:** Wi-Fi Direct requires the **`wpa_supplicant`** backend on a P2P-capable adapter (`p2p` in `Device.Capabilities`). `iwd` does not provide P2P. A P2P session and a SoftAP hotspot cannot run concurrently on the same device (`Busy`).

---

## 1. Run an Agent for Incoming Requests and PIN Display

If a peer initiates a connection to you, or if you connect using `--display` (showing a generated PIN), run `kestrel agent` in a terminal so Kestrel can deliver prompts and PINs:

```sh
kestrel agent
```

See [Scripting, Agents, and Polkit](scripting-and-agents.md#3-interactive-agent-kestrel-agent) for details.

---

## 2. Discover Peers

Scan for nearby P2P peers on a wireless interface (default timeout `30` seconds; range `1..=600` over D-Bus):

```sh
kestrel p2p find wlp0s20f3 --timeout 30
```

List currently known peers and any advertised Wi-Fi Display (WFD) subelements without starting a new scan:

```sh
kestrel p2p peers wlp0s20f3
```

---

## 3. Connect to a Peer (GO Negotiation)

Connect by P2P device MAC address. Set `--go-intent` (`0..=15`; higher prefers becoming Group Owner, default `7` from `[p2p].go_intent`):

```sh
# Prefer becoming Group Owner, WPS push-button (PBC), wait until ready or closed
kestrel p2p connect wlp0s20f3 02:11:22:33:44:55 --go-intent 15 --wait
```

WPS provisioning options:

- **Push-button (PBC)**: omit all PIN flags (default).
- **`--keypad`**: prompt on the terminal (no echo) for a PIN displayed by the peer.
- **`--pin-stdin`**: read the peer's PIN from the first line of standard input (for scripts; PINs never pass in `argv`).
- **`--display`**: generate a PIN and send it to the registered agent (`kestrel agent`).

Add `--wait` (with optional `--timeout <SECONDS>`, default `60`) to block until the session reaches `ready` or `closed`.

Once the group forms, Kestrel configures L3 automatically by role:

- **As `group-owner`**: allocates a `/24` from `[p2p].subnet_pool`, assigns `.1` to the `p2p-*` group interface, and starts `systemd-networkd`'s DHCP server (without advertising a default route).
- **As `client`**: runs an anonymous DHCP client (RFC 7844) on the group interface that does not affect host `OnlineState`.

---

## 4. Start an Autonomous Group (GO)

Start a group directly as Group Owner without peer GO negotiation:

```sh
kestrel p2p start-group wlp0s20f3 --frequency 2412 --wait
```

When an autonomous group starts:

- Kestrel configures the `/24` shared subnet and DHCP server via `systemd-networkd`.
- Kestrel arms WPS push-button on the group interface for **one** joining client. Close the session and start a new group to pair another client.

---

## 5. Save and Reconnect Persistent Groups (No WPS)

Pass `--persistent` to `p2p connect` or `p2p start-group` to save the group once formed:

```sh
kestrel p2p connect wlp0s20f3 02:11:22:33:44:55 --go-intent 15 --persistent --wait
kestrel p2p start-group wlp0s20f3 --frequency 2412 --persistent --wait
```

Kestrel seals the group PSK with `systemd-creds` (`secrets/p2p-<uuid>.cred`) and saves the group metadata (`SSID`, role, GO address, peer) under `/var/lib/kestrel/p2p-groups/`. `wpa_supplicant`'s internal persistent-group table is cleared at startup and shutdown so Kestrel's store remains the sole source of truth.

List, inspect, reconnect without WPS, or delete saved groups (accepts UUID, UUID prefix, name, or SSID):

```sh
kestrel p2p groups list
kestrel p2p groups show <group>

# Restart the saved group autonomously as Group Owner
kestrel p2p reconnect wlp0s20f3 <group> --wait

# Invite a specific peer into the saved group without WPS
kestrel p2p reconnect wlp0s20f3 <group> --peer 02:11:22:33:44:55 --wait

# Delete a saved group and its sealed PSK
kestrel p2p groups delete <group> --yes
```

---

## 6. Inspect and Close Active Sessions

List active P2P sessions (including `role`, `group_interface`, and `peer_ip`):

```sh
kestrel p2p sessions
kestrel --json p2p sessions
```

Close a session by its numeric session ID (for example `1`) or full D-Bus object path (`/com/hihusky/Kestrel/Session/1`):

```sh
kestrel p2p close 1
```

Closing releases L3 first, then removes the `p2p-*` group interface. Station Wi-Fi connections on the same device remain intact if the wireless driver supports concurrent station + P2P operation.

---

## 7. Miracast / Wi-Fi Display (WFD)

Advertise WFD subelements on a wireless device during discovery and group formation (even-length hex string; `:`, `-`, and spaces are ignored; maximum 1024 bytes):

```sh
kestrel p2p wfd wlp0s20f3 000600101c440032
```

Clear WFD advertisement (accepts `clear` or `none`):

```sh
kestrel p2p wfd wlp0s20f3 clear
```

Casting consumers read peer WFD subelements from `kestrel --json p2p peers <device>` (or `P2P.GetPeers()` / `PeerFound` over D-Bus) and connect their RTSP/streaming stack to `PeerIp` once `Session.State` reaches `ready`.

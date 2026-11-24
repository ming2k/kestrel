# Wi-Fi Direct (P2P) and Miracast

Kestrel orchestrates Wi-Fi Direct (P2P) end to end: peer discovery, WPS provisioning, Group Owner (GO) negotiation or autonomous GO creation, persistent groups for WPS-free reconnection, and role-appropriate L3 configuration via `systemd-networkd`.

> **Backend requirement:** Wi-Fi Direct requires the **`wpa_supplicant`** backend on a P2P-capable adapter (`p2p` in `Device.Capabilities`). `iwd` does not provide P2P. A P2P session and a SoftAP hotspot cannot run concurrently on the same device (`Busy`).
>
> When only one P2P-capable device exists, `kestrel` selects it automatically; otherwise pass `-d <iface>` (or export `KESTREL_DEVICE`).

---

## 1. Run an Agent for Incoming Requests and PIN Display

If a peer initiates a connection to you, or if you connect using `--wps display` (showing a generated PIN), run `kestrel agent` in a terminal so Kestrel can deliver prompts and PINs:

```sh
kestrel agent
```

See [Scripting, Agents, and Polkit](scripting-and-agents.md#3-interactive-agent-kestrel-agent) for details.

---

## 2. Discover and List Peers

Actively discover nearby P2P peers (default timeout `30` seconds; range `1..=600` over D-Bus):

```sh
kestrel p2p peer find -t 30
```

List currently known peers and any advertised Wi-Fi Display (WFD) subelements without starting a new discovery:

```sh
kestrel p2p peer list
```

---

## 3. Connect to a Peer (GO Negotiation)

Connect by P2P device MAC address. Set `--go-intent` (`0..=15`; higher prefers becoming Group Owner, default `7` from `[p2p].go_intent`). `p2p connect` waits until the session reaches `ready` by default (pass `--no-wait` to return immediately with the session ID):

```sh
# Prefer becoming Group Owner, WPS push-button (PBC), wait until ready
kestrel p2p connect 02:11:22:33:44:55 --go-intent 15
```

WPS provisioning options:

- **`--wps pbc`** (default): push-button configuration.
- **`--wps keypad`**: prompt on the terminal (no echo) for a PIN displayed by the peer.
- **`--pin-stdin`**: read the peer's PIN from the first line of standard input (implies `--wps keypad`; PINs never pass in `argv`).
- **`--wps display`**: generate a PIN and deliver it to the registered agent (`kestrel agent`).

Tune the wait deadline with `-t, --timeout <SECONDS>` (default `60`).

Once the group forms, Kestrel configures L3 automatically by role:

- **As `group-owner`**: allocates a `/24` from `[p2p].subnet_pool`, assigns `.1` to the `p2p-*` group interface, and starts `systemd-networkd`'s DHCP server (without advertising a default route).
- **As `client`**: runs an anonymous DHCP client (RFC 7844) on the group interface that does not affect host `OnlineState`.

---

## 4. Start an Autonomous Group (GO)

Start a group directly as Group Owner without peer GO negotiation:

```sh
kestrel p2p start-group -f 2412
```

When an autonomous group starts:

- Kestrel configures the `/24` shared subnet and DHCP server via `systemd-networkd`.
- Kestrel arms WPS push-button on the group interface for **one** joining client. Close the session and start a new group to pair another client.

---

## 5. Save and Reconnect Persistent Groups (No WPS)

Pass `--persistent` to `p2p connect` or `p2p start-group` to save the group once formed:

```sh
kestrel p2p connect 02:11:22:33:44:55 --go-intent 15 --persistent
kestrel p2p start-group -f 2412 --persistent
```

Kestrel seals the group PSK with `systemd-creds` (`secrets/p2p-<uuid>.cred`) and saves the group metadata (`SSID`, role, GO address, peer) under `/var/lib/kestrel/p2p-groups/`. `wpa_supplicant`'s internal persistent-group table is cleared at startup and shutdown so Kestrel's store remains the sole source of truth.

List, inspect, reconnect without WPS, or delete saved groups (accepts UUID, 8+ char prefix, name, or SSID):

```sh
kestrel p2p group list
kestrel p2p group show <group>

# Restart the saved group autonomously as Group Owner
kestrel p2p reconnect <group>

# Invite a specific peer into the saved group without WPS
kestrel p2p reconnect <group> --peer 02:11:22:33:44:55

# Delete a saved group and its sealed PSK
kestrel p2p group delete <group> -y
```

---

## 6. Inspect and Close Active Sessions

List or inspect active P2P sessions (including numeric `ID`, `device`, `role`, `group_interface`, and `peer_ip`):

```sh
kestrel p2p session list
kestrel p2p session show 1
kestrel --json p2p session list
```

Close a session by its numeric session ID (for example `1`) or full D-Bus object path (`/com/hihusky/Kestrel/Session/1`):

```sh
kestrel p2p session close 1
```

Closing releases L3 first, then removes the `p2p-*` group interface. Station Wi-Fi connections on the same device remain intact if the wireless driver supports concurrent station + P2P operation.

---

## 7. Miracast / Wi-Fi Display (WFD)

Advertise WFD subelements on a wireless device during discovery and group formation (even-length hex string; `:`, `-`, and spaces are ignored; maximum 1024 bytes):

```sh
kestrel p2p wfd set 000600101c440032
```

Stop advertising WFD subelements:

```sh
kestrel p2p wfd clear
```

Casting consumers read peer WFD subelements from `kestrel --json p2p peer list` (or `P2P.GetPeers()` / `PeerFound` over D-Bus) and connect their RTSP/streaming stack to `PeerIp` once `Session.State` reaches `ready`.

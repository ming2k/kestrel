# D-Bus API: `com.hihusky.Kestrel`

API version 1. Breaking changes bump the version and bus name.

## Conventions

- **Discovery.** The root object `/com/hihusky/Kestrel` implements
  `org.freedesktop.DBus.ObjectManager`. Watch `InterfacesAdded`/`Removed`
  and `PropertiesChanged`; never poll.
- **Returned paths are live.** A method that returns an object path (for
  example `AddProfile`, `ImportCertificate`, or `P2P.Connect`) replies only
  after the object is exported.
- **Errors.** Branch on the error *name*; the message is for humans.

  | Name (`com.hihusky.Kestrel.Error.`) | Meaning |
  |---|---|
  | `NoSuchDevice`, `NoSuchProfile`, `NoSuchSession` | Unknown target |
  | `NoSuchCertificate`, `NoSuchP2pGroup` | Unknown saved certificate or persistent group |
  | `WirelessDisabled` | Wireless is off |
  | `NotSupported` | The device or backend cannot do it |
  | `Busy` | Another session, hotspot, or agent holds the resource |
  | `InvalidArgument` | Validation failed |
  | `AccessDenied` | polkit said no |
  | `Storage`, `Backend` | Persistence or daemon failure |
  | `Stopped` | Kestrel is shutting down |

- **Failure codes** in `LastFailure` and `Failure` are stable strings:
  `auth-failed`, `secrets-required`, `not-found`, `timeout`, `link-lost`,
  `l3-failed`, `negotiation-failed`, `wps-failed`, `peer-disconnected`,
  `no-subnet`, `device-unavailable`, `cancelled`, `not-supported`, and
  `backend`. The `…Detail` properties are diagnostic text only.
- **Authorization.** Every mutating method checks one polkit action:
  `com.hihusky.kestrel.connect`, `.hotspot`, `.modify-profiles`,
  `.toggle-wireless`, or `.register-agent` (defaults in
  `data/com.hihusky.kestrel.policy`). Reads are unrestricted.
- **Activation.** Calling the name starts `kestrel.service` through
  D-Bus activation (`data/com.hihusky.Kestrel.service`).
- **Drift check.** A test introspects the running server and fails if this
  document's member lists differ from what is exported.
- **Secrets** are write-only. No property or method returns a secret.

## `/com/hihusky/Kestrel`: `com.hihusky.Kestrel.Manager`

| Member | Signature | Notes |
|---|---|---|
| `Version` | property `s` | `"1"`; clients reject anything else |
| `WirelessEnabled` | property `b` | software toggle (persisted across daemon restarts) |
| `WirelessHardwareEnabled` | property `b` | `false` when hardware rfkill blocks wireless |
| `OnlineState` | property `s` | `offline`, `partial`, `online`, or `unknown` |
| `SetWirelessEnabled(enabled)` | `b → ()` | `toggle-wireless` |
| `AddProfile(settings, secret)` | `a{sv} a{ss} → o` | `modify-profiles`; `secret` maps `passphrase`, `private_key`, and `private_key_password`; an empty bundle means none (the agent is asked on first use) |
| `ImportCertificate(name, pem)` | `s s → o` | `modify-profiles`; imports a public X.509 PEM certificate or CA bundle and returns its object path |
| `History(limit)` | `u → a(tsssss)` | recent connection events, newest first: `(unix_seconds, device, ssid, profile_id, outcome, detail)`; `0` returns an empty list, capped at `500` |
| `RegisterAgent(path)` | `o → ()` | `register-agent`; one agent at a time (`Busy`), dropped when its owner leaves the bus |
| `UnregisterAgent(path)` | `o → ()` | owner only |

## `…/Device/<name>`: `com.hihusky.Kestrel.Device`

`<name>` is the interface name with every non-alphanumeric byte written as
`_XX` (`p2p-wlp0s20f3-0` becomes `p2p_2dwlp0s20f3_2d0`).

| Member | Signature | Notes |
|---|---|---|
| `Interface`, `HardwareAddress` | `s` | |
| `Capabilities` | `as` | subset of `station`, `p2p`, `access-point` |
| `SupportedSecurity` | `as` | exact set of profile security modes the backend can enforce (`open`, `owe`, `wpa-personal`, `wpa3-personal`, `wpa-enterprise`, `wpa3-enterprise`) |
| `State` | `s` | `disabled`, `idle`, `associating`, `configuring-l3`, `connected`, `reconnecting`, `waiting` |
| `Ssid` | `s` | SSID of the active profile, empty when idle |
| `ActiveProfile` | `o` | `/` when none |
| `Bssid` | `s` | when connected |
| `Frequency` | `u` | MHz of the current BSS, or 0 when unknown |
| `Security` | `s` | active security mode when connected, or empty |
| `Signal` | `n` | dBm of the current BSS, or 0 when unknown |
| `Addresses` | `as` | addresses configured on the link |
| `Gateways` | `as` | default gateways configured on the link |
| `Dns` | `as` | DNS servers configured on the link |
| `L3Phase` | `s` | `pending`, `ready`, or `failed` |
| `OnlineState` | `s` | `offline`, `partial`, `online`, or `unknown` |
| `Scanning` | `b` | |
| `LastFailure`, `LastFailureDetail` | `s` | |
| `AutoconnectHeld` | `b` | true after a user disconnect or `SetAutoconnect(false)` |
| `AutoconnectEnabled` | `b` | inverse of `AutoconnectHeld` |
| `ProfilesNeedingSecrets` | `ao` | |
| `Scan()` | | `connect` |
| `Connect(profile)` | `o` | `connect` |
| `Disconnect()` | | `connect`; also holds autoconnect |
| `SetAutoconnect(enabled)` | `b` | `connect`; enable or disable autoconnect without changing the link |
| `GetScanResults()` | `→ a(ssunso)` | `(ssid, bssid, MHz, dBm, security, profile)`, strongest first; `profile` is `/` when unsaved |
| `ScanResultsChanged` | signal | |

## `…/Device/<name>`: `com.hihusky.Kestrel.P2P` (capable devices)

| Member | Signature | Notes |
|---|---|---|
| `Finding` | property `b` | |
| `Find(timeout_seconds)` | `u` | `connect`; 1..=600 |
| `StopFind()` | | `connect` |
| `SetWfdSubelements(subelements)` | `ay` | `connect`; Wi-Fi Display subelements advertised during discovery and group formation (empty disables WFD; max 1024 bytes) |
| `GetPeers()` | `→ a(sssay)` | `(address, name, device type, WFD subelements)` |
| `Connect(peer, method, pin, go_intent, persistent)` | `s s s y b → o` | `connect`; `method` is `pbc`, `display` (PIN goes to the agent), or `keypad` (enter `pin`); `go_intent` is 0..=15, or 255 for the default; `persistent` saves the group for WPS-free reconnection. One session per device (`Busy`). |
| `StartGroup(frequency, persistent)` | `u b → o` | `connect`; autonomous GO: starts a group as owner without GO negotiation. `frequency` is the operating channel in MHz, or 0 to let the backend choose. The group SSID is generated by the backend, and WPS push-button is armed so one client can join. One session per device (`Busy`). |
| `ConnectPersistent(group, peer, frequency)` | `o s u → o` | `connect`; invites `peer` (empty for a group-wide invite) into a saved `P2pGroup`, skipping WPS |
| `StartPersistentGroup(group, frequency)` | `o u → o` | `connect`; re-starts a saved group autonomously as owner |
| `PeerFound(address, name, device_type, wfd)` | signal | |
| `PeerLost(address)` | signal | |

## `…/Device/<name>`: `com.hihusky.Kestrel.Hotspot` (access-point capable devices)

| Member | Signature | Notes |
|---|---|---|
| `State` | `s` | `stopped`, `starting`, `configuring-l3`, or `active` |
| `Ssid`, `Security` | `s` | configured SSID and hotspot security (`open`, `wpa-personal`, `wpa3-personal`) |
| `Frequency` | `u` | operating channel in MHz, or 0 when stopped |
| `Gateway` | `s` | CIDR of the served subnet, empty when stopped |
| `Leases` | `a(ss)` | `(ipv4_address, client_mac)` served by the hotspot's DHCP server |
| `ConnectedClients` | `as` | associated client MAC addresses |
| `Failure`, `FailureDetail` | `s` | |
| `Start(settings, secret)` | `a{sv} s` | `hotspot`; settings keys are `ssid` (required), `security`, `frequency`, `hidden`. `secret` is required for `wpa-personal` and `wpa3-personal`. Starting a hotspot takes the radio away from the station and refuses while a P2P session is active (`Busy`). |
| `Stop()` | | `hotspot`; releases L3 and restores station operation |

## `…/Certificate/<id>`: `com.hihusky.Kestrel.Certificate`

Imported public X.509 material for 802.1X profiles. The PEM text and private
keys are never readable over D-Bus.

| Member | Signature | Notes |
|---|---|---|
| `Id` | `s` | UUID |
| `Name` | `s` | label given at import |
| `FingerprintSha256` | `s` | colon-separated uppercase hex of the first certificate |
| `Delete()` | | `modify-profiles`; refuses with `Busy` while a saved profile references it |

## `…/P2pGroup/<id>`: `com.hihusky.Kestrel.P2pGroup`

A saved persistent Wi-Fi Direct group. The group PSK is sealed in
`systemd-creds` and is never exported.

| Member | Signature | Notes |
|---|---|---|
| `Id` | `s` | UUID |
| `Name` | `s` | label |
| `Ssid` | `s` | group SSID used by the backend |
| `Role` | `s` | `group-owner` or `client` |
| `GoAddress` | `s` | group owner device address |
| `Peer` | `s` | peer device address, empty for an autonomous group |
| `LastConnected` | `t` | Unix seconds, 0 if never |
| `Delete()` | | `modify-profiles`; removes the group and its sealed PSK |

## `…/Profile/<id>`: `com.hihusky.Kestrel.Profile`

| Member | Signature | Notes |
|---|---|---|
| `Id` | `s` | UUID |
| `Settings` | `a{sv}` | see below; never contains a secret |
| `HasSecret` | `b` | |
| `LastConnected` | `t` | Unix seconds, 0 if never |
| `Update(settings, secret_action, secret)` | `a{sv} s a{ss}` | `modify-profiles`; merges `settings`; `secret_action` is `keep`, `set`, or `clear`; `secret` maps `passphrase`, `private_key`, and `private_key_password`; changing `security` or `enterprise.eap` clears a kept secret |
| `Delete()` | | `modify-profiles`; removes the profile and its secret; disconnects if active |

Settings keys (all optional on update; `ssid` and `security` are required
on create):

| Key | Type | Values |
|---|---|---|
| `name` | s | label |
| `ssid` | s | 1–32 bytes |
| `security` | s | `open`, `owe`, `wpa-personal` (WPA2, accepting WPA3 transition), `wpa3-personal` (SAE only, never downgrades), `wpa-enterprise`, `wpa3-enterprise` (SHA-256/Suite-B only, never downgrades) |
| `hidden`, `autoconnect` | b | |
| `priority` | i | higher wins |
| `bssid` | s | pin; `""` clears |
| `l3` | s | `dhcp`, `static`, or `unmanaged` (Kestrel binds no L3) |
| `ipv6` | s | `auto` or `disabled` (with `dhcp`) |
| `addresses`, `dns`, `domains` | as | with `static` |
| `gateway4`, `gateway6` | s | with `static`; `""` for none |
| `enterprise.eap` | s | `tls`, `peap`, `ttls`, or `pwd` |
| `enterprise.identity` | s | outer EAP identity |
| `enterprise.anonymous_identity` | s | optional outer identity |
| `enterprise.phase2` | s | `mschapv2`, `pap`, `chap`, `mschap`, or `gtc` (PEAP/TTLS) |
| `enterprise.ca_cert` | s | imported `Certificate` id; `""` clears |
| `enterprise.system_ca` | b | trust the host CA store instead of a pinned CA |
| `enterprise.client_cert` | s | imported `Certificate` id for EAP-TLS; `""` clears |
| `enterprise.domain_suffix_match` | s | RADIUS server name suffix |
| `enterprise.altsubject_match` | as | accepted SubjectAltName patterns |

## `…/Session/<n>`: `com.hihusky.Kestrel.Session`

One Wi-Fi Direct connection. It is removed when it closes, and the last
`PropertiesChanged` carries the outcome.

| Member | Signature | Notes |
|---|---|---|
| `Device` | `o` | |
| `Peer` | `s` | P2P device address; empty for an autonomous group |
| `Incoming` | `b` | |
| `Autonomous` | `b` | true when started by `P2P.StartGroup` or `P2P.StartPersistentGroup` |
| `State` | `s` | `negotiating`, `forming`, `configuring-l3`, `ready`, `closed` |
| `Role` | `s` | `group-owner`, `client`, or empty |
| `GroupInterface` | `s` | |
| `PeerIp` | `s` | as GO, the lease handed out; as client, the GO's address |
| `Failure`, `FailureDetail` | `s` | |
| `Close()` | | `connect`; unbinds L3, then removes the group |

## Agent: `com.hihusky.Kestrel.Agent` (exported by a consumer)

| Method | Signature | Notes |
|---|---|---|
| `RequestSecret(device, profile, ssid, security, reason)` | `o o s s s → s` | `reason` is a failure code; decline with `com.hihusky.Kestrel.Agent.Error.Declined` |
| `AuthorizePeer(device, peer, name, method)` | `o s s s → (ss)` | `method` is `pbc` or `pin`; return `(method, pin)` with `pbc`, `display`, or `keypad`; decline with the same error |
| `DisplayPin(session, peer, pin)` | `o s s` | The only place a generated PIN is sent |

Calls into the agent time out after `timeouts.agent` seconds (default and
maximum 120). On the system bus, the shipped D-Bus policy lets only Kestrel
call `com.hihusky.Kestrel.Agent` methods on clients.

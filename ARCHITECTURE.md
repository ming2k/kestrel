# Architecture

## Position

Kestrel is middleware between Linux networking daemons (southbound) and
their consumers (northbound). It orchestrates; it does not implement
networking.

```text
   desktop shell · settings panel · casting service · kestrel
                         │  com.hihusky.Kestrel (D-Bus) / kestrel_api::client
┌────────────────────────▼──────────────────────────────────────────────┐
│ kestrel-api       ObjectManager tree, polkit, agent bridge,            │
│                   device/profile/certificate/group/session objects     │
├────────────────────────┬───────────────────────────────────────────────┤
│ kestrel-controller     │ kestrel-catalog                               │
│ coordinator · drivers  │ profiles · secrets · certs · P2P groups ·     │
│ FIFO Executor · sweep  │ history (referential integrity + events)      │
├────────────────────────┤                                               │
│ kestrel-machines       │                                               │
│ Station · P2pSession · │                                               │
│ Hotspot   (sans-IO)    │                                               │
├────────────────────────┴────┬──────────────────────┬───────────────────┤
│ kestrel-ports  (traits)     │ kestrel-model        │ kestrel-store     │
└───────▲───────────▲─────────┴──────────────────────┴───────▲───────────┘
        │           │                                        │
 kestrel-wlan-wpa  kestrel-wlan-iwd   kestrel-l3-networkd    systemd-creds
 (fi.w1.wpa_supplicant1) (net.connman.iwd) (org.freedesktop.network1)
```

## Rules

- `kestrel-model` and `kestrel-machines` have no async runtime and no I/O.
  `kestrel-machines` depends only on `kestrel-model` and contains only
  `handle(now, input) -> Vec<Command>` state machines.
- `kestrel-catalog` depends only on `kestrel-model` and `kestrel-ports`.
- `kestrel-controller` depends on `kestrel-machines`, `kestrel-catalog`,
  `kestrel-model`, and `kestrel-ports`, never on a concrete adapter.
- `kestrel-api` depends on `kestrel-controller`, `kestrel-catalog`,
  `kestrel-ports`, and `kestrel-model`, never on `kestrel-machines` or a
  concrete adapter.
- Every persisted kind (profiles, certificates, persistent P2P groups) is
  reached through a `kestrel-ports` trait, owned in-memory by
  `kestrel-catalog`, and exported as its own D-Bus object.
- `kestrel-daemon` is the only crate that names a concrete adapter.
- **Zero L3 competition.** No crate opens a netlink socket, sends a DHCP
  packet, writes a sysctl, or touches `resolv.conf`. L3 is an
  [`L3Intent`](crates/kestrel-ports/src/l3.rs) handed to the L3 provider.
- `unsafe` is forbidden workspace-wide.

## State machines (sans-IO)

Each machine is a struct with `handle(now, input) -> Vec<Command>`:

- **Time is an input.** Timeouts are `StartTimer` commands. Expiries return
  with a token, and stale tokens are ignored, so drivers never cancel.
- **Rollback is data.** A machine records each resource it holds
  (association, L3 binding, negotiation, group) in order. Every exit path
  releases them in reverse. Property tests feed random event sequences
  (512 station cases, 1,024 session cases per run). They check that nothing
  is ever held twice, that L3 is never bound without L2, that resources are
  released in order, and that an idle or closed machine holds nothing.

**Station** (one per wireless device):

```text
Disabled ─enable→ Idle ─select/user→ Associating ─link up→ ConfiguringL3 ─ready→ Connected
                   ▲                     │ fail                 │ fail            │ link down
                   │                     ▼                      ▼                 ▼
                   └──── cooldown ◄── Waiting(retry n) ◄──────────────────── Reconnecting
```

- Autoconnect ranks candidates by priority, then visible before hidden,
  then security strength, then signal, then recency (deterministic ties).
- A wrong password marks the profile `needs-secrets` and asks the agent
  once; there is no blind retry loop. Transient failures back off
  exponentially. After three, the profile cools down and the next candidate
  is tried.
- A user disconnect holds autoconnect until an explicit connect.
- A dropped link gets a grace period for the backend to roam before L3 is
  released.

**P2P session** (one per connection):

```text
Negotiating ─GO-neg ok→ Forming ─GroupStarted{role,if}→ ConfiguringL3 ─ready→ Ready
     └────────── fail / timeout / close / peer left ──────────────────────────┘ → Closed
```

An **autonomous GO** starts directly in `Forming { role: GroupOwner }`:
there is no negotiation and no peer, and the first transition is
`GroupStarted`. It is requested through `P2P.StartGroup`, not through a
consumer-side connect. Once the group exists, Kestrel arms WPS push-button
on the group interface so one client can provision into it. The rest of
the machine, including L3 and teardown, is shared with a negotiated group.

The negotiated role decides L3: `GroupOwner` binds `SharedSubnet` (an
allocated `/24`, our `.1`, a DHCP server, no default route offered).
`Client` binds an anonymous DHCP client (RFC 7844) that does not count
toward the host being online.

A **persistent group** reuses the same machine. When the backend reports
provisioned credentials (`PersistentGroupFormed`), Kestrel seals the group
PSK and saves the group; `P2P.ConnectPersistent` and
`P2P.StartPersistentGroup` later re-enter `Forming` without WPS.

**Hotspot** (one per device):

```text
Stopped ─Start→ Starting ─ApStarted→ ConfiguringL3 ─L3Ready→ Active
   ▲                │ fail               │ fail                 │ Stop / failure
   └────────────────┴────────────────────┴──────────────────────┘
```

While a hotspot is active or starting, the station on that device stays
`Disabled` with `autoconnect_held` preserved. An active P2P session and a
hotspot are mutually exclusive (`Busy`). L3 is `SharedSubnet`,
so DHCP serving and NAT stay in `systemd-networkd`. The machine holds the
AP and its L3 binding in order and releases them in reverse on every exit.

## Controller & Catalog

One radio coordinator task owns all live machine state without awaiting I/O,
while `kestrel-catalog` owns persisted profiles, sealed credentials,
certificates, persistent P2P groups, and history behind serialized store writes.
Each device (shared by station and hotspot) and each P2P session has a generic
FIFO `Executor` task that runs its commands strictly in order. A slow backend
therefore never blocks other devices, and teardown is never reordered. Commands
return once the backend has *accepted* a request; outcomes (link up, scan
results, GO negotiation, L3 ready) arrive as events.

Live controller events (`DeviceChanged`, `SessionChanged`, …) and catalog
events (`ProfileAdded`, `CertAdded`, …) flow over broadcast channels. The D-Bus
layer mirrors them onto objects. A lagging subscriber resynchronizes from a
full snapshot.

## Ownership and crash safety

Kestrel keeps no ledger file. Every resource it creates is **tagged in the
resource itself**, and each adapter's `sweep` removes everything carrying
its tag:

| Backend | Tag | Sweep removes |
|---|---|---|
| networkd | unit file `10-kestrel-<link>.network` in `/run/systemd/network` | every such unit, then `Reload` + `ReconfigureLink` |
| wpa_supplicant | network block `id_str=kestrel` | every tagged block (station and AP); every P2P group interface; every persistent group; every `blob://kestrel-*` |
| iwd | `KnownNetwork.AutoConnect=false` (set by Kestrel) | every such known network; every AP stopped and `Device.Mode` reset to `station` |

The controller sweeps before starting any machine, and again after releasing
everything at shutdown. A `kill -9` therefore cannot leak configuration past
the next start. The e2e suite proves this against the real networkd.

## Persistence

- **Profiles:** `/var/lib/kestrel/profiles/<uuid>.toml`, schema-versioned,
  written atomically (temp file, fsync, rename, directory fsync) with mode
  0600 in a 0700 directory. An invalid file is quarantined (`*.invalid`) and
  reported, never silently rewritten, and it does not prevent the others
  from loading.
- **Secrets:** `/var/lib/kestrel/secrets/<uuid>.cred` (and
  `p2p-<uuid>.cred` for persistent groups), encrypted by `systemd-creds`
  (host key and/or TPM2). Each is bound to the name `kestrel-wifi-<uuid>` or
  `kestrel-p2p-<uuid>`, so a credential copied onto another profile fails to
  decrypt. A sealed value carries the passphrase, an EAP-TLS private key,
  and its own passphrase. The secret travels to `systemd-creds` over a pipe,
  never argv. In memory it lives in `Secret` (zeroized on drop, redacted in
  `Debug`, not serializable, not `Display`).
- **Certificates:** `/var/lib/kestrel/certs/<uuid>.toml`, mode 0600, holding
  imported public X.509 PEM material for 802.1X. Private keys are never
  stored here; they belong to the sealed secret above and are handed to
  `wpa_supplicant` as in-memory blobs.
- **Persistent P2P groups:** `/var/lib/kestrel/p2p-groups/<uuid>.toml`, mode
  0600, recording the group SSID, role, group owner address, peer, and last
  connection. The group PSK is a sealed secret, so reconnecting needs no WPS.
- **Settings:** `/etc/kestrel/kestrel.toml`, read-only, with unknown keys
  rejected.
- **History:** `/var/lib/kestrel/history.jsonl`, bounded and written
  atomically with mode 0600. Each event records time, device, SSID, profile,
  outcome, and a stable failure code. It is diagnostic, never configuration.
- **Radio state:** `/var/lib/kestrel/state.toml`, schema-versioned and
  written atomically with mode 0600. Records the user's software wireless
  toggle (`WirelessEnabled`) across daemon restarts and reboots.

## Power and rfkill

- `kestrel-daemon` subscribes to `org.freedesktop.login1.Manager.PrepareForSleep`
  on the bus. On suspend (`true`), active P2P sessions close and stations
  release L3 and L2 into `Disabled` while preserving `autoconnect_held`. On
  resume (`false`), stations clear pre-sleep failure cooldowns and stale scan
  caches, then immediately scan and autoconnect.
- Hardware rfkill is read from `/sys/class/rfkill` (requiring no
  capabilities) and exposed as `Manager.WirelessHardwareEnabled`. Hardware
  blocks suspend station orchestration without overwriting the user's
  software `WirelessEnabled` toggle.
- If a stored `systemd-creds` credential cannot be unsealed (for example
  after a host key or TPM reset), `SystemdCredsStore` quarantines the file
  to `*.cred.invalid` and the controller transitions the profile to
  `secrets-required`, prompting the registered agent for a fresh passphrase.

## Northbound API and compositor integration

`com.hihusky.Kestrel` is an ObjectManager tree of devices (with optional
`P2P` and `Hotspot` sub-interfaces), profiles, imported certificates,
persistent P2P groups, and sessions. Every mutating method is authorized by
polkit. Interactive input (secrets, peer authorization, PIN display) goes
only to the single registered agent, which is dropped when its owner leaves
the bus. Errors have stable names. `kestrel-api` defaults to its lightweight
`client` feature for Rust compositors and CLI consumers; the `server` feature
builds the D-Bus object server for `kestrel-daemon`. See
[docs/dbus-api.md](docs/dbus-api.md) and [docs/adr/](docs/adr/README.md).

## System integration

`data/` holds the deployable surface, and `scripts/check-system-files.sh`
verifies each file against the real tools:

- `kestrel.service`: `Type=notify` (`READY=1` after the bus name is owned)
  with an active-liveness `WatchdogSec=30s` probing both `RadioCoordinator` and
  D-Bus responsiveness before sending `WATCHDOG=1`, plus fail-fast exit on
  unexpected bus/name/sync loss for `Restart=on-failure` recovery
  ([ADR-0011](docs/adr/0011-daemon-supervision-liveness-watchdog-and-bounded-monitors.md)).
  Runs as root with an empty capability set, `ProtectSystem=strict` (writable:
  `/var/lib/kestrel`, `/run/systemd/network`), AF_UNIX only, a closed device
  policy except the TPM, and the `@system-service` syscall set minus
  `@privileged` and `@resources`. A graceful stop releases and sweeps
  everything.
- `kestrel.tmpfiles.conf`: guarantees `/run/systemd/network` exists, because
  the sandbox cannot create it.
- `com.hihusky.Kestrel.conf`: root owns the name; everyone may call it; only
  root (Kestrel) may call agent methods on clients.
- `com.hihusky.Kestrel.service`: D-Bus activation of the unit.
- `com.hihusky.kestrel.policy`: the five polkit actions (`connect`,
  `hotspot`, `modify-profiles`, `toggle-wireless`, `register-agent`), with
  defaults for active, inactive, and remote sessions.

## Extension points

New workflows reuse the same parts:

- **Another L2 or L3 daemon:** implement the port. Nothing above it changes.
- **Miracast / WFD:** `P2pDeviceConfig.wfd_subelements` advertises WFD IEs,
  and peers expose theirs. A casting service drives a session through the
  public API, reads `PeerIp`, and runs RTSP itself.
- **Another persisted kind:** add a store trait in `kestrel-ports` and a
  `TomlDirectory`-backed implementation in `kestrel-store`; certificates and
  persistent groups show the whole path from store to D-Bus object.

## Testing pyramid

| Layer | How |
|---|---|
| model, machines | unit tests and `proptest` over event sequences |
| catalog, controller | `kestrel-testkit` fakes, with failure injection and paused time |
| adapters | the production adapter against a fake daemon on a private `dbus-daemon`; networkd parsing against JSON captured from systemd 261 |
| API | real server, typed client, and a client-side agent on a private bus |
| e2e | `kestrel-daemon`, `kestrel`, the **real systemd-networkd**, and a fake `wpa_supplicant` in an unprivileged namespace: DHCP leases, GO and client P2P, crash sweep, and clean shutdown |
| hardware | [docs/hardware-validation.md](docs/hardware-validation.md), run by a person |

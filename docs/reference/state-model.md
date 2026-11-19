# State Model & Transitions

Kestrel models wireless station connections, Wi-Fi Direct sessions, and SoftAP hotspots as sans-IO state machines in `kestrel-machines`. Each machine exposes a pure `handle(now, input) -> Vec<Command>` transition function.

---

## 1. Station State Machine (One per Wireless Device)

```text
Disabled ─enable→ Idle ─select/user→ Associating ─link up→ ConfiguringL3 ─ready→ Connected
                   ▲                     │ fail                 │ fail            │ link down
                   │                     ▼                      ▼                 ▼
                   └──── cooldown ◄── Waiting(retry n) ◄──────────────────── Reconnecting
```

D-Bus `Device.State` strings: `disabled`, `idle`, `associating`, `configuring-l3`, `connected`, `reconnecting`, `waiting`.

### Key Rules

- **Autoconnect ranking**: Candidates are ranked deterministically by profile `priority`, then visible before hidden, then security strength, then signal strength, then recency (`last_connected`).
- **Wrong passphrase (`auth-failed`)**: Marks the profile `needs-secrets` and prompts the registered agent once; there is no blind retry loop.
- **Transient failures**: Back off exponentially. After three consecutive failures, the profile enters cooldown and the next candidate is tried. See [Stable Failure Codes](failures-and-errors.md#1-stable-failure-codes-failurereason).
- **User disconnect**: Sets `AutoconnectHeld = true` (`AutoconnectEnabled = false`) until an explicit `Connect` or `SetAutoconnect(true)`.
- **Roaming grace**: When a connected link drops, `[timeouts].link_grace` lets the L2 backend roam to another BSS before Kestrel releases L3.
- **Suspend / rfkill**: System suspend (`PrepareForSleep(true)`) or hardware rfkill transitions active stations into `Disabled` while preserving `AutoconnectHeld`. Resume clears pre-sleep cooldowns and stale scan caches, triggering an immediate scan and autoconnect.

---

## 2. P2P Session State Machine (One per P2P Session)

```text
Negotiating ─GO-neg ok→ Forming ─GroupStarted{role,if}→ ConfiguringL3 ─ready→ Ready
     └────────── fail / timeout / close / peer left ──────────────────────────┘ → Closed
```

D-Bus `Session.State` strings: `negotiating`, `forming`, `configuring-l3`, `ready`, `closed`.

- **Negotiated GO / Client**: Starts in `Negotiating`, moves to `Forming` after GO negotiation succeeds, and enters `ConfiguringL3` once `GroupStarted` reports the group interface and negotiated role (`group-owner` or `client`).
- **Autonomous GO (`P2P.StartGroup` / `StartPersistentGroup`)**: Starts directly in `Forming` as `group-owner` without GO negotiation. For non-persistent autonomous groups, WPS push-button is armed on the group interface for one client.
- **Role-based L3**:
  - `group-owner`: Binds `SharedSubnet` (an allocated `/24` from `[p2p].subnet_pool`, `.1` on the GO interface, DHCP server enabled, no default route offered).
  - `client`: Binds an anonymous DHCP client (RFC 7844) that does not contribute to host `OnlineState`.

---

## 3. Hotspot State Machine (One per Device)

```text
Stopped ─Start→ Starting ─ApStarted→ ConfiguringL3 ─L3Ready→ Active
   ▲                │ fail               │ fail                 │ Stop / failure
   └────────────────┴────────────────────┴──────────────────────┘
```

D-Bus `Hotspot.State` strings: `stopped`, `starting`, `configuring-l3`, `active`.

- **SoftAP ownership**: `Starting` holds `Ap`; `ConfiguringL3` adds `L3Binding`. Both are released in reverse order on every exit, so a failed L3 bind always stops the AP again.
- **Station handover**: While a hotspot is starting or active, the station machine on the same device is held in `Disabled` with `AutoconnectHeld` preserved; stopping the hotspot restores the previous station state and re-runs autoconnect.
- **P2P exclusion**: An active P2P session and a hotspot are mutually exclusive on one device (`Busy`); incoming persistent-group invitations are rejected the same way.
- **L3**: Binds `SharedSubnet { emit_router: true, masquerade: true }`, delegating DHCP serving, router advertisement, and IPv4 NAT masquerading to `systemd-networkd`.

---

## 4. Resource Ownership & Rollback Invariants

Every machine tracks held resources (`Association`, `L3Binding`, `Negotiation`, `Group`, `Ap`) in acquisition order and releases them in strict reverse order on every exit path.

Property tests (`proptest`) in `kestrel-machines` enforce:

1. No resource is ever acquired twice.
2. L3 is never bound without an active L2 association, P2P group, or AP.
3. Resources are always released in reverse acquisition order.
4. Any `Idle`, `Closed`, or `Stopped` machine holds zero resources.

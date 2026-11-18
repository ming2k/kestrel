# State Model & Transitions

Kestrel models wireless station connections, Wi-Fi Direct sessions, and SoftAP hotspots as sans-IO state machines in `kestrel-machines`. Each machine has a pure `handle(now, input) -> Vec<Command>` transition function.

---

## 1. Station State Machine (One per Wireless Device)

```text
Disabled ─enable→ Idle ─select/user→ Associating ─link up→ ConfiguringL3 ─ready→ Connected
                   ▲                     │ fail                 │ fail            │ link down
                   │                     ▼                      ▼                 ▼
                   └──── cooldown ◄── Waiting(retry n) ◄──────────────────── Reconnecting
```

### Key Rules

- **Autoconnect ranking**: Candidates are ranked deterministically by profile `priority`, then visible before hidden, then security strength, then signal strength, then recency.
- **Wrong passphrase**: Marks the profile `needs-secrets` and prompts the registered agent once; there is no blind retry loop.
- **Transient failures**: Back off exponentially. After three consecutive failures, the profile enters cooldown and the next candidate is tried.
- **User disconnect**: Holds autoconnect (`autoconnect_held = true`) until an explicit `Connect` or `Autoconnect = true`.
- **Roaming grace**: When a connected link drops, a `link_grace` timer allows the L2 backend to roam before Kestrel releases L3.
- **Suspend / rfkill**: System suspend (`PrepareForSleep(true)`) or hardware rfkill block transitions active stations into `Disabled` while preserving `autoconnect_held`. Resume clears pre-sleep cooldowns and stale scan caches and triggers an immediate scan and autoconnect.

---

## 2. P2P Session State Machine (One per P2P Session)

```text
Negotiating ─GO-neg ok→ Forming ─GroupStarted{role,if}→ ConfiguringL3 ─ready→ Ready
     └────────── fail / timeout / close / peer left ──────────────────────────┘ → Closed
```

- **Negotiated GO / Client**: Starts in `Negotiating`, moves to `Forming` after GO negotiation succeeds, and enters `ConfiguringL3` once `GroupStarted` reports the group interface and negotiated role (`GroupOwner` or `Client`).
- **Autonomous GO (`P2P.StartGroup`)**: Starts directly in `Forming { role: GroupOwner }` without peer negotiation. Once the group starts, WPS push-button is armed on the group interface for one client.
- **Role-based L3**:
  - `GroupOwner`: Binds `SharedSubnet` (an allocated `/24` from `SubnetAllocator`, `.1` on the GO interface, DHCP server enabled, no default route offered).
  - `Client`: Binds an anonymous DHCP client (RFC 7844) that does not contribute to host `OnlineState`.

---

## 3. Hotspot State Machine (One per Device)

```text
Stopped ─Start→ Starting ─ApStarted→ ConfiguringL3 ─L3Ready→ Active
   ▲                │ fail               │ fail                 │ Stop / failure
   └────────────────┴────────────────────┴──────────────────────┘
```

- **SoftAP ownership**: `Starting` holds `Ap`; `ConfiguringL3` adds `L3Binding`. Both are released in reverse order on every exit, so a failed L3 bind always stops the AP again.
- **Station handover**: while a hotspot is active or starting, the station machine on the same device is held in `Disabled` with `autoconnect_held` preserved; stopping the hotspot restores the previous station state and re-runs autoconnect.
- **P2P exclusion**: an active P2P session and a hotspot are mutually exclusive on one device (`Busy`); a persistent-session invitation is rejected the same way.
- **L3**: the hotspot binds `SharedSubnet { emit_router: true, masquerade: true }`, so `systemd-networkd` owns DHCP serving, router advertisement, and NAT — Kestrel still opens no netlink socket and needs no capabilities.

---

## 4. Resource Ownership & Rollback Invariants

Every machine records held resources (`Association`, `L3Binding`, `Negotiation`, `Group`, `Ap`) in acquisition order. On every exit path, resources are released in strict reverse order.

Property tests (`proptest`) in `kestrel-machines` enforce:
1. No resource is ever acquired twice.
2. L3 is never bound without an active L2 association or P2P group.
3. Resources are released in reverse acquisition order.
4. Any `Idle`, `Closed`, or `Stopped` machine holds zero resources.

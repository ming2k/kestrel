# Explanation

Conceptual documentation that explains how and why Kestrel is designed the way it is. Read these to understand architectural boundaries and trade-offs.

---

## Articles

| Article | Explains |
| :--- | :--- |
| [Architecture Overview](architecture-overview.md) | Why Kestrel is a control-plane orchestrator with zero L3 competition, and how its layered crates and sans-IO runtime fit together. |
| [Ownership and Crash Safety](ownership-and-crash-safety.md) | Why Kestrel uses self-describing ownership tags instead of a ledger file, and how startup/shutdown sweeps guarantee `kill -9` safety. |
| [Power, rfkill, and Credential Resilience](power-and-rfkill.md) | How Kestrel coordinates suspend/resume, hardware vs. software radio toggles, and `systemd-creds` quarantine recovery. |

For the formal architectural decisions, consult the [Architecture Decision Records](../adr/README.md).

# Documentation Taxonomy & Information Architecture

This document defines the organization, scope boundaries, and classification of all documentation assets in the Kestrel repository.

---

## 1. The Four-Quadrant System (Diátaxis)

Public documentation in `docs/` follows the Diátaxis information architecture:

```text
               PRACTICAL                   THEORETICAL
          ┌─────────────────────────┬─────────────────────────┐
          │  Tutorials              │  How-To Guides          │
LEARNING  │  (Learning-Oriented)    │  (Task-Oriented)        │
          │  `docs/tutorials/`      │  `docs/how-to/`         │
          ├─────────────────────────┼─────────────────────────┤
          │  Reference              │  Explanation            │
WORKING   │  (Information-Oriented) │  (Understanding-Orient) │
          │  `docs/reference/`      │  `docs/explanation/`    │
          └─────────────────────────┴─────────────────────────┘
```

- **`docs/tutorials/`**: Guided, hands-on lessons taking a new reader through their first successful experience with Kestrel.
- **`docs/how-to/`**: Step-by-step problem-solving recipes for specific user or administrator goals.
- **`docs/reference/`**: Technical descriptions of CLI commands, configuration schemas, D-Bus APIs, and state machines without tutorial prose.
- **`docs/explanation/`**: Conceptual deep dives, design rationale, and architectural discussions.

---

## 2. Documentation Spaces & Audiences

Documentation is structured into two surfaces separated by a one-way visibility boundary:

```text
┌─────────────────────────────────────────────────────────────┐
│ Public Surface (Users, Integrators, Packagers, Compositors) │
│ `docs/tutorials/`, `how-to/`, `reference/`, `explanation/`  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ Scope Boundary: public docs must
                               │ never link into `docs/dev/**`.
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Engineering Surface (Contributors, Maintainers)             │
│ `docs/dev/` (internals, standards, build/test runbooks)     │
│ `docs/adr/` (canonical architectural decision records)      │
└─────────────────────────────────────────────────────────────┘
```

1. **Public Surface**: Addressed to end users, system administrators, and desktop/compositor integrators. Emphasizes CLI workflows, D-Bus contracts, systemd integration, and architectural concepts.
2. **Engineering Surface**: Addressed to contributors and maintainers. Emphasizes crate topology, build/test gates, hardware validation, and decision records.
3. **Audience Firewall**: Public documentation surfaces (`docs/{tutorials,how-to,reference,explanation}/`) must never contain relative links pointing into `docs/dev/**`. Links into `docs/adr/` remain permitted.
4. **Reverse Linking Permitted**: Internal documents in `docs/dev/` may freely link outward to public reference, how-to guides, `docs/dbus-api.md`, and `docs/hardware-validation.md`.

# Architectural Decision Records (ADR) Standards

This document establishes the qualification criteria, lifecycle, and template for Architectural Decision Records (ADRs) under `docs/adr/`.

---

## 1. Intent & Qualification

Author an ADR when a change meets **at least two** of these criteria:

1. **High Reversal Cost**: Reversing the decision would require multi-crate refactoring or breaking migration paths.
2. **Cross-Boundary Blast Radius**: It alters crate boundaries, D-Bus API contracts, on-disk storage layouts, or security/sandbox boundaries.
3. **Generates Binding Red-Lines**: It establishes hard structural invariants (such as zero L3 competition or sans-IO core).

---

## 2. Lifecycle & Naming

ADRs live in `docs/adr/` as `NNNN-<slug>.md` and are indexed in [`docs/adr/README.md`](../../adr/README.md).

Statuses:
- **Draft**: Proposal under active review.
- **Accepted**: Ratified architectural contract binding on the repository.
- **Superseded**: Replaced by a subsequent ADR.
- **Rejected**: Discarded alternative preserved for negative knowledge.

---

## 3. Canonical ADR Template

```markdown
# ADR NNNN: [Title of Decision]

- **Status:** Draft | Accepted | Superseded | Rejected
- **Date:** YYYY-MM-DD

## Context

Describe the architectural problem, constraints, and boundary pressures.

## Decision

Detail the chosen design, affected crates, and enforceable invariants.

## Consequences

- Positive outcomes, operational benefits, and trade-offs.
```

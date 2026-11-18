# Documentation Style & Hyperlink Standards

This document specifies the style guide, Markdown conventions, and hyperlink standards for all documentation in the repository.

---

## 1. Hyperlink Standards

1. **Relative Paths**: All cross-references between documentation files must use explicit relative paths (e.g., `[ADR-0001](../../adr/0001-control-plane-orchestrator-zero-l3.md)`).
2. **Never Use Absolute Locators**: Never write hardcoded local paths (e.g., `/home/...` or `file://...`) or absolute repo URLs for internal links.
3. **Target Existence**: Every relative link must resolve to a valid file on disk.
4. **Anchor Hygiene**: When linking to section headers, use clean kebab-case anchors matching the heading text.

---

## 2. Formatting & Markdown Conventions

1. **Header Hierarchy**:
   - Exactly one `# Level 1 Heading` per file at line 1.
   - Subsections descend logically: `## Level 2`, followed by `### Level 3`.
2. **Typed Code Blocks**:
   - Always declare an explicit language identifier on fenced code blocks (e.g., `bash`, `sh`, `toml`, `text`, `rust`, `ini`). Never leave fences untyped.
3. **Lists and Tables**:
   - Use clean Markdown tables with aligned delimiters.
   - Prefer `-` for unordered bullet points and `1.` for sequential procedures.

---

## 3. Tone and Vocabulary

1. **Pragmatic and Objective**: Write in active, direct, and unambiguous language.
2. **Mechanisms Over Aspirations**: When describing behavioral constraints, describe the concrete enforcing mechanism (state machine transition, D-Bus error, systemd unit directive, or test assertion) rather than vague prose.
3. **Current Crate & Binary Names**: Always use current workspace crate names (`kestrel-model`, `kestrel-machines`, `kestrel-ports`, `kestrel-catalog`, `kestrel-controller`, `kestrel-store`, `kestrel-wlan-wpa`, `kestrel-wlan-iwd`, `kestrel-l3-networkd`, `kestrel-api`, `kestrel-daemon`, `kestrel-cli`, `kestrel-testkit`, `kestrel-e2e`) and binary names (`kestrel-daemon`, `kestrel`).

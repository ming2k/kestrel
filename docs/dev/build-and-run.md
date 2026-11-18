# Build and Run

This guide covers building Kestrel from source, running the local quality gate, and launching `kestrel-daemon` and `kestrel` during development.

---

## 1. Prerequisites

- Rust toolchain pinned in [`rust-toolchain.toml`](../../rust-toolchain.toml) (Rust 1.89+ / Edition 2024).
- `systemd-networkd`, `systemd-resolved`, and `systemd-creds`.
- Either `wpa_supplicant` (`-u` D-Bus mode) or `iwd` (`EnableNetworkConfiguration=false`).
- For the e2e lab (`./crates/kestrel-e2e/run.sh`): `unshare --map-auto` (subordinate UID/GID ranges), `nsenter`, `dbus-daemon`, `iproute2`, `systemd-networkd` with the `systemd-network` user, and `systemd-creds --user`.

---

## 2. Building

```sh
# Debug build of all workspace crates
cargo build

# Release build (LTO thin, panic=abort, stripped)
cargo build --release --workspace

# Check the lightweight client-only feature build of kestrel-api
cargo check -p kestrel-api --no-default-features --features client

# Stage or install binaries, systemd units, D-Bus/polkit policy, and docs
make install DESTDIR=/tmp/kestrel-stage
```

---

## 3. Running Locally

Both `kestrel-daemon` and `kestrel` accept `--bus` (or `KESTREL_BUS`), supporting `system`, `session`, or an explicit D-Bus address:

```sh
# Start kestrel-daemon with custom config and debug logging on the session bus
KESTREL_LOG=debug ./target/debug/kestrel-daemon \
  --config ./config.example.toml \
  --bus session

# Query it from the CLI on the same bus
./target/debug/kestrel --bus session status
```

`kestrel-daemon` writes structured logs to `stderr`. When `JOURNAL_STREAM` is set (under systemd), timestamps and ANSI color codes are omitted because the journal adds its own timestamps.

---

## 4. Continuous Integration & Quality Gate

GitHub Actions ([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)) runs the full quality gate on every push and pull request:

1. `cargo fmt --all -- --check`
2. Optional feature matrix checks (`kestrel-api --no-default-features`, `kestrel-api --no-default-features --features client`, `kestrel-wlan-wpa --no-default-features`, `kestrel-wlan-iwd --no-default-features`)
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
4. `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
5. `cargo build --release -p kestrel-daemon -p kestrel-cli`
6. MSRV check on Rust `1.89` (`cargo check --workspace --all-features`)
7. `cargo test --workspace --all-features -- --skip e2e`
8. `./scripts/check-system-files.sh`
9. `./crates/kestrel-e2e/run.sh`

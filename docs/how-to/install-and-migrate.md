# Install, Switch Backends, and Uninstall

This guide covers installing Kestrel onto a Linux system, preparing `systemd-networkd` and an L2 wireless daemon (`wpa_supplicant` or `iwd`), migrating off NetworkManager or ConnMan, customizing networkd drop-ins, and uninstalling cleanly.

---

## 1. System Requirements

| Component | Requirement | Notes |
| :--- | :--- | :--- |
| **Rust toolchain** | 1.89+ (Edition 2024) | Build-time only; pinned in [`rust-toolchain.toml`](../../rust-toolchain.toml). |
| **systemd / networkd** | `systemd-networkd`, `systemd-resolved`, `systemd-creds` | `DHCPServer.PersistLeases=runtime` requires systemd ≥ 257 (older versions ignore the key). Hotspot NAT masquerading (`IPMasquerade=ipv4`) on systemd 256+ also requires uplink forwarding. |
| **D-Bus & polkit** | `dbus`, `polkit` | System bus runs `com.hihusky.Kestrel`; polkit authorizes mutating calls. |
| **L2 wireless daemon** | `wpa_supplicant` (D-Bus `-u`) **or** `iwd` | Exclusive control of wireless interfaces is required. |

---

## 2. Build and Install

Build and install all binaries, system units, D-Bus/polkit policies, configuration templates, and documentation using the [`Makefile`](../../Makefile):

```sh
make build
sudo make install
```

For distro packaging or staged installs, `Makefile` honors `PREFIX` (default `/usr`) and `DESTDIR`:

```sh
make install PREFIX=/usr DESTDIR=/tmp/kestrel-stage
```

### Installed Files

| Source | Destination | Purpose |
| :--- | :--- | :--- |
| `target/release/kestrel` | `/usr/bin/kestrel` | CLI client |
| `target/release/kestrel-daemon` | `/usr/libexec/kestrel-daemon` | Orchestrator daemon |
| `data/kestrel.service` | `/usr/lib/systemd/system/kestrel.service` | Hardened systemd unit (`Type=notify`, D-Bus alias) |
| `data/kestrel.tmpfiles.conf` | `/usr/lib/tmpfiles.d/kestrel.conf` | Creates `/run/systemd/network` at boot |
| `data/com.hihusky.Kestrel.conf` | `/usr/share/dbus-1/system.d/com.hihusky.Kestrel.conf` | D-Bus system bus policy |
| `data/com.hihusky.Kestrel.service` | `/usr/share/dbus-1/system-services/com.hihusky.Kestrel.service` | D-Bus activation descriptor |
| `data/com.hihusky.kestrel.policy` | `/usr/share/polkit-1/actions/com.hihusky.kestrel.policy` | Polkit authorization defaults |
| `config.example.toml` | `/etc/kestrel/kestrel.toml.example` | Administrator configuration template |
| `kestrel completions {bash,zsh,fish}` | `/usr/share/bash-completion/completions/kestrel`, `/usr/share/zsh/site-functions/_kestrel`, `/usr/share/fish/vendor_completions.d/kestrel.fish` | Shell completion scripts |
| `LICENSE`, `README.md`, `ARCHITECTURE.md`, `docs/` | `/usr/share/doc/kestrel/` | Installed documentation |

---

## 3. Initialize Runtime Directories and Credential Key

Run once after installation:

```sh
sudo systemd-tmpfiles --create kestrel.conf
sudo systemd-creds setup
```

- `systemd-tmpfiles --create kestrel.conf` ensures `/run/systemd/network` exists before `kestrel-daemon` starts (`kestrel.service` runs under `ProtectSystem=strict` and cannot create the directory itself).
- `systemd-creds setup` initializes `/var/lib/systemd/credential.secret` (or binds to TPM2 where available) so Kestrel can seal Wi-Fi passphrases, 802.1X private keys, and persistent P2P PSKs at rest.

---

## 4. Choose and Configure the L2 Backend

By default, `[wireless].backend = "auto"` selects `wpa_supplicant` if `fi.w1.wpa_supplicant1` is present on the system bus, falls back to `iwd` if `net.connman.iwd` is present, and otherwise waits for `wpa_supplicant`.

See [Backend Capability Matrix](../reference/failures-and-errors.md#4-backend-capability-matrix) to compare features before choosing.

### Option A: `wpa_supplicant` (Recommended)

`wpa_supplicant` supports the full feature set: WPA3-only, OWE, 802.1X enterprise, all SoftAP security modes, and Wi-Fi Direct (P2P / Miracast).

1. Run the stock D-Bus service (`wpa_supplicant -u`) with **no saved networks** for the managed wireless interfaces:

   ```sh
   sudo systemctl enable --now wpa_supplicant
   ```

   If your distribution uses a custom command line, launch `wpa_supplicant -u -i <iface> -c /dev/null` or point it at an empty configuration without `network={...}` blocks. Kestrel attaches interfaces over D-Bus and tags every block it creates with `id_str="kestrel"`.

2. To pin `wpa_supplicant` explicitly, set in `/etc/kestrel/kestrel.toml`:

   ```toml
   [wireless]
   backend = "wpa-supplicant"
   ```

### Option B: `iwd`

`iwd` supports `open` and `wpa-personal` station connections (auto-negotiating WPA2/WPA3) and `wpa-personal` hotspots. It does **not** support forced WPA3-only, OWE-only, 802.1X enterprise profiles, or Wi-Fi Direct.

1. Disable `iwd`'s internal L3/DHCP stack in `/etc/iwd/main.conf`:

   ```ini
   [General]
   EnableNetworkConfiguration=false
   ```

2. Restart `iwd`:

   ```sh
   sudo systemctl enable --now iwd
   sudo systemctl restart iwd
   ```

3. Pin `iwd` in `/etc/kestrel/kestrel.toml` if `wpa_supplicant` is also installed:

   ```toml
   [wireless]
   backend = "iwd"
   ```

> **Ownership note for `iwd`:** Kestrel marks `iwd` known networks it provisions with `AutoConnect=false` and sweeps them on startup and shutdown. Do not share an `iwd` instance with manually disabled known networks (`AutoConnect=false`) that you expect to survive a Kestrel restart.

---

## 5. Migrate From NetworkManager or ConnMan

`kestrel.service` declares `Conflicts=NetworkManager.service connman.service` because wireless interfaces cannot be safely managed by two control planes at once.

Perform these steps from a local console or an independent wired connection:

1. Check whether existing `.network` files in `/etc/systemd/network/` match your wireless interface with a lexical prefix lower than `10-` (for example `05-wireless.network`). Rename or remove conflicting rules so Kestrel's runtime unit `10-kestrel-<link>.network` takes precedence.
2. Disable the old network manager:

   ```sh
   sudo systemctl disable --now NetworkManager
   # or, if using ConnMan:
   # sudo systemctl disable --now connman
   ```

3. Enable `systemd-networkd` and `systemd-resolved` (and confirm `/etc/resolv.conf` points to `systemd-resolved`, typically `/run/systemd/resolve/stub-resolv.conf`):

   ```sh
   sudo systemctl enable --now systemd-networkd systemd-resolved
   ```

   If your machine also has a wired Ethernet interface previously managed by NetworkManager, ensure you have a `.network` file for it in `/etc/systemd/network/` (for example `20-wired.network` matching `[Match] Name=en*` with `[Network] DHCP=yes`).

4. Reload D-Bus and start Kestrel:

   ```sh
   sudo systemctl reload dbus
   sudo systemctl enable --now kestrel
   ```

5. Confirm Kestrel is active and healthy:

   ```sh
   systemctl status kestrel
   kestrel status
   ```

---

## 6. Administrator `.network.d/` Drop-Ins

Kestrel writes runtime units to `/run/systemd/network/10-kestrel-<link>.network`. To layer custom `systemd-networkd` directives (such as `RoutingPolicyRule`, `RouteMetric`, or `IPv4Forwarding`) alongside Kestrel's generated unit without modifying Kestrel, create a drop-in directory:

```text
/etc/systemd/network/10-kestrel-<link>.network.d/*.conf
```

For example, to adjust the DHCP route metric on `wlp0s20f3`:

```ini
# /etc/systemd/network/10-kestrel-wlp0s20f3.network.d/metric.conf
[DHCPv4]
RouteMetric=200
```

---

## 7. Security Sandbox

`kestrel.service` runs `kestrel-daemon` as root with:

- Empty capability sets (`CapabilityBoundingSet=`, `AmbientCapabilities=`)
- `NoNewPrivileges=yes` and `UMask=0077`
- `ProtectSystem=strict`, writable only on `/var/lib/kestrel` (`StateDirectory=kestrel`) and `/run/systemd/network`
- `DevicePolicy=closed` with only `/dev/tpmrm0 rw` allowed (for TPM2-backed `systemd-creds`)
- `RestrictAddressFamilies=AF_UNIX` and `IPAddressDeny=any`
- `@system-service` syscall allow-list excluding `@privileged` and `@resources`

Because `kestrel.service` also installs `Alias=dbus-com.hihusky.Kestrel.service`, D-Bus activation can start the daemon on demand once enabled.

---

## 8. Uninstall and Roll Back

1. Stop and disable Kestrel (this gracefully disconnects active links and removes all `10-kestrel-*` runtime units):

   ```sh
   sudo systemctl disable --now kestrel
   ```

2. Remove installed binaries, unit files, policies, and docs from the source tree:

   ```sh
   sudo make uninstall
   sudo systemctl daemon-reload
   sudo systemctl reload dbus
   ```

3. Re-enable your previous network manager if desired:

   ```sh
   sudo systemctl enable --now NetworkManager
   ```

4. Optionally remove persistent Kestrel configuration and state:

   ```sh
   sudo rm -rf /etc/kestrel /var/lib/kestrel
   ```

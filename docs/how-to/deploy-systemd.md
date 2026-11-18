# Deploy Kestrel with systemd

This guide covers installing Kestrel onto a Linux system with `systemd-networkd`, `systemd-resolved`, `systemd-creds`, D-Bus, and polkit.

---

## 1. Install Binaries and System Files

Build the release binaries and install the runtime assets from `data/` (or run `sudo make install`, which honors `PREFIX` and `DESTDIR`):

```sh
cargo build --release --workspace
```

| Source | Destination |
| :--- | :--- |
| `target/release/kestrel` | `/usr/bin/kestrel` |
| `target/release/kestrel-daemon` | `/usr/libexec/kestrel-daemon` |
| `data/kestrel.service` | `/usr/lib/systemd/system/kestrel.service` |
| `data/kestrel.tmpfiles.conf` | `/usr/lib/tmpfiles.d/kestrel.conf` |
| `data/com.hihusky.Kestrel.conf` | `/usr/share/dbus-1/system.d/com.hihusky.Kestrel.conf` |
| `data/com.hihusky.Kestrel.service` | `/usr/share/dbus-1/system-services/com.hihusky.Kestrel.service` |
| `data/com.hihusky.kestrel.policy` | `/usr/share/polkit-1/actions/com.hihusky.kestrel.policy` |
| `config.example.toml` | `/etc/kestrel/kestrel.toml.example` (copy to `kestrel.toml` to customize) |
| `README.md`, `ARCHITECTURE.md`, `LICENSE`, `docs/` | `/usr/share/doc/kestrel/` |

---

## 2. Initialize Runtime Directories and Credential Key

Create `/run/systemd/network` (required before `kestrel-daemon` starts because the unit sandbox cannot create it) and initialize the `systemd-creds` host key once:

```sh
sudo systemd-tmpfiles --create kestrel.conf
sudo systemd-creds setup
```

---

## 3. Configure the L2 Backend

Ensure `systemd-networkd` and `systemd-resolved` are running, and configure your chosen L2 daemon so it does not compete with Kestrel:

- **`wpa_supplicant`**: run `wpa_supplicant -u` (D-Bus control mode) with no saved networks (`-c /dev/null` or empty config).
- **`iwd`**: set `EnableNetworkConfiguration=false` in `/etc/iwd/main.conf` so `iwd` does not configure IP addresses. Note that Kestrel's crash-recovery sweep forgets `iwd` known networks with `AutoConnect=false` (the ownership tag Kestrel writes); avoid sharing an `iwd` instance with manually disabled known networks you wish to preserve.

---

## 4. Reload D-Bus and Enable `kestrel.service`

```sh
sudo systemctl reload dbus
sudo systemctl enable --now kestrel
```

`kestrel.service` uses `Type=notify`, runs with an empty capability set, `ProtectSystem=strict` (writable only on `/var/lib/kestrel` and `/run/systemd/network`), `RestrictAddressFamilies=AF_UNIX`, and `IPAddressDeny=any`.

---

## 5. Administrator `.network.d/` Drop-Ins

To apply custom `systemd-networkd` directives (such as `RoutingPolicyRule`) alongside Kestrel's runtime unit on `<link>`, place drop-ins in:

```text
/etc/systemd/network/10-kestrel-<link>.network.d/*.conf
```

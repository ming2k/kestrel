# Troubleshooting

Use this guide to diagnose startup failures, permission errors, L2/L3 mismatches, credential quarantine events, hotspot forwarding issues, and radio blocks.

---

## 1. Quick Diagnostic Checklist

Gather the current view across Kestrel, systemd, networkd, DNS, and rfkill:

```sh
kestrel status
kestrel wifi history --limit 20
systemctl status kestrel systemd-networkd systemd-resolved wpa_supplicant iwd
journalctl -u kestrel -n 100 --no-pager
networkctl list
networkctl status wlp0s20f3
resolvectl status wlp0s20f3
rfkill list
ls -la /run/systemd/network/
```

---

## 2. Enable Debug Logging

`kestrel-daemon` reads the `KESTREL_LOG` filter environment variable (default `info`). To enable debug logging temporarily under systemd:

```sh
sudo systemctl edit kestrel
```

Add:

```ini
[Service]
Environment=KESTREL_LOG=debug
```

Then restart and follow the journal:

```sh
sudo systemctl restart kestrel
journalctl -u kestrel -f
```

Remove the override with `sudo systemctl revert kestrel && sudo systemctl restart kestrel` once finished.

---

## 3. Common Symptoms and Fixes

### `kestrel.service` fails to start or cannot write runtime `.network` units

- **Cause 1: `/run/systemd/network` does not exist.** `kestrel.service` runs under `ProtectSystem=strict` and cannot create the directory itself.
  - **Fix:** Run `sudo systemd-tmpfiles --create kestrel.conf` and restart `kestrel`.
- **Cause 2: Unknown or invalid key in `/etc/kestrel/kestrel.toml`.** `kestrel-daemon` rejects unknown keys (`deny_unknown_fields`) and out-of-range values before startup.
  - **Fix:** Check `journalctl -u kestrel` for the exact field name and compare against [Configuration & Storage](../reference/configuration.md).
- **Cause 3: Conflicting network manager running.** `kestrel.service` conflicts with `NetworkManager.service` and `connman.service`.
  - **Fix:** Stop and disable the conflicting manager (`sudo systemctl disable --now NetworkManager`).

### `kestrel status` shows no wireless devices

- **Cause 1: Neither `wpa_supplicant` nor `iwd` is running on the system D-Bus.**
  - **Fix:** Start your chosen L2 daemon (`sudo systemctl enable --now wpa_supplicant` or `iwd`). Confirm `kestrel-daemon` picked the right backend in `journalctl -u kestrel` (`starting Kestrel wireless=...`).
- **Cause 2: `backend = "auto"` picked the wrong daemon when both are running.**
  - **Fix:** `auto` prefers `wpa_supplicant` over `iwd`. Set `[wireless].backend = "iwd"` or `"wpa-supplicant"` explicitly in `/etc/kestrel/kestrel.toml` and restart `kestrel`.
- **Cause 3: Hardware rfkill switch is blocking Wi-Fi.**
  - **Fix:** Check `rfkill list` and `kestrel status` (which prints `(rfkill: hard-blocked)`). Toggle the physical switch or firmware key, or unblock soft rfkill with `rfkill unblock wifi`.

### `kestrel wifi status` shows `idle` / `offline` even though Wi-Fi is already connected

- **Cause 1: The connection was established outside Kestrel.** Kestrel only reports state for connections it orchestrates; it does not import `/etc/wpa_supplicant/wpa_supplicant.conf` or adopt external connections.
  - **Fix:** Confirm `kestrel profile list` and join through Kestrel (`kestrel wifi join <iface> "<SSID>"`).
- **Cause 2: A second manual `wpa_supplicant` process is running alongside `wpa_supplicant.service`.** Look for processes like `wpa_supplicant -B -i <iface> -c /etc/wpa_supplicant/wpa_supplicant.conf` via `ps -ef | grep wpa_supplicant`. Running two supplicants on the same interface causes `nl80211: kernel reports: Match already configured` and breaks P2P/association.
  - **Fix:** Stop the manual process, ensure only `wpa_supplicant.service` (`wpa_supplicant -u`) is running, restart `kestrel`, and reconnect with `kestrel wifi join`.

### `AccessDenied` when running `kestrel`

- **Cause:** Polkit rejected the action. Active local seat sessions are authorized by default (`yes`), whereas remote SSH or inactive sessions require `auth_admin_keep` (or a custom local rule restricted the action). When running in an interactive terminal, `kestrel` checks authorization before prompting for secrets and launches `pkttyagent --fallback` automatically; in non-interactive scripts or hosts without `pkttyagent` and without a desktop polkit agent, `polkitd` returns `AccessDenied`.
- **Fix:**
  - Verify your session is an active local seat (`loginctl session-status`) or run with `sudo kestrel ...` over SSH / in non-interactive scripts.
  - Ensure `pkttyagent` (part of `polkit`) or a desktop polkit authentication agent is installed when authenticating interactively.
  - To customize authorization rules, see [Scripting, Agents, and Polkit](scripting-and-agents.md#4-polkit-authorization-and-custom-rules).

### `NotSupported` on WPA3-only, OWE, 802.1X, P2P, or Hotspot

- **Cause:** The active backend or wireless driver cannot enforce the requested mode. In particular, `iwd` does not support forced `wpa3-personal`, `owe`, `wpa-enterprise`, `wpa3-enterprise`, Wi-Fi Direct, or non-WPA2 hotspots (`open` / `wpa3-personal`).
- **Fix:** Inspect what the adapter and backend actually advertise:

  ```sh
  kestrel --json status | jq '.devices[] | {interface, capabilities, supported_security}'
  ```

  Switch to `wpa_supplicant` if you require 802.1X, Wi-Fi Direct, strict WPA3/OWE enforcement, or open/WPA3 hotspots.

### `Busy` when starting a hotspot, P2P session, agent, or deleting a certificate

- **Hotspot vs. P2P:** A single wireless device cannot run a SoftAP hotspot and a Wi-Fi Direct session concurrently. Stop the active hotspot (`kestrel hotspot stop <dev>`) or close the active P2P session (`kestrel p2p close <session>`) first.
- **Agent registration:** Only one D-Bus agent (`kestrel agent` or a desktop shell agent) may be registered at a time.
- **Certificate deletion:** A certificate cannot be deleted while any saved profile references it. Check `kestrel profile list` / `kestrel profile show <profile>` and re-point or delete referencing profiles first.

### Wi-Fi associates (`configuring-l3`) but fails with `l3-failed` or `timeout`

- **Cause 1: `systemd-networkd` is not running.**
  - **Fix:** `sudo systemctl enable --now systemd-networkd systemd-resolved`.
- **Cause 2: Another `.network` file matched the interface first.** `systemd-networkd` applies the lexically first matching `.network` file; Kestrel writes `10-kestrel-<link>.network` in `/run/systemd/network`.
  - **Fix:** Run `networkctl status <iface>` and inspect the `Network File:` line. If a file with prefix `< 10-` (such as `05-wlan.network`) matched instead, remove or renumber it.
- **Cause 3: `iwd` is running with `EnableNetworkConfiguration=true`.**
  - **Fix:** Set `EnableNetworkConfiguration=false` in `/etc/iwd/main.conf` and restart `iwd`.
- **Cause 4: Static profile or DHCP server issue.**
  - **Fix:** Inspect `journalctl -u systemd-networkd -n 50` and verify static gateway/address settings or router DHCP availability.

### Profile shows `secrets-required` or `auth-failed`

- **`auth-failed`:** The AP or RADIUS server rejected the passphrase/key. Kestrel stops retrying automatically instead of looping; update the secret with `kestrel profile edit <profile> --ask-secret` (or respond to `kestrel agent`), then reconnect.
- **`secrets-required`:** Either no secret was saved yet, or `systemd-creds` could not unseal `/var/lib/kestrel/secrets/<uuid>.cred` (for example after a TPM2 reset or re-running `systemd-creds setup --force`). Unreadable files are automatically quarantined as `*.cred.invalid`.
  - **Fix:** Verify the host credential key exists (`sudo systemd-creds setup`), then re-save the passphrase with `kestrel profile edit <profile> --ask-secret` (or supply it via `kestrel agent`).

### Hotspot clients connect and receive an IP, but have no internet access

- **Cause:** Kestrel configures `IPMasquerade=ipv4` on the hotspot unit, which enables forwarding on the AP link, but on `systemd-networkd` 256+ the **uplink** `.network` unit must also allow IPv4 forwarding, and host firewall rules (nftables/ufw/firewalld) must permit forwarding and DHCP (UDP 67/68).
- **Fix:**
  1. Add `IPv4Forwarding=yes` under `[Network]` in your uplink `.network` unit (or its `.network.d/` drop-in) and run `sudo networkctl reload`.
  2. Allow forwarded traffic from the allocated hotspot subnet (default `192.168.49.0/24` or `10.49.0.0/24`–`10.49.15.0/24`) in your firewall.

### Wi-Fi stays off after reboot

- **Cause:** `kestrel wifi off` persists `WirelessEnabled = false` in `/var/lib/kestrel/state.toml`.
- **Fix:** Run `kestrel wifi on`.

### Checking for Leftover State After a Crash

After a daemon crash or `kill -9`, restarting `kestrel` automatically runs `sweep()` across `systemd-networkd` and the L2 backend. You can verify the clean baseline manually:

```sh
ls /run/systemd/network/10-kestrel-* 2>/dev/null || echo "clean"
kestrel p2p sessions
kestrel hotspot status
```

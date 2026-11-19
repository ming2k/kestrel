# Failures, Errors, and Capabilities

Reference catalog of Kestrel's stable failure codes, D-Bus error names, polkit actions, and wireless backend capability boundaries.

---

## 1. Stable Failure Codes (`FailureReason`)

Exposed in `Device.LastFailure`, `Session.Failure`, `Hotspot.Failure`, `Manager.History`, and agent `RequestSecret(..., reason)`. Consumers must branch on the code string, never on the human-readable `…Detail` string.

| Code | Transient? | Meaning |
| :--- | :--- | :--- |
| `auth-failed` | No | The AP or RADIUS server rejected credentials. Marks the profile as needing secrets and prompts the agent once (no blind retry loop). |
| `secrets-required` | No | No usable secret is stored (or a `.cred` file failed to unseal and was quarantined) and no agent supplied one. |
| `not-found` | Yes | Target SSID or P2P peer is not in range. |
| `timeout` | Yes | A bounded stage timer elapsed (`scan`, `associating`, `l3`, `negotiation`, or `group_formation`). |
| `link-lost` | Yes | An established L2 link dropped and did not recover within `[timeouts].link_grace`. |
| `l3-failed` | Yes | `systemd-networkd` reported link configuration failure or did not reach readiness in time. |
| `negotiation-failed` | Yes | P2P Group Owner negotiation failed (detail includes the P2P status code). |
| `wps-failed` | No | WPS provisioning failed during P2P setup. |
| `peer-disconnected` | No | The remote peer ended the P2P group. |
| `no-subnet` | No | Every subnet in `[p2p].subnet_pool` is currently allocated to another P2P group or hotspot. |
| `device-unavailable` | No | Wireless interface disappeared, hardware rfkill engaged, or wireless was turned off. |
| `cancelled` | No | Operation was cancelled by the user or another consumer. |
| `not-supported` | No | The active wireless backend or driver cannot enforce the requested mode or feature. |
| `backend` | Yes | Unclassified error returned by the L2 or L3 backend; see `…Detail` and daemon logs. |

**Transient vs. non-transient behavior:** On transient station failures, Kestrel backs off exponentially and retries; after three consecutive failures the profile enters cooldown and autoconnect tries the next candidate. Non-transient failures stop immediately without retrying until user intervention or state change.

---

## 2. D-Bus Error Names (`com.hihusky.Kestrel.Error.*`)

The `kestrel` CLI prints the short error name (after the last `.`) followed by the message.

| Error Name | Meaning |
| :--- | :--- |
| `NoSuchDevice` | Referenced wireless interface does not exist. |
| `NoSuchProfile` | Referenced saved profile does not exist. |
| `NoSuchSession` | Referenced active P2P session does not exist. |
| `NoSuchCertificate` | Referenced imported certificate does not exist. |
| `NoSuchP2pGroup` | Referenced saved persistent P2P group does not exist. |
| `WirelessDisabled` | Operation requires wireless to be enabled (`WirelessEnabled = false` or hardware rfkill blocked). |
| `NotSupported` | Active backend or device lacks the required capability or security mode. |
| `Busy` | Resource is already held (for example: concurrent hotspot and P2P on one device, second active P2P session, second agent registration, or deleting a certificate still referenced by a profile). |
| `InvalidArgument` | Input failed validation (for example: malformed SSID, invalid CIDR, conflicting `--ca-cert` + `--system-ca`, or out-of-range frequency/intent). |
| `AccessDenied` | Polkit denied authorization for the calling user/session. |
| `Storage` | Failed to read or write persistent state under `/var/lib/kestrel/`. |
| `Backend` | Underlying L2 (`wpa_supplicant` / `iwd`) or L3 (`systemd-networkd`) daemon error. |
| `Stopped` | `kestrel-daemon` is shutting down. |

---

## 3. Polkit Actions (`data/com.hihusky.kestrel.policy`)

Read-only D-Bus calls require no polkit authorization. Root is always authorized.

| Action ID | Covered Operations | `allow_active` | `allow_inactive` | `allow_any` |
| :--- | :--- | :--- | :--- | :--- |
| `com.hihusky.kestrel.connect` | `Device.Scan`, `Connect`, `Disconnect`, `SetAutoconnect`; all `P2P.*` methods; `Session.Close` | `yes` | `auth_admin` | `auth_admin` |
| `com.hihusky.kestrel.hotspot` | `Hotspot.Start`, `Hotspot.Stop` | `yes` | `auth_admin` | `auth_admin` |
| `com.hihusky.kestrel.modify-profiles` | `Manager.AddProfile`, `ImportCertificate`; `Profile.Update`, `Delete`; `Certificate.Delete`; `P2pGroup.Delete` | `auth_admin_keep` | `auth_admin` | `auth_admin` |
| `com.hihusky.kestrel.toggle-wireless` | `Manager.SetWirelessEnabled` | `yes` | `auth_admin` | `auth_admin` |
| `com.hihusky.kestrel.register-agent` | `Manager.RegisterAgent` | `yes` | `auth_admin` | `auth_admin` |

---

## 4. Backend Capability Matrix

Kestrel never silently weakens a requested security mode. If a backend cannot enforce a mode, `Device.SupportedSecurity` omits it and operations fail cleanly with `NotSupported`.

| Feature / Security Mode | `wpa_supplicant` | `iwd` |
| :--- | :--- | :--- |
| Station: `open` | Yes | Yes |
| Station: `owe` (OWE-only, no downgrade) | Yes (driver-dependent) | No (`NotSupported`) |
| Station: `wpa-personal` (WPA2 / WPA3 transition) | Yes | Yes (auto-negotiates WPA2/WPA3) |
| Station: `wpa3-personal` (SAE-only, no downgrade) | Yes (driver-dependent) | No (`NotSupported`) |
| Station: `wpa-enterprise` (802.1X) | Yes | No (`NotSupported`) |
| Station: `wpa3-enterprise` (802.1X SHA-256 / Suite-B) | Yes (driver-dependent) | No (`NotSupported`) |
| Hotspot (SoftAP): `wpa-personal` | Yes (AP-capable driver) | Yes (AP-capable driver) |
| Hotspot (SoftAP): `open` | Yes (AP-capable driver) | No (`NotSupported`) |
| Hotspot (SoftAP): `wpa3-personal` (SAE AP) | Yes (driver-dependent) | No (`NotSupported`) |
| Wi-Fi Direct (P2P) & persistent groups | Yes (P2P-capable driver) | No (`NotSupported`) |
| Miracast / Wi-Fi Display (WFD) subelements | Yes (P2P-capable driver) | No (`NotSupported`) |
| Required daemon configuration | `wpa_supplicant -u` with no saved networks | `/etc/iwd/main.conf`: `EnableNetworkConfiguration=false` |

# Manage Network Profiles

Saved networks in Kestrel are stored as profiles under `/var/lib/kestrel/profiles/<uuid>.toml`, with passphrases encrypted separately via `systemd-creds`.

---

## 1. List and Inspect Profiles

```sh
# List saved profiles, highest priority first
kestrel profile list

# Show details for one profile (by UUID, name, or SSID)
kestrel profile show home
```

---

## 2. Create a Profile Without Connecting Immediately

```sh
kestrel profile add \
  --ssid "OfficeNet" \
  --security wpa3-personal \
  --priority 20 \
  --ask-secret
```

For hidden networks, pass `--hidden true` and specify `--security` explicitly (`open`, `owe`, `wpa-personal`, or `wpa3-personal`).

To supply a secret non-interactively without exposing it in process arguments, pipe it via standard input:

```sh
printf '%s\n' "$PASSPHRASE" | kestrel profile add \
  --ssid "OfficeNet" \
  --security wpa-personal \
  --secret-stdin
```

---

## 3. Configure Static IPv4/IPv6 or Custom DNS

Kestrel passes L3 settings to `systemd-networkd` through runtime `.network` units:

```sh
kestrel profile edit home \
  --l3 static \
  --address 192.168.10.50/24 \
  --gateway4 192.168.10.1 \
  --dns 1.1.1.1 \
  --dns 9.9.9.9 \
  --domain corp.example
```

To switch back to DHCP:

```sh
kestrel profile edit home --l3 dhcp --ipv6 auto
```

---

## 4. Control Autoconnect and Priorities

Higher `--priority` values are preferred during autoconnect:

```sh
kestrel profile edit home --priority 100 --autoconnect true
```

To pause autoconnect on a device without deleting profiles, use:

```sh
kestrel wifi autoconnect wlp0s20f3 off
```

Note that `kestrel wifi disconnect <device>` also holds autoconnect until an explicit `wifi connect` or `wifi autoconnect <device> on`.

---

## 5. Update or Clear a Stored Secret

```sh
# Replace the stored passphrase
kestrel profile edit home --ask-secret

# Remove the stored passphrase
kestrel profile edit home --clear-secret
```

---

## 6. Forget a Network

```sh
kestrel wifi forget home
# Or non-interactively:
kestrel profile delete home --yes
```

---

## 7. 802.1X / WPA-Enterprise Profiles

Enterprise networks need the public CA (and for EAP-TLS, a client
certificate) imported first. Kestrel stores only public certificate
material; private keys stay in the sealed secret store.

```sh
# Import the CA bundle sent by IT
kestrel certificate add ./corp-ca.pem --name "Corp CA"
kestrel certificate list
```

Create the profile with the `enterprise.*` flags; `--ca-cert` accepts the
certificate id, an id prefix, or its name:

```sh
# PEAP + MSCHAPv2 with a pinned CA and a RADIUS name check
kestrel profile add --ssid corp --security wpa-enterprise \
  --eap peap --identity alice@corp.example --phase2 mschapv2 \
  --ca-cert "Corp CA" --domain-suffix-match corp.example \
  --ask-secret

# EAP-TLS: the private key is read locally and sealed by systemd-creds
kestrel profile add --ssid corp-tls --security wpa3-enterprise \
  --eap tls --identity alice@corp.example \
  --ca-cert "Corp CA" --client-cert "Alice" \
  --private-key-file ./alice.key
```

```sh
kestrel profile show corp          # confirm security, EAP, and certificate ids
kestrel certificate delete <id> --yes   # refused while a profile uses it
```

`iwd` cannot enforce enterprise or WPA3-only modes: such profiles are
rejected with `NotSupported`, and `Device.SupportedSecurity` lists what the
active backend can do.

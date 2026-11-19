# 802.1X Enterprise Wi-Fi and Certificates

Kestrel supports WPA2-Enterprise (`wpa-enterprise`) and WPA3-Enterprise (`wpa3-enterprise`, SHA-256 / Suite-B without downgrade) using EAP-TLS, PEAP, EAP-TTLS, and EAP-PWD.

> **Backend requirement:** 802.1X enterprise security requires the **`wpa_supplicant`** backend. `iwd` cannot enforce enterprise profiles and rejects them with `NotSupported`. Verify support on your device first:
>
> ```sh
> kestrel status --json | jq '.devices[] | {interface, supported_security}'
> ```

---

## 1. Security Model for Certificates and Private Keys

Kestrel separates public trust anchors from private secrets:

- **Public certificates** (CA bundles and EAP-TLS client certificates) are imported with `kestrel certificate add` and stored as `0600` TOML records under `/var/lib/kestrel/certs/<uuid>.toml`. Public PEM text is never readable back over D-Bus; only metadata and SHA-256 fingerprints are exposed.
- **Private keys and passwords** are never stored in the certificate store. `kestrel` reads `--private-key-file` locally (maximum 256 KiB), sends it over D-Bus as a write-only secret bundle, and `kestrel-daemon` seals it with `systemd-creds` under `/var/lib/kestrel/secrets/<uuid>.cred`.
- At association time, Kestrel injects certificates and private keys into `wpa_supplicant` as in-memory `blob://kestrel-*` blobs and deletes those blobs on disconnect and during crash-recovery sweeps.

---

## 2. Import Public Certificates

Import a PEM CA certificate or CA bundle (maximum 1 MiB; pass `-` to read from stdin):

```sh
kestrel certificate add ./corp-ca.pem --name "Corp CA"
```

For EAP-TLS, import your public client certificate as well:

```sh
kestrel certificate add ./alice-cert.pem --name "Alice Client"
```

Inspect imported certificates and their SHA-256 fingerprints:

```sh
kestrel certificate list
kestrel certificate show "Corp CA"
```

Certificate references in `--ca-cert` and `--client-cert` accept the full UUID, an 8+ character UUID prefix, or the certificate's `--name`.

---

## 3. Create Enterprise Profiles

Enterprise profiles are created with `kestrel profile add` (not `kestrel wifi join`, which is for personal/open networks).

### PEAP + MSCHAPv2 (Username & Password with Pinned CA)

```sh
kestrel profile add \
  --ssid "CorpWiFi" \
  --security wpa-enterprise \
  --eap peap \
  --identity "alice@corp.example" \
  --anonymous-identity "anonymous@corp.example" \
  --phase2 mschapv2 \
  --ca-cert "Corp CA" \
  --domain-suffix-match corp.example \
  --ask-secret
```

### EAP-TTLS + PAP (Using the Host CA Store)

If your RADIUS server uses a publicly trusted certificate instead of a private CA, pass `--system-ca` instead of `--ca-cert`:

```sh
kestrel profile add \
  --ssid "Eduroam" \
  --security wpa-enterprise \
  --eap ttls \
  --identity "alice@uni.example" \
  --anonymous-identity "anonymous@uni.example" \
  --phase2 pap \
  --system-ca \
  --domain-suffix-match uni.example \
  --ask-secret
```

> **Mutual exclusion:** Setting both `--ca-cert` and `--system-ca true` on the same profile is rejected with `InvalidArgument` so server verification policy is never ambiguous.

### EAP-TLS (Client Certificate + Sealed Private Key)

```sh
kestrel profile add \
  --ssid "CorpTLS" \
  --security wpa3-enterprise \
  --eap tls \
  --identity "alice@corp.example" \
  --ca-cert "Corp CA" \
  --client-cert "Alice Client" \
  --private-key-file ./alice.key \
  --domain-suffix-match corp.example
```

If `./alice.key` is encrypted with a passphrase, supply that key passphrase on stdin (non-interactively) or omit `--private-key-password-stdin` to be prompted when running in a terminal:

```sh
printf '%s\n' "$KEY_PASSPHRASE" | kestrel profile add \
  --ssid "CorpTLS" \
  --security wpa3-enterprise \
  --eap tls \
  --identity "alice@corp.example" \
  --ca-cert "Corp CA" \
  --client-cert "Alice Client" \
  --private-key-file ./alice.key \
  --private-key-password-stdin
```

### EAP-PWD

```sh
kestrel profile add \
  --ssid "CampusPWD" \
  --security wpa3-enterprise \
  --eap pwd \
  --identity "alice@campus.example" \
  --ask-secret
```

### Additional RADIUS Identity Checks

Use `--altsubject-match` (repeatable) to enforce specific `SubjectAltName` patterns on the RADIUS server certificate, and `--clear-altsubject-match` to remove them when editing:

```sh
kestrel profile edit "CorpWiFi" \
  --altsubject-match "DNS:radius1.corp.example" \
  --altsubject-match "DNS:radius2.corp.example"
```

---

## 4. Connect and Verify

Connect using the saved profile and verify the configuration:

```sh
kestrel profile show "CorpWiFi"
kestrel wifi connect wlp0s20f3 "CorpWiFi"
kestrel wifi status wlp0s20f3
```

---

## 5. Rotate or Delete Certificates

Kestrel enforces referential integrity between profiles and certificates. Attempting to delete a certificate while any saved profile still references it fails with `Busy`:

```sh
# 1. Import the replacement certificate
kestrel certificate add ./corp-ca-new.pem --name "Corp CA 2027"

# 2. Switch every profile onto the new certificate
kestrel profile edit "CorpWiFi" --ca-cert "Corp CA 2027"

# 3. Delete the old certificate
kestrel certificate delete "Corp CA" --yes
```

Changing `--eap` or `--security` on an existing profile clears its stored secret bundle automatically; pass `--ask-secret`, `--secret-stdin`, or `--private-key-file` to install new credentials.

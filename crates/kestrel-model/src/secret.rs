// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;

use zeroize::Zeroizing;

use crate::{EapMethod, ModelError, P2pGroupId, ProfileId, ProfileSecurity, WifiProfile};

/// Identifies a sealed credential entry in the secret store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretKey {
    Profile(ProfileId),
    P2pGroup(P2pGroupId),
}

impl SecretKey {
    pub fn cred_name(self) -> String {
        match self {
            Self::Profile(id) => format!("kestrel-wifi-{}", id.simple()),
            Self::P2pGroup(id) => format!("kestrel-p2p-{}", id.simple()),
        }
    }

    pub fn file_stem(self) -> String {
        match self {
            Self::Profile(id) => id.simple(),
            Self::P2pGroup(id) => format!("p2p-{}", id.simple()),
        }
    }
}

/// A credential string held in memory.
///
/// - Its `Debug` output is redacted.
/// - It does not implement `Display`, `Serialize`, or `Clone`-into-`String`,
///   so it cannot leak through logs, D-Bus replies, or profile files by
///   accident.
/// - The backing buffer is zeroed on drop.
///
/// The only way to read it is [`Secret::expose`], which makes every use
/// greppable.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Validates a passphrase/PSK secret for personal security modes.
    pub fn validate_for(&self, security: ProfileSecurity) -> Result<(), ModelError> {
        let value = self.expose();
        match security {
            ProfileSecurity::Open | ProfileSecurity::Owe => Err(ModelError::InvalidSecret(
                "open and OWE networks do not take a secret",
            )),
            ProfileSecurity::WpaPersonal => {
                if value.len() == 64 {
                    return if value.bytes().all(|b| b.is_ascii_hexdigit()) {
                        Ok(())
                    } else {
                        Err(ModelError::InvalidSecret(
                            "a 64-character PSK must be hexadecimal",
                        ))
                    };
                }
                if !(8..=63).contains(&value.len()) {
                    return Err(ModelError::InvalidSecret(
                        "a WPA passphrase must be 8..=63 characters or 64 hexadecimal digits",
                    ));
                }
                if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                    return Err(ModelError::InvalidSecret(
                        "a WPA passphrase must be printable ASCII",
                    ));
                }
                Ok(())
            }
            ProfileSecurity::Wpa3Personal => {
                if value.is_empty() || value.len() > 128 {
                    return Err(ModelError::InvalidSecret(
                        "a SAE password must be 1..=128 bytes",
                    ));
                }
                if value.contains('\0') {
                    return Err(ModelError::InvalidSecret(
                        "a SAE password must not contain NUL",
                    ));
                }
                Ok(())
            }
            ProfileSecurity::WpaEnterprise | ProfileSecurity::Wpa3Enterprise => {
                if value.is_empty() || value.len() > 512 {
                    return Err(ModelError::InvalidSecret(
                        "an EAP password must be 1..=512 bytes",
                    ));
                }
                if value.contains('\0') {
                    return Err(ModelError::InvalidSecret(
                        "an EAP password must not contain NUL",
                    ));
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Complete credential bundle for a saved profile or persistent P2P group.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProfileSecrets {
    /// PSK / SAE passphrase, EAP password, or P2P group PSK.
    pub passphrase: Option<Secret>,
    /// PEM-encoded private key for EAP-TLS.
    pub private_key: Option<Secret>,
    /// Optional passphrase decrypting `private_key`.
    pub private_key_password: Option<Secret>,
}

impl ProfileSecrets {
    pub fn from_passphrase(secret: Secret) -> Self {
        Self {
            passphrase: Some(secret),
            private_key: None,
            private_key_password: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.passphrase.is_none()
            && self.private_key.is_none()
            && self.private_key_password.is_none()
    }

    /// Whether these credentials satisfy everything required to associate
    /// `profile` without prompting an agent.
    pub fn satisfies(&self, profile: &WifiProfile) -> bool {
        match (&profile.security, &profile.enterprise) {
            (ProfileSecurity::Open | ProfileSecurity::Owe, _) => true,
            (ProfileSecurity::WpaPersonal | ProfileSecurity::Wpa3Personal, _) => {
                self.passphrase.is_some()
            }
            (ProfileSecurity::WpaEnterprise | ProfileSecurity::Wpa3Enterprise, Some(ent)) => {
                match ent.eap {
                    EapMethod::Tls => self.private_key.is_some(),
                    EapMethod::Peap | EapMethod::Ttls | EapMethod::Pwd => self.passphrase.is_some(),
                }
            }
            (ProfileSecurity::WpaEnterprise | ProfileSecurity::Wpa3Enterprise, None) => false,
        }
    }

    /// Validates the supplied fields against `profile`.
    pub fn validate_for(&self, profile: &WifiProfile) -> Result<(), ModelError> {
        if self.is_empty() {
            return Ok(());
        }
        if !profile.security.needs_secret() {
            return Err(ModelError::InvalidSecret(
                "open and OWE networks do not take secrets",
            ));
        }
        if let Some(ent) = &profile.enterprise {
            match ent.eap {
                EapMethod::Tls => {
                    if self.passphrase.is_some() {
                        return Err(ModelError::InvalidSecret(
                            "EAP-TLS uses private_key, not passphrase",
                        ));
                    }
                    if let Some(key) = &self.private_key {
                        validate_private_key_pem(key.expose())?;
                    }
                    if let Some(pw) = &self.private_key_password {
                        if self.private_key.is_none() {
                            return Err(ModelError::InvalidSecret(
                                "private_key_password requires private_key",
                            ));
                        }
                        if pw.is_empty() || pw.len() > 512 || pw.expose().contains('\0') {
                            return Err(ModelError::InvalidSecret(
                                "private_key_password must be 1..=512 bytes without NUL",
                            ));
                        }
                    }
                }
                EapMethod::Peap | EapMethod::Ttls | EapMethod::Pwd => {
                    if self.private_key.is_some() || self.private_key_password.is_some() {
                        return Err(ModelError::InvalidSecret(
                            "private_key is only valid for EAP-TLS",
                        ));
                    }
                    if let Some(pass) = &self.passphrase {
                        pass.validate_for(profile.security)?;
                    }
                }
            }
        } else {
            if self.private_key.is_some() || self.private_key_password.is_some() {
                return Err(ModelError::InvalidSecret(
                    "private_key is only valid for 802.1X EAP-TLS profiles",
                ));
            }
            if let Some(pass) = &self.passphrase {
                pass.validate_for(profile.security)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ProfileSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileSecrets")
            .field("has_passphrase", &self.passphrase.is_some())
            .field("has_private_key", &self.private_key.is_some())
            .field(
                "has_private_key_password",
                &self.private_key_password.is_some(),
            )
            .finish()
    }
}

fn validate_private_key_pem(pem: &str) -> Result<(), ModelError> {
    if pem.is_empty() || pem.len() > 256 * 1024 || pem.contains('\0') {
        return Err(ModelError::InvalidSecret(
            "private_key must be 1..=262144 bytes without NUL",
        ));
    }
    let mut active_label: Option<String> = None;
    let mut found = false;
    let mut body_bytes = 0usize;
    let mut in_headers = false;
    for raw_line in pem.lines() {
        let line = raw_line.trim();
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
        {
            if active_label.is_some() || !label.ends_with("PRIVATE KEY") {
                return Err(ModelError::InvalidSecret(
                    "private_key must contain well-formed PRIVATE KEY PEM block(s)",
                ));
            }
            active_label = Some(label.to_owned());
            body_bytes = 0;
            in_headers = true;
        } else if let Some(label) = line
            .strip_prefix("-----END ")
            .and_then(|s| s.strip_suffix("-----"))
        {
            let Some(expected) = active_label.take() else {
                return Err(ModelError::InvalidSecret(
                    "unexpected END PRIVATE KEY marker",
                ));
            };
            if expected != label || body_bytes == 0 || !body_bytes.is_multiple_of(4) {
                return Err(ModelError::InvalidSecret(
                    "mismatched or invalid PRIVATE KEY PEM block",
                ));
            }
            found = true;
            in_headers = false;
        } else if active_label.is_some() {
            if line.is_empty() {
                in_headers = false;
            } else if in_headers && line.contains(':') {
                // RFC 1421 encrypted PEM header (e.g. Proc-Type, DEK-Info).
            } else {
                in_headers = false;
                if !line
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                {
                    return Err(ModelError::InvalidSecret(
                        "invalid base64 character in private_key PEM",
                    ));
                }
                body_bytes += line.len();
            }
        } else if !line.is_empty() {
            return Err(ModelError::InvalidSecret(
                "unexpected content outside PRIVATE KEY PEM block",
            ));
        }
    }
    if active_label.is_some() || !found {
        return Err(ModelError::InvalidSecret(
            "private_key must be a PEM-encoded PRIVATE KEY",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CertId, EnterpriseConfig, Ssid};

    #[test]
    fn debug_is_redacted() {
        let secret = Secret::new("correct horse battery staple");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("horse"), "{debug}");
        let bundle = ProfileSecrets::from_passphrase(secret);
        assert!(!format!("{bundle:?}").contains("horse"));
    }

    #[test]
    fn validates_wpa_personal() {
        let wpa = ProfileSecurity::WpaPersonal;
        assert!(Secret::new("short").validate_for(wpa).is_err());
        assert!(Secret::new("long enough").validate_for(wpa).is_ok());
        assert!(Secret::new("a".repeat(64)).validate_for(wpa).is_ok());
        assert!(Secret::new("z".repeat(64)).validate_for(wpa).is_err());
        assert!(Secret::new("tab\tinside!").validate_for(wpa).is_err());
    }

    #[test]
    fn validates_sae() {
        let sae = ProfileSecurity::Wpa3Personal;
        assert!(Secret::new("x").validate_for(sae).is_ok());
        assert!(Secret::new("").validate_for(sae).is_err());
        assert!(Secret::new("a".repeat(129)).validate_for(sae).is_err());
    }

    #[test]
    fn open_networks_take_no_secret() {
        assert!(
            Secret::new("whatever1")
                .validate_for(ProfileSecurity::Open)
                .is_err()
        );
    }

    #[test]
    fn validates_eap_tls_secrets() {
        let mut profile =
            WifiProfile::new(Ssid::new("corp").unwrap(), ProfileSecurity::Wpa3Enterprise);
        profile.enterprise = Some(EnterpriseConfig {
            eap: EapMethod::Tls,
            identity: "alice@corp.example".into(),
            anonymous_identity: None,
            phase2: None,
            ca_cert: Some(CertId::generate()),
            system_ca: false,
            client_cert: Some(CertId::generate()),
            domain_suffix_match: None,
            altsubject_match: Vec::new(),
        });
        let tls_ok = ProfileSecrets {
            passphrase: None,
            private_key: Some(Secret::new(
                "-----BEGIN PRIVATE KEY-----\nMAowAwIBAQMDAAEC\n-----END PRIVATE KEY-----\n",
            )),
            private_key_password: Some(Secret::new("unlock")),
        };
        tls_ok.validate_for(&profile).unwrap();
        assert!(tls_ok.satisfies(&profile));

        let bad = ProfileSecrets::from_passphrase(Secret::new("pw"));
        assert!(bad.validate_for(&profile).is_err());
    }
}

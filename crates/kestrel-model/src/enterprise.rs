// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{CertId, ModelError};

/// Supported 802.1X EAP outer authentication methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EapMethod {
    Tls,
    Peap,
    Ttls,
    Pwd,
}

impl EapMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Peap => "peap",
            Self::Ttls => "ttls",
            Self::Pwd => "pwd",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "tls" => Ok(Self::Tls),
            "peap" => Ok(Self::Peap),
            "ttls" => Ok(Self::Ttls),
            "pwd" => Ok(Self::Pwd),
            other => Err(ModelError::InvalidEnterprise(format!(
                "unsupported EAP method {other:?}"
            ))),
        }
    }

    pub const fn wpa_supplicant_name(self) -> &'static str {
        match self {
            Self::Tls => "TLS",
            Self::Peap => "PEAP",
            Self::Ttls => "TTLS",
            Self::Pwd => "PWD",
        }
    }

    pub const fn uses_phase2(self) -> bool {
        matches!(self, Self::Peap | Self::Ttls)
    }

    pub const fn uses_client_cert(self) -> bool {
        matches!(self, Self::Tls)
    }
}

impl fmt::Display for EapMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Inner Phase 2 authentication method for PEAP and TTLS tunnels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase2Auth {
    Mschapv2,
    Pap,
    Chap,
    Mschap,
    Gtc,
}

impl Phase2Auth {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mschapv2 => "mschapv2",
            Self::Pap => "pap",
            Self::Chap => "chap",
            Self::Mschap => "mschap",
            Self::Gtc => "gtc",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "mschapv2" => Ok(Self::Mschapv2),
            "pap" => Ok(Self::Pap),
            "chap" => Ok(Self::Chap),
            "mschap" => Ok(Self::Mschap),
            "gtc" => Ok(Self::Gtc),
            other => Err(ModelError::InvalidEnterprise(format!(
                "unsupported phase2 auth {other:?}"
            ))),
        }
    }

    pub const fn wpa_supplicant_phase2(self) -> &'static str {
        match self {
            Self::Mschapv2 => "auth=MSCHAPV2",
            Self::Pap => "auth=PAP",
            Self::Chap => "auth=CHAP",
            Self::Mschap => "auth=MSCHAP",
            Self::Gtc => "auth=GTC",
        }
    }
}

impl fmt::Display for Phase2Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 802.1X / WPA-Enterprise configuration for a saved profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseConfig {
    pub eap: EapMethod,
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase2: Option<Phase2Auth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<CertId>,
    #[serde(default)]
    pub system_ca: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<CertId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_suffix_match: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub altsubject_match: Vec<String>,
}

impl EnterpriseConfig {
    pub fn validate(&self) -> Result<(), ModelError> {
        let invalid = |msg: String| Err(ModelError::InvalidEnterprise(msg));
        if self.identity.trim().is_empty()
            || self.identity.len() > 256
            || self.identity.chars().any(char::is_control)
        {
            return invalid("identity must be 1..=256 non-control bytes".to_owned());
        }
        if let Some(anon) = &self.anonymous_identity
            && (anon.trim().is_empty() || anon.len() > 256 || anon.chars().any(char::is_control))
        {
            return invalid("anonymous_identity must be 1..=256 non-control bytes".to_owned());
        }
        if self.phase2.is_some() && !self.eap.uses_phase2() {
            return invalid(format!("phase2 is not valid for EAP-{}", self.eap));
        }
        if self.eap.uses_client_cert() {
            if self.client_cert.is_none() {
                return invalid("EAP-TLS requires a client_cert".to_owned());
            }
        } else if self.client_cert.is_some() {
            return invalid(format!(
                "client_cert is only used with EAP-TLS, not {}",
                self.eap
            ));
        }
        if self.ca_cert.is_some() && self.system_ca {
            return invalid("ca_cert and system_ca are mutually exclusive".to_owned());
        }
        if let Some(domain) = &self.domain_suffix_match
            && (domain.trim().is_empty()
                || domain.len() > 253
                || domain.chars().any(|c| c.is_control() || c.is_whitespace()))
        {
            return invalid("invalid domain_suffix_match".to_owned());
        }
        if self.altsubject_match.len() > 16 {
            return invalid("at most 16 altsubject_match entries are allowed".to_owned());
        }
        for entry in &self.altsubject_match {
            if entry.trim().is_empty()
                || entry.len() > 256
                || entry.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return invalid(format!("invalid altsubject_match entry {entry:?}"));
            }
        }
        Ok(())
    }

    pub fn referenced_certs(&self) -> Vec<CertId> {
        let mut certs = Vec::new();
        if let Some(ca) = self.ca_cert {
            certs.push(ca);
        }
        if let Some(client) = self.client_cert {
            certs.push(client);
        }
        certs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_enterprise_variants() {
        let mut tls = EnterpriseConfig {
            eap: EapMethod::Tls,
            identity: "alice@example.org".into(),
            anonymous_identity: None,
            phase2: None,
            ca_cert: Some(CertId::generate()),
            system_ca: false,
            client_cert: Some(CertId::generate()),
            domain_suffix_match: Some("radius.example.org".into()),
            altsubject_match: vec!["DNS:radius.example.org".into()],
        };
        tls.validate().unwrap();
        tls.client_cert = None;
        assert!(tls.validate().is_err());

        let mut peap = EnterpriseConfig {
            eap: EapMethod::Peap,
            identity: "alice@example.org".into(),
            anonymous_identity: Some("anon@example.org".into()),
            phase2: Some(Phase2Auth::Mschapv2),
            ca_cert: None,
            system_ca: true,
            client_cert: None,
            domain_suffix_match: None,
            altsubject_match: Vec::new(),
        };
        peap.validate().unwrap();
        peap.ca_cert = Some(CertId::generate());
        assert!(peap.validate().is_err());
    }
}

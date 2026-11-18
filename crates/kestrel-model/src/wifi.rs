// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{MacAddress, ModelError};

/// A validated 802.11 SSID.
///
/// SSIDs are byte strings of 1–32 bytes. Configuration files and D-Bus carry
/// them as UTF-8 strings; the model keeps the bytes so a later backend can
/// preserve non-UTF-8 SSIDs if the API grows a byte-oriented form.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ssid(Vec<u8>);

impl Ssid {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::from_bytes(value.into().into_bytes())
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ModelError> {
        if bytes.is_empty() {
            return Err(ModelError::InvalidSsid("must not be empty".to_owned()));
        }
        if bytes.len() > 32 {
            return Err(ModelError::InvalidSsid(
                "must be at most 32 bytes".to_owned(),
            ));
        }
        if bytes.contains(&0) {
            return Err(ModelError::InvalidSsid(
                "must not contain NUL bytes".to_owned(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl fmt::Debug for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ssid")
            .field(&self.to_string_lossy())
            .finish()
    }
}

impl fmt::Display for Ssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

impl FromStr for Ssid {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for Ssid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string_lossy())
    }
}

impl<'de> Deserialize<'de> for Ssid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SsidVisitor;

        impl Visitor<'_> for SsidVisitor {
            type Value = Ssid;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an SSID of 1 to 32 bytes")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ssid::new(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(SsidVisitor)
    }
}

/// Security advertised by a BSS, as classified by a wireless backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Security {
    Open,
    Owe,
    Wep,
    /// WPA1 personal.
    WpaPsk,
    Wpa2Psk,
    /// WPA2-PSK and WPA3-SAE transition mode.
    Wpa2Wpa3,
    Wpa3Sae,
    Enterprise,
    Wpa3Enterprise,
    Unknown,
}

impl Security {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Owe => "owe",
            Self::Wep => "wep",
            Self::WpaPsk => "wpa-psk",
            Self::Wpa2Psk => "wpa2-psk",
            Self::Wpa2Wpa3 => "wpa2-wpa3",
            Self::Wpa3Sae => "wpa3-sae",
            Self::Enterprise => "enterprise",
            Self::Wpa3Enterprise => "wpa3-enterprise",
            Self::Unknown => "unknown",
        }
    }

    /// The profile security that can join a BSS advertising this security,
    /// if Kestrel supports it.
    pub const fn profile_security(self) -> Option<ProfileSecurity> {
        match self {
            Self::Open => Some(ProfileSecurity::Open),
            Self::Owe => Some(ProfileSecurity::Owe),
            Self::WpaPsk | Self::Wpa2Psk | Self::Wpa2Wpa3 => Some(ProfileSecurity::WpaPersonal),
            Self::Wpa3Sae => Some(ProfileSecurity::Wpa3Personal),
            Self::Enterprise => Some(ProfileSecurity::WpaEnterprise),
            Self::Wpa3Enterprise => Some(ProfileSecurity::Wpa3Enterprise),
            Self::Wep | Self::Unknown => None,
        }
    }
}

impl fmt::Display for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Security of a saved network profile.
///
/// WEP is deliberately not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileSecurity {
    Open,
    /// Opportunistic Wireless Encryption (Enhanced Open).
    Owe,
    /// WPA2-PSK, accepting WPA3-SAE transition-mode networks.
    WpaPersonal,
    /// WPA3-SAE only. Never downgrades to PSK.
    Wpa3Personal,
    /// WPA2/WPA3-Enterprise (802.1X).
    WpaEnterprise,
    /// WPA3-Enterprise only (SHA-256 / Suite-B with PMF required).
    Wpa3Enterprise,
}

impl ProfileSecurity {
    pub const ALL: [Self; 6] = [
        Self::Open,
        Self::Owe,
        Self::WpaPersonal,
        Self::Wpa3Personal,
        Self::WpaEnterprise,
        Self::Wpa3Enterprise,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Owe => "owe",
            Self::WpaPersonal => "wpa-personal",
            Self::Wpa3Personal => "wpa3-personal",
            Self::WpaEnterprise => "wpa-enterprise",
            Self::Wpa3Enterprise => "wpa3-enterprise",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "open" => Ok(Self::Open),
            "owe" => Ok(Self::Owe),
            "wpa-personal" => Ok(Self::WpaPersonal),
            "wpa3-personal" => Ok(Self::Wpa3Personal),
            "wpa-enterprise" => Ok(Self::WpaEnterprise),
            "wpa3-enterprise" => Ok(Self::Wpa3Enterprise),
            other => Err(ModelError::InvalidProfile(format!(
                "unsupported security {other:?}"
            ))),
        }
    }

    pub const fn is_enterprise(self) -> bool {
        matches!(self, Self::WpaEnterprise | Self::Wpa3Enterprise)
    }

    pub const fn needs_secret(self) -> bool {
        matches!(
            self,
            Self::WpaPersonal | Self::Wpa3Personal | Self::WpaEnterprise | Self::Wpa3Enterprise
        )
    }

    /// Maps the security string of a scan result (as exposed by the D-Bus
    /// API) to the profile security that can join it. Returns `None` for
    /// security types Kestrel cannot configure.
    pub fn from_scan_security(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "owe" => Some(Self::Owe),
            "wpa-psk" | "wpa2-psk" | "wpa2-wpa3" => Some(Self::WpaPersonal),
            "wpa3-sae" => Some(Self::Wpa3Personal),
            "enterprise" => Some(Self::WpaEnterprise),
            "wpa3-enterprise" => Some(Self::Wpa3Enterprise),
            _ => None,
        }
    }

    /// Whether a profile with this security may join a BSS advertising
    /// `advertised`. A WPA3-only profile never joins a PSK-only BSS, and a
    /// WPA3-Enterprise profile never joins a legacy Enterprise BSS.
    pub const fn accepts(self, advertised: Security) -> bool {
        match self {
            Self::Open => matches!(advertised, Security::Open),
            Self::Owe => matches!(advertised, Security::Owe),
            Self::WpaPersonal => matches!(
                advertised,
                Security::WpaPsk | Security::Wpa2Psk | Security::Wpa2Wpa3 | Security::Wpa3Sae
            ),
            Self::Wpa3Personal => matches!(advertised, Security::Wpa2Wpa3 | Security::Wpa3Sae),
            Self::WpaEnterprise => {
                matches!(advertised, Security::Enterprise | Security::Wpa3Enterprise)
            }
            Self::Wpa3Enterprise => matches!(advertised, Security::Wpa3Enterprise),
        }
    }

    /// Relative strength, used to rank otherwise equal candidates.
    pub const fn strength(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Owe => 1,
            Self::WpaPersonal => 2,
            Self::Wpa3Personal => 3,
            Self::WpaEnterprise => 4,
            Self::Wpa3Enterprise => 5,
        }
    }
}

impl fmt::Display for ProfileSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Link or host online reachability reported by the L3 provider.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum OnlineState {
    #[default]
    Offline,
    Unknown,
    Partial,
    Online,
}

impl OnlineState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Unknown => "unknown",
            Self::Partial => "partial",
            Self::Online => "online",
        }
    }

    pub fn from_networkd(value: Option<&str>) -> Self {
        match value {
            Some("online") => Self::Online,
            Some("partial") => Self::Partial,
            Some("offline") | None => Self::Offline,
            Some(_) => Self::Unknown,
        }
    }
}

impl fmt::Display for OnlineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One BSS seen in a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bss {
    pub ssid: Ssid,
    pub bssid: MacAddress,
    /// Centre frequency in MHz; 0 when the backend does not report it.
    pub frequency: u32,
    /// Signal strength in dBm.
    pub signal: i16,
    pub security: Security,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssid_length_is_enforced() {
        assert!(Ssid::new("").is_err());
        assert!(Ssid::new("a".repeat(32)).is_ok());
        assert!(Ssid::new("a".repeat(33)).is_err());
        assert!(Ssid::new("a\0b").is_err());
    }

    #[test]
    fn wpa3_only_never_joins_psk_only() {
        assert!(!ProfileSecurity::Wpa3Personal.accepts(Security::Wpa2Psk));
        assert!(ProfileSecurity::Wpa3Personal.accepts(Security::Wpa2Wpa3));
        assert!(ProfileSecurity::WpaPersonal.accepts(Security::Wpa3Sae));
        assert!(!ProfileSecurity::Open.accepts(Security::Owe));
        assert!(!ProfileSecurity::WpaPersonal.accepts(Security::Enterprise));
    }

    #[test]
    fn security_round_trips_through_strings() {
        for security in [
            ProfileSecurity::Open,
            ProfileSecurity::Owe,
            ProfileSecurity::WpaPersonal,
            ProfileSecurity::Wpa3Personal,
        ] {
            assert_eq!(ProfileSecurity::parse(security.as_str()).unwrap(), security);
        }
    }

    #[test]
    fn scan_security_maps_to_a_profile_security() {
        assert_eq!(
            ProfileSecurity::from_scan_security("wpa2-psk"),
            Some(ProfileSecurity::WpaPersonal)
        );
        assert_eq!(
            ProfileSecurity::from_scan_security("wpa2-wpa3"),
            Some(ProfileSecurity::WpaPersonal)
        );
        assert_eq!(
            ProfileSecurity::from_scan_security("wpa3-sae"),
            Some(ProfileSecurity::Wpa3Personal)
        );
        assert_eq!(
            ProfileSecurity::from_scan_security("owe"),
            Some(ProfileSecurity::Owe)
        );
        assert_eq!(
            ProfileSecurity::from_scan_security("open"),
            Some(ProfileSecurity::Open)
        );
        assert_eq!(ProfileSecurity::from_scan_security("wep"), None);
        assert_eq!(
            ProfileSecurity::from_scan_security("enterprise"),
            Some(ProfileSecurity::WpaEnterprise)
        );
        assert_eq!(
            ProfileSecurity::from_scan_security("wpa3-enterprise"),
            Some(ProfileSecurity::Wpa3Enterprise)
        );
    }
}

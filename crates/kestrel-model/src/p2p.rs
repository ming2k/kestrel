// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{MacAddress, ModelError, Ssid};

/// Stable identity of a saved persistent Wi-Fi Direct group.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct P2pGroupId(Uuid);

impl P2pGroupId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| ModelError::InvalidP2pGroupId(value.to_owned()))
    }

    pub fn simple(&self) -> String {
        self.0.simple().to_string()
    }
}

impl fmt::Debug for P2pGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P2pGroupId({})", self.0)
    }
}

impl fmt::Display for P2pGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for P2pGroupId {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A saved persistent Wi-Fi Direct group owned by Kestrel.
///
/// The group PSK lives separately in the secret store under
/// `SecretKey::P2pGroup(id)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct P2pGroupProfile {
    pub id: P2pGroupId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<MacAddress>,
    pub role: P2pRole,
    pub ssid: Ssid,
    pub go_address: MacAddress,
    #[serde(default)]
    pub last_connected: Option<u64>,
}

impl P2pGroupProfile {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.name.trim().is_empty() || self.name.chars().count() > 64 {
            return Err(ModelError::InvalidP2pGroup(
                "name must be 1..=64 characters".to_owned(),
            ));
        }
        if self.name.chars().any(char::is_control) {
            return Err(ModelError::InvalidP2pGroup(
                "name must not contain control characters".to_owned(),
            ));
        }
        if self.go_address.is_zero() || self.go_address.is_multicast() {
            return Err(ModelError::InvalidP2pGroup(format!(
                "invalid group owner address {}",
                self.go_address
            )));
        }
        if let Some(peer) = self.peer
            && (peer.is_zero() || peer.is_multicast())
        {
            return Err(ModelError::InvalidP2pGroup(format!(
                "invalid peer address {peer}"
            )));
        }
        Ok(())
    }
}

/// Identifier of an active Wi-Fi Direct session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Wi-Fi Direct Group Owner intent, 0..=15. Higher means "prefer to be GO";
/// 15 forces GO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct GoIntent(u8);

impl GoIntent {
    pub const MAX: Self = Self(15);

    pub const fn new(value: u8) -> Result<Self, ModelError> {
        if value <= 15 {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidGoIntent(value))
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for GoIntent {
    /// The Wi-Fi Alliance and `wpa_supplicant` default.
    fn default() -> Self {
        Self(7)
    }
}

impl TryFrom<u8> for GoIntent {
    type Error = ModelError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<GoIntent> for u8 {
    fn from(value: GoIntent) -> Self {
        value.0
    }
}

/// A WPS PIN: 4 or 8 decimal digits. An 8-digit PIN must carry a valid WPS
/// checksum digit. Zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct WpsPin(Zeroizing<String>);

impl WpsPin {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ModelError::InvalidWpsPin("must contain only digits"));
        }
        match value.len() {
            4 => Ok(Self(Zeroizing::new(value))),
            8 => {
                if checksum_ok(&value) {
                    Ok(Self(Zeroizing::new(value)))
                } else {
                    Err(ModelError::InvalidWpsPin("checksum digit is wrong"))
                }
            }
            _ => Err(ModelError::InvalidWpsPin("must be 4 or 8 digits")),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// WPS PIN checksum from the Wi-Fi Simple Configuration specification.
fn checksum_ok(pin: &str) -> bool {
    let digits: Vec<u32> = pin.bytes().map(|b| u32::from(b - b'0')).collect();
    let mut accum = 0;
    for (index, digit) in digits.iter().enumerate() {
        accum += if index % 2 == 0 { 3 * digit } else { *digit };
    }
    accum % 10 == 0
}

impl fmt::Debug for WpsPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A PIN is a short-lived credential.
        f.write_str("WpsPin(<redacted>)")
    }
}

/// How WPS provisioning is performed for a P2P connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WpsMethod {
    /// Push-button on both sides.
    PushButton,
    /// This device shows a PIN; the peer enters it. The backend generates
    /// the PIN.
    DisplayPin,
    /// The user enters the PIN shown by the peer.
    EnterPin(WpsPin),
}

impl WpsMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PushButton => "pbc",
            Self::DisplayPin => "display",
            Self::EnterPin(_) => "keypad",
        }
    }
}

/// The role this device took in a P2P group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum P2pRole {
    GroupOwner,
    Client,
}

impl P2pRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GroupOwner => "group-owner",
            Self::Client => "client",
        }
    }
}

impl fmt::Display for P2pRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A Wi-Fi Direct peer seen during discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pPeer {
    /// P2P device address.
    pub address: MacAddress,
    pub name: String,
    /// Primary device type, as `category-OUI-subcategory`, when known.
    pub device_type: Option<String>,
    /// Raw Wi-Fi Display subelements, for Miracast consumers.
    pub wfd_subelements: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_intent_range() {
        assert!(GoIntent::new(15).is_ok());
        assert!(GoIntent::new(16).is_err());
        assert_eq!(GoIntent::default().get(), 7);
    }

    #[test]
    fn wps_pin_checksum() {
        // 12345670 is the canonical valid example PIN.
        assert!(WpsPin::new("12345670").is_ok());
        assert!(WpsPin::new("12345678").is_err());
        assert!(WpsPin::new("1234").is_ok());
        assert!(WpsPin::new("123").is_err());
        assert!(WpsPin::new("12a4").is_err());
        assert!(!format!("{:?}", WpsPin::new("1234").unwrap()).contains("1234"));
    }
}

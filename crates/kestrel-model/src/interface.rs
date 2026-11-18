// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ModelError;

/// A validated Linux interface name.
///
/// The kernel limit is `IFNAMSIZ - 1` (15 bytes). Names are not normalized;
/// callers must not silently rename an interface.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn new(name: impl Into<String>) -> Result<Self, ModelError> {
        let name = name.into();
        let reason = if name.is_empty() {
            Some("must not be empty")
        } else if name.len() > 15 {
            Some("must be at most 15 bytes")
        } else if name == "." || name == ".." {
            Some("must not be '.' or '..'")
        } else if name.bytes().any(|b| {
            b == b'/'
                || b == b':'
                || b == b'\\'
                || matches!(b, b'*' | b'?' | b'[' | b']' | b'!')
                || b.is_ascii_control()
                || b.is_ascii_whitespace()
        }) {
            Some("must not contain '/', ':', glob metacharacters, control bytes, or whitespace")
        } else {
            None
        };

        match reason {
            Some(reason) => Err(ModelError::InvalidInterfaceName { name, reason }),
            None => Ok(Self(name)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("InterfaceName").field(&self.0).finish()
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for InterfaceName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for InterfaceName {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for InterfaceName {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for InterfaceName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NameVisitor;

        impl Visitor<'_> for NameVisitor {
            type Value = InterfaceName;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a valid Linux interface name")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                InterfaceName::new(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NameVisitor)
    }
}

/// A validated 48-bit Ethernet MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub const fn from_octets(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        let sep = if value.contains(':') && !value.contains('-') {
            ':'
        } else if value.contains('-') && !value.contains(':') {
            '-'
        } else {
            return Err(ModelError::InvalidMacAddress(value.to_owned()));
        };
        let parts: Vec<&str> = value.split(sep).collect();
        if parts.len() != 6 {
            return Err(ModelError::InvalidMacAddress(value.to_owned()));
        }

        let mut octets = [0u8; 6];
        for (slot, part) in octets.iter_mut().zip(parts) {
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ModelError::InvalidMacAddress(value.to_owned()));
            }
            *slot = u8::from_str_radix(part, 16)
                .map_err(|_| ModelError::InvalidMacAddress(value.to_owned()))?;
        }
        Ok(Self(octets))
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    pub const fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub const fn is_zero(self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0])
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MacAddress")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for MacAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_interface_names() {
        assert!(InterfaceName::new("wlan0").is_ok());
        assert!(InterfaceName::new("p2p-wlan0-0").is_ok());
        assert!(InterfaceName::new("").is_err());
        assert!(InterfaceName::new("a".repeat(16)).is_err());
        assert!(InterfaceName::new("..").is_err());
        assert!(InterfaceName::new("wl an").is_err());
        assert!(InterfaceName::new("a/b").is_err());
        assert!(InterfaceName::new("wlan*").is_err());
        assert!(InterfaceName::new("wlan?").is_err());
        assert!(InterfaceName::new("wl\x0ban").is_err());
    }

    #[test]
    fn parses_and_formats_mac_addresses() {
        let mac = MacAddress::parse("02-00-00-AB-cd-01").unwrap();
        assert_eq!(mac.to_string(), "02:00:00:ab:cd:01");
        assert!(MacAddress::parse("02:00:00:00:00").is_err());
        assert!(MacAddress::parse("02:00:00:00:00:zz").is_err());
        assert!(MacAddress::parse("+1:+2:+3:+4:+5:+6").is_err());
        assert!(MacAddress::parse("02:00-00:00:00:01").is_err());
        assert!(MacAddress::from_octets([1, 0, 0, 0, 0, 0]).is_multicast());
        assert!(MacAddress::from_octets([0; 6]).is_zero());
    }
}

// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ModelError, Ssid};

/// Security mode for a SoftAP / hotspot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HotspotSecurity {
    Open,
    /// WPA2-PSK.
    WpaPersonal,
    /// WPA3-SAE only.
    Wpa3Personal,
}

impl HotspotSecurity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::WpaPersonal => "wpa-personal",
            Self::Wpa3Personal => "wpa3-personal",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "open" => Ok(Self::Open),
            "wpa-personal" => Ok(Self::WpaPersonal),
            "wpa3-personal" => Ok(Self::Wpa3Personal),
            other => Err(ModelError::InvalidHotspot(format!(
                "unsupported hotspot security {other:?}"
            ))),
        }
    }

    pub const fn needs_secret(self) -> bool {
        matches!(self, Self::WpaPersonal | Self::Wpa3Personal)
    }
}

impl fmt::Display for HotspotSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration to start a SoftAP / hotspot on a wireless device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotspotConfig {
    pub ssid: Ssid,
    pub security: HotspotSecurity,
    /// Operating frequency in MHz (`None` lets the backend pick a default).
    pub frequency: Option<u32>,
    pub hidden: bool,
}

impl HotspotConfig {
    pub fn validate(&self) -> Result<(), ModelError> {
        if let Some(freq) = self.frequency {
            let valid_24 = (2412..=2484).contains(&freq);
            let valid_5_6 = (4900..=7125).contains(&freq);
            if !(valid_24 || valid_5_6) {
                return Err(ModelError::InvalidHotspot(format!(
                    "frequency {freq} MHz is outside valid 2.4/5/6 GHz bands"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_hotspot_frequency() {
        let mut cfg = HotspotConfig {
            ssid: Ssid::new("kestrel-ap").unwrap(),
            security: HotspotSecurity::WpaPersonal,
            frequency: Some(2412),
            hidden: false,
        };
        cfg.validate().unwrap();
        cfg.frequency = Some(5180);
        cfg.validate().unwrap();
        cfg.frequency = Some(100);
        assert!(cfg.validate().is_err());
    }
}

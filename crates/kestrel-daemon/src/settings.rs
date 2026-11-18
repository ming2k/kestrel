// SPDX-License-Identifier: LGPL-2.1-or-later

//! `/etc/kestrel/kestrel.toml`: administrator settings. Every key is
//! optional, unknown keys are rejected, and values are validated before
//! anything starts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kestrel_controller::{ControllerConfig, HotspotConfig, SessionConfig, StationConfig};
use kestrel_model::{GoIntent, Ipv4Net};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum SettingsError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid settings in {path}: {message}")]
    Invalid { path: PathBuf, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WirelessBackend {
    /// `wpa_supplicant` if it is on the bus, else iwd.
    #[default]
    Auto,
    WpaSupplicant,
    Iwd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum L3Backend {
    #[default]
    Networkd,
    /// L2 only: every profile must be `l3 = unmanaged`; P2P is unavailable.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SecretBackend {
    /// `systemd-creds` with the host key and/or TPM2. Requires root.
    #[default]
    SystemdCreds,
    /// `systemd-creds --user`, for unprivileged development instances.
    SystemdCredsUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Authorization {
    /// polkit decides every mutating call. The production setting.
    #[default]
    Polkit,
    /// Only the D-Bus policy applies. For private or session buses.
    BusPolicy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Wireless {
    pub(crate) backend: WirelessBackend,
    pub(crate) enabled: bool,
}

impl Default for Wireless {
    fn default() -> Self {
        Self {
            backend: WirelessBackend::Auto,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct L3 {
    pub(crate) backend: L3Backend,
    pub(crate) unit_dir: PathBuf,
}

impl Default for L3 {
    fn default() -> Self {
        Self {
            backend: L3Backend::Networkd,
            unit_dir: PathBuf::from("/run/systemd/network"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Storage {
    pub(crate) profiles: PathBuf,
    pub(crate) secrets: PathBuf,
    pub(crate) certs: PathBuf,
    pub(crate) p2p_groups: PathBuf,
    pub(crate) history: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) secret_backend: SecretBackend,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            profiles: PathBuf::from("/var/lib/kestrel/profiles"),
            secrets: PathBuf::from("/var/lib/kestrel/secrets"),
            certs: PathBuf::from("/var/lib/kestrel/certs"),
            p2p_groups: PathBuf::from("/var/lib/kestrel/p2p-groups"),
            history: PathBuf::from("/var/lib/kestrel/history.jsonl"),
            state: PathBuf::from("/var/lib/kestrel/state.toml"),
            secret_backend: SecretBackend::SystemdCreds,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Api {
    pub(crate) authorization: Authorization,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct P2p {
    pub(crate) device_name: String,
    pub(crate) go_intent: u8,
    pub(crate) subnet_pool: Vec<Ipv4Net>,
}

impl Default for P2p {
    fn default() -> Self {
        Self {
            device_name: "Kestrel".to_owned(),
            go_intent: GoIntent::default().get(),
            subnet_pool: ControllerConfig::default().subnet_pool,
        }
    }
}

/// All timeouts in seconds.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Timeouts {
    pub(crate) scan: u64,
    pub(crate) association: u64,
    pub(crate) l3: u64,
    pub(crate) link_grace: u64,
    pub(crate) negotiation: u64,
    pub(crate) group_formation: u64,
    pub(crate) agent: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        let station = StationConfig::default();
        let session = SessionConfig::default();
        Self {
            scan: station.scan_timeout.as_secs(),
            association: station.associate_timeout.as_secs(),
            l3: station.l3_timeout.as_secs(),
            link_grace: station.link_grace.as_secs(),
            negotiation: session.negotiation_timeout.as_secs(),
            group_formation: session.formation_timeout.as_secs(),
            agent: 120,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) wireless: Wireless,
    pub(crate) l3: L3,
    pub(crate) storage: Storage,
    pub(crate) api: Api,
    pub(crate) p2p: P2p,
    pub(crate) timeouts: Timeouts,
}

impl Settings {
    /// Loads and validates `path`. A missing file means defaults.
    pub(crate) fn load(path: &Path) -> Result<Self, SettingsError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(SettingsError::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        let invalid = |message: String| SettingsError::Invalid {
            path: path.to_owned(),
            message,
        };
        let settings: Self = toml::from_str(&text).map_err(|e| invalid(e.to_string()))?;
        settings.validate().map_err(invalid)?;
        Ok(settings)
    }

    fn validate(&self) -> Result<(), String> {
        GoIntent::new(self.p2p.go_intent).map_err(|e| e.to_string())?;
        let name = &self.p2p.device_name;
        if name.is_empty() || name.len() > 32 || name.chars().any(char::is_control) {
            return Err("p2p.device_name must be 1..=32 bytes without control characters".into());
        }
        if self.p2p.subnet_pool.is_empty() {
            return Err("p2p.subnet_pool must not be empty".into());
        }
        if let Some(net) = self.p2p.subnet_pool.iter().find(|n| n.prefix_len() > 30) {
            return Err(format!(
                "p2p.subnet_pool entry {net} is too small (maximum /30)"
            ));
        }
        let t = &self.timeouts;
        for (name, value) in [
            ("scan", t.scan),
            ("association", t.association),
            ("l3", t.l3),
            ("negotiation", t.negotiation),
            ("group_formation", t.group_formation),
        ] {
            if !(1..=3600).contains(&value) {
                return Err(format!("timeouts.{name} must be 1..=3600 seconds"));
            }
        }
        // Agent calls ride on the daemon's D-Bus connection, whose method
        // timeout is 120 seconds; a longer agent timeout could never apply.
        if !(1..=120).contains(&t.agent) {
            return Err("timeouts.agent must be 1..=120 seconds".into());
        }
        if t.link_grace > 600 {
            return Err("timeouts.link_grace must be at most 600 seconds".into());
        }
        Ok(())
    }

    pub(crate) fn controller_config(&self) -> ControllerConfig {
        let t = &self.timeouts;
        let secs = Duration::from_secs;
        ControllerConfig {
            station: StationConfig {
                scan_timeout: secs(t.scan),
                associate_timeout: secs(t.association),
                l3_timeout: secs(t.l3),
                link_grace: secs(t.link_grace),
                ..StationConfig::default()
            },
            session: SessionConfig {
                negotiation_timeout: secs(t.negotiation),
                formation_timeout: secs(t.group_formation),
                l3_timeout: secs(t.l3),
            },
            hotspot: HotspotConfig {
                l3_timeout: secs(t.l3),
                ..HotspotConfig::default()
            },
            hardware_enabled: None,
            subnet_pool: self.p2p.subnet_pool.clone(),
            p2p_device_name: self.p2p.device_name.clone(),
            default_go_intent: GoIntent::new(self.p2p.go_intent).unwrap_or_default(),
            agent_timeout: secs(t.agent),
            wireless_enabled: self.wireless.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Settings, SettingsError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kestrel.toml");
        std::fs::write(&path, text).unwrap();
        Settings::load(&path)
    }

    #[test]
    fn missing_file_means_defaults() {
        let settings = Settings::load(Path::new("/nonexistent/kestrel.toml")).unwrap();
        assert_eq!(settings.wireless.backend, WirelessBackend::Auto);
        assert_eq!(settings.api.authorization, Authorization::Polkit);
        assert_eq!(settings.storage.secret_backend, SecretBackend::SystemdCreds);
    }

    #[test]
    fn parses_a_full_file() {
        let settings = parse(
            r#"
            [wireless]
            backend = "iwd"
            enabled = false
            [l3]
            backend = "none"
            [storage]
            secret-backend = "systemd-creds-user"
            [api]
            authorization = "bus-policy"
            [p2p]
            device_name = "Living room"
            go_intent = 15
            subnet_pool = ["192.168.77.0/24"]
            [timeouts]
            association = 45
            "#,
        );
        // Field names are snake_case; enum values kebab-case.
        assert!(settings.is_err(), "secret-backend is not a key");
        let settings = parse(
            r#"
            [wireless]
            backend = "iwd"
            [storage]
            secret_backend = "systemd-creds-user"
            [p2p]
            go_intent = 15
            subnet_pool = ["192.168.77.0/24"]
            [timeouts]
            association = 45
            "#,
        )
        .unwrap();
        assert_eq!(settings.wireless.backend, WirelessBackend::Iwd);
        let config = settings.controller_config();
        assert_eq!(config.default_go_intent.get(), 15);
        assert_eq!(config.station.associate_timeout, Duration::from_secs(45));
    }

    /// The shipped example must stay valid, and must state the defaults.
    #[test]
    fn example_config_is_valid_and_matches_the_defaults() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
        let example = Settings::load(&path).unwrap();
        let defaults = Settings::default();
        assert_eq!(format!("{example:?}"), format!("{defaults:?}"));
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse("[p2p]\ngo_intent = 16\n").is_err());
        assert!(parse("[p2p]\nsubnet_pool = []\n").is_err());
        assert!(parse("[p2p]\nsubnet_pool = [\"10.0.0.0/31\"]\n").is_err());
        assert!(parse("[timeouts]\nscan = 0\n").is_err());
        assert!(parse("[timeouts]\nagent = 121\n").is_err());
        assert!(parse("[nonsense]\n").is_err());
        assert!(parse("[wireless]\nbackend = \"connman\"\n").is_err());
    }
}

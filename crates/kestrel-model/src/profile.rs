// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CertId, EnterpriseConfig, MacAddress, ModelError, ProfileSecurity, Ssid};

/// Stable identity of a saved network profile.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(Uuid);

impl ProfileId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| ModelError::InvalidProfileId(value.to_owned()))
    }

    /// Lowercase hex without hyphens. Safe for file names and D-Bus object
    /// path elements.
    pub fn simple(&self) -> String {
        self.0.simple().to_string()
    }
}

impl fmt::Debug for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProfileId({})", self.0)
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for ProfileId {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// IPv6 behaviour for a dynamically configured link.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Mode {
    Disabled,
    /// Router Advertisements: SLAAC and DHCPv6 as the router instructs.
    #[default]
    Auto,
}

/// Static addressing passed through to the L3 provider verbatim.
///
/// Kestrel validates it but never applies it itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticIp {
    pub addresses: Vec<IpNet>,
    #[serde(default)]
    pub gateway4: Option<Ipv4Addr>,
    #[serde(default)]
    pub gateway6: Option<Ipv6Addr>,
    #[serde(default)]
    pub dns: Vec<IpAddr>,
    #[serde(default)]
    pub domains: Vec<String>,
}

const MAX_STATIC_ADDRESSES: usize = 16;
const MAX_STATIC_DNS: usize = 8;
const MAX_STATIC_DOMAINS: usize = 16;

impl StaticIp {
    pub fn validate(&self) -> Result<(), ModelError> {
        let invalid = |reason: String| Err(ModelError::InvalidStaticIp(reason));
        if self.addresses.is_empty() {
            return invalid("at least one address is required".to_owned());
        }
        if self.addresses.len() > MAX_STATIC_ADDRESSES {
            return invalid(format!(
                "at most {MAX_STATIC_ADDRESSES} static addresses are allowed"
            ));
        }
        if self.dns.len() > MAX_STATIC_DNS {
            return invalid(format!("at most {MAX_STATIC_DNS} DNS servers are allowed"));
        }
        if self.domains.len() > MAX_STATIC_DOMAINS {
            return invalid(format!(
                "at most {MAX_STATIC_DOMAINS} DNS search domains are allowed"
            ));
        }
        let mut seen = BTreeSet::new();
        for address in &self.addresses {
            if !seen.insert(address.addr()) {
                return invalid(format!("duplicate address {address}"));
            }
            if address.addr().is_unspecified()
                || address.addr().is_multicast()
                || address.addr().is_loopback()
            {
                return invalid(format!("{address} is not a unicast host address"));
            }
            if *address == address.trunc() && address.max_prefix_len() != address.prefix_len() {
                return invalid(format!(
                    "{address} is a network address, not a host address"
                ));
            }
            if let IpNet::V4(v4) = address
                && v4.prefix_len() < 31
                && v4.addr() == v4.broadcast()
            {
                return invalid(format!(
                    "{address} is a broadcast address, not a host address"
                ));
            }
        }
        if let Some(gateway) = self.gateway4 {
            if gateway.is_unspecified() || gateway.is_multicast() || gateway.is_loopback() {
                return invalid(format!(
                    "IPv4 gateway {gateway} is not a valid unicast host"
                ));
            }
            let reachable = self.addresses.iter().any(|net| match net {
                IpNet::V4(net) => net.contains(&gateway),
                IpNet::V6(_) => false,
            });
            if !reachable {
                return invalid(format!(
                    "IPv4 gateway {gateway} is outside every configured subnet"
                ));
            }
        }
        if let Some(gateway) = self.gateway6 {
            if gateway.is_unspecified() || gateway.is_multicast() || gateway.is_loopback() {
                return invalid(format!(
                    "IPv6 gateway {gateway} is not a valid unicast host"
                ));
            }
            let link_local = gateway.segments()[0] & 0xffc0 == 0xfe80
                && gateway != Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
            let reachable = self.addresses.iter().any(|net| match net {
                IpNet::V6(net) => net.contains(&gateway),
                IpNet::V4(_) => false,
            });
            if !(link_local || reachable) {
                return invalid(format!(
                    "IPv6 gateway {gateway} is neither link-local nor in a configured subnet"
                ));
            }
        }
        let mut seen_dns = BTreeSet::new();
        for server in &self.dns {
            if server.is_unspecified() || server.is_multicast() {
                return invalid(format!("DNS server {server} is not a valid address"));
            }
            if !seen_dns.insert(*server) {
                return invalid(format!("duplicate DNS server {server}"));
            }
        }
        for domain in &self.domains {
            if !is_dns_name(domain) {
                return invalid(format!("{domain:?} is not a valid DNS search domain"));
            }
        }
        Ok(())
    }
}

/// How the L3 provider should configure a link once it is associated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case", deny_unknown_fields)]
pub enum L3Config {
    /// DHCPv4 and, if enabled, IPv6 through Router Advertisements.
    Dhcp {
        #[serde(default)]
        ipv6: Ipv6Mode,
    },
    Static(StaticIp),
    /// Kestrel does not bind L3 for this profile. The administrator's own
    /// L3 configuration (for example a hand-written `.network` file) applies.
    Unmanaged,
}

impl Default for L3Config {
    fn default() -> Self {
        Self::Dhcp {
            ipv6: Ipv6Mode::Auto,
        }
    }
}

impl L3Config {
    pub const fn is_managed(&self) -> bool {
        !matches!(self, Self::Unmanaged)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Static(config) => config.validate(),
            Self::Dhcp { .. } | Self::Unmanaged => Ok(()),
        }
    }
}

/// A saved Wi-Fi network. This is Kestrel's source of truth; backends never
/// keep their own copy beyond one association.
///
/// The secret is deliberately not part of the profile. It lives in a
/// separate secret store, keyed by [`ProfileId`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiProfile {
    pub id: ProfileId,
    /// Human-readable label. Defaults to the SSID.
    pub name: String,
    pub ssid: Ssid,
    pub security: ProfileSecurity,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default = "default_true")]
    pub autoconnect: bool,
    /// Higher wins. Ties are broken by visibility, security, and signal.
    #[serde(default)]
    pub priority: i32,
    /// Optional BSSID pin.
    #[serde(default)]
    pub bssid: Option<MacAddress>,
    #[serde(default)]
    pub l3: L3Config,
    /// 802.1X / WPA-Enterprise parameters when `security` is enterprise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise: Option<EnterpriseConfig>,
    /// Seconds since the Unix epoch of the last successful connection.
    #[serde(default)]
    pub last_connected: Option<u64>,
}

const fn default_true() -> bool {
    true
}

impl WifiProfile {
    pub fn new(ssid: Ssid, security: ProfileSecurity) -> Self {
        Self {
            id: ProfileId::generate(),
            name: ssid.to_string_lossy(),
            ssid,
            security,
            hidden: false,
            autoconnect: true,
            priority: 0,
            bssid: None,
            l3: L3Config::default(),
            enterprise: None,
            last_connected: None,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.name.trim().is_empty() || self.name.chars().count() > 64 {
            return Err(ModelError::InvalidProfile(
                "name must be 1..=64 characters".to_owned(),
            ));
        }
        if self.name.chars().any(char::is_control) {
            return Err(ModelError::InvalidProfile(
                "name must not contain control characters".to_owned(),
            ));
        }
        if let Some(bssid) = self.bssid
            && (bssid.is_multicast() || bssid.is_zero())
        {
            return Err(ModelError::InvalidBssid(bssid.to_string()));
        }
        match (self.security.is_enterprise(), &self.enterprise) {
            (true, Some(enterprise)) => enterprise.validate()?,
            (true, None) => {
                return Err(ModelError::InvalidEnterprise(format!(
                    "{} profiles require enterprise configuration",
                    self.security
                )));
            }
            (false, Some(_)) => {
                return Err(ModelError::InvalidEnterprise(format!(
                    "{} profiles do not take enterprise configuration",
                    self.security
                )));
            }
            (false, None) => {}
        }
        self.l3.validate()
    }

    /// Certificates referenced by this profile.
    pub fn referenced_certs(&self) -> Vec<CertId> {
        self.enterprise
            .as_ref()
            .map_or_else(Vec::new, EnterpriseConfig::referenced_certs)
    }

    /// Whether `other` differs in a way that requires re-associating a link
    /// that currently uses this profile. Cosmetic and policy fields (name,
    /// priority, autoconnect, timestamps) do not.
    pub fn requires_reconnect(&self, other: &Self) -> bool {
        self.ssid != other.ssid
            || self.security != other.security
            || self.hidden != other.hidden
            || self.bssid != other.bssid
            || self.l3 != other.l3
            || self.enterprise != other.enterprise
    }
}

fn is_dns_name(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    let value = value.strip_prefix('~').unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> WifiProfile {
        WifiProfile::new(Ssid::new("home").unwrap(), ProfileSecurity::WpaPersonal)
    }

    #[test]
    fn profile_round_trips_through_toml_shape() {
        let mut profile = profile();
        profile.l3 = L3Config::Static(StaticIp {
            addresses: vec!["192.0.2.10/24".parse().unwrap()],
            gateway4: Some("192.0.2.1".parse().unwrap()),
            ..StaticIp::default()
        });
        profile.validate().unwrap();
        let json = serde_json::to_string(&profile).unwrap();
        let back: WifiProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, profile);
    }

    #[test]
    fn static_ip_validation() {
        let mut ip = StaticIp {
            addresses: vec!["192.0.2.10/24".parse().unwrap()],
            gateway4: Some("198.51.100.1".parse().unwrap()),
            ..StaticIp::default()
        };
        assert!(ip.validate().is_err(), "unreachable gateway");
        ip.gateway4 = Some("192.0.2.1".parse().unwrap());
        ip.validate().unwrap();
        ip.gateway6 = Some("fe80::1".parse().unwrap());
        ip.validate().unwrap();
        ip.addresses.push("192.0.2.10/24".parse().unwrap());
        assert!(ip.validate().is_err(), "duplicate");
        ip.addresses = vec!["192.0.2.0/24".parse().unwrap()];
        ip.gateway4 = None;
        assert!(ip.validate().is_err(), "network address");
        ip.addresses = vec!["192.0.2.5/32".parse().unwrap()];
        ip.domains = vec!["example.org".into(), "~corp".into()];
        ip.validate().unwrap();
        ip.domains = vec!["bad domain".into()];
        assert!(ip.validate().is_err());
    }

    #[test]
    fn reconnect_is_only_required_for_link_relevant_changes() {
        let base = profile();
        let mut cosmetic = base.clone();
        cosmetic.name = "Home".into();
        cosmetic.priority = 10;
        cosmetic.last_connected = Some(1);
        assert!(!base.requires_reconnect(&cosmetic));
        let mut l3 = base.clone();
        l3.l3 = L3Config::Unmanaged;
        assert!(base.requires_reconnect(&l3));
    }

    #[test]
    fn rejects_bad_names() {
        let mut p = profile();
        p.name = String::new();
        assert!(p.validate().is_err());
        p.name = "a\u{7}".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn profile_id_simple_form_is_path_safe() {
        let id = ProfileId::generate();
        let simple = id.simple();
        assert_eq!(simple.len(), 32);
        assert!(simple.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(ProfileId::parse(&simple).unwrap(), id);
    }
}

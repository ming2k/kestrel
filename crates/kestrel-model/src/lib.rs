// SPDX-License-Identifier: LGPL-2.1-or-later

//! Pure domain model for Kestrel.
//!
//! This crate contains no I/O, no async runtime, and no OS-specific code.
//! Every type that can be built from untrusted input (configuration files,
//! D-Bus callers, backend daemons) is validated at construction.

mod cert;
mod enterprise;
mod error;
mod failure;
mod history;
mod hotspot;
mod interface;
mod p2p;
mod profile;
mod secret;
mod wifi;

pub use cert::{CertId, Certificate, CertificatePem};
pub use enterprise::{EapMethod, EnterpriseConfig, Phase2Auth};
pub use error::ModelError;
pub use failure::FailureReason;
pub use history::{ConnectionEvent, ConnectionOutcome};
pub use hotspot::{HotspotConfig, HotspotSecurity};
pub use interface::{InterfaceName, MacAddress};
pub use p2p::{
    GoIntent, P2pGroupId, P2pGroupProfile, P2pPeer, P2pRole, SessionId, WpsMethod, WpsPin,
};
pub use profile::{Ipv6Mode, L3Config, ProfileId, StaticIp, WifiProfile};
pub use secret::{ProfileSecrets, Secret, SecretKey};
pub use wifi::{Bss, OnlineState, ProfileSecurity, Security, Ssid};

pub use ipnet::{IpNet, Ipv4Net, Ipv6Net};
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

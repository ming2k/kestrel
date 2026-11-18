// SPDX-License-Identifier: LGPL-2.1-or-later

//! Configuration for [`crate::Controller`].

use std::time::Duration;

pub use kestrel_machines::hotspot::HotspotConfig;
pub use kestrel_machines::p2p::SessionConfig;
pub use kestrel_machines::station::StationConfig;
use kestrel_model::{GoIntent, Ipv4Net};

use crate::subnet::SubnetAllocator;

#[derive(Debug, Clone)]
pub struct ControllerConfig {
    pub station: StationConfig,
    pub session: SessionConfig,
    pub hotspot: HotspotConfig,
    /// Candidate subnets for links Kestrel serves addresses on.
    pub subnet_pool: Vec<Ipv4Net>,
    /// Wi-Fi Direct device name advertised to peers.
    pub p2p_device_name: String,
    pub default_go_intent: GoIntent,
    /// Upper bound on waiting for an agent (secret prompt, peer
    /// authorization).
    pub agent_timeout: Duration,
    pub wireless_enabled: bool,
    /// Optional initial hardware rfkill state read before startup (`None`
    /// queries `WlanProvider::hardware_enabled`).
    pub hardware_enabled: Option<bool>,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            station: StationConfig::default(),
            session: SessionConfig::default(),
            hotspot: HotspotConfig::default(),
            subnet_pool: SubnetAllocator::default_pool(),
            p2p_device_name: "Kestrel".to_owned(),
            default_go_intent: GoIntent::default(),
            agent_timeout: Duration::from_secs(120),
            wireless_enabled: true,
            hardware_enabled: None,
        }
    }
}

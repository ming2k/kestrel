// SPDX-License-Identifier: LGPL-2.1-or-later

//! IP-layer port.
//!
//! Kestrel never assigns addresses, runs DHCP, edits routes, or writes
//! resolver configuration itself. It declares an [`L3Intent`] for a link,
//! and the system's network daemon carries it out.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use kestrel_model::{InterfaceName, IpNet, Ipv4Net, Ipv6Mode, MacAddress, OnlineState, StaticIp};

use crate::{PortResult, Subscription};

/// Serve addresses on a link: the P2P Group Owner role, and later SoftAP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSubnet {
    /// Our address on the link, with the subnet prefix.
    pub address: Ipv4Net,
    pub pool_offset: u32,
    pub pool_size: u32,
    /// Advertise ourselves as the default router. Off for P2P, where the
    /// group is a point-to-point data path, not an uplink.
    pub emit_router: bool,
    /// NAT traffic from the subnet to the uplink.
    pub masquerade: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L3Intent {
    DhcpClient {
        ipv6: Ipv6Mode,
        /// RFC 7844 anonymity profile: no hostname, minimal identifiers.
        /// Used on P2P links to strangers' devices.
        anonymize: bool,
        /// Whether the link counts toward the host being online. False for
        /// P2P links, which are never an uplink.
        required_for_online: bool,
    },
    Static(StaticIp),
    SharedSubnet(SharedSubnet),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L3Phase {
    /// No binding, or the provider has not finished.
    Pending,
    Ready,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpLease {
    pub address: Ipv4Addr,
    pub client: Option<MacAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L3Status {
    pub phase: L3Phase,
    pub addresses: Vec<IpNet>,
    pub gateways: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    pub online: OnlineState,
    /// Leases handed out by a DHCP server on this link.
    pub leases: Vec<DhcpLease>,
    /// The server that granted our DHCP lease, if any.
    pub dhcp_server: Option<IpAddr>,
}

impl L3Status {
    pub const fn pending() -> Self {
        Self {
            phase: L3Phase::Pending,
            addresses: Vec::new(),
            gateways: Vec::new(),
            dns: Vec::new(),
            online: OnlineState::Offline,
            leases: Vec::new(),
            dhcp_server: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L3Event {
    pub link: InterfaceName,
    pub status: L3Status,
}

#[async_trait]
pub trait L3Provider: Send + Sync + fmt::Debug {
    fn name(&self) -> &'static str;

    /// Status changes of bound links.
    fn subscribe(&self) -> Subscription<L3Event>;

    /// Declares the intent for a link, replacing any previous binding.
    /// Progress arrives as [`L3Event`]s.
    async fn bind(&self, link: &InterfaceName, intent: &L3Intent) -> PortResult<()>;

    /// Withdraws Kestrel's intent for a link. Idempotent.
    async fn unbind(&self, link: &InterfaceName) -> PortResult<()>;

    async fn status(&self, link: &InterfaceName) -> PortResult<L3Status>;

    /// Every IP network configured on the host, for conflict-free subnet
    /// allocation.
    async fn addresses_in_use(&self) -> PortResult<Vec<IpNet>>;

    /// Removes every binding Kestrel owns. Returns the links it unbound.
    async fn sweep(&self) -> PortResult<Vec<InterfaceName>>;
}

// SPDX-License-Identifier: LGPL-2.1-or-later

//! Read-only snapshots and live radio events emitted by [`crate::Controller`].

use std::net::IpAddr;

use kestrel_machines::station::StationSnapshot;
use kestrel_model::{
    Bss, FailureReason, HotspotSecurity, InterfaceName, Ipv4Net, MacAddress, P2pPeer, P2pRole,
    ProfileId, ProfileSecurity, SessionId, Ssid,
};
use kestrel_ports::l3::{DhcpLease, L3Status};
use kestrel_ports::wlan::Capabilities;

/// One visible BSS paired with its highest-priority matching saved profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEntry {
    pub bss: Bss,
    pub profile: Option<ProfileId>,
}

/// SoftAP / hotspot status for one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotspotStatusSnapshot {
    pub state: &'static str,
    pub ssid: Option<Ssid>,
    pub security: Option<HotspotSecurity>,
    pub frequency: Option<u32>,
    pub gateway: Option<Ipv4Net>,
    pub leases: Vec<DhcpLease>,
    pub clients: Vec<MacAddress>,
    pub failure: Option<FailureReason>,
}

/// Snapshot of a wireless device and its active station, hotspot, and P2P state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub name: InterfaceName,
    pub address: Option<MacAddress>,
    pub capabilities: Capabilities,
    pub supported_security: Vec<ProfileSecurity>,
    pub station: StationSnapshot,
    pub hotspot: HotspotStatusSnapshot,
    pub p2p_finding: bool,
    /// SSID of the active profile, once known.
    pub ssid: Option<Ssid>,
    /// Centre frequency in MHz of the connected BSS, when known.
    pub frequency: Option<u32>,
    /// Security string of the active connection, when connected.
    pub security: Option<String>,
    /// Visible BSSs paired with their highest-priority matching saved profile.
    pub scan_results: Vec<ScanEntry>,
    /// Latest L3 status for this link.
    pub l3: L3Status,
}

/// A P2P session as consumers see it. The WPS PIN is deliberately absent:
/// it goes to the agent only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub id: SessionId,
    pub device: InterfaceName,
    /// The peer's P2P device address. `None` for an autonomous group.
    pub peer: Option<MacAddress>,
    pub incoming: bool,
    /// True when the group was started without GO negotiation.
    pub autonomous: bool,
    pub state: &'static str,
    pub role: Option<P2pRole>,
    pub group_interface: Option<InterfaceName>,
    pub peer_ip: Option<IpAddr>,
    pub failure: Option<FailureReason>,
}

/// Live events emitted when radios, devices, peers, or P2P sessions change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerEvent {
    DeviceAdded(DeviceSnapshot),
    DeviceChanged(DeviceSnapshot),
    DeviceRemoved(InterfaceName),
    PeerFound {
        device: InterfaceName,
        peer: P2pPeer,
    },
    PeerLost {
        device: InterfaceName,
        address: MacAddress,
    },
    SessionAdded(SessionSnapshot),
    SessionChanged(SessionSnapshot),
    /// The session reached a terminal state and is gone. The last
    /// `SessionChanged` carries the outcome.
    SessionRemoved(SessionId),
    WirelessEnabled(bool),
    WirelessHardwareEnabled(bool),
}

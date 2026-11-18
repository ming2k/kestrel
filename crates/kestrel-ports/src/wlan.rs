// SPDX-License-Identifier: LGPL-2.1-or-later

//! Wireless link (L2) port.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use kestrel_model::{
    Bss, EnterpriseConfig, InterfaceName, MacAddress, ProfileSecrets, ProfileSecurity, Ssid,
};

use crate::ap::ApProvider;
use crate::p2p::P2pProvider;
use crate::{PortError, PortResult, Subscription};

/// What a wireless device can do through this backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub station: bool,
    pub p2p: bool,
    pub access_point: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WlanDevice {
    pub name: InterfaceName,
    pub address: Option<MacAddress>,
    pub capabilities: Capabilities,
    /// Profile security modes this device and backend can enforce without
    /// downgrade.
    pub supported_security: Vec<ProfileSecurity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkStatus {
    Disconnected,
    /// Scanning, authenticating, associating, or handshaking.
    Connecting,
    Connected {
        ssid: Ssid,
        bssid: Option<MacAddress>,
    },
}

/// Resolved 802.1X parameters and PEM certificates handed to the L2 adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct EnterpriseConnect {
    pub config: EnterpriseConfig,
    pub ca_cert_pem: Option<Vec<u8>>,
    pub client_cert_pem: Option<Vec<u8>>,
}

impl fmt::Debug for EnterpriseConnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnterpriseConnect")
            .field("config", &self.config)
            .field(
                "ca_cert_pem_bytes",
                &self.ca_cert_pem.as_ref().map(Vec::len),
            )
            .field(
                "client_cert_pem_bytes",
                &self.client_cert_pem.as_ref().map(Vec::len),
            )
            .finish()
    }
}

/// One association request. Secrets are redacted in `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub ssid: Ssid,
    pub security: ProfileSecurity,
    pub secrets: ProfileSecrets,
    pub enterprise: Option<EnterpriseConnect>,
    pub hidden: bool,
    pub bssid: Option<MacAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WlanEvent {
    DeviceAdded(WlanDevice),
    DeviceRemoved(InterfaceName),
    Link {
        device: InterfaceName,
        status: LinkStatus,
    },
    /// The backend determined the credentials are wrong.
    AuthFailed {
        device: InterfaceName,
    },
    /// The backend gave up on an association for another reason. Backends
    /// that retry internally (`wpa_supplicant`) never send this; the
    /// caller's association timeout covers them.
    ConnectFailed {
        device: InterfaceName,
        error: PortError,
    },
    ScanFinished {
        device: InterfaceName,
        result: Result<Vec<Bss>, PortError>,
    },
    /// Hardware rfkill state changed (`false` when hard-blocked).
    HardwareEnabled(bool),
}

#[async_trait]
pub trait WlanProvider: Send + Sync + fmt::Debug {
    fn name(&self) -> &'static str;

    fn subscribe(&self) -> Subscription<WlanEvent>;

    async fn devices(&self) -> PortResult<Vec<WlanDevice>>;

    /// Whether wireless hardware is unblocked (no hard rfkill).
    async fn hardware_enabled(&self) -> PortResult<bool> {
        Ok(true)
    }

    /// Starts a scan. Results arrive as [`WlanEvent::ScanFinished`].
    async fn start_scan(&self, device: &InterfaceName) -> PortResult<()>;

    /// Starts associating. The outcome arrives as [`WlanEvent::Link`] or
    /// [`WlanEvent::AuthFailed`]. Any previous Kestrel association on the
    /// device is replaced.
    async fn connect(&self, device: &InterfaceName, request: ConnectRequest) -> PortResult<()>;

    /// Leaves the network and removes every backend object Kestrel created
    /// for the device. Idempotent.
    async fn disconnect(&self, device: &InterfaceName) -> PortResult<()>;

    async fn link_status(&self, device: &InterfaceName) -> PortResult<LinkStatus>;

    /// Removes everything Kestrel owns on every device: crash recovery at
    /// startup and the last step of shutdown.
    async fn sweep(&self) -> PortResult<()>;

    /// The P2P sub-port, if this backend supports Wi-Fi Direct.
    fn p2p(&self) -> Option<Arc<dyn P2pProvider>> {
        None
    }

    /// The SoftAP sub-port, if this backend supports access-point mode.
    fn ap(&self) -> Option<Arc<dyn ApProvider>> {
        None
    }
}

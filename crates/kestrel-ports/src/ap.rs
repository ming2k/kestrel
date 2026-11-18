// SPDX-License-Identifier: LGPL-2.1-or-later

//! Wireless Access Point (SoftAP / hotspot) port.

use std::fmt;

use async_trait::async_trait;
use kestrel_model::{HotspotSecurity, InterfaceName, MacAddress, Secret, Ssid};

use crate::{PortResult, Subscription};

/// Request to start a SoftAP on a wireless device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApStartRequest {
    pub ssid: Ssid,
    pub security: HotspotSecurity,
    pub secret: Option<Secret>,
    pub frequency: Option<u32>,
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApEvent {
    Started {
        device: InterfaceName,
        frequency: u32,
    },
    Stopped {
        device: InterfaceName,
    },
    Failed {
        device: InterfaceName,
        error: PortError,
    },
    ClientConnected {
        device: InterfaceName,
        mac: MacAddress,
    },
    ClientDisconnected {
        device: InterfaceName,
        mac: MacAddress,
    },
}

use crate::PortError;

#[async_trait]
pub trait ApProvider: Send + Sync + fmt::Debug {
    fn subscribe(&self) -> Subscription<ApEvent>;

    async fn start_ap(&self, device: &InterfaceName, request: &ApStartRequest) -> PortResult<()>;

    /// Stops any active SoftAP on `device` and restores station capability.
    /// Idempotent.
    async fn stop_ap(&self, device: &InterfaceName) -> PortResult<()>;
}

// SPDX-License-Identifier: LGPL-2.1-or-later

//! Northbound interactive agent port for secret prompts, peer authorization,
//! and WPS PIN display.

use std::fmt;

use async_trait::async_trait;
use kestrel_model::{
    FailureReason, InterfaceName, MacAddress, ProfileId, ProfileSecurity, Secret, SessionId, Ssid,
    WpsMethod, WpsPin,
};

use crate::p2p::RequestedMethod;

#[derive(Debug, Clone)]
pub struct SecretRequest {
    pub device: InterfaceName,
    pub profile: ProfileId,
    pub ssid: Ssid,
    pub security: ProfileSecurity,
    /// Why the secret is needed: missing, or rejected by the network.
    pub reason: FailureReason,
}

#[derive(Debug, Clone)]
pub struct PeerRequest {
    pub device: InterfaceName,
    pub peer: MacAddress,
    pub peer_name: Option<String>,
    pub method: RequestedMethod,
}

#[derive(Debug, Clone)]
pub struct PinDisplay {
    pub session: SessionId,
    pub peer: MacAddress,
    pub pin: WpsPin,
}

/// The user-facing side of Kestrel, supplied by a consumer (a desktop
/// shell, a settings panel, a CLI, a provisioning service).
///
/// Interactive input goes to the agent only. In particular, PINs are never
/// published as properties that every bus client could read.
#[async_trait]
pub trait Agent: Send + Sync + fmt::Debug {
    /// Returns a secret for the profile, or `None` to decline.
    async fn request_secret(&self, request: SecretRequest) -> Option<Secret>;

    /// A remote peer started a connection. Returns the provisioning method
    /// to accept with, or `None` to reject.
    async fn authorize_peer(&self, request: PeerRequest) -> Option<WpsMethod>;

    /// Show a PIN the user must enter on the peer.
    async fn display_pin(&self, display: PinDisplay);
}

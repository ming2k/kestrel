// SPDX-License-Identifier: LGPL-2.1-or-later

use thiserror::Error;

/// Errors produced while validating domain values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModelError {
    #[error("invalid interface name {name:?}: {reason}")]
    InvalidInterfaceName { name: String, reason: &'static str },

    #[error("invalid MAC address {0:?}")]
    InvalidMacAddress(String),

    #[error("invalid BSSID {0}")]
    InvalidBssid(String),

    #[error("invalid SSID: {0}")]
    InvalidSsid(String),

    #[error("invalid secret: {0}")]
    InvalidSecret(&'static str),

    #[error("invalid profile: {0}")]
    InvalidProfile(String),

    #[error("invalid profile id {0:?}")]
    InvalidProfileId(String),

    #[error("invalid static IP configuration: {0}")]
    InvalidStaticIp(String),

    #[error("invalid enterprise configuration: {0}")]
    InvalidEnterprise(String),

    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("invalid certificate id {0:?}")]
    InvalidCertId(String),

    #[error("invalid hotspot configuration: {0}")]
    InvalidHotspot(String),

    #[error("invalid persistent P2P group id {0:?}")]
    InvalidP2pGroupId(String),

    #[error("invalid persistent P2P group: {0}")]
    InvalidP2pGroup(String),

    #[error("invalid GO intent {0}; expected 0..=15")]
    InvalidGoIntent(u8),

    #[error("invalid WPS PIN: {0}")]
    InvalidWpsPin(&'static str),
}

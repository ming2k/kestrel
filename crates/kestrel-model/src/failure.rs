// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;

use serde::{Deserialize, Serialize};

/// Why a connection or session failed or ended.
///
/// Each variant has a stable machine-readable [`code`](Self::code).
/// Consumers decide on the code, never on the human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "kebab-case")]
pub enum FailureReason {
    /// The backend rejected the credentials.
    AuthFailed,
    /// No usable secret is stored and no agent supplied one.
    SecretsRequired,
    /// The target network or peer is not in range.
    NotFound,
    /// A bounded wait elapsed. The detail names the stage.
    Timeout(String),
    /// The L2 link dropped and did not recover within the grace period.
    LinkLost,
    /// The L3 provider reported failure or did not finish in time.
    L3Failed(String),
    /// Group Owner negotiation failed with a P2P status code.
    NegotiationFailed(u8),
    /// WPS provisioning failed.
    WpsFailed,
    /// The peer ended the P2P group.
    PeerDisconnected,
    /// No subnet is free in the configured pool.
    NoSubnet,
    /// The device disappeared or wireless was disabled.
    DeviceUnavailable,
    /// The user or a consumer cancelled the operation.
    Cancelled,
    /// The backend does not support the operation.
    NotSupported(String),
    /// Any other backend error. The detail is diagnostic only.
    Backend(String),
}

impl FailureReason {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthFailed => "auth-failed",
            Self::SecretsRequired => "secrets-required",
            Self::NotFound => "not-found",
            Self::Timeout(_) => "timeout",
            Self::LinkLost => "link-lost",
            Self::L3Failed(_) => "l3-failed",
            Self::NegotiationFailed(_) => "negotiation-failed",
            Self::WpsFailed => "wps-failed",
            Self::PeerDisconnected => "peer-disconnected",
            Self::NoSubnet => "no-subnet",
            Self::DeviceUnavailable => "device-unavailable",
            Self::Cancelled => "cancelled",
            Self::NotSupported(_) => "not-supported",
            Self::Backend(_) => "backend",
        }
    }

    /// Whether retrying the same operation without user action can succeed.
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::NotFound
                | Self::Timeout(_)
                | Self::LinkLost
                | Self::L3Failed(_)
                | Self::Backend(_)
                | Self::NegotiationFailed(_)
        )
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout(stage) => write!(f, "timeout during {stage}"),
            Self::L3Failed(detail) => write!(f, "L3 configuration failed: {detail}"),
            Self::NegotiationFailed(status) => {
                write!(f, "GO negotiation failed (P2P status {status})")
            }
            Self::NotSupported(detail) => write!(f, "not supported: {detail}"),
            Self::Backend(detail) => write!(f, "backend error: {detail}"),
            other => f.write_str(other.code()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_transience_match_contract() {
        let cases = [
            (FailureReason::AuthFailed, "auth-failed", false),
            (FailureReason::SecretsRequired, "secrets-required", false),
            (FailureReason::NotFound, "not-found", true),
            (
                FailureReason::Timeout("associating".into()),
                "timeout",
                true,
            ),
            (FailureReason::LinkLost, "link-lost", true),
            (FailureReason::L3Failed("dhcp".into()), "l3-failed", true),
            (
                FailureReason::NegotiationFailed(7),
                "negotiation-failed",
                true,
            ),
            (FailureReason::WpsFailed, "wps-failed", false),
            (FailureReason::PeerDisconnected, "peer-disconnected", false),
            (FailureReason::NoSubnet, "no-subnet", false),
            (
                FailureReason::DeviceUnavailable,
                "device-unavailable",
                false,
            ),
            (FailureReason::Cancelled, "cancelled", false),
            (
                FailureReason::NotSupported("p2p".into()),
                "not-supported",
                false,
            ),
            (FailureReason::Backend("boom".into()), "backend", true),
        ];

        for (reason, expected_code, expected_transient) in cases {
            assert_eq!(reason.code(), expected_code);
            assert_eq!(reason.is_transient(), expected_transient);
            let json = serde_json::to_string(&reason).unwrap();
            let roundtrip: FailureReason = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtrip, reason);
        }
    }

    #[test]
    fn display_formats_details_and_plain_codes() {
        assert_eq!(
            FailureReason::Timeout("l3".into()).to_string(),
            "timeout during l3"
        );
        assert_eq!(
            FailureReason::L3Failed("no lease".into()).to_string(),
            "L3 configuration failed: no lease"
        );
        assert_eq!(
            FailureReason::NegotiationFailed(11).to_string(),
            "GO negotiation failed (P2P status 11)"
        );
        assert_eq!(
            FailureReason::NotSupported("ap".into()).to_string(),
            "not supported: ap"
        );
        assert_eq!(
            FailureReason::Backend("oops".into()).to_string(),
            "backend error: oops"
        );
        assert_eq!(FailureReason::AuthFailed.to_string(), "auth-failed");
    }
}

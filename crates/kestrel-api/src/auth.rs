// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use zbus::Variant;

use crate::ApiError;

/// What a caller is trying to do. Each maps to a polkit action declared in
/// `data/com.hihusky.kestrel.policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Scan, connect, disconnect, and Wi-Fi Direct sessions.
    Connect,
    /// Start and stop wireless hotspots (SoftAP).
    Hotspot,
    /// Create, edit, or delete saved networks, certificates, and persistent groups.
    ModifyProfiles,
    /// Turn wireless on or off.
    ToggleWireless,
    /// Register the agent that receives secret and PIN requests.
    RegisterAgent,
}

impl Action {
    pub const fn polkit_id(self) -> &'static str {
        match self {
            Self::Connect => "com.hihusky.kestrel.connect",
            Self::Hotspot => "com.hihusky.kestrel.hotspot",
            Self::ModifyProfiles => "com.hihusky.kestrel.modify-profiles",
            Self::ToggleWireless => "com.hihusky.kestrel.toggle-wireless",
            Self::RegisterAgent => "com.hihusky.kestrel.register-agent",
        }
    }
}

/// Decides whether a bus peer may perform an action.
#[async_trait]
pub trait Authorizer: Send + Sync + fmt::Debug {
    async fn check(&self, sender: &str, action: Action) -> Result<(), ApiError>;
}

/// Asks polkit, allowing interactive authentication.
#[derive(Debug, Clone)]
pub struct Polkit {
    connection: zbus::Connection,
}

impl Polkit {
    /// `connection` must be on the system bus, where polkit runs.
    pub const fn new(connection: zbus::Connection) -> Self {
        Self { connection }
    }
}

#[async_trait]
impl Authorizer for Polkit {
    async fn check(&self, sender: &str, action: Action) -> Result<(), ApiError> {
        let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(&self.connection)
            .destination("org.freedesktop.PolicyKit1")
            .path("/org/freedesktop/PolicyKit1/Authority")
            .interface("org.freedesktop.PolicyKit1.Authority")
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(|e| ApiError::AccessDenied(format!("polkit unavailable: {e}")))?;
        let subject = (
            "system-bus-name",
            HashMap::from([("name", Variant::from(sender))]),
        );
        let details: HashMap<&str, &str> = HashMap::new();
        // Flag 1: allow interactive authentication.
        let reply = proxy
            .call_method(
                "CheckAuthorization",
                &(subject, action.polkit_id(), details, 1u32, ""),
            )
            .await
            .map_err(|e| ApiError::AccessDenied(format!("polkit: {e}")))?;
        let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) = reply
            .body()
            .deserialize()
            .map_err(|e| ApiError::AccessDenied(format!("polkit reply: {e}")))?;
        if authorized {
            Ok(())
        } else {
            Err(ApiError::AccessDenied(format!(
                "not authorized for {}",
                action.polkit_id()
            )))
        }
    }
}

/// Authorizes everything; access control is left to the bus policy.
/// Intended for a private or session bus (development and tests).
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

#[async_trait]
impl Authorizer for AllowAll {
    async fn check(&self, _sender: &str, _action: Action) -> Result<(), ApiError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_polkit_ids_match_policy_names() {
        assert_eq!(Action::Connect.polkit_id(), "com.hihusky.kestrel.connect");
        assert_eq!(Action::Hotspot.polkit_id(), "com.hihusky.kestrel.hotspot");
        assert_eq!(
            Action::ModifyProfiles.polkit_id(),
            "com.hihusky.kestrel.modify-profiles"
        );
        assert_eq!(
            Action::ToggleWireless.polkit_id(),
            "com.hihusky.kestrel.toggle-wireless"
        );
        assert_eq!(
            Action::RegisterAgent.polkit_id(),
            "com.hihusky.kestrel.register-agent"
        );
    }

    #[tokio::test]
    async fn allow_all_permits_every_action() {
        let auth = AllowAll;
        for action in [
            Action::Connect,
            Action::Hotspot,
            Action::ModifyProfiles,
            Action::ToggleWireless,
            Action::RegisterAgent,
        ] {
            auth.check(":1.42", action).await.unwrap();
        }
    }
}

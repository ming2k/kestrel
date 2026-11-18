// SPDX-License-Identifier: LGPL-2.1-or-later

//! Persistence ports: Kestrel's own source of truth.

use std::fmt;

use async_trait::async_trait;
use kestrel_model::{
    CertId, Certificate, ConnectionEvent, P2pGroupId, P2pGroupProfile, ProfileId, ProfileSecrets,
    SecretKey, WifiProfile,
};

use crate::PortResult;

/// Durable storage for saved network profiles.
#[async_trait]
pub trait ProfileRepository: Send + Sync + fmt::Debug {
    /// Loads every valid profile. Invalid entries are reported through
    /// logging and skipped, never silently rewritten.
    async fn load_all(&self) -> PortResult<Vec<WifiProfile>>;

    /// Creates or replaces a profile atomically.
    async fn save(&self, profile: &WifiProfile) -> PortResult<()>;

    /// Deletes a profile. Idempotent.
    async fn delete(&self, id: ProfileId) -> PortResult<()>;
}

/// Durable storage for imported public X.509 certificates.
#[async_trait]
pub trait CertStore: Send + Sync + fmt::Debug {
    async fn load_all(&self) -> PortResult<Vec<Certificate>>;

    async fn get(&self, id: CertId) -> PortResult<Option<Certificate>>;

    async fn save(&self, cert: &Certificate) -> PortResult<()>;

    /// Deletes a certificate. Idempotent.
    async fn delete(&self, id: CertId) -> PortResult<()>;
}

/// Durable storage for saved persistent Wi-Fi Direct groups.
#[async_trait]
pub trait P2pGroupStore: Send + Sync + fmt::Debug {
    async fn load_all(&self) -> PortResult<Vec<P2pGroupProfile>>;

    async fn save(&self, group: &P2pGroupProfile) -> PortResult<()>;

    /// Deletes a persistent P2P group. Idempotent.
    async fn delete(&self, id: P2pGroupId) -> PortResult<()>;
}

/// Credentials, stored separately from profiles and encrypted at rest.
#[async_trait]
pub trait SecretStore: Send + Sync + fmt::Debug {
    fn name(&self) -> &'static str;

    async fn get(&self, key: SecretKey) -> PortResult<Option<ProfileSecrets>>;

    async fn set(&self, key: SecretKey, secrets: &ProfileSecrets) -> PortResult<()>;

    /// Idempotent.
    async fn delete(&self, key: SecretKey) -> PortResult<()>;
}

/// A bounded, durable connection history.
#[async_trait]
pub trait HistoryStore: Send + Sync + fmt::Debug {
    async fn record(&self, event: &ConnectionEvent) -> PortResult<()>;

    /// Most recent events first, at most `limit`.
    async fn recent(&self, limit: usize) -> PortResult<Vec<ConnectionEvent>>;
}

/// Durable daemon state (such as the software wireless toggle) that survives
/// process restarts.
#[async_trait]
pub trait StateStore: Send + Sync + fmt::Debug {
    /// Returns the persisted wireless toggle, or `None` when none has been
    /// recorded yet (so the daemon's configuration default applies).
    async fn wireless_enabled(&self) -> PortResult<Option<bool>>;

    async fn set_wireless_enabled(&self, enabled: bool) -> PortResult<()>;
}

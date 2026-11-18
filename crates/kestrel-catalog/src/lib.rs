// SPDX-License-Identifier: LGPL-2.1-or-later

//! Persisted configuration and diagnostic asset catalog for Kestrel.
//!
//! `kestrel-catalog` is the single source of truth for saved Wi-Fi profiles,
//! sealed credentials, imported X.509 certificates, persistent Wi-Fi Direct
//! groups, and connection history. It enforces cross-asset invariants (such as
//! rejecting deletion of referenced certificates), serializes mutations against
//! the underlying [`kestrel_ports::store`] traits, and broadcasts
//! [`CatalogEvent`] notifications without depending on radio state machines or
//! L2/L3 hardware providers.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use kestrel_model::{
    CertId, Certificate, CertificatePem, ConnectionEvent, EapMethod, MacAddress, P2pGroupId,
    P2pGroupProfile, P2pRole, ProfileId, ProfileSecrets, Secret, SecretKey, Ssid, WifiProfile,
};
use kestrel_ports::PortError;
use kestrel_ports::store::{
    CertStore, HistoryStore, P2pGroupStore, ProfileRepository, SecretStore,
};
use thiserror::Error;
use tokio::sync::{Mutex, broadcast};

/// Persistence stores owned by a [`Catalog`].
#[derive(Clone)]
pub struct CatalogStores {
    pub profiles: Arc<dyn ProfileRepository>,
    pub secrets: Arc<dyn SecretStore>,
    pub certs: Arc<dyn CertStore>,
    pub p2p_groups: Arc<dyn P2pGroupStore>,
    pub history: Arc<dyn HistoryStore>,
}

impl fmt::Debug for CatalogStores {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogStores")
            .field("secrets", &self.secrets.name())
            .finish_non_exhaustive()
    }
}

/// How a profile update treats stored credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretUpdate {
    Keep,
    Set(ProfileSecrets),
    Clear,
}

/// Notifications emitted when catalog assets change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogEvent {
    ProfileAdded(WifiProfile),
    ProfileChanged(WifiProfile),
    ProfileRemoved(ProfileId),
    SecretsChanged { profile: ProfileId, available: bool },
    CertAdded(Certificate),
    CertRemoved(CertId),
    P2pGroupAdded(P2pGroupProfile),
    P2pGroupChanged(P2pGroupProfile),
    P2pGroupRemoved(P2pGroupId),
}

/// Errors returned by catalog operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CatalogError {
    #[error("no such profile {0}")]
    NoSuchProfile(ProfileId),
    #[error("no such certificate {0}")]
    NoSuchCertificate(CertId),
    #[error("no such persistent P2P group {0}")]
    NoSuchP2pGroup(P2pGroupId),
    #[error("busy: {0}")]
    Busy(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("storage: {0}")]
    Storage(PortError),
}

#[derive(Debug, Default)]
struct CatalogData {
    revision: u64,
    profiles: BTreeMap<ProfileId, WifiProfile>,
    certs: BTreeMap<CertId, Certificate>,
    p2p_groups: BTreeMap<P2pGroupId, P2pGroupProfile>,
}

struct CatalogInner {
    stores: CatalogStores,
    data: RwLock<CatalogData>,
    write_lock: Mutex<()>,
    events: broadcast::Sender<CatalogEvent>,
}

/// Cheaply cloneable handle to Kestrel's persisted asset catalog.
#[derive(Clone)]
pub struct Catalog {
    inner: Arc<CatalogInner>,
}

impl fmt::Debug for Catalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Catalog").finish_non_exhaustive()
    }
}

impl Catalog {
    /// Loads profiles, certificates, and persistent P2P groups from `stores`.
    pub async fn open(stores: CatalogStores) -> Result<Self, CatalogError> {
        let profiles = stores
            .profiles
            .load_all()
            .await
            .map_err(CatalogError::Storage)?;
        let certs = stores
            .certs
            .load_all()
            .await
            .map_err(CatalogError::Storage)?;
        let p2p_groups = stores
            .p2p_groups
            .load_all()
            .await
            .map_err(CatalogError::Storage)?;

        let data = CatalogData {
            revision: 1,
            profiles: profiles.into_iter().map(|p| (p.id, p)).collect(),
            certs: certs.into_iter().map(|c| (c.id, c)).collect(),
            p2p_groups: p2p_groups.into_iter().map(|g| (g.id, g)).collect(),
        };
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(CatalogInner {
                stores,
                data: RwLock::new(data),
                write_lock: Mutex::new(()),
                events,
            }),
        })
    }

    /// Subscribes to catalog mutation events.
    pub fn subscribe(&self) -> broadcast::Receiver<CatalogEvent> {
        self.inner.events.subscribe()
    }

    fn emit(&self, event: CatalogEvent) {
        let _ = self.inner.events.send(event);
    }

    fn read_data(&self) -> std::sync::RwLockReadGuard<'_, CatalogData> {
        self.inner
            .data
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_data(&self) -> std::sync::RwLockWriteGuard<'_, CatalogData> {
        self.inner
            .data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // ----- synchronous in-memory reads ----------------------------------

    /// Monotonically incremented whenever the profile set changes.
    pub fn profile_revision(&self) -> u64 {
        self.read_data().revision
    }

    pub fn profiles(&self) -> Vec<WifiProfile> {
        self.read_data().profiles.values().cloned().collect()
    }

    pub fn profile(&self, id: ProfileId) -> Result<WifiProfile, CatalogError> {
        self.read_data()
            .profiles
            .get(&id)
            .cloned()
            .ok_or(CatalogError::NoSuchProfile(id))
    }

    pub fn certificates(&self) -> Vec<Certificate> {
        self.read_data().certs.values().cloned().collect()
    }

    pub fn certificate(&self, id: CertId) -> Result<Certificate, CatalogError> {
        self.read_data()
            .certs
            .get(&id)
            .cloned()
            .ok_or(CatalogError::NoSuchCertificate(id))
    }

    pub fn p2p_groups(&self) -> Vec<P2pGroupProfile> {
        self.read_data().p2p_groups.values().cloned().collect()
    }

    pub fn p2p_group(&self, id: P2pGroupId) -> Result<P2pGroupProfile, CatalogError> {
        self.read_data()
            .p2p_groups
            .get(&id)
            .cloned()
            .ok_or(CatalogError::NoSuchP2pGroup(id))
    }

    pub fn find_p2p_group_for_invitation(
        &self,
        go_address: MacAddress,
        peer: MacAddress,
    ) -> Option<P2pGroupProfile> {
        let data = self.read_data();
        let rank = |g: &P2pGroupProfile| -> Option<(u8, u64)> {
            let tier = match (g.go_address == go_address, g.peer == Some(peer)) {
                (true, true) => 3,
                (true, false) => 2,
                (false, true) => 1,
                (false, false) => return None,
            };
            Some((tier, g.last_connected.unwrap_or(0)))
        };
        data.p2p_groups
            .values()
            .filter_map(|g| rank(g).map(|r| (r, g)))
            .max_by_key(|(r, _)| *r)
            .map(|(_, g)| g.clone())
    }

    // ----- secrets & certificates ---------------------------------------

    /// Whether credentials are stored for `id`.
    pub async fn has_secret(&self, id: ProfileId) -> Result<bool, CatalogError> {
        match self.inner.stores.secrets.get(SecretKey::Profile(id)).await {
            Ok(secret) => Ok(secret.is_some_and(|s| !s.is_empty())),
            Err(PortError::CorruptSecret(_)) => Ok(false),
            Err(error) => Err(CatalogError::Storage(error)),
        }
    }

    pub async fn load_secret(&self, key: SecretKey) -> Result<Option<ProfileSecrets>, PortError> {
        self.inner.stores.secrets.get(key).await
    }

    /// Validates and persists credentials provided interactively by an agent.
    ///
    /// Returns `true` if valid credentials were stored, or `false` if the
    /// agent input did not satisfy the profile's requirements or could not be
    /// sealed.
    pub async fn supply_agent_secret(&self, profile_id: ProfileId, secret: Secret) -> bool {
        let _guard = self.inner.write_lock.lock().await;
        let Ok(profile) = self.profile(profile_id) else {
            return false;
        };
        let is_tls = profile
            .enterprise
            .as_ref()
            .is_some_and(|e| e.eap == EapMethod::Tls);
        let stored = if is_tls {
            match self
                .inner
                .stores
                .secrets
                .get(SecretKey::Profile(profile_id))
                .await
            {
                Ok(Some(mut existing)) if existing.private_key.is_some() => {
                    existing.private_key_password = Some(secret);
                    match existing.validate_for(&profile) {
                        Ok(()) => self
                            .inner
                            .stores
                            .secrets
                            .set(SecretKey::Profile(profile_id), &existing)
                            .await
                            .is_ok(),
                        Err(error) => {
                            tracing::warn!(
                                profile = %profile_id,
                                %error,
                                "agent returned an invalid private key password"
                            );
                            false
                        }
                    }
                }
                _ => {
                    tracing::warn!(
                        profile = %profile_id,
                        "EAP-TLS requires a private key imported via profile update"
                    );
                    false
                }
            }
        } else {
            match secret.validate_for(profile.security) {
                Ok(()) => match self
                    .inner
                    .stores
                    .secrets
                    .set(
                        SecretKey::Profile(profile_id),
                        &ProfileSecrets::from_passphrase(secret),
                    )
                    .await
                {
                    Ok(()) => true,
                    Err(error) => {
                        tracing::error!(profile = %profile_id, %error, "cannot store secret");
                        false
                    }
                },
                Err(error) => {
                    tracing::warn!(profile = %profile_id, %error, "agent returned an invalid secret");
                    false
                }
            }
        };
        self.emit(CatalogEvent::SecretsChanged {
            profile: profile_id,
            available: stored,
        });
        stored
    }

    pub fn notify_secrets_unavailable(&self, profile: ProfileId) {
        self.emit(CatalogEvent::SecretsChanged {
            profile,
            available: false,
        });
    }

    fn check_referenced_certs(&self, profile: &WifiProfile) -> Result<(), CatalogError> {
        let data = self.read_data();
        for cert_id in profile.referenced_certs() {
            if !data.certs.contains_key(&cert_id) {
                return Err(CatalogError::NoSuchCertificate(cert_id));
            }
        }
        Ok(())
    }

    // ----- profiles -----------------------------------------------------

    /// Saves a new profile. Secrets, if any, are stored first, so a
    /// profile is never visible with half-written credentials.
    pub async fn add_profile(
        &self,
        profile: WifiProfile,
        secrets: Option<ProfileSecrets>,
    ) -> Result<ProfileId, CatalogError> {
        profile
            .validate()
            .map_err(|e| CatalogError::InvalidArgument(e.to_string()))?;

        let _guard = self.inner.write_lock.lock().await;
        if self.read_data().profiles.contains_key(&profile.id) {
            return Err(CatalogError::InvalidArgument(format!(
                "profile {} already exists",
                profile.id
            )));
        }
        self.check_referenced_certs(&profile)?;

        let secrets = secrets.filter(|s| !s.is_empty());
        if let Some(bundle) = &secrets {
            bundle
                .validate_for(&profile)
                .map_err(|e| CatalogError::InvalidArgument(e.to_string()))?;
            self.inner
                .stores
                .secrets
                .set(SecretKey::Profile(profile.id), bundle)
                .await
                .map_err(CatalogError::Storage)?;
        }
        if let Err(error) = self.inner.stores.profiles.save(&profile).await {
            let _ = self
                .inner
                .stores
                .secrets
                .delete(SecretKey::Profile(profile.id))
                .await;
            return Err(CatalogError::Storage(error));
        }

        let id = profile.id;
        {
            let mut data = self.write_data();
            data.revision = data.revision.wrapping_add(1);
            data.profiles.insert(id, profile.clone());
        }
        self.emit(CatalogEvent::ProfileAdded(profile));
        Ok(id)
    }

    pub async fn update_profile(
        &self,
        profile: WifiProfile,
        secrets: SecretUpdate,
    ) -> Result<(), CatalogError> {
        profile
            .validate()
            .map_err(|e| CatalogError::InvalidArgument(e.to_string()))?;

        let _guard = self.inner.write_lock.lock().await;
        let existing = self.profile(profile.id)?;
        self.check_referenced_certs(&profile)?;

        let eap_changed = existing.enterprise.as_ref().map(|e| e.eap)
            != profile.enterprise.as_ref().map(|e| e.eap);
        let mut secrets = secrets;
        if !profile.security.needs_secret() {
            if matches!(secrets, SecretUpdate::Set(_)) {
                return Err(CatalogError::InvalidArgument(format!(
                    "{} networks do not take a secret",
                    profile.security
                )));
            }
            secrets = SecretUpdate::Clear;
        } else if (existing.security != profile.security || eap_changed)
            && secrets == SecretUpdate::Keep
        {
            secrets = SecretUpdate::Clear;
        }

        if let SecretUpdate::Set(value) = &secrets {
            value
                .validate_for(&profile)
                .map_err(|e| CatalogError::InvalidArgument(e.to_string()))?;
            if value.is_empty() {
                secrets = SecretUpdate::Clear;
            }
        }

        // Snapshot previous credentials when mutating secrets so a failed
        // profile save can roll back without losing valid credentials.
        let key = SecretKey::Profile(profile.id);
        let previous_secret = if secrets == SecretUpdate::Keep {
            None
        } else {
            self.inner.stores.secrets.get(key).await.ok().flatten()
        };

        if let SecretUpdate::Set(value) = &secrets {
            self.inner
                .stores
                .secrets
                .set(key, value)
                .await
                .map_err(CatalogError::Storage)?;
        } else if secrets == SecretUpdate::Clear {
            self.inner
                .stores
                .secrets
                .delete(key)
                .await
                .map_err(CatalogError::Storage)?;
        }

        if let Err(error) = self.inner.stores.profiles.save(&profile).await {
            if secrets != SecretUpdate::Keep {
                match previous_secret {
                    Some(prev) => {
                        let _ = self.inner.stores.secrets.set(key, &prev).await;
                    }
                    None => {
                        let _ = self.inner.stores.secrets.delete(key).await;
                    }
                }
            }
            return Err(CatalogError::Storage(error));
        }

        let id = profile.id;
        {
            let mut data = self.write_data();
            data.revision = data.revision.wrapping_add(1);
            data.profiles.insert(id, profile.clone());
        }
        self.emit(CatalogEvent::ProfileChanged(profile));
        match secrets {
            SecretUpdate::Set(_) => {
                self.emit(CatalogEvent::SecretsChanged {
                    profile: id,
                    available: true,
                });
            }
            SecretUpdate::Clear => {
                self.emit(CatalogEvent::SecretsChanged {
                    profile: id,
                    available: false,
                });
            }
            SecretUpdate::Keep => {}
        }
        Ok(())
    }

    /// Updates `last_connected` on an existing profile without clobbering
    /// concurrent settings edits.
    pub async fn mark_profile_connected(&self, id: ProfileId, at: u64) -> Result<(), CatalogError> {
        let _guard = self.inner.write_lock.lock().await;
        let mut profile = self.profile(id)?;
        profile.last_connected = Some(at);
        self.inner
            .stores
            .profiles
            .save(&profile)
            .await
            .map_err(CatalogError::Storage)?;
        let mut data = self.write_data();
        data.revision = data.revision.wrapping_add(1);
        data.profiles.insert(id, profile.clone());
        drop(data);
        self.emit(CatalogEvent::ProfileChanged(profile));
        Ok(())
    }

    pub async fn delete_profile(&self, id: ProfileId) -> Result<(), CatalogError> {
        let _guard = self.inner.write_lock.lock().await;
        self.profile(id)?;
        self.inner
            .stores
            .profiles
            .delete(id)
            .await
            .map_err(CatalogError::Storage)?;
        {
            let mut data = self.write_data();
            data.revision = data.revision.wrapping_add(1);
            data.profiles.remove(&id);
        }
        self.emit(CatalogEvent::ProfileRemoved(id));
        if let Err(error) = self
            .inner
            .stores
            .secrets
            .delete(SecretKey::Profile(id))
            .await
        {
            tracing::warn!(profile = %id, %error, "cannot delete secret for removed profile");
        }
        Ok(())
    }

    // ----- certificates -------------------------------------------------

    pub async fn import_certificate(
        &self,
        name: String,
        pem: CertificatePem,
    ) -> Result<CertId, CatalogError> {
        let cert = Certificate::new(name, pem)
            .map_err(|e| CatalogError::InvalidArgument(e.to_string()))?;
        let _guard = self.inner.write_lock.lock().await;
        self.inner
            .stores
            .certs
            .save(&cert)
            .await
            .map_err(CatalogError::Storage)?;
        let id = cert.id;
        self.write_data().certs.insert(id, cert.clone());
        self.emit(CatalogEvent::CertAdded(cert));
        Ok(id)
    }

    pub async fn delete_certificate(&self, id: CertId) -> Result<(), CatalogError> {
        let _guard = self.inner.write_lock.lock().await;
        self.certificate(id)?;
        if self
            .read_data()
            .profiles
            .values()
            .any(|p| p.referenced_certs().contains(&id))
        {
            return Err(CatalogError::Busy(format!(
                "certificate {id} is referenced by a saved profile"
            )));
        }
        self.inner
            .stores
            .certs
            .delete(id)
            .await
            .map_err(CatalogError::Storage)?;
        self.write_data().certs.remove(&id);
        self.emit(CatalogEvent::CertRemoved(id));
        Ok(())
    }

    // ----- persistent P2P groups ----------------------------------------

    /// Saves or updates a formed persistent Wi-Fi Direct group and seals its PSK.
    #[allow(clippy::too_many_arguments)]
    pub async fn save_formed_p2p_group(
        &self,
        role: P2pRole,
        ssid: Ssid,
        go_address: MacAddress,
        peer: Option<MacAddress>,
        fallback_name: String,
        psk: Secret,
        at: u64,
    ) -> Result<P2pGroupProfile, CatalogError> {
        let _guard = self.inner.write_lock.lock().await;
        let existing = self
            .read_data()
            .p2p_groups
            .values()
            .find(|g| g.ssid == ssid && g.go_address == go_address && g.role == role)
            .cloned();
        let is_new = existing.is_none();
        let group = if let Some(mut group) = existing {
            group.peer = group.peer.or(peer);
            group.last_connected = Some(at);
            group
        } else {
            let cleaned: String = fallback_name
                .chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect();
            let name = if cleaned.trim().is_empty() {
                let fallback: String = ssid
                    .to_string_lossy()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(64)
                    .collect();
                if fallback.trim().is_empty() {
                    "P2P Group".to_owned()
                } else {
                    fallback
                }
            } else {
                cleaned
            };
            P2pGroupProfile {
                id: P2pGroupId::generate(),
                name,
                peer,
                role,
                ssid,
                go_address,
                last_connected: Some(at),
            }
        };
        group
            .validate()
            .map_err(|e| CatalogError::InvalidArgument(e.to_string()))?;
        psk.validate_for(kestrel_model::ProfileSecurity::WpaPersonal)
            .map_err(|e| CatalogError::InvalidArgument(e.to_string()))?;

        let key = SecretKey::P2pGroup(group.id);
        let previous_secret = if is_new {
            None
        } else {
            self.inner.stores.secrets.get(key).await.ok().flatten()
        };
        self.inner
            .stores
            .secrets
            .set(key, &ProfileSecrets::from_passphrase(psk))
            .await
            .map_err(CatalogError::Storage)?;
        if let Err(error) = self.inner.stores.p2p_groups.save(&group).await {
            match previous_secret {
                Some(prev) => {
                    let _ = self.inner.stores.secrets.set(key, &prev).await;
                }
                None => {
                    let _ = self.inner.stores.secrets.delete(key).await;
                }
            }
            return Err(CatalogError::Storage(error));
        }

        self.write_data().p2p_groups.insert(group.id, group.clone());
        let event = if is_new {
            CatalogEvent::P2pGroupAdded(group.clone())
        } else {
            CatalogEvent::P2pGroupChanged(group.clone())
        };
        self.emit(event);
        Ok(group)
    }

    pub async fn delete_p2p_group(&self, id: P2pGroupId) -> Result<(), CatalogError> {
        let _guard = self.inner.write_lock.lock().await;
        self.p2p_group(id)?;
        self.inner
            .stores
            .p2p_groups
            .delete(id)
            .await
            .map_err(CatalogError::Storage)?;
        self.write_data().p2p_groups.remove(&id);
        self.emit(CatalogEvent::P2pGroupRemoved(id));
        if let Err(error) = self
            .inner
            .stores
            .secrets
            .delete(SecretKey::P2pGroup(id))
            .await
        {
            tracing::warn!(group = %id, %error, "cannot delete secret for removed P2P group");
        }
        Ok(())
    }

    // ----- history ------------------------------------------------------

    pub async fn history(&self, limit: usize) -> Result<Vec<ConnectionEvent>, CatalogError> {
        self.inner
            .stores
            .history
            .recent(limit)
            .await
            .map_err(CatalogError::Storage)
    }

    pub async fn record_history(&self, event: &ConnectionEvent) {
        if let Err(error) = self.inner.stores.history.record(event).await {
            tracing::warn!(%error, "cannot record connection history");
        }
    }
}

#[cfg(test)]
mod tests {
    use kestrel_model::{EnterpriseConfig, Phase2Auth, ProfileSecurity};
    use kestrel_testkit::{
        MemoryCerts, MemoryHistory, MemoryP2pGroups, MemoryProfiles, MemorySecrets,
    };

    use super::*;

    const SAMPLE_CA: &str =
        "-----BEGIN CERTIFICATE-----\nMAowAwIBAQMDAAEC\n-----END CERTIFICATE-----\n";

    async fn open_catalog() -> Catalog {
        Catalog::open(CatalogStores {
            profiles: Arc::new(MemoryProfiles::default()),
            secrets: Arc::new(MemorySecrets::default()),
            certs: Arc::new(MemoryCerts::default()),
            p2p_groups: Arc::new(MemoryP2pGroups::default()),
            history: Arc::new(MemoryHistory::default()),
        })
        .await
        .expect("catalog opens")
    }

    #[tokio::test]
    async fn referenced_certificate_cannot_be_deleted_until_profile_is_removed() {
        let catalog = open_catalog().await;
        let pem = CertificatePem::new(SAMPLE_CA.to_owned()).unwrap();
        let cert_id = catalog
            .import_certificate("corp-ca".to_owned(), pem)
            .await
            .unwrap();

        let mut profile =
            WifiProfile::new(Ssid::new("corp").unwrap(), ProfileSecurity::WpaEnterprise);
        profile.enterprise = Some(EnterpriseConfig {
            eap: EapMethod::Peap,
            identity: "alice@example.com".to_owned(),
            anonymous_identity: None,
            ca_cert: Some(cert_id),
            system_ca: false,
            client_cert: None,
            domain_suffix_match: Some("example.com".to_owned()),
            altsubject_match: Vec::new(),
            phase2: Some(Phase2Auth::Mschapv2),
        });
        let secrets = ProfileSecrets::from_passphrase(Secret::new("secret-pass"));
        let profile_id = catalog.add_profile(profile, Some(secrets)).await.unwrap();

        let err = catalog.delete_certificate(cert_id).await.unwrap_err();
        assert!(matches!(err, CatalogError::Busy(_)));

        catalog.delete_profile(profile_id).await.unwrap();
        catalog.delete_certificate(cert_id).await.unwrap();
        assert_eq!(catalog.certificates(), [] as [Certificate; 0]);
    }

    #[tokio::test]
    async fn add_profile_rejects_missing_referenced_cert_without_leaking_secret() {
        let secrets_store = Arc::new(MemorySecrets::default());
        let catalog = Catalog::open(CatalogStores {
            profiles: Arc::new(MemoryProfiles::default()),
            secrets: secrets_store.clone(),
            certs: Arc::new(MemoryCerts::default()),
            p2p_groups: Arc::new(MemoryP2pGroups::default()),
            history: Arc::new(MemoryHistory::default()),
        })
        .await
        .unwrap();

        let mut profile =
            WifiProfile::new(Ssid::new("corp").unwrap(), ProfileSecurity::WpaEnterprise);
        let missing_cert = CertId::generate();
        profile.enterprise = Some(EnterpriseConfig {
            eap: EapMethod::Peap,
            identity: "alice".to_owned(),
            anonymous_identity: None,
            ca_cert: Some(missing_cert),
            system_ca: false,
            client_cert: None,
            domain_suffix_match: None,
            altsubject_match: Vec::new(),
            phase2: Some(Phase2Auth::Mschapv2),
        });
        let id = profile.id;
        let err = catalog
            .add_profile(
                profile,
                Some(ProfileSecrets::from_passphrase(Secret::new("hunter22"))),
            )
            .await
            .unwrap_err();
        assert_eq!(err, CatalogError::NoSuchCertificate(missing_cert));
        assert!(
            secrets_store
                .get(SecretKey::Profile(id))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn mark_profile_connected_updates_timestamp_and_emits_event() {
        let catalog = open_catalog().await;
        let mut rx = catalog.subscribe();
        let profile = WifiProfile::new(Ssid::new("home").unwrap(), ProfileSecurity::Open);
        let id = catalog.add_profile(profile, None).await.unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CatalogEvent::ProfileAdded(_)
        ));

        catalog
            .mark_profile_connected(id, 1_700_000_000)
            .await
            .unwrap();
        let updated = catalog.profile(id).unwrap();
        assert_eq!(updated.last_connected, Some(1_700_000_000));
        assert!(matches!(
            rx.recv().await.unwrap(),
            CatalogEvent::ProfileChanged(_)
        ));
    }

    #[tokio::test]
    async fn save_formed_p2p_group_deduplicates_and_seals_psk() {
        let catalog = open_catalog().await;
        let ssid = Ssid::new("DIRECT-xy").unwrap();
        let go_addr = MacAddress::from_octets([2, 0, 0, 0, 0, 1]);
        let peer_addr = MacAddress::from_octets([2, 0, 0, 0, 0, 2]);

        let first = catalog
            .save_formed_p2p_group(
                P2pRole::GroupOwner,
                ssid.clone(),
                go_addr,
                None,
                String::new(),
                Secret::new("passphrase123"),
                100,
            )
            .await
            .unwrap();
        assert_eq!(first.name, "DIRECT-xy");
        assert_eq!(first.peer, None);

        let second = catalog
            .save_formed_p2p_group(
                P2pRole::GroupOwner,
                ssid,
                go_addr,
                Some(peer_addr),
                "Living Room TV".to_owned(),
                Secret::new("passphrase456"),
                200,
            )
            .await
            .unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(second.peer, Some(peer_addr));
        assert_eq!(second.last_connected, Some(200));

        let loaded = catalog
            .load_secret(SecretKey::P2pGroup(first.id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.passphrase.unwrap().expose(), "passphrase456");
    }
}

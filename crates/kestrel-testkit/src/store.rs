// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kestrel_model::{
    CertId, Certificate, ConnectionEvent, P2pGroupId, P2pGroupProfile, ProfileId, ProfileSecrets,
    Secret, SecretKey, WifiProfile,
};
use kestrel_ports::store::{
    CertStore, HistoryStore, P2pGroupStore, ProfileRepository, SecretStore, StateStore,
};
use kestrel_ports::{PortError, PortResult};

/// In-memory profile repository.
#[derive(Debug, Clone, Default)]
pub struct MemoryProfiles {
    profiles: Arc<Mutex<BTreeMap<ProfileId, WifiProfile>>>,
}

impl MemoryProfiles {
    pub fn with(profiles: impl IntoIterator<Item = WifiProfile>) -> Self {
        let store = Self::default();
        store
            .profiles
            .lock()
            .expect("profiles")
            .extend(profiles.into_iter().map(|p| (p.id, p)));
        store
    }

    pub fn get(&self, id: ProfileId) -> Option<WifiProfile> {
        self.profiles.lock().expect("profiles").get(&id).cloned()
    }
}

#[async_trait]
impl ProfileRepository for MemoryProfiles {
    async fn load_all(&self) -> PortResult<Vec<WifiProfile>> {
        Ok(self
            .profiles
            .lock()
            .expect("profiles")
            .values()
            .cloned()
            .collect())
    }

    async fn save(&self, profile: &WifiProfile) -> PortResult<()> {
        profile
            .validate()
            .map_err(|e| PortError::InvalidArgument(e.to_string()))?;
        self.profiles
            .lock()
            .expect("profiles")
            .insert(profile.id, profile.clone());
        Ok(())
    }

    async fn delete(&self, id: ProfileId) -> PortResult<()> {
        self.profiles.lock().expect("profiles").remove(&id);
        Ok(())
    }
}

/// In-memory X.509 certificate store.
#[derive(Debug, Clone, Default)]
pub struct MemoryCerts {
    certs: Arc<Mutex<BTreeMap<CertId, Certificate>>>,
}

#[async_trait]
impl CertStore for MemoryCerts {
    async fn load_all(&self) -> PortResult<Vec<Certificate>> {
        Ok(self
            .certs
            .lock()
            .expect("certs")
            .values()
            .cloned()
            .collect())
    }

    async fn get(&self, id: CertId) -> PortResult<Option<Certificate>> {
        Ok(self.certs.lock().expect("certs").get(&id).cloned())
    }

    async fn save(&self, cert: &Certificate) -> PortResult<()> {
        cert.validate()
            .map_err(|e| PortError::InvalidArgument(e.to_string()))?;
        self.certs
            .lock()
            .expect("certs")
            .insert(cert.id, cert.clone());
        Ok(())
    }

    async fn delete(&self, id: CertId) -> PortResult<()> {
        self.certs.lock().expect("certs").remove(&id);
        Ok(())
    }
}

/// In-memory persistent Wi-Fi Direct group store.
#[derive(Debug, Clone, Default)]
pub struct MemoryP2pGroups {
    groups: Arc<Mutex<BTreeMap<P2pGroupId, P2pGroupProfile>>>,
}

#[async_trait]
impl P2pGroupStore for MemoryP2pGroups {
    async fn load_all(&self) -> PortResult<Vec<P2pGroupProfile>> {
        Ok(self
            .groups
            .lock()
            .expect("p2p_groups")
            .values()
            .cloned()
            .collect())
    }

    async fn save(&self, group: &P2pGroupProfile) -> PortResult<()> {
        group
            .validate()
            .map_err(|e| PortError::InvalidArgument(e.to_string()))?;
        self.groups
            .lock()
            .expect("p2p_groups")
            .insert(group.id, group.clone());
        Ok(())
    }

    async fn delete(&self, id: P2pGroupId) -> PortResult<()> {
        self.groups.lock().expect("p2p_groups").remove(&id);
        Ok(())
    }
}

/// In-memory secret store. For tests only: secrets are not encrypted.
#[derive(Debug, Clone, Default)]
pub struct MemorySecrets {
    secrets: Arc<Mutex<BTreeMap<SecretKey, ProfileSecrets>>>,
    corrupted: Arc<Mutex<BTreeSet<SecretKey>>>,
}

impl MemorySecrets {
    pub fn insert(&self, id: ProfileId, secret: &str) {
        let key = SecretKey::Profile(id);
        self.corrupted.lock().expect("corrupted").remove(&key);
        self.secrets
            .lock()
            .expect("secrets")
            .insert(key, ProfileSecrets::from_passphrase(Secret::new(secret)));
    }

    /// Simulates a credential that fails decryption (for example after a
    /// host key or TPM reset). The next read quarantines it and returns
    /// `PortError::CorruptSecret`.
    pub fn corrupt(&self, id: ProfileId) {
        let key = SecretKey::Profile(id);
        self.secrets.lock().expect("secrets").remove(&key);
        self.corrupted.lock().expect("corrupted").insert(key);
    }

    pub fn contains(&self, id: ProfileId) -> bool {
        self.secrets
            .lock()
            .expect("secrets")
            .contains_key(&SecretKey::Profile(id))
    }
}

#[async_trait]
impl SecretStore for MemorySecrets {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn get(&self, key: SecretKey) -> PortResult<Option<ProfileSecrets>> {
        if self.corrupted.lock().expect("corrupted").remove(&key) {
            return Err(PortError::CorruptSecret(format!(
                "credential for {} cannot be unsealed",
                key.cred_name()
            )));
        }
        Ok(self.secrets.lock().expect("secrets").get(&key).cloned())
    }

    async fn set(&self, key: SecretKey, secrets: &ProfileSecrets) -> PortResult<()> {
        self.corrupted.lock().expect("corrupted").remove(&key);
        self.secrets
            .lock()
            .expect("secrets")
            .insert(key, secrets.clone());
        Ok(())
    }

    async fn delete(&self, key: SecretKey) -> PortResult<()> {
        self.corrupted.lock().expect("corrupted").remove(&key);
        self.secrets.lock().expect("secrets").remove(&key);
        Ok(())
    }
}

/// In-memory daemon state store.
#[derive(Debug, Clone, Default)]
pub struct MemoryState {
    wireless_enabled: Arc<Mutex<Option<bool>>>,
}

impl MemoryState {
    pub fn with(enabled: bool) -> Self {
        Self {
            wireless_enabled: Arc::new(Mutex::new(Some(enabled))),
        }
    }

    pub fn get(&self) -> Option<bool> {
        *self.wireless_enabled.lock().expect("state")
    }
}

#[async_trait]
impl StateStore for MemoryState {
    async fn wireless_enabled(&self) -> PortResult<Option<bool>> {
        Ok(*self.wireless_enabled.lock().expect("state"))
    }

    async fn set_wireless_enabled(&self, enabled: bool) -> PortResult<()> {
        *self.wireless_enabled.lock().expect("state") = Some(enabled);
        Ok(())
    }
}

/// In-memory connection history.
#[derive(Debug, Clone, Default)]
pub struct MemoryHistory {
    events: Arc<Mutex<Vec<ConnectionEvent>>>,
}

impl MemoryHistory {
    pub fn events(&self) -> Vec<ConnectionEvent> {
        self.events.lock().expect("history").clone()
    }
}

#[async_trait]
impl HistoryStore for MemoryHistory {
    async fn record(&self, event: &ConnectionEvent) -> PortResult<()> {
        self.events.lock().expect("history").push(event.clone());
        Ok(())
    }

    async fn recent(&self, limit: usize) -> PortResult<Vec<ConnectionEvent>> {
        Ok(self
            .events
            .lock()
            .expect("history")
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect())
    }
}

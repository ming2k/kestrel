// SPDX-License-Identifier: LGPL-2.1-or-later

//! The D-Bus server: exported objects plus the task that keeps them in sync
//! with controller and catalog events.

mod agent;
mod cert;
mod device;
mod manager;
mod p2p_group;
mod profile;
mod session;

use std::collections::BTreeSet;
use std::sync::Arc;

use futures_util::StreamExt;
use kestrel_catalog::{Catalog, CatalogEvent};
use kestrel_controller::{ControllerEvent, ControllerHandle, SessionId, SessionSnapshot};
use kestrel_model::{CertId, Certificate, InterfaceName, P2pGroupId, ProfileId, WifiProfile};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, watch};
use tokio::task::AbortHandle;
use zbus::message::{Header, Type};

use crate::{
    Action, ApiError, Authorizer, BUS_NAME, ROOT_PATH, cert_path, p2p_group_path, profile_path,
    session_path,
};

pub(crate) use agent::AgentSlot;

/// Per-kind registries of exported D-Bus object IDs.
///
/// Each kind has its own mutex so eager exports from another interface
/// (e.g. `P2p::connect` exporting a `Session`, or `Manager::add_profile`
/// exporting a `Profile`) can never form a lock cycle with `Sync` updating
/// the calling interface.
#[derive(Debug, Default)]
pub(crate) struct ExportedState {
    devices: Mutex<BTreeSet<InterfaceName>>,
    profiles: Mutex<BTreeSet<ProfileId>>,
    certs: Mutex<BTreeSet<CertId>>,
    p2p_groups: Mutex<BTreeSet<P2pGroupId>>,
    sessions: Mutex<BTreeSet<SessionId>>,
}

/// State shared by every exported object.
#[derive(Debug, Clone)]
pub(crate) struct Shared {
    pub(crate) controller: ControllerHandle,
    pub(crate) catalog: Catalog,
    pub(crate) authorizer: Arc<dyn Authorizer>,
    pub(crate) connection: zbus::Connection,
    pub(crate) agent: AgentSlot,
    pub(crate) exported: Arc<ExportedState>,
}

impl Shared {
    pub(crate) async fn authorize(
        &self,
        header: &Header<'_>,
        action: Action,
    ) -> Result<String, ApiError> {
        let sender = header
            .sender()
            .map(ToString::to_string)
            .ok_or_else(|| ApiError::AccessDenied("anonymous caller".into()))?;
        self.authorizer.check(&sender, action).await?;
        Ok(sender)
    }

    pub(crate) async fn ensure_profile_exported(&self, profile: WifiProfile) -> zbus::Result<()> {
        let mut profiles = self.exported.profiles.lock().await;
        let id = profile.id;
        if profiles.contains(&id) {
            profile::update(self, profile).await
        } else {
            profile::export(self, profile).await?;
            profiles.insert(id);
            Ok(())
        }
    }

    pub(crate) async fn ensure_cert_exported(&self, cert: Certificate) -> zbus::Result<()> {
        let mut certs = self.exported.certs.lock().await;
        let id = cert.id;
        if !certs.contains(&id) {
            cert::export(self, cert).await?;
            certs.insert(id);
        }
        Ok(())
    }

    pub(crate) async fn ensure_session_exported(
        &self,
        snapshot: SessionSnapshot,
    ) -> zbus::Result<()> {
        let mut sessions = self.exported.sessions.lock().await;
        let id = snapshot.id;
        if sessions.contains(&id) {
            session::update(self, snapshot).await
        } else {
            session::export(self, snapshot).await?;
            sessions.insert(id);
            Ok(())
        }
    }
}

/// A running D-Bus server.
#[derive(Debug)]
pub struct Server {
    connection: zbus::Connection,
    tasks: Vec<AbortHandle>,
    fault_rx: watch::Receiver<Option<String>>,
}

impl Server {
    /// Exports the API on `connection` and claims the bus name.
    pub async fn serve(
        connection: zbus::Connection,
        controller: ControllerHandle,
        catalog: Catalog,
        authorizer: Arc<dyn Authorizer>,
    ) -> Result<Self, ApiError> {
        let shared = Shared {
            controller: controller.clone(),
            catalog: catalog.clone(),
            authorizer,
            connection: connection.clone(),
            agent: AgentSlot::default(),
            exported: Arc::new(ExportedState::default()),
        };
        let server = connection.object_server();
        server.at(ROOT_PATH, zbus::fdo::ObjectManager).await?;
        server
            .at(ROOT_PATH, manager::Manager::new(shared.clone()).await?)
            .await?;
        // Subscribe before the initial export so nothing is missed.
        let controller_events = controller.subscribe();
        let catalog_events = catalog.subscribe();
        let sync = Sync::new(shared.clone());
        sync.full_resync().await;
        // Start watching bus name owners before claiming our well-known name
        // so no agent disconnect can be missed after registration opens.
        let mut tasks = agent::watch_owner(shared).await?;
        let (fault_tx, fault_rx) = watch::channel(None);
        if let Err(error) = connection.request_name(BUS_NAME).await {
            for handle in tasks {
                handle.abort();
            }
            return Err(error.into());
        }
        match watch_bus_name(&connection, fault_tx.clone()).await {
            Ok(handle) => tasks.push(handle),
            Err(error) => {
                for handle in tasks {
                    handle.abort();
                }
                let _ = connection.release_name(BUS_NAME).await;
                return Err(error);
            }
        }
        let sync_fault = fault_tx;
        let sync_task = tokio::spawn(async move {
            sync.run(controller_events, catalog_events).await;
            let _ = sync_fault.send(Some("D-Bus object sync stopped unexpectedly".to_owned()));
        });
        tasks.push(sync_task.abort_handle());
        Ok(Self {
            connection,
            tasks,
            fault_rx,
        })
    }

    pub const fn connection(&self) -> &zbus::Connection {
        &self.connection
    }

    /// Resolves if the server loses its bus name, the D-Bus connection drops,
    /// or the internal object sync loop stops unexpectedly. Cancel-safe.
    pub async fn wait_fault(&mut self) -> String {
        loop {
            if let Some(reason) = self.fault_rx.borrow().clone() {
                return reason;
            }
            if self.fault_rx.changed().await.is_err() {
                return "D-Bus server supervisor stopped unexpectedly".to_owned();
            }
        }
    }

    /// Releases the bus name and stops syncing.
    pub async fn stop(mut self) {
        for handle in self.tasks.drain(..) {
            handle.abort();
        }
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.connection.release_name(BUS_NAME),
        )
        .await;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for handle in self.tasks.drain(..) {
            handle.abort();
        }
    }
}

/// Watches `NameOwnerChanged` for `BUS_NAME` and reports a fatal fault if the
/// server loses ownership or the D-Bus signal stream closes (bus disconnect).
async fn watch_bus_name(
    connection: &zbus::Connection,
    fault_tx: watch::Sender<Option<String>>,
) -> Result<AbortHandle, ApiError> {
    let my_name = connection.unique_name().map(|n| n.as_str().to_owned());
    let rule = zbus::MatchRule::builder()
        .msg_type(Type::Signal)
        .sender("org.freedesktop.DBus")
        .interface("org.freedesktop.DBus")
        .member("NameOwnerChanged")
        .arg(0, BUS_NAME)
        .build()?;
    let mut stream = zbus::MessageStream::for_match_rule(rule, connection, None).await?;
    let task = tokio::spawn(async move {
        while let Some(item) = stream.next().await {
            let message = match item {
                Ok(message) => message,
                Err(error) => {
                    tracing::debug!(%error, "ignoring malformed NameOwnerChanged signal");
                    continue;
                }
            };
            let Ok((name, _old, new)) = message.body().deserialize::<(String, String, String)>()
            else {
                continue;
            };
            if name == BUS_NAME && my_name.as_deref() != Some(new.as_str()) {
                let reason = if new.is_empty() {
                    format!("lost D-Bus name {BUS_NAME}")
                } else {
                    format!("lost D-Bus name {BUS_NAME} to {new}")
                };
                let _ = fault_tx.send(Some(reason));
                return;
            }
        }
        let _ = fault_tx.send(Some("D-Bus connection closed".to_owned()));
    });
    Ok(task.abort_handle())
}

struct Sync {
    shared: Shared,
}

impl Sync {
    const fn new(shared: Shared) -> Self {
        Self { shared }
    }

    async fn run(
        self,
        mut controller_events: tokio::sync::broadcast::Receiver<ControllerEvent>,
        mut catalog_events: tokio::sync::broadcast::Receiver<CatalogEvent>,
    ) {
        loop {
            tokio::select! {
                result = controller_events.recv() => match result {
                    Ok(event) => {
                        if let Err(error) = self.apply_controller(event).await {
                            tracing::warn!(%error, "D-Bus controller sync failed; resyncing");
                            self.full_resync().await;
                        }
                    }
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "D-Bus controller sync lagged; resyncing");
                        self.full_resync().await;
                    }
                    Err(RecvError::Closed) => return,
                },
                result = catalog_events.recv() => match result {
                    Ok(event) => {
                        if let Err(error) = self.apply_catalog(event).await {
                            tracing::warn!(%error, "D-Bus catalog sync failed; resyncing");
                            self.full_resync().await;
                        }
                    }
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "D-Bus catalog sync lagged; resyncing");
                        self.full_resync().await;
                    }
                    Err(RecvError::Closed) => return,
                },
            }
        }
    }

    async fn apply_controller(&self, event: ControllerEvent) -> zbus::Result<()> {
        let server = self.shared.connection.object_server();
        match event {
            ControllerEvent::DeviceAdded(snapshot) | ControllerEvent::DeviceChanged(snapshot) => {
                let name = snapshot.name.clone();
                let mut devices = self.shared.exported.devices.lock().await;
                if devices.contains(&name) {
                    device::update(&self.shared, snapshot).await?;
                } else {
                    device::export(&self.shared, snapshot).await?;
                    devices.insert(name);
                }
                drop(devices);
                manager::refresh(&self.shared).await?;
            }
            ControllerEvent::DeviceRemoved(name) => {
                let mut devices = self.shared.exported.devices.lock().await;
                if devices.contains(&name) {
                    device::unexport(&self.shared, &name).await?;
                    devices.remove(&name);
                }
                drop(devices);
                manager::refresh(&self.shared).await?;
            }
            ControllerEvent::PeerFound { device, peer } => {
                device::peer_found(&self.shared, &device, &peer).await?;
            }
            ControllerEvent::PeerLost { device, address } => {
                device::peer_lost(&self.shared, &device, address).await?;
            }
            ControllerEvent::SessionAdded(snapshot) | ControllerEvent::SessionChanged(snapshot) => {
                let id = snapshot.id;
                let mut sessions = self.shared.exported.sessions.lock().await;
                if sessions.contains(&id) {
                    session::update(&self.shared, snapshot).await?;
                } else {
                    session::export(&self.shared, snapshot).await?;
                    sessions.insert(id);
                }
            }
            ControllerEvent::SessionRemoved(id) => {
                let mut sessions = self.shared.exported.sessions.lock().await;
                if sessions.contains(&id) {
                    server
                        .remove::<session::Session, _>(session_path(id))
                        .await?;
                    sessions.remove(&id);
                }
            }
            ControllerEvent::WirelessEnabled(_) | ControllerEvent::WirelessHardwareEnabled(_) => {
                manager::refresh(&self.shared).await?;
            }
        }
        Ok(())
    }

    async fn apply_catalog(&self, event: CatalogEvent) -> zbus::Result<()> {
        let server = self.shared.connection.object_server();
        match event {
            CatalogEvent::ProfileAdded(profile) | CatalogEvent::ProfileChanged(profile) => {
                let id = profile.id;
                let mut profiles = self.shared.exported.profiles.lock().await;
                if profiles.contains(&id) {
                    profile::update(&self.shared, profile).await?;
                } else {
                    profile::export(&self.shared, profile).await?;
                    profiles.insert(id);
                }
            }
            CatalogEvent::SecretsChanged { profile, .. } => {
                let profiles = self.shared.exported.profiles.lock().await;
                if profiles.contains(&profile)
                    && let Ok(profile) = self.shared.catalog.profile(profile)
                {
                    profile::update(&self.shared, profile).await?;
                }
            }
            CatalogEvent::ProfileRemoved(id) => {
                let mut profiles = self.shared.exported.profiles.lock().await;
                if profiles.contains(&id) {
                    server
                        .remove::<profile::Profile, _>(profile_path(id))
                        .await?;
                    profiles.remove(&id);
                }
            }
            CatalogEvent::CertAdded(cert) => {
                let id = cert.id;
                let mut certs = self.shared.exported.certs.lock().await;
                if !certs.contains(&id) {
                    cert::export(&self.shared, cert).await?;
                    certs.insert(id);
                }
            }
            CatalogEvent::CertRemoved(id) => {
                let mut certs = self.shared.exported.certs.lock().await;
                if certs.contains(&id) {
                    server.remove::<cert::Certificate, _>(cert_path(id)).await?;
                    certs.remove(&id);
                }
            }
            CatalogEvent::P2pGroupAdded(group) | CatalogEvent::P2pGroupChanged(group) => {
                let id = group.id;
                let mut groups = self.shared.exported.p2p_groups.lock().await;
                if groups.contains(&id) {
                    p2p_group::update(&self.shared, group).await?;
                } else {
                    p2p_group::export(&self.shared, group).await?;
                    groups.insert(id);
                }
            }
            CatalogEvent::P2pGroupRemoved(id) => {
                let mut groups = self.shared.exported.p2p_groups.lock().await;
                if groups.contains(&id) {
                    server
                        .remove::<p2p_group::P2pGroup, _>(p2p_group_path(id))
                        .await?;
                    groups.remove(&id);
                }
            }
        }
        Ok(())
    }

    /// Reconciles exported objects against a fresh controller and catalog
    /// snapshot in place, adding new objects, updating existing ones, and
    /// removing only objects that no longer exist.
    #[allow(clippy::too_many_lines)]
    async fn full_resync(&self) {
        let server = self.shared.connection.object_server();
        let (Ok(devices), Ok(sessions)) = (
            self.shared.controller.devices().await,
            self.shared.controller.p2p().sessions().await,
        ) else {
            return;
        };
        let profiles = self.shared.catalog.profiles();
        let certs = self.shared.catalog.certificates();
        let p2p_groups = self.shared.catalog.p2p_groups();

        {
            let mut exported = self.shared.exported.devices.lock().await;
            let fresh: BTreeSet<InterfaceName> = devices.iter().map(|d| d.name.clone()).collect();
            let stale: Vec<InterfaceName> = exported.difference(&fresh).cloned().collect();
            for name in stale {
                if device::unexport(&self.shared, &name).await.is_ok() {
                    exported.remove(&name);
                }
            }
            for snapshot in devices {
                let name = snapshot.name.clone();
                if exported.contains(&name) {
                    if let Err(error) = device::update(&self.shared, snapshot).await {
                        tracing::warn!(%error, "cannot update device during resync");
                    }
                } else if let Err(error) = device::export(&self.shared, snapshot).await {
                    tracing::warn!(%error, "cannot export device");
                } else {
                    exported.insert(name);
                }
            }
        }

        {
            let mut exported = self.shared.exported.profiles.lock().await;
            let fresh: BTreeSet<ProfileId> = profiles.iter().map(|p| p.id).collect();
            let stale: Vec<ProfileId> = exported.difference(&fresh).copied().collect();
            for id in stale {
                if server
                    .remove::<profile::Profile, _>(profile_path(id))
                    .await
                    .is_ok()
                {
                    exported.remove(&id);
                }
            }
            for profile in profiles {
                let id = profile.id;
                if exported.contains(&id) {
                    if let Err(error) = profile::update(&self.shared, profile).await {
                        tracing::warn!(%error, "cannot update profile during resync");
                    }
                } else if let Err(error) = profile::export(&self.shared, profile).await {
                    tracing::warn!(%error, "cannot export profile");
                } else {
                    exported.insert(id);
                }
            }
        }

        {
            let mut exported = self.shared.exported.certs.lock().await;
            let fresh: BTreeSet<CertId> = certs.iter().map(|c| c.id).collect();
            let stale: Vec<CertId> = exported.difference(&fresh).copied().collect();
            for id in stale {
                if server
                    .remove::<cert::Certificate, _>(cert_path(id))
                    .await
                    .is_ok()
                {
                    exported.remove(&id);
                }
            }
            for cert in certs {
                let id = cert.id;
                if !exported.contains(&id) {
                    if let Err(error) = cert::export(&self.shared, cert).await {
                        tracing::warn!(%error, "cannot export certificate");
                    } else {
                        exported.insert(id);
                    }
                }
            }
        }

        {
            let mut exported = self.shared.exported.p2p_groups.lock().await;
            let fresh: BTreeSet<P2pGroupId> = p2p_groups.iter().map(|g| g.id).collect();
            let stale: Vec<P2pGroupId> = exported.difference(&fresh).copied().collect();
            for id in stale {
                if server
                    .remove::<p2p_group::P2pGroup, _>(p2p_group_path(id))
                    .await
                    .is_ok()
                {
                    exported.remove(&id);
                }
            }
            for group in p2p_groups {
                let id = group.id;
                if exported.contains(&id) {
                    if let Err(error) = p2p_group::update(&self.shared, group).await {
                        tracing::warn!(%error, "cannot update P2P group during resync");
                    }
                } else if let Err(error) = p2p_group::export(&self.shared, group).await {
                    tracing::warn!(%error, "cannot export P2P group");
                } else {
                    exported.insert(id);
                }
            }
        }

        {
            let mut exported = self.shared.exported.sessions.lock().await;
            let fresh: BTreeSet<SessionId> = sessions.iter().map(|s| s.id).collect();
            let stale: Vec<SessionId> = exported.difference(&fresh).copied().collect();
            for id in stale {
                if server
                    .remove::<session::Session, _>(session_path(id))
                    .await
                    .is_ok()
                {
                    exported.remove(&id);
                }
            }
            for snapshot in sessions {
                let id = snapshot.id;
                if exported.contains(&id) {
                    if let Err(error) = session::update(&self.shared, snapshot).await {
                        tracing::warn!(%error, "cannot update session during resync");
                    }
                } else if let Err(error) = session::export(&self.shared, snapshot).await {
                    tracing::warn!(%error, "cannot export session");
                } else {
                    exported.insert(id);
                }
            }
        }

        let _ = manager::refresh(&self.shared).await;
    }
}

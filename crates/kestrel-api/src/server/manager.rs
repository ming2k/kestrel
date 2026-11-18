// SPDX-License-Identifier: LGPL-2.1-or-later

use kestrel_model::{CertificatePem, OnlineState};
use zbus::OwnedObjectPath;
use zbus::message::Header;

use super::Shared;
use super::agent::DbusAgent;
use crate::{
    API_VERSION, Action, ApiError, ProfileSettings, ROOT_PATH, SecretBundle, cert_path,
    profile_from_settings, profile_path, secrets_from_bundle,
};

#[derive(Debug)]
pub(crate) struct Manager {
    shared: Shared,
    wireless_enabled: bool,
    wireless_hardware_enabled: bool,
    online_state: OnlineState,
}

impl Manager {
    pub(crate) async fn new(shared: Shared) -> Result<Self, ApiError> {
        let radio = shared.controller.radio();
        let wireless_enabled = radio.wireless_enabled().await?;
        let wireless_hardware_enabled = radio.wireless_hardware_enabled().await?;
        let online_state = radio.online_state().await?;
        Ok(Self {
            shared,
            wireless_enabled,
            wireless_hardware_enabled,
            online_state,
        })
    }
}

pub(crate) async fn refresh(shared: &Shared) -> zbus::Result<()> {
    let iface = shared
        .connection
        .object_server()
        .interface::<_, Manager>(ROOT_PATH)
        .await?;
    let radio = shared.controller.radio();
    let enabled = radio
        .wireless_enabled()
        .await
        .map_err(|e| zbus::Error::Failure(e.to_string()))?;
    let hardware_enabled = radio
        .wireless_hardware_enabled()
        .await
        .map_err(|e| zbus::Error::Failure(e.to_string()))?;
    let online_state = radio
        .online_state()
        .await
        .map_err(|e| zbus::Error::Failure(e.to_string()))?;
    let mut guard = iface.get_mut().await;
    if guard.wireless_enabled != enabled {
        guard.wireless_enabled = enabled;
        guard
            .wireless_enabled_changed(iface.signal_emitter())
            .await?;
    }
    if guard.wireless_hardware_enabled != hardware_enabled {
        guard.wireless_hardware_enabled = hardware_enabled;
        guard
            .wireless_hardware_enabled_changed(iface.signal_emitter())
            .await?;
    }
    if guard.online_state != online_state {
        guard.online_state = online_state;
        guard.online_state_changed(iface.signal_emitter()).await?;
    }
    Ok(())
}

#[zbus::interface(name = "com.hihusky.Kestrel.Manager")]
impl Manager {
    /// API version. Clients reject an unexpected value.
    #[zbus(property)]
    #[allow(clippy::unused_self)]
    fn version(&self) -> &str {
        API_VERSION
    }

    #[zbus(property)]
    fn wireless_enabled(&self) -> bool {
        self.wireless_enabled
    }

    #[zbus(property)]
    fn wireless_hardware_enabled(&self) -> bool {
        self.wireless_hardware_enabled
    }

    #[zbus(property)]
    fn online_state(&self) -> &str {
        self.online_state.as_str()
    }

    async fn set_wireless_enabled(
        &self,
        #[zbus(header)] header: Header<'_>,
        enabled: bool,
    ) -> Result<(), ApiError> {
        self.shared
            .authorize(&header, Action::ToggleWireless)
            .await?;
        Ok(self
            .shared
            .controller
            .radio()
            .set_wireless_enabled(enabled)
            .await?)
    }

    /// Creates a profile. `secrets` is empty for none (`passphrase`,
    /// `private_key`, `private_key_password`); secured profiles without
    /// credentials prompt the agent on first use.
    async fn add_profile(
        &self,
        #[zbus(header)] header: Header<'_>,
        settings: ProfileSettings,
        secrets: SecretBundle,
    ) -> Result<OwnedObjectPath, ApiError> {
        self.shared
            .authorize(&header, Action::ModifyProfiles)
            .await?;
        let profile = profile_from_settings(None, &settings)?;
        let bundle = secrets_from_bundle(&secrets)?;
        let secrets = (!bundle.is_empty()).then_some(bundle);
        let id = self.shared.catalog.add_profile(profile, secrets).await?;
        // A returned path must be usable at once: export before replying.
        let profile = self.shared.catalog.profile(id)?;
        self.shared.ensure_profile_exported(profile).await?;
        Ok(profile_path(id))
    }

    /// Imports an X.509 PEM certificate or CA bundle into Kestrel's store.
    async fn import_certificate(
        &self,
        #[zbus(header)] header: Header<'_>,
        name: String,
        pem: String,
    ) -> Result<OwnedObjectPath, ApiError> {
        self.shared
            .authorize(&header, Action::ModifyProfiles)
            .await?;
        let pem = CertificatePem::new(pem).map_err(|e| ApiError::invalid(e.to_string()))?;
        let id = self.shared.catalog.import_certificate(name, pem).await?;
        // Export before replying so the caller can pass `id` immediately.
        let cert = self.shared.catalog.certificate(id)?;
        self.shared.ensure_cert_exported(cert).await?;
        Ok(cert_path(id))
    }

    /// Recent connection events, newest first:
    /// `(unix_seconds, device, ssid, profile_id, outcome, detail)`.
    async fn history(
        &self,
        limit: u32,
    ) -> Result<Vec<(u64, String, String, String, String, String)>, ApiError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = usize::try_from(limit.min(500)).unwrap_or(500);
        let events = self.shared.catalog.history(limit).await?;
        Ok(events
            .into_iter()
            .map(|event| {
                (
                    event.at,
                    event.device,
                    event.ssid,
                    event.profile.map(|id| id.to_string()).unwrap_or_default(),
                    event.outcome.as_str().to_owned(),
                    event.detail.unwrap_or_default(),
                )
            })
            .collect())
    }

    /// Registers the caller's agent object. One agent at a time; it is
    /// dropped automatically when its owner leaves the bus.
    async fn register_agent(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: OwnedObjectPath,
    ) -> Result<(), ApiError> {
        let sender = self
            .shared
            .authorize(&header, Action::RegisterAgent)
            .await?;
        let previous = self.shared.agent.install(&sender, &path)?;
        // Verify the caller is still connected after installing so a
        // disconnect during polkit authorization cannot strand the slot.
        let dbus = zbus::fdo::DBusProxy::builder(&self.shared.connection)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(|error| {
                self.shared.agent.rollback(&sender, previous.clone());
                ApiError::from(error)
            })?;
        let bus_name = zbus::names::BusName::try_from(sender.as_str()).map_err(|error| {
            self.shared.agent.rollback(&sender, previous.clone());
            ApiError::AccessDenied(format!("invalid bus sender: {error}"))
        })?;
        if !dbus.name_has_owner(bus_name).await.unwrap_or(false) {
            self.shared.agent.rollback(&sender, previous);
            return Err(ApiError::AccessDenied("agent caller disconnected".into()));
        }
        let agent = DbusAgent::new(self.shared.connection.clone(), sender.clone(), path);
        if let Err(error) = self
            .shared
            .controller
            .radio()
            .set_agent(Some(std::sync::Arc::new(agent)))
            .await
        {
            self.shared.agent.rollback(&sender, previous);
            return Err(error.into());
        }
        tracing::info!(%sender, "agent registered");
        Ok(())
    }

    async fn unregister_agent(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: OwnedObjectPath,
    ) -> Result<(), ApiError> {
        let sender = header
            .sender()
            .map(ToString::to_string)
            .ok_or_else(|| ApiError::AccessDenied("anonymous caller".into()))?;
        if self.shared.agent.remove_if_owner_and_path(&sender, &path) {
            self.shared.controller.radio().set_agent(None).await?;
            Ok(())
        } else {
            Err(ApiError::AccessDenied(
                "the caller does not own the agent at that path".into(),
            ))
        }
    }
}

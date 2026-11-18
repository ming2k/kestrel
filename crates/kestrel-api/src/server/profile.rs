// SPDX-License-Identifier: LGPL-2.1-or-later

use kestrel_catalog::SecretUpdate;
use kestrel_model::WifiProfile;
use zbus::message::Header;

use super::Shared;
use crate::{
    Action, ApiError, ProfileSettings, SecretBundle, profile_from_settings, profile_path,
    secrets_from_bundle, settings_from_profile,
};

#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub(crate) struct Profile {
    shared: Shared,
    profile: WifiProfile,
    has_secret: bool,
}

pub(crate) async fn export(shared: &Shared, profile: WifiProfile) -> zbus::Result<()> {
    let has_secret = shared.catalog.has_secret(profile.id).await.unwrap_or(false);
    let existing = shared
        .connection
        .object_server()
        .at(
            profile_path(profile.id),
            Profile {
                shared: shared.clone(),
                profile: profile.clone(),
                has_secret,
            },
        )
        .await?;
    if existing.is_some() {
        update(shared, profile).await?;
    }
    Ok(())
}

fn same_settings(a: &WifiProfile, b: &WifiProfile) -> bool {
    a.name == b.name
        && a.ssid == b.ssid
        && a.security == b.security
        && a.hidden == b.hidden
        && a.autoconnect == b.autoconnect
        && a.priority == b.priority
        && a.bssid == b.bssid
        && a.l3 == b.l3
        && a.enterprise == b.enterprise
}

pub(crate) async fn update(shared: &Shared, profile: WifiProfile) -> zbus::Result<()> {
    let has_secret = shared.catalog.has_secret(profile.id).await.unwrap_or(false);
    let iface = shared
        .connection
        .object_server()
        .interface::<_, Profile>(profile_path(profile.id))
        .await?;
    let mut guard = iface.get_mut().await;
    let settings_changed = !same_settings(&guard.profile, &profile);
    let last_connected_changed = guard.profile.last_connected != profile.last_connected;
    guard.profile = profile;
    let secret_changed = guard.has_secret != has_secret;
    guard.has_secret = has_secret;
    let emitter = iface.signal_emitter();
    if settings_changed {
        guard.settings_changed(emitter).await?;
    }
    if last_connected_changed {
        guard.last_connected_changed(emitter).await?;
    }
    if secret_changed {
        guard.has_secret_changed(emitter).await?;
    }
    Ok(())
}

#[zbus::interface(name = "com.hihusky.Kestrel.Profile")]
impl Profile {
    #[zbus(property)]
    fn id(&self) -> String {
        self.profile.id.to_string()
    }

    /// All settings (see the settings table in `docs/dbus-api.md`). Never
    /// contains a secret.
    #[zbus(property)]
    fn settings(&self) -> ProfileSettings {
        settings_from_profile(&self.profile)
    }

    /// Whether a secret is stored. The secret itself is never readable.
    #[zbus(property)]
    fn has_secret(&self) -> bool {
        self.has_secret
    }

    /// Unix time of the last successful connection, or 0.
    #[zbus(property)]
    fn last_connected(&self) -> u64 {
        self.profile.last_connected.unwrap_or(0)
    }

    /// Merges `settings` into the profile. `secret_action` is `keep`,
    /// `set` (use `secrets`), or `clear`.
    async fn update(
        &self,
        #[zbus(header)] header: Header<'_>,
        settings: ProfileSettings,
        secret_action: String,
        secrets: SecretBundle,
    ) -> Result<(), ApiError> {
        self.shared
            .authorize(&header, Action::ModifyProfiles)
            .await?;
        let current = self.shared.catalog.profile(self.profile.id)?;
        let updated = profile_from_settings(Some(current), &settings)?;
        let secret = match secret_action.as_str() {
            "keep" => SecretUpdate::Keep,
            "set" => SecretUpdate::Set(secrets_from_bundle(&secrets)?),
            "clear" => SecretUpdate::Clear,
            other => {
                return Err(ApiError::invalid(format!(
                    "unknown secret action {other:?}"
                )));
            }
        };
        Ok(self.shared.catalog.update_profile(updated, secret).await?)
    }

    async fn delete(&self, #[zbus(header)] header: Header<'_>) -> Result<(), ApiError> {
        self.shared
            .authorize(&header, Action::ModifyProfiles)
            .await?;
        Ok(self.shared.catalog.delete_profile(self.profile.id).await?)
    }
}

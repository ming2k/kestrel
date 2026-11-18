// SPDX-License-Identifier: LGPL-2.1-or-later

use kestrel_model::P2pGroupProfile;
use zbus::message::Header;

use super::Shared;
use crate::{Action, ApiError, p2p_group_path};

#[derive(Debug)]
pub(crate) struct P2pGroup {
    shared: Shared,
    group: P2pGroupProfile,
}

pub(crate) async fn export(shared: &Shared, group: P2pGroupProfile) -> zbus::Result<()> {
    let existing = shared
        .connection
        .object_server()
        .at(
            p2p_group_path(group.id),
            P2pGroup {
                shared: shared.clone(),
                group: group.clone(),
            },
        )
        .await?;
    if existing.is_some() {
        update(shared, group).await?;
    }
    Ok(())
}

pub(crate) async fn update(shared: &Shared, group: P2pGroupProfile) -> zbus::Result<()> {
    let iface = shared
        .connection
        .object_server()
        .interface::<_, P2pGroup>(p2p_group_path(group.id))
        .await?;
    let mut guard = iface.get_mut().await;
    let old = std::mem::replace(&mut guard.group, group);
    let new = &guard.group;
    let emitter = iface.signal_emitter();
    if old.name != new.name {
        guard.name_changed(emitter).await?;
    }
    if old.ssid != new.ssid {
        guard.ssid_changed(emitter).await?;
    }
    if old.role != new.role {
        guard.role_changed(emitter).await?;
    }
    if old.go_address != new.go_address {
        guard.go_address_changed(emitter).await?;
    }
    if old.peer != new.peer {
        guard.peer_changed(emitter).await?;
    }
    if old.last_connected != new.last_connected {
        guard.last_connected_changed(emitter).await?;
    }
    Ok(())
}

#[zbus::interface(name = "com.hihusky.Kestrel.P2pGroup")]
impl P2pGroup {
    #[zbus(property)]
    fn id(&self) -> String {
        self.group.id.to_string()
    }

    #[zbus(property)]
    fn name(&self) -> String {
        self.group.name.clone()
    }

    #[zbus(property)]
    fn ssid(&self) -> String {
        self.group.ssid.to_string_lossy()
    }

    #[zbus(property)]
    fn role(&self) -> String {
        self.group.role.as_str().to_owned()
    }

    #[zbus(property)]
    fn go_address(&self) -> String {
        self.group.go_address.to_string()
    }

    #[zbus(property)]
    fn peer(&self) -> String {
        self.group.peer.map(|p| p.to_string()).unwrap_or_default()
    }

    /// Unix time of the last successful connection, or 0.
    #[zbus(property)]
    fn last_connected(&self) -> u64 {
        self.group.last_connected.unwrap_or(0)
    }

    async fn delete(&self, #[zbus(header)] header: Header<'_>) -> Result<(), ApiError> {
        self.shared
            .authorize(&header, Action::ModifyProfiles)
            .await?;
        Ok(self.shared.catalog.delete_p2p_group(self.group.id).await?)
    }
}

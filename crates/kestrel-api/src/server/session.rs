// SPDX-License-Identifier: LGPL-2.1-or-later

use kestrel_controller::SessionSnapshot;
use zbus::OwnedObjectPath;
use zbus::message::Header;

use super::Shared;
use crate::{Action, ApiError, device_path, session_path};

#[derive(Debug)]
pub(crate) struct Session {
    shared: Shared,
    snapshot: SessionSnapshot,
}

pub(crate) async fn export(shared: &Shared, snapshot: SessionSnapshot) -> zbus::Result<()> {
    let existing = shared
        .connection
        .object_server()
        .at(
            session_path(snapshot.id),
            Session {
                shared: shared.clone(),
                snapshot: snapshot.clone(),
            },
        )
        .await?;
    if existing.is_some() {
        update(shared, snapshot).await?;
    }
    Ok(())
}

pub(crate) async fn update(shared: &Shared, snapshot: SessionSnapshot) -> zbus::Result<()> {
    let iface = shared
        .connection
        .object_server()
        .interface::<_, Session>(session_path(snapshot.id))
        .await?;
    let mut guard = iface.get_mut().await;
    let old = std::mem::replace(&mut guard.snapshot, snapshot);
    let new = &guard.snapshot;
    let emitter = iface.signal_emitter();
    if old.role != new.role {
        guard.role_changed(emitter).await?;
    }
    if old.group_interface != new.group_interface {
        guard.group_interface_changed(emitter).await?;
    }
    if old.peer_ip != new.peer_ip {
        guard.peer_ip_changed(emitter).await?;
    }
    if old.failure != new.failure {
        guard.failure_changed(emitter).await?;
        guard.failure_detail_changed(emitter).await?;
    }
    if old.state != new.state {
        guard.state_changed(emitter).await?;
    }
    Ok(())
}

#[zbus::interface(name = "com.hihusky.Kestrel.Session")]
impl Session {
    #[zbus(property)]
    fn device(&self) -> OwnedObjectPath {
        device_path(&self.snapshot.device)
    }

    /// The peer's P2P device address; empty for an autonomous group.
    #[zbus(property)]
    fn peer(&self) -> String {
        self.snapshot
            .peer
            .map(|peer| peer.to_string())
            .unwrap_or_default()
    }

    /// Whether the peer initiated the connection.
    #[zbus(property)]
    fn incoming(&self) -> bool {
        self.snapshot.incoming
    }

    /// Whether the group was started without GO negotiation.
    #[zbus(property)]
    fn autonomous(&self) -> bool {
        self.snapshot.autonomous
    }

    /// `negotiating`, `forming`, `configuring-l3`, `ready`, or `closed`.
    #[zbus(property)]
    fn state(&self) -> String {
        self.snapshot.state.to_owned()
    }

    /// `group-owner`, `client`, or empty before negotiation completes.
    #[zbus(property)]
    fn role(&self) -> String {
        self.snapshot
            .role
            .map(|r| r.as_str().to_owned())
            .unwrap_or_default()
    }

    /// The group's network interface, once it exists.
    #[zbus(property)]
    fn group_interface(&self) -> String {
        self.snapshot
            .group_interface
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
    }

    /// The peer's IP address once known: the lease we granted as group
    /// owner, or the group owner's address as client.
    #[zbus(property)]
    fn peer_ip(&self) -> String {
        self.snapshot
            .peer_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default()
    }

    /// Failure code once closed by a failure, else empty.
    #[zbus(property)]
    fn failure(&self) -> String {
        self.snapshot
            .failure
            .as_ref()
            .map(|f| f.code().to_owned())
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn failure_detail(&self) -> String {
        self.snapshot
            .failure
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
    }

    /// Tears the session down: L3, then the group.
    async fn close(&self, #[zbus(header)] header: Header<'_>) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        Ok(self
            .shared
            .controller
            .p2p()
            .close_session(self.snapshot.id)
            .await?)
    }
}

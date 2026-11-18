// SPDX-License-Identifier: LGPL-2.1-or-later

//! The `net.connman.iwd.Agent` Kestrel registers. It answers only the
//! authenticated `net.connman.iwd` bus owner, only for the association Kestrel
//! itself started, and strictly once per attempt.

use std::sync::Weak;

use zbus::OwnedObjectPath;
use zbus::message::Header;

use crate::{AGENT_PATH, Inner, dbus_error};

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "net.connman.iwd.Agent.Error")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Canceled(String),
}

#[derive(Debug)]
struct Agent {
    inner: Weak<Inner>,
}

impl Agent {
    fn secret_for(
        &self,
        header: &Header<'_>,
        network: &OwnedObjectPath,
    ) -> Result<String, AgentError> {
        let inner = self
            .inner
            .upgrade()
            .ok_or_else(|| AgentError::Canceled("Kestrel is shutting down".into()))?;
        let sender = header
            .sender()
            .map(ToString::to_string)
            .ok_or_else(|| AgentError::Canceled("anonymous caller".into()))?;
        let mut state = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.iwd_owner.as_deref() != Some(sender.as_str()) {
            tracing::warn!(%sender, "rejected unauthorized net.connman.iwd.Agent call");
            return Err(AgentError::Canceled("unauthorized caller".into()));
        }
        // Network paths live under their station's path.
        let pending = state
            .pending
            .iter_mut()
            .find(|(station, _)| {
                network
                    .as_str()
                    .starts_with(&format!("{}/", station.as_str()))
            })
            .map(|(_, pending)| pending)
            .ok_or_else(|| AgentError::Canceled("no association in progress".into()))?;
        pending.asked = true;
        // Consume the secret so it is handed to iwd strictly once.
        pending
            .secret
            .take()
            .map(|secret| secret.expose().to_owned())
            .ok_or_else(|| AgentError::Canceled("no secret for this network".into()))
    }
}

// D-Bus methods take owned arguments.
#[allow(clippy::needless_pass_by_value, clippy::used_underscore_binding)]
#[zbus::interface(name = "net.connman.iwd.Agent")]
impl Agent {
    fn request_passphrase(
        &self,
        #[zbus(header)] header: Header<'_>,
        network: OwnedObjectPath,
    ) -> Result<String, AgentError> {
        self.secret_for(&header, &network)
    }

    #[allow(clippy::unused_self)]
    fn request_private_key_passphrase(
        &self,
        network: OwnedObjectPath,
    ) -> Result<String, AgentError> {
        let _ = network;
        Err(AgentError::Canceled("802.1X is not supported".into()))
    }

    #[allow(clippy::unused_self)]
    fn request_user_name_and_password(
        &self,
        network: OwnedObjectPath,
    ) -> Result<(String, String), AgentError> {
        let _ = network;
        Err(AgentError::Canceled("802.1X is not supported".into()))
    }

    #[allow(clippy::unused_self)]
    fn request_user_password(
        &self,
        network: OwnedObjectPath,
        user: String,
    ) -> Result<String, AgentError> {
        let _ = (network, user);
        Err(AgentError::Canceled("802.1X is not supported".into()))
    }

    #[allow(clippy::unused_self)]
    fn cancel(&self, reason: String) {
        tracing::debug!(%reason, "iwd cancelled an agent request");
    }

    #[allow(clippy::unused_self)]
    fn release(&self) {
        tracing::warn!("iwd released Kestrel's agent");
    }
}

pub(crate) async fn serve(
    connection: &zbus::Connection,
    inner: Weak<Inner>,
) -> kestrel_ports::PortResult<()> {
    connection
        .object_server()
        .at(AGENT_PATH, Agent { inner })
        .await
        .map(|_| ())
        .map_err(dbus_error)
}

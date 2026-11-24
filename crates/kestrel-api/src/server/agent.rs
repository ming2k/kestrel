// SPDX-License-Identifier: LGPL-2.1-or-later

//! Bridges the [`Agent`] port callbacks to a consumer's
//! `com.hihusky.Kestrel.Agent` object.
//!
//! The agent interface a consumer exports:
//!
//! - `RequestSecret(o device, o profile, s ssid, s security, s reason) -> s`;
//!   return the error `com.hihusky.Kestrel.Agent.Error.Declined` to
//!   decline.
//! - `AuthorizePeer(o device, s peer, s name, s method) -> (s method, s pin)`,
//!   where `method` is `pbc`, `display`, or `keypad` (with `pin`); decline
//!   with the same error.
//! - `DisplayPin(o session, s peer, s pin)`.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::StreamExt;
use kestrel_model::{Secret, WpsMethod, WpsPin};
use kestrel_ports::agent::{Agent, PeerRequest, PinDisplay, SecretRequest};
use kestrel_ports::p2p::RequestedMethod;
use zbus::OwnedObjectPath;
use zbus::message::Type;

use super::Shared;
use crate::{ApiError, device_path, profile_path, session_path};

const AGENT_INTERFACE: &str = "com.hihusky.Kestrel.Agent";

#[derive(Debug, Clone)]
pub(crate) struct DbusAgent {
    connection: zbus::Connection,
    owner: String,
    path: OwnedObjectPath,
}

impl DbusAgent {
    pub(crate) const fn new(
        connection: zbus::Connection,
        owner: String,
        path: OwnedObjectPath,
    ) -> Self {
        Self {
            connection,
            owner,
            path,
        }
    }

    async fn proxy(&self) -> Option<zbus::Proxy<'_>> {
        zbus::proxy::Builder::new(&self.connection)
            .destination(self.owner.as_str())
            .path(self.path.as_str())
            .interface(AGENT_INTERFACE)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .map_err(|error| tracing::warn!(%error, "cannot reach the agent"))
            .ok()
    }
}

#[async_trait]
impl Agent for DbusAgent {
    async fn request_secret(&self, request: SecretRequest) -> Option<Secret> {
        let proxy = self.proxy().await?;
        let reply = proxy
            .call_method(
                "RequestSecret",
                &(
                    device_path(&request.device),
                    profile_path(request.profile),
                    request.ssid.to_string_lossy(),
                    request.security.as_str(),
                    request.reason.code(),
                ),
            )
            .await
            .map_err(|error| tracing::info!(%error, "agent declined the secret request"))
            .ok()?;
        let secret: String = reply.body().deserialize().ok()?;
        Some(Secret::new(secret))
    }

    async fn authorize_peer(&self, request: PeerRequest) -> Option<WpsMethod> {
        let proxy = self.proxy().await?;
        let method = match request.method {
            RequestedMethod::PushButton => "pbc",
            RequestedMethod::Pin => "pin",
        };
        let reply = proxy
            .call_method(
                "AuthorizePeer",
                &(
                    device_path(&request.device),
                    request.peer.to_string(),
                    request.peer_name.unwrap_or_default(),
                    method,
                ),
            )
            .await
            .map_err(|error| tracing::info!(%error, "agent rejected the peer"))
            .ok()?;
        let (method, pin): (String, String) = reply.body().deserialize().ok()?;
        match method.as_str() {
            "pbc" => Some(WpsMethod::PushButton),
            "display" => Some(WpsMethod::DisplayPin),
            "keypad" => WpsPin::new(pin).ok().map(WpsMethod::EnterPin),
            _ => None,
        }
    }

    async fn display_pin(&self, display: PinDisplay) {
        let Some(proxy) = self.proxy().await else {
            return;
        };
        if let Err(error) = proxy
            .call_method(
                "DisplayPin",
                &(
                    session_path(display.session),
                    display.peer.to_string(),
                    display.pin.as_str(),
                ),
            )
            .await
        {
            tracing::warn!(%error, "agent failed to display the PIN");
        }
    }
}

/// The registered agent, if any, and its bus owner and object path.
#[derive(Debug, Clone, Default)]
pub(crate) struct AgentSlot {
    owner: Arc<Mutex<Option<(String, OwnedObjectPath)>>>,
}

impl AgentSlot {
    /// Installs or replaces the caller's agent, returning the caller's
    /// previous path if it was re-registering.
    pub(crate) fn install(
        &self,
        sender: &str,
        path: &OwnedObjectPath,
    ) -> Result<Option<OwnedObjectPath>, ApiError> {
        let mut guard = self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.as_ref() {
            Some((existing, _)) if existing != sender => {
                Err(ApiError::Busy("another agent is registered".into()))
            }
            Some((_, prev_path)) => {
                let previous = Some(prev_path.clone());
                *guard = Some((sender.to_owned(), path.clone()));
                Ok(previous)
            }
            None => {
                *guard = Some((sender.to_owned(), path.clone()));
                Ok(None)
            }
        }
    }

    pub(crate) fn rollback(&self, sender: &str, previous: Option<OwnedObjectPath>) {
        let mut guard = self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.as_ref().is_some_and(|(owner, _)| owner == sender) {
            *guard = previous.map(|path| (sender.to_owned(), path));
        }
    }

    pub(crate) fn remove_if_owner(&self, sender: &str) -> bool {
        let mut guard = self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.as_ref().is_some_and(|(owner, _)| owner == sender) {
            *guard = None;
            true
        } else {
            false
        }
    }

    pub(crate) fn remove_if_owner_and_path(&self, sender: &str, path: &OwnedObjectPath) -> bool {
        let mut guard = self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard
            .as_ref()
            .is_some_and(|(owner, registered)| owner == sender && registered == path)
        {
            *guard = None;
            true
        } else {
            false
        }
    }
}

/// Drops the agent when its owner disconnects from the bus.
///
/// Uses a non-blocking bounded drain/worker split so transient stream errors
/// never terminate monitoring and bursts of `NameOwnerChanged` signals cannot
/// stall `zbus`'s socket reader or grow memory without bound.
pub(crate) async fn watch_owner(shared: Shared) -> Result<Vec<tokio::task::AbortHandle>, ApiError> {
    const QUEUE_CAPACITY: usize = 256;

    let rule = zbus::MatchRule::builder()
        .msg_type(Type::Signal)
        .sender("org.freedesktop.DBus")
        .interface("org.freedesktop.DBus")
        .member("NameOwnerChanged")
        .build()?;
    let mut stream = zbus::MessageStream::for_match_rule(rule, &shared.connection, None).await?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(QUEUE_CAPACITY);
    let drain_agent = shared.agent.clone();
    let drain = tokio::spawn(async move {
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
            if new.is_empty() && drain_agent.remove_if_owner(&name) {
                match tx.try_send(name) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(owner)) => {
                        tracing::warn!(%owner, "agent disconnect queue full");
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
        }
    });
    let worker = tokio::spawn(async move {
        while let Some(owner) = rx.recv().await {
            tracing::info!(%owner, "agent owner left the bus");
            let _ = shared.controller.radio().set_agent(None).await;
        }
    });
    Ok(vec![drain.abort_handle(), worker.abort_handle()])
}

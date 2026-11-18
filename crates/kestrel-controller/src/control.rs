// SPDX-License-Identifier: LGPL-2.1-or-later

//! Narrow, domain-scoped control handles for [`crate::Controller`].

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use kestrel_model::{
    GoIntent, HotspotConfig as ModelHotspotConfig, HotspotSecurity, InterfaceName, MacAddress,
    OnlineState, P2pGroupId, P2pPeer, ProfileId, ProfileSecurity, Secret, SessionId, WpsMethod,
};
use kestrel_ports::agent::Agent;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::error::ControllerError;
use crate::radio::{Msg, Request};
use crate::snapshot::{ControllerEvent, DeviceSnapshot, SessionSnapshot};

async fn ask<T>(
    tx: &mpsc::UnboundedSender<Msg>,
    make: impl FnOnce(oneshot::Sender<T>) -> Request,
) -> Result<T, ControllerError> {
    let (reply, response) = oneshot::channel();
    tx.send(Msg::Request(Box::new(make(reply))))
        .map_err(|_| ControllerError::Stopped)?;
    response.await.map_err(|_| ControllerError::Stopped)
}

async fn call<T>(
    tx: &mpsc::UnboundedSender<Msg>,
    make: impl FnOnce(oneshot::Sender<Result<T, ControllerError>>) -> Request,
) -> Result<T, ControllerError> {
    ask(tx, make).await?
}

/// Cheap, cloneable handle to a running [`crate::Controller`].
#[derive(Clone)]
pub struct ControllerHandle {
    pub(crate) tx: mpsc::UnboundedSender<Msg>,
    pub(crate) events: broadcast::Sender<ControllerEvent>,
}

impl fmt::Debug for ControllerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllerHandle").finish_non_exhaustive()
    }
}

impl ControllerHandle {
    /// Subscribes to live device, peer, session, and radio state events.
    ///
    /// A lagging subscriber receives `RecvError::Lagged` and should re-read
    /// the full snapshot via [`Self::devices`] and [`P2pControl::sessions`].
    pub fn subscribe(&self) -> broadcast::Receiver<ControllerEvent> {
        self.events.subscribe()
    }

    pub async fn devices(&self) -> Result<Vec<DeviceSnapshot>, ControllerError> {
        ask(&self.tx, Request::Devices).await
    }

    pub async fn device(&self, name: &InterfaceName) -> Result<DeviceSnapshot, ControllerError> {
        let name = name.clone();
        ask(&self.tx, |reply| Request::Device(name.clone(), reply))
            .await?
            .ok_or_else(|| ControllerError::NoSuchDevice(name.to_string()))
    }

    pub fn station(&self) -> StationControl {
        StationControl {
            tx: self.tx.clone(),
        }
    }

    pub fn hotspot(&self) -> HotspotControl {
        HotspotControl {
            tx: self.tx.clone(),
        }
    }

    pub fn p2p(&self) -> P2pControl {
        P2pControl {
            tx: self.tx.clone(),
        }
    }

    pub fn radio(&self) -> RadioControl {
        RadioControl {
            tx: self.tx.clone(),
        }
    }

    pub async fn shutdown(&self) -> Result<(), ControllerError> {
        let (done, wait) = oneshot::channel();
        self.tx
            .send(Msg::Shutdown(done))
            .map_err(|_| ControllerError::Stopped)?;
        wait.await.map_err(|_| ControllerError::Stopped)
    }
}

/// Station-mode control for wireless devices.
#[derive(Clone)]
pub struct StationControl {
    tx: mpsc::UnboundedSender<Msg>,
}

impl fmt::Debug for StationControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StationControl").finish_non_exhaustive()
    }
}

impl StationControl {
    pub async fn scan(&self, device: &InterfaceName) -> Result<(), ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::Scan(device, reply)).await
    }

    pub async fn connect(
        &self,
        device: &InterfaceName,
        profile: ProfileId,
    ) -> Result<(), ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::Connect(device, profile, reply)).await
    }

    pub async fn disconnect(&self, device: &InterfaceName) -> Result<(), ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::Disconnect(device, reply)).await
    }

    pub async fn set_autoconnect(
        &self,
        device: &InterfaceName,
        enabled: bool,
    ) -> Result<(), ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| {
            Request::SetAutoconnect(device, enabled, reply)
        })
        .await
    }
}

/// SoftAP / hotspot control for wireless devices.
#[derive(Clone)]
pub struct HotspotControl {
    tx: mpsc::UnboundedSender<Msg>,
}

impl fmt::Debug for HotspotControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HotspotControl").finish_non_exhaustive()
    }
}

impl HotspotControl {
    pub async fn start(
        &self,
        device: &InterfaceName,
        config: ModelHotspotConfig,
        secret: Option<Secret>,
    ) -> Result<(), ControllerError> {
        config
            .validate()
            .map_err(|e| ControllerError::InvalidArgument(e.to_string()))?;
        if config.security.needs_secret() {
            let Some(secret) = &secret else {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} hotspot requires a passphrase",
                    config.security
                )));
            };
            let security = match config.security {
                HotspotSecurity::Open => ProfileSecurity::Open,
                HotspotSecurity::WpaPersonal => ProfileSecurity::WpaPersonal,
                HotspotSecurity::Wpa3Personal => ProfileSecurity::Wpa3Personal,
            };
            secret
                .validate_for(security)
                .map_err(|e| ControllerError::InvalidArgument(e.to_string()))?;
        } else if secret.is_some() {
            return Err(ControllerError::InvalidArgument(
                "open hotspot does not take a passphrase".to_owned(),
            ));
        }
        let device = device.clone();
        call(&self.tx, |reply| Request::StartHotspot {
            device,
            config,
            secret,
            reply,
        })
        .await
    }

    pub async fn stop(&self, device: &InterfaceName) -> Result<(), ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::StopHotspot(device, reply)).await
    }
}

/// Wi-Fi Direct discovery and session control.
#[derive(Clone)]
pub struct P2pControl {
    tx: mpsc::UnboundedSender<Msg>,
}

impl fmt::Debug for P2pControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P2pControl").finish_non_exhaustive()
    }
}

impl P2pControl {
    pub async fn find(
        &self,
        device: &InterfaceName,
        timeout: Duration,
    ) -> Result<(), ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::P2pFind(device, timeout, reply)).await
    }

    pub async fn stop_find(&self, device: &InterfaceName) -> Result<(), ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::P2pStopFind(device, reply)).await
    }

    /// Sets (or with `None`, clears) the Wi-Fi Display subelements advertised
    /// during P2P discovery and group negotiation.
    pub async fn set_wfd_subelements(
        &self,
        device: &InterfaceName,
        wfd_subelements: Option<Vec<u8>>,
    ) -> Result<(), ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| {
            Request::P2pSetWfdSubelements(device, wfd_subelements, reply)
        })
        .await
    }

    pub async fn peers(&self, device: &InterfaceName) -> Result<Vec<P2pPeer>, ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::Peers(device, reply)).await
    }

    pub async fn connect(
        &self,
        device: &InterfaceName,
        peer: MacAddress,
        method: WpsMethod,
        go_intent: Option<GoIntent>,
        persistent: bool,
    ) -> Result<SessionId, ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::P2pConnect {
            device,
            peer,
            method,
            go_intent,
            persistent,
            reply,
        })
        .await
    }

    pub async fn start_group(
        &self,
        device: &InterfaceName,
        frequency: Option<u32>,
        persistent: bool,
    ) -> Result<SessionId, ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::P2pStartGroup {
            device,
            frequency,
            persistent,
            reply,
        })
        .await
    }

    pub async fn connect_persistent(
        &self,
        device: &InterfaceName,
        group: P2pGroupId,
        peer: Option<MacAddress>,
        frequency: Option<u32>,
    ) -> Result<SessionId, ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::P2pConnectPersistent {
            device,
            group,
            peer,
            frequency,
            reply,
        })
        .await
    }

    pub async fn start_persistent_group(
        &self,
        device: &InterfaceName,
        group: P2pGroupId,
        frequency: Option<u32>,
    ) -> Result<SessionId, ControllerError> {
        let device = device.clone();
        call(&self.tx, |reply| Request::P2pStartPersistentGroup {
            device,
            group,
            frequency,
            reply,
        })
        .await
    }

    pub async fn sessions(&self) -> Result<Vec<SessionSnapshot>, ControllerError> {
        ask(&self.tx, Request::Sessions).await
    }

    pub async fn session(&self, id: SessionId) -> Result<SessionSnapshot, ControllerError> {
        ask(&self.tx, |reply| Request::Session(id, reply))
            .await?
            .ok_or(ControllerError::NoSuchSession(id))
    }

    pub async fn close_session(&self, id: SessionId) -> Result<(), ControllerError> {
        call(&self.tx, |reply| Request::CloseSession(id, reply)).await
    }
}

/// Global radio toggle, power/rfkill state, online status, and agent slot.
#[derive(Clone)]
pub struct RadioControl {
    tx: mpsc::UnboundedSender<Msg>,
}

impl fmt::Debug for RadioControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RadioControl").finish_non_exhaustive()
    }
}

impl RadioControl {
    pub async fn wireless_enabled(&self) -> Result<bool, ControllerError> {
        ask(&self.tx, Request::WirelessEnabled).await
    }

    pub async fn set_wireless_enabled(&self, enabled: bool) -> Result<(), ControllerError> {
        ask(&self.tx, |reply| {
            Request::SetWirelessEnabled(enabled, reply)
        })
        .await
    }

    pub async fn wireless_hardware_enabled(&self) -> Result<bool, ControllerError> {
        ask(&self.tx, Request::WirelessHardwareEnabled).await
    }

    pub async fn set_hardware_enabled(&self, enabled: bool) -> Result<(), ControllerError> {
        ask(&self.tx, |reply| {
            Request::SetHardwareEnabled(enabled, reply)
        })
        .await
    }

    pub async fn set_suspended(&self, suspended: bool) -> Result<(), ControllerError> {
        ask(&self.tx, |reply| Request::SetSuspended(suspended, reply)).await
    }

    pub async fn online_state(&self) -> Result<OnlineState, ControllerError> {
        ask(&self.tx, Request::OnlineState).await
    }

    pub async fn set_agent(&self, agent: Option<Arc<dyn Agent>>) -> Result<(), ControllerError> {
        ask(&self.tx, |reply| Request::SetAgent(agent, reply)).await
    }
}

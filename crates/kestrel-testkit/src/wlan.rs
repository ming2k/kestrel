// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kestrel_model::{
    Bss, HotspotSecurity, InterfaceName, MacAddress, P2pPeer, ProfileSecurity, Secret, Ssid,
    WpsMethod, WpsPin,
};
use kestrel_ports::ap::{ApEvent, ApProvider, ApStartRequest};
use kestrel_ports::p2p::{
    P2pConnectRequest, P2pDeviceConfig, P2pEvent, P2pGroupRequest, P2pProvider,
    PersistentGroupConnect,
};
use kestrel_ports::wlan::{
    Capabilities, ConnectRequest, LinkStatus, WlanDevice, WlanEvent, WlanProvider,
};
use kestrel_ports::{EventBus, PortError, PortResult, Subscription};

/// A call the fake received, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WlanCall {
    StartScan(InterfaceName),
    Connect {
        device: InterfaceName,
        ssid: Ssid,
        security: ProfileSecurity,
        /// The exposed passphrase, so tests can assert what was sent.
        secret: Option<String>,
    },
    Disconnect(InterfaceName),
    Sweep,
    StartAp {
        device: InterfaceName,
        ssid: Ssid,
        security: HotspotSecurity,
        frequency: Option<u32>,
    },
    StopAp(InterfaceName),
    P2pConfigure(InterfaceName, String),
    P2pFind(InterfaceName),
    P2pStopFind(InterfaceName),
    P2pConnect {
        device: InterfaceName,
        peer: MacAddress,
        method: &'static str,
        go_intent: u8,
        persistent: bool,
    },
    P2pStartGroup {
        device: InterfaceName,
        frequency: Option<u32>,
        persistent: bool,
    },
    P2pConnectPersistent {
        device: InterfaceName,
        peer: MacAddress,
        ssid: Ssid,
    },
    P2pStartPersistentGroup {
        device: InterfaceName,
        ssid: Ssid,
    },
    P2pAuthorizeGroup(InterfaceName, InterfaceName),
    P2pCancel(InterfaceName),
    P2pRemoveGroup(InterfaceName, InterfaceName),
}

#[derive(Debug, Default)]
struct State {
    devices: Vec<WlanDevice>,
    visible: Vec<Bss>,
    links: BTreeMap<InterfaceName, LinkStatus>,
    calls: Vec<WlanCall>,
    /// Passwords the fake access points accept, by SSID. Missing means any.
    passwords: BTreeMap<Ssid, String>,
    /// Associate automatically after `connect`.
    auto_associate: bool,
    /// Start AP automatically after `start_ap`.
    auto_ap: bool,
    hardware_enabled: bool,
    fail_connect: Option<PortError>,
    fail_start_ap: Option<PortError>,
    fail_start_group: Option<PortError>,
    fail_authorize_group: Option<PortError>,
    p2p_pin: Option<WpsPin>,
    peers: Vec<P2pPeer>,
    wfd_subelements: Option<Vec<u8>>,
}

/// Fake wireless backend with P2P and SoftAP support.
#[derive(Debug, Clone)]
pub struct FakeWlan {
    state: Arc<Mutex<State>>,
    events: Arc<EventBus<WlanEvent>>,
    p2p_events: Arc<EventBus<P2pEvent>>,
    ap_events: Arc<EventBus<ApEvent>>,
    p2p_capable: bool,
    ap_capable: bool,
    supported_security: Vec<ProfileSecurity>,
}

impl Default for FakeWlan {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeWlan {
    pub fn new() -> Self {
        let state = State {
            auto_associate: true,
            auto_ap: true,
            hardware_enabled: true,
            ..State::default()
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            events: Arc::new(EventBus::new()),
            p2p_events: Arc::new(EventBus::new()),
            ap_events: Arc::new(EventBus::new()),
            p2p_capable: true,
            ap_capable: true,
            supported_security: ProfileSecurity::ALL.to_vec(),
        }
    }

    /// A backend without Wi-Fi Direct.
    #[must_use]
    pub fn without_p2p(mut self) -> Self {
        self.p2p_capable = false;
        self
    }

    /// A backend without SoftAP.
    #[must_use]
    pub fn without_ap(mut self) -> Self {
        self.ap_capable = false;
        self
    }

    #[must_use]
    pub fn with_supported_security(mut self, security: Vec<ProfileSecurity>) -> Self {
        self.supported_security = security;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("fake wlan state")
    }

    pub fn add_device(&self, name: &str) -> InterfaceName {
        let name = InterfaceName::new(name).expect("valid name");
        let device = WlanDevice {
            name: name.clone(),
            address: Some(MacAddress::from_octets([2, 0, 0, 0, 0, 0xaa])),
            capabilities: Capabilities {
                station: true,
                p2p: self.p2p_capable,
                access_point: self.ap_capable,
            },
            supported_security: self.supported_security.clone(),
        };
        {
            let mut state = self.lock();
            state.devices.push(device.clone());
            state.links.insert(name.clone(), LinkStatus::Disconnected);
        }
        self.events.publish(&WlanEvent::DeviceAdded(device));
        name
    }

    pub fn remove_device(&self, name: &InterfaceName) {
        {
            let mut state = self.lock();
            state.devices.retain(|d| &d.name != name);
            state.links.remove(name);
        }
        self.events.publish(&WlanEvent::DeviceRemoved(name.clone()));
    }

    pub fn set_visible(&self, visible: Vec<Bss>) {
        self.lock().visible = visible;
    }

    pub fn set_password(&self, ssid: &Ssid, password: &str) {
        self.lock()
            .passwords
            .insert(ssid.clone(), password.to_owned());
    }

    pub fn set_auto_associate(&self, enabled: bool) {
        self.lock().auto_associate = enabled;
    }

    pub fn set_auto_ap(&self, enabled: bool) {
        self.lock().auto_ap = enabled;
    }

    pub fn wfd_subelements(&self) -> Option<Vec<u8>> {
        self.lock().wfd_subelements.clone()
    }

    pub fn set_hardware_enabled(&self, enabled: bool) {
        self.lock().hardware_enabled = enabled;
        self.events.publish(&WlanEvent::HardwareEnabled(enabled));
    }

    pub fn fail_next_connect(&self, error: PortError) {
        self.lock().fail_connect = Some(error);
    }

    pub fn fail_next_start_ap(&self, error: PortError) {
        self.lock().fail_start_ap = Some(error);
    }

    pub fn fail_next_start_group(&self, error: PortError) {
        self.lock().fail_start_group = Some(error);
    }

    pub fn fail_next_authorize_group(&self, error: PortError) {
        self.lock().fail_authorize_group = Some(error);
    }

    pub fn set_p2p_pin(&self, pin: Option<WpsPin>) {
        self.lock().p2p_pin = pin;
    }

    pub fn set_peers(&self, peers: Vec<P2pPeer>) {
        self.lock().peers = peers;
    }

    pub fn calls(&self) -> Vec<WlanCall> {
        self.lock().calls.clone()
    }

    pub fn link(&self, device: &InterfaceName) -> Option<LinkStatus> {
        self.lock().links.get(device).cloned()
    }

    /// Simulates the AP dropping the link.
    pub fn drop_link(&self, device: &InterfaceName) {
        self.set_link(device, LinkStatus::Disconnected);
    }

    pub fn set_link(&self, device: &InterfaceName, status: LinkStatus) {
        self.lock().links.insert(device.clone(), status.clone());
        self.events.publish(&WlanEvent::Link {
            device: device.clone(),
            status,
        });
    }

    pub fn emit(&self, event: &WlanEvent) {
        self.events.publish(event);
    }

    pub fn emit_p2p(&self, event: &P2pEvent) {
        self.p2p_events.publish(event);
    }

    pub fn emit_ap(&self, event: &ApEvent) {
        self.ap_events.publish(event);
    }

    fn record(&self, call: WlanCall) {
        self.lock().calls.push(call);
    }

    fn require_device(&self, device: &InterfaceName) -> PortResult<()> {
        if self.lock().devices.iter().any(|d| &d.name == device) {
            Ok(())
        } else {
            Err(PortError::NotFound(device.to_string()))
        }
    }
}

#[async_trait]
impl WlanProvider for FakeWlan {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn subscribe(&self) -> Subscription<WlanEvent> {
        self.events.subscribe()
    }

    async fn devices(&self) -> PortResult<Vec<WlanDevice>> {
        Ok(self.lock().devices.clone())
    }

    async fn hardware_enabled(&self) -> PortResult<bool> {
        Ok(self.lock().hardware_enabled)
    }

    async fn start_scan(&self, device: &InterfaceName) -> PortResult<()> {
        self.require_device(device)?;
        self.record(WlanCall::StartScan(device.clone()));
        let visible = self.lock().visible.clone();
        self.events.publish(&WlanEvent::ScanFinished {
            device: device.clone(),
            result: Ok(visible),
        });
        Ok(())
    }

    async fn connect(&self, device: &InterfaceName, request: ConnectRequest) -> PortResult<()> {
        self.require_device(device)?;
        if !self.supported_security.contains(&request.security) {
            return Err(PortError::NotSupported(format!(
                "fake does not support {}",
                request.security
            )));
        }
        self.record(WlanCall::Connect {
            device: device.clone(),
            ssid: request.ssid.clone(),
            security: request.security,
            secret: request
                .secrets
                .passphrase
                .as_ref()
                .map(|s| s.expose().to_owned()),
        });
        let (auto, expected, failure) = {
            let mut state = self.lock();
            (
                state.auto_associate,
                state.passwords.get(&request.ssid).cloned(),
                state.fail_connect.take(),
            )
        };
        if let Some(error) = failure {
            return Err(error);
        }
        self.set_link(device, LinkStatus::Connecting);
        if !auto {
            return Ok(());
        }
        let accepted = expected.is_none_or(|password| {
            request.secrets.passphrase.as_ref().map(Secret::expose) == Some(password.as_str())
        });
        if accepted {
            let bssid = request.bssid.or_else(|| {
                self.lock()
                    .visible
                    .iter()
                    .find(|bss| bss.ssid == request.ssid)
                    .map(|bss| bss.bssid)
            });
            self.set_link(
                device,
                LinkStatus::Connected {
                    ssid: request.ssid,
                    bssid,
                },
            );
        } else {
            self.events.publish(&WlanEvent::AuthFailed {
                device: device.clone(),
            });
        }
        Ok(())
    }

    async fn disconnect(&self, device: &InterfaceName) -> PortResult<()> {
        self.record(WlanCall::Disconnect(device.clone()));
        if self.lock().links.contains_key(device) {
            self.set_link(device, LinkStatus::Disconnected);
        }
        Ok(())
    }

    async fn link_status(&self, device: &InterfaceName) -> PortResult<LinkStatus> {
        self.lock()
            .links
            .get(device)
            .cloned()
            .ok_or_else(|| PortError::NotFound(device.to_string()))
    }

    async fn sweep(&self) -> PortResult<()> {
        self.record(WlanCall::Sweep);
        Ok(())
    }

    fn p2p(&self) -> Option<Arc<dyn P2pProvider>> {
        self.p2p_capable
            .then(|| Arc::new(self.clone()) as Arc<dyn P2pProvider>)
    }

    fn ap(&self) -> Option<Arc<dyn ApProvider>> {
        self.ap_capable
            .then(|| Arc::new(self.clone()) as Arc<dyn ApProvider>)
    }
}

#[async_trait]
impl ApProvider for FakeWlan {
    fn subscribe(&self) -> Subscription<ApEvent> {
        self.ap_events.subscribe()
    }

    async fn start_ap(&self, device: &InterfaceName, request: &ApStartRequest) -> PortResult<()> {
        self.require_device(device)?;
        self.record(WlanCall::StartAp {
            device: device.clone(),
            ssid: request.ssid.clone(),
            security: request.security,
            frequency: request.frequency,
        });
        if let Some(error) = self.lock().fail_start_ap.take() {
            return Err(error);
        }
        if self.lock().auto_ap {
            self.ap_events.publish(&ApEvent::Started {
                device: device.clone(),
                frequency: request.frequency.unwrap_or(2412),
            });
        }
        Ok(())
    }

    async fn stop_ap(&self, device: &InterfaceName) -> PortResult<()> {
        self.record(WlanCall::StopAp(device.clone()));
        self.ap_events.publish(&ApEvent::Stopped {
            device: device.clone(),
        });
        Ok(())
    }
}

#[async_trait]
impl P2pProvider for FakeWlan {
    fn subscribe(&self) -> Subscription<P2pEvent> {
        self.p2p_events.subscribe()
    }

    async fn configure(&self, device: &InterfaceName, config: &P2pDeviceConfig) -> PortResult<()> {
        self.lock()
            .wfd_subelements
            .clone_from(&config.wfd_subelements);
        self.record(WlanCall::P2pConfigure(
            device.clone(),
            config.device_name.clone(),
        ));
        Ok(())
    }

    async fn find(&self, device: &InterfaceName, _timeout: Duration) -> PortResult<()> {
        self.require_device(device)?;
        self.record(WlanCall::P2pFind(device.clone()));
        let peers = self.lock().peers.clone();
        for peer in peers {
            self.p2p_events.publish(&P2pEvent::PeerFound {
                device: device.clone(),
                peer,
            });
        }
        Ok(())
    }

    async fn stop_find(&self, device: &InterfaceName) -> PortResult<()> {
        self.record(WlanCall::P2pStopFind(device.clone()));
        self.p2p_events.publish(&P2pEvent::FindStopped {
            device: device.clone(),
        });
        Ok(())
    }

    async fn peers(&self, _device: &InterfaceName) -> PortResult<Vec<P2pPeer>> {
        Ok(self.lock().peers.clone())
    }

    async fn connect(
        &self,
        device: &InterfaceName,
        request: &P2pConnectRequest,
    ) -> PortResult<Option<WpsPin>> {
        self.require_device(device)?;
        self.record(WlanCall::P2pConnect {
            device: device.clone(),
            peer: request.peer,
            method: request.method.as_str(),
            go_intent: request.go_intent.get(),
            persistent: request.persistent,
        });
        if let Some(error) = self.lock().fail_connect.take() {
            return Err(error);
        }
        Ok(match request.method {
            WpsMethod::DisplayPin => self.lock().p2p_pin.clone(),
            WpsMethod::PushButton | WpsMethod::EnterPin(_) => None,
        })
    }

    async fn start_group(
        &self,
        device: &InterfaceName,
        request: &P2pGroupRequest,
    ) -> PortResult<()> {
        self.require_device(device)?;
        self.record(WlanCall::P2pStartGroup {
            device: device.clone(),
            frequency: request.frequency,
            persistent: request.persistent,
        });
        if let Some(error) = self.lock().fail_start_group.take() {
            return Err(error);
        }
        Ok(())
    }

    async fn connect_persistent(
        &self,
        device: &InterfaceName,
        request: &PersistentGroupConnect,
    ) -> PortResult<()> {
        self.require_device(device)?;
        self.record(WlanCall::P2pConnectPersistent {
            device: device.clone(),
            peer: request.peer,
            ssid: request.ssid.clone(),
        });
        Ok(())
    }

    async fn start_persistent_group(
        &self,
        device: &InterfaceName,
        ssid: &Ssid,
        _go_address: MacAddress,
        _psk: &Secret,
        _frequency: Option<u32>,
    ) -> PortResult<()> {
        self.require_device(device)?;
        self.record(WlanCall::P2pStartPersistentGroup {
            device: device.clone(),
            ssid: ssid.clone(),
        });
        Ok(())
    }

    async fn authorize_group(
        &self,
        device: &InterfaceName,
        group_if: &InterfaceName,
    ) -> PortResult<()> {
        self.record(WlanCall::P2pAuthorizeGroup(
            device.clone(),
            group_if.clone(),
        ));
        if let Some(error) = self.lock().fail_authorize_group.take() {
            return Err(error);
        }
        Ok(())
    }

    async fn cancel(&self, device: &InterfaceName) -> PortResult<()> {
        self.record(WlanCall::P2pCancel(device.clone()));
        Ok(())
    }

    async fn remove_group(
        &self,
        device: &InterfaceName,
        group_if: &InterfaceName,
    ) -> PortResult<()> {
        self.record(WlanCall::P2pRemoveGroup(device.clone(), group_if.clone()));
        Ok(())
    }
}

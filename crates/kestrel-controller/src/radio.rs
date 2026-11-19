// SPDX-License-Identifier: LGPL-2.1-or-later

//! Radio coordinator: owns all live state machines, enforces cross-radio
//! mutual exclusion, routes southbound and catalog events, and runs the
//! startup/shutdown ownership sweep.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kestrel_catalog::{Catalog, CatalogEvent};
use kestrel_machines::TimerToken;
use kestrel_machines::hotspot::{
    Hotspot, HotspotCommand, HotspotCommandKind, HotspotInput, HotspotTimer,
};
use kestrel_machines::p2p::{
    P2pSession, SessionCommand, SessionCommandKind, SessionInput, SessionState, SessionTimer,
};
use kestrel_machines::station::{
    Station, StationCommand, StationCommandKind, StationInput, StationState, StationTimer, policy,
};
use kestrel_model::{
    FailureReason, GoIntent, HotspotConfig as ModelHotspotConfig, InterfaceName, Ipv4Net,
    MacAddress, OnlineState, P2pGroupId, P2pPeer, P2pRole, ProfileId, Secret, SessionId, Ssid,
    WifiProfile, WpsMethod, WpsPin,
};
use kestrel_ports::Subscription;
use kestrel_ports::agent::{Agent, PeerRequest, PinDisplay};
use kestrel_ports::ap::{ApEvent, ApProvider};
use kestrel_ports::l3::{L3Event, L3Provider, L3Status};
use kestrel_ports::p2p::{P2pDeviceConfig, P2pEvent, P2pProvider, RequestedMethod};
use kestrel_ports::store::StateStore;
use kestrel_ports::wlan::{LinkStatus, WlanDevice, WlanEvent, WlanProvider};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::ControllerConfig;
use crate::control::ControllerHandle;
use crate::error::ControllerError;
use crate::executor::Executor;
use crate::hotspot::{self, HotspotExecContext, HotspotJob};
use crate::l3;
use crate::p2p::{self, SessionExecContext, SessionJob};
use crate::snapshot::{
    ControllerEvent, DeviceSnapshot, HotspotStatusSnapshot, ScanEntry, SessionSnapshot,
};
use crate::station::{self, HistoryJob, StationExecContext, StationJob};
use crate::subnet::SubnetAllocator;

type Reply<T> = oneshot::Sender<Result<T, ControllerError>>;

pub(crate) enum Request {
    Devices(oneshot::Sender<Vec<DeviceSnapshot>>),
    Device(InterfaceName, oneshot::Sender<Option<DeviceSnapshot>>),
    Scan(InterfaceName, Reply<()>),
    Connect(InterfaceName, ProfileId, Reply<()>),
    Disconnect(InterfaceName, Reply<()>),
    SetAutoconnect(InterfaceName, bool, Reply<()>),
    StartHotspot {
        device: InterfaceName,
        config: ModelHotspotConfig,
        secret: Option<Secret>,
        reply: Reply<()>,
    },
    StopHotspot(InterfaceName, Reply<()>),
    WirelessEnabled(oneshot::Sender<bool>),
    SetWirelessEnabled(bool, oneshot::Sender<()>),
    WirelessHardwareEnabled(oneshot::Sender<bool>),
    SetHardwareEnabled(bool, oneshot::Sender<()>),
    SetSuspended(bool, oneshot::Sender<()>),
    OnlineState(oneshot::Sender<OnlineState>),
    P2pFind(InterfaceName, Duration, Reply<()>),
    P2pStopFind(InterfaceName, Reply<()>),
    P2pSetWfdSubelements(InterfaceName, Option<Vec<u8>>, Reply<()>),
    Peers(InterfaceName, Reply<Vec<P2pPeer>>),
    P2pConnect {
        device: InterfaceName,
        peer: MacAddress,
        method: WpsMethod,
        go_intent: Option<GoIntent>,
        persistent: bool,
        reply: Reply<SessionId>,
    },
    P2pStartGroup {
        device: InterfaceName,
        frequency: Option<u32>,
        persistent: bool,
        reply: Reply<SessionId>,
    },
    P2pConnectPersistent {
        device: InterfaceName,
        group: P2pGroupId,
        peer: Option<MacAddress>,
        frequency: Option<u32>,
        reply: Reply<SessionId>,
    },
    P2pStartPersistentGroup {
        device: InterfaceName,
        group: P2pGroupId,
        frequency: Option<u32>,
        reply: Reply<SessionId>,
    },
    Sessions(oneshot::Sender<Vec<SessionSnapshot>>),
    Session(SessionId, oneshot::Sender<Option<SessionSnapshot>>),
    CloseSession(SessionId, Reply<()>),
    SetAgent(Option<Arc<dyn Agent>>, oneshot::Sender<()>),
}

pub(crate) enum Msg {
    Request(Box<Request>),
    StationTimer {
        device: InterfaceName,
        kind: StationTimer,
        token: TimerToken,
    },
    HotspotTimer {
        device: InterfaceName,
        kind: HotspotTimer,
        token: TimerToken,
    },
    SessionTimer {
        id: SessionId,
        kind: SessionTimer,
        token: TimerToken,
    },
    StationFailed {
        device: InterfaceName,
        command: StationCommandKind,
        reason: FailureReason,
    },
    HotspotFailed {
        device: InterfaceName,
        command: HotspotCommandKind,
        reason: FailureReason,
    },
    HotspotGateway {
        device: InterfaceName,
        gateway: Ipv4Net,
    },
    SessionFailed {
        id: SessionId,
        command: SessionCommandKind,
        reason: FailureReason,
    },
    SessionConnectAccepted {
        id: SessionId,
        pin: Option<WpsPin>,
    },
    SecretPromptFinished(ProfileId),
    IncomingAuthorized {
        device: InterfaceName,
        peer: MacAddress,
        method: Option<WpsMethod>,
    },
    IncomingInvitationAuthorized {
        device: InterfaceName,
        peer: MacAddress,
        group_id: P2pGroupId,
        accepted: bool,
    },
    P2pFindFailed(InterfaceName),
    Shutdown(oneshot::Sender<()>),
}

/// Southbound and radio-state ports driven by [`Controller`].
#[derive(Clone)]
pub struct ControllerPorts {
    pub wlan: Arc<dyn WlanProvider>,
    pub l3: Arc<dyn L3Provider>,
    pub state: Arc<dyn StateStore>,
}

impl std::fmt::Debug for ControllerPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControllerPorts")
            .field("wlan", &self.wlan.name())
            .field("l3", &self.l3.name())
            .finish_non_exhaustive()
    }
}

async fn sweep_on_start(ports: &ControllerPorts) {
    match ports.l3.sweep().await {
        Ok(swept) if !swept.is_empty() => {
            tracing::warn!(links = ?swept, "removed L3 bindings left by a previous run");
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "L3 sweep failed"),
    }
    if let Err(error) = ports.wlan.sweep().await {
        tracing::warn!(%error, "wireless sweep failed");
    }
}

fn build_exec_contexts(
    ports: &ControllerPorts,
    catalog: &Catalog,
    p2p: Option<&Arc<dyn P2pProvider>>,
    ap: Option<&Arc<dyn ApProvider>>,
    allocator: Arc<Mutex<SubnetAllocator>>,
    tx: &mpsc::UnboundedSender<Msg>,
) -> (DeviceExecContext, SessionExecContext) {
    let device_ctx = DeviceExecContext {
        station: StationExecContext {
            wlan: ports.wlan.clone(),
            l3: ports.l3.clone(),
            catalog: catalog.clone(),
            tx: tx.clone(),
        },
        hotspot: HotspotExecContext {
            ap: ap.cloned(),
            l3: ports.l3.clone(),
            allocator: allocator.clone(),
            tx: tx.clone(),
        },
    };
    let session_ctx = SessionExecContext {
        p2p: p2p.cloned(),
        l3: ports.l3.clone(),
        catalog: catalog.clone(),
        allocator,
        tx: tx.clone(),
    };
    (device_ctx, session_ctx)
}

/// Running live radio controller.
#[derive(Debug)]
pub struct Controller {
    handle: ControllerHandle,
    task: JoinHandle<()>,
}

impl Controller {
    /// Sweeps leftovers from a previous process, discovers wireless devices,
    /// and starts coordinating live station, hotspot, and P2P sessions.
    pub async fn start(
        config: ControllerConfig,
        ports: ControllerPorts,
        catalog: Catalog,
    ) -> Result<Self, ControllerError> {
        sweep_on_start(&ports).await;
        let persisted_enabled = match ports.state.wireless_enabled().await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "cannot read persisted wireless state; using config default");
                None
            }
        };
        let wireless_enabled = persisted_enabled.unwrap_or(config.wireless_enabled);

        // Subscribe before listing, so no device added in between is missed.
        let wlan_events = ports.wlan.subscribe();
        let p2p = ports.wlan.p2p();
        let p2p_events = p2p.as_ref().map(|p2p| p2p.subscribe());
        let ap = ports.wlan.ap();
        let ap_events = ap.as_ref().map(|ap| ap.subscribe());
        let l3_events = ports.l3.subscribe();
        let catalog_events = catalog.subscribe();
        let hardware_enabled = match config.hardware_enabled {
            Some(enabled) => enabled,
            None => ports.wlan.hardware_enabled().await.unwrap_or(true),
        };
        let devices = ports.wlan.devices().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "cannot list wireless devices yet");
            Vec::new()
        });

        let (tx, rx) = mpsc::unbounded_channel();
        let (events, _) = broadcast::channel(256);
        let allocator = Arc::new(Mutex::new(SubnetAllocator::new(config.subnet_pool.clone())));
        let (device_ctx, session_ctx) =
            build_exec_contexts(&ports, &catalog, p2p.as_ref(), ap.as_ref(), allocator, &tx);
        let state_exec = Executor::spawn(
            ports.state.clone(),
            |state: Arc<dyn StateStore>, (enabled, reply): (bool, oneshot::Sender<()>)| async move {
                if let Err(error) = state.set_wireless_enabled(enabled).await {
                    tracing::warn!(%error, "cannot persist wireless state");
                }
                let _ = reply.send(());
            },
        );
        let history_exec = Executor::spawn(catalog.clone(), station::execute_history_job);

        let mut coordinator = RadioCoordinator {
            config,
            ports,
            catalog: catalog.clone(),
            synced_profile_revision: catalog.profile_revision(),
            p2p,
            ap,
            device_ctx,
            session_ctx,
            state_exec: Some(state_exec),
            history_exec: Some(history_exec),
            tx: tx.clone(),
            events: events.clone(),
            devices: BTreeMap::new(),
            sessions: BTreeMap::new(),
            next_session: 1,
            wireless_enabled,
            hardware_enabled,
            suspended: false,
            agent: None,
            secret_requests: BTreeSet::new(),
            pending_peer_auth: BTreeSet::new(),
            retired: Vec::new(),
        };
        for device in devices {
            coordinator.device_added(device);
        }
        let task = tokio::spawn(coordinator.run(
            rx,
            wlan_events,
            p2p_events,
            ap_events,
            l3_events,
            catalog_events,
        ));
        Ok(Self {
            handle: ControllerHandle { tx, events },
            task,
        })
    }

    pub fn handle(&self) -> ControllerHandle {
        self.handle.clone()
    }

    /// Releases everything, sweeps the backends, and waits for the controller
    /// to stop.
    pub async fn shutdown(self) {
        let _ = self.handle.shutdown().await;
        let _ = self.task.await;
    }
}

#[derive(Debug)]
enum DeviceJob {
    Station(StationJob),
    Hotspot(HotspotJob),
}

#[derive(Clone)]
struct DeviceExecContext {
    station: StationExecContext,
    hotspot: HotspotExecContext,
}

async fn run_device_job(ctx: DeviceExecContext, job: DeviceJob) {
    match job {
        DeviceJob::Station(job) => station::execute_job(&ctx.station, job).await,
        DeviceJob::Hotspot(job) => hotspot::execute_job(&ctx.hotspot, job).await,
    }
}

async fn run_session_job(ctx: SessionExecContext, job: SessionJob) {
    p2p::execute_job(&ctx, job).await;
}

struct Device {
    info: WlanDevice,
    station: Station,
    hotspot: Hotspot,
    hotspot_secret: Option<Secret>,
    hotspot_gateway: Option<Ipv4Net>,
    exec: Executor<DeviceJob>,
    peers: BTreeMap<MacAddress, P2pPeer>,
    finding: bool,
    session: Option<SessionId>,
    l3: L3Status,
}

struct Session {
    device: InterfaceName,
    incoming: bool,
    machine: P2pSession,
    exec: Executor<SessionJob>,
}

struct RadioCoordinator {
    config: ControllerConfig,
    ports: ControllerPorts,
    catalog: Catalog,
    synced_profile_revision: u64,
    p2p: Option<Arc<dyn P2pProvider>>,
    ap: Option<Arc<dyn ApProvider>>,
    device_ctx: DeviceExecContext,
    session_ctx: SessionExecContext,
    state_exec: Option<Executor<(bool, oneshot::Sender<()>)>>,
    history_exec: Option<Executor<HistoryJob>>,
    tx: mpsc::UnboundedSender<Msg>,
    events: broadcast::Sender<ControllerEvent>,
    devices: BTreeMap<InterfaceName, Device>,
    sessions: BTreeMap<SessionId, Session>,
    next_session: u64,
    wireless_enabled: bool,
    hardware_enabled: bool,
    suspended: bool,
    agent: Option<Arc<dyn Agent>>,
    secret_requests: BTreeSet<ProfileId>,
    pending_peer_auth: BTreeSet<(InterfaceName, MacAddress)>,
    retired: Vec<JoinHandle<()>>,
}

async fn next<T>(subscription: &mut Option<Subscription<T>>) -> Option<T> {
    match subscription {
        Some(receiver) => {
            let item = receiver.recv().await;
            if item.is_none() {
                *subscription = None;
            }
            item
        }
        None => std::future::pending().await,
    }
}

fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl RadioCoordinator {
    async fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<Msg>,
        wlan: Subscription<WlanEvent>,
        p2p: Option<Subscription<P2pEvent>>,
        ap: Option<Subscription<ApEvent>>,
        l3: Subscription<L3Event>,
        mut catalog_events: broadcast::Receiver<CatalogEvent>,
    ) {
        let mut wlan = Some(wlan);
        let mut p2p = p2p;
        let mut ap = ap;
        let mut l3 = Some(l3);
        loop {
            tokio::select! {
                message = rx.recv() => match message {
                    Some(Msg::Shutdown(done)) => {
                        self.shutdown().await;
                        let _ = done.send(());
                        return;
                    }
                    Some(message) => self.on_message(message),
                    None => return,
                },
                Some(event) = next(&mut wlan) => self.on_wlan(event),
                Some(event) = next(&mut p2p) => self.on_p2p(event),
                Some(event) = next(&mut ap) => self.on_ap(event),
                Some(event) = next(&mut l3) => self.on_l3(event),
                result = catalog_events.recv() => match result {
                    Ok(event) => self.on_catalog(&event),
                    Err(broadcast::error::RecvError::Lagged(_)) => self.sync_profiles_if_stale(),
                    Err(broadcast::error::RecvError::Closed) => {}
                }
            }
        }
    }

    // ----- notifications and snapshots ---------------------------------

    fn emit(&self, event: ControllerEvent) {
        let _ = self.events.send(event);
    }

    const fn radio_blocked(&self) -> bool {
        !self.hardware_enabled || self.suspended
    }

    const fn radio_usable(&self) -> bool {
        self.wireless_enabled && self.hardware_enabled && !self.suspended
    }

    fn online_state(&self) -> OnlineState {
        if !self.radio_usable() {
            return OnlineState::Offline;
        }
        self.devices
            .values()
            .filter(|d| {
                matches!(
                    d.station.state(),
                    StationState::Connected { .. } | StationState::Reconnecting { .. }
                )
            })
            .map(|d| d.l3.online)
            .max()
            .unwrap_or(OnlineState::Offline)
    }

    fn device_snapshot(&self, device: &Device) -> DeviceSnapshot {
        let profiles = self.catalog.profiles();
        let by_id: BTreeMap<ProfileId, &WifiProfile> = profiles.iter().map(|p| (p.id, p)).collect();
        let station = device.station.snapshot();
        let hs = device.hotspot.snapshot();
        let active_profile = station
            .state
            .profile()
            .and_then(|id| by_id.get(&id).copied());
        let ssid = active_profile.map(|profile| profile.ssid.clone());
        let current_bss = match &station.state {
            StationState::Connected {
                bssid: Some(bssid), ..
            } => station.visible.iter().find(|bss| bss.bssid == *bssid),
            StationState::Connected { bssid: None, .. } => active_profile.and_then(|profile| {
                station
                    .visible
                    .iter()
                    .filter(|bss| policy::matches(profile, bss))
                    .max_by_key(|bss| bss.signal)
            }),
            _ => None,
        };
        let frequency = current_bss.map(|bss| bss.frequency).filter(|&f| f > 0);
        let security = if matches!(station.state, StationState::Connected { .. }) {
            current_bss
                .map(|bss| bss.security.as_str().to_owned())
                .or_else(|| active_profile.map(|p| p.security.as_str().to_owned()))
        } else {
            None
        };
        let scan_results = station
            .visible
            .iter()
            .map(|bss| ScanEntry {
                bss: bss.clone(),
                profile: policy::matching_profile(profiles.iter(), bss),
            })
            .collect();
        let hotspot_active = hs.state.is_active_or_starting();
        let hotspot = HotspotStatusSnapshot {
            state: hs.state.as_str(),
            ssid: hs.config.as_ref().map(|c| c.ssid.clone()),
            security: hs.config.as_ref().map(|c| c.security),
            frequency: hs.frequency,
            gateway: if hotspot_active {
                device.hotspot_gateway
            } else {
                None
            },
            leases: if hotspot_active {
                device.l3.leases.clone()
            } else {
                Vec::new()
            },
            clients: hs.clients,
            failure: hs.last_failure,
        };
        DeviceSnapshot {
            name: device.info.name.clone(),
            address: device.info.address,
            capabilities: device.info.capabilities,
            supported_security: device.info.supported_security.clone(),
            station,
            hotspot,
            p2p_finding: device.finding,
            ssid,
            frequency,
            security,
            scan_results,
            l3: device.l3.clone(),
        }
    }

    fn session_snapshot(id: SessionId, session: &Session) -> SessionSnapshot {
        let state = session.machine.state();
        SessionSnapshot {
            id,
            device: session.device.clone(),
            peer: session.machine.peer(),
            incoming: session.incoming,
            autonomous: session.machine.is_autonomous(),
            state: state.as_str(),
            role: state.role(),
            group_interface: state.group_interface().cloned(),
            peer_ip: match state {
                SessionState::Ready { peer_ip, .. } => *peer_ip,
                _ => None,
            },
            failure: match state {
                SessionState::Closed { reason } => reason.clone(),
                _ => None,
            },
        }
    }

    // ----- devices, stations, and hotspots ------------------------------

    fn device_added(&mut self, info: WlanDevice) {
        if self.devices.contains_key(&info.name) {
            return;
        }
        let name = info.name.clone();
        tracing::info!(device = %name, capabilities = ?info.capabilities, "wireless device added");
        if info.capabilities.p2p
            && let Some(p2p) = self.p2p.clone()
        {
            let config = P2pDeviceConfig {
                device_name: self.config.p2p_device_name.clone(),
                wfd_subelements: None,
            };
            let device = name.clone();
            tokio::spawn(async move {
                if let Err(error) = p2p.configure(&device, &config).await {
                    tracing::warn!(%device, %error, "cannot configure P2P device");
                }
            });
        }
        self.devices.insert(
            name.clone(),
            Device {
                info,
                station: Station::new(self.config.station.clone()),
                hotspot: Hotspot::new(self.config.hotspot.clone()),
                hotspot_secret: None,
                hotspot_gateway: None,
                exec: Executor::spawn(self.device_ctx.clone(), run_device_job),
                peers: BTreeMap::new(),
                finding: false,
                session: None,
                l3: L3Status::pending(),
            },
        );
        self.station_input(
            &name,
            StationInput::ProfilesChanged(self.catalog.profiles()),
        );
        self.station_input(&name, StationInput::SetSuspended(self.radio_blocked()));
        self.station_input(&name, StationInput::SetEnabled(self.wireless_enabled));
        if let Some(device) = self.devices.get(&name) {
            self.emit(ControllerEvent::DeviceAdded(self.device_snapshot(device)));
        }
    }

    fn push_retired(&mut self, handle: JoinHandle<()>) {
        self.retired.retain(|h| !h.is_finished());
        self.retired.push(handle);
    }

    fn device_removed(&mut self, name: &InterfaceName) {
        if !self.devices.contains_key(name) {
            return;
        }
        tracing::info!(device = %name, "wireless device removed");
        if let Some(id) = self.devices.get(name).and_then(|d| d.session) {
            self.session_input(id, SessionInput::DeviceUnavailable);
        }
        self.hotspot_input(name, HotspotInput::DeviceUnavailable);
        self.station_input(name, StationInput::SetEnabled(false));
        if let Some(device) = self.devices.remove(name) {
            self.push_retired(device.exec.retire());
        }
        self.emit(ControllerEvent::DeviceRemoved(name.clone()));
    }

    fn station_input(&mut self, name: &InterfaceName, input: StationInput) {
        let Some(device) = self.devices.get(name) else {
            return;
        };
        let before = device.station.snapshot();
        let before_snap = self.device_snapshot(device);
        let commands = self
            .devices
            .get_mut(name)
            .expect("device")
            .station
            .handle(now(), input);
        for command in commands {
            self.station_command(name, command);
        }
        if let Some(device) = self.devices.get_mut(name)
            && !device.hotspot.state().is_active_or_starting()
            && !matches!(
                device.station.state(),
                StationState::ConfiguringL3 { .. }
                    | StationState::Connected { .. }
                    | StationState::Reconnecting { .. }
            )
        {
            device.l3 = L3Status::pending();
        }
        if let Some(device) = self.devices.get(name) {
            let after = device.station.snapshot();
            let after_snap = self.device_snapshot(device);
            if after_snap != before_snap {
                self.emit(ControllerEvent::DeviceChanged(after_snap));
            }
            if let Some(job) =
                station::plan_transition(&self.catalog, name, &before, &after, unix_now())
                && let Some(exec) = &self.history_exec
            {
                exec.submit(job);
            }
        }
    }

    fn station_command(&mut self, device: &InterfaceName, command: StationCommand) {
        match command {
            StationCommand::RequestSecrets { profile } => self.request_secrets(device, profile),
            StationCommand::RecordConnected { profile } => {
                if let Some(job) =
                    station::plan_connected(&self.catalog, device, profile, unix_now())
                    && let Some(exec) = &self.history_exec
                {
                    exec.submit(job);
                }
            }
            other => {
                if let Some(job) = station::plan_job(&self.catalog, &self.tx, device, &other)
                    && let Some(entry) = self.devices.get(device)
                {
                    entry.exec.submit(DeviceJob::Station(job));
                }
            }
        }
    }

    fn request_secrets(&mut self, device: &InterfaceName, id: ProfileId) {
        let Ok(profile) = self.catalog.profile(id) else {
            return;
        };
        if !self.secret_requests.insert(id) {
            return;
        }
        let reason = self
            .devices
            .get(device)
            .and_then(|d| d.station.snapshot().last_failure)
            .unwrap_or(FailureReason::SecretsRequired);
        station::spawn_secret_prompt(
            self.catalog.clone(),
            self.agent.clone(),
            self.tx.clone(),
            self.config.agent_timeout,
            device.clone(),
            profile,
            reason,
        );
    }

    fn hotspot_input(&mut self, name: &InterfaceName, input: HotspotInput) {
        let Some(device) = self.devices.get(name) else {
            return;
        };
        let was_active = device.hotspot.state().is_active_or_starting();
        let before_snap = self.device_snapshot(device);
        let commands = self
            .devices
            .get_mut(name)
            .expect("device")
            .hotspot
            .handle(now(), input);
        for command in commands {
            let secret = if matches!(command, HotspotCommand::StartAp(_)) {
                self.devices
                    .get_mut(name)
                    .and_then(|d| d.hotspot_secret.take())
            } else {
                None
            };
            if let Some(job) = hotspot::plan_job(&self.tx, name, secret, command)
                && let Some(entry) = self.devices.get(name)
            {
                entry.exec.submit(DeviceJob::Hotspot(job));
            }
        }
        let stopped_now = if let Some(device) = self.devices.get_mut(name) {
            let is_active = device.hotspot.state().is_active_or_starting();
            if was_active && !is_active {
                device.hotspot_secret = None;
                device.hotspot_gateway = None;
                device.l3 = L3Status::pending();
                true
            } else {
                false
            }
        } else {
            false
        };
        if let Some(device) = self.devices.get(name) {
            let after_snap = self.device_snapshot(device);
            if after_snap != before_snap {
                self.emit(ControllerEvent::DeviceChanged(after_snap));
            }
        }
        if stopped_now {
            self.station_input(name, StationInput::SetHotspotActive(false));
        }
    }

    fn broadcast_station(&mut self, input: &StationInput) {
        let names: Vec<InterfaceName> = self.devices.keys().cloned().collect();
        for name in names {
            self.station_input(&name, input.clone());
        }
    }

    fn stop_all_hotspots(&mut self, unavailable: bool) {
        let names: Vec<InterfaceName> = self
            .devices
            .iter()
            .filter(|(_, d)| d.hotspot.state().is_active_or_starting())
            .map(|(n, _)| n.clone())
            .collect();
        let input = if unavailable {
            HotspotInput::DeviceUnavailable
        } else {
            HotspotInput::Stop
        };
        for name in names {
            self.hotspot_input(&name, input.clone());
        }
    }

    // ----- sessions ------------------------------------------------------

    fn check_session_slot(&self, device: &InterfaceName) -> Result<(), ControllerError> {
        if !self.radio_usable() {
            return Err(ControllerError::WirelessDisabled);
        }
        let entry = self
            .devices
            .get(device)
            .ok_or_else(|| ControllerError::NoSuchDevice(device.to_string()))?;
        if self.p2p.is_none() || !entry.info.capabilities.p2p {
            return Err(ControllerError::NotSupported(format!(
                "{device} does not support Wi-Fi Direct"
            )));
        }
        if entry.hotspot.state().is_active_or_starting() {
            return Err(ControllerError::Busy(format!(
                "{device} is running a hotspot"
            )));
        }
        if let Some(active) = entry.session {
            return Err(ControllerError::Busy(format!(
                "{device} already has P2P session {active}"
            )));
        }
        Ok(())
    }

    fn insert_session(
        &mut self,
        device: &InterfaceName,
        incoming: bool,
        machine: P2pSession,
        commands: Vec<SessionCommand>,
    ) -> SessionId {
        let id = SessionId(self.next_session);
        self.next_session += 1;
        let session = Session {
            device: device.clone(),
            incoming,
            machine,
            exec: Executor::spawn(self.session_ctx.clone(), run_session_job),
        };
        self.emit(ControllerEvent::SessionAdded(Self::session_snapshot(
            id, &session,
        )));
        self.sessions.insert(id, session);
        if let Some(entry) = self.devices.get_mut(device) {
            entry.session = Some(id);
        }
        for command in commands {
            self.session_command(id, command);
        }
        id
    }

    fn create_session(
        &mut self,
        device: &InterfaceName,
        peer: MacAddress,
        method: WpsMethod,
        go_intent: Option<GoIntent>,
        persistent: bool,
        incoming: bool,
    ) -> Result<SessionId, ControllerError> {
        self.check_session_slot(device)?;
        let (machine, commands) = P2pSession::start_with_options(
            self.config.session.clone(),
            peer,
            method,
            go_intent.unwrap_or(self.config.default_go_intent),
            persistent,
        );
        Ok(self.insert_session(device, incoming, machine, commands))
    }

    fn create_autonomous_session(
        &mut self,
        device: &InterfaceName,
        frequency: Option<u32>,
        persistent: bool,
    ) -> Result<SessionId, ControllerError> {
        self.check_session_slot(device)?;
        let (machine, commands) = P2pSession::start_autonomous_with_options(
            self.config.session.clone(),
            frequency,
            persistent,
        );
        Ok(self.insert_session(device, false, machine, commands))
    }

    fn create_persistent_session(
        &mut self,
        device: &InterfaceName,
        group_id: P2pGroupId,
        peer: Option<MacAddress>,
        frequency: Option<u32>,
        incoming: bool,
    ) -> Result<SessionId, ControllerError> {
        self.check_session_slot(device)?;
        let group = self.catalog.p2p_group(group_id)?;
        let target_peer = peer.or(group.peer).ok_or_else(|| {
            ControllerError::InvalidArgument(
                "peer address is required for this persistent group".to_owned(),
            )
        })?;
        let (machine, commands) = P2pSession::connect_persistent(
            self.config.session.clone(),
            group_id,
            target_peer,
            frequency,
        );
        Ok(self.insert_session(device, incoming, machine, commands))
    }

    fn create_persistent_autonomous_session(
        &mut self,
        device: &InterfaceName,
        group_id: P2pGroupId,
        frequency: Option<u32>,
    ) -> Result<SessionId, ControllerError> {
        self.check_session_slot(device)?;
        let group = self.catalog.p2p_group(group_id)?;
        if group.role != P2pRole::GroupOwner {
            return Err(ControllerError::InvalidArgument(
                "only group-owner persistent groups can be started autonomously".to_owned(),
            ));
        }
        let (machine, commands) =
            P2pSession::start_persistent_group(self.config.session.clone(), group_id, frequency);
        Ok(self.insert_session(device, false, machine, commands))
    }

    fn session_input(&mut self, id: SessionId, input: SessionInput) {
        let Some(session) = self.sessions.get_mut(&id) else {
            return;
        };
        let before = Self::session_snapshot(id, session);
        let commands = session.machine.handle(now(), input);
        for command in commands {
            self.session_command(id, command);
        }
        let Some(session) = self.sessions.get(&id) else {
            return;
        };
        let after = Self::session_snapshot(id, session);
        if after != before {
            tracing::info!(
                session = %id,
                state = after.state,
                role = ?after.role,
                failure = ?after.failure,
                "P2P session changed"
            );
            self.emit(ControllerEvent::SessionChanged(after));
        }
        if session.machine.is_closed()
            && let Some(session) = self.sessions.remove(&id)
        {
            if let Some(device) = self.devices.get_mut(&session.device)
                && device.session == Some(id)
            {
                device.session = None;
            }
            self.push_retired(session.exec.retire());
            self.emit(ControllerEvent::SessionRemoved(id));
        }
    }

    fn session_command(&mut self, id: SessionId, command: SessionCommand) {
        let Some(session) = self.sessions.get(&id) else {
            return;
        };
        let device = &session.device;
        if let Some(job) = p2p::plan_job(&self.catalog, &self.tx, id, device, command) {
            session.exec.submit(job);
        }
    }

    fn session_for_device(&self, device: &InterfaceName) -> Option<SessionId> {
        self.devices.get(device).and_then(|d| d.session)
    }

    // ----- inbound events ------------------------------------------------

    fn on_catalog(&mut self, event: &CatalogEvent) {
        match event {
            CatalogEvent::ProfileAdded(_)
            | CatalogEvent::ProfileChanged(_)
            | CatalogEvent::ProfileRemoved(_) => self.sync_profiles_if_stale(),
            CatalogEvent::SecretsChanged { profile, available } => {
                self.secret_requests.remove(profile);
                let input = if *available {
                    StationInput::SecretsUpdated(*profile)
                } else {
                    StationInput::SecretsUnavailable(*profile)
                };
                self.broadcast_station(&input);
            }
            CatalogEvent::CertAdded(_)
            | CatalogEvent::CertRemoved(_)
            | CatalogEvent::P2pGroupAdded(_)
            | CatalogEvent::P2pGroupChanged(_)
            | CatalogEvent::P2pGroupRemoved(_) => {}
        }
    }

    fn sync_profiles_if_stale(&mut self) {
        let rev = self.catalog.profile_revision();
        if rev != self.synced_profile_revision {
            self.synced_profile_revision = rev;
            let all = self.catalog.profiles();
            self.broadcast_station(&StationInput::ProfilesChanged(all));
        }
    }

    fn on_wlan(&mut self, event: WlanEvent) {
        match event {
            WlanEvent::DeviceAdded(device) => self.device_added(device),
            WlanEvent::DeviceRemoved(name) => self.device_removed(&name),
            WlanEvent::Link { device, status } => match status {
                LinkStatus::Connected { ssid, bssid } => {
                    self.station_input(&device, StationInput::LinkConnected { ssid, bssid });
                }
                LinkStatus::Disconnected => {
                    self.station_input(&device, StationInput::LinkDisconnected);
                }
                LinkStatus::Connecting => {}
            },
            WlanEvent::AuthFailed { device } => {
                self.station_input(&device, StationInput::AuthFailed);
            }
            WlanEvent::ConnectFailed { device, error } => {
                self.station_input(
                    &device,
                    StationInput::CommandFailed {
                        command: StationCommandKind::Associate,
                        reason: error.into(),
                    },
                );
            }
            WlanEvent::ScanFinished { device, result } => {
                self.station_input(
                    &device,
                    StationInput::ScanFinished(result.map_err(FailureReason::from)),
                );
            }
            WlanEvent::HardwareEnabled(enabled) => self.apply_hardware_enabled(enabled),
        }
    }

    fn on_ap(&mut self, event: ApEvent) {
        match event {
            ApEvent::Started { device, frequency } => {
                self.hotspot_input(&device, HotspotInput::ApStarted { frequency });
            }
            ApEvent::Stopped { device } => {
                self.hotspot_input(&device, HotspotInput::ApStopped);
            }
            ApEvent::Failed { device, error } => {
                self.hotspot_input(&device, HotspotInput::ApFailed(error.into()));
            }
            ApEvent::ClientConnected { device, mac } => {
                self.hotspot_input(&device, HotspotInput::ClientConnected(mac));
            }
            ApEvent::ClientDisconnected { device, mac } => {
                self.hotspot_input(&device, HotspotInput::ClientDisconnected(mac));
            }
        }
    }

    fn apply_hardware_enabled(&mut self, enabled: bool) {
        if enabled != self.hardware_enabled {
            tracing::info!(
                hardware_enabled = enabled,
                "wireless hardware rfkill changed"
            );
            self.hardware_enabled = enabled;
            self.emit(ControllerEvent::WirelessHardwareEnabled(enabled));
            if !enabled {
                let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
                for id in ids {
                    self.session_input(id, SessionInput::DeviceUnavailable);
                }
                self.stop_all_hotspots(true);
            }
            self.broadcast_station(&StationInput::SetSuspended(self.radio_blocked()));
        }
    }

    fn apply_suspended(&mut self, suspended: bool) {
        if suspended != self.suspended {
            tracing::info!(suspended, "system sleep state changed");
            self.suspended = suspended;
            if suspended {
                let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
                for id in ids {
                    self.session_input(id, SessionInput::DeviceUnavailable);
                }
                self.stop_all_hotspots(true);
            }
            self.broadcast_station(&StationInput::SetSuspended(self.radio_blocked()));
        }
    }

    fn on_p2p(&mut self, event: P2pEvent) {
        match event {
            P2pEvent::PeerFound { device, peer } => {
                if let Some(entry) = self.devices.get_mut(&device) {
                    let changed = entry.peers.get(&peer.address) != Some(&peer);
                    entry.peers.insert(peer.address, peer.clone());
                    if changed {
                        self.emit(ControllerEvent::PeerFound { device, peer });
                    }
                }
            }
            P2pEvent::PeerLost { device, address } => {
                if let Some(entry) = self.devices.get_mut(&device)
                    && entry.peers.remove(&address).is_some()
                {
                    self.emit(ControllerEvent::PeerLost { device, address });
                }
            }
            P2pEvent::FindStopped { device } => {
                if let Some(entry) = self.devices.get(&device)
                    && entry.finding
                {
                    self.devices.get_mut(&device).expect("device").finding = false;
                    let snapshot = self.device_snapshot(&self.devices[&device]);
                    self.emit(ControllerEvent::DeviceChanged(snapshot));
                }
            }
            P2pEvent::NegotiationRequest {
                device,
                peer,
                method,
            } => self.incoming_request(device, peer, method),
            P2pEvent::InvitationReceived {
                device,
                peer,
                go_address,
                persistent,
            } => self.incoming_invitation(device, peer, go_address, persistent),
            P2pEvent::GoNegotiationSucceeded { device, role } => {
                if let Some(id) = self.session_for_device(&device) {
                    self.session_input(id, SessionInput::GoNegotiationSucceeded { role });
                }
            }
            P2pEvent::GoNegotiationFailed { device, status } => {
                if let Some(id) = self.session_for_device(&device) {
                    self.session_input(id, SessionInput::GoNegotiationFailed { status });
                }
            }
            P2pEvent::PersistentGroupFormed {
                device,
                role,
                ssid,
                go_address,
                psk,
            } => self.save_formed_persistent_group(&device, role, ssid, go_address, psk),
            P2pEvent::GroupStarted {
                device,
                group_if,
                role,
            } => {
                if let Some(id) = self.session_for_device(&device) {
                    self.session_input(id, SessionInput::GroupStarted { group_if, role });
                } else if let Some(p2p) = self.p2p.clone() {
                    tracing::warn!(%device, %group_if, "removing a P2P group no session asked for");
                    tokio::spawn(async move {
                        let _ = p2p.remove_group(&device, &group_if).await;
                    });
                }
            }
            P2pEvent::GroupFinished { device, group_if } => {
                if let Some(id) = self.session_for_device(&device) {
                    self.session_input(id, SessionInput::GroupFinished { group_if });
                }
            }
            P2pEvent::WpsFailed { device } => {
                if let Some(id) = self.session_for_device(&device) {
                    self.session_input(id, SessionInput::WpsFailed);
                }
            }
        }
    }

    fn save_formed_persistent_group(
        &self,
        device: &InterfaceName,
        role: P2pRole,
        ssid: Ssid,
        go_address: MacAddress,
        psk: Secret,
    ) {
        let peer = self
            .session_for_device(device)
            .and_then(|id| self.sessions.get(&id))
            .and_then(|s| s.machine.peer());
        let fallback_name = peer
            .and_then(|addr| {
                self.devices
                    .get(device)
                    .and_then(|d| d.peers.get(&addr))
                    .map(|p| p.name.clone())
            })
            .unwrap_or_default();
        p2p::spawn_save_persistent_group(
            self.catalog.clone(),
            p2p::FormedGroup {
                role,
                ssid,
                go_address,
                peer,
                fallback_name,
                psk,
                at: unix_now(),
            },
        );
    }

    fn incoming_invitation(
        &mut self,
        device: InterfaceName,
        peer: MacAddress,
        go_address: MacAddress,
        persistent: bool,
    ) {
        if !persistent {
            return;
        }
        let Some(entry) = self.devices.get(&device) else {
            return;
        };
        if entry.session.is_some()
            || entry.hotspot.state().is_active_or_starting()
            || !self.radio_usable()
        {
            return;
        }
        let Some(group) = self.catalog.find_p2p_group_for_invitation(go_address, peer) else {
            return;
        };
        let Some(agent) = self.agent.clone() else {
            return;
        };
        if !self.pending_peer_auth.insert((device.clone(), peer)) {
            return;
        }
        let request = PeerRequest {
            device: device.clone(),
            peer,
            peer_name: entry.peers.get(&peer).map(|p| p.name.clone()),
            method: RequestedMethod::PushButton,
        };
        let tx = self.tx.clone();
        let timeout = self.config.agent_timeout;
        let group_id = group.id;
        tokio::spawn(async move {
            let accepted = tokio::time::timeout(timeout, agent.authorize_peer(request))
                .await
                .ok()
                .flatten()
                .is_some();
            let _ = tx.send(Msg::IncomingInvitationAuthorized {
                device,
                peer,
                group_id,
                accepted,
            });
        });
    }

    fn incoming_request(
        &mut self,
        device: InterfaceName,
        peer: MacAddress,
        method: RequestedMethod,
    ) {
        let Some(entry) = self.devices.get(&device) else {
            return;
        };
        if entry.session.is_some()
            || entry.hotspot.state().is_active_or_starting()
            || !self.radio_usable()
        {
            return;
        }
        let Some(agent) = self.agent.clone() else {
            tracing::info!(%device, %peer, "incoming P2P request declined: no agent registered");
            return;
        };
        if !self.pending_peer_auth.insert((device.clone(), peer)) {
            return;
        }
        let request = PeerRequest {
            device: device.clone(),
            peer,
            peer_name: entry.peers.get(&peer).map(|p| p.name.clone()),
            method,
        };
        let tx = self.tx.clone();
        let timeout = self.config.agent_timeout;
        tokio::spawn(async move {
            let method = if let Ok(method) =
                tokio::time::timeout(timeout, agent.authorize_peer(request)).await
            {
                method
            } else {
                tracing::warn!(%device, %peer, "agent did not authorize peer in time");
                None
            };
            let _ = tx.send(Msg::IncomingAuthorized {
                device,
                peer,
                method,
            });
        });
    }

    fn on_l3(&mut self, event: L3Event) {
        let L3Event { link, status } = event;
        if let Some(device) = self.devices.get(&link) {
            let before_snap = self.device_snapshot(device);
            self.devices.get_mut(&link).expect("device").l3 = status.clone();
            let after_snap = self.device_snapshot(&self.devices[&link]);
            if after_snap != before_snap {
                self.emit(ControllerEvent::DeviceChanged(after_snap));
            }
            if self.devices[&link].hotspot.state().is_active_or_starting() {
                match &status.phase {
                    kestrel_ports::l3::L3Phase::Ready => {
                        self.hotspot_input(&link, HotspotInput::L3Ready);
                    }
                    kestrel_ports::l3::L3Phase::Failed(detail) => {
                        self.hotspot_input(&link, HotspotInput::L3Failed(detail.clone()));
                    }
                    kestrel_ports::l3::L3Phase::Pending => {}
                }
            } else {
                match &status.phase {
                    kestrel_ports::l3::L3Phase::Ready => {
                        self.station_input(&link, StationInput::L3Ready);
                    }
                    kestrel_ports::l3::L3Phase::Failed(detail) => {
                        self.station_input(&link, StationInput::L3Failed(detail.clone()));
                    }
                    kestrel_ports::l3::L3Phase::Pending => {}
                }
            }
            return;
        }
        let session_id = self
            .sessions
            .iter()
            .find(|(_, s)| s.machine.state().group_interface() == Some(&link))
            .map(|(id, _)| *id);
        let Some(id) = session_id else {
            return;
        };
        match status.phase {
            kestrel_ports::l3::L3Phase::Ready => {
                let peer_ip = l3::peer_ip(self.sessions[&id].machine.state().role(), &status);
                self.session_input(id, SessionInput::L3Ready { peer_ip });
            }
            kestrel_ports::l3::L3Phase::Failed(detail) => {
                self.session_input(id, SessionInput::L3Failed(detail));
            }
            kestrel_ports::l3::L3Phase::Pending => {}
        }
    }

    // ----- messages & requests ------------------------------------------

    fn on_message(&mut self, message: Msg) {
        match message {
            Msg::Request(request) => self.on_request(*request),
            Msg::StationTimer {
                device,
                kind,
                token,
            } => self.station_input(&device, StationInput::Timer { kind, token }),
            Msg::HotspotTimer {
                device,
                kind,
                token,
            } => self.hotspot_input(&device, HotspotInput::Timer { kind, token }),
            Msg::SessionTimer { id, kind, token } => {
                self.session_input(id, SessionInput::Timer { kind, token });
            }
            Msg::StationFailed {
                device,
                command,
                reason,
            } => self.station_input(&device, StationInput::CommandFailed { command, reason }),
            Msg::HotspotFailed {
                device,
                command,
                reason,
            } => self.hotspot_input(&device, HotspotInput::CommandFailed { command, reason }),
            Msg::HotspotGateway { device, gateway } => {
                if let Some(entry) = self.devices.get(&device) {
                    let _ = entry;
                    self.devices
                        .get_mut(&device)
                        .expect("device")
                        .hotspot_gateway = Some(gateway);
                    let snap = self.device_snapshot(&self.devices[&device]);
                    self.emit(ControllerEvent::DeviceChanged(snap));
                }
            }
            Msg::SessionFailed {
                id,
                command,
                reason,
            } => self.session_input(id, SessionInput::CommandFailed { command, reason }),
            Msg::SessionConnectAccepted { id, pin } => {
                if let (Some(pin), Some(agent), Some(session)) =
                    (pin.clone(), self.agent.clone(), self.sessions.get(&id))
                    && let Some(peer) = session.machine.peer()
                {
                    let display = PinDisplay {
                        session: id,
                        peer,
                        pin,
                    };
                    tokio::spawn(async move { agent.display_pin(display).await });
                }
                self.session_input(id, SessionInput::ConnectAccepted { generated_pin: pin });
            }
            Msg::SecretPromptFinished(profile) => {
                self.secret_requests.remove(&profile);
            }
            Msg::IncomingAuthorized {
                device,
                peer,
                method,
            } => {
                self.pending_peer_auth.remove(&(device.clone(), peer));
                self.on_incoming_authorized(&device, peer, method);
            }
            Msg::IncomingInvitationAuthorized {
                device,
                peer,
                group_id,
                accepted,
            } => {
                self.pending_peer_auth.remove(&(device.clone(), peer));
                if accepted
                    && let Err(error) =
                        self.create_persistent_session(&device, group_id, Some(peer), None, true)
                {
                    tracing::warn!(%device, %peer, %error, "cannot accept persistent P2P invitation");
                }
            }
            Msg::P2pFindFailed(device) => {
                if let Some(entry) = self.devices.get_mut(&device)
                    && entry.finding
                {
                    entry.finding = false;
                    let snapshot = self.device_snapshot(&self.devices[&device]);
                    self.emit(ControllerEvent::DeviceChanged(snapshot));
                }
            }
            Msg::Shutdown(_) => unreachable!("handled in run"),
        }
    }

    fn on_incoming_authorized(
        &mut self,
        device: &InterfaceName,
        peer: MacAddress,
        method: Option<WpsMethod>,
    ) {
        if let Some(method) = method {
            if let Err(error) = self.create_session(device, peer, method, None, false, true) {
                tracing::warn!(%device, %peer, %error, "cannot accept P2P request");
            }
        } else {
            tracing::info!(%device, %peer, "P2P request rejected by the agent");
        }
    }

    fn on_request(&mut self, request: Request) {
        match request {
            Request::Devices(..)
            | Request::Device(..)
            | Request::Scan(..)
            | Request::Connect(..)
            | Request::Disconnect(..)
            | Request::SetAutoconnect(..)
            | Request::StartHotspot { .. }
            | Request::StopHotspot(..) => self.on_device_request(request),
            Request::WirelessEnabled(..)
            | Request::SetWirelessEnabled(..)
            | Request::WirelessHardwareEnabled(..)
            | Request::SetHardwareEnabled(..)
            | Request::SetSuspended(..)
            | Request::OnlineState(..)
            | Request::SetAgent(..) => self.on_radio_request(request),
            other => self.on_p2p_request(other),
        }
    }

    fn on_device_request(&mut self, request: Request) {
        match request {
            Request::Devices(reply) => {
                let _ = reply.send(
                    self.devices
                        .values()
                        .map(|device| self.device_snapshot(device))
                        .collect(),
                );
            }
            Request::Device(name, reply) => {
                let _ = reply.send(
                    self.devices
                        .get(&name)
                        .map(|device| self.device_snapshot(device)),
                );
            }
            Request::Scan(device, reply) => {
                let result = self.require_enabled_device(&device).and_then(|()| {
                    if self.devices[&device]
                        .hotspot
                        .state()
                        .is_active_or_starting()
                    {
                        return Err(ControllerError::Busy(format!(
                            "{device} is running a hotspot"
                        )));
                    }
                    Ok(())
                });
                if result.is_ok() {
                    self.station_input(&device, StationInput::Scan);
                }
                let _ = reply.send(result);
            }
            Request::Connect(device, profile, reply) => {
                self.sync_profiles_if_stale();
                let result = self.require_enabled_device(&device).and_then(|()| {
                    if self.devices[&device]
                        .hotspot
                        .state()
                        .is_active_or_starting()
                    {
                        return Err(ControllerError::Busy(format!(
                            "{device} is running a hotspot"
                        )));
                    }
                    self.catalog.profile(profile)?;
                    Ok(())
                });
                if result.is_ok() {
                    self.station_input(&device, StationInput::Connect(profile));
                }
                let _ = reply.send(result);
            }
            Request::Disconnect(device, reply) => {
                let result = self.require_enabled_device(&device);
                if result.is_ok() {
                    self.station_input(&device, StationInput::Disconnect);
                }
                let _ = reply.send(result);
            }
            Request::SetAutoconnect(device, enabled, reply) => {
                let result = self.require_enabled_device(&device);
                if result.is_ok() {
                    self.station_input(&device, StationInput::SetAutoconnect(enabled));
                }
                let _ = reply.send(result);
            }
            Request::StartHotspot {
                device,
                config,
                secret,
                reply,
            } => {
                let _ = reply.send(self.start_hotspot(&device, config, secret));
            }
            Request::StopHotspot(device, reply) => {
                let result = if self.devices.contains_key(&device) {
                    self.hotspot_input(&device, HotspotInput::Stop);
                    Ok(())
                } else {
                    Err(ControllerError::NoSuchDevice(device.to_string()))
                };
                let _ = reply.send(result);
            }
            _ => unreachable!("handled by on_request"),
        }
    }

    fn on_radio_request(&mut self, request: Request) {
        match request {
            Request::WirelessEnabled(reply) => {
                let _ = reply.send(self.wireless_enabled);
            }
            Request::SetWirelessEnabled(enabled, reply) => {
                self.handle_set_wireless_enabled(enabled, reply);
            }
            Request::WirelessHardwareEnabled(reply) => {
                let _ = reply.send(self.hardware_enabled);
            }
            Request::SetHardwareEnabled(enabled, reply) => {
                self.apply_hardware_enabled(enabled);
                let _ = reply.send(());
            }
            Request::SetSuspended(suspended, reply) => {
                self.apply_suspended(suspended);
                let _ = reply.send(());
            }
            Request::OnlineState(reply) => {
                let _ = reply.send(self.online_state());
            }
            Request::SetAgent(agent, reply) => {
                tracing::info!(registered = agent.is_some(), "agent changed");
                self.agent = agent;
                let _ = reply.send(());
            }
            _ => unreachable!("handled by on_request"),
        }
    }

    fn handle_set_wireless_enabled(&mut self, enabled: bool, reply: oneshot::Sender<()>) {
        if enabled == self.wireless_enabled {
            let _ = reply.send(());
            return;
        }
        tracing::info!(enabled, "wireless toggled");
        self.wireless_enabled = enabled;
        self.emit(ControllerEvent::WirelessEnabled(enabled));
        if !enabled {
            let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
            for id in ids {
                self.session_input(id, SessionInput::DeviceUnavailable);
            }
            self.stop_all_hotspots(true);
        }
        self.broadcast_station(&StationInput::SetEnabled(enabled));
        if let Some(exec) = &self.state_exec {
            exec.submit((enabled, reply));
        } else {
            let _ = reply.send(());
        }
    }

    fn on_p2p_request(&mut self, request: Request) {
        match request {
            Request::P2pFind(..)
            | Request::P2pStopFind(..)
            | Request::P2pSetWfdSubelements(..)
            | Request::Peers(..) => self.on_p2p_discovery_request(request),
            other => self.on_p2p_session_request(other),
        }
    }

    fn on_p2p_discovery_request(&mut self, request: Request) {
        match request {
            Request::P2pFind(device, timeout, reply) => match self.require_p2p_device(&device) {
                Ok(p2p) => {
                    if let Some(entry) = self.devices.get_mut(&device) {
                        entry.finding = true;
                        let snapshot = self.device_snapshot(&self.devices[&device]);
                        self.emit(ControllerEvent::DeviceChanged(snapshot));
                    }
                    let tx = self.tx.clone();
                    tokio::spawn(async move {
                        let result = p2p
                            .find(&device, timeout)
                            .await
                            .map_err(ControllerError::Backend);
                        if result.is_err() {
                            let _ = tx.send(Msg::P2pFindFailed(device));
                        }
                        let _ = reply.send(result);
                    });
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Request::P2pStopFind(device, reply) => match self.require_p2p_device(&device) {
                Ok(p2p) => {
                    tokio::spawn(async move {
                        let result = p2p
                            .stop_find(&device)
                            .await
                            .map_err(ControllerError::Backend);
                        let _ = reply.send(result);
                    });
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Request::P2pSetWfdSubelements(device, wfd_subelements, reply) => {
                match self.require_p2p_device(&device) {
                    Ok(p2p) => {
                        let config = P2pDeviceConfig {
                            device_name: self.config.p2p_device_name.clone(),
                            wfd_subelements,
                        };
                        tokio::spawn(async move {
                            let result = p2p
                                .configure(&device, &config)
                                .await
                                .map_err(ControllerError::Backend);
                            let _ = reply.send(result);
                        });
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Request::Peers(device, reply) => {
                let result = self
                    .require_p2p_device(&device)
                    .map(|_| self.devices[&device].peers.values().cloned().collect());
                let _ = reply.send(result);
            }
            _ => unreachable!("handled by on_p2p_request"),
        }
    }

    fn on_p2p_session_request(&mut self, request: Request) {
        match request {
            Request::P2pConnect {
                device,
                peer,
                method,
                go_intent,
                persistent,
                reply,
            } => {
                let _ = reply
                    .send(self.create_session(&device, peer, method, go_intent, persistent, false));
            }
            Request::P2pStartGroup {
                device,
                frequency,
                persistent,
                reply,
            } => {
                let _ = reply.send(self.create_autonomous_session(&device, frequency, persistent));
            }
            Request::P2pConnectPersistent {
                device,
                group,
                peer,
                frequency,
                reply,
            } => {
                let _ = reply
                    .send(self.create_persistent_session(&device, group, peer, frequency, false));
            }
            Request::P2pStartPersistentGroup {
                device,
                group,
                frequency,
                reply,
            } => {
                let _ = reply
                    .send(self.create_persistent_autonomous_session(&device, group, frequency));
            }
            Request::Sessions(reply) => {
                let _ = reply.send(
                    self.sessions
                        .iter()
                        .map(|(id, s)| Self::session_snapshot(*id, s))
                        .collect(),
                );
            }
            Request::Session(id, reply) => {
                let _ = reply.send(
                    self.sessions
                        .get(&id)
                        .map(|s| Self::session_snapshot(id, s)),
                );
            }
            Request::CloseSession(id, reply) => {
                if self.sessions.contains_key(&id) {
                    self.session_input(id, SessionInput::Close);
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = reply.send(Err(ControllerError::NoSuchSession(id)));
                }
            }
            _ => unreachable!("handled by on_p2p_request"),
        }
    }

    fn start_hotspot(
        &mut self,
        device: &InterfaceName,
        config: ModelHotspotConfig,
        secret: Option<Secret>,
    ) -> Result<(), ControllerError> {
        self.require_enabled_device(device)?;
        let entry = &self.devices[device];
        if self.ap.is_none() || !entry.info.capabilities.access_point {
            return Err(ControllerError::NotSupported(format!(
                "{device} does not support SoftAP"
            )));
        }
        if let Some(session) = entry.session {
            return Err(ControllerError::Busy(format!(
                "{device} has active P2P session {session}"
            )));
        }
        if entry.hotspot.state().is_active_or_starting() {
            return Err(ControllerError::Busy(format!(
                "{device} already has an active hotspot"
            )));
        }
        self.devices.get_mut(device).expect("device").hotspot_secret = secret;
        self.station_input(device, StationInput::SetHotspotActive(true));
        self.hotspot_input(device, HotspotInput::Start(config));
        Ok(())
    }

    fn require_enabled_device(&self, device: &InterfaceName) -> Result<(), ControllerError> {
        if !self.devices.contains_key(device) {
            return Err(ControllerError::NoSuchDevice(device.to_string()));
        }
        if !self.radio_usable() {
            return Err(ControllerError::WirelessDisabled);
        }
        Ok(())
    }

    fn require_p2p_device(
        &self,
        device: &InterfaceName,
    ) -> Result<Arc<dyn P2pProvider>, ControllerError> {
        self.require_enabled_device(device)?;
        let capable = self.devices[device].info.capabilities.p2p;
        match (&self.p2p, capable) {
            (Some(p2p), true) => Ok(p2p.clone()),
            _ => Err(ControllerError::NotSupported(format!(
                "{device} does not support Wi-Fi Direct"
            ))),
        }
    }

    async fn shutdown(&mut self) {
        const EXECUTOR_SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);
        const SWEEP_SHUTDOWN_BUDGET: Duration = Duration::from_secs(5);

        tracing::info!("shutting down: releasing all resources");
        let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for id in ids {
            self.session_input(id, SessionInput::Close);
        }
        self.stop_all_hotspots(false);
        self.broadcast_station(&StationInput::SetEnabled(false));
        for (_, device) in std::mem::take(&mut self.devices) {
            self.retired.push(device.exec.retire());
        }
        for (_, session) in std::mem::take(&mut self.sessions) {
            self.retired.push(session.exec.retire());
        }
        if let Some(exec) = self.state_exec.take() {
            self.retired.push(exec.retire());
        }
        if let Some(exec) = self.history_exec.take() {
            self.retired.push(exec.retire());
        }
        let mut tasks = std::mem::take(&mut self.retired);
        let deadline = tokio::time::Instant::now() + EXECUTOR_SHUTDOWN_BUDGET;
        let mut aborts: Vec<tokio::task::AbortHandle> =
            tasks.iter().map(JoinHandle::abort_handle).collect();
        let drain_all = async {
            for task in &mut tasks {
                let _ = task.await;
            }
        };
        if tokio::time::timeout_at(deadline, drain_all).await.is_err() {
            tracing::warn!("shutdown executor drain timed out; aborting wedged tasks");
            for handle in aborts.drain(..) {
                handle.abort();
            }
        }
        match tokio::time::timeout(SWEEP_SHUTDOWN_BUDGET, self.ports.l3.sweep()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!(%error, "L3 sweep at shutdown failed"),
            Err(_) => tracing::warn!("L3 sweep at shutdown timed out"),
        }
        match tokio::time::timeout(SWEEP_SHUTDOWN_BUDGET, self.ports.wlan.sweep()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "wireless sweep at shutdown failed"),
            Err(_) => tracing::warn!("wireless sweep at shutdown timed out"),
        }
    }
}

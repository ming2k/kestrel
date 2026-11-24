// SPDX-License-Identifier: LGPL-2.1-or-later

//! iwd as Kestrel's wireless provider (station and SoftAP).
//!
//! Event-driven like the `wpa_supplicant` adapter: `InterfacesAdded/Removed`
//! track devices, `PropertiesChanged` on `Station` tracks the link and scan
//! completion, and the daemon appearing or vanishing on the bus adds or
//! removes every device.
//!
//! **Credentials** reach iwd only through Kestrel's registered agent, for
//! the one association in progress.
//!
//! **Statelessness.** iwd persists a `KnownNetwork` after every successful
//! connection, by design. The adapter marks each network it provisions
//! with `AutoConnect=false`, so iwd never acts on it alone. It forgets the
//! network on disconnect, and `sweep` forgets every known network still
//! marked that way. Networks an administrator provisions with autoconnect
//! enabled are never touched.
//!
//! **Limits.** iwd reports WPA2 and WPA3 personal networks as one type
//! (`psk`) and negotiates SAE by itself. It cannot be told to refuse a
//! downgrade, so WPA3-only and OWE-only profiles are rejected as not
//! supported rather than silently weakened. Wi-Fi Direct is not offered
//! through this adapter. iwd must run with `EnableNetworkConfiguration=false`
//! so that L3 stays with the L3 provider.

mod agent;
#[cfg(feature = "testkit")]
pub mod testkit;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use kestrel_model::{
    Bss, HotspotSecurity, InterfaceName, MacAddress, ProfileSecurity, Secret, Security, Ssid,
};
use kestrel_ports::ap::{ApEvent, ApProvider, ApStartRequest};
use kestrel_ports::wlan::{
    Capabilities, ConnectRequest, LinkStatus, WlanDevice, WlanEvent, WlanProvider,
};
use kestrel_ports::{EventBus, PortError, PortResult, Subscription};
use zbus::message::Type;
use zbus::proxy::CacheProperties;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

pub(crate) const SERVICE: &str = "net.connman.iwd";
const MANAGER_PATH: &str = "/net/connman/iwd";
const ADAPTER: &str = "net.connman.iwd.Adapter";
const DEVICE: &str = "net.connman.iwd.Device";
const STATION: &str = "net.connman.iwd.Station";
const ACCESS_POINT: &str = "net.connman.iwd.AccessPoint";
const NETWORK: &str = "net.connman.iwd.Network";
const KNOWN_NETWORK: &str = "net.connman.iwd.KnownNetwork";
const BSS: &str = "net.connman.iwd.BasicServiceSet";
const AGENT_MANAGER: &str = "net.connman.iwd.AgentManager";
const OBJECT_MANAGER: &str = "org.freedesktop.DBus.ObjectManager";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
pub(crate) const AGENT_PATH: &str = "/com/hihusky/Kestrel/iwd/agent";

const SUPPORTED_SECURITY: [ProfileSecurity; 2] =
    [ProfileSecurity::Open, ProfileSecurity::WpaPersonal];
const SIGNAL_QUEUE_CAPACITY: usize = 2048;

type Props = HashMap<String, OwnedVariant>;
type Objects = HashMap<OwnedObjectPath, HashMap<String, Props>>;

/// One association in progress on a station.
#[derive(Debug)]
pub(crate) struct Pending {
    pub(crate) attempt_id: u64,
    pub(crate) secret: Option<Secret>,
    /// Set when iwd asked the agent: a later failure is then an
    /// authentication failure.
    pub(crate) asked: bool,
}

#[derive(Debug, Default)]
pub(crate) struct State {
    /// Current unique D-Bus owner name of `net.connman.iwd`. Only this peer
    /// may invoke `net.connman.iwd.Agent.RequestPassphrase`.
    pub(crate) iwd_owner: Option<String>,
    /// Station/AP device object path to interface name.
    stations: HashMap<OwnedObjectPath, InterfaceName>,
    /// Adapter object path to whether `"ap"` is in `SupportedModes`.
    adapter_ap: HashMap<OwnedObjectPath, bool>,
    /// Active AP devices for unexpected-stop reporting.
    ap_active: HashSet<InterfaceName>,
    /// Pre-existing admin known networks `(name, type)` that Kestrel must not
    /// mark or forget on disconnect.
    preexisting_known: HashSet<(String, String)>,
    links: BTreeMap<InterfaceName, LinkStatus>,
    scanning: HashMap<OwnedObjectPath, bool>,
    next_attempt: u64,
    pub(crate) pending: HashMap<OwnedObjectPath, Pending>,
}

#[derive(Debug)]
pub(crate) struct Inner {
    connection: zbus::Connection,
    pub(crate) state: Mutex<State>,
    events: EventBus<WlanEvent>,
    ap_events: EventBus<ApEvent>,
    monitor_tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let tasks = self
            .monitor_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for task in tasks.iter() {
            task.abort();
        }
    }
}

/// The iwd provider.
#[derive(Debug, Clone)]
pub struct Iwd {
    inner: Arc<Inner>,
}

impl fmt::Display for Iwd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("iwd")
    }
}

fn prop<T: TryFrom<OwnedVariant>>(props: &Props, key: &str) -> Option<T> {
    props.get(key)?.try_clone().ok()?.try_into().ok()
}

impl Iwd {
    /// Connects, registers the agent, starts the monitor, and discovers
    /// devices. Succeeds even if iwd is not running yet.
    pub async fn new(connection: zbus::Connection) -> PortResult<Self> {
        let inner = Arc::new(Inner {
            connection,
            state: Mutex::new(State::default()),
            events: EventBus::new(),
            ap_events: EventBus::new(),
            monitor_tasks: Mutex::new(Vec::new()),
        });
        let this = Self { inner };
        agent::serve(&this.inner.connection, Arc::downgrade(&this.inner)).await?;
        this.start_monitor().await?;
        if let Err(error) = this.attach().await {
            tracing::warn!(%error, "iwd is not available yet");
        }
        Ok(this)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn proxy(&self, path: &str, interface: &'static str) -> PortResult<zbus::Proxy<'static>> {
        zbus::proxy::Builder::new(&self.inner.connection)
            .destination(SERVICE)
            .path(path.to_owned())
            .interface(interface)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(dbus_error)
    }

    async fn objects(&self) -> PortResult<Objects> {
        let proxy = self.proxy("/", OBJECT_MANAGER).await?;
        let reply = proxy
            .call_method("GetManagedObjects", &())
            .await
            .map_err(dbus_error)?;
        reply.body().deserialize().map_err(dbus_error)
    }

    /// Registers the agent and discovers stations (startup, or iwd
    /// appearing on the bus).
    async fn attach(&self) -> PortResult<()> {
        if let Ok(dbus) = zbus::fdo::DBusProxy::new(&self.inner.connection).await
            && let Ok(name) = zbus::names::BusName::try_from(SERVICE)
            && let Ok(owner) = dbus.get_name_owner(name).await
        {
            self.lock().iwd_owner = Some(owner.as_str().to_owned());
        }
        let manager = self.proxy(MANAGER_PATH, AGENT_MANAGER).await?;
        let agent = OwnedObjectPath::try_from(AGENT_PATH).expect("valid path");
        if let Err(error) = manager.call_method("RegisterAgent", &(agent,)).await
            && !error.to_string().contains("AlreadyExists")
        {
            return Err(dbus_error(error));
        }
        let objects = self.objects().await?;
        self.record_adapters(&objects);
        for (path, interfaces) in &objects {
            self.object_added(path, interfaces);
        }
        Ok(())
    }

    fn record_adapters(&self, objects: &Objects) {
        let mut state = self.lock();
        for (path, interfaces) in objects {
            if let Some(adapter) = interfaces.get(ADAPTER) {
                let ap = prop::<Vec<String>>(adapter, "SupportedModes")
                    .is_none_or(|modes| modes.iter().any(|m| m.eq_ignore_ascii_case("ap")));
                state.adapter_ap.insert(path.clone(), ap);
            }
        }
    }

    fn adapter_supports_ap(state: &State, device_path: &OwnedObjectPath, device: &Props) -> bool {
        if let Some(adapter_path) = prop::<OwnedObjectPath>(device, "Adapter")
            && let Some(&ap) = state.adapter_ap.get(&adapter_path)
        {
            return ap;
        }
        if let Some((_, &ap)) = state.adapter_ap.iter().find(|(path, _)| {
            device_path
                .as_str()
                .starts_with(&format!("{}/", path.as_str()))
        }) {
            return ap;
        }
        true
    }

    fn object_added(&self, path: &OwnedObjectPath, interfaces: &HashMap<String, Props>) {
        if let Some(adapter) = interfaces.get(ADAPTER) {
            let ap = prop::<Vec<String>>(adapter, "SupportedModes")
                .is_none_or(|modes| modes.iter().any(|m| m.eq_ignore_ascii_case("ap")));
            self.lock().adapter_ap.insert(path.clone(), ap);
        }
        let Some(device) = interfaces.get(DEVICE) else {
            return;
        };
        let has_station = interfaces.contains_key(STATION);
        let has_ap = interfaces.contains_key(ACCESS_POINT);
        if !has_station && !has_ap {
            return;
        }
        let Some(name) = prop::<String>(device, "Name").and_then(|n| InterfaceName::new(n).ok())
        else {
            return;
        };
        let address = prop::<String>(device, "Address").and_then(|a| MacAddress::parse(&a).ok());
        let link = interfaces
            .get(STATION)
            .and_then(|station| prop::<String>(station, "State"))
            .map_or(LinkStatus::Disconnected, |s| {
                if s == "disconnected" {
                    LinkStatus::Disconnected
                } else {
                    LinkStatus::Connecting
                }
            });
        let access_point = {
            let mut state = self.lock();
            if state.stations.insert(path.clone(), name.clone()).is_some() {
                return;
            }
            state.links.insert(name.clone(), link);
            Self::adapter_supports_ap(&state, path, device)
        };
        self.inner
            .events
            .publish(&WlanEvent::DeviceAdded(WlanDevice {
                name,
                address,
                capabilities: Capabilities {
                    station: true,
                    p2p: false,
                    access_point,
                },
                supported_security: SUPPORTED_SECURITY.to_vec(),
            }));
        if has_station {
            let this = self.clone();
            let path = path.clone();
            tokio::spawn(async move { this.refresh_link(&path).await });
        }
    }

    fn object_removed(&self, path: &OwnedObjectPath) {
        let (removed, stopped_ap) = {
            let mut state = self.lock();
            let removed = state.stations.remove(path);
            let mut stopped_ap = None;
            if let Some(name) = &removed {
                state.links.remove(name);
                state.pending.remove(path);
                state.scanning.remove(path);
                if state.ap_active.remove(name) {
                    stopped_ap = Some(name.clone());
                }
            }
            (removed, stopped_ap)
        };
        if let Some(device) = stopped_ap {
            self.inner.ap_events.publish(&ApEvent::Stopped { device });
        }
        if let Some(name) = removed {
            self.inner.events.publish(&WlanEvent::DeviceRemoved(name));
        }
    }

    fn vanished(&self) {
        let paths: Vec<OwnedObjectPath> = self.lock().stations.keys().cloned().collect();
        for path in paths {
            self.object_removed(&path);
        }
        let mut state = self.lock();
        state.iwd_owner = None;
        state.adapter_ap.clear();
        state.ap_active.clear();
        state.preexisting_known.clear();
    }

    fn station_path(&self, device: &InterfaceName) -> PortResult<OwnedObjectPath> {
        self.lock()
            .stations
            .iter()
            .find(|(_, name)| *name == device)
            .map(|(path, _)| path.clone())
            .ok_or_else(|| PortError::NotFound(device.to_string()))
    }

    async fn read_link(&self, station: &OwnedObjectPath) -> PortResult<LinkStatus> {
        let proxy = self.proxy(station.as_str(), STATION).await?;
        let state: String = proxy.get_property("State").await.map_err(dbus_error)?;
        Ok(match state.as_str() {
            "connected" => {
                let network: OwnedObjectPath = proxy
                    .get_property("ConnectedNetwork")
                    .await
                    .map_err(dbus_error)?;
                let name: String = self
                    .proxy(network.as_str(), NETWORK)
                    .await?
                    .get_property("Name")
                    .await
                    .map_err(dbus_error)?;
                let ssid = Ssid::new(name).map_err(|e| PortError::Backend(e.to_string()))?;
                let bssid = match proxy
                    .get_property::<OwnedObjectPath>("ConnectedAccessPoint")
                    .await
                {
                    Ok(bss) => self.bss_address(&bss).await,
                    Err(_) => None,
                };
                LinkStatus::Connected { ssid, bssid }
            }
            "disconnected" => LinkStatus::Disconnected,
            _ => LinkStatus::Connecting,
        })
    }

    async fn bss_address(&self, bss: &OwnedObjectPath) -> Option<MacAddress> {
        let proxy = self.proxy(bss.as_str(), BSS).await.ok()?;
        let address: String = proxy.get_property("Address").await.ok()?;
        MacAddress::parse(&address).ok()
    }

    async fn refresh_link(&self, station: &OwnedObjectPath) {
        let Some(name) = self.lock().stations.get(station).cloned() else {
            return;
        };
        let Ok(status) = self.read_link(station).await else {
            return;
        };
        let changed = {
            let mut state = self.lock();
            if state.links.get(&name) == Some(&status) {
                false
            } else {
                state.links.insert(name.clone(), status.clone());
                true
            }
        };
        if changed {
            if matches!(status, LinkStatus::Connected { .. }) {
                self.lock().pending.remove(station);
            }
            self.inner.events.publish(&WlanEvent::Link {
                device: name,
                status,
            });
        }
    }

    async fn scan_results(&self, station: &OwnedObjectPath) -> PortResult<Vec<Bss>> {
        let proxy = self.proxy(station.as_str(), STATION).await?;
        let reply = proxy
            .call_method("GetOrderedNetworks", &())
            .await
            .map_err(dbus_error)?;
        let ordered: Vec<(OwnedObjectPath, i16)> =
            reply.body().deserialize().map_err(dbus_error)?;
        let objects = self.objects().await?;
        let mut results = Vec::new();
        for (network, signal) in ordered {
            let Some(props) = objects.get(&network).and_then(|i| i.get(NETWORK)) else {
                continue;
            };
            let Some(ssid) = prop::<String>(props, "Name").and_then(|n| Ssid::new(n).ok()) else {
                continue;
            };
            let bss_props = prop::<Vec<OwnedObjectPath>>(props, "ExtendedServiceSet")
                .and_then(|set| set.first().cloned())
                .and_then(|bss| objects.get(&bss).and_then(|i| i.get(BSS)));
            let bssid = bss_props
                .and_then(|bss| prop::<String>(bss, "Address"))
                .and_then(|a| MacAddress::parse(&a).ok())
                .unwrap_or(MacAddress::from_octets([0; 6]));
            let frequency = bss_props
                .and_then(|bss| prop::<u32>(bss, "Frequency"))
                .unwrap_or(0);
            results.push(Bss {
                ssid,
                bssid,
                frequency,
                // iwd reports 100 * dBm.
                signal: signal / 100,
                security: map_security(prop::<String>(props, "Type").as_deref()),
            });
        }
        Ok(results)
    }

    async fn find_network(
        &self,
        station: &OwnedObjectPath,
        ssid: &Ssid,
        expected_type: &str,
    ) -> PortResult<Option<OwnedObjectPath>> {
        let objects = self.objects().await?;
        let name = ssid.to_string_lossy();
        let prefix = format!("{}/", station.as_str());
        Ok(objects
            .iter()
            .filter(|(path, _)| path.as_str().starts_with(&prefix))
            .find(|(_, interfaces)| {
                interfaces.get(NETWORK).is_some_and(|props| {
                    prop::<String>(props, "Name").as_deref() == Some(name.as_str())
                        && prop::<String>(props, "Type").as_deref() == Some(expected_type)
                })
            })
            .map(|(path, _)| path.clone()))
    }

    /// Forgets known networks Kestrel provisioned (`AutoConnect=false`),
    /// never touching networks explicitly preserved as pre-existing.
    async fn forget_owned(&self, only_ssid: Option<&Ssid>) -> PortResult<()> {
        let objects = self.objects().await?;
        let preexisting = self.lock().preexisting_known.clone();
        for (path, interfaces) in &objects {
            let Some(known) = interfaces.get(KNOWN_NETWORK) else {
                continue;
            };
            if prop::<bool>(known, "AutoConnect") != Some(false) {
                continue;
            }
            let name = prop::<String>(known, "Name").unwrap_or_default();
            let kind = prop::<String>(known, "Type").unwrap_or_default();
            if preexisting.contains(&(name.clone(), kind)) {
                continue;
            }
            if let Some(ssid) = only_ssid
                && name != ssid.to_string_lossy()
            {
                continue;
            }
            let proxy = self.proxy(path.as_str(), KNOWN_NETWORK).await?;
            match proxy.call_method("Forget", &()).await {
                Ok(_) => {}
                Err(error) if error.to_string().contains("UnknownObject") => {}
                Err(error) => return Err(dbus_error(error)),
            }
        }
        Ok(())
    }

    fn monitor_rules() -> PortResult<[zbus::MatchRule<'static>; 3]> {
        Ok([
            zbus::MatchRule::builder()
                .msg_type(Type::Signal)
                .sender("org.freedesktop.DBus")
                .interface("org.freedesktop.DBus")
                .member("NameOwnerChanged")
                .arg(0, SERVICE)
                .build()
                .map_err(dbus_error)?,
            zbus::MatchRule::builder()
                .msg_type(Type::Signal)
                .sender(SERVICE)
                .interface(OBJECT_MANAGER)
                .path("/")
                .build()
                .map_err(dbus_error)?,
            zbus::MatchRule::builder()
                .msg_type(Type::Signal)
                .sender(SERVICE)
                .interface(PROPERTIES)
                .member("PropertiesChanged")
                .path_namespace(MANAGER_PATH)
                .build()
                .map_err(dbus_error)?,
        ])
    }

    async fn start_monitor(&self) -> PortResult<()> {
        let connection = self.inner.connection.clone();
        let rules = Self::monitor_rules()?;
        let mut streams = Vec::with_capacity(rules.len());
        for rule in rules {
            streams.push(
                zbus::MessageStream::for_match_rule(rule, &connection, None)
                    .await
                    .map_err(dbus_error)?,
            );
        }

        let mut merged = futures_util::stream::select_all(streams);
        let (tx, mut rx) = tokio::sync::mpsc::channel(SIGNAL_QUEUE_CAPACITY);
        let lagged = Arc::new(AtomicBool::new(false));
        let lag_wake = Arc::new(tokio::sync::Notify::new());
        let drain_weak = Arc::downgrade(&self.inner);
        let drain_lagged = Arc::clone(&lagged);
        let drain_wake = Arc::clone(&lag_wake);
        let drain = tokio::spawn(async move {
            while let Some(message) = merged.next().await {
                if drain_weak.strong_count() == 0 {
                    return;
                }
                match tx.try_send(message) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        if !drain_lagged.swap(true, Ordering::AcqRel) {
                            tracing::warn!(
                                capacity = SIGNAL_QUEUE_CAPACITY,
                                "iwd signal queue full; scheduling full resync"
                            );
                        }
                        drain_wake.notify_one();
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
            tracing::warn!("iwd signal stream ended");
        });
        let worker_weak = Arc::downgrade(&self.inner);
        let worker = tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    biased;
                    () = lag_wake.notified(), if lagged.load(Ordering::Acquire) => {
                        let Some(inner) = worker_weak.upgrade() else {
                            return;
                        };
                        if lagged.swap(false, Ordering::AcqRel) {
                            let this = Self { inner };
                            if let Err(error) = this.attach().await {
                                tracing::warn!(%error, "iwd resync after signal lag failed");
                            }
                        }
                        continue;
                    }
                    message = rx.recv() => message,
                };
                let Some(message) = next else {
                    return;
                };
                let Some(inner) = worker_weak.upgrade() else {
                    return;
                };
                let this = Self { inner };
                match message {
                    Ok(message) => this.dispatch(&message).await,
                    Err(error) => tracing::warn!(%error, "malformed iwd signal"),
                }
                if lagged.swap(false, Ordering::AcqRel)
                    && let Err(error) = this.attach().await
                {
                    tracing::warn!(%error, "iwd resync after signal lag failed");
                }
            }
        });
        self.inner
            .monitor_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend([drain.abort_handle(), worker.abort_handle()]);
        Ok(())
    }

    async fn dispatch(&self, message: &zbus::Message) {
        let header = message.header();
        let (Some(interface), Some(member), Some(path)) =
            (header.interface(), header.member(), header.path())
        else {
            return;
        };
        let path = OwnedObjectPath::from(path.to_owned());
        let body = message.body();
        if interface.as_str() == "org.freedesktop.DBus" && member.as_str() == "NameOwnerChanged" {
            // Filter by name here too: match-rule argument filtering is
            // not guaranteed to be applied to every delivered message.
            if let Ok((name, old_owner, new_owner)) = body.deserialize::<(String, String, String)>()
                && name == SERVICE
            {
                if !old_owner.is_empty() {
                    tracing::warn!("iwd left the bus");
                    self.vanished();
                }
                if !new_owner.is_empty() {
                    self.lock().iwd_owner = Some(new_owner);
                    if let Err(error) = self.attach().await {
                        tracing::warn!(%error, "cannot attach to iwd");
                    }
                }
            }
            return;
        }
        if let Some(expected_owner) = self.lock().iwd_owner.clone()
            && header.sender().map(zbus::names::UniqueName::as_str) != Some(expected_owner.as_str())
        {
            return;
        }
        match (interface.as_str(), member.as_str()) {
            (OBJECT_MANAGER, "InterfacesAdded") => {
                if let Ok((added, interfaces)) =
                    body.deserialize::<(OwnedObjectPath, HashMap<String, Props>)>()
                {
                    if interfaces.contains_key(DEVICE) || interfaces.contains_key(ADAPTER) {
                        self.object_added(&added, &interfaces);
                    } else if (interfaces.contains_key(STATION)
                        || interfaces.contains_key(ACCESS_POINT))
                        && !self.lock().stations.contains_key(&added)
                        && let Ok(objects) = self.objects().await
                        && let Some(full) = objects.get(&added)
                    {
                        self.record_adapters(&objects);
                        self.object_added(&added, full);
                    }
                }
            }
            (OBJECT_MANAGER, "InterfacesRemoved") => {
                if let Ok((removed, interfaces)) =
                    body.deserialize::<(OwnedObjectPath, Vec<String>)>()
                    && interfaces.iter().any(|i| i == DEVICE)
                {
                    self.object_removed(&removed);
                }
            }
            (PROPERTIES, "PropertiesChanged") => {
                let Ok((changed_interface, changed, _)) =
                    body.deserialize::<(String, Props, Vec<String>)>()
                else {
                    return;
                };
                if changed_interface == ACCESS_POINT {
                    if prop::<bool>(&changed, "Started") == Some(false)
                        && let Some(device) = self.lock().stations.get(&path).cloned()
                        && self.lock().ap_active.remove(&device)
                    {
                        self.inner.ap_events.publish(&ApEvent::Stopped { device });
                    }
                    return;
                }
                if changed_interface != STATION {
                    return;
                }
                if changed.contains_key("State") || changed.contains_key("ConnectedNetwork") {
                    self.refresh_link(&path).await;
                }
                if let Some(scanning) = prop::<bool>(&changed, "Scanning") {
                    let was = self
                        .lock()
                        .scanning
                        .insert(path.clone(), scanning)
                        .unwrap_or(false);
                    if was && !scanning {
                        let Some(device) = self.lock().stations.get(&path).cloned() else {
                            return;
                        };
                        let result = self.scan_results(&path).await;
                        self.inner
                            .events
                            .publish(&WlanEvent::ScanFinished { device, result });
                    }
                }
            }
            _ => {}
        }
    }
}

#[async_trait]
impl WlanProvider for Iwd {
    fn name(&self) -> &'static str {
        "iwd"
    }

    fn subscribe(&self) -> Subscription<WlanEvent> {
        self.inner.events.subscribe()
    }

    async fn devices(&self) -> PortResult<Vec<WlanDevice>> {
        let objects = self.objects().await?;
        self.record_adapters(&objects);
        let state = self.lock();
        let mut devices: Vec<WlanDevice> = objects
            .iter()
            .filter(|(_, interfaces)| {
                interfaces.contains_key(STATION) || interfaces.contains_key(ACCESS_POINT)
            })
            .filter_map(|(path, interfaces)| {
                let device = interfaces.get(DEVICE)?;
                Some(WlanDevice {
                    name: InterfaceName::new(prop::<String>(device, "Name")?).ok()?,
                    address: prop::<String>(device, "Address")
                        .and_then(|a| MacAddress::parse(&a).ok()),
                    capabilities: Capabilities {
                        station: true,
                        p2p: false,
                        access_point: Self::adapter_supports_ap(&state, path, device),
                    },
                    supported_security: SUPPORTED_SECURITY.to_vec(),
                })
            })
            .collect();
        devices.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(devices)
    }

    async fn start_scan(&self, device: &InterfaceName) -> PortResult<()> {
        let station = self.station_path(device)?;
        let proxy = self.proxy(station.as_str(), STATION).await?;
        // Mark scanning before calling `Scan` so a fast completion signal or
        // an in-progress `Busy` reply still delivers `ScanFinished`.
        self.lock().scanning.insert(station.clone(), true);
        match proxy.call_method("Scan", &()).await {
            Ok(_) => Ok(()),
            // A scan is already running; its completion delivers results.
            Err(error) if error.to_string().contains("Busy") => Ok(()),
            Err(error) => {
                self.lock().scanning.remove(&station);
                Err(dbus_error(error))
            }
        }
    }

    async fn connect(&self, device: &InterfaceName, request: ConnectRequest) -> PortResult<()> {
        let expected_type = match request.security {
            ProfileSecurity::Open => "open",
            ProfileSecurity::WpaPersonal => "psk",
            ProfileSecurity::Wpa3Personal
            | ProfileSecurity::Owe
            | ProfileSecurity::WpaEnterprise
            | ProfileSecurity::Wpa3Enterprise => {
                return Err(PortError::NotSupported(format!(
                    "iwd cannot enforce {} without downgrade; use wpa_supplicant",
                    request.security
                )));
            }
        };
        if request.bssid.is_some() {
            return Err(PortError::NotSupported(
                "iwd does not support BSSID pinning; use wpa_supplicant".to_owned(),
            ));
        }
        let Some(ssid_utf8) = std::str::from_utf8(request.ssid.as_bytes()).ok() else {
            return Err(PortError::NotSupported(
                "iwd requires UTF-8 SSIDs; use wpa_supplicant".to_owned(),
            ));
        };
        let station = self.station_path(device)?;
        let station_proxy = self.proxy(station.as_str(), STATION).await?;
        let network = if request.hidden {
            None
        } else {
            Some(
                self.find_network(&station, &request.ssid, expected_type)
                    .await?
                    .ok_or_else(|| {
                        PortError::NotFound(format!("{} is not in range", request.ssid))
                    })?,
            )
        };
        // Check if this (SSID, Type) was already known to iwd before Kestrel
        // connected so we do not overwrite/delete a pre-existing admin network.
        let already_known = self.objects().await.is_ok_and(|objects| {
            objects.values().any(|interfaces| {
                interfaces.get(KNOWN_NETWORK).is_some_and(|props| {
                    prop::<String>(props, "Name").as_deref() == Some(ssid_utf8)
                        && prop::<String>(props, "Type").is_none_or(|t| t == expected_type)
                })
            })
        });
        if already_known {
            self.lock()
                .preexisting_known
                .insert((ssid_utf8.to_owned(), expected_type.to_owned()));
        }
        let attempt_id = {
            let mut state = self.lock();
            state.next_attempt = state.next_attempt.wrapping_add(1);
            let id = state.next_attempt;
            state.pending.insert(
                station.clone(),
                Pending {
                    attempt_id: id,
                    secret: request.secrets.passphrase.clone(),
                    asked: false,
                },
            );
            id
        };
        // iwd's Connect blocks until the outcome; run it in the background
        // and report failures as events.
        let this = self.clone();
        let device = device.clone();
        let ssid = request.ssid.clone();
        let expected_type = expected_type.to_owned();
        tokio::spawn(async move {
            let result = match &network {
                Some(network) => match this.proxy(network.as_str(), NETWORK).await {
                    Ok(proxy) => proxy.call_method("Connect", &()).await.map(|_| ()),
                    Err(error) => {
                        this.connect_failed(&station, attempt_id, &device, error);
                        return;
                    }
                },
                None => station_proxy
                    .call_method("ConnectHiddenNetwork", &(ssid.to_string_lossy(),))
                    .await
                    .map(|_| ()),
            };
            match result {
                Ok(()) => {
                    if !already_known {
                        this.mark_owned(&ssid, &expected_type).await;
                    }
                }
                Err(error) => {
                    let text = error.to_string();
                    if text.contains("Aborted") || text.contains("InProgress") {
                        return; // Superseded by another request.
                    }
                    this.connect_failed(&station, attempt_id, &device, dbus_error(error));
                }
            }
        });
        Ok(())
    }

    async fn disconnect(&self, device: &InterfaceName) -> PortResult<()> {
        let Ok(station) = self.station_path(device) else {
            return Ok(());
        };
        self.lock().pending.remove(&station);
        let connected = match self.lock().links.get(device) {
            Some(LinkStatus::Connected { ssid, .. }) => Some(ssid.clone()),
            _ => None,
        };
        let proxy = self.proxy(station.as_str(), STATION).await?;
        match proxy.call_method("Disconnect", &()).await {
            Ok(_) => {}
            Err(error) if error.to_string().contains("NotConnected") => {}
            Err(error) => return Err(dbus_error(error)),
        }
        match connected {
            Some(ssid) => self.forget_owned(Some(&ssid)).await,
            None => Ok(()),
        }
    }

    async fn link_status(&self, device: &InterfaceName) -> PortResult<LinkStatus> {
        let station = self.station_path(device)?;
        self.read_link(&station).await
    }

    async fn sweep(&self) -> PortResult<()> {
        if let Ok(objects) = self.objects().await {
            for (path, interfaces) in &objects {
                if interfaces.contains_key(ACCESS_POINT) {
                    if let Ok(ap) = self.proxy(path.as_str(), ACCESS_POINT).await {
                        let _ = ap.call_method("Stop", &()).await;
                    }
                    if let Ok(dev) = self.proxy(path.as_str(), DEVICE).await {
                        let _ = dev.set_property("Mode", Variant::from("station")).await;
                    }
                }
            }
        }
        self.forget_owned(None).await
    }

    fn ap(&self) -> Option<Arc<dyn ApProvider>> {
        Some(Arc::new(self.clone()))
    }
}

#[async_trait]
impl ApProvider for Iwd {
    fn subscribe(&self) -> Subscription<ApEvent> {
        self.inner.ap_events.subscribe()
    }

    async fn start_ap(&self, device: &InterfaceName, request: &ApStartRequest) -> PortResult<()> {
        if request.security != HotspotSecurity::WpaPersonal {
            return Err(PortError::NotSupported(format!(
                "iwd AccessPoint.Start only supports wpa-personal, not {}; use wpa_supplicant",
                request.security
            )));
        }
        if request.hidden {
            return Err(PortError::NotSupported(
                "iwd AccessPoint.Start does not support hidden SSIDs; use wpa_supplicant"
                    .to_owned(),
            ));
        }
        if request.frequency.is_some() {
            return Err(PortError::NotSupported(
                "iwd AccessPoint.Start does not accept an explicit channel/frequency; use wpa_supplicant".to_owned(),
            ));
        }
        let Some(secret) = &request.secret else {
            return Err(PortError::InvalidArgument(
                "wpa-personal hotspot requires a passphrase".to_owned(),
            ));
        };
        let dev_path = self.station_path(device)?;
        let dev_proxy = self.proxy(dev_path.as_str(), DEVICE).await?;
        dev_proxy
            .set_property("Mode", Variant::from("ap"))
            .await
            .map_err(dbus_error)?;
        let ap_proxy = self.proxy(dev_path.as_str(), ACCESS_POINT).await?;
        let ssid = request.ssid.to_string_lossy();
        let mut last_err = None;
        for _ in 0..10 {
            match ap_proxy
                .call_method("Start", &(ssid.as_str(), secret.expose()))
                .await
            {
                Ok(_) => {
                    let freq = ap_proxy.get_property::<u32>("Frequency").await.unwrap_or(0);
                    self.lock().ap_active.insert(device.clone());
                    self.inner.ap_events.publish(&ApEvent::Started {
                        device: device.clone(),
                        frequency: freq,
                    });
                    return Ok(());
                }
                Err(error) if error.to_string().contains("UnknownInterface") => {
                    last_err = Some(error);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => {
                    let _ = dev_proxy
                        .set_property("Mode", Variant::from("station"))
                        .await;
                    return Err(dbus_error(error));
                }
            }
        }
        let _ = dev_proxy
            .set_property("Mode", Variant::from("station"))
            .await;
        Err(last_err.map_or_else(
            || PortError::NotSupported("iwd AccessPoint interface unavailable".to_owned()),
            dbus_error,
        ))
    }

    async fn stop_ap(&self, device: &InterfaceName) -> PortResult<()> {
        let Ok(dev_path) = self.station_path(device) else {
            return Ok(());
        };
        let ap_proxy = self.proxy(dev_path.as_str(), ACCESS_POINT).await?;
        match ap_proxy.call_method("Stop", &()).await {
            Ok(_) => {}
            Err(error)
                if error.to_string().contains("UnknownInterface")
                    || error.to_string().contains("NotStarted") => {}
            Err(error) => return Err(dbus_error(error)),
        }
        let dev_proxy = self.proxy(dev_path.as_str(), DEVICE).await?;
        dev_proxy
            .set_property("Mode", Variant::from("station"))
            .await
            .map_err(dbus_error)?;
        // Wait briefly for `net.connman.iwd.Station` to reappear before
        // returning so an immediate station scan does not hit UnknownInterface.
        for _ in 0..10 {
            if let Ok(objects) = self.objects().await
                && objects
                    .get(&dev_path)
                    .is_some_and(|ifaces| ifaces.contains_key(STATION))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.lock().ap_active.remove(device);
        self.inner.ap_events.publish(&ApEvent::Stopped {
            device: device.clone(),
        });
        Ok(())
    }
}

impl Iwd {
    fn connect_failed(
        &self,
        station: &OwnedObjectPath,
        attempt_id: u64,
        device: &InterfaceName,
        error: PortError,
    ) {
        let asked = {
            let mut state = self.lock();
            match state.pending.get(station) {
                Some(pending) if pending.attempt_id == attempt_id => {
                    let asked = pending.asked;
                    state.pending.remove(station);
                    asked
                }
                _ => return, // Superseded by a newer connect() or disconnect().
            }
        };
        let event = if asked && matches!(error, PortError::Backend(_)) {
            WlanEvent::AuthFailed {
                device: device.clone(),
            }
        } else {
            WlanEvent::ConnectFailed {
                device: device.clone(),
                error,
            }
        };
        self.inner.events.publish(&event);
    }

    /// Marks the known network iwd just saved as Kestrel's.
    async fn mark_owned(&self, ssid: &Ssid, expected_type: &str) {
        // iwd creates the KnownNetwork object shortly after connecting.
        for _ in 0..20 {
            if let Ok(objects) = self.objects().await {
                let known = objects.iter().find(|(_, interfaces)| {
                    interfaces.get(KNOWN_NETWORK).is_some_and(|props| {
                        prop::<String>(props, "Name").as_deref() == Some(&ssid.to_string_lossy())
                            && prop::<String>(props, "Type").is_none_or(|t| t == expected_type)
                    })
                });
                if let Some((path, _)) = known {
                    if let Ok(proxy) = self.proxy(path.as_str(), KNOWN_NETWORK).await
                        && let Err(error) = proxy.set_property("AutoConnect", false).await
                    {
                        tracing::warn!(%error, "cannot disable iwd autoconnect");
                    }
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn map_security(network_type: Option<&str>) -> Security {
    match network_type {
        Some("open") => Security::Open,
        Some("wep") => Security::Wep,
        Some("psk") => Security::Wpa2Psk,
        Some("8021x") => Security::Enterprise,
        _ => Security::Unknown,
    }
}

pub(crate) fn dbus_error(error: impl fmt::Display) -> PortError {
    let text = error.to_string();
    if text.contains("AccessDenied")
        || text.contains("PermissionDenied")
        || text.contains("NotAuthorized")
    {
        PortError::PermissionDenied(text)
    } else if text.contains("ServiceUnknown") || text.contains("NameHasNoOwner") {
        PortError::Unavailable(format!("iwd is not running: {text}"))
    } else if text.contains("UnknownObject") || text.contains("NotFound") {
        PortError::NotFound(text)
    } else if text.contains("Busy") || text.contains("InProgress") {
        PortError::Busy(text)
    } else if text.contains("Timeout") {
        PortError::Timeout(text)
    } else if text.contains("NotSupported") {
        PortError::NotSupported(text)
    } else {
        PortError::Backend(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_security() {
        assert_eq!(map_security(Some("psk")), Security::Wpa2Psk);
        assert_eq!(map_security(Some("open")), Security::Open);
        assert_eq!(map_security(Some("8021x")), Security::Enterprise);
        assert_eq!(map_security(None), Security::Unknown);
    }

    #[test]
    fn classifies_errors() {
        assert!(matches!(
            dbus_error("net.connman.iwd.Busy"),
            PortError::Busy(_)
        ));
        assert!(matches!(
            dbus_error("net.connman.iwd.NotSupported"),
            PortError::NotSupported(_)
        ));
        assert!(matches!(
            dbus_error("net.connman.iwd.Failed"),
            PortError::Backend(_)
        ));
    }
}

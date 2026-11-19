// SPDX-License-Identifier: LGPL-2.1-or-later

//! `wpa_supplicant` as Kestrel's wireless, SoftAP, and Wi-Fi Direct provider.
//!
//! The adapter talks to `fi.w1.wpa_supplicant1` over D-Bus and is fully
//! event-driven. A single monitor task consumes the daemon's signals in
//! order and turns them into port events:
//!
//! - `PropertiesChanged` (`State`, `CurrentBSS`) becomes station link status
//!   or SoftAP `Started`/`Stopped` events;
//! - `ScanDone` becomes scan results;
//! - `PskMismatch` and `EAP` failures become authentication failures;
//! - `StaAuthorized`/`StaDeauthorized` become SoftAP client events;
//! - `P2PDevice` signals become peer discovery, GO negotiation, persistent
//!   group provisioning, and group lifecycle events;
//! - the daemon appearing or vanishing on the bus becomes devices being
//!   added or removed.
//!
//! **Statelessness.** Each association or SoftAP adds exactly one network
//! block, tagged `id_str=kestrel`, and removes it on disconnect/stop. 802.1X
//! certificates and private keys are uploaded via `AddBlob` (`kestrel-*`)
//! and never hit disk. `sweep` removes every tagged block, every `kestrel-*`
//! blob, every P2P group interface, and every internal `wpa_supplicant`
//! persistent group.

mod monitor;
mod network;
mod p2p;
#[cfg(feature = "testkit")]
pub mod testkit;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kestrel_model::{Bss, InterfaceName, MacAddress, ProfileSecurity, Ssid};
use kestrel_ports::ap::{ApEvent, ApProvider, ApStartRequest};
use kestrel_ports::p2p::{P2pEvent, P2pProvider};
use kestrel_ports::wlan::{
    Capabilities, ConnectRequest, LinkStatus, WlanDevice, WlanEvent, WlanProvider,
};
use kestrel_ports::{EventBus, PortError, PortResult, Subscription};
use zbus::proxy::CacheProperties;
use zbus::{OwnedObjectPath, OwnedVariant as OwnedValue, Variant as Value};

use crate::network::{
    BlobRefs, OWNER_TAG, ap_network_args, classify, network_args, system_ca_path,
};

pub(crate) const SERVICE: &str = "fi.w1.wpa_supplicant1";
pub(crate) const MAIN_PATH: &str = "/fi/w1/wpa_supplicant1";
pub(crate) const MAIN: &str = "fi.w1.wpa_supplicant1";
pub(crate) const INTERFACE: &str = "fi.w1.wpa_supplicant1.Interface";
pub(crate) const P2P_DEVICE: &str = "fi.w1.wpa_supplicant1.Interface.P2PDevice";
pub(crate) const BSS: &str = "fi.w1.wpa_supplicant1.BSS";
pub(crate) const NETWORK: &str = "fi.w1.wpa_supplicant1.Network";
pub(crate) const PEER: &str = "fi.w1.wpa_supplicant1.Peer";

const BLOB_CA: &str = "kestrel-ca";
const BLOB_CLIENT_CERT: &str = "kestrel-cert";
const BLOB_PRIVATE_KEY: &str = "kestrel-key";
const OWNED_BLOBS: [&str; 3] = [BLOB_CA, BLOB_CLIENT_CERT, BLOB_PRIVATE_KEY];

/// What a `wpa_supplicant` interface object represents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Role {
    /// A wireless device Kestrel exposes.
    Station,
    /// The dedicated P2P management interface of a device (`p2p-dev-*`).
    P2pDevice(InterfaceName),
    /// A P2P group interface owned by a device.
    P2pGroup(InterfaceName),
}

#[derive(Debug, Clone)]
pub(crate) struct Iface {
    pub(crate) ifname: InterfaceName,
    pub(crate) role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApState {
    /// `SelectNetwork` was sent; waiting for `wpa_supplicant` to reach
    /// `"completed"` asynchronously without letting initial `"disconnected"`
    /// states abort startup.
    Starting(u32),
    /// AP reached `"completed"` and `ApEvent::Started` has been emitted.
    Running(u32),
}

#[derive(Debug, Clone)]
pub(crate) struct IfaceCaps {
    pub(crate) capabilities: Capabilities,
    pub(crate) supported_security: Vec<ProfileSecurity>,
    pub(crate) key_mgmt: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) interfaces: HashMap<OwnedObjectPath, Iface>,
    pub(crate) links: BTreeMap<InterfaceName, LinkStatus>,
    pub(crate) macs: HashMap<InterfaceName, MacAddress>,
    pub(crate) peers: HashMap<OwnedObjectPath, P2pPeerState>,
    pub(crate) iface_caps: HashMap<InterfaceName, IfaceCaps>,
    pub(crate) ap_active: HashMap<InterfaceName, ApState>,
    pub(crate) known_groups: HashMap<OwnedObjectPath, (InterfaceName, bool)>,
    pub(crate) self_persistent_groups: HashSet<OwnedObjectPath>,
    pub(crate) suppress_persistent_added: usize,
    pub(crate) p2p_capable: bool,
    pub(crate) ap_capable: bool,
    pub(crate) wpa_owner: Option<String>,
}

type P2pPeerState = kestrel_model::P2pPeer;

impl State {
    /// Finds the object that carries P2P methods for `station`: its
    /// dedicated `p2p-dev-*` interface (handling kernel `IFNAMSIZ` 15-byte
    /// truncation) when the driver uses one, else the station itself.
    pub(crate) fn p2p_path(&self, station: &InterfaceName) -> Option<OwnedObjectPath> {
        self.interfaces
            .iter()
            .filter(|(_, iface)| {
                matches!(&iface.role, Role::P2pDevice(parent) if parent == station)
            })
            .min_by_key(|(path, _)| path.as_str())
            .or_else(|| {
                self.interfaces
                    .iter()
                    .filter(|(_, iface)| {
                        matches!(
                            &iface.role,
                            Role::P2pDevice(parent) if matches_station(station, parent, &iface.ifname)
                        )
                    })
                    .min_by_key(|(path, _)| path.as_str())
            })
            .or_else(|| {
                self.interfaces
                    .iter()
                    .find(|(_, iface)| &iface.ifname == station && iface.role == Role::Station)
            })
            .map(|(path, _)| path.clone())
    }

    /// Resolves the parent name extracted from a `p2p-dev-*` or `p2p-*-*`
    /// interface to a known station's full name when `IFNAMSIZ` truncated it.
    pub(crate) fn resolve_station(
        &self,
        parent: &InterfaceName,
        p2p_ifname: &InterfaceName,
    ) -> InterfaceName {
        if self
            .interfaces
            .values()
            .any(|iface| iface.role == Role::Station && &iface.ifname == parent)
        {
            return parent.clone();
        }
        self.interfaces
            .values()
            .filter(|iface| {
                iface.role == Role::Station && matches_station(&iface.ifname, parent, p2p_ifname)
            })
            .min_by(|a, b| a.ifname.cmp(&b.ifname))
            .map_or_else(|| parent.clone(), |iface| iface.ifname.clone())
    }
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) connection: zbus::Connection,
    pub(crate) sysfs: PathBuf,
    pub(crate) state: Mutex<State>,
    pub(crate) events: EventBus<WlanEvent>,
    pub(crate) p2p_events: EventBus<P2pEvent>,
    pub(crate) ap_events: EventBus<ApEvent>,
    pub(crate) monitor_tasks: Mutex<Vec<tokio::task::AbortHandle>>,
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

/// The `wpa_supplicant` provider.
#[derive(Debug, Clone)]
pub struct WpaSupplicant {
    pub(crate) inner: Arc<Inner>,
}

impl fmt::Display for WpaSupplicant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("wpa_supplicant")
    }
}

impl WpaSupplicant {
    /// Connects to the daemon, starts the signal monitor, and discovers
    /// interfaces. Succeeds even if the daemon is not running yet; devices
    /// appear when it starts.
    pub async fn new(connection: zbus::Connection) -> PortResult<Self> {
        Self::with_sysfs(connection, "/sys/class/net").await
    }

    /// Like [`Self::new`], reading wireless interface metadata from `sysfs`
    /// instead of `/sys/class/net`.
    pub async fn with_sysfs(
        connection: zbus::Connection,
        sysfs: impl Into<PathBuf>,
    ) -> PortResult<Self> {
        let inner = Arc::new(Inner {
            connection,
            sysfs: sysfs.into(),
            state: Mutex::new(State::default()),
            events: EventBus::new(),
            p2p_events: EventBus::new(),
            ap_events: EventBus::new(),
            monitor_tasks: Mutex::new(Vec::new()),
        });
        let this = Self { inner };
        let tasks =
            monitor::start(Arc::downgrade(&this.inner), this.inner.connection.clone()).await?;
        this.inner
            .monitor_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(tasks);
        if let Err(error) = this.discover().await {
            tracing::warn!(%error, "wpa_supplicant is not available yet");
        }
        Ok(this)
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) async fn proxy(
        &self,
        path: impl Into<String>,
        interface: &'static str,
    ) -> PortResult<zbus::Proxy<'static>> {
        let path: String = path.into();
        zbus::proxy::Builder::new(&self.inner.connection)
            .destination(SERVICE)
            .path(path)
            .interface(interface)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(dbus_error)
    }

    /// Reads the daemon's interfaces and capabilities from scratch.
    pub(crate) async fn discover(&self) -> PortResult<()> {
        if let Ok(dbus) = zbus::fdo::DBusProxy::new(&self.inner.connection).await
            && let Ok(name) = zbus::names::BusName::try_from(SERVICE)
            && let Ok(owner) = dbus.get_name_owner(name).await
        {
            self.lock().wpa_owner = Some(owner.as_str().to_owned());
        }
        let main = self.proxy(MAIN_PATH, MAIN).await?;
        let capabilities: Vec<String> = main.get_property("Capabilities").await.unwrap_or_default();
        let mut paths: Vec<OwnedObjectPath> =
            main.get_property("Interfaces").await.map_err(dbus_error)?;
        {
            let mut state = self.lock();
            state.p2p_capable = capabilities.iter().any(|c| c == "p2p");
            state.ap_capable = capabilities.iter().any(|c| c == "ap");
        }
        if paths.is_empty() {
            paths = self.attach_sysfs_interfaces(&main).await;
        }
        let mut stations = Vec::new();
        for path in paths {
            match self.read_ifname(&path).await {
                Ok(ifname) if role_for(&ifname) == Role::Station => stations.push(path),
                Ok(_) => self.interface_added(path).await,
                Err(error) => {
                    tracing::warn!(path = %path.as_str(), %error, "ignoring wpa_supplicant interface");
                }
            }
        }
        for path in stations {
            self.interface_added(path).await;
        }
        Ok(())
    }

    async fn attach_sysfs_interfaces(&self, main: &zbus::Proxy<'static>) -> Vec<OwnedObjectPath> {
        let sysfs = self.inner.sysfs.clone();
        let stations = tokio::task::spawn_blocking(move || sysfs_stations(&sysfs))
            .await
            .unwrap_or_default();
        let mut paths = Vec::new();
        for ifname in stations {
            let args: HashMap<&str, Value<'_>> = HashMap::from([
                ("Ifname", Value::from(ifname.as_str())),
                ("Driver", Value::from("nl80211,wext")),
            ]);
            let reply = match main.call_method("CreateInterface", &(args,)).await {
                Ok(reply) => Ok(reply),
                Err(error) if error.to_string().contains("InterfaceExists") => {
                    main.call_method("GetInterface", &(ifname.as_str(),)).await
                }
                Err(error) => Err(error),
            };
            match reply {
                Ok(reply) => {
                    if let Ok(path) = reply.body().deserialize::<OwnedObjectPath>() {
                        paths.push(path);
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        device = %ifname,
                        %error,
                        "cannot attach sysfs wireless interface to wpa_supplicant"
                    );
                }
            }
        }
        paths
    }

    async fn read_interface_capabilities(&self, path: &OwnedObjectPath) -> IfaceCaps {
        let (global_p2p, global_ap) = {
            let s = self.lock();
            (s.p2p_capable, s.ap_capable)
        };
        let Ok(proxy) = self.proxy(path.as_str(), INTERFACE).await else {
            return IfaceCaps {
                capabilities: Capabilities {
                    station: true,
                    p2p: global_p2p,
                    access_point: global_ap,
                },
                supported_security: ProfileSecurity::ALL.to_vec(),
                key_mgmt: Vec::new(),
            };
        };
        let caps: HashMap<String, OwnedValue> =
            proxy.get_property("Capabilities").await.unwrap_or_default();
        let modes: Vec<String> = caps
            .get("Modes")
            .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
            .unwrap_or_default();
        let access_point = if modes.is_empty() {
            global_ap
        } else {
            global_ap && modes.iter().any(|m| m.eq_ignore_ascii_case("ap"))
        };
        let p2p = if modes.is_empty() {
            global_p2p
        } else {
            global_p2p
                && modes
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case("p2p") || m.eq_ignore_ascii_case("p2p-device"))
        };
        let key_mgmt: Vec<String> = caps
            .get("KeyMgmt")
            .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
            .unwrap_or_default();
        let supported_security = if key_mgmt.is_empty() {
            ProfileSecurity::ALL.to_vec()
        } else {
            supported_security_from_key_mgmt(&key_mgmt)
        };
        IfaceCaps {
            capabilities: Capabilities {
                station: true,
                p2p,
                access_point,
            },
            supported_security,
            key_mgmt,
        }
    }

    /// Records a new interface object and announces stations.
    pub(crate) async fn interface_added(&self, path: OwnedObjectPath) {
        let ifname = match self.read_ifname(&path).await {
            Ok(ifname) => ifname,
            Err(error) => {
                tracing::warn!(path = %path.as_str(), %error, "ignoring wpa_supplicant interface");
                return;
            }
        };
        let role = role_for(&ifname);
        let (caps, mac) = if role == Role::Station {
            let caps = self.read_interface_capabilities(&path).await;
            let mac = read_sysfs_mac(&self.inner.sysfs, &ifname).await;
            (Some(caps), mac)
        } else {
            (None, None)
        };
        let device = {
            let mut state = self.lock();
            if state.interfaces.contains_key(&path) {
                return;
            }
            if let Some(caps) = caps {
                state.iface_caps.insert(ifname.clone(), caps);
            }
            if let Some(mac) = mac {
                state.macs.insert(ifname.clone(), mac);
            }
            state.interfaces.insert(
                path.clone(),
                Iface {
                    ifname: ifname.clone(),
                    role: role.clone(),
                },
            );
            (role == Role::Station).then(|| Self::device_for(&state, &ifname, mac))
        };
        if let Some(device) = device {
            if let Ok(status) = self.read_link(&path).await {
                self.lock().links.insert(ifname.clone(), status);
            }
            self.inner.events.publish(&WlanEvent::DeviceAdded(device));
        }
    }

    pub(crate) fn interface_removed(&self, path: &OwnedObjectPath) {
        let prefix = format!("{}/", path.as_str());
        let (removed, stopped_ap) = {
            let mut state = self.lock();
            let removed = state.interfaces.remove(path);
            let mut stopped_ap = None;
            if let Some(iface) = &removed {
                state.links.remove(&iface.ifname);
                state.macs.remove(&iface.ifname);
                state.iface_caps.remove(&iface.ifname);
                if matches!(
                    state.ap_active.remove(&iface.ifname),
                    Some(ApState::Running(_))
                ) {
                    stopped_ap = Some(iface.ifname.clone());
                }
                state
                    .peers
                    .retain(|peer, _| !peer.as_str().starts_with(&prefix));
            }
            (removed, stopped_ap)
        };
        if let Some(device) = stopped_ap {
            self.inner.ap_events.publish(&ApEvent::Stopped { device });
        }
        if let Some(Iface {
            ifname,
            role: Role::Station,
        }) = removed
        {
            self.inner.events.publish(&WlanEvent::DeviceRemoved(ifname));
        }
    }

    /// The daemon left the bus: every device is gone.
    pub(crate) fn backend_vanished(&self) {
        let paths: Vec<OwnedObjectPath> = self.lock().interfaces.keys().cloned().collect();
        for path in paths {
            self.interface_removed(&path);
        }
        let mut state = self.lock();
        state.p2p_capable = false;
        state.ap_capable = false;
        state.iface_caps.clear();
        state.known_groups.clear();
        state.self_persistent_groups.clear();
        state.suppress_persistent_added = 0;
        state.wpa_owner = None;
    }

    pub(crate) fn device_for(
        state: &State,
        ifname: &InterfaceName,
        address: Option<MacAddress>,
    ) -> WlanDevice {
        let (capabilities, supported_security) = state.iface_caps.get(ifname).map_or_else(
            || {
                (
                    Capabilities {
                        station: true,
                        p2p: state.p2p_capable,
                        access_point: state.ap_capable,
                    },
                    ProfileSecurity::ALL.to_vec(),
                )
            },
            |caps| (caps.capabilities, caps.supported_security.clone()),
        );
        WlanDevice {
            name: ifname.clone(),
            address: address.or_else(|| state.macs.get(ifname).copied()),
            capabilities,
            supported_security,
        }
    }

    async fn read_ifname(&self, path: &OwnedObjectPath) -> PortResult<InterfaceName> {
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        let ifname: String = proxy.get_property("Ifname").await.map_err(dbus_error)?;
        InterfaceName::new(ifname).map_err(|e| {
            PortError::Backend(format!("invalid interface name from wpa_supplicant: {e}"))
        })
    }

    pub(crate) fn path_of(&self, device: &InterfaceName, role: &Role) -> Option<OwnedObjectPath> {
        self.lock()
            .interfaces
            .iter()
            .find(|(_, iface)| &iface.ifname == device && &iface.role == role)
            .map(|(path, _)| path.clone())
    }

    pub(crate) fn station_path(&self, device: &InterfaceName) -> PortResult<OwnedObjectPath> {
        self.path_of(device, &Role::Station)
            .ok_or_else(|| PortError::NotFound(device.to_string()))
    }

    /// Reads `State` and `CurrentBSS` into a link status.
    pub(crate) async fn read_link(&self, path: &OwnedObjectPath) -> PortResult<LinkStatus> {
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        let state: String = proxy.get_property("State").await.map_err(dbus_error)?;
        Ok(match state.as_str() {
            "completed" => {
                let current: OwnedObjectPath =
                    proxy.get_property("CurrentBSS").await.map_err(dbus_error)?;
                match self.read_bss(&current).await {
                    Some(bss) => LinkStatus::Connected {
                        ssid: bss.ssid,
                        bssid: Some(bss.bssid),
                    },
                    None => LinkStatus::Connecting,
                }
            }
            "disconnected" | "inactive" | "interface_disabled" => LinkStatus::Disconnected,
            _ => LinkStatus::Connecting,
        })
    }

    /// Publishes a link change (or AP state transition) for a station.
    pub(crate) async fn refresh_link(&self, path: &OwnedObjectPath) {
        let ifname = match self.lock().interfaces.get(path) {
            Some(Iface {
                ifname,
                role: Role::Station,
            }) => ifname.clone(),
            _ => return,
        };
        let ap_state = self.lock().ap_active.get(&ifname).copied();
        if let Some(ap_state) = ap_state {
            let Ok(proxy) = self.proxy(path.as_str(), INTERFACE).await else {
                return;
            };
            let Ok(state_str) = proxy.get_property::<String>("State").await else {
                return;
            };
            match (ap_state, state_str.as_str()) {
                (ApState::Starting(freq), "completed") => {
                    self.lock()
                        .ap_active
                        .insert(ifname.clone(), ApState::Running(freq));
                    self.inner.ap_events.publish(&ApEvent::Started {
                        device: ifname,
                        frequency: freq,
                    });
                }
                (ApState::Running(_), "disconnected" | "inactive" | "interface_disabled") => {
                    self.lock().ap_active.remove(&ifname);
                    self.inner
                        .ap_events
                        .publish(&ApEvent::Stopped { device: ifname });
                }
                _ => {}
            }
            return;
        }
        let Ok(status) = self.read_link(path).await else {
            return;
        };
        let changed = {
            let mut state = self.lock();
            if state.links.get(&ifname) == Some(&status) {
                false
            } else {
                state.links.insert(ifname.clone(), status.clone());
                true
            }
        };
        if changed {
            self.inner.events.publish(&WlanEvent::Link {
                device: ifname,
                status,
            });
        }
    }

    pub(crate) async fn read_bss(&self, path: &OwnedObjectPath) -> Option<Bss> {
        if path.as_str() == "/" {
            return None;
        }
        let props_proxy = self
            .proxy(path.as_str(), "org.freedesktop.DBus.Properties")
            .await
            .ok()?;
        let reply = props_proxy.call_method("GetAll", &(BSS,)).await.ok()?;
        let props: HashMap<String, OwnedValue> = reply.body().deserialize().ok()?;
        let ssid_bytes = props
            .get("SSID")
            .and_then(|v| Vec::<u8>::try_from(v.clone()).ok())?;
        let ssid = Ssid::from_bytes(ssid_bytes).ok()?;
        let bssid_bytes = props
            .get("BSSID")
            .and_then(|v| Vec::<u8>::try_from(v.clone()).ok())?;
        let bssid = mac_from_bytes(&bssid_bytes)?;
        let frequency = props
            .get("Frequency")
            .and_then(|v| u16::try_from(v.clone()).ok())
            .unwrap_or(0);
        let signal = props
            .get("Signal")
            .and_then(|v| i16::try_from(v.clone()).ok())
            .unwrap_or(i16::MIN);
        let privacy = props
            .get("Privacy")
            .and_then(|v| bool::try_from(v.clone()).ok())
            .unwrap_or(false);
        let wpa: HashMap<String, OwnedValue> = props
            .get("WPA")
            .and_then(|v| HashMap::<String, OwnedValue>::try_from(v.clone()).ok())
            .unwrap_or_default();
        let rsn: HashMap<String, OwnedValue> = props
            .get("RSN")
            .and_then(|v| HashMap::<String, OwnedValue>::try_from(v.clone()).ok())
            .unwrap_or_default();
        Some(Bss {
            ssid,
            bssid,
            frequency: u32::from(frequency),
            signal,
            security: classify(privacy, &key_mgmt(&wpa), &key_mgmt(&rsn)),
        })
    }

    /// Reads the current scan results of a station.
    pub(crate) async fn scan_results(&self, path: &OwnedObjectPath) -> PortResult<Vec<Bss>> {
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        let paths: Vec<OwnedObjectPath> = proxy.get_property("BSSs").await.map_err(dbus_error)?;
        let mut results = Vec::with_capacity(paths.len());
        for bss in paths {
            if let Some(bss) = self.read_bss(&bss).await {
                results.push(bss);
            }
        }
        results.sort_by(|a, b| b.signal.cmp(&a.signal).then_with(|| a.ssid.cmp(&b.ssid)));
        Ok(results)
    }

    async fn upload_blobs(
        &self,
        proxy: &zbus::Proxy<'static>,
        request: &ConnectRequest,
    ) -> PortResult<BlobRefs> {
        self.remove_owned_blobs(proxy).await;
        let mut refs = BlobRefs::default();
        if let Some(ent) = &request.enterprise {
            if let Some(ca) = &ent.ca_cert_pem {
                if let Err(error) = proxy
                    .call_method("AddBlob", &(BLOB_CA, ca.as_slice()))
                    .await
                {
                    self.remove_owned_blobs(proxy).await;
                    return Err(dbus_error(error));
                }
                refs.ca_cert = Some(BLOB_CA.to_owned());
            }
            if let Some(cert) = &ent.client_cert_pem {
                if let Err(error) = proxy
                    .call_method("AddBlob", &(BLOB_CLIENT_CERT, cert.as_slice()))
                    .await
                {
                    self.remove_owned_blobs(proxy).await;
                    return Err(dbus_error(error));
                }
                refs.client_cert = Some(BLOB_CLIENT_CERT.to_owned());
            }
        }
        if let Some(key) = &request.secrets.private_key {
            if let Err(error) = proxy
                .call_method("AddBlob", &(BLOB_PRIVATE_KEY, key.expose().as_bytes()))
                .await
            {
                self.remove_owned_blobs(proxy).await;
                return Err(dbus_error(error));
            }
            refs.private_key = Some(BLOB_PRIVATE_KEY.to_owned());
        }
        Ok(refs)
    }

    async fn remove_owned_blobs(&self, proxy: &zbus::Proxy<'static>) {
        for name in OWNED_BLOBS {
            let _ = proxy.call_method("RemoveBlob", &(name,)).await;
        }
    }

    /// Removes every network block on an interface that Kestrel added, plus
    /// any Kestrel-owned 802.1X blobs.
    async fn remove_owned_networks(&self, path: &OwnedObjectPath) -> PortResult<()> {
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        let networks: Vec<OwnedObjectPath> =
            proxy.get_property("Networks").await.map_err(dbus_error)?;
        for network in networks {
            let owned = match self.proxy(network.as_str(), NETWORK).await {
                Ok(network) => network
                    .get_property::<HashMap<String, OwnedValue>>("Properties")
                    .await
                    .ok()
                    .and_then(|props| {
                        props
                            .get("id_str")
                            .and_then(|v| String::try_from(v.clone()).ok())
                    })
                    .is_some_and(|tag| tag.trim_matches('"') == OWNER_TAG),
                Err(_) => false,
            };
            if owned {
                match proxy.call_method("RemoveNetwork", &(network,)).await {
                    Ok(_) => {}
                    Err(error) if error.to_string().contains("NetworkUnknown") => {}
                    Err(error) => return Err(dbus_error(error)),
                }
            }
        }
        self.remove_owned_blobs(&proxy).await;
        Ok(())
    }
}

#[async_trait]
impl WlanProvider for WpaSupplicant {
    fn name(&self) -> &'static str {
        "wpa_supplicant"
    }

    fn subscribe(&self) -> Subscription<WlanEvent> {
        self.inner.events.subscribe()
    }

    async fn devices(&self) -> PortResult<Vec<WlanDevice>> {
        let state = self.lock();
        let mut devices: Vec<WlanDevice> = state
            .interfaces
            .values()
            .filter(|iface| iface.role == Role::Station)
            .map(|iface| Self::device_for(&state, &iface.ifname, None))
            .collect();
        devices.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(devices)
    }

    async fn start_scan(&self, device: &InterfaceName) -> PortResult<()> {
        let path = self.station_path(device)?;
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        let args: HashMap<&str, Value<'_>> = HashMap::from([("Type", Value::from("active"))]);
        match proxy.call_method("Scan", &(args,)).await {
            Ok(_) => Ok(()),
            Err(error) => {
                let scanning: bool = proxy.get_property("Scanning").await.unwrap_or(false);
                if scanning {
                    Ok(())
                } else {
                    Err(dbus_error(error))
                }
            }
        }
    }

    async fn connect(&self, device: &InterfaceName, request: ConnectRequest) -> PortResult<()> {
        let path = self.station_path(device)?;
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        let supported_key_mgmt = self
            .lock()
            .iface_caps
            .get(device)
            .map(|caps| caps.key_mgmt.clone())
            .unwrap_or_default();
        let system_ca = if request
            .enterprise
            .as_ref()
            .is_some_and(|ent| ent.config.system_ca && ent.ca_cert_pem.is_none())
        {
            system_ca_path().await
        } else {
            None
        };
        self.lock().ap_active.remove(device);
        self.remove_owned_networks(&path).await?;
        let blobs = self.upload_blobs(&proxy, &request).await?;
        let args = match network_args(&request, &blobs, &supported_key_mgmt, system_ca) {
            Ok(args) => args,
            Err(error) => {
                self.remove_owned_blobs(&proxy).await;
                return Err(error);
            }
        };
        let reply = match proxy.call_method("AddNetwork", &(args,)).await {
            Ok(reply) => reply,
            Err(error) => {
                self.remove_owned_blobs(&proxy).await;
                return Err(dbus_error(error));
            }
        };
        let network: OwnedObjectPath = reply.body().deserialize().map_err(dbus_error)?;
        if let Err(error) = proxy
            .call_method("SelectNetwork", &(network.clone(),))
            .await
        {
            let _ = proxy.call_method("RemoveNetwork", &(network,)).await;
            self.remove_owned_blobs(&proxy).await;
            return Err(dbus_error(error));
        }
        self.refresh_link(&path).await;
        Ok(())
    }

    async fn disconnect(&self, device: &InterfaceName) -> PortResult<()> {
        let Ok(path) = self.station_path(device) else {
            return Ok(());
        };
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        match proxy.call_method("Disconnect", &()).await {
            Ok(_) => {}
            Err(error) if error.to_string().contains("NotConnected") => {}
            Err(error) => return Err(dbus_error(error)),
        }
        self.remove_owned_networks(&path).await
    }

    async fn link_status(&self, device: &InterfaceName) -> PortResult<LinkStatus> {
        let path = self.station_path(device)?;
        self.read_link(&path).await
    }

    async fn sweep(&self) -> PortResult<()> {
        let interfaces: Vec<(OwnedObjectPath, Iface)> = self
            .lock()
            .interfaces
            .iter()
            .map(|(path, iface)| (path.clone(), iface.clone()))
            .collect();
        for (path, iface) in interfaces {
            match iface.role {
                Role::Station => {
                    self.lock().ap_active.remove(&iface.ifname);
                    if let Err(error) = self.remove_owned_networks(&path).await {
                        tracing::warn!(device = %iface.ifname, %error, "sweep: cannot remove networks");
                    }
                    self.remove_all_persistent_groups(&path).await;
                }
                Role::P2pGroup(_) => {
                    tracing::warn!(group = %iface.ifname, "sweep: removing leftover P2P group");
                    if let Ok(proxy) = self.proxy(path.as_str(), P2P_DEVICE).await {
                        let _ = proxy.call_method("Disconnect", &()).await;
                    }
                }
                Role::P2pDevice(_) => {
                    self.remove_all_persistent_groups(&path).await;
                }
            }
        }
        Ok(())
    }

    fn p2p(&self) -> Option<Arc<dyn P2pProvider>> {
        // Always expose the P2P sub-port so late-starting `wpa_supplicant`
        // instances still work; per-device `capabilities.p2p` gates usage.
        Some(Arc::new(self.clone()) as Arc<dyn P2pProvider>)
    }

    fn ap(&self) -> Option<Arc<dyn ApProvider>> {
        // Always expose the SoftAP sub-port so late-starting `wpa_supplicant`
        // instances still work; per-device `capabilities.access_point` gates usage.
        Some(Arc::new(self.clone()) as Arc<dyn ApProvider>)
    }
}

#[async_trait]
impl ApProvider for WpaSupplicant {
    fn subscribe(&self) -> Subscription<ApEvent> {
        self.inner.ap_events.subscribe()
    }

    async fn start_ap(&self, device: &InterfaceName, request: &ApStartRequest) -> PortResult<()> {
        let path = self.station_path(device)?;
        let ap_supported = self
            .lock()
            .iface_caps
            .get(device)
            .is_some_and(|c| c.capabilities.access_point);
        if !ap_supported {
            return Err(PortError::NotSupported(format!(
                "{device} does not support AP mode"
            )));
        }
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        self.remove_owned_networks(&path).await?;
        let freq = request.frequency.unwrap_or(2412);
        let args = ap_network_args(request);
        let reply = proxy
            .call_method("AddNetwork", &(args,))
            .await
            .map_err(dbus_error)?;
        let network: OwnedObjectPath = reply.body().deserialize().map_err(dbus_error)?;
        self.lock()
            .ap_active
            .insert(device.clone(), ApState::Starting(freq));
        if let Err(error) = proxy
            .call_method("SelectNetwork", &(network.clone(),))
            .await
        {
            self.lock().ap_active.remove(device);
            let _ = proxy.call_method("RemoveNetwork", &(network,)).await;
            return Err(dbus_error(error));
        }
        // If `SelectNetwork` completed synchronously (e.g. fast driver/fake)
        // before PropertiesChanged was processed, refresh once. While still
        // `ApState::Starting`, an initial `"disconnected"`/`"inactive"` state
        // is ignored so async AP bring-up is not prematurely aborted.
        self.refresh_link(&path).await;
        Ok(())
    }

    async fn stop_ap(&self, device: &InterfaceName) -> PortResult<()> {
        let was_active = self.lock().ap_active.remove(device).is_some();
        let Ok(path) = self.station_path(device) else {
            return Ok(());
        };
        let proxy = self.proxy(path.as_str(), INTERFACE).await?;
        match proxy.call_method("Disconnect", &()).await {
            Ok(_) => {}
            Err(error) if error.to_string().contains("NotConnected") => {}
            Err(error) => return Err(dbus_error(error)),
        }
        self.remove_owned_networks(&path).await?;
        if was_active {
            self.inner.ap_events.publish(&ApEvent::Stopped {
                device: device.clone(),
            });
        }
        Ok(())
    }
}

fn supported_security_from_key_mgmt(suites: &[String]) -> Vec<ProfileSecurity> {
    let has = |name: &str| suites.iter().any(|s| s.eq_ignore_ascii_case(name));
    let mut out = vec![ProfileSecurity::Open];
    if has("owe") {
        out.push(ProfileSecurity::Owe);
    }
    if has("wpa-psk") || has("wpa-psk-sha256") || has("sae") {
        out.push(ProfileSecurity::WpaPersonal);
    }
    if has("sae") || has("sae-ext-key") {
        out.push(ProfileSecurity::Wpa3Personal);
    }
    if has("wpa-eap") || has("wpa-eap-sha256") {
        out.push(ProfileSecurity::WpaEnterprise);
    }
    if has("wpa-eap-sha256") || has("wpa-eap-suite-b-192") {
        out.push(ProfileSecurity::Wpa3Enterprise);
    }
    out
}

/// Maximum length of a Linux network interface name (`IFNAMSIZ - 1`).
const MAX_IFNAME_LEN: usize = 15;

/// `p2p-dev-wlan0` is the P2P management interface of `wlan0`;
/// `p2p-wlan0-0` is a group interface of `wlan0`; anything else is a
/// station.
pub(crate) fn role_for(ifname: &InterfaceName) -> Role {
    let name = ifname.as_str();
    if let Some(parent) = name.strip_prefix("p2p-dev-")
        && let Ok(parent) = InterfaceName::new(parent)
    {
        return Role::P2pDevice(parent);
    }
    if let Some(rest) = name.strip_prefix("p2p-")
        && let Some((parent, index)) = rest.rsplit_once('-')
        && !index.is_empty()
        && index.bytes().all(|b| b.is_ascii_digit())
        && let Ok(parent) = InterfaceName::new(parent)
    {
        return Role::P2pGroup(parent);
    }
    Role::Station
}

/// Whether a P2P interface (`p2p-dev-<parent>` or `p2p-<parent>-<n>`)
/// belongs to `station`.
pub(crate) fn matches_station(
    station: &InterfaceName,
    parent: &InterfaceName,
    p2p_ifname: &InterfaceName,
) -> bool {
    station == parent
        || (p2p_ifname.as_str().len() == MAX_IFNAME_LEN
            && station.as_str().starts_with(parent.as_str()))
}

pub(crate) fn mac_from_bytes(bytes: &[u8]) -> Option<MacAddress> {
    <[u8; 6]>::try_from(bytes).ok().map(MacAddress::from_octets)
}

pub(crate) async fn read_sysfs_mac(sysfs: &Path, ifname: &InterfaceName) -> Option<MacAddress> {
    let path = sysfs.join(ifname.as_str()).join("address");
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .and_then(|text| MacAddress::parse(text.trim()).ok())
}

fn sysfs_stations(sysfs: &Path) -> Vec<InterfaceName> {
    let Ok(entries) = std::fs::read_dir(sysfs) else {
        return Vec::new();
    };
    let mut stations: Vec<InterfaceName> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.join("wireless").exists() && !path.join("phy80211").exists() {
                return None;
            }
            let name = entry.file_name().into_string().ok()?;
            let ifname = InterfaceName::new(name).ok()?;
            (role_for(&ifname) == Role::Station).then_some(ifname)
        })
        .collect();
    stations.sort();
    stations
}

fn key_mgmt(dict: &HashMap<String, OwnedValue>) -> Vec<String> {
    dict.get("KeyMgmt")
        .and_then(|value| Vec::<String>::try_from(value.clone()).ok())
        .unwrap_or_default()
}

pub(crate) fn dbus_error(error: impl fmt::Display) -> PortError {
    let text = error.to_string();
    if text.contains("AccessDenied") || text.contains("PermissionDenied") {
        PortError::PermissionDenied(text)
    } else if text.contains("ServiceUnknown") || text.contains("NameHasNoOwner") {
        PortError::Unavailable(format!("wpa_supplicant is not running: {text}"))
    } else if text.contains("UnknownObject") || text.contains("InterfaceUnknown") {
        PortError::NotFound(text)
    } else if text.contains("InvalidArgs") {
        PortError::InvalidArgument(text)
    } else {
        PortError::Backend(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> InterfaceName {
        InterfaceName::new(value).unwrap()
    }

    #[test]
    fn classifies_interface_roles() {
        assert_eq!(role_for(&name("wlan0")), Role::Station);
        assert_eq!(
            role_for(&name("p2p-dev-wlan0")),
            Role::P2pDevice(name("wlan0"))
        );
        assert_eq!(
            role_for(&name("p2p-wlan0-3")),
            Role::P2pGroup(name("wlan0"))
        );
        assert_eq!(role_for(&name("p2p-wlan0-x")), Role::Station);
    }

    #[test]
    fn matches_truncated_p2p_interface_names_to_stations() {
        assert!(matches_station(
            &name("wlp0s20f3"),
            &name("wlp0s20"),
            &name("p2p-dev-wlp0s20")
        ));
        assert!(matches_station(
            &name("wlx40c73cceba9e"),
            &name("wlx40c73c"),
            &name("p2p-wlx40c73c-0")
        ));
        assert!(!matches_station(
            &name("wlan00"),
            &name("wlan0"),
            &name("p2p-dev-wlan0")
        ));
    }
}

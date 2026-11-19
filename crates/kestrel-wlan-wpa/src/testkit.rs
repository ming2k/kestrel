// SPDX-License-Identifier: LGPL-2.1-or-later

//! A fake `fi.w1.wpa_supplicant1` service.
//!
//! It implements the subset of the real API that the adapter uses, with
//! the same object layout, property names, and signals, including P2P.
//! Tests script the radio side through [`FakeWpa`] methods, or over D-Bus
//! through the `com.hihusky.Kestrel.Testing.FakeWpa` control interface at
//! `/com/hihusky/Kestrel/testing` (for tests where the fake runs as a separate
//! process).

#![allow(
    clippy::assigning_clones,
    clippy::format_collect,
    clippy::unused_async_trait_impl,
    clippy::used_underscore_binding,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::unused_async,
    clippy::unused_self,
    clippy::too_many_lines,
    missing_docs
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zbus::fdo;
use zbus::object_server::SignalEmitter;
use zbus::{OwnedObjectPath, OwnedVariant as OwnedValue, Variant as Value};

const SERVICE: &str = "fi.w1.wpa_supplicant1";
const MAIN_PATH: &str = "/fi/w1/wpa_supplicant1";
const CONTROL_PATH: &str = "/com/hihusky/Kestrel/testing";

type Dict = HashMap<String, OwnedValue>;

fn path(value: impl Into<String>) -> OwnedObjectPath {
    OwnedObjectPath::try_from(value.into()).expect("valid object path")
}

fn ov(value: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(value).expect("owned value")
}

/// The group interface `wpa_supplicant` derives from a P2P device.
fn group_ifname(device: &str) -> String {
    let parent = device.strip_prefix("p2p-dev-").unwrap_or(device);
    format!("p2p-{parent}-0")
}

#[derive(Debug, Clone)]
struct Ap {
    ssid: Vec<u8>,
    bssid: [u8; 6],
    rsn: Vec<String>,
    password: Option<String>,
    path: OwnedObjectPath,
}

#[derive(Debug, Clone)]
struct Iface {
    ifname: String,
    state: String,
    current_bss: OwnedObjectPath,
    current_network: OwnedObjectPath,
    networks: Vec<OwnedObjectPath>,
    blobs: HashMap<String, Vec<u8>>,
    /// For group interfaces: the parent device path and our role.
    group_of: Option<(OwnedObjectPath, bool)>,
}

#[derive(Debug, Clone)]
struct Network {
    ssid: Vec<u8>,
    mode: u32,
    secret: Option<String>,
    id_str: Option<String>,
    key_mgmt: String,
}

#[derive(Debug, Clone)]
struct Peer {
    address: [u8; 6],
    name: String,
}

#[derive(Debug, Default)]
struct State {
    next_iface: u32,
    next_network: u32,
    next_bss: u32,
    next_pg: u32,
    ifaces: HashMap<OwnedObjectPath, Iface>,
    aps: Vec<Ap>,
    networks: HashMap<OwnedObjectPath, Network>,
    persistent_groups: HashMap<OwnedObjectPath, Dict>,
    peers: HashMap<OwnedObjectPath, Peer>,
    calls: Vec<String>,
    device_name: Option<String>,
}

impl State {
    fn iface_by_name(&self, ifname: &str) -> Option<OwnedObjectPath> {
        self.ifaces
            .iter()
            .find(|(_, iface)| iface.ifname == ifname)
            .map(|(path, _)| path.clone())
    }
}

/// A running fake `wpa_supplicant`.
#[derive(Debug, Clone)]
pub struct FakeWpa {
    connection: zbus::Connection,
    state: Arc<Mutex<State>>,
}

impl FakeWpa {
    /// Serves the fake on the bus at `address`, with one station per name.
    pub async fn start(address: &str, stations: &[&str]) -> zbus::Result<Self> {
        let connection = zbus::connection::Builder::address(address).build().await?;
        Self::serve(connection, stations).await
    }

    /// Serves the fake on an existing connection.
    pub async fn serve(connection: zbus::Connection, stations: &[&str]) -> zbus::Result<Self> {
        let state = Arc::new(Mutex::new(State::default()));
        let fake = Self { connection, state };
        let server = fake.connection.object_server();
        server.at(MAIN_PATH, Main { fake: fake.clone() }).await?;
        server
            .at(CONTROL_PATH, Control { fake: fake.clone() })
            .await?;
        for station in stations {
            fake.add_interface(station, None).await?;
        }
        fake.connection.request_name(SERVICE).await?;
        Ok(fake)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("fake wpa state")
    }

    fn record(&self, call: impl Into<String>) {
        self.lock().calls.push(call.into());
    }

    /// Every method call received, in order, as short strings.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    /// Network blocks currently configured on all interfaces.
    pub fn network_count(&self) -> usize {
        self.lock().networks.len()
    }

    pub fn state_of(&self, ifname: &str) -> Option<String> {
        let state = self.lock();
        let path = state.iface_by_name(ifname)?;
        Some(state.ifaces[&path].state.clone())
    }

    pub fn interface_names(&self) -> Vec<String> {
        self.lock()
            .ifaces
            .values()
            .map(|i| i.ifname.clone())
            .collect()
    }

    pub fn device_name(&self) -> Option<String> {
        self.lock().device_name.clone()
    }

    /// Adds an access point. `security` is `open`, `wpa2`, `wpa3`, or
    /// `transition`.
    pub async fn add_access_point(
        &self,
        ssid: &str,
        password: Option<&str>,
        security: &str,
    ) -> zbus::Result<()> {
        let rsn: Vec<String> = match security {
            "open" => vec![],
            "wpa3" => vec!["sae".into()],
            "transition" => vec!["wpa-psk".into(), "sae".into()],
            "enterprise" => vec!["wpa-eap".into()],
            "wpa3-enterprise" => vec!["wpa-eap-sha256".into()],
            _ => vec!["wpa-psk".into()],
        };
        let (ap, station_paths) = {
            let mut state = self.lock();
            state.next_bss += 1;
            let n = state.next_bss;
            let ap = Ap {
                ssid: ssid.as_bytes().to_vec(),
                bssid: [2, 0, 0, 0, 1, u8::try_from(n % 255).unwrap_or(0)],
                rsn,
                password: password.map(str::to_owned),
                path: path(format!("{MAIN_PATH}/BSSs/{n}")),
            };
            state.aps.push(ap.clone());
            let stations: Vec<OwnedObjectPath> = state
                .ifaces
                .iter()
                .filter(|(_, i)| i.group_of.is_none())
                .map(|(p, _)| p.clone())
                .collect();
            (ap, stations)
        };
        self.connection
            .object_server()
            .at(ap.path.clone(), FakeBss { ap: ap.clone() })
            .await?;
        let _ = station_paths;
        Ok(())
    }

    /// Adds a configured network that Kestrel did not create.
    pub fn add_foreign_network(&self, ifname: &str) -> OwnedObjectPath {
        let mut state = self.lock();
        state.next_network += 1;
        let network = path(format!("{MAIN_PATH}/Networks/{}", state.next_network));
        state.networks.insert(
            network.clone(),
            Network {
                ssid: b"foreign".to_vec(),
                mode: 0,
                secret: None,
                id_str: None,
                key_mgmt: "WPA-PSK".into(),
            },
        );
        let iface = state.iface_by_name(ifname).expect("known interface");
        state
            .ifaces
            .get_mut(&iface)
            .unwrap()
            .networks
            .push(network.clone());
        network
    }

    pub fn blob_names(&self, ifname: &str) -> Vec<String> {
        let state = self.lock();
        let Some(path) = state.iface_by_name(ifname) else {
            return Vec::new();
        };
        let mut names: Vec<String> = state.ifaces[&path].blobs.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn persistent_group_count(&self) -> usize {
        self.lock().persistent_groups.len()
    }

    pub async fn authorize_sta(&self, ifname: &str, mac: &str) -> zbus::Result<()> {
        let path = self.lock().iface_by_name(ifname).expect("known iface");
        let emitter = SignalEmitter::new(&self.connection, path)?;
        FakeInterface::sta_authorized(&emitter, mac).await
    }

    pub async fn emit_persistent_group(
        &self,
        device: &str,
        ssid: &str,
        go_address: &str,
        psk: &str,
        go: bool,
    ) -> zbus::Result<()> {
        let device_path = self.lock().iface_by_name(device).expect("known device");
        let pg_path = path(format!("{}/PersistentGroups/0", device_path.as_str()));
        let props: HashMap<&str, Value<'_>> = HashMap::from([
            ("ssid", Value::from(ssid.as_bytes().to_vec())),
            ("bssid", Value::from(go_address)),
            ("psk", Value::from(psk)),
            ("mode", Value::from(if go { 3u32 } else { 0u32 })),
        ]);
        let emitter = SignalEmitter::new(&self.connection, device_path)?;
        FakeP2p::persistent_group_added(&emitter, pg_path, props).await
    }

    pub fn add_peer(&self, address: [u8; 6], name: &str) -> OwnedObjectPath {
        let mut state = self.lock();
        let device = state
            .ifaces
            .iter()
            .find(|(_, i)| i.ifname.starts_with("p2p-dev-"))
            .or_else(|| state.ifaces.iter().find(|(_, i)| i.group_of.is_none()))
            .map(|(p, _)| p.clone())
            .expect("a station");
        let hex: String = address.iter().map(|b| format!("{b:02x}")).collect();
        let peer = path(format!("{}/Peers/{hex}", device.as_str()));
        state.peers.insert(
            peer.clone(),
            Peer {
                address,
                name: name.to_owned(),
            },
        );
        peer
    }

    async fn add_interface(
        &self,
        ifname: &str,
        group_of: Option<(OwnedObjectPath, bool)>,
    ) -> zbus::Result<OwnedObjectPath> {
        let iface_path = {
            let mut state = self.lock();
            let n = state.next_iface;
            state.next_iface += 1;
            let iface_path = path(format!("{MAIN_PATH}/Interfaces/{n}"));
            state.ifaces.insert(
                iface_path.clone(),
                Iface {
                    ifname: ifname.to_owned(),
                    state: if group_of.is_some() {
                        "completed"
                    } else {
                        "disconnected"
                    }
                    .to_owned(),
                    current_bss: path("/"),
                    current_network: path("/"),
                    networks: Vec::new(),
                    blobs: HashMap::new(),
                    group_of,
                },
            );
            iface_path
        };
        let server = self.connection.object_server();
        server
            .at(
                iface_path.clone(),
                FakeInterface {
                    fake: self.clone(),
                    path: iface_path.clone(),
                },
            )
            .await?;
        server
            .at(
                iface_path.clone(),
                FakeP2p {
                    fake: self.clone(),
                    path: iface_path.clone(),
                },
            )
            .await?;
        server
            .at(iface_path.clone(), FakeWps { fake: self.clone() })
            .await?;
        let emitter = SignalEmitter::new(&self.connection, MAIN_PATH)?;
        Main::interface_added(&emitter, iface_path.clone(), HashMap::new()).await?;
        Ok(iface_path)
    }

    async fn remove_interface(&self, iface_path: &OwnedObjectPath) -> zbus::Result<()> {
        let server = self.connection.object_server();
        let _ = server.remove::<FakeInterface, _>(iface_path.clone()).await;
        let _ = server.remove::<FakeP2p, _>(iface_path.clone()).await;
        let _ = server.remove::<FakeWps, _>(iface_path.clone()).await;
        self.lock().ifaces.remove(iface_path);
        let emitter = SignalEmitter::new(&self.connection, MAIN_PATH)?;
        Main::interface_removed(&emitter, iface_path.clone()).await
    }

    async fn emit_state(&self, iface_path: &OwnedObjectPath) -> zbus::Result<()> {
        let (state_str, current_bss) = {
            let state = self.lock();
            let Some(iface) = state.ifaces.get(iface_path) else {
                return Ok(());
            };
            (iface.state.clone(), iface.current_bss.clone())
        };
        let emitter = SignalEmitter::new(&self.connection, iface_path.clone())?;
        // Real `wpa_supplicant` emits `fi.w1.wpa_supplicant1.Interface.PropertiesChanged(a{sv})`,
        // not `org.freedesktop.DBus.Properties.PropertiesChanged`.
        let props = HashMap::from([
            ("State", Value::from(state_str.as_str())),
            ("CurrentBSS", Value::from(current_bss.as_ref())),
        ]);
        FakeInterface::properties_changed(&emitter, props).await
    }

    /// Emits `count` rapid `Interface.PropertiesChanged` signals to stress
    /// signal-stream backpressure and verify deadlock immunity.
    pub async fn flood_properties_changed(&self, device: &str, count: usize) -> zbus::Result<()> {
        let iface_path = self.lock().iface_by_name(device).expect("known device");
        let emitter = SignalEmitter::new(&self.connection, iface_path)?;
        for i in 0..count {
            let props = HashMap::from([(
                "DisconnectReason",
                Value::from(i32::try_from(i).unwrap_or(0)),
            )]);
            FakeInterface::properties_changed(&emitter, props).await?;
        }
        Ok(())
    }

    async fn set_state(
        &self,
        iface_path: &OwnedObjectPath,
        value: &str,
        bss: Option<OwnedObjectPath>,
    ) -> zbus::Result<()> {
        {
            let mut state = self.lock();
            let Some(iface) = state.ifaces.get_mut(iface_path) else {
                return Ok(());
            };
            iface.state = value.to_owned();
            iface.current_bss = bss.unwrap_or_else(|| path("/"));
        }
        self.emit_state(iface_path).await
    }

    /// The AP drops the station.
    pub async fn drop_link(&self, ifname: &str) -> zbus::Result<()> {
        let iface = self.lock().iface_by_name(ifname).expect("known interface");
        self.set_state(&iface, "disconnected", None).await
    }

    /// Completes GO negotiation and starts a group, as `wpa_supplicant` does
    /// after a successful P2P connect.
    pub async fn start_group(
        &self,
        device: &str,
        group_ifname: &str,
        go: bool,
    ) -> zbus::Result<()> {
        let device_path = self.lock().iface_by_name(device).expect("known device");
        let emitter = SignalEmitter::new(&self.connection, device_path)?;
        let role_go: i32 = i32::from(go);
        FakeP2p::go_negotiation_success(
            &emitter,
            HashMap::from([("role_go", Value::from(role_go))]),
        )
        .await?;
        self.emit_group_started(device, group_ifname, go).await
    }

    /// Starts a group without GO negotiation, as `wpa_supplicant` does after
    /// `P2PDevice.GroupAdd` (autonomous GO).
    pub async fn start_autonomous_group(
        &self,
        device: &str,
        group_ifname: &str,
    ) -> zbus::Result<()> {
        self.emit_group_started(device, group_ifname, true).await
    }

    async fn emit_group_started(
        &self,
        device: &str,
        group_ifname: &str,
        go: bool,
    ) -> zbus::Result<()> {
        let device_path = self.lock().iface_by_name(device).expect("known device");
        let emitter = SignalEmitter::new(&self.connection, device_path.clone())?;
        let role = if go { "GO" } else { "client" };
        let group = self
            .add_interface(group_ifname, Some((device_path, go)))
            .await?;
        FakeP2p::group_started(
            &emitter,
            HashMap::from([
                ("interface_object", Value::from(group.clone())),
                (
                    "group_object",
                    Value::from(path(format!("{}/Groups/0", group.as_str()))),
                ),
                ("role", Value::from(role)),
            ]),
        )
        .await
    }

    /// The peer ends the group.
    pub async fn finish_group(&self, group_ifname: &str) -> zbus::Result<()> {
        let (group, parent, go) = {
            let state = self.lock();
            let Some(group) = state.iface_by_name(group_ifname) else {
                return Ok(());
            };
            let (parent, go) = state.ifaces[&group].group_of.clone().expect("a group");
            (group, parent, go)
        };
        let emitter = SignalEmitter::new(&self.connection, parent)?;
        FakeP2p::group_finished(
            &emitter,
            HashMap::from([
                ("interface_object", Value::from(group.clone())),
                ("role", Value::from(if go { "GO" } else { "client" })),
            ]),
        )
        .await?;
        self.remove_interface(&group).await
    }

    pub async fn fail_negotiation(&self, device: &str, status: i32) -> zbus::Result<()> {
        let device = self.lock().iface_by_name(device).expect("known device");
        let emitter = SignalEmitter::new(&self.connection, device)?;
        FakeP2p::go_negotiation_failure(&emitter, HashMap::from([("status", Value::from(status))]))
            .await
    }

    pub async fn request_negotiation(
        &self,
        device: &str,
        peer: [u8; 6],
        password_id: u16,
    ) -> zbus::Result<()> {
        let device_path = self.lock().iface_by_name(device).expect("known device");
        let hex: String = peer.iter().map(|b| format!("{b:02x}")).collect();
        let emitter = SignalEmitter::new(&self.connection, device_path.clone())?;
        FakeP2p::go_negotiation_request(
            &emitter,
            path(format!("{}/Peers/{hex}", device_path.as_str())),
            password_id,
            7,
        )
        .await
    }

    /// Simulates `wpa_supplicant` exiting.
    pub async fn vanish(&self) -> zbus::Result<()> {
        self.connection.release_name(SERVICE).await.map(|_| ())
    }

    pub async fn reappear(&self) -> zbus::Result<()> {
        self.connection.request_name(SERVICE).await
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Main {
    fake: FakeWpa,
}

#[zbus::interface(name = "fi.w1.wpa_supplicant1")]
impl Main {
    #[zbus(property)]
    fn interfaces(&self) -> Vec<OwnedObjectPath> {
        let mut paths: Vec<OwnedObjectPath> = self.fake.lock().ifaces.keys().cloned().collect();
        paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        paths
    }

    #[zbus(property)]
    fn capabilities(&self) -> Vec<String> {
        vec!["ap".into(), "p2p".into()]
    }

    #[zbus(property, name = "WFDIEs")]
    fn wfd_ies(&self) -> Vec<u8> {
        Vec::new()
    }

    #[zbus(property, name = "WFDIEs")]
    fn set_wfd_ies(&mut self, _value: Vec<u8>) {
        self.fake.record("SetWFDIEs");
    }

    async fn create_interface(&self, args: Dict) -> fdo::Result<OwnedObjectPath> {
        let ifname = args
            .get("Ifname")
            .and_then(|v| String::try_from(v.clone()).ok())
            .ok_or_else(|| fdo::Error::InvalidArgs("Ifname is required".into()))?;
        self.fake.record(format!("CreateInterface {ifname}"));
        if self.fake.lock().iface_by_name(&ifname).is_some() {
            return Err(fdo::Error::Failed(
                "fi.w1.wpa_supplicant1.InterfaceExists".into(),
            ));
        }
        self.fake.add_interface(&ifname, None).await.map_err(failed)
    }

    fn get_interface(&self, ifname: String) -> fdo::Result<OwnedObjectPath> {
        self.fake
            .lock()
            .iface_by_name(&ifname)
            .ok_or_else(|| fdo::Error::Failed("fi.w1.wpa_supplicant1.InterfaceUnknown".into()))
    }

    #[zbus(signal)]
    async fn interface_added(
        emitter: &SignalEmitter<'_>,
        path: OwnedObjectPath,
        properties: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn interface_removed(
        emitter: &SignalEmitter<'_>,
        path: OwnedObjectPath,
    ) -> zbus::Result<()>;
}

#[derive(Debug)]
struct FakeInterface {
    fake: FakeWpa,
    path: OwnedObjectPath,
}

impl FakeInterface {
    fn iface(&self) -> Iface {
        self.fake
            .lock()
            .ifaces
            .get(&self.path)
            .cloned()
            .expect("live interface")
    }
}

#[zbus::interface(name = "fi.w1.wpa_supplicant1.Interface")]
impl FakeInterface {
    #[zbus(property)]
    fn ifname(&self) -> String {
        self.iface().ifname
    }

    #[zbus(property)]
    fn state(&self) -> String {
        self.iface().state
    }

    #[zbus(property)]
    fn scanning(&self) -> bool {
        false
    }

    #[zbus(property, name = "BSSs")]
    fn bsss(&self) -> Vec<OwnedObjectPath> {
        self.fake
            .lock()
            .aps
            .iter()
            .map(|ap| ap.path.clone())
            .collect()
    }

    #[zbus(property, name = "CurrentBSS")]
    fn current_bss(&self) -> OwnedObjectPath {
        self.iface().current_bss
    }

    #[zbus(property)]
    fn networks(&self) -> Vec<OwnedObjectPath> {
        self.iface().networks
    }

    async fn scan(
        &self,
        _args: Dict,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        self.fake.record("Scan");
        Self::scan_done(&emitter, true)
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    async fn add_network(
        &self,
        args: Dict,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> fdo::Result<OwnedObjectPath> {
        let ssid = args
            .get("ssid")
            .and_then(|v| Vec::<u8>::try_from(v.clone()).ok())
            .ok_or_else(|| fdo::Error::InvalidArgs("ssid is required".into()))?;
        let secret = ["psk", "sae_password", "password"].iter().find_map(|key| {
            args.get(*key)
                .and_then(|v| String::try_from(v.clone()).ok())
        });
        let mode = args
            .get("mode")
            .and_then(|v| u32::try_from(v.clone()).ok())
            .unwrap_or(0);
        let id_str = args
            .get("id_str")
            .and_then(|v| String::try_from(v.clone()).ok());
        let key_mgmt = args
            .get("key_mgmt")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();
        self.fake.record(format!("AddNetwork key_mgmt={key_mgmt}"));
        let network = {
            let mut state = self.fake.lock();
            state.next_network += 1;
            let network = path(format!("{MAIN_PATH}/Networks/{}", state.next_network));
            state.networks.insert(
                network.clone(),
                Network {
                    ssid,
                    mode,
                    secret,
                    id_str,
                    key_mgmt,
                },
            );
            state
                .ifaces
                .get_mut(&self.path)
                .expect("live interface")
                .networks
                .push(network.clone());
            network
        };
        server
            .at(
                network.clone(),
                FakeNetwork {
                    fake: self.fake.clone(),
                    path: network.clone(),
                },
            )
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        Ok(network)
    }

    async fn select_network(
        &self,
        network: OwnedObjectPath,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        self.fake.record("SelectNetwork");
        let (target, ap) = {
            let mut state = self.fake.lock();
            let target =
                state.networks.get(&network).cloned().ok_or_else(|| {
                    fdo::Error::Failed("fi.w1.wpa_supplicant1.NetworkUnknown".into())
                })?;
            let ap = state.aps.iter().find(|ap| ap.ssid == target.ssid).cloned();
            let iface = state.ifaces.get_mut(&self.path).expect("live interface");
            iface.current_network = network.clone();
            iface.state = "associating".into();
            (target, ap)
        };
        self.fake
            .emit_state(&self.path)
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        if target.mode == 2 {
            self.fake
                .set_state(&self.path, "completed", None)
                .await
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
            return Ok(());
        }
        let Some(ap) = ap else {
            // Not in range: keeps scanning until the caller gives up.
            self.fake
                .set_state(&self.path, "scanning", None)
                .await
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
            return Ok(());
        };
        let accepted = ap.password.is_none() || ap.password == target.secret;
        if accepted {
            self.fake
                .set_state(&self.path, "completed", Some(ap.path.clone()))
                .await
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        } else {
            self.fake
                .set_state(&self.path, "4way_handshake", None)
                .await
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
            if target.key_mgmt.contains("WPA-EAP") {
                Self::eap(&emitter, "completion", "fail")
                    .await
                    .map_err(|e| fdo::Error::Failed(e.to_string()))?;
            } else {
                Self::psk_mismatch(&emitter)
                    .await
                    .map_err(|e| fdo::Error::Failed(e.to_string()))?;
            }
            self.fake
                .set_state(&self.path, "disconnected", None)
                .await
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        }
        Ok(())
    }

    async fn remove_network(
        &self,
        network: OwnedObjectPath,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> fdo::Result<()> {
        self.fake.record("RemoveNetwork");
        let was_current = {
            let mut state = self.fake.lock();
            if state.networks.remove(&network).is_none() {
                return Err(fdo::Error::Failed(
                    "fi.w1.wpa_supplicant1.NetworkUnknown".into(),
                ));
            }
            let iface = state.ifaces.get_mut(&self.path).expect("live interface");
            iface.networks.retain(|n| *n != network);
            let current = iface.current_network == network;
            if current {
                iface.current_network = path("/");
            }
            current
        };
        let _ = server.remove::<FakeNetwork, _>(network).await;
        if was_current {
            self.fake
                .set_state(&self.path, "disconnected", None)
                .await
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        }
        Ok(())
    }

    async fn disconnect(&self) -> fdo::Result<()> {
        self.fake.record("Disconnect");
        if self.iface().state == "disconnected" {
            return Err(fdo::Error::Failed(
                "fi.w1.wpa_supplicant1.NotConnected".into(),
            ));
        }
        self.fake
            .set_state(&self.path, "disconnected", None)
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    async fn add_blob(&self, name: String, data: Vec<u8>) -> fdo::Result<()> {
        self.fake.record(format!("AddBlob {name}"));
        let mut state = self.fake.lock();
        let iface = state.ifaces.get_mut(&self.path).expect("live interface");
        if iface.blobs.contains_key(&name) {
            return Err(fdo::Error::Failed(
                "fi.w1.wpa_supplicant1.BlobExists".into(),
            ));
        }
        iface.blobs.insert(name, data);
        Ok(())
    }

    async fn remove_blob(&self, name: String) -> fdo::Result<()> {
        self.fake.record(format!("RemoveBlob {name}"));
        let mut state = self.fake.lock();
        let iface = state.ifaces.get_mut(&self.path).expect("live interface");
        if iface.blobs.remove(&name).is_none() {
            return Err(fdo::Error::Failed(
                "fi.w1.wpa_supplicant1.BlobUnknown".into(),
            ));
        }
        Ok(())
    }

    #[zbus(signal, name = "PropertiesChanged")]
    async fn properties_changed(
        emitter: &SignalEmitter<'_>,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn scan_done(emitter: &SignalEmitter<'_>, success: bool) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn psk_mismatch(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal, name = "EAP")]
    async fn eap(emitter: &SignalEmitter<'_>, status: &str, parameter: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn sta_authorized(emitter: &SignalEmitter<'_>, name: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn sta_deauthorized(emitter: &SignalEmitter<'_>, name: &str) -> zbus::Result<()>;
}

#[derive(Debug)]
struct FakeWps {
    fake: FakeWpa,
}

#[zbus::interface(name = "fi.w1.wpa_supplicant1.Interface.WPS")]
impl FakeWps {
    async fn start(&self, args: Dict) -> fdo::Result<Dict> {
        let role = args
            .get("Role")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();
        let kind = args
            .get("Type")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();
        self.fake
            .record(format!("WPS.Start role={role} type={kind}"));
        Ok(Dict::new())
    }
}

#[derive(Debug)]
struct FakeP2p {
    fake: FakeWpa,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "fi.w1.wpa_supplicant1.Interface.P2PDevice")]
impl FakeP2p {
    #[zbus(property, name = "P2PDeviceConfig")]
    fn p2p_device_config(&self) -> Dict {
        let mut config = Dict::new();
        if let Some(name) = self.fake.lock().device_name.clone() {
            config.insert("DeviceName".into(), ov(Value::from(name)));
        }
        config
    }

    #[zbus(property, name = "P2PDeviceConfig")]
    fn set_p2p_device_config(&mut self, value: Dict) {
        if let Some(name) = value
            .get("DeviceName")
            .and_then(|v| String::try_from(v.clone()).ok())
        {
            self.fake.lock().device_name = Some(name);
        }
    }

    #[zbus(property)]
    fn peers(&self) -> Vec<OwnedObjectPath> {
        self.fake.lock().peers.keys().cloned().collect()
    }

    async fn find(
        &self,
        _args: Dict,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> fdo::Result<()> {
        self.fake.record("P2P.Find");
        let peers: Vec<(OwnedObjectPath, Peer)> = self
            .fake
            .lock()
            .peers
            .iter()
            .map(|(p, peer)| (p.clone(), peer.clone()))
            .collect();
        for (peer_path, peer) in peers {
            let _ = server.at(peer_path.clone(), FakePeer { peer }).await;
            Self::device_found(&emitter, peer_path)
                .await
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        }
        Ok(())
    }

    async fn stop_find(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        self.fake.record("P2P.StopFind");
        Self::find_stopped(&emitter)
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    async fn connect(&self, args: Dict) -> fdo::Result<String> {
        let method = args
            .get("wps_method")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();
        let intent = args
            .get("go_intent")
            .and_then(|v| i32::try_from(v.clone()).ok())
            .unwrap_or(-1);
        let peer = args
            .get("peer")
            .and_then(|v| OwnedObjectPath::try_from(v.clone()).ok())
            .map(|p| p.as_str().to_owned())
            .unwrap_or_default();
        let pin = args
            .get("pin")
            .and_then(|v| String::try_from(v.clone()).ok());
        self.fake.record(format!(
            "P2P.Connect peer={} method={method} go_intent={intent} pin={}",
            peer.rsplit('/').next().unwrap_or(""),
            pin.as_deref().unwrap_or("-")
        ));
        Ok(if method == "display" {
            "12345670".into()
        } else {
            String::new()
        })
    }

    async fn group_add(&self, args: Dict) -> fdo::Result<()> {
        let frequency = args
            .get("frequency")
            .and_then(|v| i32::try_from(v.clone()).ok())
            .unwrap_or(0);
        let device = self
            .fake
            .lock()
            .ifaces
            .get(&self.path)
            .map(|iface| iface.ifname.clone());
        self.fake
            .record(format!("P2P.GroupAdd frequency={frequency}"));
        if let Some(device) = device {
            let fake = self.fake.clone();
            // Emit after replying, as the real daemon starts the group
            // asynchronously.
            tokio::spawn(async move {
                let group_ifname = group_ifname(&device);
                let _ = fake.start_autonomous_group(&device, &group_ifname).await;
            });
        }
        Ok(())
    }

    async fn add_persistent_group(&self, args: Dict) -> fdo::Result<OwnedObjectPath> {
        let mut state = self.fake.lock();
        state.next_pg += 1;
        let pg_path = path(format!(
            "{}/PersistentGroups/{}",
            self.path.as_str(),
            state.next_pg
        ));
        state.persistent_groups.insert(pg_path.clone(), args);
        drop(state);
        self.fake.record("P2P.AddPersistentGroup");
        Ok(pg_path)
    }

    async fn remove_persistent_group(&self, group: OwnedObjectPath) -> fdo::Result<()> {
        self.fake.lock().persistent_groups.remove(&group);
        self.fake.record("P2P.RemovePersistentGroup");
        Ok(())
    }

    async fn remove_all_persistent_groups(&self) -> fdo::Result<()> {
        self.fake.lock().persistent_groups.clear();
        self.fake.record("P2P.RemoveAllPersistentGroups");
        Ok(())
    }

    async fn invite(&self, args: Dict) -> fdo::Result<()> {
        let peer = args
            .get("peer")
            .and_then(|v| OwnedObjectPath::try_from(v.clone()).ok())
            .map(|p| p.as_str().to_owned())
            .unwrap_or_default();
        self.fake.record(format!(
            "P2P.Invite peer={}",
            peer.rsplit('/').next().unwrap_or("")
        ));
        Ok(())
    }

    async fn cancel(&self) -> fdo::Result<()> {
        self.fake.record("P2P.Cancel");
        Ok(())
    }

    async fn disconnect(&self) -> fdo::Result<()> {
        let ifname = self
            .fake
            .lock()
            .ifaces
            .get(&self.path)
            .map(|i| i.ifname.clone());
        self.fake.record(format!(
            "P2P.Disconnect {}",
            ifname.clone().unwrap_or_default()
        ));
        if let Some(ifname) = ifname {
            let fake = self.fake.clone();
            // Emit after replying, as the real daemon tears down async.
            tokio::spawn(async move {
                let _ = fake.finish_group(&ifname).await;
            });
        }
        Ok(())
    }

    #[zbus(signal)]
    async fn device_found(emitter: &SignalEmitter<'_>, path: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn find_stopped(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal, name = "GONegotiationSuccess")]
    async fn go_negotiation_success(
        emitter: &SignalEmitter<'_>,
        info: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;
    #[zbus(signal, name = "GONegotiationFailure")]
    async fn go_negotiation_failure(
        emitter: &SignalEmitter<'_>,
        info: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;
    #[zbus(signal, name = "GONegotiationRequest")]
    async fn go_negotiation_request(
        emitter: &SignalEmitter<'_>,
        path: OwnedObjectPath,
        dev_passwd_id: u16,
        device_go_intent: u8,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn group_started(
        emitter: &SignalEmitter<'_>,
        info: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn group_finished(
        emitter: &SignalEmitter<'_>,
        info: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn persistent_group_added(
        emitter: &SignalEmitter<'_>,
        path: OwnedObjectPath,
        properties: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;
}

#[derive(Debug)]
struct FakeBss {
    ap: Ap,
}

#[zbus::interface(name = "fi.w1.wpa_supplicant1.BSS")]
impl FakeBss {
    #[zbus(property, name = "SSID")]
    fn ssid(&self) -> Vec<u8> {
        self.ap.ssid.clone()
    }
    #[zbus(property, name = "BSSID")]
    fn bssid(&self) -> Vec<u8> {
        self.ap.bssid.to_vec()
    }
    #[zbus(property)]
    fn frequency(&self) -> u16 {
        2412
    }
    #[zbus(property)]
    fn signal(&self) -> i16 {
        -50
    }
    #[zbus(property)]
    fn privacy(&self) -> bool {
        !self.ap.rsn.is_empty()
    }
    #[zbus(property, name = "WPA")]
    fn wpa(&self) -> Dict {
        Dict::new()
    }
    #[zbus(property, name = "RSN")]
    fn rsn(&self) -> Dict {
        HashMap::from([("KeyMgmt".to_owned(), ov(Value::from(self.ap.rsn.clone())))])
    }
}

#[derive(Debug)]
struct FakeNetwork {
    fake: FakeWpa,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "fi.w1.wpa_supplicant1.Network")]
impl FakeNetwork {
    #[zbus(property)]
    fn properties(&self) -> Dict {
        let state = self.fake.lock();
        let mut props = Dict::new();
        if let Some(network) = state.networks.get(&self.path) {
            let hex: String = network.ssid.iter().map(|b| format!("{b:02x}")).collect();
            props.insert("ssid".into(), ov(Value::from(hex)));
            if let Some(id) = &network.id_str {
                // wpa_supplicant returns string fields quoted.
                props.insert("id_str".into(), ov(Value::from(format!("\"{id}\""))));
            }
        }
        props
    }
}

#[derive(Debug)]
struct FakePeer {
    peer: Peer,
}

#[zbus::interface(name = "fi.w1.wpa_supplicant1.Peer")]
impl FakePeer {
    #[zbus(property)]
    fn device_name(&self) -> String {
        self.peer.name.clone()
    }
    #[zbus(property)]
    fn device_address(&self) -> Vec<u8> {
        self.peer.address.to_vec()
    }
    #[zbus(property)]
    fn primary_device_type(&self) -> Vec<u8> {
        vec![0, 10, 0, 0x50, 0xf2, 4, 0, 5]
    }
    #[zbus(property, name = "IEs")]
    fn ies(&self) -> Vec<u8> {
        Vec::new()
    }
}

/// Remote control of the fake for out-of-process tests.
#[derive(Debug)]
struct Control {
    fake: FakeWpa,
}

fn failed(error: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(error.to_string())
}

fn parse_mac(value: &str) -> fdo::Result<[u8; 6]> {
    let parts: Vec<u8> = value
        .split(':')
        .map(|p| u8::from_str_radix(p, 16))
        .collect::<Result<_, _>>()
        .map_err(failed)?;
    parts
        .try_into()
        .map_err(|_| fdo::Error::InvalidArgs("bad MAC".into()))
}

#[zbus::interface(name = "com.hihusky.Kestrel.Testing.FakeWpa")]
impl Control {
    async fn add_access_point(
        &self,
        ssid: String,
        password: String,
        security: String,
    ) -> fdo::Result<()> {
        let password = (!password.is_empty()).then_some(password);
        self.fake
            .add_access_point(&ssid, password.as_deref(), &security)
            .await
            .map_err(failed)
    }

    fn add_peer(&self, address: String, name: String) -> fdo::Result<()> {
        self.fake.add_peer(parse_mac(&address)?, &name);
        Ok(())
    }

    async fn start_group(&self, device: String, group_ifname: String, go: bool) -> fdo::Result<()> {
        self.fake
            .start_group(&device, &group_ifname, go)
            .await
            .map_err(failed)
    }

    async fn finish_group(&self, group_ifname: String) -> fdo::Result<()> {
        self.fake.finish_group(&group_ifname).await.map_err(failed)
    }

    async fn fail_negotiation(&self, device: String, status: i32) -> fdo::Result<()> {
        self.fake
            .fail_negotiation(&device, status)
            .await
            .map_err(failed)
    }

    async fn request_negotiation(
        &self,
        device: String,
        peer: String,
        password_id: u16,
    ) -> fdo::Result<()> {
        self.fake
            .request_negotiation(&device, parse_mac(&peer)?, password_id)
            .await
            .map_err(failed)
    }

    async fn drop_link(&self, device: String) -> fdo::Result<()> {
        self.fake.drop_link(&device).await.map_err(failed)
    }

    async fn set_sleep(&self, sleeping: bool) -> fdo::Result<()> {
        let _ = self
            .fake
            .connection
            .request_name("org.freedesktop.login1")
            .await;
        self.fake
            .connection
            .emit_signal(
                Option::<&str>::None,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                &(sleeping,),
            )
            .await
            .map_err(failed)
    }

    fn calls(&self) -> Vec<String> {
        self.fake.calls()
    }

    fn network_count(&self) -> u32 {
        u32::try_from(self.fake.network_count()).unwrap_or(u32::MAX)
    }

    fn interface_names(&self) -> Vec<String> {
        self.fake.interface_names()
    }

    fn state_of(&self, ifname: String) -> String {
        self.fake.state_of(&ifname).unwrap_or_default()
    }

    fn blob_names(&self, ifname: String) -> Vec<String> {
        self.fake.blob_names(&ifname)
    }

    async fn emit_persistent_group(
        &self,
        device: String,
        ssid: String,
        go_address: String,
        psk: String,
        go: bool,
    ) -> fdo::Result<()> {
        self.fake
            .emit_persistent_group(&device, &ssid, &go_address, &psk, go)
            .await
            .map_err(failed)
    }
}

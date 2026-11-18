// SPDX-License-Identifier: LGPL-2.1-or-later

//! A fake `net.connman.iwd` service with the object layout, properties,
//! signals, and agent protocol the adapter relies on.

#![allow(
    clippy::struct_field_names,
    clippy::unnecessary_wraps,
    clippy::used_underscore_binding,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::unused_async,
    clippy::unused_self,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::unused_async_trait_impl,
    missing_docs
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zbus::fdo;
use zbus::object_server::SignalEmitter;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

const SERVICE: &str = "net.connman.iwd";
const STATION_PATH: &str = "/net/connman/iwd/0/4";

type Props = HashMap<String, OwnedVariant>;
type Objects = HashMap<OwnedObjectPath, HashMap<String, Props>>;

fn path(value: impl Into<String>) -> OwnedObjectPath {
    OwnedObjectPath::try_from(value.into()).expect("valid path")
}

fn ov(value: Variant<'_>) -> OwnedVariant {
    OwnedVariant::try_from(value).expect("owned value")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone)]
struct Net {
    name: String,
    kind: String,
    password: Option<String>,
    path: OwnedObjectPath,
    bss: OwnedObjectPath,
}

#[derive(Debug, Clone)]
struct Known {
    name: String,
    kind: String,
    auto_connect: bool,
}

#[derive(Debug, Default)]
struct State {
    ifname: String,
    mode: String,
    ap_started: bool,
    ap_name: String,
    station_state: String,
    scanning: bool,
    connected: Option<OwnedObjectPath>,
    networks: Vec<Net>,
    known: HashMap<OwnedObjectPath, Known>,
    agent: Option<(String, OwnedObjectPath)>,
    calls: Vec<String>,
}

/// A running fake iwd.
#[derive(Debug, Clone)]
pub struct FakeIwd {
    connection: zbus::Connection,
    state: Arc<Mutex<State>>,
}

impl FakeIwd {
    pub async fn start(address: &str, ifname: &str) -> zbus::Result<Self> {
        let connection = zbus::connection::Builder::address(address).build().await?;
        let state = Arc::new(Mutex::new(State {
            ifname: ifname.to_owned(),
            mode: "station".into(),
            station_state: "disconnected".into(),
            ..State::default()
        }));
        let fake = Self { connection, state };
        let server = fake.connection.object_server();
        server.at("/", Manager { fake: fake.clone() }).await?;
        server
            .at("/net/connman/iwd", AgentManager { fake: fake.clone() })
            .await?;
        server
            .at(STATION_PATH, Device { fake: fake.clone() })
            .await?;
        server
            .at(STATION_PATH, Station { fake: fake.clone() })
            .await?;
        fake.connection.request_name(SERVICE).await?;
        Ok(fake)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("fake iwd state")
    }

    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    pub fn agent_registered(&self) -> bool {
        self.lock().agent.is_some()
    }

    pub fn agent_bus_name(&self) -> Option<String> {
        self.lock().agent.as_ref().map(|(owner, _)| owner.clone())
    }

    pub fn station_state(&self) -> String {
        self.lock().station_state.clone()
    }

    pub fn device_mode(&self) -> String {
        self.lock().mode.clone()
    }

    pub fn ap_started(&self) -> bool {
        self.lock().ap_started
    }

    /// Names of known networks, with their `AutoConnect` flag.
    pub fn known_networks(&self) -> Vec<(String, bool)> {
        let mut known: Vec<(String, bool)> = self
            .lock()
            .known
            .values()
            .map(|k| (k.name.clone(), k.auto_connect))
            .collect();
        known.sort();
        known
    }

    pub async fn add_network(&self, name: &str, password: Option<&str>) -> zbus::Result<()> {
        let kind = if password.is_some() { "psk" } else { "open" };
        let net_path = path(format!("{STATION_PATH}/{}_{kind}", hex(name.as_bytes())));
        let bss = path(format!("{}/020000000001", net_path.as_str()));
        let net = Net {
            name: name.to_owned(),
            kind: kind.to_owned(),
            password: password.map(str::to_owned),
            path: net_path.clone(),
            bss: bss.clone(),
        };
        self.lock().networks.push(net.clone());
        let server = self.connection.object_server();
        server
            .at(
                net_path,
                Network {
                    fake: self.clone(),
                    net,
                },
            )
            .await?;
        server.at(bss, BasicServiceSet).await?;
        Ok(())
    }

    /// A known network provisioned by someone else (autoconnect on).
    pub async fn add_admin_known_network(&self, name: &str) -> zbus::Result<()> {
        self.add_known(name, "psk", true).await
    }

    async fn add_known(&self, name: &str, kind: &str, auto_connect: bool) -> zbus::Result<()> {
        let known_path = path(format!("/net/connman/iwd/{}_{kind}", hex(name.as_bytes())));
        self.lock().known.insert(
            known_path.clone(),
            Known {
                name: name.to_owned(),
                kind: kind.to_owned(),
                auto_connect,
            },
        );
        self.connection
            .object_server()
            .at(
                known_path.clone(),
                KnownNetwork {
                    fake: self.clone(),
                    path: known_path.clone(),
                },
            )
            .await?;
        let emitter = SignalEmitter::new(&self.connection, "/")?;
        let props = self.known_props(&known_path);
        Manager::interfaces_added(
            &emitter,
            known_path,
            HashMap::from([("net.connman.iwd.KnownNetwork".to_owned(), props)]),
        )
        .await
    }

    fn known_props(&self, known_path: &OwnedObjectPath) -> Props {
        let state = self.lock();
        let known = &state.known[known_path];
        HashMap::from([
            ("Name".to_owned(), ov(Variant::from(known.name.clone()))),
            ("Type".to_owned(), ov(Variant::from(known.kind.clone()))),
            (
                "AutoConnect".to_owned(),
                ov(Variant::from(known.auto_connect)),
            ),
        ])
    }

    async fn emit_station(&self) -> zbus::Result<()> {
        let iface = self
            .connection
            .object_server()
            .interface::<_, Station>(STATION_PATH)
            .await?;
        let guard = iface.get().await;
        guard.state_changed(iface.signal_emitter()).await?;
        guard
            .connected_network_changed(iface.signal_emitter())
            .await
    }

    async fn set_station(
        &self,
        value: &str,
        connected: Option<OwnedObjectPath>,
    ) -> zbus::Result<()> {
        {
            let mut state = self.lock();
            value.clone_into(&mut state.station_state);
            state.connected = connected;
        }
        self.emit_station().await
    }

    /// The AP drops us.
    pub async fn drop_link(&self) -> zbus::Result<()> {
        self.set_station("disconnected", None).await
    }

    /// iwd exits.
    pub async fn vanish(&self) -> zbus::Result<()> {
        self.connection.release_name(SERVICE).await.map(|_| ())
    }

    pub async fn reappear(&self) -> zbus::Result<()> {
        self.connection.request_name(SERVICE).await
    }

    async fn ask_agent(&self, network: &OwnedObjectPath) -> Option<String> {
        let (destination, agent_path) = self.lock().agent.clone()?;
        let proxy = zbus::Proxy::new(
            &self.connection,
            destination,
            agent_path,
            "net.connman.iwd.Agent",
        )
        .await
        .ok()?;
        let reply = proxy
            .call_method("RequestPassphrase", &(network.clone(),))
            .await
            .ok()?;
        reply.body().deserialize::<String>().ok()
    }
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "net.connman.iwd")]
enum IwdError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Failed(String),
    NotConnected(String),
    Busy(String),
}

#[derive(Debug)]
struct Manager {
    fake: FakeIwd,
}

#[zbus::interface(name = "org.freedesktop.DBus.ObjectManager")]
impl Manager {
    fn get_managed_objects(&self) -> Objects {
        let state = self.fake.lock();
        let mut objects = Objects::new();
        let connected = state.connected.clone().unwrap_or_else(|| path("/"));
        let mut dev_map = HashMap::from([(
            "net.connman.iwd.Device".to_owned(),
            HashMap::from([
                ("Name".to_owned(), ov(Variant::from(state.ifname.clone()))),
                ("Address".to_owned(), ov(Variant::from("02:00:00:00:00:aa"))),
                ("Mode".to_owned(), ov(Variant::from(state.mode.clone()))),
                ("Powered".to_owned(), ov(Variant::from(true))),
            ]),
        )]);
        if state.mode == "ap" {
            dev_map.insert(
                "net.connman.iwd.AccessPoint".to_owned(),
                HashMap::from([
                    ("Started".to_owned(), ov(Variant::from(state.ap_started))),
                    ("Name".to_owned(), ov(Variant::from(state.ap_name.clone()))),
                    ("Frequency".to_owned(), ov(Variant::from(2412u32))),
                ]),
            );
        } else {
            dev_map.insert(
                "net.connman.iwd.Station".to_owned(),
                HashMap::from([
                    (
                        "State".to_owned(),
                        ov(Variant::from(state.station_state.clone())),
                    ),
                    ("Scanning".to_owned(), ov(Variant::from(state.scanning))),
                    ("ConnectedNetwork".to_owned(), ov(Variant::from(connected))),
                ]),
            );
        }
        objects.insert(path(STATION_PATH), dev_map);
        for net in &state.networks {
            objects.insert(
                net.path.clone(),
                HashMap::from([(
                    "net.connman.iwd.Network".to_owned(),
                    HashMap::from([
                        ("Name".to_owned(), ov(Variant::from(net.name.clone()))),
                        ("Type".to_owned(), ov(Variant::from(net.kind.clone()))),
                        (
                            "Connected".to_owned(),
                            ov(Variant::from(state.connected.as_ref() == Some(&net.path))),
                        ),
                        (
                            "ExtendedServiceSet".to_owned(),
                            ov(Variant::from(vec![net.bss.clone()])),
                        ),
                    ]),
                )]),
            );
            objects.insert(
                net.bss.clone(),
                HashMap::from([(
                    "net.connman.iwd.BasicServiceSet".to_owned(),
                    HashMap::from([("Address".to_owned(), ov(Variant::from("02:00:00:00:00:01")))]),
                )]),
            );
        }
        for (known_path, known) in &state.known {
            objects.insert(
                known_path.clone(),
                HashMap::from([(
                    "net.connman.iwd.KnownNetwork".to_owned(),
                    HashMap::from([
                        ("Name".to_owned(), ov(Variant::from(known.name.clone()))),
                        ("Type".to_owned(), ov(Variant::from(known.kind.clone()))),
                        (
                            "AutoConnect".to_owned(),
                            ov(Variant::from(known.auto_connect)),
                        ),
                    ]),
                )]),
            );
        }
        objects
    }

    #[zbus(signal)]
    async fn interfaces_added(
        emitter: &SignalEmitter<'_>,
        object: OwnedObjectPath,
        interfaces: HashMap<String, Props>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn interfaces_removed(
        emitter: &SignalEmitter<'_>,
        object: OwnedObjectPath,
        interfaces: Vec<String>,
    ) -> zbus::Result<()>;
}

#[derive(Debug)]
struct AgentManager {
    fake: FakeIwd,
}

#[zbus::interface(name = "net.connman.iwd.AgentManager")]
impl AgentManager {
    fn register_agent(
        &self,
        agent: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<()> {
        let sender = header.sender().map(ToString::to_string).unwrap_or_default();
        self.fake.lock().agent = Some((sender, agent));
        self.fake.lock().calls.push("RegisterAgent".into());
        Ok(())
    }

    fn unregister_agent(&self, _agent: OwnedObjectPath) -> fdo::Result<()> {
        self.fake.lock().agent = None;
        Ok(())
    }
}

#[derive(Debug)]
struct Device {
    fake: FakeIwd,
}

#[zbus::interface(name = "net.connman.iwd.Device")]
impl Device {
    #[zbus(property)]
    fn name(&self) -> String {
        self.fake.lock().ifname.clone()
    }

    #[zbus(property)]
    fn address(&self) -> String {
        "02:00:00:00:00:aa".into()
    }

    #[zbus(property)]
    fn mode(&self) -> String {
        self.fake.lock().mode.clone()
    }

    #[zbus(property)]
    fn set_mode(&self, value: String) -> fdo::Result<()> {
        let prev = {
            let mut state = self.fake.lock();
            let prev = state.mode.clone();
            state.mode.clone_from(&value);
            state.calls.push(format!("SetMode {value}"));
            prev
        };
        if prev == value {
            return Ok(());
        }
        // Mutating interfaces on STATION_PATH inside a property setter on the
        // same path would deadlock ObjectServer's node lock in zbus; run it
        // immediately after returning.
        let fake = self.fake.clone();
        tokio::spawn(async move {
            let server = fake.connection.object_server();
            let Ok(emitter) = SignalEmitter::new(&fake.connection, "/") else {
                return;
            };
            if value == "ap" {
                let _ = server.remove::<Station, _>(STATION_PATH).await;
                let _ = Manager::interfaces_removed(
                    &emitter,
                    path(STATION_PATH),
                    vec!["net.connman.iwd.Station".into()],
                )
                .await;
                let _ = server
                    .at(STATION_PATH, AccessPoint { fake: fake.clone() })
                    .await;
            } else {
                let _ = server.remove::<AccessPoint, _>(STATION_PATH).await;
                let _ = Manager::interfaces_removed(
                    &emitter,
                    path(STATION_PATH),
                    vec!["net.connman.iwd.AccessPoint".into()],
                )
                .await;
                let _ = server
                    .at(STATION_PATH, Station { fake: fake.clone() })
                    .await;
            }
        });
        Ok(())
    }
}

#[derive(Debug)]
struct AccessPoint {
    fake: FakeIwd,
}

#[zbus::interface(name = "net.connman.iwd.AccessPoint")]
impl AccessPoint {
    #[zbus(property)]
    fn started(&self) -> bool {
        self.fake.lock().ap_started
    }

    #[zbus(property)]
    fn name(&self) -> String {
        self.fake.lock().ap_name.clone()
    }

    #[zbus(property)]
    fn frequency(&self) -> u32 {
        2412
    }

    fn start(&self, ssid: String, _passphrase: String) -> Result<(), IwdError> {
        let mut state = self.fake.lock();
        state.ap_started = true;
        state.ap_name.clone_from(&ssid);
        state.calls.push(format!("AccessPoint.Start {ssid}"));
        Ok(())
    }

    fn stop(&self) -> Result<(), IwdError> {
        let mut state = self.fake.lock();
        state.ap_started = false;
        state.ap_name.clear();
        state.calls.push("AccessPoint.Stop".into());
        Ok(())
    }
}

#[derive(Debug)]
struct Station {
    fake: FakeIwd,
}

#[zbus::interface(name = "net.connman.iwd.Station")]
impl Station {
    #[zbus(property)]
    fn state(&self) -> String {
        self.fake.lock().station_state.clone()
    }

    #[zbus(property)]
    fn scanning(&self) -> bool {
        self.fake.lock().scanning
    }

    #[zbus(property)]
    fn connected_network(&self) -> OwnedObjectPath {
        self.fake
            .lock()
            .connected
            .clone()
            .unwrap_or_else(|| path("/"))
    }

    async fn scan(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(), IwdError> {
        {
            let mut state = self.fake.lock();
            if state.scanning {
                return Err(IwdError::Busy("scanning".into()));
            }
            state.scanning = true;
            state.calls.push("Scan".into());
        }
        self.scanning_changed(&emitter).await?;
        let fake = self.fake.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            fake.lock().scanning = false;
            if let Ok(iface) = fake
                .connection
                .object_server()
                .interface::<_, Station>(STATION_PATH)
                .await
            {
                let _ = iface
                    .get()
                    .await
                    .scanning_changed(iface.signal_emitter())
                    .await;
            }
        });
        Ok(())
    }

    fn get_ordered_networks(&self) -> Vec<(OwnedObjectPath, i16)> {
        self.fake
            .lock()
            .networks
            .iter()
            .map(|n| (n.path.clone(), -5000))
            .collect()
    }

    async fn disconnect(&self) -> Result<(), IwdError> {
        self.fake.lock().calls.push("Disconnect".into());
        if self.fake.lock().connected.is_none() {
            return Err(IwdError::NotConnected("not connected".into()));
        }
        self.fake.set_station("disconnected", None).await?;
        Ok(())
    }

    async fn connect_hidden_network(&self, name: String) -> Result<(), IwdError> {
        self.fake
            .lock()
            .calls
            .push(format!("ConnectHiddenNetwork {name}"));
        Err(IwdError::Failed("not found".into()))
    }
}

#[derive(Debug)]
struct Network {
    fake: FakeIwd,
    net: Net,
}

#[zbus::interface(name = "net.connman.iwd.Network")]
impl Network {
    #[zbus(property)]
    fn name(&self) -> String {
        self.net.name.clone()
    }

    #[zbus(property, name = "Type")]
    fn kind(&self) -> String {
        self.net.kind.clone()
    }

    async fn connect(&self) -> Result<(), IwdError> {
        self.fake
            .lock()
            .calls
            .push(format!("Connect {}", self.net.name));
        self.fake.set_station("connecting", None).await?;
        if let Some(expected) = &self.net.password {
            let given = self.fake.ask_agent(&self.net.path).await;
            if given.as_deref() != Some(expected.as_str()) {
                self.fake.set_station("disconnected", None).await?;
                return Err(IwdError::Failed("Operation failed".into()));
            }
        }
        // iwd remembers every network it connects to.
        self.fake
            .add_known(&self.net.name, &self.net.kind, true)
            .await?;
        self.fake
            .set_station("connected", Some(self.net.path.clone()))
            .await?;
        Ok(())
    }
}

#[derive(Debug)]
struct BasicServiceSet;

#[zbus::interface(name = "net.connman.iwd.BasicServiceSet")]
impl BasicServiceSet {
    #[zbus(property)]
    fn address(&self) -> String {
        "02:00:00:00:00:01".into()
    }
}

#[derive(Debug)]
struct KnownNetwork {
    fake: FakeIwd,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "net.connman.iwd.KnownNetwork")]
impl KnownNetwork {
    #[zbus(property)]
    fn name(&self) -> String {
        self.fake
            .lock()
            .known
            .get(&self.path)
            .map(|k| k.name.clone())
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn auto_connect(&self) -> bool {
        self.fake
            .lock()
            .known
            .get(&self.path)
            .is_some_and(|k| k.auto_connect)
    }

    #[zbus(property)]
    fn set_auto_connect(&mut self, value: bool) {
        if let Some(known) = self.fake.lock().known.get_mut(&self.path) {
            known.auto_connect = value;
        }
    }

    async fn forget(&self, #[zbus(object_server)] server: &zbus::ObjectServer) -> fdo::Result<()> {
        let removed = self.fake.lock().known.remove(&self.path);
        if let Some(known) = removed {
            self.fake
                .lock()
                .calls
                .push(format!("Forget {}", known.name));
        }
        let path = self.path.clone();
        let fake = self.fake.clone();
        let _ = server;
        // Remove after replying.
        tokio::spawn(async move {
            let _ = fake
                .connection
                .object_server()
                .remove::<KnownNetwork, _>(path.clone())
                .await;
            if let Ok(emitter) = SignalEmitter::new(&fake.connection, "/") {
                let _ = Manager::interfaces_removed(
                    &emitter,
                    path,
                    vec!["net.connman.iwd.KnownNetwork".into()],
                )
                .await;
            }
        });
        Ok(())
    }
}

// SPDX-License-Identifier: LGPL-2.1-or-later

//! The D-Bus server and typed client over a private bus, with the controller
//! driving in-memory fakes.

#![allow(clippy::used_underscore_binding)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kestrel_api::client::Client;
use kestrel_api::{Action, AllowAll, ApiError, Authorizer, ProfileSettings, SecretBundle, Server};
use kestrel_catalog::{Catalog, CatalogStores};
use kestrel_controller::{Controller, ControllerConfig, ControllerPorts};
use kestrel_model::{
    Bss, ConnectionEvent, ConnectionOutcome, InterfaceName, MacAddress, P2pRole, Security, Ssid,
};
use kestrel_ports::p2p::P2pEvent;
use kestrel_ports::store::HistoryStore;
use kestrel_testkit::{
    FakeL3, FakeWlan, MemoryCerts, MemoryHistory, MemoryP2pGroups, MemoryProfiles, MemorySecrets,
    MemoryState,
};
use zbus::{OwnedVariant, Variant};

struct TestBus {
    child: Child,
    address: String,
}

impl TestBus {
    fn start() -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon must be installed");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        Self {
            child,
            address: line.trim().to_owned(),
        }
    }

    async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .build()
            .await
            .unwrap()
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Env {
    bus: TestBus,
    wlan: FakeWlan,
    l3: FakeL3,
    history: MemoryHistory,
    catalog: Catalog,
    controller: Option<Controller>,
    server: Option<Server>,
    client: Client,
}

impl Env {
    async fn start(authorizer: Arc<dyn Authorizer>) -> Self {
        let bus = TestBus::start();
        let wlan = FakeWlan::new();
        let l3 = FakeL3::new();
        l3.set_dns(vec!["1.1.1.1".parse().unwrap()]);
        let history = MemoryHistory::default();
        wlan.add_device("wlan0");
        wlan.set_visible(vec![Bss {
            ssid: Ssid::new("home").unwrap(),
            bssid: MacAddress::from_octets([2, 0, 0, 0, 0, 1]),
            frequency: 2412,
            signal: -40,
            security: Security::Wpa2Psk,
        }]);
        let catalog = Catalog::open(CatalogStores {
            profiles: Arc::new(MemoryProfiles::default()),
            secrets: Arc::new(MemorySecrets::default()),
            certs: Arc::new(MemoryCerts::default()),
            p2p_groups: Arc::new(MemoryP2pGroups::default()),
            history: Arc::new(history.clone()),
        })
        .await
        .unwrap();
        let controller = Controller::start(
            ControllerConfig::default(),
            ControllerPorts {
                wlan: Arc::new(wlan.clone()),
                l3: Arc::new(l3.clone()),
                state: Arc::new(MemoryState::default()),
            },
            catalog.clone(),
        )
        .await
        .unwrap();
        let server = Server::serve(
            bus.connect().await,
            controller.handle(),
            catalog.clone(),
            authorizer,
        )
        .await
        .unwrap();
        let client = Client::new(bus.connect().await).await.unwrap();
        Self {
            bus,
            wlan,
            l3,
            history,
            catalog,
            controller: Some(controller),
            server: Some(server),
            client,
        }
    }

    async fn stop(mut self) {
        if let Some(server) = self.server.take() {
            server.stop().await;
        }
        if let Some(controller) = self.controller.take() {
            controller.shutdown().await;
        }
    }
}

fn secrets(passphrase: &str) -> SecretBundle {
    if passphrase.is_empty() {
        SecretBundle::new()
    } else {
        HashMap::from([("passphrase".to_owned(), passphrase.to_owned())])
    }
}

fn settings(pairs: &[(&str, Variant<'_>)]) -> ProfileSettings {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), OwnedVariant::try_from(v.clone()).unwrap()))
        .collect()
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..300 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn error_name(error: &zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        other => other.to_string(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn profile_lifecycle_and_station_connection() {
    let env = Env::start(Arc::new(AllowAll)).await;
    let manager = env.client.manager().await.unwrap();
    assert!(manager.wireless_enabled().await.unwrap());

    let devices = env.client.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    let device = &devices[0];
    assert_eq!(device.interface().await.unwrap(), "wlan0");
    assert_eq!(
        device.capabilities().await.unwrap(),
        ["station", "p2p", "access-point"]
    );

    // Validation errors carry a stable name.
    let error = manager
        .add_profile(settings(&[("ssid", Variant::from("home"))]), secrets(""))
        .await
        .unwrap_err();
    assert_eq!(
        error_name(&error),
        "com.hihusky.Kestrel.Error.InvalidArgument"
    );

    let path = manager
        .add_profile(
            settings(&[
                ("ssid", Variant::from("home")),
                ("security", Variant::from("wpa-personal")),
                ("priority", Variant::from(3i32)),
            ]),
            secrets("correct horse battery staple"),
        )
        .await
        .unwrap();
    let profile = env.client.profile(path.clone()).await.unwrap();
    // A returned path is usable at once.
    assert_ne!(profile.id().await.unwrap(), "");
    eventually("profile exported", || async {
        profile.has_secret().await.unwrap_or(false)
    })
    .await;
    let exported = profile.settings().await.unwrap();
    assert_eq!(
        String::try_from(exported["ssid"].try_clone().unwrap()).unwrap(),
        "home"
    );
    assert!(!exported.contains_key("psk"), "secrets are never exported");

    // Autoconnect picks it up; the device object follows.
    eventually("connected", || async {
        device.state().await.unwrap() == "connected"
    })
    .await;
    assert_eq!(device.active_profile().await.unwrap(), path);
    assert_eq!(device.frequency().await.unwrap(), 2412);
    assert_eq!(device.security().await.unwrap(), "wpa2-psk");
    assert_eq!(device.dns().await.unwrap(), ["1.1.1.1"]);
    assert_eq!(device.online_state().await.unwrap(), "online");
    eventually("manager online", || async {
        manager.online_state().await.unwrap() == "online"
    })
    .await;
    assert!(manager.wireless_hardware_enabled().await.unwrap());
    let results = device.get_scan_results().await.unwrap();
    assert_eq!(results[0].5, path, "scan result links to saved profile");
    assert!(
        env.l3
            .bindings()
            .contains_key(&InterfaceName::new("wlan0").unwrap())
    );

    device.disconnect().await.unwrap();
    eventually("idle", || async { device.state().await.unwrap() == "idle" }).await;
    assert!(device.autoconnect_held().await.unwrap());
    device.connect(&path.as_ref()).await.unwrap();
    eventually("reconnected", || async {
        device.state().await.unwrap() == "connected"
    })
    .await;

    profile
        .update(
            settings(&[("name", Variant::from("Home"))]),
            "keep",
            secrets(""),
        )
        .await
        .unwrap();
    eventually("renamed", || async {
        profile
            .settings()
            .await
            .ok()
            .and_then(|s| {
                s.get("name")
                    .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            })
            .as_deref()
            == Some("Home")
    })
    .await;

    profile.delete().await.unwrap();
    eventually("profile gone", || async {
        env.client.profiles().await.unwrap().is_empty()
    })
    .await;
    eventually("disconnected", || async {
        device.state().await.unwrap() == "idle"
    })
    .await;

    let results = device.get_scan_results().await.unwrap();
    assert_eq!(results[0].0, "home");
    assert_eq!(results[0].4, "wpa2-psk");
    assert_eq!(results[0].5.as_str(), "/", "deleted profile is unlinked");

    manager.set_wireless_enabled(false).await.unwrap();
    eventually("disabled", || async {
        device.state().await.unwrap() == "disabled"
    })
    .await;
    assert!(!manager.wireless_enabled().await.unwrap());
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2p_sessions_are_objects() {
    let env = Env::start(Arc::new(AllowAll)).await;
    let p2p = env.client.p2p("wlan0").await.unwrap();
    let session_path = p2p
        .connect("02:00:00:00:aa:42", "pbc", "", 255, false)
        .await
        .unwrap();
    let session = env.client.session(session_path.clone()).await.unwrap();
    assert_ne!(session.peer().await.unwrap(), "");
    assert_eq!(session.state().await.unwrap(), "negotiating");
    assert_eq!(session.peer().await.unwrap(), "02:00:00:00:aa:42");

    let error = p2p
        .connect("02:00:00:00:aa:43", "pbc", "", 255, false)
        .await
        .unwrap_err();
    assert_eq!(error_name(&error), "com.hihusky.Kestrel.Error.Busy");
    let error = p2p
        .connect("02:00:00:00:aa:43", "keypad", "12345678", 255, false)
        .await
        .unwrap_err();
    assert_eq!(
        error_name(&error),
        "com.hihusky.Kestrel.Error.InvalidArgument"
    );

    let wlan0 = InterfaceName::new("wlan0").unwrap();
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: wlan0.clone(),
        group_if: InterfaceName::new("p2p-wlan0-0").unwrap(),
        role: P2pRole::GroupOwner,
    });
    eventually("ready", || async {
        session.state().await.unwrap() == "ready"
    })
    .await;
    assert_eq!(session.role().await.unwrap(), "group-owner");
    assert_eq!(session.group_interface().await.unwrap(), "p2p-wlan0-0");

    session.close().await.unwrap();
    eventually("session removed", || async {
        env.client.sessions().await.unwrap().is_empty()
    })
    .await;
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autonomous_group_is_a_session_without_a_peer() {
    let env = Env::start(Arc::new(AllowAll)).await;
    let p2p = env.client.p2p("wlan0").await.unwrap();
    let session_path = p2p.start_group(2412, false).await.unwrap();
    let session = env.client.session(session_path).await.unwrap();
    assert!(session.autonomous().await.unwrap());
    assert_eq!(session.peer().await.unwrap(), "");
    assert_eq!(session.state().await.unwrap(), "forming");
    assert_eq!(session.role().await.unwrap(), "group-owner");

    let error = p2p.start_group(0, false).await.unwrap_err();
    assert_eq!(error_name(&error), "com.hihusky.Kestrel.Error.Busy");

    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: InterfaceName::new("wlan0").unwrap(),
        group_if: InterfaceName::new("p2p-wlan0-0").unwrap(),
        role: P2pRole::GroupOwner,
    });
    eventually("ready", || async {
        session.state().await.unwrap() == "ready"
    })
    .await;
    assert_eq!(session.group_interface().await.unwrap(), "p2p-wlan0-0");

    session.close().await.unwrap();
    eventually("session removed", || async {
        env.client.sessions().await.unwrap().is_empty()
    })
    .await;
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2p_set_wfd_subelements_updates_and_clears_advertisement() {
    let env = Env::start(Arc::new(AllowAll)).await;
    let p2p = env.client.p2p("wlan0").await.unwrap();
    let sample = [0x00, 0x00, 0x06, 0x00, 0x10, 0x1c, 0x44, 0x00, 0x32];
    p2p.set_wfd_subelements(&sample).await.unwrap();
    assert_eq!(env.wlan.wfd_subelements().as_deref(), Some(&sample[..]));

    p2p.set_wfd_subelements(&[]).await.unwrap();
    assert_eq!(env.wlan.wfd_subelements(), None);
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_history_is_readable_through_the_manager() {
    let env = Env::start(Arc::new(AllowAll)).await;
    env.history
        .record(&ConnectionEvent {
            at: 1_700_000_000,
            device: "wlan0".into(),
            ssid: "home".into(),
            profile: None,
            outcome: ConnectionOutcome::Connected,
            detail: None,
        })
        .await
        .unwrap();
    let history = env
        .client
        .manager()
        .await
        .unwrap()
        .history(10)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].0, 1_700_000_000);
    assert_eq!(history[0].2, "home");
    assert_eq!(history[0].4, "connected");
    env.stop().await;
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct AgentState {
    secret_requests: Vec<(String, String)>,
    pins: Vec<String>,
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "com.hihusky.Kestrel.Agent.Error")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Declined(String),
}

struct TestAgent {
    state: Arc<Mutex<AgentState>>,
    secret: Option<String>,
}

#[allow(
    clippy::unnecessary_wraps,
    clippy::unused_self,
    clippy::used_underscore_binding,
    clippy::needless_pass_by_value
)]
#[zbus::interface(name = "com.hihusky.Kestrel.Agent")]
impl TestAgent {
    fn request_secret(
        &self,
        _device: zbus::OwnedObjectPath,
        _profile: zbus::OwnedObjectPath,
        ssid: String,
        _security: String,
        reason: String,
    ) -> Result<String, AgentError> {
        self.state
            .lock()
            .unwrap()
            .secret_requests
            .push((ssid, reason));
        self.secret
            .clone()
            .ok_or_else(|| AgentError::Declined("no".into()))
    }

    fn authorize_peer(
        &self,
        _device: zbus::OwnedObjectPath,
        _peer: String,
        _name: String,
        _method: String,
    ) -> Result<(String, String), AgentError> {
        Ok(("pbc".into(), String::new()))
    }

    fn display_pin(&self, _session: zbus::OwnedObjectPath, _peer: String, pin: String) {
        self.state.lock().unwrap().pins.push(pin);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_supplies_secrets_and_is_dropped_with_its_owner() {
    let env = Env::start(Arc::new(AllowAll)).await;
    env.wlan
        .set_password(&Ssid::new("home").unwrap(), "the real password");

    // A separate consumer process, with its own connection, is the agent.
    let agent_connection = env.bus.connect().await;
    let state = Arc::new(Mutex::new(AgentState::default()));
    agent_connection
        .object_server()
        .at(
            "/test/agent",
            TestAgent {
                state: state.clone(),
                secret: Some("the real password".into()),
            },
        )
        .await
        .unwrap();
    let agent_client = Client::new(agent_connection.clone()).await.unwrap();
    let agent_path = zbus::ObjectPath::try_from("/test/agent").unwrap();
    agent_client
        .manager()
        .await
        .unwrap()
        .register_agent(&agent_path)
        .await
        .unwrap();
    // A second agent is refused while the first is alive.
    let error = env
        .client
        .manager()
        .await
        .unwrap()
        .register_agent(&agent_path)
        .await
        .unwrap_err();
    assert_eq!(error_name(&error), "com.hihusky.Kestrel.Error.Busy");

    // A profile without a secret: the agent is asked on first use.
    env.client
        .manager()
        .await
        .unwrap()
        .add_profile(
            settings(&[
                ("ssid", Variant::from("home")),
                ("security", Variant::from("wpa-personal")),
            ]),
            secrets(""),
        )
        .await
        .unwrap();
    let device = env.client.device("wlan0").await.unwrap();
    eventually("connected with the agent's secret", || async {
        device.state().await.unwrap() == "connected"
    })
    .await;
    assert_eq!(
        state.lock().unwrap().secret_requests,
        [("home".to_owned(), "secrets-required".to_owned())]
    );

    // The agent's owner leaves; a new agent may register.
    drop(agent_client);
    drop(agent_connection);
    let again = env.client.manager().await.unwrap();
    eventually("agent slot freed", || async {
        again.register_agent(&agent_path).await.is_ok()
    })
    .await;
    env.stop().await;
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ToggleAuthorizer {
    allow_all: std::sync::atomic::AtomicBool,
    denied: Mutex<Vec<Action>>,
}

impl ToggleAuthorizer {
    fn new(allow_all: bool) -> Self {
        Self {
            allow_all: std::sync::atomic::AtomicBool::new(allow_all),
            denied: Mutex::new(Vec::new()),
        }
    }

    fn set_allow_all(&self, allow: bool) {
        self.allow_all
            .store(allow, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait]
impl Authorizer for ToggleAuthorizer {
    async fn check(&self, _sender: &str, action: Action) -> Result<(), ApiError> {
        if self.allow_all.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(())
        } else {
            self.denied.lock().unwrap().push(action);
            Err(ApiError::AccessDenied("test policy".into()))
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn every_mutation_is_authorized() {
    let auth = Arc::new(ToggleAuthorizer::new(true));
    let env = Env::start(auth.clone()).await;
    let manager = env.client.manager().await.unwrap();
    let device = env.client.device("wlan0").await.unwrap();
    let p2p = env.client.p2p("wlan0").await.unwrap();
    let hotspot = env.client.hotspot("wlan0").await.unwrap();

    // Seed objects while authorization is enabled.
    let profile_path = manager
        .add_profile(
            settings(&[
                ("ssid", Variant::from("home")),
                ("security", Variant::from("open")),
            ]),
            secrets(""),
        )
        .await
        .unwrap();
    let cert_path = manager
        .import_certificate("Auth CA", TEST_CERT_PEM)
        .await
        .unwrap();
    let session_path = p2p
        .connect("02:00:00:00:aa:42", "pbc", "", 255, false)
        .await
        .unwrap();
    env.wlan.emit_p2p(&P2pEvent::PersistentGroupFormed {
        device: InterfaceName::new("wlan0").unwrap(),
        role: P2pRole::GroupOwner,
        ssid: Ssid::new("DIRECT-auth").unwrap(),
        go_address: MacAddress::from_octets([2, 0, 0, 0, 0, 0x66]),
        psk: kestrel_model::Secret::new("group-psk"),
    });
    eventually("persistent group exported", || async {
        !env.client.p2p_groups().await.unwrap().is_empty()
    })
    .await;
    let group_path: zbus::OwnedObjectPath = env.client.p2p_groups().await.unwrap()[0]
        .inner()
        .path()
        .to_owned()
        .into();
    let profile = env.client.profile(profile_path.clone()).await.unwrap();
    let cert = env.client.certificate(cert_path).await.unwrap();
    let group = env.client.p2p_group(group_path.clone()).await.unwrap();
    let session = env.client.session(session_path).await.unwrap();
    let agent_path = zbus::ObjectPath::try_from("/test/agent").unwrap();
    manager.register_agent(&agent_path).await.unwrap();

    // Wrong path on unregister must fail even for the owner; another peer must also fail.
    let wrong_path = zbus::ObjectPath::try_from("/test/other").unwrap();
    assert_eq!(
        error_name(&manager.unregister_agent(&wrong_path).await.unwrap_err()),
        "com.hihusky.Kestrel.Error.AccessDenied"
    );
    let other_client = Client::new(env.bus.connect().await).await.unwrap();
    assert_eq!(
        error_name(
            &other_client
                .manager()
                .await
                .unwrap()
                .unregister_agent(&agent_path)
                .await
                .unwrap_err()
        ),
        "com.hihusky.Kestrel.Error.AccessDenied"
    );
    manager.unregister_agent(&agent_path).await.unwrap();

    // Deny all actions and verify every mutating method fails with AccessDenied.
    auth.set_allow_all(false);
    let denied: Vec<zbus::Error> = vec![
        manager.set_wireless_enabled(false).await.unwrap_err(),
        manager
            .add_profile(
                settings(&[
                    ("ssid", Variant::from("blocked")),
                    ("security", Variant::from("open")),
                ]),
                secrets(""),
            )
            .await
            .unwrap_err(),
        manager
            .import_certificate("Blocked", TEST_CERT_PEM)
            .await
            .unwrap_err(),
        manager.register_agent(&agent_path).await.unwrap_err(),
        device.scan().await.unwrap_err(),
        device.connect(&profile_path.as_ref()).await.unwrap_err(),
        device.disconnect().await.unwrap_err(),
        device.set_autoconnect(false).await.unwrap_err(),
        p2p.find(10).await.unwrap_err(),
        p2p.stop_find().await.unwrap_err(),
        p2p.set_wfd_subelements(&[0, 1]).await.unwrap_err(),
        p2p.connect("02:00:00:00:aa:42", "pbc", "", 255, false)
            .await
            .unwrap_err(),
        p2p.start_group(0, false).await.unwrap_err(),
        p2p.connect_persistent(&group_path.as_ref(), "", 0)
            .await
            .unwrap_err(),
        p2p.start_persistent_group(&group_path.as_ref(), 0)
            .await
            .unwrap_err(),
        hotspot
            .start(
                settings(&[
                    ("ssid", Variant::from("blocked-ap")),
                    ("security", Variant::from("open")),
                ]),
                "",
            )
            .await
            .unwrap_err(),
        hotspot.stop().await.unwrap_err(),
        profile
            .update(
                settings(&[("name", Variant::from("Blocked"))]),
                "keep",
                secrets(""),
            )
            .await
            .unwrap_err(),
        profile.delete().await.unwrap_err(),
        cert.delete().await.unwrap_err(),
        group.delete().await.unwrap_err(),
        session.close().await.unwrap_err(),
    ];
    for err in &denied {
        assert_eq!(error_name(err), "com.hihusky.Kestrel.Error.AccessDenied");
    }
    // Read-only calls still succeed.
    assert!(manager.wireless_enabled().await.unwrap());
    assert_eq!(manager.history(0).await.unwrap().len(), 0);
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn polkit_authorizer_checks_authority_allow_and_deny() {
    struct MockAuthority {
        allow: std::sync::atomic::AtomicBool,
    }

    #[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
    impl MockAuthority {
        #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
        fn check_authorization(
            &self,
            _subject: (String, HashMap<String, zbus::OwnedVariant>),
            action_id: String,
            _details: HashMap<String, String>,
            _flags: u32,
            _cancellation_id: String,
        ) -> (bool, bool, HashMap<String, String>) {
            assert_eq!(action_id, "com.hihusky.kestrel.toggle-wireless");
            let ok = self.allow.load(std::sync::atomic::Ordering::SeqCst);
            (ok, false, HashMap::new())
        }
    }

    let bus = TestBus::start();
    let authority_conn = bus.connect().await;
    authority_conn
        .object_server()
        .at(
            "/org/freedesktop/PolicyKit1/Authority",
            MockAuthority {
                allow: std::sync::atomic::AtomicBool::new(true),
            },
        )
        .await
        .unwrap();
    authority_conn
        .request_name("org.freedesktop.PolicyKit1")
        .await
        .unwrap();

    let polkit = kestrel_api::Polkit::new(bus.connect().await);
    polkit
        .check(":1.99", Action::ToggleWireless)
        .await
        .expect("authorized by mock polkit");

    let iface = authority_conn
        .object_server()
        .interface::<_, MockAuthority>("/org/freedesktop/PolicyKit1/Authority")
        .await
        .unwrap();
    iface
        .get()
        .await
        .allow
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let err = polkit
        .check(":1.99", Action::ToggleWireless)
        .await
        .unwrap_err();
    assert!(matches!(err, ApiError::AccessDenied(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_agent_caller_disconnect_during_auth_does_not_strand_slot() {
    #[derive(Debug)]
    struct DelayedAllow {
        entered: Arc<tokio::sync::Notify>,
        proceed: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl Authorizer for DelayedAllow {
        async fn check(&self, _sender: &str, action: Action) -> Result<(), ApiError> {
            if action == Action::RegisterAgent {
                self.entered.notify_one();
                self.proceed.notified().await;
            }
            Ok(())
        }
    }

    let entered = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());
    let env = Env::start(Arc::new(DelayedAllow {
        entered: entered.clone(),
        proceed: proceed.clone(),
    }))
    .await;

    let doomed_conn = env.bus.connect().await;
    let doomed_client = Client::new(doomed_conn.clone()).await.unwrap();
    let doomed_mgr = doomed_client.manager().await.unwrap();
    let agent_path = zbus::ObjectPath::try_from("/test/agent").unwrap();
    let reg_task = tokio::spawn({
        let path = agent_path.to_owned();
        async move { doomed_mgr.register_agent(&path.as_ref()).await }
    });

    // Wait until the server is blocked inside authorization, then drop the caller.
    entered.notified().await;
    reg_task.abort();
    drop(doomed_client);
    drop(doomed_conn);
    tokio::time::sleep(Duration::from_millis(50)).await;
    proceed.notify_waiters();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A healthy client can still register without hitting Busy.
    let healthy_mgr = env.client.manager().await.unwrap();
    let ok_task = tokio::spawn({
        let path = agent_path.to_owned();
        async move { healthy_mgr.register_agent(&path.as_ref()).await }
    });
    entered.notified().await;
    proceed.notify_waiters();
    ok_task
        .await
        .unwrap()
        .expect("slot must remain free after dead caller");
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wfd_subelements_limit_and_p2p_group_change_propagation() {
    let env = Env::start(Arc::new(AllowAll)).await;
    let p2p = env.client.p2p("wlan0").await.unwrap();
    let oversized = vec![0u8; 1025];
    let err = p2p.set_wfd_subelements(&oversized).await.unwrap_err();
    assert_eq!(
        error_name(&err),
        "com.hihusky.Kestrel.Error.InvalidArgument"
    );

    let go = MacAddress::from_octets([2, 0, 0, 0, 0, 0x77]);
    env.wlan.emit_p2p(&P2pEvent::PersistentGroupFormed {
        device: InterfaceName::new("wlan0").unwrap(),
        role: P2pRole::GroupOwner,
        ssid: Ssid::new("DIRECT-sync").unwrap(),
        go_address: go,
        psk: kestrel_model::Secret::new("group-psk-1"),
    });
    eventually("persistent group exported", || async {
        !env.client.p2p_groups().await.unwrap().is_empty()
    })
    .await;
    let group = env.client.p2p_groups().await.unwrap().pop().unwrap();
    assert_eq!(group.role().await.unwrap(), "group-owner");
    assert_eq!(group.peer().await.unwrap(), "");

    // Updating the group in catalog propagates CatalogEvent::P2pGroupChanged to D-Bus.
    let peer = MacAddress::from_octets([2, 0, 0, 0, 0, 0x88]);
    env.catalog
        .save_formed_p2p_group(
            P2pRole::GroupOwner,
            Ssid::new("DIRECT-sync").unwrap(),
            go,
            Some(peer),
            "DIRECT-sync".into(),
            kestrel_model::Secret::new("group-psk-2"),
            1_750_000_000,
        )
        .await
        .unwrap();
    eventually("persistent group updated", || async {
        group.last_connected().await.unwrap() == 1_750_000_000
            && group.peer().await.unwrap() == "02:00:00:00:00:88"
    })
    .await;
    env.stop().await;
}

// ---------------------------------------------------------------------------
// The reference documentation matches what is exported.
// ---------------------------------------------------------------------------

use std::collections::{BTreeMap, BTreeSet};

/// Member names per interface, from `docs/dbus-api.md`: every backticked
/// name in the first column of each interface's table, without arguments.
fn documented() -> BTreeMap<String, BTreeSet<String>> {
    let doc = include_str!("../../../docs/dbus-api.md");
    let mut result = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in doc.lines() {
        if line.starts_with("## ") {
            current = line
                .split('`')
                .find(|part| part.starts_with("com.hihusky.Kestrel."))
                .map(str::to_owned);
            continue;
        }
        let (Some(interface), Some(first)) = (&current, line.strip_prefix('|')) else {
            continue;
        };
        let cell = first.split('|').next().unwrap_or("");
        for (index, part) in cell.split('`').enumerate() {
            let name = part.split('(').next().unwrap_or("").trim();
            if index % 2 == 1 && name.chars().next().is_some_and(char::is_uppercase) {
                result
                    .entry(interface.clone())
                    .or_insert_with(BTreeSet::new)
                    .insert(name.to_owned());
            }
        }
    }
    result
}

async fn exported(connection: &zbus::Connection, path: &str) -> BTreeMap<String, BTreeSet<String>> {
    let proxy = zbus::fdo::IntrospectableProxy::builder(connection)
        .destination(kestrel_api::BUS_NAME)
        .path(path.to_owned())
        .build()
        .await
        .unwrap();
    let xml = proxy.introspect().await.unwrap();
    let mut result = BTreeMap::new();
    for block in xml.split("<interface name=\"").skip(1) {
        let name = block.split('"').next().unwrap().to_owned();
        if !name.starts_with("com.hihusky.Kestrel.") {
            continue;
        }
        let body = block.split("</interface>").next().unwrap();
        let members: BTreeSet<String> = ["<method name=\"", "<property name=\"", "<signal name=\""]
            .iter()
            .flat_map(|tag| {
                body.split(tag)
                    .skip(1)
                    .map(|rest| rest.split('"').next().unwrap().to_owned())
            })
            .collect();
        result.insert(name, members);
    }
    result
}

const TEST_CERT_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nMAowAwIBAQMDAAEC\n-----END CERTIFICATE-----\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reference_documentation_matches_the_exported_api() {
    let env = Env::start(Arc::new(AllowAll)).await;
    let profile = env
        .client
        .manager()
        .await
        .unwrap()
        .add_profile(
            settings(&[
                ("ssid", Variant::from("doc")),
                ("security", Variant::from("open")),
            ]),
            secrets(""),
        )
        .await
        .unwrap();
    let session = env
        .client
        .p2p("wlan0")
        .await
        .unwrap()
        .connect("02:00:00:00:aa:42", "pbc", "", 255, true)
        .await
        .unwrap();
    let certificate = env
        .client
        .manager()
        .await
        .unwrap()
        .import_certificate("Doc CA", TEST_CERT_PEM)
        .await
        .unwrap();
    // A persistent group object appears once the backend provisions one.
    env.wlan.emit_p2p(&P2pEvent::PersistentGroupFormed {
        device: InterfaceName::new("wlan0").unwrap(),
        role: P2pRole::GroupOwner,
        ssid: Ssid::new("DIRECT-doc").unwrap(),
        go_address: MacAddress::from_octets([2, 0, 0, 0, 0, 0x43]),
        psk: kestrel_model::Secret::new("group-psk"),
    });
    eventually("persistent group exported", || async {
        !env.client.p2p_groups().await.unwrap().is_empty()
    })
    .await;
    let connection = env.client.connection().clone();
    let mut actual = BTreeMap::new();
    let mut paths = vec![
        kestrel_api::ROOT_PATH.to_owned(),
        "/com/hihusky/Kestrel/Device/wlan0".to_owned(),
        profile.as_str().to_owned(),
        session.as_str().to_owned(),
        certificate.as_str().to_owned(),
    ];
    for group in env.client.p2p_groups().await.unwrap() {
        paths.push(group.inner().path().as_str().to_owned());
    }
    for path in &paths {
        actual.extend(exported(&connection, path).await);
    }
    let mut documented = documented();
    // Exported by consumers, not by Kestrel.
    documented.remove("com.hihusky.Kestrel.Agent");
    assert_eq!(
        documented.keys().collect::<Vec<_>>(),
        actual.keys().collect::<Vec<_>>(),
        "documented interfaces differ from exported ones"
    );
    for (interface, members) in &actual {
        assert_eq!(
            &documented[interface], members,
            "{interface}: docs/dbus-api.md is out of date"
        );
    }
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hotspot_starts_configures_shared_l3_and_stops() {
    let env = Env::start(Arc::new(AllowAll)).await;
    let device = env.client.device("wlan0").await.unwrap();
    assert_ne!(
        device.supported_security().await.unwrap(),
        [] as [String; 0]
    );

    let hotspot = env.client.hotspot("wlan0").await.unwrap();
    assert_eq!(hotspot.state().await.unwrap(), "stopped");

    hotspot
        .start(
            settings(&[
                ("ssid", Variant::from("kestrel-hotspot")),
                ("security", Variant::from("wpa-personal")),
                ("frequency", Variant::from(2437u32)),
            ]),
            "hotspot-passphrase",
        )
        .await
        .unwrap();
    eventually("hotspot active", || async {
        hotspot.state().await.unwrap() == "active"
    })
    .await;
    assert_eq!(hotspot.ssid().await.unwrap(), "kestrel-hotspot");
    assert_eq!(hotspot.security().await.unwrap(), "wpa-personal");
    assert_eq!(hotspot.frequency().await.unwrap(), 2437);
    assert_ne!(hotspot.gateway().await.unwrap(), "");

    hotspot.stop().await.unwrap();
    eventually("hotspot stopped", || async {
        hotspot.state().await.unwrap() == "stopped"
    })
    .await;
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_import_enterprise_profile_and_delete_guard() {
    let env = Env::start(Arc::new(AllowAll)).await;
    let manager = env.client.manager().await.unwrap();
    let ca_path = manager
        .import_certificate("Corp CA", TEST_CERT_PEM)
        .await
        .unwrap();
    let ca = env.client.certificate(ca_path.clone()).await.unwrap();
    let ca_id = ca.id().await.unwrap();
    assert_eq!(ca.name().await.unwrap(), "Corp CA");
    assert_ne!(ca.fingerprint_sha256().await.unwrap(), "");

    let mut bundle = SecretBundle::new();
    bundle.insert("passphrase".to_owned(), "eap-secret".to_owned());
    let profile_path = manager
        .add_profile(
            settings(&[
                ("ssid", Variant::from("corp-wifi")),
                ("security", Variant::from("wpa3-enterprise")),
                ("enterprise.eap", Variant::from("peap")),
                ("enterprise.identity", Variant::from("alice@corp.example")),
                ("enterprise.phase2", Variant::from("mschapv2")),
                ("enterprise.ca_cert", Variant::from(ca_id.as_str())),
                (
                    "enterprise.domain_suffix_match",
                    Variant::from("radius.corp.example"),
                ),
            ]),
            bundle,
        )
        .await
        .unwrap();
    let profile = env.client.profile(profile_path).await.unwrap();
    assert!(profile.has_secret().await.unwrap());
    let exported = profile.settings().await.unwrap();
    assert_eq!(
        String::try_from(exported["enterprise.identity"].try_clone().unwrap()).unwrap(),
        "alice@corp.example"
    );

    // Certificate referenced by a profile cannot be deleted until the profile is deleted.
    let err = ca.delete().await.unwrap_err();
    assert_eq!(error_name(&err), "com.hihusky.Kestrel.Error.Busy");

    profile.delete().await.unwrap();
    eventually("profile removed", || async {
        env.client.profiles().await.unwrap().is_empty()
    })
    .await;
    ca.delete().await.unwrap();
    eventually("cert removed", || async {
        env.client.certificates().await.unwrap().is_empty()
    })
    .await;
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_p2p_group_lifecycle_and_reconnect() {
    let env = Env::start(Arc::new(AllowAll)).await;
    env.wlan.emit_p2p(&P2pEvent::PersistentGroupFormed {
        device: InterfaceName::new("wlan0").unwrap(),
        role: P2pRole::GroupOwner,
        ssid: Ssid::new("DIRECT-persist").unwrap(),
        go_address: MacAddress::from_octets([2, 0, 0, 0, 0, 0x55]),
        psk: kestrel_model::Secret::new("group-psk"),
    });
    eventually("persistent group exported", || async {
        !env.client.p2p_groups().await.unwrap().is_empty()
    })
    .await;
    let groups = env.client.p2p_groups().await.unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.ssid().await.unwrap(), "DIRECT-persist");
    assert_eq!(group.role().await.unwrap(), "group-owner");

    let p2p = env.client.p2p("wlan0").await.unwrap();
    let session_path = p2p
        .start_persistent_group(&group.inner().path().as_ref(), 0)
        .await
        .unwrap();
    let session = env.client.session(session_path).await.unwrap();
    assert_eq!(
        session.device().await.unwrap().as_str(),
        "/com/hihusky/Kestrel/Device/wlan0"
    );
    session.close().await.unwrap();
    eventually("session closed", || async {
        env.client.sessions().await.unwrap().is_empty()
    })
    .await;

    group.delete().await.unwrap();
    eventually("persistent group removed", || async {
        env.client.p2p_groups().await.unwrap().is_empty()
    })
    .await;
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_wait_fault_reports_bus_name_loss() {
    let mut env = Env::start(Arc::new(AllowAll)).await;
    let mut server = env.server.take().unwrap();
    let conn = server.connection().clone();
    conn.release_name(kestrel_api::BUS_NAME).await.unwrap();
    let reason = tokio::time::timeout(Duration::from_secs(3), server.wait_fault())
        .await
        .expect("server must report bus name loss promptly");
    assert!(
        reason.contains("lost D-Bus name"),
        "unexpected fault reason: {reason}"
    );
    server.stop().await;
    env.stop().await;
}

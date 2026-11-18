// SPDX-License-Identifier: LGPL-2.1-or-later

//! Cross-layer workflows against in-memory fakes: no radios, no root.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kestrel_catalog::{Catalog, CatalogError, CatalogStores, SecretUpdate};
use kestrel_controller::{
    Controller, ControllerConfig, ControllerError, ControllerEvent, ControllerHandle,
    ControllerPorts, SessionId, StationState,
};
use kestrel_model::{
    Bss, CertificatePem, ConnectionOutcome, EapMethod, EnterpriseConfig, FailureReason,
    HotspotConfig, HotspotSecurity, InterfaceName, Ipv6Mode, L3Config, MacAddress, OnlineState,
    P2pRole, ProfileSecrets, ProfileSecurity, Secret, Security, Ssid, WifiProfile, WpsMethod,
    WpsPin,
};
use kestrel_ports::PortError;
use kestrel_ports::agent::{Agent, PeerRequest, PinDisplay, SecretRequest};
use kestrel_ports::l3::{DhcpLease, L3Intent, L3Phase, L3Status};
use kestrel_ports::p2p::{P2pEvent, RequestedMethod};
use kestrel_testkit::{
    FakeL3, FakeWlan, MemoryCerts, MemoryHistory, MemoryP2pGroups, MemoryProfiles, MemorySecrets,
    MemoryState, WlanCall,
};

const PEER: MacAddress = MacAddress::from_octets([2, 0, 0, 0, 0, 0x42]);

struct Env {
    wlan: FakeWlan,
    l3: FakeL3,
    profiles: MemoryProfiles,
    secrets: MemorySecrets,
    history: MemoryHistory,
    state: MemoryState,
    catalog: Catalog,
    controller: Controller,
    handle: ControllerHandle,
    wlan0: InterfaceName,
}

#[allow(clippy::too_many_arguments)]
async fn open_catalog(
    profiles: &MemoryProfiles,
    secrets: &MemorySecrets,
    certs: &MemoryCerts,
    p2p_groups: &MemoryP2pGroups,
    history: &MemoryHistory,
) -> Catalog {
    Catalog::open(CatalogStores {
        profiles: Arc::new(profiles.clone()),
        secrets: Arc::new(secrets.clone()),
        certs: Arc::new(certs.clone()),
        p2p_groups: Arc::new(p2p_groups.clone()),
        history: Arc::new(history.clone()),
    })
    .await
    .expect("catalog opens")
}

async fn start_with(
    profiles: Vec<WifiProfile>,
    setup: impl FnOnce(&FakeWlan, &FakeL3, &MemorySecrets),
) -> Env {
    let wlan = FakeWlan::new();
    let l3 = FakeL3::new();
    let profiles = MemoryProfiles::with(profiles);
    let secrets = MemorySecrets::default();
    let certs = MemoryCerts::default();
    let p2p_groups = MemoryP2pGroups::default();
    let history = MemoryHistory::default();
    let state = MemoryState::default();
    let wlan0 = wlan.add_device("wlan0");
    setup(&wlan, &l3, &secrets);
    let catalog = open_catalog(&profiles, &secrets, &certs, &p2p_groups, &history).await;
    let controller = Controller::start(
        ControllerConfig::default(),
        ControllerPorts {
            wlan: Arc::new(wlan.clone()),
            l3: Arc::new(l3.clone()),
            state: Arc::new(state.clone()),
        },
        catalog.clone(),
    )
    .await
    .expect("controller starts");
    let handle = controller.handle();
    Env {
        wlan,
        l3,
        profiles,
        secrets,
        history,
        state,
        catalog,
        controller,
        handle,
        wlan0,
    }
}

fn home() -> WifiProfile {
    WifiProfile::new(Ssid::new("home").unwrap(), ProfileSecurity::WpaPersonal)
}

fn bss(ssid: &str) -> Bss {
    Bss {
        ssid: Ssid::new(ssid).unwrap(),
        bssid: MacAddress::from_octets([2, 0, 0, 0, 0, 1]),
        frequency: 2412,
        signal: -50,
        security: Security::Wpa2Psk,
    }
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..500 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn station_state(env: &Env) -> StationState {
    env.handle.device(&env.wlan0).await.unwrap().station.state
}

async fn wait_connected(env: &Env) {
    eventually("connected", || async {
        matches!(station_state(env).await, StationState::Connected { .. })
    })
    .await;
}

#[derive(Debug, Default)]
struct TestAgent {
    secret: Mutex<Option<String>>,
    accept: Mutex<Option<WpsMethod>>,
    secret_requests: AtomicUsize,
    pins: Mutex<Vec<String>>,
    reasons: Mutex<Vec<FailureReason>>,
}

#[async_trait]
impl Agent for TestAgent {
    async fn request_secret(&self, request: SecretRequest) -> Option<Secret> {
        self.secret_requests.fetch_add(1, Ordering::SeqCst);
        self.reasons.lock().unwrap().push(request.reason);
        self.secret.lock().unwrap().clone().map(Secret::new)
    }

    async fn authorize_peer(&self, _request: PeerRequest) -> Option<WpsMethod> {
        self.accept.lock().unwrap().clone()
    }

    async fn display_pin(&self, display: PinDisplay) {
        self.pins
            .lock()
            .unwrap()
            .push(display.pin.as_str().to_owned());
    }
}

// ---------------------------------------------------------------------------
// Station
// ---------------------------------------------------------------------------

#[tokio::test]
async fn autoconnects_and_delegates_l3_to_the_provider() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    wait_connected(&env).await;

    let connect = env
        .wlan
        .calls()
        .into_iter()
        .find(|c| matches!(c, WlanCall::Connect { .. }))
        .unwrap();
    assert_eq!(
        connect,
        WlanCall::Connect {
            device: env.wlan0.clone(),
            ssid: Ssid::new("home").unwrap(),
            security: ProfileSecurity::WpaPersonal,
            secret: Some("correct horse battery staple".into()),
        }
    );
    assert_eq!(
        env.l3.bindings().get(&env.wlan0),
        Some(&L3Intent::DhcpClient {
            ipv6: Ipv6Mode::Auto,
            anonymize: false,
            required_for_online: true,
        })
    );
    eventually("last_connected recorded", || async {
        env.profiles.get(id).unwrap().last_connected.is_some()
    })
    .await;
    assert_eq!(
        env.handle.device(&env.wlan0).await.unwrap().ssid,
        Some(Ssid::new("home").unwrap())
    );
    eventually("connection history recorded", || async {
        env.history
            .events()
            .iter()
            .any(|event| event.outcome == ConnectionOutcome::Connected && event.ssid == "home")
    })
    .await;
    env.controller.shutdown().await;
}

#[tokio::test]
async fn autoconnect_can_be_toggled_without_disconnecting() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    wait_connected(&env).await;
    env.handle
        .station()
        .set_autoconnect(&env.wlan0, false)
        .await
        .unwrap();
    eventually("autoconnect held", || async {
        env.handle
            .device(&env.wlan0)
            .await
            .unwrap()
            .station
            .autoconnect_held
    })
    .await;
    assert!(matches!(
        station_state(&env).await,
        StationState::Connected { .. }
    ));
    env.handle
        .station()
        .set_autoconnect(&env.wlan0, true)
        .await
        .unwrap();
    eventually("autoconnect resumed", || async {
        !env.handle
            .device(&env.wlan0)
            .await
            .unwrap()
            .station
            .autoconnect_held
    })
    .await;
    env.controller.shutdown().await;
}

#[tokio::test]
async fn static_and_unmanaged_profiles() {
    let mut profile = home();
    profile.security = ProfileSecurity::Open;
    profile.l3 = L3Config::Unmanaged;
    let env = start_with(vec![profile.clone()], |wlan, _, _| {
        wlan.set_visible(vec![Bss {
            security: Security::Open,
            ..bss("home")
        }]);
    })
    .await;
    wait_connected(&env).await;
    assert!(env.l3.bindings().is_empty(), "unmanaged must not bind L3");
    env.controller.shutdown().await;
}

#[tokio::test]
async fn wrong_password_asks_the_agent_and_retries_with_the_answer() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        wlan.set_password(&Ssid::new("home").unwrap(), "the-real-password");
        secrets.insert(id, "a-stale-password");
    })
    .await;
    let agent = Arc::new(TestAgent::default());
    *agent.secret.lock().unwrap() = Some("the-real-password".into());
    // Register before the first association fails.
    env.handle
        .radio()
        .set_agent(Some(agent.clone()))
        .await
        .unwrap();
    env.handle.station().connect(&env.wlan0, id).await.unwrap();
    wait_connected(&env).await;
    assert!(agent.secret_requests.load(Ordering::SeqCst) >= 1);
    assert!(
        agent
            .reasons
            .lock()
            .unwrap()
            .contains(&FailureReason::AuthFailed)
    );
    let stored = env.catalog.has_secret(id).await.unwrap();
    assert!(stored);
    env.controller.shutdown().await;
}

#[tokio::test]
async fn missing_secret_without_agent_waits_instead_of_looping() {
    let profile = home();
    let env = start_with(vec![profile.clone()], |wlan, _, _| {
        wlan.set_visible(vec![bss("home")]);
    })
    .await;
    eventually("secrets required", || async {
        let snapshot = env.handle.device(&env.wlan0).await.unwrap();
        snapshot.station.needs_secrets.contains(&profile.id)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let connects = env
        .wlan
        .calls()
        .iter()
        .filter(|c| matches!(c, WlanCall::Connect { .. }))
        .count();
    assert_eq!(connects, 0, "never associates without a secret");
    // Supplying the secret through the catalog connects.
    env.catalog
        .update_profile(
            profile.clone(),
            SecretUpdate::Set(ProfileSecrets::from_passphrase(Secret::new(
                "correct horse battery",
            ))),
        )
        .await
        .unwrap();
    wait_connected(&env).await;
    env.controller.shutdown().await;
}

#[tokio::test]
async fn disconnect_releases_l3_before_l2_and_holds_autoconnect() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    wait_connected(&env).await;
    env.handle.station().disconnect(&env.wlan0).await.unwrap();
    eventually("L3 unbound", || async { env.l3.bindings().is_empty() }).await;
    eventually("L2 disconnected", || async {
        env.wlan
            .calls()
            .contains(&WlanCall::Disconnect(env.wlan0.clone()))
    })
    .await;
    let snapshot = env.handle.device(&env.wlan0).await.unwrap();
    assert_eq!(snapshot.station.state, StationState::Idle);
    assert!(snapshot.station.autoconnect_held);
    env.controller.shutdown().await;
}

#[tokio::test]
async fn device_removal_releases_its_binding() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    wait_connected(&env).await;
    env.wlan.remove_device(&env.wlan0);
    eventually("binding released", || async {
        env.l3.bindings().is_empty()
    })
    .await;
    assert!(matches!(
        env.handle.device(&env.wlan0).await,
        Err(ControllerError::NoSuchDevice(_))
    ));
    env.controller.shutdown().await;
}

#[tokio::test]
async fn deleting_the_active_profile_disconnects_and_forgets_the_secret() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    wait_connected(&env).await;
    env.catalog.delete_profile(id).await.unwrap();
    eventually("idle", || async {
        station_state(&env).await == StationState::Idle
    })
    .await;
    assert!(!env.secrets.contains(id));
    assert!(env.l3.bindings().is_empty());
    env.controller.shutdown().await;
}

#[tokio::test]
async fn profile_validation_at_the_boundary() {
    let env = start_with(vec![], |_, _, _| {}).await;
    let mut open = home();
    open.security = ProfileSecurity::Open;
    assert!(matches!(
        env.catalog
            .add_profile(
                open.clone(),
                Some(ProfileSecrets::from_passphrase(Secret::new("not-allowed")))
            )
            .await,
        Err(CatalogError::InvalidArgument(_))
    ));
    assert!(matches!(
        env.catalog
            .add_profile(
                home(),
                Some(ProfileSecrets::from_passphrase(Secret::new("short")))
            )
            .await,
        Err(CatalogError::InvalidArgument(_))
    ));
    let id = env
        .catalog
        .add_profile(
            home(),
            Some(ProfileSecrets::from_passphrase(Secret::new(
                "long enough secret",
            ))),
        )
        .await
        .unwrap();
    // Changing security drops a secret that belonged to the old mode.
    let mut changed = env.catalog.profile(id).unwrap();
    changed.security = ProfileSecurity::Wpa3Personal;
    env.catalog
        .update_profile(changed, SecretUpdate::Keep)
        .await
        .unwrap();
    assert!(!env.secrets.contains(id));
    env.controller.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn l3_that_never_becomes_ready_is_rolled_back_and_retried() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, l3, secrets| {
        wlan.set_visible(vec![bss("home")]);
        l3.set_auto_ready(false);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    eventually("configuring", || async {
        matches!(
            station_state(&env).await,
            StationState::ConfiguringL3 { .. }
        )
    })
    .await;
    tokio::time::sleep(Duration::from_secs(31)).await;
    eventually("waiting to retry", || async {
        matches!(station_state(&env).await, StationState::Waiting { .. })
    })
    .await;
    let snapshot = env.handle.device(&env.wlan0).await.unwrap();
    assert!(matches!(
        snapshot.station.last_failure,
        Some(FailureReason::Timeout(_))
    ));
    assert!(env.l3.bindings().is_empty(), "binding rolled back");
    env.controller.shutdown().await;
}

// ---------------------------------------------------------------------------
// Wi-Fi Direct
// ---------------------------------------------------------------------------

fn group_if() -> InterfaceName {
    InterfaceName::new("p2p-wlan0-0").unwrap()
}

async fn session_state(env: &Env, id: SessionId) -> Option<&'static str> {
    env.handle.p2p().session(id).await.ok().map(|s| s.state)
}

#[tokio::test]
async fn group_owner_serves_dhcp_on_an_allocated_subnet_and_cleans_up() {
    let env = start_with(vec![], |_, l3, _| {
        l3.set_leases(vec![DhcpLease {
            address: "192.168.49.23".parse().unwrap(),
            client: Some(PEER),
        }]);
        l3.set_in_use(vec!["10.0.0.5/24".parse().unwrap()]);
    })
    .await;
    let id = env
        .handle
        .p2p()
        .connect(&env.wlan0, PEER, WpsMethod::PushButton, None, false)
        .await
        .unwrap();
    eventually("p2p connect issued", || async {
        env.wlan.calls().iter().any(|c| {
            matches!(
                c,
                WlanCall::P2pConnect {
                    go_intent: 7,
                    method: "pbc",
                    ..
                }
            )
        })
    })
    .await;
    env.wlan.emit_p2p(&P2pEvent::GoNegotiationSucceeded {
        device: env.wlan0.clone(),
        role: P2pRole::GroupOwner,
    });
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: env.wlan0.clone(),
        group_if: group_if(),
        role: P2pRole::GroupOwner,
    });
    eventually("session ready", || async {
        session_state(&env, id).await == Some("ready")
    })
    .await;
    let L3Intent::SharedSubnet(shared) = env.l3.bindings()[&group_if()].clone() else {
        panic!("GO must serve a shared subnet");
    };
    assert_eq!(shared.address.to_string(), "192.168.49.1/24");
    assert_eq!((shared.pool_offset, shared.pool_size), (2, 253));
    assert!(!shared.emit_router, "a P2P GO is not an uplink");
    let snapshot = env.handle.p2p().session(id).await.unwrap();
    assert_eq!(snapshot.role, Some(P2pRole::GroupOwner));
    assert_eq!(snapshot.peer_ip, "192.168.49.23".parse().ok());

    env.handle.p2p().close_session(id).await.unwrap();
    eventually("group removed", || async {
        env.wlan
            .calls()
            .contains(&WlanCall::P2pRemoveGroup(env.wlan0.clone(), group_if()))
    })
    .await;
    assert!(env.l3.bindings().is_empty());
    // The subnet was released: the next GO session gets it again.
    let unbind_before_remove = {
        let history = env.l3.history();
        history.last() == Some(&(group_if(), None))
    };
    assert!(unbind_before_remove);
    assert!(matches!(
        env.handle.p2p().session(id).await,
        Err(ControllerError::NoSuchSession(_))
    ));
    let second = env
        .handle
        .p2p()
        .connect(&env.wlan0, PEER, WpsMethod::PushButton, None, false)
        .await
        .unwrap();
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: env.wlan0.clone(),
        group_if: group_if(),
        role: P2pRole::GroupOwner,
    });
    eventually("second session ready", || async {
        session_state(&env, second).await == Some("ready")
    })
    .await;
    let L3Intent::SharedSubnet(again) = env.l3.bindings()[&group_if()].clone() else {
        panic!();
    };
    assert_eq!(again.address.to_string(), "192.168.49.1/24");
    env.controller.shutdown().await;
    assert!(
        env.l3.bindings().is_empty(),
        "shutdown releases the GO binding"
    );
}

#[tokio::test]
async fn autonomous_group_owner_serves_dhcp_without_negotiation() {
    let env = start_with(vec![], |_, l3, _| {
        l3.set_leases(vec![DhcpLease {
            address: "192.168.49.23".parse().unwrap(),
            client: Some(PEER),
        }]);
    })
    .await;
    let id = env
        .handle
        .p2p()
        .start_group(&env.wlan0, Some(2412), false)
        .await
        .unwrap();
    eventually("group add issued", || async {
        env.wlan.calls().contains(&WlanCall::P2pStartGroup {
            device: env.wlan0.clone(),
            frequency: Some(2412),
            persistent: false,
        })
    })
    .await;

    let snapshot = env.handle.p2p().session(id).await.unwrap();
    assert!(snapshot.autonomous);
    assert_eq!(snapshot.peer, None);
    assert_eq!(snapshot.state, "forming");
    assert_eq!(snapshot.role, Some(P2pRole::GroupOwner));

    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: env.wlan0.clone(),
        group_if: group_if(),
        role: P2pRole::GroupOwner,
    });
    eventually("group authorized", || async {
        env.wlan
            .calls()
            .contains(&WlanCall::P2pAuthorizeGroup(env.wlan0.clone(), group_if()))
    })
    .await;
    eventually("session ready", || async {
        session_state(&env, id).await == Some("ready")
    })
    .await;
    let L3Intent::SharedSubnet(shared) = env.l3.bindings()[&group_if()].clone() else {
        panic!("an autonomous GO must serve a shared subnet");
    };
    assert_eq!(shared.address.to_string(), "192.168.49.1/24");
    assert!(!shared.emit_router);
    let snapshot = env.handle.p2p().session(id).await.unwrap();
    assert_eq!(snapshot.peer_ip, "192.168.49.23".parse().ok());

    env.handle.p2p().close_session(id).await.unwrap();
    eventually("group removed", || async {
        env.wlan
            .calls()
            .contains(&WlanCall::P2pRemoveGroup(env.wlan0.clone(), group_if()))
    })
    .await;
    assert!(env.l3.bindings().is_empty());
    env.controller.shutdown().await;
}

#[tokio::test]
async fn client_role_runs_a_dhcp_client_on_the_group_interface() {
    let env = start_with(vec![], |_, _, _| {}).await;
    let pin = WpsPin::new("12345670").unwrap();
    let id = env
        .handle
        .p2p()
        .connect(
            &env.wlan0,
            PEER,
            WpsMethod::EnterPin(pin),
            Some(kestrel_model::GoIntent::new(0).unwrap()),
            false,
        )
        .await
        .unwrap();
    env.wlan.emit_p2p(&P2pEvent::GoNegotiationSucceeded {
        device: env.wlan0.clone(),
        role: P2pRole::Client,
    });
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: env.wlan0.clone(),
        group_if: group_if(),
        role: P2pRole::Client,
    });
    eventually("ready", || async {
        session_state(&env, id).await == Some("ready")
    })
    .await;
    assert_eq!(
        env.l3.bindings()[&group_if()],
        L3Intent::DhcpClient {
            ipv6: Ipv6Mode::Disabled,
            anonymize: true,
            required_for_online: false,
        }
    );
    // The peer ends the group.
    env.wlan.emit_p2p(&P2pEvent::GroupFinished {
        device: env.wlan0.clone(),
        group_if: group_if(),
    });
    eventually("session gone", || async {
        session_state(&env, id).await.is_none()
    })
    .await;
    assert!(env.l3.bindings().is_empty());
    assert!(
        !env.wlan
            .calls()
            .iter()
            .any(|c| matches!(c, WlanCall::P2pRemoveGroup(..))),
        "a finished group is not removed again"
    );
    env.controller.shutdown().await;
}

#[tokio::test]
async fn negotiation_failure_is_reported_and_cancelled() {
    let env = start_with(vec![], |_, _, _| {}).await;
    let mut notifications = env.handle.subscribe();
    let id = env
        .handle
        .p2p()
        .connect(&env.wlan0, PEER, WpsMethod::PushButton, None, false)
        .await
        .unwrap();
    env.wlan.emit_p2p(&P2pEvent::GoNegotiationFailed {
        device: env.wlan0.clone(),
        status: 9,
    });
    let failure = loop {
        match notifications.recv().await.unwrap() {
            ControllerEvent::SessionChanged(s) if s.id == id && s.state == "closed" => {
                break s.failure;
            }
            _ => {}
        }
    };
    assert_eq!(failure, Some(FailureReason::NegotiationFailed(9)));
    eventually("cancelled", || async {
        env.wlan
            .calls()
            .contains(&WlanCall::P2pCancel(env.wlan0.clone()))
    })
    .await;
    env.controller.shutdown().await;
}

#[tokio::test]
async fn one_session_per_device_and_capability_checks() {
    let env = start_with(vec![], |_, _, _| {}).await;
    env.handle
        .p2p()
        .connect(&env.wlan0, PEER, WpsMethod::PushButton, None, false)
        .await
        .unwrap();
    assert!(matches!(
        env.handle
            .p2p()
            .connect(&env.wlan0, PEER, WpsMethod::PushButton, None, false)
            .await,
        Err(ControllerError::Busy(_))
    ));
    env.controller.shutdown().await;

    let wlan = FakeWlan::new().without_p2p();
    let l3 = FakeL3::new();
    let wlan0 = wlan.add_device("wlan0");
    let catalog = open_catalog(
        &MemoryProfiles::default(),
        &MemorySecrets::default(),
        &MemoryCerts::default(),
        &MemoryP2pGroups::default(),
        &MemoryHistory::default(),
    )
    .await;
    let controller = Controller::start(
        ControllerConfig::default(),
        ControllerPorts {
            wlan: Arc::new(wlan),
            l3: Arc::new(l3),
            state: Arc::new(MemoryState::default()),
        },
        catalog,
    )
    .await
    .unwrap();
    assert!(matches!(
        controller
            .handle()
            .p2p()
            .connect(&wlan0, PEER, WpsMethod::PushButton, None, false)
            .await,
        Err(ControllerError::NotSupported(_))
    ));
    controller.shutdown().await;
}

#[tokio::test]
async fn display_pin_goes_to_the_agent_only() {
    let env = start_with(vec![], |wlan, _, _| {
        wlan.set_p2p_pin(Some(WpsPin::new("12345670").unwrap()));
    })
    .await;
    let agent = Arc::new(TestAgent::default());
    env.handle
        .radio()
        .set_agent(Some(agent.clone()))
        .await
        .unwrap();
    let mut notifications = env.handle.subscribe();
    let id = env
        .handle
        .p2p()
        .connect(&env.wlan0, PEER, WpsMethod::DisplayPin, None, false)
        .await
        .unwrap();
    eventually("pin displayed", || async {
        !agent.pins.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(agent.pins.lock().unwrap()[0], "12345670");
    let snapshot = env.handle.p2p().session(id).await.unwrap();
    assert!(!format!("{snapshot:?}").contains("12345670"));
    while let Ok(notification) = notifications.try_recv() {
        assert!(!format!("{notification:?}").contains("12345670"));
    }
    env.controller.shutdown().await;
}

#[tokio::test]
async fn incoming_requests_need_agent_authorization() {
    let env = start_with(vec![], |_, _, _| {}).await;
    // No agent: ignored.
    env.wlan.emit_p2p(&P2pEvent::NegotiationRequest {
        device: env.wlan0.clone(),
        peer: PEER,
        method: RequestedMethod::PushButton,
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(env.handle.p2p().sessions().await.unwrap().len(), 0);

    let agent = Arc::new(TestAgent::default());
    *agent.accept.lock().unwrap() = Some(WpsMethod::PushButton);
    env.handle.radio().set_agent(Some(agent)).await.unwrap();
    env.wlan.emit_p2p(&P2pEvent::NegotiationRequest {
        device: env.wlan0.clone(),
        peer: PEER,
        method: RequestedMethod::PushButton,
    });
    eventually("incoming session", || async {
        env.handle
            .p2p()
            .sessions()
            .await
            .unwrap()
            .iter()
            .any(|s| s.incoming && s.peer == Some(PEER))
    })
    .await;
    env.controller.shutdown().await;
}

#[tokio::test]
async fn unrequested_groups_are_removed() {
    let env = start_with(vec![], |_, _, _| {}).await;
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: env.wlan0.clone(),
        group_if: group_if(),
        role: P2pRole::GroupOwner,
    });
    eventually("removed", || async {
        env.wlan
            .calls()
            .contains(&WlanCall::P2pRemoveGroup(env.wlan0.clone(), group_if()))
    })
    .await;
    assert!(env.l3.bindings().is_empty());
    env.controller.shutdown().await;
}

#[tokio::test]
async fn subnet_exhaustion_fails_the_session_cleanly() {
    let env = start_with(vec![], |_, l3, _| {
        l3.set_in_use(vec!["0.0.0.0/0".parse().unwrap()]);
    })
    .await;
    let id = env
        .handle
        .p2p()
        .connect(&env.wlan0, PEER, WpsMethod::PushButton, None, false)
        .await
        .unwrap();
    let mut notifications = env.handle.subscribe();
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: env.wlan0.clone(),
        group_if: group_if(),
        role: P2pRole::GroupOwner,
    });
    let failure = loop {
        if let ControllerEvent::SessionChanged(s) = notifications.recv().await.unwrap()
            && s.id == id
            && s.state == "closed"
        {
            break s.failure;
        }
    };
    assert_eq!(failure, Some(FailureReason::NoSubnet));
    eventually("group removed", || async {
        env.wlan
            .calls()
            .contains(&WlanCall::P2pRemoveGroup(env.wlan0.clone(), group_if()))
    })
    .await;
    env.controller.shutdown().await;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn startup_sweeps_leftovers_and_shutdown_leaves_nothing() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, l3, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
        l3.set_leftovers(vec![InterfaceName::new("p2p-wlan0-9").unwrap()]);
    })
    .await;
    assert_eq!(env.wlan.calls().first(), Some(&WlanCall::Sweep));
    assert!(
        env.l3
            .history()
            .contains(&(InterfaceName::new("p2p-wlan0-9").unwrap(), None))
    );
    wait_connected(&env).await;
    let session = env
        .handle
        .p2p()
        .connect(&env.wlan0, PEER, WpsMethod::PushButton, None, false)
        .await
        .unwrap();
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: env.wlan0.clone(),
        group_if: group_if(),
        role: P2pRole::GroupOwner,
    });
    eventually("ready", || async {
        session_state(&env, session).await == Some("ready")
    })
    .await;
    assert_eq!(env.l3.bindings().len(), 2);

    let Env {
        wlan,
        l3,
        controller,
        wlan0,
        ..
    } = env;
    controller.shutdown().await;
    assert!(l3.bindings().is_empty());
    let calls = wlan.calls();
    assert!(calls.contains(&WlanCall::Disconnect(wlan0.clone())));
    assert!(calls.contains(&WlanCall::P2pRemoveGroup(wlan0, group_if())));
    assert_eq!(calls.last(), Some(&WlanCall::Sweep));
}

#[tokio::test]
async fn wireless_toggle_releases_and_restores() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    wait_connected(&env).await;
    env.handle
        .radio()
        .set_wireless_enabled(false)
        .await
        .unwrap();
    assert_eq!(station_state(&env).await, StationState::Disabled);
    assert_eq!(env.state.get(), Some(false));
    eventually("released", || async { env.l3.bindings().is_empty() }).await;
    assert!(matches!(
        env.handle.station().scan(&env.wlan0).await,
        Err(ControllerError::WirelessDisabled)
    ));
    env.handle.radio().set_wireless_enabled(true).await.unwrap();
    assert_eq!(env.state.get(), Some(true));
    wait_connected(&env).await;
    env.controller.shutdown().await;
}

#[tokio::test]
async fn persisted_wireless_off_is_honoured_on_restart() {
    let profile = home();
    let id = profile.id;
    let wlan = FakeWlan::new();
    let l3 = FakeL3::new();
    let profiles = MemoryProfiles::with(vec![profile]);
    let secrets = MemorySecrets::default();
    let history = MemoryHistory::default();
    let state = MemoryState::with(false);
    let wlan0 = wlan.add_device("wlan0");
    wlan.set_visible(vec![bss("home")]);
    secrets.insert(id, "correct horse battery staple");
    let catalog = open_catalog(
        &profiles,
        &secrets,
        &MemoryCerts::default(),
        &MemoryP2pGroups::default(),
        &history,
    )
    .await;
    let controller = Controller::start(
        ControllerConfig::default(),
        ControllerPorts {
            wlan: Arc::new(wlan),
            l3: Arc::new(l3),
            state: Arc::new(state),
        },
        catalog,
    )
    .await
    .unwrap();
    let handle = controller.handle();
    assert!(!handle.radio().wireless_enabled().await.unwrap());
    assert_eq!(
        handle.device(&wlan0).await.unwrap().station.state,
        StationState::Disabled
    );
    controller.shutdown().await;
}

#[tokio::test]
async fn hardware_rfkill_and_system_sleep_suspend_without_losing_software_toggle() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, l3, secrets| {
        wlan.set_visible(vec![bss("home")]);
        l3.set_dns(vec!["1.1.1.1".parse().unwrap()]);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    wait_connected(&env).await;
    assert_eq!(
        env.handle.radio().online_state().await.unwrap(),
        OnlineState::Online
    );
    let snap = env.handle.device(&env.wlan0).await.unwrap();
    assert_eq!(snap.frequency, Some(2412));
    assert_eq!(snap.security.as_deref(), Some("wpa2-psk"));
    assert_eq!(
        snap.l3.dns,
        vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(snap.scan_results.len(), 1);
    assert_eq!(snap.scan_results[0].profile, Some(id));

    // Hardware rfkill blocks the radio, but software WirelessEnabled stays true.
    env.wlan.set_hardware_enabled(false);
    eventually("disabled by rfkill", || async {
        station_state(&env).await == StationState::Disabled
    })
    .await;
    assert!(env.handle.radio().wireless_enabled().await.unwrap());
    assert!(
        !env.handle
            .radio()
            .wireless_hardware_enabled()
            .await
            .unwrap()
    );
    assert_eq!(
        env.handle.radio().online_state().await.unwrap(),
        OnlineState::Offline
    );
    eventually("L3 released on rfkill", || async {
        env.l3.bindings().is_empty()
    })
    .await;

    env.wlan.set_hardware_enabled(true);
    wait_connected(&env).await;
    assert!(
        env.handle
            .radio()
            .wireless_hardware_enabled()
            .await
            .unwrap()
    );

    // System sleep tears down and resume reconnects.
    env.handle.radio().set_suspended(true).await.unwrap();
    eventually("disabled on sleep", || async {
        station_state(&env).await == StationState::Disabled
    })
    .await;
    eventually("L3 released on sleep", || async {
        env.l3.bindings().is_empty()
    })
    .await;
    env.handle.radio().set_suspended(false).await.unwrap();
    wait_connected(&env).await;
    env.controller.shutdown().await;
}

#[tokio::test]
async fn corrupt_secret_prompts_the_agent_and_recovers() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        wlan.set_password(&Ssid::new("home").unwrap(), "recovered-secret");
        secrets.corrupt(id);
    })
    .await;
    eventually("secrets required after corrupt credential", || async {
        env.handle
            .device(&env.wlan0)
            .await
            .unwrap()
            .station
            .needs_secrets
            .contains(&id)
    })
    .await;
    assert!(!env.catalog.has_secret(id).await.unwrap());

    let agent = Arc::new(TestAgent::default());
    *agent.secret.lock().unwrap() = Some("recovered-secret".into());
    env.handle
        .radio()
        .set_agent(Some(agent.clone()))
        .await
        .unwrap();
    env.handle.station().connect(&env.wlan0, id).await.unwrap();
    wait_connected(&env).await;
    assert!(env.catalog.has_secret(id).await.unwrap());
    env.controller.shutdown().await;
}

#[tokio::test]
async fn backend_rejection_of_bind_is_a_classified_failure() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, l3, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
        l3.fail_next_bind(PortError::PermissionDenied("no".into()));
    })
    .await;
    eventually("failure recorded", || async {
        matches!(
            env.handle
                .device(&env.wlan0)
                .await
                .unwrap()
                .station
                .last_failure,
            Some(FailureReason::L3Failed(_))
        )
    })
    .await;
    // The retry succeeds.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::time::resume();
    wait_connected(&env).await;
    env.controller.shutdown().await;
}

#[test]
fn status_types_are_constructible() {
    let status = L3Status {
        phase: L3Phase::Ready,
        addresses: vec![],
        gateways: vec![],
        dns: vec![],
        online: OnlineState::Online,
        leases: vec![],
        dhcp_server: None,
    };
    assert_eq!(status.phase, L3Phase::Ready);
}

#[tokio::test]
async fn hotspot_suspends_station_binds_nat_and_restores_on_stop() {
    let profile = home();
    let id = profile.id;
    let env = start_with(vec![profile], |wlan, _, secrets| {
        wlan.set_visible(vec![bss("home")]);
        secrets.insert(id, "correct horse battery staple");
    })
    .await;
    wait_connected(&env).await;

    env.handle
        .hotspot()
        .start(
            &env.wlan0,
            HotspotConfig {
                ssid: Ssid::new("kestrel-ap").unwrap(),
                security: HotspotSecurity::WpaPersonal,
                frequency: Some(2412),
                hidden: false,
            },
            Some(Secret::new("hotspot-pass")),
        )
        .await
        .unwrap();
    eventually("hotspot active", || async {
        env.handle.device(&env.wlan0).await.unwrap().hotspot.state == "active"
    })
    .await;
    assert_eq!(station_state(&env).await, StationState::Disabled);
    assert!(matches!(
        env.l3.bindings().get(&env.wlan0),
        Some(L3Intent::SharedSubnet(s)) if s.emit_router && s.masquerade
    ));
    assert!(matches!(
        env.handle.p2p().start_group(&env.wlan0, None, false).await,
        Err(ControllerError::Busy(_))
    ));

    env.handle.hotspot().stop(&env.wlan0).await.unwrap();
    eventually("hotspot stopped", || async {
        env.handle.device(&env.wlan0).await.unwrap().hotspot.state == "stopped"
    })
    .await;
    wait_connected(&env).await;
    env.controller.shutdown().await;
}

#[tokio::test]
async fn certificate_import_and_referential_integrity() {
    let env = start_with(vec![], |_, _, _| {}).await;
    let pem = CertificatePem::new(
        "-----BEGIN CERTIFICATE-----\nMAowAwIBAQMDAAEC\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let ca_id = env
        .catalog
        .import_certificate("Corp CA".into(), pem)
        .await
        .unwrap();
    let mut corp = WifiProfile::new(Ssid::new("corp").unwrap(), ProfileSecurity::Wpa3Enterprise);
    corp.enterprise = Some(EnterpriseConfig {
        eap: EapMethod::Peap,
        identity: "alice@corp.example".into(),
        anonymous_identity: None,
        phase2: None,
        ca_cert: Some(ca_id),
        system_ca: false,
        client_cert: None,
        domain_suffix_match: Some("corp.example".into()),
        altsubject_match: Vec::new(),
    });
    let profile_id = env
        .catalog
        .add_profile(
            corp,
            Some(ProfileSecrets::from_passphrase(Secret::new("eap-pw"))),
        )
        .await
        .unwrap();
    assert!(matches!(
        env.catalog.delete_certificate(ca_id).await,
        Err(CatalogError::Busy(_))
    ));
    env.catalog.delete_profile(profile_id).await.unwrap();
    env.catalog.delete_certificate(ca_id).await.unwrap();
    assert_eq!(
        env.catalog.certificates(),
        [] as [kestrel_model::Certificate; 0]
    );
    env.controller.shutdown().await;
}

#[tokio::test]
async fn persistent_p2p_group_is_saved_and_reinvoked() {
    let env = start_with(vec![], |_, _, _| {}).await;
    let session_id = env
        .handle
        .p2p()
        .connect(
            &env.wlan0,
            PEER,
            WpsMethod::PushButton,
            Some(kestrel_model::GoIntent::MAX),
            true,
        )
        .await
        .unwrap();
    env.wlan.emit_p2p(&P2pEvent::PersistentGroupFormed {
        device: env.wlan0.clone(),
        role: P2pRole::GroupOwner,
        ssid: Ssid::new("DIRECT-xy-Kestrel").unwrap(),
        go_address: PEER,
        psk: Secret::new("p2p-psk-123"),
    });
    eventually("persistent group saved", || async {
        !env.catalog.p2p_groups().is_empty()
    })
    .await;
    let groups = env.catalog.p2p_groups();
    assert_eq!(groups.len(), 1);
    let group_id = groups[0].id;
    env.handle.p2p().close_session(session_id).await.unwrap();
    eventually("session closed", || async {
        env.handle.p2p().sessions().await.unwrap().is_empty()
    })
    .await;

    let reinvoked = env
        .handle
        .p2p()
        .connect_persistent(&env.wlan0, group_id, None, Some(2412))
        .await
        .unwrap();
    assert!(
        env.wlan
            .calls()
            .iter()
            .any(|c| matches!(c, WlanCall::P2pConnectPersistent { .. }))
    );
    env.handle.p2p().close_session(reinvoked).await.unwrap();
    env.catalog.delete_p2p_group(group_id).await.unwrap();
    assert_eq!(
        env.catalog.p2p_groups(),
        [] as [kestrel_model::P2pGroupProfile; 0]
    );
    env.controller.shutdown().await;
}

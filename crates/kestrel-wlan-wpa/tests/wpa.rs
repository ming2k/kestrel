// SPDX-License-Identifier: LGPL-2.1-or-later

//! The production adapter against the fake `wpa_supplicant` on a private
//! bus.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use kestrel_model::{
    EapMethod, EnterpriseConfig, GoIntent, HotspotSecurity, InterfaceName, MacAddress, P2pRole,
    ProfileSecrets, ProfileSecurity, Secret, Security, Ssid, WpsMethod,
};
use kestrel_ports::Subscription;
use kestrel_ports::ap::{ApEvent, ApStartRequest};
use kestrel_ports::p2p::{
    P2pConnectRequest, P2pEvent, P2pGroupRequest, PersistentGroupConnect, RequestedMethod,
};
use kestrel_ports::wlan::{ConnectRequest, EnterpriseConnect, LinkStatus, WlanEvent, WlanProvider};
use kestrel_wlan_wpa::WpaSupplicant;
use kestrel_wlan_wpa::testkit::FakeWpa;

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

async fn next_matching<T: std::fmt::Debug>(
    events: &mut Subscription<T>,
    what: &str,
    mut pred: impl FnMut(&T) -> bool,
) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .expect("event stream open");
        if pred(&event) {
            return event;
        }
    }
}

fn wlan0() -> InterfaceName {
    InterfaceName::new("wlan0").unwrap()
}

fn request(ssid: &str, security: ProfileSecurity, secret: Option<&str>) -> ConnectRequest {
    ConnectRequest {
        ssid: Ssid::new(ssid).unwrap(),
        security,
        secrets: secret
            .map(|s| ProfileSecrets::from_passphrase(Secret::new(s)))
            .unwrap_or_default(),
        enterprise: None,
        hidden: false,
        bssid: None,
    }
}

async fn setup() -> (TestBus, FakeWpa, WpaSupplicant) {
    let bus = TestBus::start();
    let fake = FakeWpa::start(&bus.address, &["wlan0"]).await.unwrap();
    fake.add_access_point("home", Some("correct horse battery"), "transition")
        .await
        .unwrap();
    fake.add_access_point("cafe", None, "open").await.unwrap();
    let wpa = WpaSupplicant::new(bus.connect().await).await.unwrap();
    (bus, fake, wpa)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovers_devices_and_scans_through_signals() {
    let (_bus, _fake, wpa) = setup().await;
    let devices = wpa.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, wlan0());
    assert!(devices[0].capabilities.p2p);
    assert!(wpa.p2p().is_some());

    let mut events = WlanProvider::subscribe(&wpa);
    wpa.start_scan(&wlan0()).await.unwrap();
    let WlanEvent::ScanFinished { result, .. } = next_matching(&mut events, "scan", |e| {
        matches!(e, WlanEvent::ScanFinished { .. })
    })
    .await
    else {
        unreachable!()
    };
    let mut results = result.unwrap();
    results.sort_by(|a, b| a.ssid.cmp(&b.ssid));
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].security, Security::Open);
    assert_eq!(results[1].security, Security::Wpa2Wpa3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn associates_and_reports_link_up_then_cleans_up() {
    let (_bus, fake, wpa) = setup().await;
    let mut events = WlanProvider::subscribe(&wpa);
    WlanProvider::connect(
        &wpa,
        &wlan0(),
        request(
            "home",
            ProfileSecurity::WpaPersonal,
            Some("correct horse battery"),
        ),
    )
    .await
    .unwrap();
    let event = next_matching(&mut events, "link up", |e| {
        matches!(
            e,
            WlanEvent::Link {
                status: LinkStatus::Connected { .. },
                ..
            }
        )
    })
    .await;
    let WlanEvent::Link {
        status: LinkStatus::Connected { ssid, bssid },
        ..
    } = event
    else {
        unreachable!()
    };
    assert_eq!(ssid.to_string(), "home");
    assert!(bssid.is_some());
    assert_eq!(fake.network_count(), 1);
    assert!(
        fake.calls()
            .contains(&"AddNetwork key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE".to_owned())
    );

    // Reconnecting replaces, never accumulates, network blocks.
    WlanProvider::connect(&wpa, &wlan0(), request("cafe", ProfileSecurity::Open, None))
        .await
        .unwrap();
    assert_eq!(fake.network_count(), 1);

    wpa.disconnect(&wlan0()).await.unwrap();
    next_matching(&mut events, "link down", |e| {
        matches!(
            e,
            WlanEvent::Link {
                status: LinkStatus::Disconnected,
                ..
            }
        )
    })
    .await;
    assert_eq!(fake.network_count(), 0);
    // Idempotent.
    wpa.disconnect(&wlan0()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_is_an_auth_failure() {
    let (_bus, _fake, wpa) = setup().await;
    let mut events = WlanProvider::subscribe(&wpa);
    WlanProvider::connect(
        &wpa,
        &wlan0(),
        request("home", ProfileSecurity::WpaPersonal, Some("wrong password")),
    )
    .await
    .unwrap();
    next_matching(&mut events, "auth failure", |e| {
        matches!(e, WlanEvent::AuthFailed { .. })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweep_removes_only_kestrel_networks() {
    let (bus, fake, wpa) = setup().await;
    let foreign = fake.add_foreign_network("wlan0");
    WlanProvider::connect(&wpa, &wlan0(), request("cafe", ProfileSecurity::Open, None))
        .await
        .unwrap();
    assert_eq!(fake.network_count(), 2);
    // A new process (after a crash) sweeps what the old one left.
    drop(wpa);
    let restarted = WpaSupplicant::new(bus.connect().await).await.unwrap();
    restarted.sweep().await.unwrap();
    assert_eq!(
        fake.network_count(),
        1,
        "the foreign network {foreign:?} must survive"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_restart_removes_and_re_adds_devices() {
    let (_bus, fake, wpa) = setup().await;
    let mut events = WlanProvider::subscribe(&wpa);
    fake.vanish().await.unwrap();
    next_matching(&mut events, "device removed", |e| {
        matches!(e, WlanEvent::DeviceRemoved(_))
    })
    .await;
    assert_eq!(wpa.devices().await.unwrap().len(), 0);
    fake.reappear().await.unwrap();
    next_matching(&mut events, "device added", |e| {
        matches!(e, WlanEvent::DeviceAdded(_))
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2p_discovery_negotiation_and_group_lifecycle() {
    let (_bus, fake, wpa) = setup().await;
    let p2p = wpa.p2p().unwrap();
    let mut events = p2p.subscribe();
    let peer = [2, 0, 0, 0, 0xaa, 0x42];
    fake.add_peer(peer, "Living room TV");

    p2p.configure(
        &wlan0(),
        &kestrel_ports::p2p::P2pDeviceConfig {
            device_name: "Kestrel test".into(),
            wfd_subelements: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(fake.device_name().as_deref(), Some("Kestrel test"));

    p2p.find(&wlan0(), Duration::from_secs(10)).await.unwrap();
    let P2pEvent::PeerFound { peer: found, .. } = next_matching(&mut events, "peer", |e| {
        matches!(e, P2pEvent::PeerFound { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(found.name, "Living room TV");
    assert_eq!(found.address, MacAddress::from_octets(peer));
    assert_eq!(found.device_type.as_deref(), Some("10-0050F204-5"));

    let pin = p2p
        .connect(
            &wlan0(),
            &P2pConnectRequest {
                peer: found.address,
                method: WpsMethod::DisplayPin,
                go_intent: GoIntent::MAX,
                persistent: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(pin.unwrap().as_str(), "12345670");
    assert!(
        fake.calls()
            .iter()
            .any(|c| c == "P2P.Connect peer=02000000aa42 method=display go_intent=15 pin=-")
    );

    fake.start_group("wlan0", "p2p-wlan0-0", true)
        .await
        .unwrap();
    next_matching(&mut events, "negotiated", |e| {
        matches!(
            e,
            P2pEvent::GoNegotiationSucceeded {
                role: P2pRole::GroupOwner,
                ..
            }
        )
    })
    .await;
    let P2pEvent::GroupStarted {
        device,
        group_if,
        role,
    } = next_matching(&mut events, "group", |e| {
        matches!(e, P2pEvent::GroupStarted { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(
        (device, group_if.as_str(), role),
        (wlan0(), "p2p-wlan0-0", P2pRole::GroupOwner)
    );
    // Group interfaces are never offered as devices.
    assert_eq!(wpa.devices().await.unwrap().len(), 1);

    p2p.remove_group(&wlan0(), &group_if).await.unwrap();
    next_matching(&mut events, "group finished", |e| {
        matches!(e, P2pEvent::GroupFinished { .. })
    })
    .await;

    fake.request_negotiation("wlan0", peer, 4).await.unwrap();
    let P2pEvent::NegotiationRequest { method, .. } = next_matching(&mut events, "request", |e| {
        matches!(e, P2pEvent::NegotiationRequest { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(method, RequestedMethod::PushButton);

    fake.fail_negotiation("wlan0", 9).await.unwrap();
    next_matching(&mut events, "failure", |e| {
        matches!(e, P2pEvent::GoNegotiationFailed { status: 9, .. })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_group_adds_an_autonomous_group() {
    let (_bus, fake, wpa) = setup().await;
    let p2p = wpa.p2p().unwrap();
    let mut events = p2p.subscribe();

    p2p.start_group(
        &wlan0(),
        &P2pGroupRequest {
            frequency: Some(2412),
            persistent: false,
        },
    )
    .await
    .unwrap();
    assert!(
        fake.calls()
            .iter()
            .any(|c| c == "P2P.GroupAdd frequency=2412")
    );

    let P2pEvent::GroupStarted {
        device,
        group_if,
        role,
    } = next_matching(&mut events, "autonomous group", |e| {
        matches!(e, P2pEvent::GroupStarted { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(
        (device, group_if.as_str(), role),
        (wlan0(), "p2p-wlan0-0", P2pRole::GroupOwner)
    );

    p2p.authorize_group(&wlan0(), &group_if).await.unwrap();
    assert!(
        fake.calls()
            .iter()
            .any(|c| c == "WPS.Start role=registrar type=pbc")
    );

    p2p.remove_group(&wlan0(), &group_if).await.unwrap();
    next_matching(&mut events, "group finished", |e| {
        matches!(e, P2pEvent::GroupFinished { .. })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweep_removes_leftover_groups() {
    let (bus, fake, wpa) = setup().await;
    fake.start_group("wlan0", "p2p-wlan0-0", false)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(wpa);
    let restarted = WpaSupplicant::new(bus.connect().await).await.unwrap();
    restarted.sweep().await.unwrap();
    for _ in 0..50 {
        if fake.interface_names() == ["wlan0"] {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("group survived the sweep: {:?}", fake.interface_names());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_bus_clients_coming_and_going_change_nothing() {
    let (bus, _fake, wpa) = setup().await;
    let mut events = WlanProvider::subscribe(&wpa);
    for _ in 0..3 {
        drop(bus.connect().await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                event,
                WlanEvent::DeviceRemoved(_) | WlanEvent::DeviceAdded(_)
            ),
            "spurious {event:?}"
        );
    }
    assert_eq!(wpa.devices().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attaches_sysfs_interfaces_when_supplicant_starts_empty() {
    let bus = TestBus::start();
    let fake = FakeWpa::start(&bus.address, &[]).await.unwrap();
    let sysfs = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(sysfs.path().join("wlp0s20f3/wireless")).unwrap();
    std::fs::write(
        sysfs.path().join("wlp0s20f3/address"),
        "40:c7:3c:ce:ba:9e\n",
    )
    .unwrap();
    std::fs::create_dir_all(sysfs.path().join("enp0s31f6")).unwrap();

    let wpa = WpaSupplicant::with_sysfs(bus.connect().await, sysfs.path())
        .await
        .unwrap();
    let devices = wpa.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name.as_str(), "wlp0s20f3");
    assert_eq!(
        devices[0].address,
        Some(MacAddress::parse("40:c7:3c:ce:ba:9e").unwrap())
    );
    assert!(
        fake.calls()
            .contains(&"CreateInterface wlp0s20f3".to_owned())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2p_over_truncated_p2p_dev_interface() {
    let bus = TestBus::start();
    let fake = FakeWpa::start(&bus.address, &["wlp0s20f3", "p2p-dev-wlp0s20"])
        .await
        .unwrap();
    let wpa = WpaSupplicant::new(bus.connect().await).await.unwrap();
    let device = InterfaceName::new("wlp0s20f3").unwrap();
    let devices = wpa.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, device);

    let p2p = wpa.p2p().unwrap();
    let mut events = p2p.subscribe();
    let peer = [2, 0, 0, 0, 0xaa, 0x77];
    fake.add_peer(peer, "Android Phone");

    p2p.find(&device, Duration::from_secs(10)).await.unwrap();
    let P2pEvent::PeerFound {
        device: found_on,
        peer: found,
    } = next_matching(&mut events, "peer on truncated p2p-dev", |e| {
        matches!(e, P2pEvent::PeerFound { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(found_on, device);
    assert_eq!(found.name, "Android Phone");

    fake.start_group("p2p-dev-wlp0s20", "p2p-wlp0s20f3-0", true)
        .await
        .unwrap();
    let P2pEvent::GroupStarted {
        device: started_on,
        group_if,
        role,
    } = next_matching(&mut events, "group on truncated p2p-dev", |e| {
        matches!(e, P2pEvent::GroupStarted { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(started_on, device);
    assert_eq!(group_if.as_str(), "p2p-wlp0s20f3-0");
    assert_eq!(role, P2pRole::GroupOwner);

    p2p.remove_group(&device, &group_if).await.unwrap();
    let P2pEvent::GroupFinished {
        device: finished_on,
        ..
    } = next_matching(&mut events, "group finished on truncated p2p-dev", |e| {
        matches!(e, P2pEvent::GroupFinished { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(finished_on, device);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn softap_starts_tracks_clients_and_stops_cleanly() {
    let (_bus, fake, wpa) = setup().await;
    let ap = wpa.ap().unwrap();
    let mut events = ap.subscribe();
    ap.start_ap(
        &wlan0(),
        &ApStartRequest {
            ssid: Ssid::new("kestrel-hotspot").unwrap(),
            security: HotspotSecurity::WpaPersonal,
            secret: Some(Secret::new("hotspot-pass")),
            frequency: Some(2437),
            hidden: false,
        },
    )
    .await
    .unwrap();
    next_matching(&mut events, "ap started", |e| {
        matches!(
            e,
            ApEvent::Started {
                frequency: 2437,
                ..
            }
        )
    })
    .await;

    fake.authorize_sta("wlan0", "02:11:22:33:44:55")
        .await
        .unwrap();
    let ApEvent::ClientConnected { mac, .. } = next_matching(&mut events, "sta authorized", |e| {
        matches!(e, ApEvent::ClientConnected { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(mac.to_string(), "02:11:22:33:44:55");

    ap.stop_ap(&wlan0()).await.unwrap();
    next_matching(&mut events, "ap stopped", |e| {
        matches!(e, ApEvent::Stopped { .. })
    })
    .await;
    assert_eq!(fake.network_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enterprise_uploads_blobs_and_maps_eap_failure() {
    let (_bus, fake, wpa) = setup().await;
    fake.add_access_point("corp", Some("good-eap-pw"), "wpa3-enterprise")
        .await
        .unwrap();
    let mut events = WlanProvider::subscribe(&wpa);

    let bad_req = ConnectRequest {
        ssid: Ssid::new("corp").unwrap(),
        security: ProfileSecurity::Wpa3Enterprise,
        secrets: ProfileSecrets {
            passphrase: None,
            private_key: Some(Secret::new(
                "-----BEGIN PRIVATE KEY-----\nMAowAwIBAQMDAAEC\n-----END PRIVATE KEY-----\n",
            )),
            private_key_password: None,
        },
        enterprise: Some(EnterpriseConnect {
            config: EnterpriseConfig {
                eap: EapMethod::Tls,
                identity: "alice@corp.example".into(),
                anonymous_identity: None,
                phase2: None,
                ca_cert: None,
                system_ca: false,
                client_cert: None,
                domain_suffix_match: Some("radius.corp.example".into()),
                altsubject_match: Vec::new(),
            },
            ca_cert_pem: Some(b"CA-PEM".to_vec()),
            client_cert_pem: Some(b"CERT-PEM".to_vec()),
        }),
        hidden: false,
        bssid: None,
    };
    WlanProvider::connect(&wpa, &wlan0(), bad_req)
        .await
        .unwrap();
    next_matching(&mut events, "eap auth failed", |e| {
        matches!(e, WlanEvent::AuthFailed { .. })
    })
    .await;
    assert_eq!(
        fake.blob_names("wlan0"),
        vec!["kestrel-ca", "kestrel-cert", "kestrel-key"]
    );

    wpa.disconnect(&wlan0()).await.unwrap();
    assert_eq!(fake.blob_names("wlan0"), [] as [std::string::String; 0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_p2p_events_and_reinvocation() {
    let (_bus, fake, wpa) = setup().await;
    let p2p = wpa.p2p().unwrap();
    let mut events = p2p.subscribe();
    let peer = MacAddress::from_octets([2, 0, 0, 0, 0xbb, 0x11]);
    fake.add_peer(peer.octets(), "Saved Phone");

    fake.emit_persistent_group(
        "wlan0",
        "DIRECT-ab-Kestrel",
        "02:00:00:00:aa:01",
        "p2p-secret-psk",
        true,
    )
    .await
    .unwrap();
    let P2pEvent::PersistentGroupFormed {
        role,
        ssid,
        go_address,
        psk,
        ..
    } = next_matching(&mut events, "persistent group formed", |e| {
        matches!(e, P2pEvent::PersistentGroupFormed { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(role, P2pRole::GroupOwner);
    assert_eq!(ssid.to_string(), "DIRECT-ab-Kestrel");
    assert_eq!(go_address.to_string(), "02:00:00:00:aa:01");
    assert_eq!(psk.expose(), "p2p-secret-psk");

    p2p.connect_persistent(
        &wlan0(),
        &PersistentGroupConnect {
            peer,
            role: P2pRole::Client,
            ssid,
            go_address,
            psk,
            frequency: Some(2412),
        },
    )
    .await
    .unwrap();
    assert!(fake.calls().iter().any(|c| c == "P2P.AddPersistentGroup"));
    assert!(
        fake.calls()
            .iter()
            .any(|c| c == "P2P.Invite peer=02000000bb11")
    );
    assert_eq!(fake.persistent_group_count(), 1);

    wpa.sweep().await.unwrap();
    assert_eq!(fake.persistent_group_count(), 0);
}

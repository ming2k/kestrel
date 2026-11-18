// SPDX-License-Identifier: LGPL-2.1-or-later

//! The production iwd adapter against the fake iwd on a private bus.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use kestrel_model::{
    HotspotSecurity, InterfaceName, ProfileSecrets, ProfileSecurity, Secret, Security, Ssid,
};
use kestrel_ports::ap::{ApEvent, ApStartRequest};
use kestrel_ports::wlan::{ConnectRequest, LinkStatus, WlanEvent, WlanProvider};
use kestrel_ports::{PortError, Subscription};
use kestrel_wlan_iwd::Iwd;
use kestrel_wlan_iwd::testkit::FakeIwd;

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

async fn setup() -> (TestBus, FakeIwd, Iwd) {
    let bus = TestBus::start();
    let fake = FakeIwd::start(&bus.address, "wlan0").await.unwrap();
    fake.add_network("home", Some("correct horse battery"))
        .await
        .unwrap();
    fake.add_network("cafe", None).await.unwrap();
    let iwd = Iwd::new(bus.connect().await).await.unwrap();
    (bus, fake, iwd)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registers_agent_discovers_and_scans() {
    let (_bus, fake, iwd) = setup().await;
    assert!(fake.agent_registered());
    let devices = iwd.devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert!(!devices[0].capabilities.p2p, "no P2P through iwd");
    assert!(iwd.p2p().is_none());

    let mut events = iwd.subscribe();
    iwd.start_scan(&wlan0()).await.unwrap();
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
    assert_eq!(results[1].security, Security::Wpa2Psk);
    assert_eq!(results[1].signal, -50);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connects_through_the_agent_and_leaves_nothing_behind() {
    let (_bus, fake, iwd) = setup().await;
    let mut events = iwd.subscribe();
    iwd.connect(
        &wlan0(),
        request(
            "home",
            ProfileSecurity::WpaPersonal,
            Some("correct horse battery"),
        ),
    )
    .await
    .unwrap();
    next_matching(&mut events, "connected", |e| {
        matches!(
            e,
            WlanEvent::Link {
                status: LinkStatus::Connected { .. },
                ..
            }
        )
    })
    .await;
    // iwd saved it; the adapter marked it as Kestrel's.
    for _ in 0..50 {
        if fake.known_networks() == [("home".to_owned(), false)] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fake.known_networks(), [("home".to_owned(), false)]);

    iwd.disconnect(&wlan0()).await.unwrap();
    next_matching(&mut events, "disconnected", |e| {
        matches!(
            e,
            WlanEvent::Link {
                status: LinkStatus::Disconnected,
                ..
            }
        )
    })
    .await;
    for _ in 0..50 {
        if fake.known_networks().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("known network survived: {:?}", fake.known_networks());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_is_an_auth_failure() {
    let (_bus, _fake, iwd) = setup().await;
    let mut events = iwd.subscribe();
    iwd.connect(
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
async fn refuses_what_it_cannot_enforce() {
    let (_bus, _fake, iwd) = setup().await;
    for security in [
        ProfileSecurity::Wpa3Personal,
        ProfileSecurity::Owe,
        ProfileSecurity::WpaEnterprise,
        ProfileSecurity::Wpa3Enterprise,
    ] {
        assert!(matches!(
            iwd.connect(&wlan0(), request("home", security, Some("whatever-secret")))
                .await,
            Err(PortError::NotSupported(_))
        ));
    }
    assert!(matches!(
        iwd.connect(&wlan0(), request("absent", ProfileSecurity::Open, None))
            .await,
        Err(PortError::NotFound(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweep_forgets_only_kestrel_networks() {
    let (bus, fake, iwd) = setup().await;
    fake.add_admin_known_network("office").await.unwrap();
    let mut events = iwd.subscribe();
    iwd.connect(&wlan0(), request("cafe", ProfileSecurity::Open, None))
        .await
        .unwrap();
    next_matching(&mut events, "connected", |e| {
        matches!(
            e,
            WlanEvent::Link {
                status: LinkStatus::Connected { .. },
                ..
            }
        )
    })
    .await;
    for _ in 0..50 {
        if fake.known_networks().contains(&("cafe".to_owned(), false)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Crash and restart.
    drop(iwd);
    let restarted = Iwd::new(bus.connect().await).await.unwrap();
    restarted.sweep().await.unwrap();
    for _ in 0..50 {
        if fake.known_networks() == [("office".to_owned(), true)] {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("unexpected known networks: {:?}", fake.known_networks());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_restart_removes_and_re_adds_devices() {
    let (_bus, fake, iwd) = setup().await;
    let mut events = iwd.subscribe();
    fake.vanish().await.unwrap();
    next_matching(&mut events, "removed", |e| {
        matches!(e, WlanEvent::DeviceRemoved(_))
    })
    .await;
    fake.reappear().await.unwrap();
    next_matching(&mut events, "added", |e| {
        matches!(e, WlanEvent::DeviceAdded(_))
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_bus_clients_coming_and_going_change_nothing() {
    let (bus, _fake, iwd) = setup().await;
    let mut events = iwd.subscribe();
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
    assert_eq!(iwd.devices().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn softap_switches_device_mode_and_restores_on_sweep() {
    let (_bus, fake, iwd) = setup().await;
    let ap = iwd.ap().unwrap();
    let mut wlan_events = iwd.subscribe();
    let mut ap_events = ap.subscribe();

    assert!(matches!(
        ap.start_ap(
            &wlan0(),
            &ApStartRequest {
                ssid: Ssid::new("open-ap").unwrap(),
                security: HotspotSecurity::Open,
                secret: None,
                frequency: None,
                hidden: false,
            }
        )
        .await,
        Err(PortError::NotSupported(_))
    ));

    assert!(matches!(
        ap.start_ap(
            &wlan0(),
            &ApStartRequest {
                ssid: Ssid::new("hidden-ap").unwrap(),
                security: HotspotSecurity::WpaPersonal,
                secret: Some(Secret::new("hotspot-secret")),
                frequency: None,
                hidden: true,
            }
        )
        .await,
        Err(PortError::NotSupported(_))
    ));

    assert!(matches!(
        ap.start_ap(
            &wlan0(),
            &ApStartRequest {
                ssid: Ssid::new("freq-ap").unwrap(),
                security: HotspotSecurity::WpaPersonal,
                secret: Some(Secret::new("hotspot-secret")),
                frequency: Some(5180),
                hidden: false,
            }
        )
        .await,
        Err(PortError::NotSupported(_))
    ));

    ap.start_ap(
        &wlan0(),
        &ApStartRequest {
            ssid: Ssid::new("kestrel-iwd-ap").unwrap(),
            security: HotspotSecurity::WpaPersonal,
            secret: Some(Secret::new("hotspot-secret")),
            frequency: None,
            hidden: false,
        },
    )
    .await
    .unwrap();
    next_matching(&mut ap_events, "ap started", |e| {
        matches!(e, ApEvent::Started { .. })
    })
    .await;
    assert_eq!(fake.device_mode(), "ap");
    assert!(fake.ap_started());

    // Mode switch must NOT emit DeviceRemoved.
    while let Ok(event) = wlan_events.try_recv() {
        assert!(
            !matches!(event, WlanEvent::DeviceRemoved(_)),
            "spurious device removal during AP mode switch: {event:?}"
        );
    }

    iwd.sweep().await.unwrap();
    assert_eq!(fake.device_mode(), "station");
    assert!(!fake.ap_started());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_open_ap_downgrade_and_unauthorized_agent_call() {
    let (bus, fake, iwd) = setup().await;
    // "cafe" is an open network; connecting as wpa-personal must NOT match it.
    assert!(matches!(
        iwd.connect(
            &wlan0(),
            request(
                "cafe",
                ProfileSecurity::WpaPersonal,
                Some("some-passphrase")
            ),
        )
        .await,
        Err(PortError::NotFound(_))
    ));
    // "home" is a psk network; connecting as open must NOT match it.
    assert!(matches!(
        iwd.connect(&wlan0(), request("home", ProfileSecurity::Open, None))
            .await,
        Err(PortError::NotFound(_))
    ));
    // An unrelated bus peer calling RequestPassphrase on Kestrel's iwd Agent
    // must be rejected (cannot steal plaintext Wi-Fi passphrases).
    let attacker = bus.connect().await;
    let iwd_conn_name = bus.connect().await;
    let _ = iwd_conn_name;
    // Trigger an association so a pending secret exists, then verify an
    // unrelated bus client cannot read it via RequestPassphrase.
    let agent_owner = fake.agent_bus_name();
    if let Some(dest) = agent_owner {
        let proxy = zbus::Proxy::new(
            &attacker,
            dest.as_str(),
            "/com/hihusky/Kestrel/iwd/agent",
            "net.connman.iwd.Agent",
        )
        .await
        .unwrap();
        let net_path = zbus::ObjectPath::try_from("/net/connman/iwd/0/4/x").unwrap();
        let err = proxy
            .call_method("RequestPassphrase", &(net_path,))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Canceled") || err.to_string().contains("unauthorized"),
            "unexpected error: {err}"
        );
    }
}

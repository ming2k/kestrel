// SPDX-License-Identifier: LGPL-2.1-or-later

//! Workspace-level integration tests across `kestrel-controller`,
//! `kestrel-catalog`, `kestrel-store`, `kestrel-api`, and the `kestrel` CLI binary.

#![allow(clippy::used_underscore_binding)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kestrel_api::{Action, AllowAll, Server};
use kestrel_catalog::{Catalog, CatalogStores};
use kestrel_controller::{Controller, ControllerConfig, ControllerPorts};
use kestrel_model::{Bss, InterfaceName, MacAddress, P2pRole, ProfileId, Security, Ssid};
use kestrel_ports::p2p::P2pEvent;
use kestrel_store::{CertDirectory, HistoryFile, P2pGroupDirectory, ProfileDirectory, StateFile};
use kestrel_testkit::{FakeL3, FakeWlan, MemorySecrets};
use kestrel_tests::{DenyAction, TestBus, TestEnv, run_kestrel, wait_until};
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

async fn cli_json(
    bus: &str,
    args: &[&str],
    stdin_data: Option<&str>,
) -> Result<serde_json::Value, String> {
    let bus = bus.to_owned();
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let stdin_data = stdin_data.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run_kestrel(&bus, true, &refs, stdin_data.as_deref())?;
        if out.trim().is_empty() {
            Ok(serde_json::Value::Null)
        } else {
            serde_json::from_str(&out).map_err(|e| format!("invalid json: {e}\n{out}"))
        }
    })
    .await
    .expect("join cli task")
}

async fn cli_text(bus: &str, args: &[&str], stdin_data: Option<&str>) -> Result<String, String> {
    let bus = bus.to_owned();
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let stdin_data = stdin_data.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_kestrel(&bus, false, &refs, stdin_data.as_deref())
    })
    .await
    .expect("join cli task")
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_and_dbus_station_lifecycle_with_disk_stores() {
    let mut env = TestEnv::start_disk().await;
    let bus = env.bus.address().to_owned();

    let overview = cli_json(&bus, &["status"], None).await.expect("status");
    assert_eq!(overview["wireless_enabled"], true);
    assert_eq!(overview["devices"][0]["interface"], "wlan0");

    let text_status = cli_text(&bus, &["status"], None)
        .await
        .expect("text status");
    assert!(text_status.contains("wlan0"));

    let scan = cli_json(&bus, &["wifi", "scan", "wlan0"], None)
        .await
        .expect("wifi scan");
    assert_eq!(scan[0]["ssid"], "home");
    assert_eq!(scan[0]["known"], false);

    let joined = cli_json(
        &bus,
        &[
            "wifi",
            "join",
            "wlan0",
            "home",
            "--secret-stdin",
            "--timeout",
            "10",
        ],
        Some("super-secret\n"),
    )
    .await
    .expect("wifi join");
    assert_eq!(joined["state"], "connected");
    assert_eq!(joined["ssid"], "home");

    let profiles = cli_json(&bus, &["profile", "list"], None)
        .await
        .expect("profile list");
    assert_eq!(profiles.as_array().expect("array").len(), 1);
    assert_eq!(profiles[0]["ssid"], "home");

    wait_until("history recorded", Duration::from_secs(5), || async {
        cli_json(&bus, &["wifi", "history", "--limit", "5"], None)
            .await
            .ok()
            .and_then(|v| {
                v.as_array().map(|arr| {
                    arr.iter()
                        .any(|e| e["ssid"] == "home" && e["outcome"] == "connected")
                })
            })
            .unwrap_or(false)
    })
    .await;

    cli_json(&bus, &["wifi", "disconnect", "wlan0"], None)
        .await
        .expect("disconnect");
    wait_until("idle after disconnect", Duration::from_secs(5), || async {
        cli_json(&bus, &["wifi", "status", "wlan0"], None)
            .await
            .is_ok_and(|v| v["state"] == "idle")
    })
    .await;

    cli_json(&bus, &["wifi", "forget", "home", "--yes"], None)
        .await
        .expect("forget");
    let profiles_after = cli_json(&bus, &["profile", "list"], None)
        .await
        .expect("profile list after forget");
    assert_eq!(profiles_after.as_array().expect("array").len(), 0);

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn disk_persistence_survives_runtime_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bus = TestBus::start();

    // First run: save profile, connect, disable wireless, shut down.
    {
        let wlan = FakeWlan::new();
        let l3 = FakeL3::new();
        wlan.add_device("wlan0");
        wlan.set_visible(vec![Bss {
            ssid: Ssid::new("office").expect("ssid"),
            bssid: MacAddress::from_octets([2, 0, 0, 0, 0, 2]),
            frequency: 5180,
            signal: -50,
            security: Security::Wpa2Psk,
        }]);
        let profiles = ProfileDirectory::new(dir.path().join("profiles"));
        let history = HistoryFile::new(dir.path().join("history.jsonl"));
        let state = StateFile::new(dir.path().join("state.toml"));

        let catalog = Catalog::open(CatalogStores {
            profiles: Arc::new(profiles),
            secrets: Arc::new(MemorySecrets::default()),
            certs: Arc::new(CertDirectory::new(dir.path().join("certs"))),
            p2p_groups: Arc::new(P2pGroupDirectory::new(dir.path().join("p2p-groups"))),
            history: Arc::new(history),
        })
        .await
        .expect("catalog 1");
        let controller = Controller::start(
            ControllerConfig::default(),
            ControllerPorts {
                wlan: Arc::new(wlan),
                l3: Arc::new(l3),
                state: Arc::new(state),
            },
            catalog.clone(),
        )
        .await
        .expect("controller 1");
        let server = Server::serve(
            bus.connect().await,
            controller.handle(),
            catalog,
            Arc::new(AllowAll),
        )
        .await
        .expect("server 1");

        cli_json(
            bus.address(),
            &[
                "wifi",
                "join",
                "wlan0",
                "office",
                "--secret-stdin",
                "--timeout",
                "10",
            ],
            Some("office-pass\n"),
        )
        .await
        .expect("join");
        cli_json(bus.address(), &["wifi", "off"], None)
            .await
            .expect("wifi off");

        server.stop().await;
        controller.shutdown().await;
    }

    // Second run on the same directory: profile, history, and wireless_enabled=false persist.
    {
        let wlan = FakeWlan::new();
        let l3 = FakeL3::new();
        wlan.add_device("wlan0");
        let profiles = ProfileDirectory::new(dir.path().join("profiles"));
        let history = HistoryFile::new(dir.path().join("history.jsonl"));
        let state = StateFile::new(dir.path().join("state.toml"));

        let catalog = Catalog::open(CatalogStores {
            profiles: Arc::new(profiles),
            secrets: Arc::new(MemorySecrets::default()),
            certs: Arc::new(CertDirectory::new(dir.path().join("certs"))),
            p2p_groups: Arc::new(P2pGroupDirectory::new(dir.path().join("p2p-groups"))),
            history: Arc::new(history),
        })
        .await
        .expect("catalog 2");
        let controller = Controller::start(
            ControllerConfig::default(),
            ControllerPorts {
                wlan: Arc::new(wlan),
                l3: Arc::new(l3),
                state: Arc::new(state),
            },
            catalog.clone(),
        )
        .await
        .expect("controller 2");
        let server = Server::serve(
            bus.connect().await,
            controller.handle(),
            catalog,
            Arc::new(AllowAll),
        )
        .await
        .expect("server 2");

        let status = cli_json(bus.address(), &["status"], None)
            .await
            .expect("status");
        assert_eq!(status["wireless_enabled"], false);
        assert_eq!(status["devices"][0]["state"], "disabled");

        let profiles = cli_json(bus.address(), &["profile", "list"], None)
            .await
            .expect("profiles");
        assert_eq!(profiles[0]["ssid"], "office");

        let history = cli_json(bus.address(), &["wifi", "history", "--limit", "5"], None)
            .await
            .expect("history");
        assert!(
            history
                .as_array()
                .expect("array")
                .iter()
                .any(|e| e["ssid"] == "office" && e["outcome"] == "connected")
        );

        server.stop().await;
        controller.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn authorizer_enforces_permissions_across_dbus_and_cli() {
    let mut env =
        TestEnv::start_with_authorizer(Arc::new(DenyAction(Action::ModifyProfiles)), false).await;
    let bus = env.bus.address().to_owned();

    // Read-only queries still succeed.
    cli_json(&bus, &["status"], None)
        .await
        .expect("status allowed");

    // Profile modification is denied with AccessDenied.
    let err = cli_json(
        &bus,
        &[
            "profile",
            "add",
            "--ssid",
            "restricted",
            "--security",
            "open",
        ],
        None,
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("AccessDenied") || err.contains("denied"),
        "unexpected error: {err}"
    );

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_p2p_session_connect_and_close() {
    let mut env = TestEnv::start_memory().await;
    let bus = env.bus.address().to_owned();

    let created = cli_json(
        &bus,
        &["p2p", "connect", "wlan0", "02:00:00:00:aa:11"],
        None,
    )
    .await
    .expect("p2p connect");
    let session_path = created["session"]
        .as_str()
        .expect("session path")
        .to_owned();

    let group_if = InterfaceName::new("p2p-wlan0-0").expect("iface");
    let wlan_iface = InterfaceName::new("wlan0").expect("iface");
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: wlan_iface,
        group_if,
        role: P2pRole::GroupOwner,
    });

    wait_until("session ready", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "sessions"], None)
            .await
            .ok()
            .and_then(|v| {
                v.as_array().map(|arr| {
                    arr.iter()
                        .any(|s| s["path"] == session_path && s["state"] == "ready")
                })
            })
            .unwrap_or(false)
    })
    .await;

    cli_json(&bus, &["p2p", "close", &session_path], None)
        .await
        .expect("p2p close");

    wait_until("session closed", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "sessions"], None)
            .await
            .ok()
            .and_then(|v| v.as_array().map(Vec::is_empty))
            .unwrap_or(false)
    })
    .await;

    env.shutdown().await;
}

#[derive(Debug)]
struct TestAgent {
    prompts: Arc<Mutex<Vec<String>>>,
    reply: String,
}

#[zbus::interface(name = "com.hihusky.Kestrel.Agent")]
#[allow(clippy::unnecessary_wraps, clippy::unused_self)]
impl TestAgent {
    fn request_secret(
        &self,
        _device: OwnedObjectPath,
        _profile: OwnedObjectPath,
        ssid: String,
        _security: String,
        _reason: String,
    ) -> zbus::fdo::Result<String> {
        self.prompts.lock().expect("lock").push(ssid);
        Ok(self.reply.clone())
    }

    fn authorize_peer(
        &self,
        _device: OwnedObjectPath,
        _peer: String,
        _name: String,
        _method: String,
    ) -> zbus::fdo::Result<(String, String)> {
        Ok(("pbc".to_owned(), String::new()))
    }

    fn display_pin(&self, _session: OwnedObjectPath, _peer: String, _pin: String) {}
}

#[tokio::test(flavor = "multi_thread")]
async fn dbus_agent_supplies_missing_secret_and_station_connects() {
    let mut env = TestEnv::start_memory().await;
    let prompts = Arc::new(Mutex::new(Vec::new()));

    let agent_conn = env.bus.connect().await;
    let agent_path = "/com/example/TestAgent";
    agent_conn
        .object_server()
        .at(
            agent_path,
            TestAgent {
                prompts: Arc::clone(&prompts),
                reply: "agent-provided-pass".to_owned(),
            },
        )
        .await
        .expect("export agent");

    let agent_client = kestrel_api::client::Client::new(agent_conn)
        .await
        .expect("agent client");
    agent_client
        .manager()
        .await
        .expect("manager")
        .register_agent(&OwnedObjectPath::try_from(agent_path).expect("path"))
        .await
        .expect("register agent");

    // Add a profile without a secret, then connect; the runtime should ask the agent.
    let settings: kestrel_api::ProfileSettings = HashMap::from([
        (
            "ssid".to_owned(),
            OwnedVariant::try_from(Variant::from("home")).expect("variant"),
        ),
        (
            "security".to_owned(),
            OwnedVariant::try_from(Variant::from("wpa-personal")).expect("variant"),
        ),
    ]);
    let profile_path = env
        .client
        .manager()
        .await
        .expect("manager")
        .add_profile(settings, kestrel_api::SecretBundle::new())
        .await
        .expect("add profile");
    let profile = env
        .client
        .profile(profile_path.clone())
        .await
        .expect("profile");
    let id = profile.id().await.expect("id");
    assert_ne!(id, "");
    let _parsed: ProfileId = id.parse().expect("valid profile id");

    env.client
        .device("wlan0")
        .await
        .expect("device")
        .connect(&profile_path)
        .await
        .expect("connect profile");

    wait_until(
        "connected via agent secret",
        Duration::from_secs(5),
        || async {
            env.client
                .device("wlan0")
                .await
                .expect("device")
                .state()
                .await
                .expect("state")
                == "connected"
        },
    )
    .await;

    assert_eq!(prompts.lock().expect("lock").as_slice(), ["home"]);
    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn cli_hotspot_lifecycle_and_certificate_store() {
    let mut env = TestEnv::start_disk().await;
    let bus = env.bus.address().to_owned();

    let devices =
        cli_json(&bus, &["status"], None).await.expect("status")["devices"][0]["capabilities"]
            .clone();
    assert!(
        devices
            .as_array()
            .expect("capabilities")
            .iter()
            .any(|c| c == "access-point"),
        "the fake device is AP capable"
    );

    // Status of an idle hotspot is readable before anything starts.
    let idle = cli_json(&bus, &["hotspot", "status", "wlan0"], None)
        .await
        .expect("hotspot status");
    assert_eq!(idle[0]["state"], "stopped");

    cli_json(
        &bus,
        &[
            "hotspot",
            "start",
            "wlan0",
            "--ssid",
            "lab-ap",
            "--secret-stdin",
        ],
        Some("hotspot-pass\n"),
    )
    .await
    .expect("hotspot start");
    wait_until("hotspot active", Duration::from_secs(5), || async {
        cli_json(&bus, &["hotspot", "status", "wlan0"], None)
            .await
            .is_ok_and(|v| v[0]["state"] == "active")
    })
    .await;
    let active = cli_json(&bus, &["hotspot", "status", "wlan0"], None)
        .await
        .expect("hotspot status");
    assert_eq!(active[0]["ssid"], "lab-ap");
    assert_eq!(active[0]["security"], "wpa-personal");
    assert!(
        active[0]["gateway"]
            .as_str()
            .is_some_and(|g| g.contains('/')),
        "the hotspot serves a subnet: {active:?}"
    );

    cli_json(&bus, &["hotspot", "stop", "wlan0"], None)
        .await
        .expect("hotspot stop");
    wait_until("hotspot stopped", Duration::from_secs(5), || async {
        cli_json(&bus, &["hotspot", "status", "wlan0"], None)
            .await
            .is_ok_and(|v| v[0]["state"] == "stopped")
    })
    .await;

    // Certificates: import, list, reference, and delete.
    let dir = tempfile::tempdir().expect("tempdir");
    let pem = dir.path().join("ca.pem");
    std::fs::write(
        &pem,
        "-----BEGIN CERTIFICATE-----\nMAowAwIBAQMDAAEC\n-----END CERTIFICATE-----\n",
    )
    .expect("write pem");
    let added = cli_json(
        &bus,
        &[
            "certificate",
            "add",
            pem.to_str().expect("utf8"),
            "--name",
            "Lab CA",
        ],
        None,
    )
    .await
    .expect("certificate add");
    let cert_id = added["id"].as_str().expect("id").to_owned();

    let listed = cli_json(&bus, &["certificate", "list"], None)
        .await
        .expect("certificate list");
    assert_eq!(listed[0]["name"], "Lab CA");
    assert!(
        listed[0]["fingerprint_sha256"]
            .as_str()
            .is_some_and(|f| f.split(':').count() == 32)
    );

    // An enterprise profile can reference the imported CA by name; the CLI
    // resolves it to the certificate id before calling the API.
    let created = cli_json(
        &bus,
        &[
            "profile",
            "add",
            "--ssid",
            "corp",
            "--security",
            "wpa-enterprise",
            "--eap",
            "peap",
            "--identity",
            "alice@corp.example",
            "--phase2",
            "mschapv2",
            "--ca-cert",
            "Lab CA",
            "--domain-suffix-match",
            "corp.example",
            "--secret-stdin",
            "--priority",
            "1",
        ],
        Some("eap-password\n"),
    )
    .await
    .expect("enterprise profile add");
    let profile_id = created["id"].as_str().expect("id").to_owned();
    let shown = cli_json(&bus, &["profile", "show", &profile_id], None)
        .await
        .expect("profile show");
    assert_eq!(shown["security"], "wpa-enterprise");
    assert_eq!(shown["enterprise.eap"], "peap");
    assert_eq!(shown["enterprise.ca_cert"], cert_id);
    assert_eq!(shown["enterprise.domain_suffix_match"], "corp.example");
    assert_eq!(shown["has_secret"], true);

    // Deleting the certificate is refused while the profile references it.
    let err = cli_json(&bus, &["certificate", "delete", &cert_id, "--yes"], None)
        .await
        .unwrap_err();
    assert!(err.contains("Busy") || err.contains("busy"), "{err}");
    cli_json(&bus, &["profile", "delete", &profile_id, "--yes"], None)
        .await
        .expect("profile delete");

    cli_json(&bus, &["certificate", "delete", &cert_id, "--yes"], None)
        .await
        .expect("certificate delete");
    let empty = cli_json(&bus, &["certificate", "list"], None)
        .await
        .expect("certificate list after delete");
    assert_eq!(empty.as_array().expect("array").len(), 0);

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn p2p_persistent_groups_via_the_cli() {
    let mut env = TestEnv::start_memory().await;
    let bus = env.bus.address().to_owned();

    cli_json(
        &bus,
        &[
            "p2p",
            "connect",
            "wlan0",
            "02:00:00:00:aa:55",
            "--go-intent",
            "15",
            "--persistent",
        ],
        None,
    )
    .await
    .expect("p2p connect");
    env.wlan.emit_p2p(&P2pEvent::PersistentGroupFormed {
        device: InterfaceName::new("wlan0").expect("iface"),
        role: P2pRole::GroupOwner,
        ssid: Ssid::new("DIRECT-lab").expect("ssid"),
        go_address: MacAddress::from_octets([2, 0, 0, 0, 0, 0x55]),
        psk: kestrel_model::Secret::new("group-psk"),
    });

    wait_until("group saved", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "groups", "list"], None)
            .await
            .is_ok_and(|v| !v.as_array().expect("array").is_empty())
    })
    .await;
    let groups = cli_json(&bus, &["p2p", "groups", "list"], None)
        .await
        .expect("groups list");
    let group_id = groups[0]["id"].as_str().expect("id").to_owned();
    assert_eq!(groups[0]["ssid"], "DIRECT-lab");

    let shown = cli_json(&bus, &["p2p", "groups", "show", &group_id], None)
        .await
        .expect("groups show");
    assert_eq!(shown["role"], "group-owner");

    let sessions_before = env
        .wlan
        .calls()
        .iter()
        .filter(|c| matches!(c, kestrel_testkit::WlanCall::P2pConnectPersistent { .. }))
        .count();
    // The connect above still holds the device; only one session at a time.
    for session in cli_json(&bus, &["p2p", "sessions"], None)
        .await
        .expect("sessions")
        .as_array()
        .expect("array")
        .clone()
    {
        cli_json(
            &bus,
            &["p2p", "close", session["path"].as_str().expect("path")],
            None,
        )
        .await
        .expect("p2p close");
    }
    wait_until("first session closed", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "sessions"], None)
            .await
            .is_ok_and(|v| v.as_array().is_some_and(Vec::is_empty))
    })
    .await;

    cli_json(
        &bus,
        &[
            "p2p",
            "reconnect",
            "wlan0",
            &group_id,
            "--peer",
            "02:00:00:00:aa:56",
        ],
        None,
    )
    .await
    .expect("p2p reconnect");
    let sessions_after = env
        .wlan
        .calls()
        .iter()
        .filter(|c| matches!(c, kestrel_testkit::WlanCall::P2pConnectPersistent { .. }))
        .count();
    assert_eq!(sessions_after, sessions_before + 1, "WPS is skipped");

    for session in cli_json(&bus, &["p2p", "sessions"], None)
        .await
        .expect("sessions")
        .as_array()
        .expect("array")
        .clone()
    {
        cli_json(
            &bus,
            &["p2p", "close", session["path"].as_str().expect("path")],
            None,
        )
        .await
        .expect("p2p close");
    }
    wait_until("sessions closed", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "sessions"], None)
            .await
            .is_ok_and(|v| v.as_array().is_some_and(Vec::is_empty))
    })
    .await;

    cli_json(&bus, &["p2p", "groups", "delete", &group_id, "--yes"], None)
        .await
        .expect("groups delete");
    let empty = cli_json(&bus, &["p2p", "groups", "list"], None)
        .await
        .expect("groups list after delete");
    assert_eq!(empty.as_array().expect("array").len(), 0);

    env.shutdown().await;
}

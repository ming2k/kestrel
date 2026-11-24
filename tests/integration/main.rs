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

    // Implicit single-device resolution: no `-d wlan0` required.
    let scan = cli_json(&bus, &["wifi", "scan"], None)
        .await
        .expect("wifi scan");
    assert_eq!(scan[0]["ssid"], "home");
    assert_eq!(scan[0]["known"], false);

    let joined = cli_json(
        &bus,
        &["wifi", "connect", "home", "--secret-stdin", "-t", "10"],
        Some("super-secret\n"),
    )
    .await
    .expect("wifi connect");
    assert_eq!(joined["state"], "connected");
    assert_eq!(joined["ssid"], "home");

    // Human single-device status prints a friendly profile label, not a raw D-Bus path.
    let detail_text = cli_text(&bus, &["status", "wlan0"], None)
        .await
        .expect("status wlan0");
    assert!(detail_text.contains("Profile: home ("), "{detail_text}");
    assert!(
        !detail_text.contains("/com/hihusky/Kestrel/"),
        "D-Bus path leaked in human output: {detail_text}"
    );

    let profiles = cli_json(&bus, &["profile", "list"], None)
        .await
        .expect("profile list");
    assert_eq!(profiles.as_array().expect("array").len(), 1);
    assert_eq!(profiles[0]["ssid"], "home");

    wait_until("history recorded", Duration::from_secs(5), || async {
        cli_json(&bus, &["wifi", "history", "-n", "5"], None)
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

    // `wifi disconnect` waits until idle by default.
    cli_json(&bus, &["wifi", "disconnect"], None)
        .await
        .expect("disconnect");
    let dev_status = cli_json(&bus, &["status", "wlan0"], None)
        .await
        .expect("status wlan0");
    assert_eq!(dev_status["state"], "idle");

    // Autoconnect query works without mutating state.
    let auto = cli_json(&bus, &["wifi", "autoconnect"], None)
        .await
        .expect("autoconnect query");
    assert_eq!(auto["held"], true);

    cli_json(&bus, &["profile", "delete", "home", "-y"], None)
        .await
        .expect("profile delete");
    let profiles_after = cli_json(&bus, &["profile", "list"], None)
        .await
        .expect("profile list after delete");
    assert_eq!(profiles_after.as_array().expect("array").len(), 0);

    env.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_device_requires_explicit_device_flag() {
    let mut env = TestEnv::start_memory().await;
    env.wlan.add_device("wlan1");
    let bus = env.bus.address().to_owned();

    wait_until(
        "second device registered",
        Duration::from_secs(5),
        || async {
            cli_json(&bus, &["status"], None)
                .await
                .ok()
                .and_then(|v| v["devices"].as_array().map(Vec::len))
                == Some(2)
        },
    )
    .await;

    // Omitting `-d` when two devices exist must fail clearly instead of guessing.
    let err = cli_json(&bus, &["wifi", "scan", "--cached"], None)
        .await
        .unwrap_err();
    assert!(
        err.contains("wlan0") && err.contains("wlan1") && err.contains("-d/--device"),
        "unexpected ambiguity error: {err}"
    );

    // Explicit `-d wlan1` succeeds cleanly.
    cli_json(&bus, &["wifi", "scan", "--cached", "-d", "wlan1"], None)
        .await
        .expect("explicit device scan");

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
            &["wifi", "connect", "office", "--secret-stdin", "-t", "10"],
            Some("office-pass\n"),
        )
        .await
        .expect("connect");
        cli_json(bus.address(), &["radio", "off"], None)
            .await
            .expect("radio off");

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

        let radio = cli_json(bus.address(), &["radio"], None)
            .await
            .expect("radio query");
        assert_eq!(radio["wireless_enabled"], false);

        let status = cli_json(bus.address(), &["status"], None)
            .await
            .expect("status");
        assert_eq!(status["wireless_enabled"], false);
        assert_eq!(status["devices"][0]["state"], "disabled");

        let profiles = cli_json(bus.address(), &["profile", "list"], None)
            .await
            .expect("profiles");
        assert_eq!(profiles[0]["ssid"], "office");

        let history = cli_json(bus.address(), &["wifi", "history", "-n", "5"], None)
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
        &["profile", "add", "restricted", "--security", "open"],
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
async fn cli_p2p_session_connect_show_and_close() {
    let mut env = TestEnv::start_memory().await;
    let bus = env.bus.address().to_owned();

    let created = cli_json(
        &bus,
        &["p2p", "connect", "02:00:00:00:aa:11", "--no-wait"],
        None,
    )
    .await
    .expect("p2p connect --no-wait");
    let session_id = created["id"].as_str().expect("session id").to_owned();
    let session_path = created["path"].as_str().expect("session path").to_owned();

    let group_if = InterfaceName::new("p2p-wlan0-0").expect("iface");
    let wlan_iface = InterfaceName::new("wlan0").expect("iface");
    env.wlan.emit_p2p(&P2pEvent::GroupStarted {
        device: wlan_iface,
        group_if,
        role: P2pRole::GroupOwner,
    });

    wait_until("session ready", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "session", "list"], None)
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

    let shown = cli_json(&bus, &["p2p", "session", "show", &session_id], None)
        .await
        .expect("p2p session show");
    assert_eq!(shown["id"], session_id);
    assert_eq!(shown["device"], "wlan0");
    assert_eq!(shown["state"], "ready");

    cli_json(&bus, &["p2p", "session", "close", &session_id], None)
        .await
        .expect("p2p session close");

    wait_until("session closed", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "session", "list"], None)
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
    let idle = cli_json(&bus, &["hotspot", "status", "-d", "wlan0"], None)
        .await
        .expect("hotspot status");
    assert_eq!(idle["state"], "stopped");

    // `hotspot start` waits until active by default and returns full status.
    let active = cli_json(
        &bus,
        &["hotspot", "start", "lab-ap", "--secret-stdin"],
        Some("hotspot-pass\n"),
    )
    .await
    .expect("hotspot start");
    assert_eq!(active["state"], "active");
    assert_eq!(active["ssid"], "lab-ap");
    assert_eq!(active["security"], "wpa-personal");
    assert!(
        active["gateway"].as_str().is_some_and(|g| g.contains('/')),
        "the hotspot serves a subnet: {active:?}"
    );

    // `hotspot stop` waits until stopped by default.
    cli_json(&bus, &["hotspot", "stop"], None)
        .await
        .expect("hotspot stop");
    let stopped = cli_json(&bus, &["hotspot", "status", "-d", "wlan0"], None)
        .await
        .expect("hotspot status");
    assert_eq!(stopped["state"], "stopped");

    // Certificates: import via `cert` alias with derived name, list, reference, and delete.
    let dir = tempfile::tempdir().expect("tempdir");
    let pem = dir.path().join("Lab CA.pem");
    std::fs::write(
        &pem,
        "-----BEGIN CERTIFICATE-----\nMAowAwIBAQMDAAEC\n-----END CERTIFICATE-----\n",
    )
    .expect("write pem");
    let added = cli_json(&bus, &["cert", "add", pem.to_str().expect("utf8")], None)
        .await
        .expect("cert add");
    let cert_id = added["id"].as_str().expect("id").to_owned();
    assert_eq!(added["name"], "Lab CA");

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
    let err = cli_json(&bus, &["certificate", "delete", &cert_id, "-y"], None)
        .await
        .unwrap_err();
    assert!(err.contains("Busy") || err.contains("busy"), "{err}");
    cli_json(&bus, &["profile", "delete", &profile_id, "-y"], None)
        .await
        .expect("profile delete");

    cli_json(&bus, &["certificate", "delete", &cert_id, "-y"], None)
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
            "02:00:00:00:aa:55",
            "--go-intent",
            "15",
            "--persistent",
            "--no-wait",
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
        cli_json(&bus, &["p2p", "group", "list"], None)
            .await
            .is_ok_and(|v| !v.as_array().expect("array").is_empty())
    })
    .await;
    let groups = cli_json(&bus, &["p2p", "group", "list"], None)
        .await
        .expect("group list");
    let group_id = groups[0]["id"].as_str().expect("id").to_owned();
    assert_eq!(groups[0]["ssid"], "DIRECT-lab");

    let shown = cli_json(&bus, &["p2p", "group", "show", &group_id], None)
        .await
        .expect("group show");
    assert_eq!(shown["role"], "group-owner");

    let sessions_before = env
        .wlan
        .calls()
        .iter()
        .filter(|c| matches!(c, kestrel_testkit::WlanCall::P2pConnectPersistent { .. }))
        .count();
    // The connect above still holds the device; only one session at a time.
    for session in cli_json(&bus, &["p2p", "session", "list"], None)
        .await
        .expect("sessions")
        .as_array()
        .expect("array")
        .clone()
    {
        cli_json(
            &bus,
            &[
                "p2p",
                "session",
                "close",
                session["id"].as_str().expect("id"),
            ],
            None,
        )
        .await
        .expect("p2p session close");
    }
    wait_until("first session closed", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "session", "list"], None)
            .await
            .is_ok_and(|v| v.as_array().is_some_and(Vec::is_empty))
    })
    .await;

    cli_json(
        &bus,
        &[
            "p2p",
            "reconnect",
            &group_id,
            "--peer",
            "02:00:00:00:aa:56",
            "--no-wait",
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

    for session in cli_json(&bus, &["p2p", "session", "list"], None)
        .await
        .expect("sessions")
        .as_array()
        .expect("array")
        .clone()
    {
        cli_json(
            &bus,
            &[
                "p2p",
                "session",
                "close",
                session["id"].as_str().expect("id"),
            ],
            None,
        )
        .await
        .expect("p2p session close");
    }
    wait_until("sessions closed", Duration::from_secs(5), || async {
        cli_json(&bus, &["p2p", "session", "list"], None)
            .await
            .is_ok_and(|v| v.as_array().is_some_and(Vec::is_empty))
    })
    .await;

    cli_json(&bus, &["p2p", "group", "delete", &group_id, "-y"], None)
        .await
        .expect("group delete");
    let empty = cli_json(&bus, &["p2p", "group", "list"], None)
        .await
        .expect("group list after delete");
    assert_eq!(empty.as_array().expect("array").len(), 0);

    env.shutdown().await;
}

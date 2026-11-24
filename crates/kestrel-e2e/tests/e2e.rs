// SPDX-License-Identifier: LGPL-2.1-or-later

//! Real `kestrel-daemon` and `kestrel` against the real systemd-networkd, with
//! a fake `wpa_supplicant` standing in for the radio. Run with
//! `crates/kestrel-e2e/run.sh` (sets `KESTREL_E2E=1`).

use std::time::Duration;

use kestrel_e2e::{
    Lab, Process, ctl, daemon_config, enabled, fake_control, fake_wpa, kestrel_daemon, wait_for,
};
use serde_json::Value;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn control<T>(lab: &Lab, method: &str, args: &T) -> zbus::Message
where
    T: serde::ser::Serialize + zbus::zvariant::DynamicType,
{
    block_on(async {
        fake_control(lab)
            .await
            .call_method(method, args)
            .await
            .unwrap_or_else(|e| panic!("fake {method}: {e}"))
    })
}

fn fake_calls(lab: &Lab) -> Vec<String> {
    control(lab, "Calls", &())
        .body()
        .deserialize()
        .expect("calls")
}

fn network_count(lab: &Lab) -> u32 {
    control(lab, "NetworkCount", &())
        .body()
        .deserialize()
        .expect("count")
}

fn blob_names(lab: &Lab, device: &str) -> Vec<String> {
    control(lab, "BlobNames", &(device,))
        .body()
        .deserialize()
        .expect("blobs")
}

fn device_state(lab: &Lab, device: &str) -> String {
    ctl(lab, &["status"], None)
        .ok()
        .and_then(|status| {
            status["devices"]
                .as_array()?
                .iter()
                .find(|d| d["interface"] == device)
                .and_then(|d| d["state"].as_str().map(str::to_owned))
        })
        .unwrap_or_default()
}

fn sessions(lab: &Lab) -> Vec<Value> {
    ctl(lab, &["p2p", "session", "list"], None)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

struct Setup {
    lab: Lab,
    dir: tempfile::TempDir,
    _wpa: Process,
    daemon: Option<Process>,
}

impl Setup {
    /// A lab with `wlan0` (and its AP side `ap0` serving DHCP on
    /// 10.77.0.0/24), the fake `wpa_supplicant`, and a running daemon.
    fn start() -> Option<Self> {
        if !enabled() {
            eprintln!("skipping: set KESTREL_E2E=1 (crates/kestrel-e2e/run.sh)");
            return None;
        }
        let lab = Lab::start();
        lab.veth("wlan0", "ap0");
        lab.remote_unit(
            "ap0",
            "Address=10.77.0.1/24\nDHCPServer=yes\n\n[DHCPServer]\nPersistLeases=runtime\nEmitDNS=yes\nDNS=10.77.0.1\n",
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let wpa = fake_wpa(&lab, &["wlan0"], dir.path());
        control(
            &lab,
            "AddAccessPoint",
            &("lab-home", "correct horse battery", "wpa2"),
        );
        let config = daemon_config(&lab, dir.path());
        let daemon = kestrel_daemon(&lab, &config, dir.path());
        Some(Self {
            lab,
            dir,
            _wpa: wpa,
            daemon: Some(daemon),
        })
    }

    fn restart_daemon(&mut self) {
        let config = self.dir.path().join("kestrel.toml");
        self.daemon = Some(kestrel_daemon(&self.lab, &config, self.dir.path()));
    }

    fn add_home_profile(&self) -> String {
        let added = ctl(
            &self.lab,
            &[
                "profile",
                "add",
                "lab-home",
                "--security",
                "wpa-personal",
                "--secret-stdin",
            ],
            Some("correct horse battery\n"),
        )
        .expect("profile add");
        added["id"].as_str().expect("id").to_owned()
    }

    fn wait_connected(&self) {
        let lab = &self.lab;
        wait_for("wlan0 connected", Duration::from_secs(30), || {
            device_state(lab, "wlan0") == "connected"
        });
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(daemon) = &self.daemon {
                eprintln!("===== kestrel-daemon log =====\n{}", daemon.log());
            }
            let log = self.lab.networkd_log();
            let tail: Vec<&str> = log.lines().rev().take(60).collect();
            eprintln!("===== networkd log (tail) =====");
            for line in tail.iter().rev() {
                eprintln!("{line}");
            }
        }
    }
}

#[test]
fn station_gets_its_address_from_networkd_and_releases_it() {
    let Some(setup) = Setup::start() else { return };
    let lab = &setup.lab;
    setup.add_home_profile();
    setup.wait_connected();

    // networkd, not Kestrel, configured the address via DHCP.
    let addresses = lab.ipv4("wlan0");
    assert!(
        addresses.iter().any(|a| a.starts_with("10.77.0.")),
        "wlan0 has no lease: {addresses:?}\n{}",
        lab.networkd_log()
    );
    assert_eq!(lab.kestrel_units(), ["10-kestrel-wlan0.network"]);

    // The secret is encrypted at rest, and only Kestrel's network block exists.
    let secrets: Vec<_> = std::fs::read_dir(setup.dir.path().join("secrets"))
        .unwrap()
        .collect();
    assert_eq!(secrets.len(), 1);
    let raw = std::fs::read(secrets[0].as_ref().unwrap().path()).unwrap();
    assert!(
        !raw.windows(5).any(|w| w == b"horse"),
        "secret stored in plaintext"
    );
    assert_eq!(network_count(lab), 1);
    let profile_files = std::fs::read_dir(setup.dir.path().join("profiles")).unwrap();
    for file in profile_files {
        let text = std::fs::read_to_string(file.unwrap().path()).unwrap();
        assert!(
            !text.contains("horse"),
            "secret leaked into the profile file"
        );
    }

    ctl(lab, &["wifi", "disconnect"], None).unwrap();
    assert_eq!(device_state(lab, "wlan0"), "idle");
    wait_for("unit removed", Duration::from_secs(10), || {
        lab.kestrel_units().is_empty()
    });
    wait_for("lease released", Duration::from_secs(10), || {
        !lab.ipv4("wlan0").iter().any(|a| a.starts_with("10.77.0."))
    });
    wait_for("network block removed", Duration::from_secs(10), || {
        network_count(lab) == 0
    });
}

#[test]
fn connect_status_history_and_autoconnect_work() {
    let Some(setup) = Setup::start() else { return };
    let lab = &setup.lab;
    let connected = ctl(
        lab,
        &["wifi", "connect", "lab-home", "--secret-stdin", "-t", "30"],
        Some("correct horse battery\n"),
    )
    .unwrap();
    assert_eq!(connected["state"], "connected");
    assert_eq!(connected["ssid"], "lab-home");

    wait_for("address after connect", Duration::from_secs(10), || {
        ctl(lab, &["status", "wlan0"], None)
            .ok()
            .and_then(|status| {
                status["addresses"]
                    .as_array()
                    .map(|addresses| !addresses.is_empty())
            })
            .unwrap_or(false)
    });
    let status = ctl(lab, &["status", "wlan0"], None).unwrap();
    assert_eq!(status["ssid"], "lab-home");
    assert_eq!(status["state"], "connected");
    assert_eq!(status["frequency"], 2412);
    assert_eq!(status["security"], "wpa2-psk");
    assert_eq!(status["online_state"], "online");
    assert_eq!(status["dns"], serde_json::json!(["10.77.0.1"]));

    let scan = ctl(lab, &["wifi", "scan", "--cached"], None).unwrap();
    assert_eq!(scan[0]["ssid"], "lab-home");
    assert_eq!(scan[0]["known"], true);
    assert_eq!(scan[0]["profile"], status["profile"]);

    let profiles = ctl(lab, &["profile", "list"], None).unwrap();
    assert!(
        profiles
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile["ssid"] == "lab-home")
    );

    wait_for("history entry", Duration::from_secs(10), || {
        ctl(lab, &["wifi", "history", "-n", "10"], None)
            .ok()
            .and_then(|history| {
                history.as_array().map(|events| {
                    events
                        .iter()
                        .any(|event| event["ssid"] == "lab-home" && event["outcome"] == "connected")
                })
            })
            .unwrap_or(false)
    });

    ctl(lab, &["wifi", "autoconnect", "off"], None).unwrap();
    let status = ctl(lab, &["status", "wlan0"], None).unwrap();
    assert_eq!(status["state"], "connected");
    assert_eq!(status["autoconnect_enabled"], false);
    ctl(lab, &["wifi", "autoconnect", "on"], None).unwrap();
    let status = ctl(lab, &["status", "wlan0"], None).unwrap();
    assert_eq!(status["autoconnect_enabled"], true);

    ctl(lab, &["profile", "delete", "lab-home", "-y"], None).unwrap();
    wait_for("idle after delete", Duration::from_secs(10), || {
        device_state(lab, "wlan0") == "idle"
    });
}

#[test]
fn p2p_group_owner_serves_dhcp_through_networkd() {
    let Some(setup) = Setup::start() else { return };
    let lab = &setup.lab;
    // The group interface and the peer's side of the link.
    lab.veth("p2p-wlan0-0", "peer0");
    lab.remote_unit(
        "peer0",
        "DHCP=ipv4\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n",
    );

    let session = ctl(
        lab,
        &["p2p", "connect", "02:00:00:00:aa:42", "--no-wait"],
        None,
    )
    .unwrap();
    let session_id = session["id"].as_str().unwrap().to_owned();
    wait_for("connect issued", Duration::from_secs(10), || {
        fake_calls(lab)
            .iter()
            .any(|c| c.starts_with("P2P.Connect peer=02000000aa42 method=pbc go_intent=7"))
    });
    control(lab, "StartGroup", &("wlan0", "p2p-wlan0-0", true));

    wait_for(
        "session ready with a peer address",
        Duration::from_secs(30),
        || {
            sessions(lab).iter().any(|s| {
                s["state"] == "ready" && s["peer_ip"].as_str().is_some_and(|ip| !ip.is_empty())
            })
        },
    );
    let ready = sessions(lab).remove(0);
    assert_eq!(ready["role"], "group-owner");
    assert_eq!(ready["group_interface"], "p2p-wlan0-0");
    assert_eq!(lab.ipv4("p2p-wlan0-0"), ["192.168.49.1/24"]);
    let peer_addresses = lab.ipv4("peer0");
    assert_eq!(
        peer_addresses,
        [format!("{}/24", ready["peer_ip"].as_str().unwrap())],
        "the reported peer address must be the lease networkd handed out"
    );

    ctl(lab, &["p2p", "session", "close", &session_id], None).unwrap();
    wait_for("group removed", Duration::from_secs(10), || {
        fake_calls(lab).contains(&"P2P.Disconnect p2p-wlan0-0".to_owned())
    });
    wait_for("unit removed", Duration::from_secs(10), || {
        lab.kestrel_units().is_empty()
    });
    wait_for("session gone", Duration::from_secs(10), || {
        sessions(lab).is_empty()
    });
}

#[test]
fn autonomous_group_owner_serves_dhcp_through_networkd() {
    let Some(setup) = Setup::start() else { return };
    let lab = &setup.lab;
    lab.veth("p2p-wlan0-0", "peer0");
    lab.remote_unit(
        "peer0",
        "DHCP=ipv4\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n",
    );

    let session = ctl(
        lab,
        &["p2p", "start-group", "-f", "2412", "--no-wait"],
        None,
    )
    .unwrap();
    let session_id = session["id"].as_str().unwrap().to_owned();
    wait_for("group add issued", Duration::from_secs(10), || {
        fake_calls(lab)
            .iter()
            .any(|c| c == "P2P.GroupAdd frequency=2412")
    });
    wait_for("group authorization armed", Duration::from_secs(10), || {
        fake_calls(lab)
            .iter()
            .any(|c| c == "WPS.Start role=registrar type=pbc")
    });

    wait_for(
        "autonomous session ready with a peer address",
        Duration::from_secs(30),
        || {
            sessions(lab).iter().any(|s| {
                s["state"] == "ready"
                    && s["autonomous"] == true
                    && s["peer_ip"].as_str().is_some_and(|ip| !ip.is_empty())
            })
        },
    );
    let ready = sessions(lab).remove(0);
    assert_eq!(ready["role"], "group-owner");
    assert_eq!(ready["peer"], "");
    assert_eq!(ready["group_interface"], "p2p-wlan0-0");
    assert_eq!(lab.ipv4("p2p-wlan0-0"), ["192.168.49.1/24"]);
    assert_eq!(
        lab.ipv4("peer0"),
        [format!("{}/24", ready["peer_ip"].as_str().unwrap())]
    );

    ctl(lab, &["p2p", "session", "close", &session_id], None).unwrap();
    wait_for("group removed", Duration::from_secs(10), || {
        fake_calls(lab).contains(&"P2P.Disconnect p2p-wlan0-0".to_owned())
    });
    wait_for("unit removed", Duration::from_secs(10), || {
        lab.kestrel_units().is_empty()
    });
    wait_for("session gone", Duration::from_secs(10), || {
        sessions(lab).is_empty()
    });
}

#[test]
fn p2p_client_obtains_an_address_from_the_remote_group_owner() {
    let Some(setup) = Setup::start() else { return };
    let lab = &setup.lab;
    lab.veth("p2p-wlan0-1", "go0");
    lab.remote_unit(
        "go0",
        "Address=10.88.0.1/24\nDHCPServer=yes\n\n[DHCPServer]\nPersistLeases=runtime\nEmitDNS=no\n",
    );
    ctl(
        lab,
        &[
            "p2p",
            "connect",
            "02:00:00:00:aa:43",
            "--go-intent",
            "0",
            "--no-wait",
        ],
        None,
    )
    .unwrap();
    control(lab, "StartGroup", &("wlan0", "p2p-wlan0-1", false));
    wait_for("client session ready", Duration::from_secs(30), || {
        sessions(lab)
            .iter()
            .any(|s| s["state"] == "ready" && s["peer_ip"] == "10.88.0.1")
    });
    assert_eq!(sessions(lab)[0]["role"], "client");
    assert!(
        lab.ipv4("p2p-wlan0-1")
            .iter()
            .any(|a| a.starts_with("10.88.0."))
    );

    // The remote group owner ends the group.
    control(lab, "FinishGroup", &("p2p-wlan0-1",));
    wait_for("session gone", Duration::from_secs(10), || {
        sessions(lab).is_empty()
    });
    wait_for("unit removed", Duration::from_secs(10), || {
        lab.kestrel_units().is_empty()
    });
}

#[test]
fn hotspot_takes_the_radio_and_restores_the_station() {
    let Some(setup) = Setup::start() else { return };
    let lab = &setup.lab;
    setup.add_home_profile();
    setup.wait_connected();

    let active = ctl(
        lab,
        &["hotspot", "start", "lab-ap", "--security", "open"],
        None,
    )
    .unwrap();
    assert_eq!(active["state"], "active");
    assert_eq!(active["ssid"], "lab-ap");
    assert_eq!(active["security"], "open");
    assert_eq!(active["gateway"], "192.168.49.1/24");
    assert_eq!(
        lab.ipv4("wlan0"),
        ["192.168.49.1/24"],
        "networkd serves the shared subnet"
    );
    // The station hands the radio over while the AP owns it.
    assert_eq!(device_state(lab, "wlan0"), "disabled");
    assert_eq!(lab.kestrel_units(), ["10-kestrel-wlan0.network"]);

    ctl(lab, &["hotspot", "stop"], None).unwrap();
    let stopped = ctl(lab, &["hotspot", "status", "-d", "wlan0"], None).unwrap();
    assert_eq!(stopped["state"], "stopped");
    // The station gets the radio back and autoconnects to its saved profile.
    setup.wait_connected();
    assert!(
        lab.ipv4("wlan0").iter().any(|a| a.starts_with("10.77.0.")),
        "the station lease came back: {:?}",
        lab.ipv4("wlan0")
    );
}

#[test]
fn crash_leftovers_are_swept_and_shutdown_leaves_nothing() {
    let Some(mut setup) = Setup::start() else {
        return;
    };
    setup.add_home_profile();
    setup.wait_connected();
    let lab = &setup.lab;
    lab.veth("p2p-wlan0-0", "peer0");
    ctl(
        lab,
        &["p2p", "connect", "02:00:00:00:aa:42", "--no-wait"],
        None,
    )
    .unwrap();
    control(lab, "StartGroup", &("wlan0", "p2p-wlan0-0", true));
    wait_for("both bound", Duration::from_secs(30), || {
        lab.kestrel_units().len() == 2
    });

    // Crash: nothing is released.
    setup.daemon.take().unwrap().crash();
    assert_eq!(setup.lab.kestrel_units().len(), 2);

    // Restart: the sweep removes every leftover before anything else runs,
    // then autoconnect binds the station afresh.
    setup.restart_daemon();
    let lab = &setup.lab;
    assert!(
        setup
            .daemon
            .as_ref()
            .unwrap()
            .log()
            .contains("removed L3 bindings left by a previous run"),
        "{}",
        setup.daemon.as_ref().unwrap().log()
    );
    wait_for("leftover group removed", Duration::from_secs(10), || {
        fake_calls(lab).contains(&"P2P.Disconnect p2p-wlan0-0".to_owned())
    });
    setup.wait_connected();
    assert_eq!(lab.kestrel_units(), ["10-kestrel-wlan0.network"]);
    assert_eq!(
        network_count(lab),
        1,
        "the crashed run's network block was not swept"
    );

    // A spoofed PrepareForSleep from a peer that does not own org.freedesktop.login1
    // must be ignored.
    block_on(async {
        let spoof = zbus::connection::Builder::address(lab.bus_address().as_str())
            .user_id(0)
            .build()
            .await
            .unwrap();
        spoof
            .emit_signal(
                Option::<&str>::None,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                &(true,),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
    });
    assert_eq!(
        device_state(lab, "wlan0"),
        "connected",
        "spoofed PrepareForSleep must be ignored"
    );

    // System suspend/resume via PrepareForSleep from org.freedesktop.login1
    // releases L3 and reconnects.
    control(lab, "SetSleep", &(true,));
    wait_for("disabled on sleep", Duration::from_secs(10), || {
        device_state(lab, "wlan0") == "disabled" && lab.kestrel_units().is_empty()
    });
    control(lab, "SetSleep", &(false,));
    setup.wait_connected();

    // Persistent radio off across daemon restart.
    ctl(lab, &["radio", "off"], None).unwrap();
    wait_for("disabled on radio off", Duration::from_secs(10), || {
        device_state(lab, "wlan0") == "disabled"
    });
    setup.daemon.take().unwrap().terminate();
    setup.restart_daemon();
    let lab = &setup.lab;
    let overview = ctl(lab, &["status"], None).unwrap();
    assert_eq!(overview["wireless_enabled"], false);
    assert_eq!(device_state(lab, "wlan0"), "disabled");
    ctl(lab, &["radio", "on"], None).unwrap();
    setup.wait_connected();

    // Graceful shutdown releases everything.
    let status = setup.daemon.take().unwrap().terminate();
    assert!(status.success(), "kestrel-daemon exited with {status}");
    assert_eq!(lab.kestrel_units(), Vec::<String>::new());
    assert_eq!(network_count(lab), 0);
}

#[test]
fn enterprise_8021x_imports_cert_uploads_blobs_and_binds_networkd() {
    let Some(setup) = Setup::start() else { return };
    let lab = &setup.lab;
    control(
        lab,
        "AddAccessPoint",
        &("corp-eap", "eap-secret", "wpa3-enterprise"),
    );

    let ca_path = setup.dir.path().join("corp-ca.pem");
    std::fs::write(
        &ca_path,
        "-----BEGIN CERTIFICATE-----\nMAowAwIBAQMDAAEC\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let cert = ctl(
        lab,
        &[
            "certificate",
            "add",
            ca_path.to_str().unwrap(),
            "--name",
            "Corp CA",
        ],
        None,
    )
    .unwrap();
    let cert_id = cert["id"].as_str().unwrap().to_owned();

    ctl(
        lab,
        &[
            "profile",
            "add",
            "corp-eap",
            "--security",
            "wpa3-enterprise",
            "--eap",
            "peap",
            "--identity",
            "alice@corp.example",
            "--phase2",
            "mschapv2",
            "--ca-cert",
            &cert_id,
            "--domain-suffix-match",
            "radius.corp.example",
            "--secret-stdin",
        ],
        Some("eap-secret\n"),
    )
    .unwrap();

    setup.wait_connected();
    wait_for("enterprise lease", Duration::from_secs(30), || {
        lab.ipv4("wlan0").iter().any(|a| a.starts_with("10.77.0."))
    });
    assert_eq!(blob_names(lab, "wlan0"), ["kestrel-ca"]);

    ctl(lab, &["wifi", "disconnect"], None).unwrap();
    assert_eq!(device_state(lab, "wlan0"), "idle");
    wait_for(
        "enterprise blobs removed after disconnect",
        Duration::from_secs(10),
        || blob_names(lab, "wlan0").is_empty(),
    );
}

#[test]
fn persistent_p2p_group_reconnects_via_networkd() {
    let Some(setup) = Setup::start() else { return };
    let lab = &setup.lab;
    control(
        lab,
        "EmitPersistentGroup",
        &(
            "wlan0",
            "DIRECT-lab-persist",
            "02:00:00:00:aa:99",
            "persist-psk",
            true,
        ),
    );
    wait_for("persistent group saved", Duration::from_secs(10), || {
        ctl(lab, &["p2p", "group", "list"], None)
            .ok()
            .and_then(|v| v.as_array().map(|a| !a.is_empty()))
            .unwrap_or(false)
    });
    let groups = ctl(lab, &["p2p", "group", "list"], None).unwrap();
    let group_id = groups[0]["id"].as_str().unwrap().to_owned();

    lab.veth("p2p-wlan0-0", "peer0");
    lab.remote_unit(
        "peer0",
        "IPv6AcceptRA=no\n[Network]\nDHCP=ipv4\n[DHCPv4]\nUseDNS=no\nUseRoutes=no\n",
    );
    let session = ctl(lab, &["p2p", "reconnect", &group_id, "--no-wait"], None).unwrap();
    let session_id = session["id"].as_str().unwrap().to_owned();
    let session_path = session["path"].as_str().unwrap().to_owned();
    control(lab, "StartGroup", &("wlan0", "p2p-wlan0-0", true));

    wait_for(
        "persistent group session ready",
        Duration::from_secs(30),
        || {
            sessions(lab)
                .iter()
                .any(|s| s["path"] == session_path && s["state"] == "ready")
        },
    );
    let calls = fake_calls(lab);
    assert!(calls.iter().any(|c| c == "P2P.AddPersistentGroup"));
    assert!(
        !calls.iter().any(|c| c.starts_with("WPS.Start")),
        "persistent GO reuse must not invoke WPS: {calls:?}"
    );
    assert_eq!(lab.ipv4("p2p-wlan0-0"), ["192.168.49.1/24"]);

    ctl(lab, &["p2p", "session", "close", &session_id], None).unwrap();
    wait_for("persistent session gone", Duration::from_secs(10), || {
        sessions(lab).is_empty()
    });
}

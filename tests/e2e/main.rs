// SPDX-License-Identifier: LGPL-2.1-or-later

//! Workspace-level end-to-end tests: real `kestrel-daemon`, `kestrel`, and
//! `systemd-networkd` in an unprivileged namespace with `kestrel-fake-wpa`.
//!
//! Run via `./crates/kestrel-e2e/run.sh` (sets `KESTREL_E2E=1`).

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

struct E2eSetup {
    lab: Lab,
    _dir: tempfile::TempDir,
    _wpa: Process,
    daemon: Option<Process>,
}

impl E2eSetup {
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
            _dir: dir,
            _wpa: wpa,
            daemon: Some(daemon),
        })
    }
}

impl Drop for E2eSetup {
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
        if let Some(daemon) = self.daemon.take() {
            let _ = daemon.terminate();
        }
    }
}

#[test]
fn wrong_password_marks_needs_secrets_and_recovers_after_edit() {
    let Some(setup) = E2eSetup::start() else {
        return;
    };
    let lab = &setup.lab;

    // Add profile with an incorrect password.
    let added = ctl(
        lab,
        &[
            "profile",
            "add",
            "lab-home",
            "--security",
            "wpa-personal",
            "--secret-stdin",
        ],
        Some("wrong-password\n"),
    )
    .expect("profile add");
    let id = added["id"].as_str().expect("id");

    // Autoconnect tries and fails authentication, recording outcome = "failed" in history.
    wait_for(
        "failed attempt recorded in history",
        Duration::from_secs(20),
        || {
            ctl(lab, &["wifi", "history", "-n", "10"], None)
                .ok()
                .and_then(|h| {
                    h.as_array().map(|arr| {
                        arr.iter()
                            .any(|e| e["ssid"] == "lab-home" && e["outcome"] == "failed")
                    })
                })
                .unwrap_or(false)
        },
    );
    wait_for(
        "wlan0 idle after auth failure",
        Duration::from_secs(10),
        || device_state(lab, "wlan0") == "idle",
    );

    // Fix the secret via `profile edit` and connect explicitly.
    ctl(
        lab,
        &["profile", "edit", id, "--secret-stdin"],
        Some("correct horse battery\n"),
    )
    .expect("profile edit");
    let shown = ctl(lab, &["profile", "show", id], None).expect("profile show");
    assert_eq!(shown["has_secret"], true);

    ctl(lab, &["wifi", "connect", id, "--no-wait"], None).expect("wifi connect");
    wait_for(
        "wlan0 connected after secret fix",
        Duration::from_secs(30),
        || device_state(lab, "wlan0") == "connected",
    );
    wait_for(
        "dhcp lease after secret fix",
        Duration::from_secs(15),
        || lab.ipv4("wlan0").iter().any(|a| a.starts_with("10.77.0.")),
    );
}

#[test]
fn profile_crud_and_scan_all_work_end_to_end() {
    let Some(setup) = E2eSetup::start() else {
        return;
    };
    let lab = &setup.lab;

    let added = ctl(
        lab,
        &[
            "profile",
            "add",
            "lab-guest",
            "--security",
            "open",
            "--priority",
            "5",
            "--no-autoconnect",
        ],
        None,
    )
    .expect("profile add");
    let id = added["id"].as_str().expect("id").to_owned();

    ctl(
        lab,
        &[
            "profile",
            "edit",
            &id,
            "--priority",
            "50",
            "--name",
            "Guest Network",
        ],
        None,
    )
    .expect("profile edit");

    let shown = ctl(lab, &["profile", "show", &id], None).expect("profile show");
    assert_eq!(shown["priority"], 50);
    assert_eq!(shown["name"], "Guest Network");
    assert_eq!(shown["autoconnect"], false);

    let scan_all = ctl(lab, &["wifi", "scan", "--all"], None).expect("wifi scan --all");
    assert!(
        scan_all
            .as_array()
            .expect("array")
            .iter()
            .any(|bss| bss["ssid"] == "lab-home")
    );
    let cached_all =
        ctl(lab, &["wifi", "scan", "--cached", "--all"], None).expect("wifi scan --cached --all");
    assert_ne!(cached_all.as_array().expect("array").len(), 0);

    ctl(lab, &["profile", "delete", &id, "-y"], None).expect("profile delete");
    let profiles = ctl(lab, &["profile", "list"], None).expect("profile list");
    assert!(
        !profiles
            .as_array()
            .expect("array")
            .iter()
            .any(|p| p["id"] == id)
    );
}

#[test]
fn p2p_pin_connect_and_missing_session_close() {
    let Some(setup) = E2eSetup::start() else {
        return;
    };
    let lab = &setup.lab;
    lab.veth("p2p-wlan0-0", "peer0");
    lab.remote_unit(
        "peer0",
        "DHCP=ipv4\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n",
    );

    let created = ctl(
        lab,
        &[
            "p2p",
            "connect",
            "02:00:00:00:aa:55",
            "--pin-stdin",
            "--no-wait",
        ],
        Some("12345670\n"),
    )
    .expect("p2p connect");
    let session_id = created["id"].as_str().expect("id").to_owned();
    let session_path = created["path"].as_str().expect("path").to_owned();

    wait_for("pin connect issued", Duration::from_secs(10), || {
        fake_calls(lab)
            .iter()
            .any(|c| c.starts_with("P2P.Connect peer=02000000aa55 method=keypad"))
    });

    control(lab, "StartGroup", &("wlan0", "p2p-wlan0-0", true));
    wait_for("p2p session ready", Duration::from_secs(20), || {
        sessions(lab)
            .iter()
            .any(|s| s["path"] == session_path && s["state"] == "ready")
    });

    ctl(lab, &["p2p", "session", "close", &session_id], None).expect("p2p session close");
    wait_for("session removed", Duration::from_secs(10), || {
        sessions(lab).is_empty()
    });

    // Closing a non-existent session should fail cleanly.
    let err = ctl(lab, &["p2p", "session", "close", "999999"], None).unwrap_err();
    assert_ne!(err, "");
}

// SPDX-License-Identifier: LGPL-2.1-or-later

//! Shared harness for workspace-level integration and end-to-end tests.

#![allow(clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kestrel_api::client::Client;
use kestrel_api::{Action, AllowAll, ApiError, Authorizer, Server};
use kestrel_catalog::{Catalog, CatalogStores};
use kestrel_controller::{Controller, ControllerConfig, ControllerPorts};
use kestrel_model::{Bss, MacAddress, Security, Ssid};
use kestrel_store::{CertDirectory, HistoryFile, P2pGroupDirectory, ProfileDirectory, StateFile};
use kestrel_testkit::{
    FakeL3, FakeWlan, MemoryCerts, MemoryHistory, MemoryP2pGroups, MemoryProfiles, MemorySecrets,
    MemoryState,
};
use tempfile::TempDir;

/// A private `dbus-daemon` instance scoped to a test.
#[derive(Debug)]
pub struct TestBus {
    child: Child,
    address: String,
}

impl TestBus {
    /// Starts an isolated session `dbus-daemon` and waits for its socket address.
    pub fn start() -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon must be installed");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("read dbus address");
        Self {
            child,
            address: line.trim().to_owned(),
        }
    }

    /// The D-Bus address string for this private bus.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Connects a `zbus::Connection` to this private bus.
    pub async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .build()
            .await
            .expect("connect to test bus")
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Authorizer that rejects a configurable [`Action`] with [`ApiError::AccessDenied`].
#[derive(Debug)]
pub struct DenyAction(pub Action);

#[async_trait]
impl Authorizer for DenyAction {
    async fn check(&self, _sender: &str, action: Action) -> Result<(), ApiError> {
        if action == self.0 {
            Err(ApiError::AccessDenied(format!(
                "denied {}",
                action.polkit_id()
            )))
        } else {
            Ok(())
        }
    }
}

/// Integrated test environment: private D-Bus daemon, `Controller`, `Catalog`, `Server`, `Client`,
/// and in-memory or disk-backed stores.
#[derive(Debug)]
pub struct TestEnv {
    pub bus: TestBus,
    pub wlan: FakeWlan,
    pub l3: FakeL3,
    pub controller: Option<Controller>,
    pub server: Option<Server>,
    pub client: Client,
    pub dir: Option<TempDir>,
}

impl TestEnv {
    /// Starts an in-memory environment with `wlan0` and a visible `home` WPA2 network.
    pub async fn start_memory() -> Self {
        Self::start_with_authorizer(Arc::new(AllowAll), false).await
    }

    /// Starts an environment backed by real disk stores (`ProfileDirectory`, `HistoryFile`,
    /// `StateFile`) in a fresh temporary directory.
    pub async fn start_disk() -> Self {
        Self::start_with_authorizer(Arc::new(AllowAll), true).await
    }

    /// Starts an in-memory environment with a custom [`Authorizer`].
    pub async fn start_with_authorizer(authorizer: Arc<dyn Authorizer>, disk_stores: bool) -> Self {
        let bus = TestBus::start();
        let wlan = FakeWlan::new();
        let l3 = FakeL3::new();
        l3.set_dns(vec!["1.1.1.1".parse().expect("dns")]);
        wlan.add_device("wlan0");
        wlan.set_visible(vec![Bss {
            ssid: Ssid::new("home").expect("ssid"),
            bssid: MacAddress::from_octets([2, 0, 0, 0, 0, 1]),
            frequency: 2412,
            signal: -40,
            security: Security::Wpa2Psk,
        }]);

        let (dir, stores, ports) = if disk_stores {
            let dir = tempfile::tempdir().expect("tempdir");
            let profiles = ProfileDirectory::new(dir.path().join("profiles"));
            let history = HistoryFile::new(dir.path().join("history.jsonl"));
            let state = StateFile::new(dir.path().join("state.toml"));
            let stores = CatalogStores {
                profiles: Arc::new(profiles),
                secrets: Arc::new(MemorySecrets::default()),
                certs: Arc::new(CertDirectory::new(dir.path().join("certs"))),
                p2p_groups: Arc::new(P2pGroupDirectory::new(dir.path().join("p2p-groups"))),
                history: Arc::new(history),
            };
            let ports = ControllerPorts {
                wlan: Arc::new(wlan.clone()),
                l3: Arc::new(l3.clone()),
                state: Arc::new(state),
            };
            (Some(dir), stores, ports)
        } else {
            let stores = CatalogStores {
                profiles: Arc::new(MemoryProfiles::default()),
                secrets: Arc::new(MemorySecrets::default()),
                certs: Arc::new(MemoryCerts::default()),
                p2p_groups: Arc::new(MemoryP2pGroups::default()),
                history: Arc::new(MemoryHistory::default()),
            };
            let ports = ControllerPorts {
                wlan: Arc::new(wlan.clone()),
                l3: Arc::new(l3.clone()),
                state: Arc::new(MemoryState::default()),
            };
            (None, stores, ports)
        };

        let catalog = Catalog::open(stores).await.expect("catalog open");
        let controller = Controller::start(ControllerConfig::default(), ports, catalog.clone())
            .await
            .expect("controller start");
        let server_conn = bus.connect().await;
        let server = Server::serve(server_conn, controller.handle(), catalog, authorizer)
            .await
            .expect("server start");
        let client_conn = bus.connect().await;
        let client = Client::new(client_conn).await.expect("client connect");

        Self {
            bus,
            wlan,
            l3,
            controller: Some(controller),
            server: Some(server),
            client,
            dir,
        }
    }

    /// Shuts down the D-Bus server and controller cleanly.
    pub async fn shutdown(&mut self) {
        if let Some(server) = self.server.take() {
            server.stop().await;
        }
        if let Some(controller) = self.controller.take() {
            controller.shutdown().await;
        }
    }
}

/// Locates (or builds once) the workspace `kestrel` binary.
pub fn kestrel_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(dir) = std::env::var_os("KESTREL_BIN_DIR") {
            let candidate = PathBuf::from(dir).join("kestrel");
            if candidate.exists() {
                return candidate;
            }
        }
        let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"),
            PathBuf::from,
        );
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let candidate = target.join(profile).join("kestrel");
        if candidate.exists() {
            return candidate;
        }
        let status = Command::new("cargo")
            .args(["build", "--quiet", "-p", "kestrel-cli", "--bin", "kestrel"])
            .status()
            .expect("invoke cargo build for kestrel");
        assert!(status.success(), "cargo build -p kestrel-cli failed");
        assert!(
            candidate.exists(),
            "kestrel binary missing at {}",
            candidate.display()
        );
        candidate
    })
    .clone()
}

/// Runs `kestrel` against a bus address, returning stdout on success or stderr on failure.
pub fn run_kestrel(
    bus: &str,
    json: bool,
    args: &[&str],
    stdin_data: Option<&str>,
) -> Result<String, String> {
    let mut cmd = Command::new(kestrel_bin());
    cmd.args(["--bus", bus]);
    if json {
        cmd.arg("--json");
    }
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd.spawn().expect("spawn kestrel");
    if let Some(data) = stdin_data
        && let Some(mut pipe) = child.stdin.take()
    {
        pipe.write_all(data.as_bytes()).expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait kestrel");
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// Polls an async condition until it returns `true` or `timeout` elapses.
pub async fn wait_until<F, Fut>(label: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

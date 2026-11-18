// SPDX-License-Identifier: LGPL-2.1-or-later

//! The end-to-end lab.
//!
//! [`Lab`] creates an unprivileged user, network, and mount namespace with
//! a private system bus and the **real** `systemd-networkd`. The test
//! processes (`kestrel-daemon`, `kestrel`, the fake `wpa_supplicant`) run
//! outside the namespace. They reach its bus and runtime unit directory
//! through `/proc/<pid>/root`. That works because Kestrel never touches
//! kernel networking itself: everything it does goes through D-Bus and
//! unit files. Assertions about addresses are made inside the namespace
//! with `ip`.
//!
//! Requirements: `unshare` with `--map-auto` (subordinate IDs in
//! `/etc/subuid` and `/etc/subgid`), `nsenter`, `dbus-daemon`, `ip`,
//! `systemd-networkd` with its `systemd-network` user, and
//! `systemd-creds --user` for the daemon's secret store. Tests run only
//! when `KESTREL_E2E=1`.

#![allow(clippy::missing_panics_doc, missing_docs)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const NETWORKD: &str = "/usr/lib/systemd/systemd-networkd";

const BUS_CONFIG: &str = r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
  </policy>
</busconfig>
"#;

const INNER: &str = r#"
set -eu
umask 022
mount -t tmpfs tmpfs /run
mkdir -p /run/dbus /run/systemd/network /run/systemd/netif
chown "$NETWORKD_UID:$NETWORKD_GID" /run/systemd/netif
# A read-only sysfs tells networkd that no udev manages this namespace.
mount -t sysfs -o ro sysfs /sys
ip link set lo up
dbus-daemon --nofork --config-file="$BUS_CONFIG" &
while [ ! -S /run/dbus/system_bus_socket ]; do sleep 0.05; done
"$NETWORKD" > /run/networkd.log 2>&1 &
until busctl --system status org.freedesktop.network1 >/dev/null 2>&1; do sleep 0.05; done
touch /run/lab-ready
wait
"#;

pub fn enabled() -> bool {
    std::env::var_os("KESTREL_E2E").is_some_and(|v| v == "1")
}

/// Where the workspace binaries are: `$KESTREL_BIN_DIR` (set by `run.sh`),
/// else `<workspace>/target/<profile>`.
fn bin_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("KESTREL_BIN_DIR") {
        return PathBuf::from(dir);
    }
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    target.join(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    })
}

pub fn binary(name: &str) -> PathBuf {
    let path = bin_dir().join(name);
    assert!(
        path.exists(),
        "{} is missing; build it first (crates/kestrel-e2e/run.sh does)",
        path.display()
    );
    path
}

fn id_of(user: &str, flag: &str) -> String {
    let output = Command::new("id").args([flag, user]).output().expect("id");
    assert!(output.status.success(), "the {user} user must exist");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A namespace with its own system bus and systemd-networkd.
#[derive(Debug)]
pub struct Lab {
    child: Child,
    pid: u32,
    _dir: tempfile::TempDir,
}

impl Lab {
    pub fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("bus.conf");
        std::fs::write(&config, BUS_CONFIG).expect("bus config");
        let child = Command::new("unshare")
            .args([
                "--map-root-user",
                "--map-auto",
                "--net",
                "--mount",
                "--propagation",
                "private",
            ])
            .args(["sh", "-c", INNER])
            .env("BUS_CONFIG", &config)
            .env("NETWORKD", NETWORKD)
            .env("NETWORKD_UID", id_of("systemd-network", "-u"))
            .env("NETWORKD_GID", id_of("systemd-network", "-g"))
            .process_group(0)
            .stdin(Stdio::null())
            .spawn()
            .expect("unshare");
        let pid = child.id();
        let lab = Self {
            child,
            pid,
            _dir: dir,
        };
        let ready = lab.root().join("run/lab-ready");
        wait_for("the lab", Duration::from_secs(20), || ready.exists());
        lab
    }

    /// The namespace's root, as seen from outside.
    pub fn root(&self) -> PathBuf {
        PathBuf::from(format!("/proc/{}/root", self.pid))
    }

    pub fn bus_address(&self) -> String {
        format!(
            "unix:path=/proc/{}/root/run/dbus/system_bus_socket",
            self.pid
        )
    }

    pub fn unit_dir(&self) -> PathBuf {
        self.root().join("run/systemd/network")
    }

    /// Runs a shell command inside the namespace.
    pub fn sh(&self, script: &str) -> Output {
        Command::new("nsenter")
            .args([
                "-t",
                &self.pid.to_string(),
                "-U",
                "-n",
                "-m",
                "--preserve-credentials",
            ])
            .args(["timeout", "30", "sh", "-c", script])
            .output()
            .expect("nsenter")
    }

    pub fn sh_ok(&self, script: &str) -> String {
        let output = self.sh(script);
        assert!(
            output.status.success(),
            "`{script}` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    pub fn veth(&self, a: &str, b: &str) {
        self.sh_ok(&format!("ip link add {a} type veth peer name {b}"));
    }

    /// Installs a networkd unit that plays the remote side (an AP's DHCP
    /// server, or a P2P peer). Named outside Kestrel's prefix.
    pub fn remote_unit(&self, link: &str, network_section: &str) {
        let contents = format!("[Match]\nName={link}\n\n[Network]\n{network_section}");
        let path = self.unit_dir().join(format!("50-lab-{link}.network"));
        std::fs::write(&path, contents).expect("unit");
        // networkd runs as systemd-network; the test's umask may be strict.
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .expect("chmod");
        self.sh_ok(&format!(
            "networkctl reload && networkctl reconfigure {link}"
        ));
    }

    /// IPv4 addresses (CIDR) on a link inside the namespace.
    pub fn ipv4(&self, link: &str) -> Vec<String> {
        self.sh_ok(&format!("ip -4 -o addr show dev {link}"))
            .lines()
            .filter_map(|line| line.split_whitespace().nth(3).map(str::to_owned))
            .collect()
    }

    pub fn kestrel_units(&self) -> Vec<String> {
        let mut units: Vec<String> = std::fs::read_dir(self.unit_dir())
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.starts_with("10-kestrel-"))
                    .collect()
            })
            .unwrap_or_default();
        units.sort();
        units
    }

    pub fn networkd_log(&self) -> String {
        std::fs::read_to_string(self.root().join("run/networkd.log")).unwrap_or_default()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        // The whole process group: the shell, dbus-daemon, and networkd.
        let _ = Command::new("pkill")
            .args(["-KILL", "-g", &self.pid.to_string()])
            .status();
        let _ = self.child.wait();
    }
}

pub fn wait_for(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out after {timeout:?} waiting for {what}");
}

/// A process that is killed on drop.
#[derive(Debug)]
pub struct Process {
    child: Option<Child>,
    log: PathBuf,
}

impl Process {
    pub fn pid(&self) -> u32 {
        self.child.as_ref().expect("running").id()
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// SIGTERM and wait; returns the exit status.
    pub fn terminate(mut self) -> std::process::ExitStatus {
        let mut child = self.child.take().expect("running");
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().expect("wait") {
                return status;
            }
            assert!(Instant::now() < deadline, "process did not exit on SIGTERM");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// SIGKILL: a crash.
    pub fn crash(mut self) {
        let mut child = self.child.take().expect("running");
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn fake_wpa(lab: &Lab, stations: &[&str], log_dir: &Path) -> Process {
    let log = log_dir.join("fake-wpa.log");
    let mut child = Command::new(binary("kestrel-fake-wpa"))
        .arg(lab.bus_address())
        .args(stations)
        .env("KESTREL_BUS_UID", "0")
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).expect("log"))
        .spawn()
        .expect("fake wpa");
    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut line)
        .expect("fake wpa ready");
    assert_eq!(
        line.trim(),
        "ready",
        "the fake wpa_supplicant failed to start: {}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    Process {
        child: Some(child),
        log,
    }
}

/// Writes the daemon settings for a lab and returns the config path.
pub fn daemon_config(lab: &Lab, dir: &Path) -> PathBuf {
    let config = dir.join("kestrel.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[wireless]
backend = "wpa-supplicant"

[l3]
unit_dir = "{units}"

[storage]
profiles = "{dir}/profiles"
secrets = "{dir}/secrets"
certs = "{dir}/certs"
p2p_groups = "{dir}/p2p-groups"
history = "{dir}/history.jsonl"
state = "{dir}/state.toml"
secret_backend = "systemd-creds-user"

[api]
authorization = "bus-policy"

[timeouts]
association = 10
l3 = 20
"#,
            units = lab.unit_dir().display(),
            dir = dir.display()
        ),
    )
    .expect("config");
    config
}

pub fn kestrel_daemon(lab: &Lab, config: &Path, log_dir: &Path) -> Process {
    static NEXT_LOG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let seq = NEXT_LOG.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let log = log_dir.join(format!("kestrel-daemon-{}-{seq}.log", std::process::id()));
    let file = std::fs::File::create(&log).expect("log");
    let child = Command::new(binary("kestrel-daemon"))
        .args(["--bus", &lab.bus_address(), "--config"])
        .arg(config)
        .env("KESTREL_LOG", "debug")
        .env("KESTREL_BUS_UID", "0")
        .env("KESTREL_RFKILL_DIR", log_dir.join("rfkill"))
        .stdout(file.try_clone().expect("log"))
        .stderr(file)
        .spawn()
        .expect("kestrel-daemon");
    let process = Process {
        child: Some(child),
        log,
    };
    wait_for(
        "kestrel-daemon to be ready",
        Duration::from_secs(20),
        || process.log().contains("ready"),
    );
    process
}

/// Runs `kestrel --json` and parses its output.
pub fn ctl(lab: &Lab, args: &[&str], stdin: Option<&str>) -> Result<serde_json::Value, String> {
    let mut child = Command::new(binary("kestrel"))
        .args(["--bus", &lab.bus_address(), "--json"])
        .env("KESTREL_BUS_UID", "0")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kestrel");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write stdin");
    } else {
        drop(child.stdin.take());
    }
    let output = child.wait_with_output().expect("kestrel");
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(&stdout).map_err(|e| format!("bad JSON from kestrel: {e}: {stdout}"))
}

/// The fake `wpa_supplicant`'s control interface.
pub async fn fake_control(lab: &Lab) -> zbus::Proxy<'static> {
    // Outside the lab's user namespace we are root inside it.
    let connection = zbus::connection::Builder::address(lab.bus_address().as_str())
        .user_id(0)
        .build()
        .await
        .expect("bus");
    zbus::Proxy::new_owned(
        connection,
        "fi.w1.wpa_supplicant1",
        "/com/hihusky/Kestrel/testing",
        "com.hihusky.Kestrel.Testing.FakeWpa",
    )
    .await
    .expect("control proxy")
}

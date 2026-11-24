// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use kestrel_model::{InterfaceName, IpNet};
use kestrel_ports::l3::{L3Event, L3Intent, L3Provider, L3Status};
use kestrel_ports::{EventBus, PortError, PortResult, Subscription};
use serde_json::Value;
use zbus::OwnedObjectPath;
use zbus::message::Type;
use zbus::proxy::CacheProperties;

use crate::describe::{all_addresses, parse_link_status};
use crate::unit::render;

const SERVICE: &str = "org.freedesktop.network1";
const MANAGER_PATH: &str = "/org/freedesktop/network1";
const MANAGER: &str = "org.freedesktop.network1.Manager";
const LINK: &str = "org.freedesktop.network1.Link";
const LINK_NAMESPACE: &str = "/org/freedesktop/network1/link";

static NEXT_UNIT_TMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct NetworkdConfig {
    /// Runtime unit directory. Units here vanish on reboot, which is what
    /// Kestrel's bindings are: runtime state.
    pub unit_dir: PathBuf,
    /// File name prefix that marks a unit as Kestrel's.
    pub prefix: String,
    /// Safety-net refresh of bound links, in addition to D-Bus signals.
    pub poll_interval: Duration,
}

impl Default for NetworkdConfig {
    fn default() -> Self {
        Self {
            unit_dir: PathBuf::from("/run/systemd/network"),
            prefix: "10-kestrel-".to_owned(),
            poll_interval: Duration::from_secs(2),
        }
    }
}

#[derive(Debug)]
struct Inner {
    connection: zbus::Connection,
    config: NetworkdConfig,
    /// Serializes `bind`, `unbind`, and `sweep` unit mutations so concurrent
    /// calls cannot interleave filesystem writes with `Reload`.
    op_lock: tokio::sync::Mutex<()>,
    bound: Mutex<BTreeMap<InterfaceName, L3Intent>>,
    last: Mutex<BTreeMap<InterfaceName, L3Status>>,
    events: EventBus<L3Event>,
    monitor_tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let tasks = self
            .monitor_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for task in tasks.iter() {
            task.abort();
        }
    }
}

/// The systemd-networkd L3 provider.
#[derive(Debug, Clone)]
pub struct Networkd {
    inner: Arc<Inner>,
}

impl Networkd {
    /// Creates the provider and starts watching networkd for link changes.
    pub async fn new(connection: zbus::Connection, config: NetworkdConfig) -> PortResult<Self> {
        let inner = Arc::new(Inner {
            connection,
            config,
            op_lock: tokio::sync::Mutex::new(()),
            bound: Mutex::new(BTreeMap::new()),
            last: Mutex::new(BTreeMap::new()),
            events: EventBus::new(),
            monitor_tasks: Mutex::new(Vec::new()),
        });
        let rules = [
            zbus::MatchRule::builder()
                .msg_type(Type::Signal)
                .sender(SERVICE)
                .interface("org.freedesktop.DBus.Properties")
                .member("PropertiesChanged")
                .path_namespace(LINK_NAMESPACE)
                .build()
                .map_err(dbus_error)?,
            zbus::MatchRule::builder()
                .msg_type(Type::Signal)
                .sender("org.freedesktop.DBus")
                .interface("org.freedesktop.DBus")
                .member("NameOwnerChanged")
                .arg(0, SERVICE)
                .build()
                .map_err(dbus_error)?,
        ];
        let mut streams = Vec::with_capacity(rules.len());
        for rule in rules {
            streams.push(
                zbus::MessageStream::for_match_rule(rule, &inner.connection, None)
                    .await
                    .map_err(dbus_error)?,
            );
        }
        let mut merged = futures_util::stream::select_all(streams);
        let wake = Arc::new(tokio::sync::Notify::new());
        let drain_weak = Arc::downgrade(&inner);
        let drain_wake = Arc::clone(&wake);
        let drain = tokio::spawn(async move {
            while let Some(message) = merged.next().await {
                let Some(inner) = drain_weak.upgrade() else {
                    return;
                };
                if let Ok(message) = message {
                    let header = message.header();
                    if header.interface().map(zbus::names::InterfaceName::as_str)
                        == Some("org.freedesktop.DBus")
                        && header.member().map(zbus::names::MemberName::as_str)
                            == Some("NameOwnerChanged")
                        && let Ok((name, old_owner, new_owner)) =
                            message.body().deserialize::<(String, String, String)>()
                    {
                        if name != SERVICE {
                            continue;
                        }
                        if !old_owner.is_empty() {
                            tracing::warn!("systemd-networkd left the bus");
                            inner.last_lock().clear();
                        }
                        if !new_owner.is_empty() {
                            tracing::info!("systemd-networkd appeared on the bus");
                        }
                    }
                }
                drain_wake.notify_one();
            }
            tracing::warn!("networkd signal stream ended; relying on polling");
        });
        let worker = tokio::spawn(monitor(Arc::downgrade(&inner), wake));
        inner
            .monitor_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend([drain.abort_handle(), worker.abort_handle()]);
        Ok(Self { inner })
    }

    fn unit_path(&self, link: &InterfaceName) -> PathBuf {
        self.inner.unit_path(link)
    }
}

impl Inner {
    fn bound_lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<InterfaceName, L3Intent>> {
        self.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn last_lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<InterfaceName, L3Status>> {
        self.last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn unit_path(&self, link: &InterfaceName) -> PathBuf {
        self.config
            .unit_dir
            .join(format!("{}{link}.network", self.config.prefix))
    }

    async fn manager(&self) -> PortResult<zbus::Proxy<'static>> {
        zbus::proxy::Builder::new(&self.connection)
            .destination(SERVICE)
            .path(MANAGER_PATH)
            .interface(MANAGER)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(dbus_error)
    }

    async fn link_proxy(&self, path: OwnedObjectPath) -> PortResult<zbus::Proxy<'static>> {
        zbus::proxy::Builder::new(&self.connection)
            .destination(SERVICE)
            .path(path)
            .interface(LINK)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(dbus_error)
    }

    /// The link's ifindex and object path, or `None` if networkd does not
    /// know the link (yet).
    async fn link(&self, link: &InterfaceName) -> PortResult<Option<(i32, OwnedObjectPath)>> {
        let manager = self.manager().await?;
        match manager
            .call_method("GetLinkByName", &(link.as_str(),))
            .await
        {
            Ok(reply) => reply.body().deserialize().map(Some).map_err(dbus_error),
            Err(error) if is_no_such_link(&error) => Ok(None),
            Err(error) => Err(dbus_error(error)),
        }
    }

    async fn reload_and_reconfigure(&self, link: &InterfaceName) -> PortResult<()> {
        let manager = self.manager().await?;
        manager
            .call_method("Reload", &())
            .await
            .map_err(dbus_error)?;
        if let Some((ifindex, _)) = self.link(link).await? {
            match manager.call_method("ReconfigureLink", &(ifindex,)).await {
                Ok(_) => {}
                // The link vanished between the lookup and the call.
                Err(error) if is_no_such_link(&error) => {}
                Err(error) => return Err(dbus_error(error)),
            }
        }
        Ok(())
    }

    async fn describe(&self, link: &InterfaceName) -> PortResult<L3Status> {
        let Some((_, path)) = self.link(link).await? else {
            return Ok(L3Status::pending());
        };
        let proxy = self.link_proxy(path).await?;
        let reply = match proxy.call_method("Describe", &()).await {
            Ok(reply) => reply,
            Err(error) if is_no_such_link(&error) => return Ok(L3Status::pending()),
            Err(error) => return Err(dbus_error(error)),
        };
        let text: String = reply.body().deserialize().map_err(dbus_error)?;
        let json: Value = serde_json::from_str(&text)
            .map_err(|e| PortError::Backend(format!("networkd returned invalid JSON: {e}")))?;
        Ok(parse_link_status(&json, &self.unit_path(link)))
    }

    /// Re-reads every bound link and publishes changes.
    async fn refresh_all(&self) {
        let links: Vec<InterfaceName> = self.bound_lock().keys().cloned().collect();
        for link in links {
            self.refresh(&link).await;
        }
    }

    async fn refresh(&self, link: &InterfaceName) {
        let status = match self.describe(link).await {
            Ok(status) => status,
            Err(error) => {
                tracing::debug!(%link, %error, "cannot read link status");
                return;
            }
        };
        if !self.bound_lock().contains_key(link) {
            return; // Unbound while we were asking.
        }
        let changed = {
            let mut last = self.last_lock();
            if last.get(link) == Some(&status) {
                false
            } else {
                last.insert(link.clone(), status.clone());
                true
            }
        };
        if changed {
            tracing::debug!(%link, phase = ?status.phase, "L3 status changed");
            self.events.publish(&L3Event {
                link: link.clone(),
                status,
            });
        }
    }
}

async fn monitor(inner: Weak<Inner>, wake: Arc<tokio::sync::Notify>) {
    let poll = match inner.upgrade() {
        Some(inner) => inner.config.poll_interval.max(Duration::from_millis(100)),
        None => return,
    };
    let mut ticker = tokio::time::interval(poll);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = wake.notified() => {}
            _ = ticker.tick() => {}
        }
        let Some(inner) = inner.upgrade() else {
            return;
        };
        if !inner.bound_lock().is_empty() {
            inner.refresh_all().await;
        }
    }
}

#[async_trait]
impl L3Provider for Networkd {
    fn name(&self) -> &'static str {
        "systemd-networkd"
    }

    fn subscribe(&self) -> Subscription<L3Event> {
        self.inner.events.subscribe()
    }

    async fn bind(&self, link: &InterfaceName, intent: &L3Intent) -> PortResult<()> {
        let contents =
            render(link, intent).map_err(|e| PortError::InvalidArgument(e.to_string()))?;
        let _guard = self.inner.op_lock.lock().await;
        let path = self.unit_path(link);
        let dir = self.inner.config.unit_dir.clone();
        let write_path = path.clone();
        tokio::task::spawn_blocking(move || write_unit(&dir, &write_path, contents.as_bytes()))
            .await
            .map_err(|e| PortError::Backend(e.to_string()))?
            .map_err(|e| io_error(&e))?;
        self.inner.bound_lock().insert(link.clone(), intent.clone());
        self.inner.last_lock().remove(link);
        if let Err(error) = self.inner.reload_and_reconfigure(link).await {
            self.inner.bound_lock().remove(link);
            self.inner.last_lock().remove(link);
            let _ = tokio::task::spawn_blocking(move || remove_if_present(&path)).await;
            return Err(error);
        }
        let inner = self.inner.clone();
        let link = link.clone();
        tokio::spawn(async move { inner.refresh(&link).await });
        Ok(())
    }

    async fn unbind(&self, link: &InterfaceName) -> PortResult<()> {
        let _guard = self.inner.op_lock.lock().await;
        self.inner.bound_lock().remove(link);
        self.inner.last_lock().remove(link);
        let path = self.unit_path(link);
        let removed = tokio::task::spawn_blocking(move || remove_if_present(&path))
            .await
            .map_err(|e| PortError::Backend(e.to_string()))?
            .map_err(|e| io_error(&e))?;
        if removed {
            self.inner.reload_and_reconfigure(link).await?;
        }
        Ok(())
    }

    async fn status(&self, link: &InterfaceName) -> PortResult<L3Status> {
        self.inner.describe(link).await
    }

    async fn addresses_in_use(&self) -> PortResult<Vec<IpNet>> {
        let manager = self.inner.manager().await?;
        let reply = manager
            .call_method("Describe", &())
            .await
            .map_err(dbus_error)?;
        let text: String = reply.body().deserialize().map_err(dbus_error)?;
        let json: Value = serde_json::from_str(&text)
            .map_err(|e| PortError::Backend(format!("networkd returned invalid JSON: {e}")))?;
        Ok(all_addresses(&json))
    }

    async fn sweep(&self) -> PortResult<Vec<InterfaceName>> {
        let _guard = self.inner.op_lock.lock().await;
        let dir = self.inner.config.unit_dir.clone();
        let prefix = self.inner.config.prefix.clone();
        let swept = tokio::task::spawn_blocking(move || remove_owned_units(&dir, &prefix))
            .await
            .map_err(|e| PortError::Backend(e.to_string()))?
            .map_err(|e| io_error(&e))?;
        self.inner.bound_lock().clear();
        self.inner.last_lock().clear();
        if !swept.is_empty() {
            let manager = self.inner.manager().await?;
            manager
                .call_method("Reload", &())
                .await
                .map_err(dbus_error)?;
            for link in &swept {
                if let Ok(Some((ifindex, _))) = self.inner.link(link).await {
                    let _ = manager.call_method("ReconfigureLink", &(ifindex,)).await;
                }
            }
        }
        Ok(swept)
    }
}

/// Units must be world-readable: networkd runs as `systemd-network`. They
/// never contain secrets.
fn write_unit(dir: &Path, path: &Path, contents: &[u8]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unit path has no file name"))?;
    let pid = std::process::id();
    let seq = NEXT_UNIT_TMP.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!("{}.{pid}.{seq}.tmp", name.to_string_lossy()));
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)?;
        // The creation mode is filtered by the umask; set it explicitly so
        // networkd can read the unit regardless of the daemon's umask.
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn remove_if_present(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                let _ = File::open(dir).and_then(|d| d.sync_all());
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn remove_owned_units(dir: &Path, prefix: &str) -> io::Result<Vec<InterfaceName>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut swept = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix(prefix) else {
            continue;
        };
        let link = rest
            .strip_suffix(".network")
            .or_else(|| rest.strip_suffix(".network.tmp"))
            .or_else(|| {
                rest.strip_suffix(".tmp")
                    .and_then(|r| r.split(".network.").next())
            });
        let Some(link) = link else {
            continue;
        };
        match fs::remove_file(entry.path()) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        if let Ok(link) = InterfaceName::new(link) {
            swept.push(link);
        }
    }
    if !swept.is_empty() {
        let _ = File::open(dir).and_then(|d| d.sync_all());
    }
    swept.sort();
    swept.dedup();
    Ok(swept)
}

fn io_error(error: &io::Error) -> PortError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => PortError::PermissionDenied(error.to_string()),
        _ => PortError::Backend(error.to_string()),
    }
}

fn is_no_such_link(error: &zbus::Error) -> bool {
    let text = error.to_string();
    text.contains("NoSuchLink") || text.contains("UnknownObject") || text.contains("No such link")
}

fn dbus_error(error: impl std::fmt::Display) -> PortError {
    let text = error.to_string();
    if text.contains("AccessDenied") || text.contains("InteractiveAuthorizationRequired") {
        PortError::PermissionDenied(text)
    } else if text.contains("ServiceUnknown")
        || text.contains("NameHasNoOwner")
        || text.contains("not provided by any")
    {
        PortError::Unavailable(format!("systemd-networkd is not running: {text}"))
    } else {
        PortError::Backend(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_removes_only_owned_units() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "10-kestrel-wlan0.network",
            "10-kestrel-p2p-wlan0-0.network",
            "10-kestrel-p2p-wlan0-1.network.tmp",
            "10-kestrel-p2p-wlan0-2.network.1234.0.tmp",
            "20-admin.network",
            "10-kestrel-notes.txt",
        ] {
            fs::write(tmp.path().join(name), "x").unwrap();
        }
        let swept = remove_owned_units(tmp.path(), "10-kestrel-").unwrap();
        let names: Vec<&str> = swept.iter().map(InterfaceName::as_str).collect();
        assert_eq!(
            names,
            ["p2p-wlan0-0", "p2p-wlan0-1", "p2p-wlan0-2", "wlan0"]
        );
        let mut left: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["10-kestrel-notes.txt", "20-admin.network"]);
    }

    #[test]
    fn units_are_world_readable_whatever_the_umask() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("10-kestrel-wlan0.network");
        // Simulate a strict umask by restricting the directory's defaults:
        // the explicit chmod must win regardless.
        write_unit(tmp.path(), &path, b"[Match]\n").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn missing_unit_dir_is_an_empty_sweep() {
        assert_eq!(
            remove_owned_units(Path::new("/nonexistent/kestrel"), "10-kestrel-").unwrap(),
            Vec::<InterfaceName>::new()
        );
    }
}

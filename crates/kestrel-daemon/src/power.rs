// SPDX-License-Identifier: LGPL-2.1-or-later

//! System sleep (`systemd-logind` `PrepareForSleep` + sleep delay inhibitor)
//! and hardware rfkill (`/sys/class/rfkill`) monitoring.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::StreamExt;
use kestrel_controller::RadioControl;
use tokio::task::JoinHandle;
use zbus::OwnedFd;
use zbus::message::Type;
use zbus::proxy::CacheProperties;

const LOGIND_SERVICE: &str = "org.freedesktop.login1";
const LOGIND_INTERFACE: &str = "org.freedesktop.login1.Manager";
const LOGIND_PATH: &str = "/org/freedesktop/login1";
const RFKILL_POLL: Duration = Duration::from_secs(1);
const SLEEP_QUEUE_CAPACITY: usize = 64;

fn rfkill_dir() -> PathBuf {
    std::env::var_os("KESTREL_RFKILL_DIR")
        .map_or_else(|| PathBuf::from("/sys/class/rfkill"), PathBuf::from)
}

/// Reads the current hardware rfkill state from `/sys/class/rfkill` (or
/// `$KESTREL_RFKILL_DIR`) before the radio controller starts.
pub(crate) fn initial_hardware_enabled() -> bool {
    read_hardware_enabled(&rfkill_dir())
}

/// Returns `false` when any wireless (`type == "wlan"`) rfkill switch is
/// hard-blocked (`hard == "1"`), and `true` otherwise (including when
/// `/sys/class/rfkill` is absent).
pub(crate) fn read_hardware_enabled(root: &Path) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return true;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let kind = fs::read_to_string(path.join("type")).unwrap_or_default();
        if kind.trim() != "wlan" {
            continue;
        }
        let hard = fs::read_to_string(path.join("hard")).unwrap_or_default();
        if hard.trim() == "1" {
            return false;
        }
    }
    true
}

async fn acquire_sleep_inhibitor(connection: &zbus::Connection) -> Option<OwnedFd> {
    let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(connection)
        .destination(LOGIND_SERVICE)
        .path(LOGIND_PATH)
        .interface(LOGIND_INTERFACE)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .ok()?;
    let reply = proxy
        .call_method(
            "Inhibit",
            &(
                "sleep",
                "Kestrel",
                "Release wireless connections cleanly before sleep",
                "delay",
            ),
        )
        .await
        .ok()?;
    reply.body().deserialize::<OwnedFd>().ok()
}

struct AbortOnDrop(Option<tokio::task::AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// Starts watching `PrepareForSleep` on `connection` (strictly from
/// `org.freedesktop.login1`) and hardware rfkill state in `/sys/class/rfkill`
/// (or `$KESTREL_RFKILL_DIR`).
pub(crate) async fn watch(
    connection: zbus::Connection,
    radio: RadioControl,
    initial_hw: bool,
) -> JoinHandle<()> {
    let rfkill = rfkill_dir();
    let rule = zbus::MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(LOGIND_SERVICE)
        .interface(LOGIND_INTERFACE)
        .member("PrepareForSleep")
        .path(LOGIND_PATH)
        .build()
        .expect("valid match rule");
    let stream = zbus::MessageStream::for_match_rule(rule, &connection, None)
        .await
        .ok();
    let initial_inhibitor = acquire_sleep_inhibitor(&connection).await;

    // Drain `PrepareForSleep` on a dedicated non-blocking bounded task so
    // D-Bus RPCs (such as re-acquiring the sleep inhibitor) never stall
    // `zbus`'s socket reader and queue memory stays bounded.
    let (sleep_tx, mut sleep_rx) = tokio::sync::mpsc::channel(SLEEP_QUEUE_CAPACITY);
    let drain_handle = stream.map(|mut s| {
        tokio::spawn(async move {
            while let Some(message) = s.next().await {
                match message {
                    Ok(msg) => {
                        if let Ok(sleeping) = msg.body().deserialize::<bool>() {
                            match sleep_tx.try_send(sleeping) {
                                Ok(()) => {}
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    tracing::warn!(
                                        sleeping,
                                        "PrepareForSleep queue full; dropping stale event"
                                    );
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                            }
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "PrepareForSleep stream error");
                    }
                }
            }
        })
        .abort_handle()
    });

    tokio::spawn(async move {
        let _drain_guard = AbortOnDrop(drain_handle);
        let mut sleep_open = true;
        let mut inhibitor = initial_inhibitor;
        let mut last_hw = initial_hw;
        let mut interval = tokio::time::interval(RFKILL_POLL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let dir = rfkill.clone();
                    let enabled = tokio::task::spawn_blocking(move || read_hardware_enabled(&dir))
                        .await
                        .unwrap_or(last_hw);
                    if enabled != last_hw {
                        last_hw = enabled;
                        if radio.set_hardware_enabled(enabled).await.is_err() {
                            return;
                        }
                    }
                }
                sleeping = async {
                    if sleep_open {
                        sleep_rx.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match sleeping {
                        Some(sleeping) => {
                            if radio.set_suspended(sleeping).await.is_err() {
                                return;
                            }
                            if sleeping {
                                // Release the delay inhibitor so logind can
                                // proceed with suspend now that teardown is
                                // queued.
                                drop(inhibitor.take());
                            } else if inhibitor.is_none() {
                                inhibitor = acquire_sleep_inhibitor(&connection).await;
                            }
                        }
                        None => {
                            sleep_open = false;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_wlan_hard_rfkill_from_sysfs_tree() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_hardware_enabled(tmp.path()));

        let bt = tmp.path().join("rfkill0");
        fs::create_dir(&bt).unwrap();
        fs::write(bt.join("type"), "bluetooth\n").unwrap();
        fs::write(bt.join("hard"), "1\n").unwrap();
        assert!(
            read_hardware_enabled(tmp.path()),
            "non-wlan rfkill must not block wireless"
        );

        let wlan = tmp.path().join("rfkill1");
        fs::create_dir(&wlan).unwrap();
        fs::write(wlan.join("type"), "wlan\n").unwrap();
        fs::write(wlan.join("hard"), "0\n").unwrap();
        assert!(read_hardware_enabled(tmp.path()));

        fs::write(wlan.join("hard"), "1\n").unwrap();
        assert!(!read_hardware_enabled(tmp.path()));
    }
}

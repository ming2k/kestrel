// SPDX-License-Identifier: LGPL-2.1-or-later

//! The single, ordered consumer of `wpa_supplicant` signals.
//!
//! Signal reception is strictly decoupled from async D-Bus RPC dispatch:
//! a non-blocking drain task pulls messages off `zbus::MessageStream`s and
//! enqueues them with non-blocking `try_send` into a bounded channel, while a
//! dedicated worker task processes them in arrival order. This prevents both
//! `zbus`'s socket reader from deadlocking during RPC work (ADR-0009) and
//! unbounded queue growth under pathological signal floods (ADR-0011): if the
//! bounded queue ever saturates, the drain sets an atomic lag flag and the
//! worker performs a full `discover()` resync.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use futures_util::StreamExt;
use kestrel_model::{InterfaceName, MacAddress, P2pRole, Secret, Ssid};
use kestrel_ports::PortResult;
use kestrel_ports::ap::ApEvent;
use kestrel_ports::p2p::{P2pEvent, RequestedMethod};
use kestrel_ports::wlan::WlanEvent;
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;
use zbus::message::Type;
use zbus::{OwnedObjectPath, OwnedVariant as OwnedValue};

use crate::{
    INTERFACE, Iface, Inner, MAIN, MAIN_PATH, P2P_DEVICE, Role, SERVICE, WpaSupplicant, dbus_error,
    mac_from_bytes,
};

const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const WPS: &str = "fi.w1.wpa_supplicant1.Interface.WPS";
const PERSISTENT_GROUP: &str = "fi.w1.wpa_supplicant1.PersistentGroup";
const SIGNAL_QUEUE_CAPACITY: usize = 2048;

type Dict = HashMap<String, OwnedValue>;

fn match_rules() -> PortResult<[zbus::MatchRule<'static>; 6]> {
    // Explicit, interface-scoped match rules:
    // - excludes noisy `fi.w1.wpa_supplicant1.BSS` beacon/signal churn at the
    //   bus daemon;
    // - avoids unfiltered well-known sender rules, which `zbus` treats as
    //   client-side wildcards across all streams on the shared connection.
    Ok([
        zbus::MatchRule::builder()
            .msg_type(Type::Signal)
            .sender("org.freedesktop.DBus")
            .interface("org.freedesktop.DBus")
            .member("NameOwnerChanged")
            .arg(0, SERVICE)
            .build()
            .map_err(dbus_error)?,
        zbus::MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(SERVICE)
            .interface(MAIN)
            .path(MAIN_PATH)
            .build()
            .map_err(dbus_error)?,
        zbus::MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(SERVICE)
            .interface(INTERFACE)
            .path_namespace(MAIN_PATH)
            .build()
            .map_err(dbus_error)?,
        zbus::MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(SERVICE)
            .interface(P2P_DEVICE)
            .path_namespace(MAIN_PATH)
            .build()
            .map_err(dbus_error)?,
        zbus::MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(SERVICE)
            .interface(WPS)
            .path_namespace(MAIN_PATH)
            .build()
            .map_err(dbus_error)?,
        zbus::MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(SERVICE)
            .interface(PROPERTIES)
            .member("PropertiesChanged")
            .path_namespace(MAIN_PATH)
            .build()
            .map_err(dbus_error)?,
    ])
}

pub(crate) async fn start(
    inner: Weak<Inner>,
    connection: zbus::Connection,
) -> PortResult<Vec<AbortHandle>> {
    let rules = match_rules()?;

    let mut streams = Vec::with_capacity(rules.len());
    for rule in rules {
        streams.push(
            zbus::MessageStream::for_match_rule(rule, &connection, None)
                .await
                .map_err(dbus_error)?,
        );
    }
    let mut merged = futures_util::stream::select_all(streams);

    let (tx, mut rx) = mpsc::channel(SIGNAL_QUEUE_CAPACITY);
    let lagged = Arc::new(AtomicBool::new(false));
    let lag_wake = Arc::new(Notify::new());
    let drain_weak = inner.clone();
    let drain_lagged = Arc::clone(&lagged);
    let drain_wake = Arc::clone(&lag_wake);
    let drain = tokio::spawn(async move {
        while let Some(message) = merged.next().await {
            if drain_weak.strong_count() == 0 {
                return;
            }
            match tx.try_send(message) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    if !drain_lagged.swap(true, Ordering::AcqRel) {
                        tracing::warn!(
                            capacity = SIGNAL_QUEUE_CAPACITY,
                            "wpa_supplicant signal queue full; scheduling full resync"
                        );
                    }
                    drain_wake.notify_one();
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
        tracing::warn!("wpa_supplicant signal stream ended");
    });

    let worker = tokio::spawn(async move {
        loop {
            let next = tokio::select! {
                biased;
                () = lag_wake.notified(), if lagged.load(Ordering::Acquire) => {
                    let Some(inner) = inner.upgrade() else {
                        return;
                    };
                    if lagged.swap(false, Ordering::AcqRel) {
                        let wpa = WpaSupplicant { inner };
                        if let Err(error) = wpa.discover().await {
                            tracing::warn!(%error, "wpa_supplicant resync after signal lag failed");
                        }
                    }
                    continue;
                }
                message = rx.recv() => message,
            };
            let Some(message) = next else {
                return;
            };
            let Some(inner) = inner.upgrade() else {
                return;
            };
            let wpa = WpaSupplicant { inner };
            match message {
                Ok(message) => dispatch(&wpa, &message).await,
                Err(error) => tracing::warn!(%error, "malformed wpa_supplicant signal"),
            }
            if lagged.swap(false, Ordering::AcqRel)
                && let Err(error) = wpa.discover().await
            {
                tracing::warn!(%error, "wpa_supplicant resync after signal lag failed");
            }
        }
    });

    Ok(vec![drain.abort_handle(), worker.abort_handle()])
}

#[allow(clippy::too_many_lines)]
async fn dispatch(wpa: &WpaSupplicant, message: &zbus::Message) {
    let header = message.header();
    let (Some(interface), Some(member), Some(path)) =
        (header.interface(), header.member(), header.path())
    else {
        return;
    };
    let path = OwnedObjectPath::from(path.to_owned());
    let body = message.body();

    if interface.as_str() == "org.freedesktop.DBus" && member.as_str() == "NameOwnerChanged" {
        if let Ok((name, old_owner, new_owner)) = body.deserialize::<(String, String, String)>()
            && name == SERVICE
        {
            if !old_owner.is_empty() {
                tracing::warn!("wpa_supplicant left the bus");
                wpa.backend_vanished();
            }
            if !new_owner.is_empty() {
                tracing::info!("wpa_supplicant appeared on the bus");
                wpa.lock().wpa_owner = Some(new_owner);
                if let Err(error) = wpa.discover().await {
                    tracing::warn!(%error, "cannot discover wpa_supplicant interfaces");
                }
            }
        }
        return;
    }

    // Reject signals that did not originate from the current `wpa_supplicant`
    // bus owner (protects against client-side well-known sender wildcards).
    if let Some(expected_owner) = wpa.lock().wpa_owner.clone()
        && header.sender().map(zbus::names::UniqueName::as_str) != Some(expected_owner.as_str())
    {
        return;
    }

    match (interface.as_str(), member.as_str()) {
        (MAIN, "InterfaceAdded") => {
            if let Ok((added, _)) = body.deserialize::<(OwnedObjectPath, Dict)>() {
                wpa.interface_added(added).await;
            }
        }
        (MAIN, "InterfaceRemoved") => {
            if let Ok(removed) = body.deserialize::<OwnedObjectPath>() {
                wpa.interface_removed(&removed);
            }
        }
        // Native `wpa_supplicant` D-Bus v1 signal: `Interface.PropertiesChanged(a{sv})`.
        (INTERFACE, "PropertiesChanged") => {
            if let Ok(changed) = body.deserialize::<Dict>()
                && (changed.contains_key("State") || changed.contains_key("CurrentBSS"))
            {
                wpa.refresh_link(&path).await;
            }
        }
        // Standard D-Bus `org.freedesktop.DBus.Properties.PropertiesChanged(s, a{sv}, as)`
        // fallback for compatibility if emitted on an interface object.
        (PROPERTIES, "PropertiesChanged") => {
            if let Ok((changed_interface, changed, _)) =
                body.deserialize::<(String, Dict, Vec<String>)>()
                && changed_interface == INTERFACE
                && (changed.contains_key("State") || changed.contains_key("CurrentBSS"))
            {
                wpa.refresh_link(&path).await;
            }
        }
        (INTERFACE, "ScanDone") => {
            let success = body.deserialize::<bool>().unwrap_or(false);
            scan_done(wpa, &path, success).await;
        }
        (INTERFACE, "PskMismatch") => {
            if let Some(device) = station(wpa, &path) {
                tracing::info!(%device, "wpa_supplicant reported a PSK mismatch");
                wpa.inner.events.publish(&WlanEvent::AuthFailed { device });
            }
        }
        (INTERFACE, "EAP") => {
            if let Ok((status, parameter)) = body.deserialize::<(String, String)>()
                && let Some(device) = station(wpa, &path)
            {
                let param_lower = parameter.to_ascii_lowercase();
                let cert_ok =
                    param_lower == "ok" || param_lower == "success" || param_lower == "passed";
                let failed = (status == "completion" && param_lower != "success")
                    || (status == "remote certificate verification" && !cert_ok);
                if failed {
                    tracing::info!(%device, %status, %parameter, "wpa_supplicant reported 802.1X failure");
                    wpa.inner.events.publish(&WlanEvent::AuthFailed { device });
                }
            }
        }
        (INTERFACE, "StaAuthorized") => {
            if let Ok(mac_str) = body.deserialize::<String>()
                && let Some(device) = station(wpa, &path)
                && wpa.lock().ap_active.contains_key(&device)
                && let Ok(mac) = MacAddress::parse(&mac_str)
            {
                wpa.inner
                    .ap_events
                    .publish(&ApEvent::ClientConnected { device, mac });
            }
        }
        (INTERFACE, "StaDeauthorized") => {
            if let Ok(mac_str) = body.deserialize::<String>()
                && let Some(device) = station(wpa, &path)
                && wpa.lock().ap_active.contains_key(&device)
                && let Ok(mac) = MacAddress::parse(&mac_str)
            {
                wpa.inner
                    .ap_events
                    .publish(&ApEvent::ClientDisconnected { device, mac });
            }
        }
        (P2P_DEVICE, member) => p2p_signal(wpa, &path, member, message).await,
        (WPS, "Event") => {
            if let Ok((name, _)) = body.deserialize::<(String, Dict)>()
                && name == "fail"
                && let Some(device) = p2p_owner(wpa, &path)
            {
                wpa.inner
                    .p2p_events
                    .publish(&P2pEvent::WpsFailed { device });
            }
        }
        _ => {}
    }
}

fn station(wpa: &WpaSupplicant, path: &OwnedObjectPath) -> Option<InterfaceName> {
    match wpa.lock().interfaces.get(path) {
        Some(Iface {
            ifname,
            role: Role::Station,
        }) => Some(ifname.clone()),
        _ => None,
    }
}

/// The device a P2P signal belongs to: the station itself, the parent of
/// a `p2p-dev-*` interface, or the parent of a group interface.
fn p2p_owner(wpa: &WpaSupplicant, path: &OwnedObjectPath) -> Option<InterfaceName> {
    let state = wpa.lock();
    state.interfaces.get(path).map(|iface| match &iface.role {
        Role::Station => iface.ifname.clone(),
        Role::P2pDevice(parent) | Role::P2pGroup(parent) => {
            state.resolve_station(parent, &iface.ifname)
        }
    })
}

async fn scan_done(wpa: &WpaSupplicant, path: &OwnedObjectPath, success: bool) {
    let Some(device) = station(wpa, path) else {
        return;
    };
    let result = if success {
        wpa.scan_results(path).await
    } else {
        Err(kestrel_ports::PortError::Backend("scan failed".to_owned()))
    };
    wpa.inner
        .events
        .publish(&WlanEvent::ScanFinished { device, result });
}

fn dict_str(dict: &Dict, key: &str) -> Option<String> {
    dict.get(key).and_then(|v| String::try_from(v.clone()).ok())
}

fn dict_bytes(dict: &Dict, key: &str) -> Option<Vec<u8>> {
    dict.get(key)
        .and_then(|v| Vec::<u8>::try_from(v.clone()).ok())
}

fn dict_path(dict: &Dict, key: &str) -> Option<OwnedObjectPath> {
    dict.get(key)
        .and_then(|v| OwnedObjectPath::try_from(v.clone()).ok())
}

fn role_from(value: Option<&str>) -> P2pRole {
    if value == Some("GO") {
        P2pRole::GroupOwner
    } else {
        P2pRole::Client
    }
}

/// Real `wpa_supplicant` sends `role_go` in `GONegotiationSuccess` as an
/// `i32` (`1` = Group Owner, `0` = client). Accept integers, booleans, and
/// `"GO"` strings for robustness.
fn role_from_go_flag(dict: &Dict, key: &str) -> P2pRole {
    let Some(value) = dict.get(key) else {
        return P2pRole::Client;
    };
    if let Ok(n) = i32::try_from(value.clone()) {
        return if n != 0 {
            P2pRole::GroupOwner
        } else {
            P2pRole::Client
        };
    }
    if let Ok(n) = u32::try_from(value.clone()) {
        return if n != 0 {
            P2pRole::GroupOwner
        } else {
            P2pRole::Client
        };
    }
    if let Ok(b) = bool::try_from(value.clone()) {
        return if b {
            P2pRole::GroupOwner
        } else {
            P2pRole::Client
        };
    }
    role_from(String::try_from(value.clone()).ok().as_deref())
}

#[allow(clippy::too_many_lines)]
async fn p2p_signal(
    wpa: &WpaSupplicant,
    path: &OwnedObjectPath,
    member: &str,
    message: &zbus::Message,
) {
    let body = message.body();
    let Some(device) = p2p_owner(wpa, path) else {
        return;
    };
    let events = &wpa.inner.p2p_events;
    match member {
        "DeviceFound" => {
            if let Ok(peer_path) = body.deserialize::<OwnedObjectPath>()
                && let Some(peer) = wpa.read_peer(&peer_path).await
            {
                wpa.lock().peers.insert(peer_path, peer.clone());
                events.publish(&P2pEvent::PeerFound { device, peer });
            }
        }
        "DeviceLost" => {
            if let Ok(peer_path) = body.deserialize::<OwnedObjectPath>()
                && let Some(peer) = wpa.lock().peers.remove(&peer_path)
            {
                events.publish(&P2pEvent::PeerLost {
                    device,
                    address: peer.address,
                });
            }
        }
        "FindStopped" => events.publish(&P2pEvent::FindStopped { device }),
        "GONegotiationRequest" => {
            if let Ok((peer_path, password_id, _intent)) =
                body.deserialize::<(OwnedObjectPath, u16, u8)>()
                && let Some(peer) = crate::p2p::peer_address(&peer_path)
            {
                let method = if password_id == 4 {
                    RequestedMethod::PushButton
                } else {
                    RequestedMethod::Pin
                };
                events.publish(&P2pEvent::NegotiationRequest {
                    device,
                    peer,
                    method,
                });
            }
        }
        "InvitationReceived" => {
            if let Ok(info) = body.deserialize::<Dict>()
                && let Some(peer) = dict_bytes(&info, "sa").and_then(|b| mac_from_bytes(&b))
            {
                let go_address = dict_bytes(&info, "go_dev_addr")
                    .and_then(|b| mac_from_bytes(&b))
                    .unwrap_or(peer);
                let persistent = info.contains_key("persistent_id");
                events.publish(&P2pEvent::InvitationReceived {
                    device,
                    peer,
                    go_address,
                    persistent,
                });
            }
        }
        "GONegotiationSuccess" => {
            if let Ok(info) = body.deserialize::<Dict>() {
                let role = role_from_go_flag(&info, "role_go");
                events.publish(&P2pEvent::GoNegotiationSucceeded { device, role });
            }
        }
        "GONegotiationFailure" => {
            let status = body
                .deserialize::<Dict>()
                .ok()
                .and_then(|info| {
                    info.get("status")
                        .and_then(|v| i32::try_from(v.clone()).ok())
                })
                .and_then(|status| u8::try_from(status).ok())
                .unwrap_or(u8::MAX);
            events.publish(&P2pEvent::GoNegotiationFailed { device, status });
        }
        "PersistentGroupAdded" => {
            if let Ok((group_path, props)) = body.deserialize::<(OwnedObjectPath, Dict)>() {
                emit_persistent_group(wpa, &device, &group_path, &props).await;
            }
        }
        "GroupStarted" => {
            let Ok(info) = body.deserialize::<Dict>() else {
                return;
            };
            let Some(group_path) = dict_path(&info, "interface_object") else {
                return;
            };
            let role = role_from(dict_str(&info, "role").as_deref());
            wpa.interface_added(group_path.clone()).await;
            let previous = {
                let mut state = wpa.lock();
                state.interfaces.get_mut(&group_path).map(|iface| {
                    let previous = iface.role.clone();
                    iface.role = Role::P2pGroup(device.clone());
                    (iface.ifname.clone(), previous)
                })
            };
            let Some((group_if, previous)) = previous else {
                tracing::warn!(path = %group_path.as_str(), "GroupStarted for an unknown interface");
                return;
            };
            let reused_station = previous == Role::Station;
            wpa.lock()
                .known_groups
                .insert(group_path, (group_if.clone(), reused_station));
            if reused_station {
                wpa.lock().links.remove(&group_if);
                wpa.inner
                    .events
                    .publish(&WlanEvent::DeviceRemoved(group_if.clone()));
            }
            events.publish(&P2pEvent::GroupStarted {
                device,
                group_if,
                role,
            });
        }
        "GroupFinished" => {
            let Ok(info) = body.deserialize::<Dict>() else {
                return;
            };
            let group_path = dict_path(&info, "interface_object");
            let cached = group_path
                .as_ref()
                .and_then(|p| wpa.lock().known_groups.remove(p));
            let group_if = cached
                .as_ref()
                .map(|(ifname, _)| ifname.clone())
                .or_else(|| {
                    group_path
                        .as_ref()
                        .and_then(|p| wpa.lock().interfaces.get(p).map(|i| i.ifname.clone()))
                })
                .or_else(|| dict_str(&info, "ifname").and_then(|n| InterfaceName::new(n).ok()));
            if let Some(group_if) = group_if {
                events.publish(&P2pEvent::GroupFinished {
                    device,
                    group_if: group_if.clone(),
                });
                if cached.is_some_and(|(_, reused)| reused)
                    && let Some(path) = group_path
                {
                    let restored = {
                        let mut state = wpa.lock();
                        if let Some(iface) = state.interfaces.get_mut(&path) {
                            iface.role = Role::Station;
                            Some(WpaSupplicant::device_for(&state, &group_if, None))
                        } else {
                            None
                        }
                    };
                    if let Some(mut dev) = restored {
                        dev.address = crate::read_sysfs_mac(&wpa.inner.sysfs, &group_if).await;
                        wpa.inner.events.publish(&WlanEvent::DeviceAdded(dev));
                    }
                }
            }
        }
        "WpsFailed" => events.publish(&P2pEvent::WpsFailed { device }),
        _ => {}
    }
}

async fn emit_persistent_group(
    wpa: &WpaSupplicant,
    device: &InterfaceName,
    group_path: &OwnedObjectPath,
    inline_props: &Dict,
) {
    {
        let mut state = wpa.lock();
        if state.suppress_persistent_added > 0 || state.self_persistent_groups.remove(group_path) {
            return;
        }
    }
    let props = if inline_props.is_empty() {
        let Ok(proxy) = wpa.proxy(group_path.as_str(), PERSISTENT_GROUP).await else {
            return;
        };
        proxy
            .get_property::<Dict>("Properties")
            .await
            .unwrap_or_default()
    } else {
        inline_props.clone()
    };
    let ssid = dict_bytes(&props, "ssid")
        .or_else(|| dict_str(&props, "ssid").map(|s| s.trim_matches('"').as_bytes().to_vec()))
        .and_then(|b| Ssid::from_bytes(b).ok());
    let go_address = dict_str(&props, "bssid")
        .and_then(|s| MacAddress::parse(s.trim_matches('"')).ok())
        .or_else(|| dict_bytes(&props, "bssid").and_then(|b| mac_from_bytes(&b)));
    let psk = dict_str(&props, "psk").map(|s| Secret::new(s.trim_matches('"')));
    // Real `wpa_supplicant` exposes `PersistentGroup.Properties` values as
    // strings (`"3"`), whereas test fakes may send integers (`3u32`).
    let mode = props
        .get("mode")
        .and_then(|v| {
            u32::try_from(v.clone())
                .ok()
                .or_else(|| {
                    i32::try_from(v.clone())
                        .ok()
                        .and_then(|n| u32::try_from(n).ok())
                })
                .or_else(|| {
                    String::try_from(v.clone())
                        .ok()
                        .and_then(|s| s.trim_matches('"').parse::<u32>().ok())
                })
        })
        .unwrap_or(0);
    let role = if mode == 3 {
        P2pRole::GroupOwner
    } else {
        P2pRole::Client
    };
    if let (Some(ssid), Some(go_address), Some(psk)) = (ssid, go_address, psk) {
        wpa.inner
            .p2p_events
            .publish(&P2pEvent::PersistentGroupFormed {
                device: device.clone(),
                role,
                ssid,
                go_address,
                psk,
            });
    }
}

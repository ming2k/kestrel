// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel p2p`: Wi-Fi Direct discovery, sessions, WFD, and persistent groups.

use std::fmt::Write as _;
use std::io::IsTerminal;
use std::time::Duration;

use clap::{Args, Subcommand};
use futures_util::StreamExt;
use kestrel_api::client::{Client, P2pGroupProxy, SessionProxy};
use serde_json::{Value, json};
use zbus::OwnedObjectPath;

use crate::common::{
    confirm_delete, dash_if_empty, failure, format_age, json_str_or_dash, print, print_table,
    prompt_secret_with, resolve_p2p_group, short_id, stdin_secret_labeled,
};

const MAX_WFD_SUBELEMENTS_BYTES: usize = 1024;

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ConnectArgs {
    pub(crate) device: String,
    pub(crate) peer: String,
    /// Prompt for the peer's WPS PIN on the terminal (keypad method).
    #[arg(long, conflicts_with_all = ["display", "pin_stdin"])]
    pub(crate) keypad: bool,
    /// Read the peer's WPS PIN from the first line of standard input.
    #[arg(long, conflicts_with = "display")]
    pub(crate) pin_stdin: bool,
    /// Show a PIN for the peer to enter (delivered to the agent).
    #[arg(long)]
    pub(crate) display: bool,
    /// 0..=15; higher prefers being the group owner.
    #[arg(long)]
    pub(crate) go_intent: Option<u8>,
    /// Save the group for WPS-free reconnection.
    #[arg(long)]
    pub(crate) persistent: bool,
    /// Wait until the session is ready or closed.
    #[arg(long)]
    pub(crate) wait: bool,
    /// Seconds to wait when `--wait` is set.
    #[arg(long, default_value_t = 60)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Subcommand)]
pub(crate) enum P2p {
    /// Discover peers for a while, printing them as they appear.
    Find {
        device: String,
        #[arg(long, default_value_t = 30)]
        timeout: u32,
    },
    /// Show currently known P2P peers.
    Peers { device: String },
    /// Set or clear Wi-Fi Display (Miracast) subelements advertised on a device.
    Wfd {
        device: String,
        /// Hex-encoded WFD subelements, or `clear` to disable advertisement.
        subelements: String,
    },
    /// Connect to a peer.
    Connect(ConnectArgs),
    /// Start a group as owner without GO negotiation (autonomous GO).
    StartGroup {
        device: String,
        /// Operating channel in MHz; omit to let the backend choose.
        #[arg(long)]
        frequency: Option<u32>,
        /// Save the group for WPS-free reconnection.
        #[arg(long)]
        persistent: bool,
        /// Wait until the session is ready or closed.
        #[arg(long)]
        wait: bool,
        /// Seconds to wait when `--wait` is set.
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
    /// Saved persistent groups (reconnect without WPS).
    #[command(subcommand)]
    Groups(P2pGroups),
    /// Reconnect to a saved persistent group, inviting `--peer` if given.
    Reconnect {
        device: String,
        group: String,
        /// Peer to invite; omit to restart the group as owner.
        #[arg(long)]
        peer: Option<String>,
        /// Operating channel in MHz; omit for automatic selection.
        #[arg(long)]
        frequency: Option<u32>,
        /// Wait until the session is ready or closed.
        #[arg(long)]
        wait: bool,
        /// Seconds to wait when `--wait` is set.
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
    /// List active P2P sessions.
    Sessions,
    /// Close an active P2P session.
    Close { session: String },
}

#[derive(Debug, Subcommand)]
pub(crate) enum P2pGroups {
    /// List saved persistent groups.
    List,
    /// Show one saved persistent group.
    Show { group: String },
    /// Delete a saved persistent group.
    Delete {
        group: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

pub(crate) async fn run(client: &Client, command: P2p, json: bool) -> zbus::Result<()> {
    match command {
        P2p::Find { device, timeout } => find(client, &device, timeout, json).await,
        P2p::Peers { device } => peers(client, &device, json).await,
        P2p::Wfd {
            device,
            subelements,
        } => wfd(client, &device, &subelements, json).await,
        P2p::Connect(args) => connect(client, &args, json).await,
        P2p::StartGroup {
            device,
            frequency,
            persistent,
            wait,
            timeout,
        } => {
            let path = client
                .p2p(&device)
                .await?
                .start_group(frequency.unwrap_or(0), persistent)
                .await?;
            report_session(client, path, wait, Duration::from_secs(timeout), json).await
        }
        P2p::Groups(command) => p2p_groups(client, command, json).await,
        P2p::Reconnect {
            device,
            group,
            peer,
            frequency,
            wait,
            timeout,
        } => {
            reconnect(
                client,
                &device,
                &group,
                peer.as_deref(),
                frequency,
                wait,
                Duration::from_secs(timeout),
                json,
            )
            .await
        }
        P2p::Sessions => sessions(client, json).await,
        P2p::Close { session } => {
            let path = session_ref(&session)?;
            client.session(path.clone()).await?.close().await?;
            print(
                json,
                &json!({"session": path.as_str(), "closed": true}),
                || println!("closed {}", path.as_str()),
            );
            Ok(())
        }
    }
}

async fn find(client: &Client, device: &str, timeout: u32, json: bool) -> zbus::Result<()> {
    let proxy = client.p2p(device).await?;
    let mut found = proxy.receive_peer_found().await?;
    proxy.find(timeout).await?;
    let deadline = tokio::time::sleep(Duration::from_secs(u64::from(timeout)));
    tokio::pin!(deadline);
    let mut collected = Vec::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            () = &mut deadline => break,
            signal = found.next() => {
                let Some(signal) = signal else { break };
                let args = signal.args()?;
                let wfd_hex = encode_hex(&args.wfd_subelements);
                let value = json!({
                    "address": args.address,
                    "name": args.name,
                    "device_type": args.device_type,
                    "wfd_subelements": wfd_hex,
                });
                if json {
                    collected.push(value);
                } else if wfd_hex.is_empty() {
                    println!("{}  {}  {}", args.address, args.device_type, args.name);
                } else {
                    println!(
                        "{}  {}  {}  wfd={wfd_hex}",
                        args.address, args.device_type, args.name
                    );
                }
            }
        }
    }
    let _ = proxy.stop_find().await;
    if json {
        print(json, &Value::Array(collected), || {});
    }
    Ok(())
}

async fn peers(client: &Client, device: &str, json: bool) -> zbus::Result<()> {
    let peers = client.p2p(device).await?.get_peers().await?;
    let value: Vec<Value> = peers
        .iter()
        .map(|(address, name, kind, wfd)| {
            json!({
                "address": address,
                "name": name,
                "device_type": kind,
                "wfd_subelements": encode_hex(wfd),
            })
        })
        .collect();
    print(json, &Value::Array(value), || {
        let rows: Vec<Vec<String>> = peers
            .iter()
            .map(|(address, name, kind, wfd)| {
                let wfd_hex = encode_hex(wfd);
                vec![
                    address.clone(),
                    dash_if_empty(kind).to_owned(),
                    dash_if_empty(name).to_owned(),
                    dash_if_empty(&wfd_hex).to_owned(),
                ]
            })
            .collect();
        print_table(&["ADDRESS", "TYPE", "NAME", "WFD"], &rows);
    });
    Ok(())
}

async fn wfd(client: &Client, device: &str, raw: &str, json: bool) -> zbus::Result<()> {
    let bytes = parse_wfd_arg(raw)?;
    client
        .p2p(device)
        .await?
        .set_wfd_subelements(&bytes)
        .await?;
    let hex = encode_hex(&bytes);
    print(
        json,
        &json!({
            "device": device,
            "wfd_subelements": hex,
            "enabled": !bytes.is_empty(),
        }),
        || {
            if bytes.is_empty() {
                println!("{device}: WFD subelements cleared");
            } else {
                println!("{device}: WFD subelements set ({hex})");
            }
        },
    );
    Ok(())
}

async fn connect(client: &Client, args: &ConnectArgs, json: bool) -> zbus::Result<()> {
    let (method, pin) = if args.pin_stdin {
        ("keypad", Some(stdin_secret_labeled("WPS PIN")?))
    } else if args.keypad {
        if !std::io::stdin().is_terminal() {
            return Err(failure(
                "--keypad needs a terminal; use --pin-stdin in a script",
            ));
        }
        ("keypad", Some(prompt_secret_with("WPS PIN: ", "WPS PIN")?))
    } else if args.display {
        ("display", None)
    } else {
        ("pbc", None)
    };
    let path = client
        .p2p(&args.device)
        .await?
        .connect(
            &args.peer,
            method,
            pin.as_deref().map_or("", String::as_str),
            args.go_intent.unwrap_or(u8::MAX),
            args.persistent,
        )
        .await?;
    report_session(
        client,
        path,
        args.wait,
        Duration::from_secs(args.timeout),
        json,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn reconnect(
    client: &Client,
    device: &str,
    group: &str,
    peer: Option<&str>,
    frequency: Option<u32>,
    wait: bool,
    timeout: Duration,
    json: bool,
) -> zbus::Result<()> {
    let group = resolve_p2p_group(client, group).await?;
    let proxy = client.p2p(device).await?;
    let path = match peer {
        Some(peer) => {
            proxy
                .connect_persistent(&group.as_ref(), peer, frequency.unwrap_or(0))
                .await?
        }
        None => {
            proxy
                .start_persistent_group(&group.as_ref(), frequency.unwrap_or(0))
                .await?
        }
    };
    report_session(client, path, wait, timeout, json).await
}

async fn sessions(client: &Client, json: bool) -> zbus::Result<()> {
    let mut rows = Vec::new();
    for session in client.sessions().await? {
        rows.push(session_json(&session).await?);
    }
    print(json, &Value::Array(rows.clone()), || {
        let table: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                vec![
                    row["path"].as_str().unwrap_or("").to_owned(),
                    row["state"].as_str().unwrap_or("").to_owned(),
                    json_str_or_dash(row, "role").to_owned(),
                    if row["autonomous"].as_bool() == Some(true) {
                        "autonomous".to_owned()
                    } else {
                        json_str_or_dash(row, "peer").to_owned()
                    },
                    json_str_or_dash(row, "group_interface").to_owned(),
                    json_str_or_dash(row, "peer_ip").to_owned(),
                ]
            })
            .collect();
        print_table(
            &["SESSION", "STATE", "ROLE", "PEER", "GROUP IF", "PEER IP"],
            &table,
        );
    });
    Ok(())
}

/// Prints a new session immediately, or waits for it to settle with `wait`.
async fn report_session(
    client: &Client,
    path: OwnedObjectPath,
    wait: bool,
    timeout: Duration,
    json: bool,
) -> zbus::Result<()> {
    let session = client.session(path.clone()).await?;
    if wait {
        let value = wait_session(&session, timeout).await?;
        print(json, &value, || print_session(&value));
    } else {
        print(json, &json!({"session": path.as_str()}), || {
            println!("{}", path.as_str());
        });
    }
    Ok(())
}

fn print_session(value: &Value) {
    println!("Session: {}", value["path"].as_str().unwrap_or(""));
    println!("Device: {}", json_str_or_dash(value, "device"));
    println!("State: {}", value["state"].as_str().unwrap_or(""));
    println!("Role: {}", json_str_or_dash(value, "role"));
    println!(
        "Peer: {}",
        if value["autonomous"].as_bool() == Some(true) {
            "autonomous"
        } else {
            json_str_or_dash(value, "peer")
        }
    );
    println!(
        "Group interface: {}",
        json_str_or_dash(value, "group_interface")
    );
    println!("Peer IP: {}", json_str_or_dash(value, "peer_ip"));
    let failure_code = value["failure"].as_str().unwrap_or("");
    if !failure_code.is_empty() {
        let detail = value["failure_detail"].as_str().unwrap_or("");
        if detail.is_empty() {
            println!("Failure: {failure_code}");
        } else {
            println!("Failure: {failure_code} ({detail})");
        }
    }
}

/// Lists, shows, or deletes saved persistent Wi-Fi Direct groups.
async fn p2p_groups(client: &Client, command: P2pGroups, json: bool) -> zbus::Result<()> {
    match command {
        P2pGroups::List => {
            let mut rows = Vec::new();
            for group in client.p2p_groups().await? {
                rows.push(p2p_group_json(&group).await?);
            }
            rows.sort_by(|a, b| {
                b["last_connected"]
                    .as_u64()
                    .unwrap_or(0)
                    .cmp(&a["last_connected"].as_u64().unwrap_or(0))
                    .then_with(|| {
                        a["name"]
                            .as_str()
                            .unwrap_or("")
                            .cmp(b["name"].as_str().unwrap_or(""))
                    })
            });
            print(json, &Value::Array(rows.clone()), || {
                let table: Vec<Vec<String>> = rows
                    .iter()
                    .map(|row| {
                        vec![
                            short_id(row["id"].as_str().unwrap_or("")),
                            row["name"].as_str().unwrap_or("").to_owned(),
                            row["ssid"].as_str().unwrap_or("").to_owned(),
                            row["role"].as_str().unwrap_or("").to_owned(),
                            json_str_or_dash(row, "peer").to_owned(),
                            row["go_address"].as_str().unwrap_or("").to_owned(),
                            format_age(row["last_connected"].as_u64().unwrap_or(0)),
                        ]
                    })
                    .collect();
                print_table(
                    &[
                        "ID",
                        "NAME",
                        "SSID",
                        "ROLE",
                        "PEER",
                        "GO ADDRESS",
                        "LAST USED",
                    ],
                    &table,
                );
            });
        }
        P2pGroups::Show { group } => {
            let path = resolve_p2p_group(client, &group).await?;
            let group = client.p2p_group(path).await?;
            let value = p2p_group_json(&group).await?;
            print(json, &value, || {
                println!("ID: {}", value["id"].as_str().unwrap_or(""));
                println!("Name: {}", value["name"].as_str().unwrap_or(""));
                println!("SSID: {}", value["ssid"].as_str().unwrap_or(""));
                println!("Role: {}", value["role"].as_str().unwrap_or(""));
                println!("Peer: {}", json_str_or_dash(&value, "peer"));
                println!("GO address: {}", value["go_address"].as_str().unwrap_or(""));
                println!(
                    "Last connected: {} ({})",
                    value["last_connected"],
                    format_age(value["last_connected"].as_u64().unwrap_or(0))
                );
            });
        }
        P2pGroups::Delete { group, yes } => {
            let path = resolve_p2p_group(client, &group).await?;
            let proxy = client.p2p_group(path).await?;
            let value = p2p_group_json(&proxy).await?;
            let name = value["name"].as_str().unwrap_or("").to_owned();
            if !confirm_delete(&format!("Delete persistent group {name:?}? [y/N] "), yes)? {
                print(
                    json,
                    &json!({"name": name, "deleted": false, "cancelled": true}),
                    || println!("cancelled"),
                );
                return Ok(());
            }
            proxy.delete().await?;
            print(json, &json!({"name": name, "deleted": true}), || {
                println!("deleted {name:?}");
            });
        }
    }
    Ok(())
}

async fn p2p_group_json(group: &P2pGroupProxy<'_>) -> zbus::Result<Value> {
    Ok(json!({
        "path": group.inner().path().as_str(),
        "id": group.id().await?,
        "name": group.name().await?,
        "ssid": group.ssid().await?,
        "role": group.role().await?,
        "peer": group.peer().await?,
        "go_address": group.go_address().await?,
        "last_connected": group.last_connected().await?,
    }))
}

async fn session_json(session: &SessionProxy<'_>) -> zbus::Result<Value> {
    Ok(json!({
        "path": session.inner().path().as_str(),
        "device": session.device().await?.as_str(),
        "peer": session.peer().await?,
        "incoming": session.incoming().await?,
        "autonomous": session.autonomous().await?,
        "state": session.state().await?,
        "role": session.role().await?,
        "group_interface": session.group_interface().await?,
        "peer_ip": session.peer_ip().await?,
        "failure": session.failure().await?,
        "failure_detail": session.failure_detail().await?,
    }))
}

async fn wait_session(session: &SessionProxy<'_>, timeout: Duration) -> zbus::Result<Value> {
    let mut changes = session.receive_state_changed().await;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let state = session.state().await?;
        if state == "ready" || state == "closed" {
            return session_json(session).await;
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                return Err(failure("timed out waiting for P2P session"));
            }
            event = changes.next() => {
                if event.is_none() {
                    return session_json(session).await;
                }
            }
        }
    }
}

pub(crate) fn session_ref(value: &str) -> zbus::Result<OwnedObjectPath> {
    let path = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{}/Session/{value}", kestrel_api::ROOT_PATH)
    } else {
        value.to_owned()
    };
    OwnedObjectPath::try_from(path).map_err(|error| failure(error.to_string()))
}

pub(crate) fn parse_wfd_arg(raw: &str) -> zbus::Result<Vec<u8>> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("clear")
        || trimmed.eq_ignore_ascii_case("none")
    {
        return Ok(Vec::new());
    }
    let hex: String = trimmed
        .chars()
        .filter(|ch| !matches!(ch, ':' | ' ' | '-' | '\t'))
        .collect();
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return Err(failure(
            "WFD subelements must be an even-length hex string or `clear`",
        ));
    }
    let (chunks, _) = hex.as_bytes().as_chunks::<2>();
    let mut bytes = Vec::with_capacity(chunks.len());
    for pair in chunks {
        let s = std::str::from_utf8(pair).map_err(|_| failure("invalid hex in WFD subelements"))?;
        let byte = u8::from_str_radix(s, 16)
            .map_err(|_| failure(format!("invalid hex byte {s:?} in WFD subelements")))?;
        bytes.push(byte);
    }
    if bytes.len() > MAX_WFD_SUBELEMENTS_BYTES {
        return Err(failure(format!(
            "WFD subelements exceed {MAX_WFD_SUBELEMENTS_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

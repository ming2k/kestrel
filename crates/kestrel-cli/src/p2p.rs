// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel p2p`: Wi-Fi Direct peers, sessions, WFD, and persistent groups.

use std::fmt::Write as _;
use std::io::IsTerminal;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use futures_util::StreamExt;
use kestrel_api::client::{Client, P2pGroupProxy, SessionProxy};
use serde_json::{Value, json};
use zbus::OwnedObjectPath;

use crate::common::{
    CliError, CliResult, DeviceOpt, confirm_delete, dash_if_empty, format_age, json_str_or_dash,
    print, print_table, prompt_secret_with, resolve_device, resolve_p2p_group, short_id,
    stdin_secret_labeled,
};

const MAX_WFD_SUBELEMENTS_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum WpsMethod {
    /// Push-button configuration (default).
    Pbc,
    /// Enter the peer's WPS PIN on this host.
    Keypad,
    /// Display a generated WPS PIN via the registered agent.
    Display,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ConnectArgs {
    /// Peer P2P device MAC address.
    pub(crate) peer: String,
    #[command(flatten)]
    pub(crate) device: DeviceOpt,
    /// WPS authentication method (defaults to `pbc`, or `keypad` when `--pin-stdin` is set).
    #[arg(long, value_enum)]
    pub(crate) wps: Option<WpsMethod>,
    /// Read the peer's WPS PIN from the first line of standard input (implies `--wps keypad`).
    #[arg(long)]
    pub(crate) pin_stdin: bool,
    /// Group Owner intent (`0..=15`; higher prefers being the group owner).
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=15))]
    pub(crate) go_intent: Option<u8>,
    /// Save the formed group for WPS-free reconnection.
    #[arg(long)]
    pub(crate) persistent: bool,
    /// Return immediately after the session is created instead of waiting for `ready`.
    #[arg(long)]
    pub(crate) no_wait: bool,
    /// Seconds to wait for the session to become ready.
    #[arg(short = 't', long, default_value_t = 60)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Args)]
pub(crate) struct StartGroupArgs {
    #[command(flatten)]
    pub(crate) device: DeviceOpt,
    /// Operating channel in MHz; omit to let the backend choose.
    #[arg(short = 'f', long)]
    pub(crate) frequency: Option<u32>,
    /// Save the group for WPS-free reconnection.
    #[arg(long)]
    pub(crate) persistent: bool,
    /// Return immediately after the session is created instead of waiting for `ready`.
    #[arg(long)]
    pub(crate) no_wait: bool,
    /// Seconds to wait for the session to become ready.
    #[arg(short = 't', long, default_value_t = 60)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Args)]
pub(crate) struct ReconnectArgs {
    /// Saved persistent group (UUID, prefix, name, or SSID).
    pub(crate) group: String,
    #[command(flatten)]
    pub(crate) device: DeviceOpt,
    /// Peer MAC address to invite; omit to restart the group autonomously as owner.
    #[arg(long)]
    pub(crate) peer: Option<String>,
    /// Operating channel in MHz; omit for automatic selection.
    #[arg(short = 'f', long)]
    pub(crate) frequency: Option<u32>,
    /// Return immediately after the session is created instead of waiting for `ready`.
    #[arg(long)]
    pub(crate) no_wait: bool,
    /// Seconds to wait for the session to become ready.
    #[arg(short = 't', long, default_value_t = 60)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Subcommand)]
pub(crate) enum P2p {
    /// Discover or list Wi-Fi Direct peers.
    #[command(subcommand)]
    Peer(P2pPeer),
    /// Connect to a peer via Group Owner negotiation.
    Connect(ConnectArgs),
    /// Start an autonomous Group Owner group without GO negotiation.
    StartGroup(StartGroupArgs),
    /// Reconnect a saved persistent group without WPS.
    Reconnect(ReconnectArgs),
    /// Manage Wi-Fi Display (Miracast) subelements advertised on a device.
    #[command(subcommand)]
    Wfd(P2pWfd),
    /// Inspect or close active P2P sessions.
    #[command(subcommand)]
    Session(P2pSession),
    /// Manage saved persistent P2P groups.
    #[command(subcommand)]
    Group(P2pGroup),
}

#[derive(Debug, Subcommand)]
pub(crate) enum P2pPeer {
    /// Actively discover P2P peers, printing them as they appear.
    Find {
        #[command(flatten)]
        device: DeviceOpt,
        /// Discovery duration in seconds.
        #[arg(short = 't', long, default_value_t = 30)]
        timeout: u32,
    },
    /// List currently known P2P peers.
    List {
        #[command(flatten)]
        device: DeviceOpt,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum P2pWfd {
    /// Advertise hex-encoded Wi-Fi Display (Miracast) subelements.
    Set {
        /// Hex-encoded WFD subelements (separators `:`, `-`, and spaces are ignored).
        hex: String,
        #[command(flatten)]
        device: DeviceOpt,
    },
    /// Stop advertising Wi-Fi Display subelements.
    Clear {
        #[command(flatten)]
        device: DeviceOpt,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum P2pSession {
    /// List active P2P sessions.
    List,
    /// Show details of one active P2P session.
    Show {
        /// Numeric session ID (e.g. `1`) or full D-Bus object path.
        session: String,
    },
    /// Close an active P2P session.
    Close {
        /// Numeric session ID (e.g. `1`) or full D-Bus object path.
        session: String,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum P2pGroup {
    /// List saved persistent P2P groups.
    List,
    /// Show one saved persistent P2P group.
    Show {
        /// Group UUID, 8+ char prefix, name, or SSID.
        group: String,
    },
    /// Delete a saved persistent P2P group and its sealed PSK.
    Delete {
        /// Group UUID, 8+ char prefix, name, or SSID.
        group: String,
        /// Do not ask for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

pub(crate) async fn run(client: &Client, command: P2p, json: bool) -> CliResult<()> {
    match command {
        P2p::Peer(P2pPeer::Find { device, timeout }) => {
            let (iface, _) = resolve_device(client, device.device.as_deref(), Some("p2p")).await?;
            find(client, &iface, timeout, json).await
        }
        P2p::Peer(P2pPeer::List { device }) => {
            let (iface, _) = resolve_device(client, device.device.as_deref(), Some("p2p")).await?;
            peers(client, &iface, json).await
        }
        P2p::Connect(args) => connect(client, &args, json).await,
        P2p::StartGroup(args) => start_group(client, &args, json).await,
        P2p::Reconnect(args) => reconnect(client, &args, json).await,
        P2p::Wfd(P2pWfd::Set { hex, device }) => {
            let (iface, _) = resolve_device(client, device.device.as_deref(), Some("p2p")).await?;
            let bytes = parse_wfd_hex(&hex)?;
            wfd_apply(client, &iface, &bytes, json).await
        }
        P2p::Wfd(P2pWfd::Clear { device }) => {
            let (iface, _) = resolve_device(client, device.device.as_deref(), Some("p2p")).await?;
            wfd_apply(client, &iface, &[], json).await
        }
        P2p::Session(command) => p2p_session(client, command, json).await,
        P2p::Group(command) => p2p_group(client, command, json).await,
    }
}

async fn find(client: &Client, device: &str, timeout: u32, json: bool) -> CliResult<()> {
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

async fn peers(client: &Client, device: &str, json: bool) -> CliResult<()> {
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
        print_table(
            &["ADDRESS", "TYPE", "NAME", "WFD"],
            &rows,
            Some("No known P2P peers."),
        );
    });
    Ok(())
}

async fn wfd_apply(client: &Client, device: &str, bytes: &[u8], json: bool) -> CliResult<()> {
    client.p2p(device).await?.set_wfd_subelements(bytes).await?;
    let hex = encode_hex(bytes);
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

async fn connect(client: &Client, args: &ConnectArgs, json: bool) -> CliResult<()> {
    let wps = match (args.wps, args.pin_stdin) {
        (Some(WpsMethod::Pbc | WpsMethod::Display), true) => {
            return Err(CliError::runtime(
                "--pin-stdin requires --wps keypad (or omit --wps)",
            ));
        }
        (None | Some(WpsMethod::Keypad), true) => WpsMethod::Keypad,
        (Some(method), false) => method,
        (None, false) => WpsMethod::Pbc,
    };

    let (method, pin) = match wps {
        WpsMethod::Pbc => ("pbc", None),
        WpsMethod::Display => ("display", None),
        WpsMethod::Keypad if args.pin_stdin => ("keypad", Some(stdin_secret_labeled("WPS PIN")?)),
        WpsMethod::Keypad => {
            if !std::io::stdin().is_terminal() {
                return Err(CliError::runtime(
                    "--wps keypad needs a terminal; use --pin-stdin in a script",
                ));
            }
            ("keypad", Some(prompt_secret_with("WPS PIN: ", "WPS PIN")?))
        }
    };

    let (iface, _) = resolve_device(client, args.device.device.as_deref(), Some("p2p")).await?;
    let path = client
        .p2p(&iface)
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
        args.no_wait,
        Duration::from_secs(args.timeout),
        json,
    )
    .await
}

async fn start_group(client: &Client, args: &StartGroupArgs, json: bool) -> CliResult<()> {
    let (iface, _) = resolve_device(client, args.device.device.as_deref(), Some("p2p")).await?;
    let path = client
        .p2p(&iface)
        .await?
        .start_group(args.frequency.unwrap_or(0), args.persistent)
        .await?;
    report_session(
        client,
        path,
        args.no_wait,
        Duration::from_secs(args.timeout),
        json,
    )
    .await
}

async fn reconnect(client: &Client, args: &ReconnectArgs, json: bool) -> CliResult<()> {
    let (iface, _) = resolve_device(client, args.device.device.as_deref(), Some("p2p")).await?;
    let group = resolve_p2p_group(client, &args.group).await?;
    let proxy = client.p2p(&iface).await?;
    let path = match args.peer.as_deref() {
        Some(peer) => {
            proxy
                .connect_persistent(&group.as_ref(), peer, args.frequency.unwrap_or(0))
                .await?
        }
        None => {
            proxy
                .start_persistent_group(&group.as_ref(), args.frequency.unwrap_or(0))
                .await?
        }
    };
    report_session(
        client,
        path,
        args.no_wait,
        Duration::from_secs(args.timeout),
        json,
    )
    .await
}

async fn p2p_session(client: &Client, command: P2pSession, json: bool) -> CliResult<()> {
    match command {
        P2pSession::List => {
            let mut rows = Vec::new();
            for session in client.sessions().await? {
                rows.push(session_json(&session).await?);
            }
            print(json, &Value::Array(rows.clone()), || {
                let table: Vec<Vec<String>> = rows
                    .iter()
                    .map(|row| {
                        vec![
                            row["id"].as_str().unwrap_or("").to_owned(),
                            row["device"].as_str().unwrap_or("").to_owned(),
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
                    &[
                        "ID", "DEVICE", "STATE", "ROLE", "PEER", "GROUP IF", "PEER IP",
                    ],
                    &table,
                    Some("No active P2P sessions."),
                );
            });
            Ok(())
        }
        P2pSession::Show { session } => {
            let path = session_ref(&session)?;
            let proxy = client.session(path).await?;
            let value = session_json(&proxy).await?;
            print(json, &value, || print_session(&value));
            Ok(())
        }
        P2pSession::Close { session } => {
            let path = session_ref(&session)?;
            let id = session_id_from_path(path.as_str()).to_owned();
            client.session(path.clone()).await?.close().await?;
            print(
                json,
                &json!({"id": id, "path": path.as_str(), "closed": true}),
                || println!("closed session {id}"),
            );
            Ok(())
        }
    }
}

async fn report_session(
    client: &Client,
    path: OwnedObjectPath,
    no_wait: bool,
    timeout: Duration,
    json: bool,
) -> CliResult<()> {
    let id = session_id_from_path(path.as_str()).to_owned();
    if no_wait {
        print(
            json,
            &json!({"id": id, "path": path.as_str(), "state": "starting"}),
            || println!("{id}"),
        );
        return Ok(());
    }
    let session = client.session(path).await?;
    let value = wait_session(client, &session, timeout).await?;
    if value["state"].as_str() == Some("closed") {
        let failure_code = value["failure"].as_str().unwrap_or("");
        let detail = value["failure_detail"].as_str().unwrap_or("");
        if failure_code.is_empty() {
            return Err(CliError::runtime(
                "P2P session closed before becoming ready",
            ));
        }
        let suffix = if detail.is_empty() {
            String::new()
        } else {
            format!(" ({detail})")
        };
        return Err(CliError::runtime(format!(
            "P2P session failed: {failure_code}{suffix}"
        )));
    }
    print(json, &value, || print_session(&value));
    Ok(())
}

fn print_session(value: &Value) {
    println!("Session: {}", value["id"].as_str().unwrap_or(""));
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

async fn p2p_group(client: &Client, command: P2pGroup, json: bool) -> CliResult<()> {
    match command {
        P2pGroup::List => {
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
                    Some("No saved persistent P2P groups."),
                );
            });
        }
        P2pGroup::Show { group } => {
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
        P2pGroup::Delete { group, yes } => {
            let path = resolve_p2p_group(client, &group).await?;
            let proxy = client.p2p_group(path).await?;
            let value = p2p_group_json(&proxy).await?;
            let name = value["name"].as_str().unwrap_or("").to_owned();
            if !confirm_delete(&format!("Delete persistent group {name:?}? [y/N] "), yes)? {
                print(
                    json,
                    &json!({"name": name, "deleted": false, "cancelled": true}),
                    || eprintln!("cancelled"),
                );
                return Ok(());
            }
            proxy.delete().await?;
            print(json, &json!({"name": name, "deleted": true}), || {
                println!("deleted persistent group {name:?}");
            });
        }
    }
    Ok(())
}

async fn p2p_group_json(group: &P2pGroupProxy<'_>) -> CliResult<Value> {
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

async fn session_json(session: &SessionProxy<'_>) -> CliResult<Value> {
    let path = session.inner().path().as_str();
    let device_path = session.device().await?;
    let device_name = kestrel_api::device_from_path(device_path.as_str())
        .map_or_else(|| device_path.as_str().to_owned(), |name| name.to_string());
    Ok(json!({
        "id": session_id_from_path(path),
        "path": path,
        "device": device_name,
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

async fn wait_session(
    client: &Client,
    session: &SessionProxy<'_>,
    timeout: Duration,
) -> CliResult<Value> {
    let mut changes = session.receive_state_changed().await;
    let deadline = tokio::time::Instant::now() + timeout;
    let fresh_snapshot = || async {
        let fresh = SessionProxy::builder(client.connection())
            .path(session.inner().path().to_owned())
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await?;
        session_json(&fresh).await
    };
    let closed_snapshot = || async {
        if let Ok(value) = fresh_snapshot().await {
            return Ok(value);
        }
        if let Ok(mut cached) = session_json(session).await {
            cached["state"] = json!("closed");
            return Ok(cached);
        }
        Err(CliError::runtime(
            "P2P session closed before becoming ready",
        ))
    };
    loop {
        let Ok(state) = session.state().await else {
            return closed_snapshot().await;
        };
        if state == "ready" {
            return fresh_snapshot().await;
        }
        if state == "closed" {
            return closed_snapshot().await;
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Err(CliError::Interrupted),
            () = tokio::time::sleep_until(deadline) => {
                return Err(CliError::timeout("timed out waiting for P2P session"));
            }
            event = changes.next() => {
                if event.is_none() {
                    return closed_snapshot().await;
                }
            }
        }
    }
}

pub(crate) fn session_id_from_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub(crate) fn session_ref(value: &str) -> CliResult<OwnedObjectPath> {
    let path = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{}/Session/{value}", kestrel_api::ROOT_PATH)
    } else {
        value.to_owned()
    };
    OwnedObjectPath::try_from(path).map_err(|error| CliError::runtime(error.to_string()))
}

pub(crate) fn parse_wfd_hex(raw: &str) -> CliResult<Vec<u8>> {
    let hex: String = raw
        .trim()
        .chars()
        .filter(|ch| !matches!(ch, ':' | ' ' | '-' | '\t'))
        .collect();
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return Err(CliError::runtime(
            "WFD subelements must be a non-empty, even-length hex string (use `kestrel p2p wfd clear` to disable)",
        ));
    }
    let (chunks, _) = hex.as_bytes().as_chunks::<2>();
    let mut bytes = Vec::with_capacity(chunks.len());
    for pair in chunks {
        let s = std::str::from_utf8(pair)
            .map_err(|_| CliError::runtime("invalid hex in WFD subelements"))?;
        let byte = u8::from_str_radix(s, 16)
            .map_err(|_| CliError::runtime(format!("invalid hex byte {s:?} in WFD subelements")))?;
        bytes.push(byte);
    }
    if bytes.len() > MAX_WFD_SUBELEMENTS_BYTES {
        return Err(CliError::runtime(format!(
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

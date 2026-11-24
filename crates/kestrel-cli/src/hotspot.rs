// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel hotspot`: SoftAP / hotspot commands.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use futures_util::StreamExt;
use kestrel_api::HotspotSettings;
use kestrel_api::client::{Client, HotspotProxy};
use serde_json::{Value, json};
use zbus::{OwnedVariant, Variant};

use crate::common::{
    CliError, CliResult, DeviceOpt, addresses_text, json_str_or_dash, json_string_list, print,
    print_table, prompt_secret, resolve_device, stdin_secret,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum HotspotSecurityMode {
    Open,
    WpaPersonal,
    Wpa3Personal,
}

impl HotspotSecurityMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::WpaPersonal => "wpa-personal",
            Self::Wpa3Personal => "wpa3-personal",
        }
    }

    pub(crate) const fn needs_secret(self) -> bool {
        !matches!(self, Self::Open)
    }
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct StartArgs {
    /// Hotspot SSID (1-32 UTF-8 bytes).
    pub(crate) ssid: String,
    #[command(flatten)]
    pub(crate) device: DeviceOpt,
    /// Security mode.
    #[arg(long, value_enum, default_value_t = HotspotSecurityMode::WpaPersonal)]
    pub(crate) security: HotspotSecurityMode,
    /// Operating channel in MHz; omit to let the backend choose.
    #[arg(short = 'f', long)]
    pub(crate) frequency: Option<u32>,
    /// Do not broadcast the SSID.
    #[arg(long)]
    pub(crate) hidden: bool,
    /// Prompt for the passphrase on the terminal.
    #[arg(long, conflicts_with = "secret_stdin")]
    pub(crate) ask_secret: bool,
    /// Read the passphrase from the first line of standard input.
    #[arg(long)]
    pub(crate) secret_stdin: bool,
    /// Return immediately after the request is accepted.
    #[arg(long)]
    pub(crate) no_wait: bool,
    /// Seconds to wait for the hotspot to become active.
    #[arg(short = 't', long, default_value_t = 30)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Hotspot {
    /// Show hotspot status (all AP-capable devices, or one device with `-d`).
    Status {
        #[command(flatten)]
        device: DeviceOpt,
    },
    /// Start a SoftAP hotspot.
    Start(StartArgs),
    /// Stop the hotspot and restore station orchestration.
    Stop {
        #[command(flatten)]
        device: DeviceOpt,
        /// Return immediately after the request is accepted.
        #[arg(long)]
        no_wait: bool,
        /// Seconds to wait for the hotspot to stop.
        #[arg(short = 't', long, default_value_t = 15)]
        timeout: u64,
    },
}

pub(crate) async fn run(client: &Client, command: Hotspot, json: bool) -> CliResult<()> {
    match command {
        Hotspot::Status { device } => status(client, device.device.as_deref(), json).await,
        Hotspot::Start(args) => start(client, &args, json).await,
        Hotspot::Stop {
            device,
            no_wait,
            timeout,
        } => stop(client, device.device.as_deref(), no_wait, timeout, json).await,
    }
}

async fn start(client: &Client, args: &StartArgs, json: bool) -> CliResult<()> {
    let (iface, _) =
        resolve_device(client, args.device.device.as_deref(), Some("access-point")).await?;
    let proxy = client.hotspot(&iface).await?;
    let mut settings: HotspotSettings = HashMap::new();
    let mut put = |key: &str, value: Variant<'_>| {
        settings.insert(
            key.to_owned(),
            OwnedVariant::try_from(value).expect("plain value"),
        );
    };
    put("ssid", Variant::from(args.ssid.as_str()));
    put("security", Variant::from(args.security.as_str()));
    if let Some(frequency) = args.frequency {
        put("frequency", Variant::from(frequency));
    }
    if args.hidden {
        put("hidden", Variant::from(true));
    }
    let secret = if args.secret_stdin {
        Some(stdin_secret()?)
    } else if args.ask_secret {
        Some(prompt_secret()?)
    } else if args.security.needs_secret() {
        if std::io::stdin().is_terminal() {
            Some(prompt_secret()?)
        } else {
            return Err(CliError::runtime(
                "this hotspot needs a passphrase; use --secret-stdin in a script",
            ));
        }
    } else {
        None
    };

    // Subscribe before issuing `start()` so fast transitions and failures are never missed.
    let previous_failure = proxy.failure().await.unwrap_or_default();
    let state_changes = proxy.receive_state_changed().await;
    let failure_changes = proxy.receive_failure_changed().await;

    proxy
        .start(settings, secret.as_deref().map_or("", String::as_str))
        .await?;

    if args.no_wait {
        print(
            json,
            &json!({"device": iface, "ssid": args.ssid, "state": "starting"}),
            || println!("{iface}: starting hotspot {:?}", args.ssid),
        );
        return Ok(());
    }

    wait_hotspot_active(
        &proxy,
        &previous_failure,
        state_changes,
        failure_changes,
        Duration::from_secs(args.timeout),
    )
    .await?;

    // Read a fresh uncached snapshot so properties updated alongside `state`
    // (such as `gateway` and `frequency`) are never served from a pre-start cache.
    let fresh = HotspotProxy::builder(client.connection())
        .path(proxy.inner().path().to_owned())
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    let value = hotspot_json(&fresh).await?;
    print(json, &value, || {
        let freq = match value["frequency"].as_u64().unwrap_or(0) {
            0 => "-".to_owned(),
            mhz => format!("{mhz} MHz"),
        };
        println!(
            "{iface}: hotspot active  SSID {:?}  gateway {}  {freq}",
            args.ssid,
            json_str_or_dash(&value, "gateway"),
        );
    });
    Ok(())
}

async fn stop(
    client: &Client,
    device: Option<&str>,
    no_wait: bool,
    timeout: u64,
    json: bool,
) -> CliResult<()> {
    let (iface, _) = resolve_device(client, device, Some("access-point")).await?;
    let proxy = client.hotspot(&iface).await?;
    let mut state_changes = proxy.receive_state_changed().await;
    proxy.stop().await?;
    if !no_wait {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout);
        loop {
            if proxy.state().await? == "stopped" {
                break;
            }
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Err(CliError::Interrupted),
                () = tokio::time::sleep_until(deadline) => {
                    return Err(CliError::timeout("timed out waiting for hotspot to stop"));
                }
                event = state_changes.next() => {
                    if event.is_none() {
                        break;
                    }
                }
            }
        }
    }
    print(json, &json!({"device": iface, "state": "stopped"}), || {
        println!("{iface}: hotspot stopped");
    });
    Ok(())
}

async fn wait_hotspot_active(
    proxy: &HotspotProxy<'_>,
    previous_failure: &str,
    mut state_changes: zbus::proxy::PropertyStream<'_, String>,
    mut failure_changes: zbus::proxy::PropertyStream<'_, String>,
    timeout: Duration,
) -> CliResult<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut saw_attempt = false;
    loop {
        let state = proxy.state().await?;
        if matches!(state.as_str(), "starting" | "active") {
            saw_attempt = true;
        }
        match state.as_str() {
            "active" => return Ok(()),
            "stopped" => {
                let failure = proxy.failure().await?;
                if !failure.is_empty() && (saw_attempt || failure != previous_failure) {
                    let detail = proxy.failure_detail().await.unwrap_or_default();
                    let suffix = if detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({detail})")
                    };
                    return Err(CliError::runtime(format!(
                        "hotspot failed: {failure}{suffix}"
                    )));
                }
            }
            _ => {}
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Err(CliError::Interrupted),
            () = tokio::time::sleep_until(deadline) => {
                let failure = proxy.failure().await.unwrap_or_default();
                let suffix = if failure.is_empty() {
                    String::new()
                } else {
                    format!(" ({failure})")
                };
                return Err(CliError::timeout(format!(
                    "timed out waiting for hotspot to start{suffix}"
                )));
            }
            event = state_changes.next() => {
                let Some(change) = event else {
                    return Err(CliError::runtime("hotspot disappeared while waiting"));
                };
                if let Ok(state) = change.get().await
                    && matches!(state.as_str(), "starting" | "active")
                {
                    saw_attempt = true;
                }
            }
            event = failure_changes.next() => {
                if event.is_none() {
                    return Err(CliError::runtime("hotspot disappeared while waiting"));
                }
                saw_attempt = true;
            }
        }
    }
}

async fn status(client: &Client, device: Option<&str>, json: bool) -> CliResult<()> {
    if let Some(name) = device {
        let proxy = client.hotspot(name).await?;
        let value = hotspot_json(&proxy).await?;
        print(json, &value, || print_hotspot_detail(&value));
        return Ok(());
    }

    let mut proxies = Vec::new();
    for device in client.devices().await? {
        if device
            .capabilities()
            .await?
            .iter()
            .any(|cap| cap == "access-point")
        {
            proxies.push(client.hotspot(&device.interface().await?).await?);
        }
    }
    let mut rows = Vec::new();
    for proxy in &proxies {
        rows.push(hotspot_json(proxy).await?);
    }
    print(json, &Value::Array(rows.clone()), || {
        let table: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                let clients = json_string_list(row, "connected_clients");
                vec![
                    row["device"].as_str().unwrap_or("").to_owned(),
                    row["state"].as_str().unwrap_or("").to_owned(),
                    json_str_or_dash(row, "ssid").to_owned(),
                    json_str_or_dash(row, "security").to_owned(),
                    match row["frequency"].as_u64().unwrap_or(0) {
                        0 => "-".to_owned(),
                        frequency => format!("{frequency} MHz"),
                    },
                    json_str_or_dash(row, "gateway").to_owned(),
                    addresses_text(&clients),
                    row["failure"].as_str().unwrap_or("").to_owned(),
                ]
            })
            .collect();
        print_table(
            &[
                "DEVICE",
                "STATE",
                "SSID",
                "SECURITY",
                "FREQUENCY",
                "GATEWAY",
                "CLIENTS",
                "FAILURE",
            ],
            &table,
            Some("No AP-capable wireless devices found."),
        );
    });
    Ok(())
}

fn print_hotspot_detail(value: &Value) {
    println!("Device: {}", value["device"].as_str().unwrap_or(""));
    println!("State: {}", value["state"].as_str().unwrap_or(""));
    println!("SSID: {}", json_str_or_dash(value, "ssid"));
    println!("Security: {}", json_str_or_dash(value, "security"));
    let freq = match value["frequency"].as_u64().unwrap_or(0) {
        0 => "-".to_owned(),
        mhz => format!("{mhz} MHz"),
    };
    println!("Frequency: {freq}");
    println!("Gateway: {}", json_str_or_dash(value, "gateway"));
    let clients = json_string_list(value, "connected_clients");
    println!("Connected clients: {}", addresses_text(&clients));
    if let Some(leases) = value["leases"].as_array()
        && !leases.is_empty()
    {
        let formatted: Vec<String> = leases
            .iter()
            .map(|lease| {
                format!(
                    "{} ({})",
                    lease["address"].as_str().unwrap_or(""),
                    lease["client"].as_str().unwrap_or(""),
                )
            })
            .collect();
        println!("Leases: {}", formatted.join(", "));
    }
    let failure = value["failure"].as_str().unwrap_or("");
    if !failure.is_empty() {
        let detail = value["failure_detail"].as_str().unwrap_or("");
        if detail.is_empty() {
            println!("Failure: {failure}");
        } else {
            println!("Failure: {failure} ({detail})");
        }
    }
}

async fn hotspot_json(hotspot: &HotspotProxy<'_>) -> CliResult<Value> {
    let leases: Vec<Value> = hotspot
        .leases()
        .await?
        .iter()
        .map(|(address, client)| json!({"address": address, "client": client}))
        .collect();
    Ok(json!({
        "device": kestrel_api::device_from_path(hotspot.inner().path().as_str())
            .map_or_else(String::new, |name| name.to_string()),
        "state": hotspot.state().await?,
        "ssid": hotspot.ssid().await?,
        "security": hotspot.security().await?,
        "frequency": hotspot.frequency().await?,
        "gateway": hotspot.gateway().await?,
        "leases": leases,
        "connected_clients": hotspot.connected_clients().await?,
        "failure": hotspot.failure().await?,
        "failure_detail": hotspot.failure_detail().await?,
    }))
}

// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel hotspot`: SoftAP / hotspot commands.

use std::collections::HashMap;
use std::io::IsTerminal;

use clap::{Args, Subcommand};
use kestrel_api::HotspotSettings;
use kestrel_api::client::{Client, HotspotProxy};
use kestrel_model::HotspotSecurity;
use serde_json::{Value, json};
use zbus::{OwnedVariant, Variant};

use crate::common::{
    addresses_text, failure, json_str_or_dash, json_string_list, print, print_table, prompt_secret,
    stdin_secret,
};

#[derive(Debug, Args)]
pub(crate) struct StartArgs {
    pub(crate) device: String,
    #[arg(long)]
    pub(crate) ssid: String,
    /// `open`, `wpa-personal`, or `wpa3-personal`.
    #[arg(long, default_value = "wpa-personal")]
    pub(crate) security: String,
    /// Operating channel in MHz; omit to let the backend choose.
    #[arg(long)]
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
}

#[derive(Debug, Subcommand)]
pub(crate) enum Hotspot {
    /// Start a hotspot on a device.
    Start(StartArgs),
    /// Stop the hotspot on a device.
    Stop { device: String },
    /// Show hotspot status for one device (or every AP-capable device).
    Status { device: Option<String> },
}

pub(crate) async fn run(client: &Client, command: Hotspot, json: bool) -> zbus::Result<()> {
    match command {
        Hotspot::Start(args) => start(client, &args, json).await,
        Hotspot::Stop { device } => {
            client.hotspot(&device).await?.stop().await?;
            print(json, &json!({"device": device, "state": "stopped"}), || {
                println!("{device}: hotspot stopped");
            });
            Ok(())
        }
        Hotspot::Status { device } => status(client, device.as_deref(), json).await,
    }
}

async fn start(client: &Client, args: &StartArgs, json: bool) -> zbus::Result<()> {
    let parsed_security =
        HotspotSecurity::parse(&args.security).map_err(|error| failure(error.to_string()))?;
    let proxy = client.hotspot(&args.device).await?;
    let mut settings: HotspotSettings = HashMap::new();
    let mut put = |key: &str, value: Variant<'_>| {
        settings.insert(
            key.to_owned(),
            OwnedVariant::try_from(value).expect("plain value"),
        );
    };
    put("ssid", Variant::from(args.ssid.as_str()));
    put("security", Variant::from(parsed_security.as_str()));
    if let Some(frequency) = args.frequency {
        put("frequency", Variant::from(frequency));
    }
    if args.hidden {
        put("hidden", Variant::from(true));
    }
    let needs_secret = parsed_security != HotspotSecurity::Open;
    let secret = if args.secret_stdin {
        Some(stdin_secret()?)
    } else if args.ask_secret {
        Some(prompt_secret()?)
    } else if needs_secret {
        if std::io::stdin().is_terminal() {
            Some(prompt_secret()?)
        } else {
            return Err(failure(
                "this hotspot needs a passphrase; use --secret-stdin in a script",
            ));
        }
    } else {
        None
    };
    proxy
        .start(settings, secret.as_deref().map_or("", String::as_str))
        .await?;
    print(
        json,
        &json!({"device": args.device, "ssid": args.ssid, "state": "starting"}),
        || println!("{}: starting hotspot {:?}", args.device, args.ssid),
    );
    Ok(())
}

async fn status(client: &Client, device: Option<&str>, json: bool) -> zbus::Result<()> {
    let proxies = if let Some(name) = device {
        vec![client.hotspot(name).await?]
    } else {
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
        proxies
    };
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
        );
    });
    Ok(())
}

async fn hotspot_json(hotspot: &HotspotProxy<'_>) -> zbus::Result<Value> {
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

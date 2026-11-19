// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel status` and `kestrel wifi`: station status, scanning, and connections.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use futures_util::StreamExt;
use kestrel_api::ProfileSettings;
use kestrel_api::client::{Client, DeviceProxy, ProfileProxy, ScanResult};
use kestrel_model::ProfileSecurity;
use serde_json::{Value, json};
use zbus::{OwnedObjectPath, OwnedVariant, Variant};
use zeroize::Zeroizing;

use crate::common::{
    addresses_text, dash_if_empty, device_json, failure, format_age, json_str_or_dash,
    json_string_list, link_has_l3, print, print_device_summary, print_table, profile_security,
    profiles_by_ssid, prompt_secret, resolve_profile, secret_bundle, setting_string, signal_text,
    stdin_secret,
};
use crate::profile::forget;

#[derive(Debug, Subcommand)]
pub(crate) enum Wifi {
    /// Detailed state of one device (or the first wireless device).
    Status { device: Option<String> },
    /// Scan and print the results.
    Scan {
        device: String,
        /// Show every BSS instead of the strongest BSS per SSID.
        #[arg(long)]
        all: bool,
    },
    /// Print the latest scan results without scanning.
    List {
        device: String,
        /// Show every BSS instead of the strongest BSS per SSID.
        #[arg(long)]
        all: bool,
    },
    /// Join a network, creating or updating its profile.
    Join(JoinArgs),
    /// Connect to an existing saved profile.
    Connect(ConnectArgs),
    /// Disconnect and hold autoconnect until explicitly resumed.
    Disconnect { device: String },
    /// Forget a saved network.
    Forget {
        profile: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Enable or disable autoconnect without changing the current link.
    Autoconnect {
        device: String,
        #[arg(value_enum)]
        state: OnOff,
    },
    /// Turn wireless on.
    On,
    /// Turn wireless off.
    Off,
    /// Show recent connection events, newest first.
    History {
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum OnOff {
    On,
    Off,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct JoinArgs {
    pub(crate) device: String,
    pub(crate) ssid: String,
    /// `open`, `owe`, `wpa-personal`, or `wpa3-personal`. Inferred from the
    /// scan when omitted.
    #[arg(long)]
    pub(crate) security: Option<String>,
    #[arg(long)]
    pub(crate) name: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) priority: Option<i32>,
    /// The network is hidden; requires `--security`.
    #[arg(long)]
    pub(crate) hidden: bool,
    /// Prompt for the passphrase even if the profile already has one.
    #[arg(long, conflicts_with = "secret_stdin")]
    pub(crate) ask_secret: bool,
    /// Read the passphrase from the first line of standard input.
    #[arg(long)]
    pub(crate) secret_stdin: bool,
    /// Return as soon as the request is accepted.
    #[arg(long)]
    pub(crate) no_wait: bool,
    /// Seconds to wait for `connected`.
    #[arg(long, default_value_t = 30)]
    pub(crate) timeout: u64,
}

#[derive(Debug, Args)]
pub(crate) struct ConnectArgs {
    pub(crate) device: String,
    /// Profile id, name, or SSID.
    pub(crate) profile: String,
    /// Prompt for a passphrase and store it if the profile has none.
    #[arg(long, conflicts_with = "secret_stdin")]
    pub(crate) ask_secret: bool,
    /// Read a passphrase from the first line of standard input.
    #[arg(long)]
    pub(crate) secret_stdin: bool,
    /// Return as soon as the request is accepted.
    #[arg(long)]
    pub(crate) no_wait: bool,
    /// Seconds to wait for `connected`.
    #[arg(long, default_value_t = 30)]
    pub(crate) timeout: u64,
}

pub(crate) async fn status(client: &Client, json: bool, watch: bool) -> zbus::Result<()> {
    if json && watch {
        return Err(failure("--watch cannot be combined with --json"));
    }
    loop {
        let value = status_value(client).await?;
        if watch && std::io::stdout().is_terminal() {
            print!("\x1b[2J\x1b[H");
            let _ = std::io::stdout().flush();
        }
        print(json, &value, || print_status_overview(&value));
        if !watch {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn status_value(client: &Client) -> zbus::Result<Value> {
    let manager = client.manager().await?;
    let wireless = manager.wireless_enabled().await?;
    let hardware = manager.wireless_hardware_enabled().await?;
    let online = manager.online_state().await?;
    let mut devices = Vec::new();
    for device in client.devices().await? {
        devices.push(device_json(&device).await?);
    }
    Ok(json!({
        "wireless_enabled": wireless,
        "wireless_hardware_enabled": hardware,
        "online_state": online,
        "devices": devices,
    }))
}

fn print_status_overview(value: &Value) {
    let sw = if value["wireless_enabled"].as_bool() == Some(true) {
        "on"
    } else {
        "off"
    };
    let hw_note = if value["wireless_hardware_enabled"].as_bool() == Some(false) {
        " (rfkill: hard-blocked)"
    } else {
        ""
    };
    let online = value["online_state"].as_str().unwrap_or("offline");
    println!("wireless: {sw}{hw_note}  online: {online}");
    let mut rows = Vec::new();
    for device in value["devices"].as_array().into_iter().flatten() {
        let state = device["state"].as_str().unwrap_or("");
        let addresses = if link_has_l3(state) {
            json_string_list(device, "addresses")
        } else {
            Vec::new()
        };
        rows.push(vec![
            device["interface"].as_str().unwrap_or("").to_owned(),
            state.to_owned(),
            json_str_or_dash(device, "ssid").to_owned(),
            addresses_text(&addresses),
            signal_text(i16::try_from(device["signal"].as_i64().unwrap_or(0)).unwrap_or(0)),
            device["last_failure"].as_str().unwrap_or("").to_owned(),
        ]);
    }
    print_table(
        &["IFACE", "STATE", "SSID", "ADDRESSES", "SIGNAL", "FAILURE"],
        &rows,
    );
}

pub(crate) async fn run(client: &Client, command: Wifi, json: bool) -> zbus::Result<()> {
    match command {
        Wifi::Status { device } => wifi_status(client, device.as_deref(), json).await,
        Wifi::Scan { device, all } => {
            let device = client.device(&device).await?;
            let results = scan_and_get(&device, Duration::from_secs(20)).await?;
            print_scan(json, &results, all);
            Ok(())
        }
        Wifi::List { device, all } => {
            let results = client.device(&device).await?.get_scan_results().await?;
            print_scan(json, &results, all);
            Ok(())
        }
        Wifi::Join(args) => wifi_join(client, args, json).await,
        Wifi::Connect(args) => wifi_connect(client, args, json).await,
        Wifi::Disconnect { device } => {
            client.device(&device).await?.disconnect().await?;
            print(
                json,
                &json!({"device": device, "state": "disconnected"}),
                || {
                    println!(
                        "{device}: disconnected; autoconnect is held until `kestrel wifi autoconnect {device} on`"
                    );
                },
            );
            Ok(())
        }
        Wifi::Forget { profile, yes } => forget(client, &profile, yes, json).await,
        Wifi::Autoconnect { device, state } => {
            let enabled = matches!(state, OnOff::On);
            let proxy = client.device(&device).await?;
            proxy.set_autoconnect(enabled).await?;
            wait_autoconnect(&proxy, enabled).await?;
            print(
                json,
                &json!({"device": device, "autoconnect": enabled}),
                || {
                    println!(
                        "{device}: autoconnect {}",
                        if enabled { "on" } else { "off" }
                    );
                },
            );
            Ok(())
        }
        Wifi::On => {
            client.manager().await?.set_wireless_enabled(true).await?;
            print(json, &json!({"wireless_enabled": true}), || {
                println!("wireless: on");
            });
            Ok(())
        }
        Wifi::Off => {
            client.manager().await?.set_wireless_enabled(false).await?;
            print(json, &json!({"wireless_enabled": false}), || {
                println!("wireless: off");
            });
            Ok(())
        }
        Wifi::History { limit } => wifi_history(client, limit, json).await,
    }
}

async fn wifi_status(client: &Client, device: Option<&str>, json: bool) -> zbus::Result<()> {
    let device = if let Some(name) = device {
        client.device(name).await?
    } else {
        client
            .devices()
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| failure("no wireless devices"))?
    };
    let value = device_json(&device).await?;
    print(json, &value, || print_wifi_status(&value));
    Ok(())
}

fn print_wifi_status(value: &Value) {
    let state = value["state"].as_str().unwrap_or("");
    let active = link_has_l3(state);
    let supported = json_string_list(value, "supported_security");
    let addresses = if active {
        json_string_list(value, "addresses")
    } else {
        Vec::new()
    };
    let gateways = if active {
        json_string_list(value, "gateways")
    } else {
        Vec::new()
    };
    let dns = if active {
        json_string_list(value, "dns")
    } else {
        Vec::new()
    };
    println!("Interface: {}", value["interface"].as_str().unwrap_or(""));
    println!("State: {state}");
    if value["scanning"].as_bool() == Some(true) {
        println!("Scanning: yes");
    }
    println!("SSID: {}", json_str_or_dash(value, "ssid"));
    println!("BSSID: {}", json_str_or_dash(value, "bssid"));
    println!("Security: {}", json_str_or_dash(value, "security"));
    let frequency = value["frequency"].as_u64().unwrap_or(0);
    println!(
        "Frequency: {}",
        if frequency == 0 {
            "-".to_owned()
        } else {
            format!("{frequency} MHz")
        }
    );
    println!(
        "Signal: {}",
        signal_text(i16::try_from(value["signal"].as_i64().unwrap_or(0)).unwrap_or(0))
    );
    println!("Supported security: {}", addresses_text(&supported));
    println!("Addresses: {}", addresses_text(&addresses));
    println!("Gateways: {}", addresses_text(&gateways));
    println!("DNS: {}", addresses_text(&dns));
    println!(
        "L3: {}",
        if active {
            value["l3_phase"].as_str().unwrap_or("pending")
        } else {
            "pending"
        }
    );
    println!(
        "Online: {}",
        if active {
            value["online_state"].as_str().unwrap_or("offline")
        } else {
            "offline"
        }
    );
    println!(
        "Autoconnect: {}",
        if value["autoconnect_enabled"].as_bool() == Some(true) {
            "on"
        } else {
            "off"
        }
    );
    let profile = value["profile"].as_str().unwrap_or("/");
    println!("Profile: {}", if profile == "/" { "-" } else { profile });
    let needing = json_string_list(value, "profiles_needing_secrets");
    if !needing.is_empty() {
        println!("Profiles needing secrets: {}", needing.join(", "));
    }
    let last_failure = value["last_failure"].as_str().unwrap_or("");
    if !last_failure.is_empty() {
        println!("Last failure: {last_failure}");
    }
}

async fn wifi_join(client: &Client, args: JoinArgs, json: bool) -> zbus::Result<()> {
    let device = client.device(&args.device).await?;
    let security = match args.security.as_deref() {
        Some(security) => {
            ProfileSecurity::parse(security).map_err(|error| failure(error.to_string()))?
        }
        None if args.hidden => {
            return Err(failure(
                "a hidden network needs --security open|owe|wpa-personal|wpa3-personal",
            ));
        }
        None => infer_security(&device, &args.ssid, Duration::from_secs(args.timeout)).await?,
    };
    if security.is_enterprise() {
        return Err(failure(
            "enterprise networks require `kestrel profile add` with --eap and --identity",
        ));
    }

    let existing = profiles_by_ssid(client, &args.ssid).await?;
    if existing.len() > 1 {
        return Err(failure(format!(
            "{:?} matches several profiles; use `kestrel profile list` and delete the duplicates",
            args.ssid
        )));
    }
    let existing = existing.into_iter().next();
    let (unmanaged, existing_security) = if let Some(profile) = &existing {
        let existing_settings = profile.settings().await?;
        (
            setting_string(&existing_settings, "l3") == "unmanaged",
            Some(setting_string(&existing_settings, "security")),
        )
    } else {
        (false, None)
    };
    let secret = join_secret(&args, security, existing.as_ref()).await?;
    let settings = join_settings(&args, security);
    let path = if let Some(profile) = &existing {
        let needs_update = secret.is_some()
            || args.name.is_some()
            || args.priority.is_some()
            || args.hidden
            || existing_security.as_deref() != Some(security.as_str());
        if needs_update {
            let action = if secret.is_some() { "set" } else { "keep" };
            profile
                .update(
                    settings,
                    action,
                    secret_bundle(secret.as_deref().map(String::as_str)),
                )
                .await?;
        }
        profile.inner().path().to_owned().into()
    } else {
        client
            .manager()
            .await?
            .add_profile(
                settings,
                secret_bundle(secret.as_deref().map(String::as_str)),
            )
            .await?
    };

    connect_and_wait(
        &device,
        &path,
        &args.device,
        Some(&args.ssid),
        args.no_wait,
        unmanaged,
        Duration::from_secs(args.timeout),
        json,
    )
    .await
}

async fn wifi_connect(client: &Client, args: ConnectArgs, json: bool) -> zbus::Result<()> {
    let path = resolve_profile(client, &args.profile).await?;
    let profile = client.profile(path.clone()).await?;
    let settings = profile.settings().await?;
    let security = profile_security(&settings)?;
    let unmanaged = setting_string(&settings, "l3") == "unmanaged";
    let is_eap_tls = setting_string(&settings, "enterprise.eap") == "tls";
    if args.secret_stdin || args.ask_secret {
        let secret = if args.secret_stdin {
            stdin_secret()?
        } else {
            prompt_secret()?
        };
        profile
            .update(HashMap::new(), "set", secret_bundle(Some(secret.as_str())))
            .await?;
    } else if security.needs_secret() && !profile.has_secret().await? {
        if is_eap_tls {
            return Err(failure(
                "this EAP-TLS profile has no private key; run `kestrel profile edit --private-key-file <path>`",
            ));
        }
        let secret = if std::io::stdin().is_terminal() {
            prompt_secret()?
        } else {
            return Err(failure(
                "the profile has no passphrase; use --secret-stdin in a script",
            ));
        };
        profile
            .update(HashMap::new(), "set", secret_bundle(Some(secret.as_str())))
            .await?;
    }

    let device = client.device(&args.device).await?;
    connect_and_wait(
        &device,
        &path,
        &args.device,
        None,
        args.no_wait,
        unmanaged,
        Duration::from_secs(args.timeout),
        json,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn connect_and_wait(
    device: &DeviceProxy<'_>,
    path: &OwnedObjectPath,
    device_name: &str,
    ssid: Option<&str>,
    no_wait: bool,
    unmanaged: bool,
    timeout: Duration,
    json: bool,
) -> zbus::Result<()> {
    // Subscribe BEFORE issuing `connect()` so fast transitions and failures
    // are never missed and stale pre-existing failures are ignored.
    let previous_failure = device.last_failure().await.unwrap_or_default();
    let state_changes = device.receive_state_changed().await;
    let failure_changes = device.receive_last_failure_changed().await;
    device.connect(&path.as_ref()).await?;
    if no_wait {
        let payload = if let Some(ssid) = ssid {
            json!({
                "device": device_name,
                "ssid": ssid,
                "profile": path.as_str(),
                "state": "requested",
            })
        } else {
            json!({
                "device": device_name,
                "profile": path.as_str(),
                "state": "requested",
            })
        };
        print(json, &payload, || {
            if let Some(ssid) = ssid {
                println!(
                    "{device_name}: joining {ssid:?} (profile {})",
                    path.as_str()
                );
            } else {
                println!("{device_name}: connecting (profile {})", path.as_str());
            }
        });
        return Ok(());
    }
    wait_connected(
        device,
        path,
        &previous_failure,
        state_changes,
        failure_changes,
        timeout,
    )
    .await?;
    if !unmanaged {
        wait_l3_ready(device, Duration::from_secs(5)).await?;
    }
    print_device_summary(device, json).await
}

async fn scan_and_get(
    device: &DeviceProxy<'_>,
    timeout: Duration,
) -> zbus::Result<Vec<ScanResult>> {
    let mut results_changed = device.receive_scan_results_changed().await?;
    let mut scanning_changed = device.receive_scanning_changed().await;
    device.scan().await?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut saw_scanning = device.scanning().await.unwrap_or(false);
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                return Err(failure("scan timed out"));
            }
            signal = results_changed.next() => {
                match signal {
                    Some(_) => break,
                    None => return Err(failure("scan stream closed")),
                }
            }
            change = scanning_changed.next() => {
                let Some(change) = change else {
                    return Err(failure("scan stream closed"));
                };
                if let Ok(scanning) = change.get().await {
                    if scanning {
                        saw_scanning = true;
                    } else if saw_scanning {
                        // Scan finished cleanly even when the visible BSS list
                        // did not change (so `ScanResultsChanged` wasn't emitted).
                        break;
                    }
                }
            }
        }
    }
    device.get_scan_results().await
}

async fn infer_security(
    device: &DeviceProxy<'_>,
    ssid: &str,
    timeout: Duration,
) -> zbus::Result<ProfileSecurity> {
    let results = match scan_and_get(device, timeout).await {
        Ok(results) => results,
        Err(_) => device.get_scan_results().await?,
    };
    let mut best: Option<(i16, ProfileSecurity)> = None;
    for (found, _, _, signal, security, _) in &results {
        if found != ssid {
            continue;
        }
        if let Some(candidate) = ProfileSecurity::from_scan_security(security)
            && best.is_none_or(|(best_signal, _)| *signal > best_signal)
        {
            best = Some((*signal, candidate));
        }
    }
    best.map(|(_, security)| security).ok_or_else(|| {
        failure(format!(
            "{ssid:?} was not found; use --hidden --security <mode> for a hidden network"
        ))
    })
}

async fn join_secret(
    args: &JoinArgs,
    security: ProfileSecurity,
    existing: Option<&ProfileProxy<'_>>,
) -> zbus::Result<Option<Zeroizing<String>>> {
    if args.secret_stdin {
        return stdin_secret().map(Some);
    }
    if args.ask_secret {
        return prompt_secret().map(Some);
    }
    if !security.needs_secret() {
        return Ok(None);
    }
    if let Some(existing) = existing {
        let settings = existing.settings().await?;
        if setting_string(&settings, "security") == security.as_str()
            && existing.has_secret().await?
        {
            return Ok(None);
        }
    }
    if std::io::stdin().is_terminal() {
        prompt_secret().map(Some)
    } else {
        Err(failure(
            "this network needs a passphrase; use --secret-stdin in a script",
        ))
    }
}

fn join_settings(args: &JoinArgs, security: ProfileSecurity) -> ProfileSettings {
    let mut settings = HashMap::new();
    let mut put = |key: &str, value: Variant<'_>| {
        settings.insert(
            key.to_owned(),
            OwnedVariant::try_from(value).expect("plain value"),
        );
    };
    put("ssid", Variant::from(args.ssid.as_str()));
    put("security", Variant::from(security.as_str()));
    if let Some(name) = &args.name {
        put("name", Variant::from(name.as_str()));
    }
    if let Some(priority) = args.priority {
        put("priority", Variant::from(priority));
    }
    if args.hidden {
        put("hidden", Variant::from(true));
    }
    settings
}

async fn wait_connected(
    device: &DeviceProxy<'_>,
    target_profile: &OwnedObjectPath,
    previous_failure: &str,
    mut state_changes: zbus::proxy::PropertyStream<'_, String>,
    mut failure_changes: zbus::proxy::PropertyStream<'_, String>,
    timeout: Duration,
) -> zbus::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut saw_attempt = false;
    loop {
        let state = device.state().await?;
        let active = device.active_profile().await?;
        if active == *target_profile
            && matches!(
                state.as_str(),
                "associating" | "configuring-l3" | "connected" | "reconnecting"
            )
        {
            saw_attempt = true;
        }
        match state.as_str() {
            "connected" if active == *target_profile => return Ok(()),
            "disabled" => return Err(failure("wireless is disabled")),
            "idle" | "waiting" => {
                let last_failure = device.last_failure().await?;
                if !last_failure.is_empty() && (saw_attempt || last_failure != previous_failure) {
                    return Err(failure(format!("connection failed: {last_failure}")));
                }
            }
            _ => {}
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {
                let last_failure = device.last_failure().await?;
                let detail = if last_failure.is_empty() {
                    String::new()
                } else {
                    format!(" ({last_failure})")
                };
                return Err(failure(format!("timed out waiting for a connection{detail}")));
            }
            event = state_changes.next() => {
                let Some(change) = event else {
                    return Err(failure("device disappeared while waiting"));
                };
                if let Ok(state) = change.get().await
                    && matches!(
                        state.as_str(),
                        "associating" | "configuring-l3" | "connected" | "reconnecting"
                    )
                {
                    saw_attempt = true;
                }
            }
            event = failure_changes.next() => {
                if event.is_none() {
                    return Err(failure("device disappeared while waiting"));
                }
                saw_attempt = true;
            }
        }
    }
}

async fn wait_autoconnect(device: &DeviceProxy<'_>, enabled: bool) -> zbus::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if device.autoconnect_enabled().await? == enabled {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(failure("timed out waiting for autoconnect state"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_l3_ready(device: &DeviceProxy<'_>, timeout: Duration) -> zbus::Result<()> {
    let mut phase_changes = device.receive_l3_phase_changed().await;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match device.l3_phase().await?.as_str() {
            "ready" => return Ok(()),
            "failed" => {
                let detail = device.last_failure_detail().await.unwrap_or_default();
                let suffix = if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                };
                return Err(failure(format!("L3 configuration failed{suffix}")));
            }
            _ => {}
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(()),
            event = phase_changes.next() => {
                if event.is_none() {
                    return Ok(());
                }
            }
        }
    }
}

async fn wifi_history(client: &Client, limit: u32, json: bool) -> zbus::Result<()> {
    let events = client.manager().await?.history(limit).await?;
    let value: Vec<Value> = events
        .iter()
        .map(|(at, device, ssid, profile, outcome, detail)| {
            json!({
                "at": at,
                "device": device,
                "ssid": ssid,
                "profile": profile,
                "outcome": outcome,
                "detail": detail,
            })
        })
        .collect();
    print(json, &Value::Array(value), || {
        let rows: Vec<Vec<String>> = events
            .iter()
            .map(|(at, device, ssid, _, outcome, detail)| {
                vec![
                    format_age(*at),
                    device.clone(),
                    dash_if_empty(ssid).to_owned(),
                    outcome.clone(),
                    detail.clone(),
                ]
            })
            .collect();
        print_table(&["WHEN", "DEVICE", "SSID", "OUTCOME", "DETAIL"], &rows);
    });
    Ok(())
}

#[derive(Debug)]
struct ScanRow {
    ssid: String,
    bssid: String,
    frequency: u32,
    signal: i16,
    security: String,
    profile: OwnedObjectPath,
}

fn scan_rows(results: &[ScanResult], all: bool) -> Vec<ScanRow> {
    let mut rows: Vec<ScanRow> = Vec::new();
    if all {
        for (ssid, bssid, frequency, signal, security, profile) in results {
            rows.push(ScanRow {
                ssid: ssid.clone(),
                bssid: bssid.clone(),
                frequency: *frequency,
                signal: *signal,
                security: security.clone(),
                profile: profile.clone(),
            });
        }
    } else {
        let mut best: HashMap<&str, &ScanResult> = HashMap::new();
        for result in results {
            best.entry(result.0.as_str())
                .and_modify(|current| {
                    if result.3 > current.3 {
                        *current = result;
                    }
                })
                .or_insert(result);
        }
        for (_, (ssid, bssid, frequency, signal, security, profile)) in best {
            rows.push(ScanRow {
                ssid: ssid.clone(),
                bssid: bssid.clone(),
                frequency: *frequency,
                signal: *signal,
                security: security.clone(),
                profile: profile.clone(),
            });
        }
    }
    rows.sort_by(|a, b| {
        b.signal
            .cmp(&a.signal)
            .then_with(|| a.ssid.cmp(&b.ssid))
            .then_with(|| a.bssid.cmp(&b.bssid))
    });
    rows
}

fn print_scan(json: bool, results: &[ScanResult], all: bool) {
    let rows = scan_rows(results, all);
    let value: Vec<Value> = rows
        .iter()
        .map(|row| {
            let known = row.profile.as_str() != "/";
            json!({
                "ssid": row.ssid,
                "bssid": row.bssid,
                "frequency": row.frequency,
                "signal": row.signal,
                "security": row.security,
                "known": known,
                "profile": row.profile.as_str(),
            })
        })
        .collect();
    print(json, &Value::Array(value), || {
        let table: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                vec![
                    if row.profile.as_str() == "/" {
                        String::new()
                    } else {
                        "*".to_owned()
                    },
                    row.ssid.clone(),
                    row.security.clone(),
                    format!("{} dBm", row.signal),
                    format!("{} MHz", row.frequency),
                    row.bssid.clone(),
                ]
            })
            .collect();
        print_table(
            &["", "SSID", "SECURITY", "SIGNAL", "FREQUENCY", "BSSID"],
            &table,
        );
    });
}

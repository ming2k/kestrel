// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel wifi`: station scanning, connection management, autoconnect, and history.

use std::collections::HashMap;
use std::io::IsTerminal;
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
    CliError, CliResult, DeviceOpt, OnOff, dash_if_empty, format_age, format_ambiguous_profiles,
    matching_profiles, print, print_device_summary, print_table, profile_security, prompt_secret,
    resolve_device, secret_bundle, setting_string, stdin_secret,
};
use crate::polkit;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PersonalSecurityMode {
    Open,
    Owe,
    WpaPersonal,
    Wpa3Personal,
}

impl PersonalSecurityMode {
    pub(crate) const fn to_profile_security(self) -> ProfileSecurity {
        match self {
            Self::Open => ProfileSecurity::Open,
            Self::Owe => ProfileSecurity::Owe,
            Self::WpaPersonal => ProfileSecurity::WpaPersonal,
            Self::Wpa3Personal => ProfileSecurity::Wpa3Personal,
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Wifi {
    /// Scan for visible networks (or print cached results with `--cached`).
    Scan {
        #[command(flatten)]
        device: DeviceOpt,
        /// Show every BSS instead of the strongest BSS per SSID.
        #[arg(short = 'a', long)]
        all: bool,
        /// Print the latest cached scan results without triggering a new scan.
        #[arg(long)]
        cached: bool,
    },
    /// Connect to a saved profile (by id, name, or SSID) or join a new SSID.
    Connect(ConnectArgs),
    /// Disconnect and hold autoconnect until explicitly resumed.
    Disconnect {
        #[command(flatten)]
        device: DeviceOpt,
        /// Return immediately after the request is accepted.
        #[arg(long)]
        no_wait: bool,
        /// Seconds to wait for the link to become idle.
        #[arg(short = 't', long, default_value_t = 15)]
        timeout: u64,
    },
    /// Show or change station autoconnect without changing the current link.
    Autoconnect {
        /// Omit to query the current autoconnect state.
        #[arg(value_enum)]
        state: Option<OnOff>,
        #[command(flatten)]
        device: DeviceOpt,
    },
    /// Show recent Wi-Fi station connection events, newest first.
    History {
        /// Filter events to one wireless interface.
        #[arg(short = 'd', long = "device", value_name = "IFACE")]
        device: Option<String>,
        /// Maximum number of events to display.
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: u32,
    },
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ConnectArgs {
    /// Saved profile (id, id prefix, name, or SSID) or new SSID to join.
    pub(crate) target: String,
    #[command(flatten)]
    pub(crate) device: DeviceOpt,
    /// Security mode for a new network (inferred from scan when omitted).
    #[arg(long, value_enum)]
    pub(crate) security: Option<PersonalSecurityMode>,
    /// Human-readable label for a created or updated profile.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// Autoconnect priority (higher wins; allows negative values).
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) priority: Option<i32>,
    /// The network does not broadcast its SSID; requires `--security`.
    #[arg(long)]
    pub(crate) hidden: bool,
    /// Prompt for a passphrase even if the profile already stores one.
    #[arg(long, conflicts_with = "secret_stdin")]
    pub(crate) ask_secret: bool,
    /// Read the passphrase from the first line of standard input.
    #[arg(long)]
    pub(crate) secret_stdin: bool,
    /// Return immediately after the request is accepted.
    #[arg(long)]
    pub(crate) no_wait: bool,
    /// Seconds to wait for `connected`.
    #[arg(short = 't', long, default_value_t = 30)]
    pub(crate) timeout: u64,
}

pub(crate) async fn run(
    client: &Client,
    bus: &str,
    polkit_guard: &mut polkit::PolkitGuard,
    command: Wifi,
    json: bool,
) -> CliResult<()> {
    match command {
        Wifi::Scan {
            device,
            all,
            cached,
        } => {
            let (_, proxy) = resolve_device(client, device.device.as_deref(), None).await?;
            let results = if cached {
                proxy.get_scan_results().await?
            } else {
                scan_and_get(&proxy, Duration::from_secs(20)).await?
            };
            print_scan(json, &results, all);
            Ok(())
        }
        Wifi::Connect(args) => wifi_connect(client, bus, polkit_guard, args, json).await,
        Wifi::Disconnect {
            device,
            no_wait,
            timeout,
        } => wifi_disconnect(client, device.device.as_deref(), no_wait, timeout, json).await,
        Wifi::Autoconnect { state, device } => {
            wifi_autoconnect(client, device.device.as_deref(), state, json).await
        }
        Wifi::History { device, limit } => {
            wifi_history(client, device.as_deref(), limit, json).await
        }
    }
}

async fn wifi_disconnect(
    client: &Client,
    device: Option<&str>,
    no_wait: bool,
    timeout: u64,
    json: bool,
) -> CliResult<()> {
    let (iface, proxy) = resolve_device(client, device, None).await?;
    let mut state_changes = proxy.receive_state_changed().await;
    proxy.disconnect().await?;
    if !no_wait {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout);
        loop {
            let state = proxy.state().await?;
            if matches!(state.as_str(), "idle" | "disabled" | "waiting") {
                break;
            }
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Err(CliError::Interrupted),
                () = tokio::time::sleep_until(deadline) => {
                    return Err(CliError::timeout("timed out waiting for disconnect"));
                }
                event = state_changes.next() => {
                    if event.is_none() {
                        break;
                    }
                }
            }
        }
    }
    print(
        json,
        &json!({"device": iface, "state": "disconnected"}),
        || {
            println!(
                "{iface}: disconnected; autoconnect is held until `kestrel wifi autoconnect on`"
            );
        },
    );
    Ok(())
}

async fn wifi_autoconnect(
    client: &Client,
    device: Option<&str>,
    state: Option<OnOff>,
    json: bool,
) -> CliResult<()> {
    let (iface, proxy) = resolve_device(client, device, None).await?;
    if let Some(target) = state {
        let enabled = target.as_bool();
        proxy.set_autoconnect(enabled).await?;
        wait_autoconnect(&proxy, enabled).await?;
        print(
            json,
            &json!({"device": iface, "autoconnect": enabled}),
            || {
                println!(
                    "{iface}: autoconnect {}",
                    if enabled { "on" } else { "off" }
                );
            },
        );
    } else {
        let enabled = proxy.autoconnect_enabled().await?;
        let held = proxy.autoconnect_held().await?;
        print(
            json,
            &json!({
                "device": iface,
                "autoconnect": enabled,
                "held": held,
            }),
            || {
                let held_note = if held { " (held)" } else { "" };
                println!(
                    "{iface}: autoconnect {}{held_note}",
                    if enabled { "on" } else { "off" }
                );
            },
        );
    }
    Ok(())
}

async fn wifi_connect(
    client: &Client,
    bus: &str,
    polkit_guard: &mut polkit::PolkitGuard,
    args: ConnectArgs,
    json: bool,
) -> CliResult<()> {
    let (iface, device) = resolve_device(client, args.device.device.as_deref(), None).await?;
    let mut matches = matching_profiles(client, &args.target).await?;

    match matches.len() {
        1 => {
            let entry = matches.remove(0);
            connect_existing(
                client,
                bus,
                polkit_guard,
                &iface,
                &device,
                entry.proxy,
                entry.path,
                args,
                json,
            )
            .await
        }
        0 => connect_new(client, bus, polkit_guard, &iface, &device, args, json).await,
        _ => Err(CliError::runtime(format_ambiguous_profiles(
            &args.target,
            &matches,
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_existing(
    client: &Client,
    bus: &str,
    polkit_guard: &mut polkit::PolkitGuard,
    iface: &str,
    device: &DeviceProxy<'_>,
    profile: ProfileProxy<'_>,
    path: OwnedObjectPath,
    args: ConnectArgs,
    json: bool,
) -> CliResult<()> {
    let existing_settings = profile.settings().await?;
    let existing_security = profile_security(&existing_settings)?;
    let unmanaged = setting_string(&existing_settings, "l3") == "unmanaged";
    let is_eap_tls = setting_string(&existing_settings, "enterprise.eap") == "tls";
    let existing_has_secret = profile.has_secret().await?;

    let target_security = match args.security {
        Some(mode) => {
            if existing_security.is_enterprise() {
                return Err(CliError::runtime(
                    "use `kestrel profile edit` to change an 802.1X enterprise profile's security mode",
                ));
            }
            mode.to_profile_security()
        }
        None => existing_security,
    };

    let security_changed = target_security != existing_security;
    let missing_secret =
        target_security.needs_secret() && (!existing_has_secret || security_changed);
    let wants_secret = args.secret_stdin || args.ask_secret || missing_secret;
    let wants_settings_update =
        security_changed || args.name.is_some() || args.priority.is_some() || args.hidden;

    if wants_secret || wants_settings_update {
        polkit_guard
            .ensure_authorized(client.connection(), bus, &[polkit::ACTION_MODIFY_PROFILES])
            .await?;
    }

    let secret = if args.secret_stdin {
        Some(stdin_secret()?)
    } else if args.ask_secret {
        Some(prompt_secret()?)
    } else if missing_secret {
        if is_eap_tls {
            return Err(CliError::runtime(
                "this EAP-TLS profile has no private key; run `kestrel profile edit <profile> --private-key-file <path>`",
            ));
        }
        if std::io::stdin().is_terminal() {
            Some(prompt_secret()?)
        } else {
            return Err(CliError::runtime(
                "this profile has no passphrase; use --secret-stdin in a script",
            ));
        }
    } else {
        None
    };

    if wants_settings_update || secret.is_some() {
        let mut settings: ProfileSettings = HashMap::new();
        let mut put = |key: &str, value: Variant<'_>| {
            settings.insert(
                key.to_owned(),
                OwnedVariant::try_from(value).expect("plain value"),
            );
        };
        if security_changed {
            put("security", Variant::from(target_security.as_str()));
        }
        if let Some(name) = &args.name {
            put("name", Variant::from(name.as_str()));
        }
        if let Some(priority) = args.priority {
            put("priority", Variant::from(priority));
        }
        if args.hidden {
            put("hidden", Variant::from(true));
        }
        let action = if secret.is_some() { "set" } else { "keep" };
        profile
            .update(
                settings,
                action,
                secret_bundle(secret.as_deref().map(String::as_str)),
            )
            .await?;
    }

    connect_and_wait(
        client,
        device,
        &path,
        iface,
        None,
        args.no_wait,
        unmanaged,
        Duration::from_secs(args.timeout),
        json,
    )
    .await
}

async fn connect_new(
    client: &Client,
    bus: &str,
    polkit_guard: &mut polkit::PolkitGuard,
    iface: &str,
    device: &DeviceProxy<'_>,
    args: ConnectArgs,
    json: bool,
) -> CliResult<()> {
    let security = match args.security {
        Some(mode) => mode.to_profile_security(),
        None if args.hidden => {
            return Err(CliError::runtime(
                "a hidden network needs --security open|owe|wpa-personal|wpa3-personal",
            ));
        }
        None => {
            infer_security(
                device,
                &args.target,
                Duration::from_secs(args.timeout),
                json,
            )
            .await?
        }
    };
    if security.is_enterprise() {
        return Err(CliError::runtime(
            "enterprise networks require `kestrel profile add <SSID> --security wpa-enterprise --eap <method> --identity <name>`",
        ));
    }

    polkit_guard
        .ensure_authorized(client.connection(), bus, &[polkit::ACTION_MODIFY_PROFILES])
        .await?;

    let secret = new_network_secret(&args, security)?;
    let settings = new_network_settings(&args, security);
    let path = client
        .manager()
        .await?
        .add_profile(
            settings,
            secret_bundle(secret.as_deref().map(String::as_str)),
        )
        .await?;

    connect_and_wait(
        client,
        device,
        &path,
        iface,
        Some(&args.target),
        args.no_wait,
        false,
        Duration::from_secs(args.timeout),
        json,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn connect_and_wait(
    client: &Client,
    device: &DeviceProxy<'_>,
    path: &OwnedObjectPath,
    device_name: &str,
    ssid: Option<&str>,
    no_wait: bool,
    unmanaged: bool,
    timeout: Duration,
    json: bool,
) -> CliResult<()> {
    // Subscribe BEFORE issuing `connect()` so fast transitions and failures
    // are never missed and stale pre-existing failures are ignored.
    let previous_failure = device.last_failure().await.unwrap_or_default();
    let state_changes = device.receive_state_changed().await;
    let failure_changes = device.receive_last_failure_changed().await;
    device.connect(&path.as_ref()).await?;
    if no_wait {
        let profile_id = client
            .profile(path.clone())
            .await
            .ok()
            .map(|p| async move { p.id().await.unwrap_or_default() });
        let id = match profile_id {
            Some(fut) => fut.await,
            None => String::new(),
        };
        let payload = if let Some(ssid) = ssid {
            json!({
                "device": device_name,
                "ssid": ssid,
                "profile": path.as_str(),
                "profile_id": id,
                "state": "requested",
            })
        } else {
            json!({
                "device": device_name,
                "profile": path.as_str(),
                "profile_id": id,
                "state": "requested",
            })
        };
        print(json, &payload, || {
            if let Some(ssid) = ssid {
                println!("{device_name}: connecting to {ssid:?}");
            } else {
                println!("{device_name}: connecting");
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
    let fresh = DeviceProxy::builder(client.connection())
        .path(device.inner().path().to_owned())
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    print_device_summary(client, &fresh, json).await
}

async fn scan_and_get(device: &DeviceProxy<'_>, timeout: Duration) -> CliResult<Vec<ScanResult>> {
    let mut results_changed = device.receive_scan_results_changed().await?;
    let mut scanning_changed = device.receive_scanning_changed().await;
    device.scan().await?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut saw_scanning = device.scanning().await.unwrap_or(false);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Err(CliError::Interrupted),
            () = tokio::time::sleep_until(deadline) => {
                return Err(CliError::timeout("scan timed out"));
            }
            signal = results_changed.next() => {
                match signal {
                    Some(_) => break,
                    None => return Err(CliError::runtime("scan stream closed")),
                }
            }
            change = scanning_changed.next() => {
                let Some(change) = change else {
                    return Err(CliError::runtime("scan stream closed"));
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
    Ok(device.get_scan_results().await?)
}

fn best_security_for_ssid(results: &[ScanResult], ssid: &str) -> Option<ProfileSecurity> {
    let mut best: Option<(i16, ProfileSecurity)> = None;
    for (found, _, _, signal, security, _) in results {
        if found != ssid {
            continue;
        }
        if let Some(candidate) = ProfileSecurity::from_scan_security(security)
            && best.is_none_or(|(best_signal, _)| *signal > best_signal)
        {
            best = Some((*signal, candidate));
        }
    }
    best.map(|(_, security)| security)
}

async fn infer_security(
    device: &DeviceProxy<'_>,
    ssid: &str,
    timeout: Duration,
    json: bool,
) -> CliResult<ProfileSecurity> {
    if let Ok(cached) = device.get_scan_results().await
        && let Some(security) = best_security_for_ssid(&cached, ssid)
    {
        return Ok(security);
    }
    if !json && std::io::stderr().is_terminal() {
        eprintln!("scanning for {ssid:?}...");
    }
    let scan_timeout = timeout.min(Duration::from_secs(15));
    let results = match scan_and_get(device, scan_timeout).await {
        Ok(results) => results,
        Err(CliError::Interrupted) => return Err(CliError::Interrupted),
        Err(_) => device.get_scan_results().await?,
    };
    best_security_for_ssid(&results, ssid).ok_or_else(|| {
        CliError::runtime(format!(
            "{ssid:?} was not found; use --hidden --security <mode> for a hidden network"
        ))
    })
}

fn new_network_secret(
    args: &ConnectArgs,
    security: ProfileSecurity,
) -> CliResult<Option<Zeroizing<String>>> {
    if args.secret_stdin {
        return stdin_secret().map(Some);
    }
    if args.ask_secret {
        return prompt_secret().map(Some);
    }
    if !security.needs_secret() {
        return Ok(None);
    }
    if std::io::stdin().is_terminal() {
        prompt_secret().map(Some)
    } else {
        Err(CliError::runtime(
            "this network needs a passphrase; use --secret-stdin in a script",
        ))
    }
}

fn new_network_settings(args: &ConnectArgs, security: ProfileSecurity) -> ProfileSettings {
    let mut settings = HashMap::new();
    let mut put = |key: &str, value: Variant<'_>| {
        settings.insert(
            key.to_owned(),
            OwnedVariant::try_from(value).expect("plain value"),
        );
    };
    put("ssid", Variant::from(args.target.as_str()));
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
) -> CliResult<()> {
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
            "disabled" => return Err(CliError::runtime("wireless is disabled")),
            "idle" | "waiting" => {
                let last_failure = device.last_failure().await?;
                if !last_failure.is_empty() && (saw_attempt || last_failure != previous_failure) {
                    return Err(CliError::runtime(format!(
                        "connection failed: {last_failure}"
                    )));
                }
            }
            _ => {}
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Err(CliError::Interrupted),
            () = tokio::time::sleep_until(deadline) => {
                let last_failure = device.last_failure().await?;
                let detail = if last_failure.is_empty() {
                    String::new()
                } else {
                    format!(" ({last_failure})")
                };
                return Err(CliError::timeout(format!(
                    "timed out waiting for a connection{detail}"
                )));
            }
            event = state_changes.next() => {
                let Some(change) = event else {
                    return Err(CliError::runtime("device disappeared while waiting"));
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
                    return Err(CliError::runtime("device disappeared while waiting"));
                }
                saw_attempt = true;
            }
        }
    }
}

async fn wait_autoconnect(device: &DeviceProxy<'_>, enabled: bool) -> CliResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if device.autoconnect_enabled().await? == enabled {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::timeout("timed out waiting for autoconnect state"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_l3_ready(device: &DeviceProxy<'_>, timeout: Duration) -> CliResult<()> {
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
                return Err(CliError::runtime(format!(
                    "L3 configuration failed{suffix}"
                )));
            }
            _ => {}
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Err(CliError::Interrupted),
            () = tokio::time::sleep_until(deadline) => return Ok(()),
            event = phase_changes.next() => {
                if event.is_none() {
                    return Ok(());
                }
            }
        }
    }
}

async fn wifi_history(
    client: &Client,
    device_filter: Option<&str>,
    limit: u32,
    json: bool,
) -> CliResult<()> {
    // When filtering by device, fetch up to the server cap (500) before trimming to `limit`.
    let fetch_limit = if device_filter.is_some() && limit > 0 {
        500
    } else {
        limit
    };
    let mut events = client.manager().await?.history(fetch_limit).await?;
    if let Some(iface) = device_filter {
        events.retain(|(_, dev, _, _, _, _)| dev == iface);
        events.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    }
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
        print_table(
            &["WHEN", "DEVICE", "SSID", "OUTCOME", "DETAIL"],
            &rows,
            Some("No connection history."),
        );
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
            Some("No networks found."),
        );
    });
}

// SPDX-License-Identifier: LGPL-2.1-or-later

//! Shared CLI errors, device resolution, formatting, prompting, bounded I/O,
//! and object-lookup helpers.

use std::fmt;
use std::fs::File;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use kestrel_api::client::{Client, DeviceProxy, ProfileProxy};
use kestrel_api::{ProfileSettings, SecretBundle};
use kestrel_model::ProfileSecurity;
use serde_json::{Value, json};
use zbus::OwnedObjectPath;
use zeroize::Zeroizing;

pub(crate) type CliResult<T> = Result<T, CliError>;

/// Structured CLI error with semantic exit codes (ADR-0010).
#[derive(Debug)]
pub(crate) enum CliError {
    /// Runtime, D-Bus, validation, or authorization error (exit 1).
    Runtime(String),
    /// Operation timed out waiting for a terminal state (exit 124).
    Timeout(String),
    /// Interrupted by `Ctrl-C` while waiting for an operation (exit 130).
    Interrupted,
}

impl CliError {
    pub(crate) fn runtime(message: impl Into<String>) -> Self {
        Self::Runtime(message.into())
    }

    pub(crate) fn timeout(message: impl Into<String>) -> Self {
        Self::Timeout(message.into())
    }

    pub(crate) fn exit_code(&self) -> ExitCode {
        match self {
            Self::Runtime(_) => ExitCode::from(1),
            Self::Timeout(_) => ExitCode::from(124),
            Self::Interrupted => ExitCode::from(130),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(message) | Self::Timeout(message) => f.write_str(message),
            Self::Interrupted => f.write_str("interrupted"),
        }
    }
}

impl From<zbus::Error> for CliError {
    fn from(error: zbus::Error) -> Self {
        match error {
            zbus::Error::MethodError(name, Some(message), _) => {
                let short = name
                    .as_str()
                    .rsplit('.')
                    .next()
                    .unwrap_or(name.as_str())
                    .to_owned();
                Self::Runtime(format!("{short}: {message}"))
            }
            other => Self::Runtime(other.to_string()),
        }
    }
}

/// Optional `-d / --device` flag shared across single-device commands.
#[derive(Debug, Default, Clone, Args)]
pub(crate) struct DeviceOpt {
    /// Wireless interface name (auto-selected when only one capable device exists).
    #[arg(
        short = 'd',
        long = "device",
        env = "KESTREL_DEVICE",
        value_name = "IFACE"
    )]
    pub(crate) device: Option<String>,
}

/// Common `on` / `off` toggle value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum OnOff {
    On,
    Off,
}

impl OnOff {
    pub(crate) const fn as_bool(self) -> bool {
        matches!(self, Self::On)
    }
}

/// Resolves a wireless device from an explicit interface name or auto-selects
/// the unique device advertising `required_capability` (or any wireless device
/// when `None`). Ambiguity across multiple devices is always an error.
pub(crate) async fn resolve_device(
    client: &Client,
    explicit: Option<&str>,
    required_capability: Option<&str>,
) -> CliResult<(String, DeviceProxy<'static>)> {
    if let Some(name) = explicit {
        let proxy = client.device(name).await?;
        return Ok((name.to_owned(), proxy));
    }

    let devices = client.devices().await?;
    let mut candidates = Vec::new();
    for proxy in devices {
        if let Some(cap) = required_capability {
            let caps = proxy.capabilities().await?;
            if !caps.iter().any(|item| item == cap) {
                continue;
            }
        }
        let iface = proxy.interface().await?;
        candidates.push((iface, proxy));
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    match candidates.len() {
        1 => {
            let (iface, _) = candidates.remove(0);
            // Re-open via `client.device()` so the returned proxy has default property
            // caching enabled and supports `receive_*_changed()` streams.
            let proxy = client.device(&iface).await?;
            Ok((iface, proxy))
        }
        0 => {
            if let Some(cap) = required_capability {
                Err(CliError::runtime(format!(
                    "no {cap}-capable wireless devices found"
                )))
            } else {
                Err(CliError::runtime("no wireless devices found"))
            }
        }
        _ => {
            let names: Vec<&str> = candidates.iter().map(|(name, _)| name.as_str()).collect();
            Err(CliError::runtime(format!(
                "multiple wireless devices found ({}); specify one with -d/--device",
                names.join(", ")
            )))
        }
    }
}

pub(crate) fn print(json: bool, value: &Value, human: impl FnOnce()) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    } else {
        human();
    }
}

pub(crate) fn dash_if_empty(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

pub(crate) fn json_str_or_dash<'a>(value: &'a Value, key: &str) -> &'a str {
    dash_if_empty(value[key].as_str().unwrap_or(""))
}

pub(crate) fn json_string_list(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

#[allow(clippy::format_push_string)]
pub(crate) fn print_table(headers: &[&str], rows: &[Vec<String>], empty_notice: Option<&str>) {
    if rows.is_empty() {
        if let Some(notice) = empty_notice {
            eprintln!("{notice}");
        }
        return;
    }
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(cell.chars().count());
            }
        }
    }
    let render = |cells: &[String]| -> String {
        let mut line = String::new();
        for (index, cell) in cells.iter().enumerate() {
            if index > 0 {
                line.push_str("  ");
            }
            let width = widths.get(index).copied().unwrap_or(0);
            line.push_str(&format!("{cell:<width$}"));
        }
        line.trim_end().to_owned()
    };
    let header_cells: Vec<String> = headers.iter().map(|header| (*header).to_owned()).collect();
    println!("{}", render(&header_cells));
    for row in rows {
        println!("{}", render(row));
    }
}

pub(crate) fn format_age(at: u64) -> String {
    if at == 0 {
        return "-".to_owned();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let delta = now.saturating_sub(at);
    match delta {
        0..=9 => "just now".to_owned(),
        10..=59 => format!("{delta}s ago"),
        60..=3599 => format!("{}m ago", delta / 60),
        3600..=86_399 => format!("{}h ago", delta / 3600),
        _ => format!("{}d ago", delta / 86_400),
    }
}

pub(crate) fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

pub(crate) fn setting_string(settings: &ProfileSettings, key: &str) -> String {
    settings
        .get(key)
        .and_then(|value| value.try_clone().ok())
        .and_then(|value| String::try_from(value).ok())
        .unwrap_or_default()
}

pub(crate) fn setting_bool(settings: &ProfileSettings, key: &str) -> Option<bool> {
    settings
        .get(key)
        .and_then(|value| value.try_clone().ok())
        .and_then(|value| bool::try_from(value).ok())
}

pub(crate) fn setting_i32(settings: &ProfileSettings, key: &str) -> Option<i32> {
    settings
        .get(key)
        .and_then(|value| value.try_clone().ok())
        .and_then(|value| i32::try_from(value).ok())
}

pub(crate) fn profile_security(settings: &ProfileSettings) -> CliResult<ProfileSecurity> {
    let security = setting_string(settings, "security");
    ProfileSecurity::parse(&security).map_err(|error| CliError::runtime(error.to_string()))
}

pub(crate) fn profile_autoconnect(settings: &ProfileSettings) -> bool {
    setting_bool(settings, "autoconnect").unwrap_or(true)
}

pub(crate) fn prompt_secret_with(prompt: &str, label: &str) -> CliResult<Zeroizing<String>> {
    let secret = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .map_err(|error| CliError::runtime(format!("cannot read {label}: {error}")))?,
    );
    if secret.is_empty() {
        return Err(CliError::runtime(format!("empty {label}")));
    }
    Ok(secret)
}

pub(crate) fn prompt_secret() -> CliResult<Zeroizing<String>> {
    prompt_secret_with("Passphrase: ", "passphrase")
}

pub(crate) fn prompt_optional(prompt: &str) -> CliResult<Option<Zeroizing<String>>> {
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .map_err(|error| CliError::runtime(format!("cannot read input: {error}")))?,
    );
    Ok((!value.is_empty()).then_some(value))
}

pub(crate) fn stdin_secret_labeled(label: &str) -> CliResult<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| CliError::runtime(format!("cannot read {label}: {error}")))?;
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(CliError::runtime(format!(
            "empty {label} on standard input"
        )));
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

pub(crate) fn stdin_secret() -> CliResult<Zeroizing<String>> {
    stdin_secret_labeled("passphrase")
}

pub(crate) fn read_bounded_reader(
    reader: impl Read,
    max_bytes: usize,
    source: &str,
) -> CliResult<String> {
    let limit = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let mut buf = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|error| CliError::runtime(format!("cannot read {source}: {error}")))?;
    if buf.len() > max_bytes {
        return Err(CliError::runtime(format!(
            "{source} exceeds {max_bytes} bytes"
        )));
    }
    String::from_utf8(buf)
        .map_err(|error| CliError::runtime(format!("{source} is not valid UTF-8: {error}")))
}

pub(crate) fn read_bounded_file(path: &str, max_bytes: usize) -> CliResult<String> {
    let file = File::open(path)
        .map_err(|error| CliError::runtime(format!("cannot read {path}: {error}")))?;
    read_bounded_reader(file, max_bytes, path)
}

pub(crate) fn read_bounded_stdin(max_bytes: usize) -> CliResult<String> {
    read_bounded_reader(std::io::stdin().lock(), max_bytes, "standard input")
}

/// Builds the D-Bus secret bundle from an optional passphrase.
pub(crate) fn secret_bundle(passphrase: Option<&str>) -> SecretBundle {
    match passphrase {
        Some(value) if !value.is_empty() => {
            SecretBundle::from([("passphrase".to_owned(), value.to_owned())])
        }
        _ => SecretBundle::new(),
    }
}

/// Prompts for confirmation on stderr so stdout remains clean for pipelines.
pub(crate) fn confirm(prompt: &str) -> bool {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}

pub(crate) fn confirm_delete(prompt: &str, yes: bool) -> CliResult<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::runtime("refusing to delete without --yes"));
    }
    Ok(confirm(prompt))
}

pub(crate) fn signal_text(signal: i16) -> String {
    if signal == 0 {
        "-".to_owned()
    } else {
        format!("{signal} dBm")
    }
}

pub(crate) fn link_has_l3(state: &str) -> bool {
    matches!(state, "configuring-l3" | "connected" | "reconnecting")
}

pub(crate) fn addresses_text(addresses: &[String]) -> String {
    if addresses.is_empty() {
        "-".to_owned()
    } else {
        addresses.join(", ")
    }
}

/// Formats a profile object path as a human-friendly label (`<name> (<short-id>)`)
/// without leaking D-Bus paths.
pub(crate) async fn format_profile_label(client: &Client, path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "-".to_owned();
    }
    if let Ok(object_path) = OwnedObjectPath::try_from(path.to_owned())
        && let Ok(proxy) = client.profile(object_path).await
        && let (Ok(id), Ok(settings)) = (proxy.id().await, proxy.settings().await)
    {
        let name = setting_string(&settings, "name");
        let ssid = setting_string(&settings, "ssid");
        let label = if name.is_empty() { ssid } else { name };
        let short = short_id(&id);
        return if label.is_empty() {
            short
        } else {
            format!("{label} ({short})")
        };
    }
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

pub(crate) async fn device_json(client: &Client, device: &DeviceProxy<'_>) -> CliResult<Value> {
    let profile_path = device.active_profile().await?;
    let profile_str = profile_path.as_str().to_owned();
    let (profile_id, profile_name) = if profile_str == "/" {
        (String::new(), String::new())
    } else if let Ok(proxy) = client.profile(profile_path).await {
        let id = proxy.id().await.unwrap_or_default();
        let name = proxy
            .settings()
            .await
            .map(|settings| {
                let name = setting_string(&settings, "name");
                if name.is_empty() {
                    setting_string(&settings, "ssid")
                } else {
                    name
                }
            })
            .unwrap_or_default();
        (id, name)
    } else {
        (String::new(), String::new())
    };
    let needing_secrets: Vec<String> = device
        .profiles_needing_secrets()
        .await?
        .into_iter()
        .map(|path| path.as_str().to_owned())
        .collect();
    Ok(json!({
        "interface": device.interface().await?,
        "address": device.hardware_address().await?,
        "capabilities": device.capabilities().await?,
        "supported_security": device.supported_security().await?,
        "state": device.state().await?,
        "scanning": device.scanning().await?,
        "ssid": device.ssid().await?,
        "profile": profile_str,
        "profile_id": profile_id,
        "profile_name": profile_name,
        "bssid": device.bssid().await?,
        "frequency": device.frequency().await?,
        "security": device.security().await?,
        "signal": device.signal().await?,
        "addresses": device.addresses().await?,
        "gateways": device.gateways().await?,
        "dns": device.dns().await?,
        "l3_phase": device.l3_phase().await?,
        "online_state": device.online_state().await?,
        "last_failure": device.last_failure().await?,
        "last_failure_detail": device.last_failure_detail().await?,
        "autoconnect_held": device.autoconnect_held().await?,
        "autoconnect_enabled": device.autoconnect_enabled().await?,
        "profiles_needing_secrets": needing_secrets,
    }))
}

pub(crate) async fn print_device_summary(
    client: &Client,
    device: &DeviceProxy<'_>,
    json: bool,
) -> CliResult<()> {
    let value = device_json(client, device).await?;
    print(json, &value, || {
        let addresses = json_string_list(&value, "addresses");
        println!(
            "{}: {}  SSID {}  {}",
            value["interface"].as_str().unwrap_or(""),
            value["state"].as_str().unwrap_or(""),
            json_str_or_dash(&value, "ssid"),
            addresses_text(&addresses)
        );
    });
    Ok(())
}

fn id_matches(id: &str, query: &str) -> bool {
    id == query
        || id.replace('-', "") == query
        || (query.len() >= 8
            && query
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
            && id.starts_with(query))
}

/// A saved profile match returned by [`matching_profiles`].
pub(crate) struct MatchedProfile {
    pub(crate) path: OwnedObjectPath,
    pub(crate) id: String,
    pub(crate) ssid: String,
    pub(crate) name: String,
    pub(crate) security: String,
    pub(crate) proxy: ProfileProxy<'static>,
}

/// Finds all saved profiles matching `query` by id (or 8+ char prefix), name, or SSID.
pub(crate) async fn matching_profiles(
    client: &Client,
    query: &str,
) -> CliResult<Vec<MatchedProfile>> {
    let mut matches: Vec<MatchedProfile> = Vec::new();
    for profile in client.profiles().await? {
        let settings = profile.settings().await?;
        let id = profile.id().await?;
        let name = setting_string(&settings, "name");
        let ssid = setting_string(&settings, "ssid");
        let is_match = id_matches(&id, query) || name == query || ssid == query;
        if is_match {
            let path: OwnedObjectPath = profile.inner().path().to_owned().into();
            if !matches.iter().any(|item| item.path == path) {
                let security = setting_string(&settings, "security");
                matches.push(MatchedProfile {
                    path,
                    id,
                    ssid,
                    name,
                    security,
                    proxy: profile,
                });
            }
        }
    }
    Ok(matches)
}

pub(crate) fn format_ambiguous_profiles(query: &str, matches: &[MatchedProfile]) -> String {
    let choices: Vec<String> = matches
        .iter()
        .map(|item| {
            let label = if item.name.is_empty() || item.name == item.ssid {
                item.ssid.clone()
            } else {
                format!("{} ({})", item.name, item.ssid)
            };
            format!("{} [{label}, {}]", short_id(&item.id), item.security)
        })
        .collect();
    format!(
        "{query:?} matches several profiles ({}); specify the profile id",
        choices.join("; ")
    )
}

/// Finds a unique profile by id (including a unique 8+ character prefix), name,
/// or SSID. Ambiguity or missing match is an error.
pub(crate) async fn resolve_profile(client: &Client, query: &str) -> CliResult<OwnedObjectPath> {
    let mut matches = matching_profiles(client, query).await?;
    match matches.len() {
        1 => Ok(matches.remove(0).path),
        0 => Err(CliError::runtime(format!("no profile matches {query:?}"))),
        _ => Err(CliError::runtime(format_ambiguous_profiles(
            query, &matches,
        ))),
    }
}

/// Finds a certificate by id, id prefix, or name.
pub(crate) async fn resolve_certificate(
    client: &Client,
    query: &str,
) -> CliResult<OwnedObjectPath> {
    let mut matches: Vec<OwnedObjectPath> = Vec::new();
    for certificate in client.certificates().await? {
        let id = certificate.id().await?;
        if id_matches(&id, query) || certificate.name().await? == query {
            let path: OwnedObjectPath = certificate.inner().path().to_owned().into();
            if !matches.contains(&path) {
                matches.push(path);
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(CliError::runtime(format!(
            "no certificate matches {query:?}"
        ))),
        _ => Err(CliError::runtime(format!(
            "{query:?} matches several certificates; specify the certificate id"
        ))),
    }
}

/// Finds a persistent group by id (including a unique 8+ character prefix),
/// name, or SSID.
pub(crate) async fn resolve_p2p_group(client: &Client, query: &str) -> CliResult<OwnedObjectPath> {
    let mut matches: Vec<OwnedObjectPath> = Vec::new();
    for group in client.p2p_groups().await? {
        let id = group.id().await?;
        if id_matches(&id, query) || group.name().await? == query || group.ssid().await? == query {
            let path: OwnedObjectPath = group.inner().path().to_owned().into();
            if !matches.contains(&path) {
                matches.push(path);
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(CliError::runtime(format!(
            "no persistent group matches {query:?}"
        ))),
        _ => Err(CliError::runtime(format!(
            "{query:?} matches several persistent groups; specify the group id"
        ))),
    }
}

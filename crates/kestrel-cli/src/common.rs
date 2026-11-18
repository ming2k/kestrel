// SPDX-License-Identifier: LGPL-2.1-or-later

//! Shared formatting, prompting, bounded I/O, and object-lookup helpers.

use std::fs::File;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use kestrel_api::client::{Client, DeviceProxy, ProfileProxy};
use kestrel_api::{ProfileSettings, SecretBundle};
use kestrel_model::ProfileSecurity;
use serde_json::{Value, json};
use zbus::OwnedObjectPath;
use zeroize::Zeroizing;

pub(crate) fn failure(message: impl Into<String>) -> zbus::Error {
    zbus::Error::Failure(message.into())
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
pub(crate) fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
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

pub(crate) fn profile_security(settings: &ProfileSettings) -> zbus::Result<ProfileSecurity> {
    let security = setting_string(settings, "security");
    ProfileSecurity::parse(&security).map_err(|error| failure(error.to_string()))
}

pub(crate) fn profile_autoconnect(settings: &ProfileSettings) -> bool {
    setting_bool(settings, "autoconnect").unwrap_or(true)
}

pub(crate) fn prompt_secret_with(prompt: &str, label: &str) -> zbus::Result<Zeroizing<String>> {
    let secret = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .map_err(|error| failure(format!("cannot read {label}: {error}")))?,
    );
    if secret.is_empty() {
        return Err(failure(format!("empty {label}")));
    }
    Ok(secret)
}

pub(crate) fn prompt_secret() -> zbus::Result<Zeroizing<String>> {
    prompt_secret_with("Passphrase: ", "passphrase")
}

pub(crate) fn prompt_optional(prompt: &str) -> zbus::Result<Option<Zeroizing<String>>> {
    let value = Zeroizing::new(
        rpassword::prompt_password(prompt)
            .map_err(|error| failure(format!("cannot read input: {error}")))?,
    );
    Ok((!value.is_empty()).then_some(value))
}

pub(crate) fn stdin_secret_labeled(label: &str) -> zbus::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| failure(format!("cannot read {label}: {error}")))?;
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(failure(format!("empty {label} on standard input")));
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

pub(crate) fn stdin_secret() -> zbus::Result<Zeroizing<String>> {
    stdin_secret_labeled("passphrase")
}

pub(crate) fn read_bounded_reader(
    reader: impl Read,
    max_bytes: usize,
    source: &str,
) -> zbus::Result<String> {
    let limit = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let mut buf = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|error| failure(format!("cannot read {source}: {error}")))?;
    if buf.len() > max_bytes {
        return Err(failure(format!("{source} exceeds {max_bytes} bytes")));
    }
    String::from_utf8(buf).map_err(|error| failure(format!("{source} is not valid UTF-8: {error}")))
}

pub(crate) fn read_bounded_file(path: &str, max_bytes: usize) -> zbus::Result<String> {
    let file = File::open(path).map_err(|error| failure(format!("cannot read {path}: {error}")))?;
    read_bounded_reader(file, max_bytes, path)
}

pub(crate) fn read_bounded_stdin(max_bytes: usize) -> zbus::Result<String> {
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

pub(crate) fn confirm(prompt: &str) -> bool {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}

pub(crate) fn confirm_delete(prompt: &str, yes: bool) -> zbus::Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(failure("refusing to delete without --yes"));
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

pub(crate) async fn device_json(device: &DeviceProxy<'_>) -> zbus::Result<Value> {
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
        "profile": device.active_profile().await?.as_str(),
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

pub(crate) async fn print_device_summary(device: &DeviceProxy<'_>, json: bool) -> zbus::Result<()> {
    let value = device_json(device).await?;
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

pub(crate) async fn profiles_by_ssid(
    client: &Client,
    ssid: &str,
) -> zbus::Result<Vec<ProfileProxy<'static>>> {
    let mut matches = Vec::new();
    for profile in client.profiles().await? {
        if setting_string(&profile.settings().await?, "ssid") == ssid {
            matches.push(profile);
        }
    }
    Ok(matches)
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

/// Finds a profile by id (including a unique 8+ character prefix), name, or
/// SSID. Ambiguity is an error.
pub(crate) async fn resolve_profile(client: &Client, query: &str) -> zbus::Result<OwnedObjectPath> {
    let mut matches: Vec<OwnedObjectPath> = Vec::new();
    for profile in client.profiles().await? {
        let settings = profile.settings().await?;
        let id = profile.id().await?;
        let is_match = id_matches(&id, query)
            || setting_string(&settings, "name") == query
            || setting_string(&settings, "ssid") == query;
        if is_match {
            let path: OwnedObjectPath = profile.inner().path().to_owned().into();
            if !matches.contains(&path) {
                matches.push(path);
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(failure(format!("no profile matches {query:?}"))),
        _ => Err(failure(format!(
            "{query:?} matches several profiles; use the id"
        ))),
    }
}

/// Finds a certificate by id, id prefix, or name.
pub(crate) async fn resolve_certificate(
    client: &Client,
    query: &str,
) -> zbus::Result<OwnedObjectPath> {
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
        0 => Err(failure(format!("no certificate matches {query:?}"))),
        _ => Err(failure(format!(
            "{query:?} matches several certificates; use the id"
        ))),
    }
}

/// Finds a persistent group by id (including a unique 8+ character prefix),
/// name, or SSID.
pub(crate) async fn resolve_p2p_group(
    client: &Client,
    query: &str,
) -> zbus::Result<OwnedObjectPath> {
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
        0 => Err(failure(format!("no persistent group matches {query:?}"))),
        _ => Err(failure(format!(
            "{query:?} matches several persistent groups; use the id"
        ))),
    }
}

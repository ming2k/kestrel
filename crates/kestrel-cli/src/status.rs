// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel status` and `kestrel radio`: global/device status and radio control.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use kestrel_api::client::Client;
use serde_json::{Value, json};

use crate::common::{
    CliError, CliResult, OnOff, addresses_text, device_json, format_profile_label,
    json_str_or_dash, json_string_list, link_has_l3, print, print_table, short_id, signal_text,
};

pub(crate) async fn status(
    client: &Client,
    device: Option<&str>,
    json: bool,
    watch: bool,
) -> CliResult<()> {
    if json && watch {
        return Err(CliError::runtime("--watch cannot be combined with --json"));
    }
    loop {
        if watch && std::io::stdout().is_terminal() {
            print!("\x1b[2J\x1b[H");
            let _ = std::io::stdout().flush();
        }
        if let Some(iface) = device {
            let proxy = client.device(iface).await?;
            let value = device_json(client, &proxy).await?;
            let needing_labels = resolve_needing_labels(client, &value).await;
            print(json, &value, || {
                print_device_detail(&value, &needing_labels);
            });
        } else {
            let value = overview_value(client).await?;
            print(json, &value, || print_status_overview(&value));
        }
        if !watch {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

pub(crate) async fn radio(client: &Client, state: Option<OnOff>, json: bool) -> CliResult<()> {
    let manager = client.manager().await?;
    if let Some(target) = state {
        let enabled = target.as_bool();
        manager.set_wireless_enabled(enabled).await?;
        let hardware = manager.wireless_hardware_enabled().await?;
        print(
            json,
            &json!({
                "wireless_enabled": enabled,
                "wireless_hardware_enabled": hardware,
            }),
            || print_radio_line(enabled, hardware),
        );
    } else {
        let enabled = manager.wireless_enabled().await?;
        let hardware = manager.wireless_hardware_enabled().await?;
        print(
            json,
            &json!({
                "wireless_enabled": enabled,
                "wireless_hardware_enabled": hardware,
            }),
            || print_radio_line(enabled, hardware),
        );
    }
    Ok(())
}

fn print_radio_line(enabled: bool, hardware: bool) {
    let sw = if enabled { "on" } else { "off" };
    let hw_note = if hardware {
        ""
    } else {
        " (rfkill: hard-blocked)"
    };
    println!("radio: {sw}{hw_note}");
}

async fn overview_value(client: &Client) -> CliResult<Value> {
    let manager = client.manager().await?;
    let wireless = manager.wireless_enabled().await?;
    let hardware = manager.wireless_hardware_enabled().await?;
    let online = manager.online_state().await?;
    let mut devices = Vec::new();
    for device in client.devices().await? {
        devices.push(device_json(client, &device).await?);
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
    println!("radio: {sw}{hw_note}  online: {online}");
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
        Some("No wireless devices found."),
    );
}

async fn resolve_needing_labels(client: &Client, value: &Value) -> Vec<String> {
    let paths = json_string_list(value, "profiles_needing_secrets");
    let mut labels = Vec::with_capacity(paths.len());
    for path in paths {
        labels.push(format_profile_label(client, &path).await);
    }
    labels
}

fn print_device_detail(value: &Value, needing_labels: &[String]) {
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
    println!("Profile: {}", format_profile_from_json(value));
    if !needing_labels.is_empty() {
        println!("Profiles needing secrets: {}", needing_labels.join(", "));
    }
    let last_failure = value["last_failure"].as_str().unwrap_or("");
    if !last_failure.is_empty() {
        let detail = value["last_failure_detail"].as_str().unwrap_or("");
        if detail.is_empty() {
            println!("Last failure: {last_failure}");
        } else {
            println!("Last failure: {last_failure} ({detail})");
        }
    }
}

fn format_profile_from_json(value: &Value) -> String {
    let id = value["profile_id"].as_str().unwrap_or("");
    let name = value["profile_name"].as_str().unwrap_or("");
    if id.is_empty() && name.is_empty() {
        return "-".to_owned();
    }
    let short = short_id(id);
    if name.is_empty() {
        short
    } else if short.is_empty() {
        name.to_owned()
    } else {
        format!("{name} ({short})")
    }
}

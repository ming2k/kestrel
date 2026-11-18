// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel profile`: saved Wi-Fi profile management.

use std::collections::HashMap;
use std::io::IsTerminal;

use clap::{Args, Subcommand};
use kestrel_api::client::{Client, ProfileProxy};
use kestrel_api::{ProfileSettings, SecretBundle};
use kestrel_model::{EapMethod, ProfileSecurity};
use serde_json::{Value, json};
use zbus::{OwnedVariant, Variant};

use crate::common::{
    confirm_delete, dash_if_empty, failure, format_age, print, print_table, profile_autoconnect,
    prompt_optional, prompt_secret, read_bounded_file, resolve_certificate, resolve_profile,
    setting_bool, setting_i32, setting_string, short_id, stdin_secret, stdin_secret_labeled,
};

const MAX_PRIVATE_KEY_BYTES: usize = 256 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum Profile {
    /// List saved networks, highest priority first.
    List,
    /// Show one saved network.
    Show { profile: String },
    /// Create a saved network.
    Add(ProfileArgs),
    /// Change a saved network.
    Edit {
        profile: String,
        #[command(flatten)]
        args: ProfileArgs,
        /// Remove the stored secret.
        #[arg(long, conflicts_with_all = ["ask_secret", "secret_stdin", "private_key_file", "private_key_password_stdin"])]
        clear_secret: bool,
    },
    /// Delete a saved network.
    Delete {
        profile: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ProfileArgs {
    #[arg(long)]
    pub(crate) ssid: Option<String>,
    /// `open`, `owe`, `wpa-personal`, `wpa3-personal`, `wpa-enterprise`, or
    /// `wpa3-enterprise`.
    #[arg(long)]
    pub(crate) security: Option<String>,
    #[arg(long)]
    pub(crate) name: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) priority: Option<i32>,
    #[arg(long)]
    pub(crate) hidden: Option<bool>,
    #[arg(long)]
    pub(crate) autoconnect: Option<bool>,
    /// Pin to one access point (`""` clears).
    #[arg(long)]
    pub(crate) bssid: Option<String>,
    /// `dhcp`, `static`, or `unmanaged`.
    #[arg(long)]
    pub(crate) l3: Option<String>,
    /// `auto` or `disabled` (with `--l3 dhcp`).
    #[arg(long)]
    pub(crate) ipv6: Option<String>,
    /// CIDR address (repeatable, with `--l3 static`).
    #[arg(long = "address")]
    pub(crate) addresses: Vec<String>,
    #[arg(long)]
    pub(crate) gateway4: Option<String>,
    #[arg(long)]
    pub(crate) gateway6: Option<String>,
    #[arg(long = "dns", conflicts_with = "clear_dns")]
    pub(crate) dns: Vec<String>,
    /// Clear configured static DNS servers.
    #[arg(long)]
    pub(crate) clear_dns: bool,
    #[arg(long = "domain", conflicts_with = "clear_domains")]
    pub(crate) domains: Vec<String>,
    /// Clear configured static DNS search domains.
    #[arg(long)]
    pub(crate) clear_domains: bool,
    /// 802.1X outer method: `tls`, `peap`, `ttls`, or `pwd`.
    #[arg(long)]
    pub(crate) eap: Option<String>,
    /// 802.1X outer identity (usually the user name or `user@realm`).
    #[arg(long)]
    pub(crate) identity: Option<String>,
    /// Optional outer identity sent before authentication.
    #[arg(long)]
    pub(crate) anonymous_identity: Option<String>,
    /// Inner method for PEAP/TTLS: `mschapv2`, `pap`, `chap`, `mschap`, or
    /// `gtc`.
    #[arg(long)]
    pub(crate) phase2: Option<String>,
    /// Imported CA certificate (id, id prefix, or name; `""` clears).
    #[arg(long)]
    pub(crate) ca_cert: Option<String>,
    /// Trust the host CA store (`true` or `false`).
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub(crate) system_ca: Option<bool>,
    /// Imported client certificate for EAP-TLS (id, id prefix, or name; `""` clears).
    #[arg(long)]
    pub(crate) client_cert: Option<String>,
    /// RADIUS server name suffix that must match (`""` clears).
    #[arg(long)]
    pub(crate) domain_suffix_match: Option<String>,
    /// Accepted RADIUS `SubjectAltName` pattern (repeatable).
    #[arg(long = "altsubject-match", conflicts_with = "clear_altsubject_match")]
    pub(crate) altsubject_match: Vec<String>,
    /// Clear configured RADIUS `SubjectAltName` match patterns.
    #[arg(long)]
    pub(crate) clear_altsubject_match: bool,
    /// PEM private key file for EAP-TLS; read locally, sent over D-Bus only.
    #[arg(long)]
    pub(crate) private_key_file: Option<String>,
    /// Read the private key's passphrase from the first line of stdin.
    #[arg(long, requires = "private_key_file", conflicts_with = "secret_stdin")]
    pub(crate) private_key_password_stdin: bool,
    /// Prompt for the passphrase on the terminal.
    #[arg(long)]
    pub(crate) ask_secret: bool,
    /// Read the passphrase from the first line of standard input.
    #[arg(long, conflicts_with = "ask_secret")]
    pub(crate) secret_stdin: bool,
}

pub(crate) async fn run(client: &Client, command: Profile, json: bool) -> zbus::Result<()> {
    match command {
        Profile::List => list(client, json).await,
        Profile::Show { profile } => show(client, &profile, json).await,
        Profile::Add(args) => add(client, args, json).await,
        Profile::Edit {
            profile,
            args,
            clear_secret,
        } => edit(client, &profile, args, clear_secret, json).await,
        Profile::Delete { profile, yes } => forget(client, &profile, yes, json).await,
    }
}

pub(crate) async fn forget(
    client: &Client,
    query: &str,
    yes: bool,
    json: bool,
) -> zbus::Result<()> {
    let path = resolve_profile(client, query).await?;
    let profile = client.profile(path).await?;
    let ssid = setting_string(&profile.settings().await?, "ssid");
    if !confirm_delete(&format!("Forget {ssid:?}? [y/N] "), yes)? {
        print(
            json,
            &json!({"ssid": ssid, "deleted": false, "cancelled": true}),
            || println!("cancelled"),
        );
        return Ok(());
    }
    profile.delete().await?;
    print(json, &json!({"ssid": ssid, "deleted": true}), || {
        println!("forgot {ssid:?}");
    });
    Ok(())
}

async fn list(client: &Client, json: bool) -> zbus::Result<()> {
    let mut rows = Vec::new();
    for profile in client.profiles().await? {
        rows.push(profile_json(&profile).await?);
    }
    rows.sort_by(|a, b| {
        b["priority"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["priority"].as_i64().unwrap_or(0))
            .then_with(|| {
                a["ssid"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["ssid"].as_str().unwrap_or(""))
            })
    });
    print(json, &Value::Array(rows.clone()), || {
        let table: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                vec![
                    short_id(row["id"].as_str().unwrap_or("")),
                    row["ssid"].as_str().unwrap_or("").to_owned(),
                    row["name"].as_str().unwrap_or("").to_owned(),
                    row["security"].as_str().unwrap_or("").to_owned(),
                    row["priority"].to_string(),
                    format_age(row["last_connected"].as_u64().unwrap_or(0)),
                    if row["autoconnect"].as_bool() == Some(false) {
                        "off".to_owned()
                    } else {
                        "on".to_owned()
                    },
                    if row["has_secret"].as_bool() == Some(true) {
                        "yes".to_owned()
                    } else {
                        "-".to_owned()
                    },
                ]
            })
            .collect();
        print_table(
            &[
                "ID",
                "SSID",
                "NAME",
                "SECURITY",
                "PRI",
                "LAST USED",
                "AUTO",
                "SECRET",
            ],
            &table,
        );
    });
    Ok(())
}

async fn show(client: &Client, query: &str, json: bool) -> zbus::Result<()> {
    let path = resolve_profile(client, query).await?;
    let profile = client.profile(path).await?;
    let value = profile_json(&profile).await?;
    print(json, &value, || print_profile(&value));
    Ok(())
}

async fn add(client: &Client, mut args: ProfileArgs, json: bool) -> zbus::Result<()> {
    resolve_certificate_args(client, &mut args).await?;
    if args.ssid.is_none() {
        return Err(failure("--ssid is required"));
    }
    let Some(security_str) = args.security.as_deref() else {
        return Err(failure(
            "--security is required (open|owe|wpa-personal|wpa3-personal|wpa-enterprise|wpa3-enterprise)",
        ));
    };
    let security =
        ProfileSecurity::parse(security_str).map_err(|error| failure(error.to_string()))?;
    let eap = parse_optional_eap(args.eap.as_deref())?;
    let secrets = read_secrets(&args, security, eap)?;
    let path = client
        .manager()
        .await?
        .add_profile(settings_from_args(&args), secrets)
        .await?;
    let id = client.profile(path).await?.id().await?;
    print(json, &json!({"id": id}), || println!("{id}"));
    Ok(())
}

async fn edit(
    client: &Client,
    query: &str,
    mut args: ProfileArgs,
    clear_secret: bool,
    json: bool,
) -> zbus::Result<()> {
    resolve_certificate_args(client, &mut args).await?;
    let path = resolve_profile(client, query).await?;
    let proxy = client.profile(path).await?;
    let existing_settings = proxy.settings().await?;
    let effective_security = match args.security.as_deref() {
        Some(value) => ProfileSecurity::parse(value).map_err(|error| failure(error.to_string()))?,
        None => ProfileSecurity::parse(&setting_string(&existing_settings, "security"))
            .unwrap_or(ProfileSecurity::Open),
    };
    let effective_eap = if let Some(value) = args.eap.as_deref() {
        Some(EapMethod::parse(value).map_err(|error| failure(error.to_string()))?)
    } else {
        let current = setting_string(&existing_settings, "enterprise.eap");
        if current.is_empty() {
            None
        } else {
            EapMethod::parse(&current).ok()
        }
    };
    let secrets = read_secrets_for_edit(&args, effective_security, effective_eap)?;
    let (action, value) = match (secrets, clear_secret) {
        (Some(bundle), _) => ("set", bundle),
        (None, true) => ("clear", SecretBundle::new()),
        (None, false) => ("keep", SecretBundle::new()),
    };
    let id = proxy.id().await?;
    proxy
        .update(settings_from_args(&args), action, value)
        .await?;
    print(json, &json!({"id": id, "updated": true}), || {});
    Ok(())
}

fn parse_optional_eap(value: Option<&str>) -> zbus::Result<Option<EapMethod>> {
    value
        .map(|raw| EapMethod::parse(raw).map_err(|error| failure(error.to_string())))
        .transpose()
}

/// Reads credentials for `profile add`: a passphrase (skipped for EAP-TLS
/// unless explicitly requested) plus, for EAP-TLS, the private key file and
/// its optional passphrase.
fn read_secrets(
    args: &ProfileArgs,
    security: ProfileSecurity,
    eap: Option<EapMethod>,
) -> zbus::Result<SecretBundle> {
    let mut bundle = SecretBundle::new();
    let interactive = std::io::stdin().is_terminal();
    let needs_passphrase = security.needs_secret() && eap != Some(EapMethod::Tls);
    let passphrase = if args.secret_stdin {
        Some(stdin_secret()?)
    } else if args.ask_secret || (needs_passphrase && interactive) {
        Some(prompt_secret()?)
    } else {
        None
    };
    if let Some(passphrase) = passphrase {
        bundle.insert("passphrase".to_owned(), passphrase.as_str().to_owned());
    }
    if let Some(path) = &args.private_key_file {
        let key = read_bounded_file(path, MAX_PRIVATE_KEY_BYTES)?;
        if key.trim().is_empty() {
            return Err(failure(format!("{path} is empty")));
        }
        bundle.insert("private_key".to_owned(), key);
        let password = if args.private_key_password_stdin {
            Some(stdin_secret_labeled("private key passphrase")?)
        } else if interactive {
            prompt_optional("Private key passphrase (empty for none): ")?
        } else {
            None
        };
        if let Some(password) = password {
            bundle.insert(
                "private_key_password".to_owned(),
                password.as_str().to_owned(),
            );
        }
    }
    Ok(bundle)
}

/// Reads credentials for `profile edit` only when the caller explicitly asked
/// to supply them, so unrelated edits never wipe existing secrets.
fn read_secrets_for_edit(
    args: &ProfileArgs,
    effective_security: ProfileSecurity,
    effective_eap: Option<EapMethod>,
) -> zbus::Result<Option<SecretBundle>> {
    let asked = args.secret_stdin
        || args.ask_secret
        || args.private_key_file.is_some()
        || args.private_key_password_stdin;
    if !asked {
        return Ok(None);
    }
    // Never auto-prompt for an unrelated passphrase when only updating a key.
    let prompt_security = if args.ask_secret || args.secret_stdin {
        effective_security
    } else {
        ProfileSecurity::Open
    };
    let bundle = read_secrets(args, prompt_security, effective_eap)?;
    Ok((!bundle.is_empty()).then_some(bundle))
}

/// Rewrites `--ca-cert` / `--client-cert` references (id, id prefix, or name)
/// into the certificate ids the API expects.
async fn resolve_certificate_args(client: &Client, args: &mut ProfileArgs) -> zbus::Result<()> {
    for slot in [&mut args.ca_cert, &mut args.client_cert] {
        let Some(query) = slot.clone() else {
            continue;
        };
        if query.is_empty() {
            *slot = Some(String::new());
            continue;
        }
        let path = resolve_certificate(client, &query).await?;
        let id = client.certificate(path).await?.id().await?;
        *slot = Some(id);
    }
    Ok(())
}

pub(crate) fn settings_from_args(args: &ProfileArgs) -> ProfileSettings {
    let mut settings: HashMap<String, OwnedVariant> = HashMap::new();
    let mut put = |key: &str, value: Variant<'_>| {
        settings.insert(
            key.to_owned(),
            OwnedVariant::try_from(value).expect("plain value"),
        );
    };
    let strings = |values: &[String]| Variant::from(values.to_vec());
    if let Some(value) = &args.ssid {
        put("ssid", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.security {
        put("security", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.name {
        put("name", Variant::from(value.as_str()));
    }
    if let Some(value) = args.priority {
        put("priority", Variant::from(value));
    }
    if let Some(value) = args.hidden {
        put("hidden", Variant::from(value));
    }
    if let Some(value) = args.autoconnect {
        put("autoconnect", Variant::from(value));
    }
    if let Some(value) = &args.bssid {
        put("bssid", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.l3 {
        put("l3", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.ipv6 {
        put("ipv6", Variant::from(value.as_str()));
    }
    if !args.addresses.is_empty() {
        put("addresses", strings(&args.addresses));
    }
    if let Some(value) = &args.gateway4 {
        put("gateway4", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.gateway6 {
        put("gateway6", Variant::from(value.as_str()));
    }
    if args.clear_dns {
        put("dns", Variant::from(Vec::<String>::new()));
    } else if !args.dns.is_empty() {
        put("dns", strings(&args.dns));
    }
    if args.clear_domains {
        put("domains", Variant::from(Vec::<String>::new()));
    } else if !args.domains.is_empty() {
        put("domains", strings(&args.domains));
    }
    apply_enterprise_args(args, &mut settings);
    settings
}

fn apply_enterprise_args(args: &ProfileArgs, settings: &mut ProfileSettings) {
    let mut put = |key: &str, value: Variant<'_>| {
        settings.insert(
            key.to_owned(),
            OwnedVariant::try_from(value).expect("plain value"),
        );
    };
    if let Some(value) = &args.eap {
        put("enterprise.eap", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.identity {
        put("enterprise.identity", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.anonymous_identity {
        put(
            "enterprise.anonymous_identity",
            Variant::from(value.as_str()),
        );
    }
    if let Some(value) = &args.phase2 {
        put("enterprise.phase2", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.ca_cert {
        put("enterprise.ca_cert", Variant::from(value.as_str()));
    }
    if let Some(value) = args.system_ca {
        put("enterprise.system_ca", Variant::from(value));
    }
    if let Some(value) = &args.client_cert {
        put("enterprise.client_cert", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.domain_suffix_match {
        put(
            "enterprise.domain_suffix_match",
            Variant::from(value.as_str()),
        );
    }
    if args.clear_altsubject_match {
        put(
            "enterprise.altsubject_match",
            Variant::from(Vec::<String>::new()),
        );
    } else if !args.altsubject_match.is_empty() {
        put(
            "enterprise.altsubject_match",
            Variant::from(args.altsubject_match.clone()),
        );
    }
}

async fn profile_json(profile: &ProfileProxy<'_>) -> zbus::Result<Value> {
    let settings = profile.settings().await?;
    let mut map = serde_json::Map::new();
    map.insert("id".into(), json!(profile.id().await?));
    let mut keys: Vec<&String> = settings.keys().collect();
    keys.sort();
    for key in keys {
        let value = settings[key]
            .try_clone()
            .map_err(|error| failure(error.to_string()))?;
        let value = match &*value {
            Variant::Str(value) => json!(value.as_str()),
            Variant::Bool(value) => json!(value),
            Variant::I32(value) => json!(value),
            Variant::Array(_) => json!(Vec::<String>::try_from(value).unwrap_or_default()),
            other => json!(other.to_string()),
        };
        map.insert(key.clone(), value);
    }
    map.insert("has_secret".into(), json!(profile.has_secret().await?));
    map.insert(
        "last_connected".into(),
        json!(profile.last_connected().await?),
    );
    map.insert("autoconnect".into(), json!(profile_autoconnect(&settings)));
    map.insert(
        "hidden".into(),
        json!(setting_bool(&settings, "hidden").unwrap_or(false)),
    );
    map.insert("ssid".into(), json!(setting_string(&settings, "ssid")));
    map.insert("name".into(), json!(setting_string(&settings, "name")));
    map.insert(
        "security".into(),
        json!(setting_string(&settings, "security")),
    );
    map.insert(
        "priority".into(),
        json!(setting_i32(&settings, "priority").unwrap_or(0)),
    );
    Ok(Value::Object(map))
}

fn print_profile(value: &Value) {
    println!("ID: {}", value["id"].as_str().unwrap_or(""));
    println!("SSID: {}", value["ssid"].as_str().unwrap_or(""));
    println!("Name: {}", value["name"].as_str().unwrap_or(""));
    println!("Security: {}", value["security"].as_str().unwrap_or(""));
    println!("Priority: {}", value["priority"]);
    println!(
        "Autoconnect: {}",
        if value["autoconnect"].as_bool() == Some(false) {
            "off"
        } else {
            "on"
        }
    );
    println!(
        "Hidden: {}",
        if value["hidden"].as_bool() == Some(true) {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "BSSID: {}",
        dash_if_empty(value["bssid"].as_str().unwrap_or(""))
    );
    println!("L3: {}", value["l3"].as_str().unwrap_or("dhcp"));
    print_l3_fields(value);
    print_enterprise_fields(value);
    println!(
        "Last connected: {} ({})",
        value["last_connected"],
        format_age(value["last_connected"].as_u64().unwrap_or(0))
    );
    println!(
        "Secret: {}",
        if value["has_secret"].as_bool() == Some(true) {
            "yes"
        } else {
            "no"
        }
    );
}

fn print_l3_fields(value: &Value) {
    for (label, key) in [
        ("IPv6", "ipv6"),
        ("Addresses", "addresses"),
        ("Gateway4", "gateway4"),
        ("Gateway6", "gateway6"),
        ("DNS", "dns"),
        ("Domains", "domains"),
    ] {
        let text = match &value[key] {
            Value::String(text) => text.clone(),
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        if !text.is_empty() {
            println!("{label}: {text}");
        }
    }
}

fn print_enterprise_fields(value: &Value) {
    let Some(eap) = value["enterprise.eap"].as_str() else {
        return;
    };
    if eap.is_empty() {
        return;
    }
    println!("Enterprise: EAP-{}", eap.to_ascii_uppercase());
    for (label, key) in [
        ("Identity", "enterprise.identity"),
        ("Anonymous identity", "enterprise.anonymous_identity"),
        ("Phase2", "enterprise.phase2"),
        ("CA certificate", "enterprise.ca_cert"),
        ("Client certificate", "enterprise.client_cert"),
        ("Domain suffix match", "enterprise.domain_suffix_match"),
    ] {
        let text = value[key].as_str().unwrap_or("");
        if !text.is_empty() {
            println!("{label}: {text}");
        }
    }
    if value["enterprise.system_ca"].as_bool() == Some(true) {
        println!("CA: system trust store");
    }
    let alt: Vec<&str> = value["enterprise.altsubject_match"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !alt.is_empty() {
        println!("SubjectAltName match: {}", alt.join(", "));
    }
}

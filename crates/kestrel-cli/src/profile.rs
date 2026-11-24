// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel profile`: saved Wi-Fi profile management.

use std::collections::HashMap;
use std::io::IsTerminal;

use clap::{Args, Subcommand, ValueEnum};
use kestrel_api::client::{Client, ProfileProxy};
use kestrel_api::{ProfileSettings, SecretBundle};
use kestrel_model::{EapMethod, ProfileSecurity};
use serde_json::{Value, json};
use zbus::{OwnedVariant, Variant};
use zeroize::Zeroizing;

use crate::common::{
    CliError, CliResult, confirm_delete, dash_if_empty, format_age, print, print_table,
    profile_autoconnect, prompt_optional, prompt_secret, read_bounded_file, resolve_certificate,
    resolve_profile, setting_bool, setting_i32, setting_string, short_id, stdin_secret,
    stdin_secret_labeled,
};

const MAX_PRIVATE_KEY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SecurityMode {
    Open,
    Owe,
    WpaPersonal,
    Wpa3Personal,
    WpaEnterprise,
    Wpa3Enterprise,
}

impl SecurityMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Owe => "owe",
            Self::WpaPersonal => "wpa-personal",
            Self::Wpa3Personal => "wpa3-personal",
            Self::WpaEnterprise => "wpa-enterprise",
            Self::Wpa3Enterprise => "wpa3-enterprise",
        }
    }

    pub(crate) const fn to_profile_security(self) -> ProfileSecurity {
        match self {
            Self::Open => ProfileSecurity::Open,
            Self::Owe => ProfileSecurity::Owe,
            Self::WpaPersonal => ProfileSecurity::WpaPersonal,
            Self::Wpa3Personal => ProfileSecurity::Wpa3Personal,
            Self::WpaEnterprise => ProfileSecurity::WpaEnterprise,
            Self::Wpa3Enterprise => ProfileSecurity::Wpa3Enterprise,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum L3Mode {
    Dhcp,
    Static,
    Unmanaged,
}

impl L3Mode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dhcp => "dhcp",
            Self::Static => "static",
            Self::Unmanaged => "unmanaged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Ipv6ModeArg {
    Auto,
    Disabled,
}

impl Ipv6ModeArg {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum EapMode {
    Tls,
    Peap,
    Ttls,
    Pwd,
}

impl EapMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Peap => "peap",
            Self::Ttls => "ttls",
            Self::Pwd => "pwd",
        }
    }

    pub(crate) const fn to_eap_method(self) -> EapMethod {
        match self {
            Self::Tls => EapMethod::Tls,
            Self::Peap => EapMethod::Peap,
            Self::Ttls => EapMethod::Ttls,
            Self::Pwd => EapMethod::Pwd,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Phase2Mode {
    Mschapv2,
    Pap,
    Chap,
    Mschap,
    Gtc,
}

impl Phase2Mode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Mschapv2 => "mschapv2",
            Self::Pap => "pap",
            Self::Chap => "chap",
            Self::Mschap => "mschap",
            Self::Gtc => "gtc",
        }
    }
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Profile {
    /// List saved networks, highest priority first.
    List,
    /// Show one saved network.
    Show {
        /// Profile UUID, 8+ char prefix, name, or SSID.
        profile: String,
    },
    /// Create a saved network profile.
    Add(ProfileAddArgs),
    /// Modify a saved network profile.
    Edit(ProfileEditArgs),
    /// Delete a saved network profile and its sealed secret.
    Delete {
        /// Profile UUID, 8+ char prefix, name, or SSID.
        profile: String,
        /// Do not ask for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ProfileAddArgs {
    /// Network SSID (1-32 UTF-8 bytes).
    pub(crate) ssid: String,
    /// Security mode.
    #[arg(long, value_enum)]
    pub(crate) security: SecurityMode,

    /// Human-readable label shown in listings.
    #[arg(long, help_heading = "General Options")]
    pub(crate) name: Option<String>,
    /// Autoconnect priority (higher wins; allows negative values).
    #[arg(long, allow_hyphen_values = true, help_heading = "General Options")]
    pub(crate) priority: Option<i32>,
    /// Mark the network as hidden (non-broadcasting SSID).
    #[arg(long, help_heading = "General Options")]
    pub(crate) hidden: bool,
    /// Disable automatic connection to this profile.
    #[arg(long, help_heading = "General Options")]
    pub(crate) no_autoconnect: bool,
    /// Pin to a specific access point BSSID.
    #[arg(long, help_heading = "General Options")]
    pub(crate) bssid: Option<String>,

    /// Layer-3 address configuration mode.
    #[arg(long, value_enum, help_heading = "L3 / IP Options")]
    pub(crate) l3: Option<L3Mode>,
    /// IPv6 mode (with `--l3 dhcp`).
    #[arg(long, value_enum, help_heading = "L3 / IP Options")]
    pub(crate) ipv6: Option<Ipv6ModeArg>,
    /// Static CIDR address (repeatable, with `--l3 static`).
    #[arg(long = "address", help_heading = "L3 / IP Options")]
    pub(crate) addresses: Vec<String>,
    /// Static IPv4 default gateway.
    #[arg(long, help_heading = "L3 / IP Options")]
    pub(crate) gateway4: Option<String>,
    /// Static IPv6 default gateway.
    #[arg(long, help_heading = "L3 / IP Options")]
    pub(crate) gateway6: Option<String>,
    /// Static DNS server IP (repeatable).
    #[arg(long = "dns", help_heading = "L3 / IP Options")]
    pub(crate) dns: Vec<String>,
    /// Static DNS search domain (repeatable).
    #[arg(long = "domain", help_heading = "L3 / IP Options")]
    pub(crate) domains: Vec<String>,

    /// 802.1X outer EAP method.
    #[arg(long, value_enum, help_heading = "802.1X Enterprise Options")]
    pub(crate) eap: Option<EapMode>,
    /// 802.1X outer identity (usually `user` or `user@realm`).
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) identity: Option<String>,
    /// Optional outer identity sent before inner authentication.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) anonymous_identity: Option<String>,
    /// Inner authentication method for PEAP/TTLS.
    #[arg(long, value_enum, help_heading = "802.1X Enterprise Options")]
    pub(crate) phase2: Option<Phase2Mode>,
    /// Imported CA certificate (id, prefix, or name).
    #[arg(
        long,
        conflicts_with = "system_ca",
        help_heading = "802.1X Enterprise Options"
    )]
    pub(crate) ca_cert: Option<String>,
    /// Trust the host system CA store.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) system_ca: bool,
    /// Imported client certificate for EAP-TLS (id, prefix, or name).
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) client_cert: Option<String>,
    /// Required RADIUS server certificate domain suffix.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) domain_suffix_match: Option<String>,
    /// Accepted RADIUS `SubjectAltName` pattern (repeatable).
    #[arg(long = "altsubject-match", help_heading = "802.1X Enterprise Options")]
    pub(crate) altsubject_match: Vec<String>,

    /// PEM private key file for EAP-TLS (read locally, sealed in daemon).
    #[arg(long, help_heading = "Credentials")]
    pub(crate) private_key_file: Option<String>,
    /// Read the private key passphrase from the first line of stdin.
    #[arg(
        long,
        requires = "private_key_file",
        conflicts_with = "secret_stdin",
        help_heading = "Credentials"
    )]
    pub(crate) private_key_password_stdin: bool,
    /// Prompt for the passphrase on the terminal.
    #[arg(long, help_heading = "Credentials")]
    pub(crate) ask_secret: bool,
    /// Read the passphrase from the first line of standard input.
    #[arg(long, conflicts_with = "ask_secret", help_heading = "Credentials")]
    pub(crate) secret_stdin: bool,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ProfileEditArgs {
    /// Profile UUID, 8+ char prefix, name, or SSID.
    pub(crate) profile: String,

    /// Change the network SSID.
    #[arg(long, help_heading = "General Options")]
    pub(crate) ssid: Option<String>,
    /// Change the security mode (clears any kept secret).
    #[arg(long, value_enum, help_heading = "General Options")]
    pub(crate) security: Option<SecurityMode>,
    /// Change the human-readable label.
    #[arg(long, help_heading = "General Options")]
    pub(crate) name: Option<String>,
    /// Change autoconnect priority (higher wins; allows negative values).
    #[arg(long, allow_hyphen_values = true, help_heading = "General Options")]
    pub(crate) priority: Option<i32>,
    /// Set whether the network is hidden (`true` or `false`).
    #[arg(long, help_heading = "General Options")]
    pub(crate) hidden: Option<bool>,
    /// Set whether autoconnect is enabled (`true` or `false`).
    #[arg(long, help_heading = "General Options")]
    pub(crate) autoconnect: Option<bool>,
    /// Pin to a specific access point BSSID.
    #[arg(long, conflicts_with = "clear_bssid", help_heading = "General Options")]
    pub(crate) bssid: Option<String>,
    /// Clear the pinned BSSID.
    #[arg(long, help_heading = "General Options")]
    pub(crate) clear_bssid: bool,

    /// Layer-3 address configuration mode.
    #[arg(long, value_enum, help_heading = "L3 / IP Options")]
    pub(crate) l3: Option<L3Mode>,
    /// IPv6 mode (with `--l3 dhcp`).
    #[arg(long, value_enum, help_heading = "L3 / IP Options")]
    pub(crate) ipv6: Option<Ipv6ModeArg>,
    /// Static CIDR address (repeatable, replaces existing list).
    #[arg(long = "address", help_heading = "L3 / IP Options")]
    pub(crate) addresses: Vec<String>,
    /// Static IPv4 default gateway.
    #[arg(
        long,
        conflicts_with = "clear_gateway4",
        help_heading = "L3 / IP Options"
    )]
    pub(crate) gateway4: Option<String>,
    /// Clear static IPv4 default gateway.
    #[arg(long, help_heading = "L3 / IP Options")]
    pub(crate) clear_gateway4: bool,
    /// Static IPv6 default gateway.
    #[arg(
        long,
        conflicts_with = "clear_gateway6",
        help_heading = "L3 / IP Options"
    )]
    pub(crate) gateway6: Option<String>,
    /// Clear static IPv6 default gateway.
    #[arg(long, help_heading = "L3 / IP Options")]
    pub(crate) clear_gateway6: bool,
    /// Static DNS server IP (repeatable, replaces existing list).
    #[arg(
        long = "dns",
        conflicts_with = "clear_dns",
        help_heading = "L3 / IP Options"
    )]
    pub(crate) dns: Vec<String>,
    /// Clear configured static DNS servers.
    #[arg(long, help_heading = "L3 / IP Options")]
    pub(crate) clear_dns: bool,
    /// Static DNS search domain (repeatable, replaces existing list).
    #[arg(
        long = "domain",
        conflicts_with = "clear_domains",
        help_heading = "L3 / IP Options"
    )]
    pub(crate) domains: Vec<String>,
    /// Clear configured static DNS search domains.
    #[arg(long, help_heading = "L3 / IP Options")]
    pub(crate) clear_domains: bool,

    /// 802.1X outer EAP method (clears any kept secret when changed).
    #[arg(long, value_enum, help_heading = "802.1X Enterprise Options")]
    pub(crate) eap: Option<EapMode>,
    /// 802.1X outer identity.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) identity: Option<String>,
    /// Optional outer identity sent before inner authentication.
    #[arg(
        long,
        conflicts_with = "clear_anonymous_identity",
        help_heading = "802.1X Enterprise Options"
    )]
    pub(crate) anonymous_identity: Option<String>,
    /// Clear the anonymous identity.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) clear_anonymous_identity: bool,
    /// Inner authentication method for PEAP/TTLS.
    #[arg(
        long,
        value_enum,
        conflicts_with = "clear_phase2",
        help_heading = "802.1X Enterprise Options"
    )]
    pub(crate) phase2: Option<Phase2Mode>,
    /// Clear the phase2 inner authentication method.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) clear_phase2: bool,
    /// Imported CA certificate (id, prefix, or name).
    #[arg(
        long,
        conflicts_with = "clear_ca_cert",
        help_heading = "802.1X Enterprise Options"
    )]
    pub(crate) ca_cert: Option<String>,
    /// Clear the imported CA certificate reference.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) clear_ca_cert: bool,
    /// Trust the host system CA store (`true` or `false`).
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) system_ca: Option<bool>,
    /// Imported client certificate for EAP-TLS (id, prefix, or name).
    #[arg(
        long,
        conflicts_with = "clear_client_cert",
        help_heading = "802.1X Enterprise Options"
    )]
    pub(crate) client_cert: Option<String>,
    /// Clear the imported client certificate reference.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) clear_client_cert: bool,
    /// Required RADIUS server certificate domain suffix.
    #[arg(
        long,
        conflicts_with = "clear_domain_suffix_match",
        help_heading = "802.1X Enterprise Options"
    )]
    pub(crate) domain_suffix_match: Option<String>,
    /// Clear the RADIUS server domain suffix match.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) clear_domain_suffix_match: bool,
    /// Accepted RADIUS `SubjectAltName` pattern (repeatable, replaces existing list).
    #[arg(
        long = "altsubject-match",
        conflicts_with = "clear_altsubject_match",
        help_heading = "802.1X Enterprise Options"
    )]
    pub(crate) altsubject_match: Vec<String>,
    /// Clear configured RADIUS `SubjectAltName` match patterns.
    #[arg(long, help_heading = "802.1X Enterprise Options")]
    pub(crate) clear_altsubject_match: bool,

    /// PEM private key file for EAP-TLS (read locally, sealed in daemon).
    #[arg(long, help_heading = "Credentials")]
    pub(crate) private_key_file: Option<String>,
    /// Read the private key passphrase from the first line of stdin.
    #[arg(
        long,
        requires = "private_key_file",
        conflicts_with = "secret_stdin",
        help_heading = "Credentials"
    )]
    pub(crate) private_key_password_stdin: bool,
    /// Prompt for a new passphrase on the terminal.
    #[arg(long, help_heading = "Credentials")]
    pub(crate) ask_secret: bool,
    /// Read a new passphrase from the first line of standard input.
    #[arg(long, conflicts_with = "ask_secret", help_heading = "Credentials")]
    pub(crate) secret_stdin: bool,
    /// Remove the stored secret.
    #[arg(
        long,
        conflicts_with_all = [
            "ask_secret",
            "secret_stdin",
            "private_key_file",
            "private_key_password_stdin",
        ],
        help_heading = "Credentials"
    )]
    pub(crate) clear_secret: bool,
}

pub(crate) async fn run(client: &Client, command: Profile, json: bool) -> CliResult<()> {
    match command {
        Profile::List => list(client, json).await,
        Profile::Show { profile } => show(client, &profile, json).await,
        Profile::Add(args) => add(client, args, json).await,
        Profile::Edit(args) => edit(client, args, json).await,
        Profile::Delete { profile, yes } => delete(client, &profile, yes, json).await,
    }
}

async fn delete(client: &Client, query: &str, yes: bool, json: bool) -> CliResult<()> {
    let path = resolve_profile(client, query).await?;
    let profile = client.profile(path).await?;
    let ssid = setting_string(&profile.settings().await?, "ssid");
    if !confirm_delete(&format!("Delete profile {ssid:?}? [y/N] "), yes)? {
        print(
            json,
            &json!({"ssid": ssid, "deleted": false, "cancelled": true}),
            || eprintln!("cancelled"),
        );
        return Ok(());
    }
    profile.delete().await?;
    print(json, &json!({"ssid": ssid, "deleted": true}), || {
        println!("deleted profile {ssid:?}");
    });
    Ok(())
}

async fn list(client: &Client, json: bool) -> CliResult<()> {
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
            Some("No saved profiles."),
        );
    });
    Ok(())
}

async fn show(client: &Client, query: &str, json: bool) -> CliResult<()> {
    let path = resolve_profile(client, query).await?;
    let profile = client.profile(path).await?;
    let value = profile_json(&profile).await?;
    print(json, &value, || print_profile(&value));
    Ok(())
}

async fn add(client: &Client, mut args: ProfileAddArgs, json: bool) -> CliResult<()> {
    resolve_cert_slots(client, &mut args.ca_cert, &mut args.client_cert).await?;
    let security = args.security.to_profile_security();
    let eap = args.eap.map(EapMode::to_eap_method);
    let secrets = read_secrets(
        &SecretInput {
            ask_secret: args.ask_secret,
            secret_stdin: args.secret_stdin,
            private_key_file: args.private_key_file.as_deref(),
            private_key_password_stdin: args.private_key_password_stdin,
        },
        security,
        eap,
    )?;
    let path = client
        .manager()
        .await?
        .add_profile(settings_from_add_args(&args), secrets)
        .await?;
    let id = client.profile(path).await?.id().await?;
    print(json, &json!({"id": id}), || println!("{id}"));
    Ok(())
}

async fn edit(client: &Client, mut args: ProfileEditArgs, json: bool) -> CliResult<()> {
    resolve_cert_slots(client, &mut args.ca_cert, &mut args.client_cert).await?;
    let path = resolve_profile(client, &args.profile).await?;
    let proxy = client.profile(path).await?;
    let existing_settings = proxy.settings().await?;
    let effective_security = match args.security {
        Some(mode) => mode.to_profile_security(),
        None => ProfileSecurity::parse(&setting_string(&existing_settings, "security"))
            .unwrap_or(ProfileSecurity::Open),
    };
    let effective_eap = if let Some(mode) = args.eap {
        Some(mode.to_eap_method())
    } else {
        let current = setting_string(&existing_settings, "enterprise.eap");
        if current.is_empty() {
            None
        } else {
            EapMethod::parse(&current).ok()
        }
    };

    let asked = args.secret_stdin
        || args.ask_secret
        || args.private_key_file.is_some()
        || args.private_key_password_stdin;
    let secrets = if asked {
        let prompt_security = if args.ask_secret || args.secret_stdin {
            effective_security
        } else {
            ProfileSecurity::Open
        };
        let bundle = read_secrets(
            &SecretInput {
                ask_secret: args.ask_secret,
                secret_stdin: args.secret_stdin,
                private_key_file: args.private_key_file.as_deref(),
                private_key_password_stdin: args.private_key_password_stdin,
            },
            prompt_security,
            effective_eap,
        )?;
        (!bundle.is_empty()).then_some(bundle)
    } else {
        None
    };

    let (action, value) = match (secrets, args.clear_secret) {
        (Some(bundle), _) => ("set", bundle),
        (None, true) => ("clear", SecretBundle::new()),
        (None, false) => ("keep", SecretBundle::new()),
    };
    let id = proxy.id().await?;
    proxy
        .update(settings_from_edit_args(&args), action, value)
        .await?;
    print(json, &json!({"id": id, "updated": true}), || {
        println!("updated profile {}", short_id(&id));
    });
    Ok(())
}

struct SecretInput<'a> {
    ask_secret: bool,
    secret_stdin: bool,
    private_key_file: Option<&'a str>,
    private_key_password_stdin: bool,
}

fn read_secrets(
    input: &SecretInput<'_>,
    security: ProfileSecurity,
    eap: Option<EapMethod>,
) -> CliResult<SecretBundle> {
    let mut bundle = SecretBundle::new();
    let interactive = std::io::stdin().is_terminal();
    let needs_passphrase = security.needs_secret() && eap != Some(EapMethod::Tls);
    let passphrase = if input.secret_stdin {
        Some(stdin_secret()?)
    } else if input.ask_secret || (needs_passphrase && interactive) {
        Some(prompt_secret()?)
    } else {
        None
    };
    if let Some(passphrase) = passphrase {
        bundle.insert("passphrase".to_owned(), passphrase.as_str().to_owned());
    }
    if let Some(path) = input.private_key_file {
        let key = Zeroizing::new(read_bounded_file(path, MAX_PRIVATE_KEY_BYTES)?);
        if key.trim().is_empty() {
            return Err(CliError::runtime(format!("{path} is empty")));
        }
        bundle.insert("private_key".to_owned(), key.as_str().to_owned());
        let password = if input.private_key_password_stdin {
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

async fn resolve_cert_slots(
    client: &Client,
    ca_cert: &mut Option<String>,
    client_cert: &mut Option<String>,
) -> CliResult<()> {
    for slot in [ca_cert, client_cert] {
        let Some(query) = slot.clone() else {
            continue;
        };
        let path = resolve_certificate(client, &query).await?;
        let id = client.certificate(path).await?.id().await?;
        *slot = Some(id);
    }
    Ok(())
}

fn put_setting(settings: &mut ProfileSettings, key: &str, value: Variant<'_>) {
    settings.insert(
        key.to_owned(),
        OwnedVariant::try_from(value).expect("plain value"),
    );
}

pub(crate) fn settings_from_add_args(args: &ProfileAddArgs) -> ProfileSettings {
    let mut settings: ProfileSettings = HashMap::new();
    put_setting(&mut settings, "ssid", Variant::from(args.ssid.as_str()));
    put_setting(
        &mut settings,
        "security",
        Variant::from(args.security.as_str()),
    );
    if let Some(value) = &args.name {
        put_setting(&mut settings, "name", Variant::from(value.as_str()));
    }
    if let Some(value) = args.priority {
        put_setting(&mut settings, "priority", Variant::from(value));
    }
    if args.hidden {
        put_setting(&mut settings, "hidden", Variant::from(true));
    }
    if args.no_autoconnect {
        put_setting(&mut settings, "autoconnect", Variant::from(false));
    }
    if let Some(value) = &args.bssid {
        put_setting(&mut settings, "bssid", Variant::from(value.as_str()));
    }
    apply_add_l3(args, &mut settings);
    apply_add_enterprise(args, &mut settings);
    settings
}

fn apply_add_l3(args: &ProfileAddArgs, settings: &mut ProfileSettings) {
    if let Some(value) = args.l3 {
        put_setting(settings, "l3", Variant::from(value.as_str()));
    }
    if let Some(value) = args.ipv6 {
        put_setting(settings, "ipv6", Variant::from(value.as_str()));
    }
    if !args.addresses.is_empty() {
        put_setting(settings, "addresses", Variant::from(args.addresses.clone()));
    }
    if let Some(value) = &args.gateway4 {
        put_setting(settings, "gateway4", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.gateway6 {
        put_setting(settings, "gateway6", Variant::from(value.as_str()));
    }
    if !args.dns.is_empty() {
        put_setting(settings, "dns", Variant::from(args.dns.clone()));
    }
    if !args.domains.is_empty() {
        put_setting(settings, "domains", Variant::from(args.domains.clone()));
    }
}

fn apply_add_enterprise(args: &ProfileAddArgs, settings: &mut ProfileSettings) {
    if let Some(value) = args.eap {
        put_setting(settings, "enterprise.eap", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.identity {
        put_setting(
            settings,
            "enterprise.identity",
            Variant::from(value.as_str()),
        );
    }
    if let Some(value) = &args.anonymous_identity {
        put_setting(
            settings,
            "enterprise.anonymous_identity",
            Variant::from(value.as_str()),
        );
    }
    if let Some(value) = args.phase2 {
        put_setting(settings, "enterprise.phase2", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.ca_cert {
        put_setting(
            settings,
            "enterprise.ca_cert",
            Variant::from(value.as_str()),
        );
    }
    if args.system_ca {
        put_setting(settings, "enterprise.system_ca", Variant::from(true));
    }
    if let Some(value) = &args.client_cert {
        put_setting(
            settings,
            "enterprise.client_cert",
            Variant::from(value.as_str()),
        );
    }
    if let Some(value) = &args.domain_suffix_match {
        put_setting(
            settings,
            "enterprise.domain_suffix_match",
            Variant::from(value.as_str()),
        );
    }
    if !args.altsubject_match.is_empty() {
        put_setting(
            settings,
            "enterprise.altsubject_match",
            Variant::from(args.altsubject_match.clone()),
        );
    }
}

pub(crate) fn settings_from_edit_args(args: &ProfileEditArgs) -> ProfileSettings {
    let mut settings: ProfileSettings = HashMap::new();
    if let Some(value) = &args.ssid {
        put_setting(&mut settings, "ssid", Variant::from(value.as_str()));
    }
    if let Some(value) = args.security {
        put_setting(&mut settings, "security", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.name {
        put_setting(&mut settings, "name", Variant::from(value.as_str()));
    }
    if let Some(value) = args.priority {
        put_setting(&mut settings, "priority", Variant::from(value));
    }
    if let Some(value) = args.hidden {
        put_setting(&mut settings, "hidden", Variant::from(value));
    }
    if let Some(value) = args.autoconnect {
        put_setting(&mut settings, "autoconnect", Variant::from(value));
    }
    if args.clear_bssid {
        put_setting(&mut settings, "bssid", Variant::from(""));
    } else if let Some(value) = &args.bssid {
        put_setting(&mut settings, "bssid", Variant::from(value.as_str()));
    }
    apply_edit_l3(args, &mut settings);
    apply_edit_enterprise(args, &mut settings);
    settings
}

fn apply_edit_l3(args: &ProfileEditArgs, settings: &mut ProfileSettings) {
    if let Some(value) = args.l3 {
        put_setting(settings, "l3", Variant::from(value.as_str()));
    }
    if let Some(value) = args.ipv6 {
        put_setting(settings, "ipv6", Variant::from(value.as_str()));
    }
    if !args.addresses.is_empty() {
        put_setting(settings, "addresses", Variant::from(args.addresses.clone()));
    }
    if args.clear_gateway4 {
        put_setting(settings, "gateway4", Variant::from(""));
    } else if let Some(value) = &args.gateway4 {
        put_setting(settings, "gateway4", Variant::from(value.as_str()));
    }
    if args.clear_gateway6 {
        put_setting(settings, "gateway6", Variant::from(""));
    } else if let Some(value) = &args.gateway6 {
        put_setting(settings, "gateway6", Variant::from(value.as_str()));
    }
    if args.clear_dns {
        put_setting(settings, "dns", Variant::from(Vec::<String>::new()));
    } else if !args.dns.is_empty() {
        put_setting(settings, "dns", Variant::from(args.dns.clone()));
    }
    if args.clear_domains {
        put_setting(settings, "domains", Variant::from(Vec::<String>::new()));
    } else if !args.domains.is_empty() {
        put_setting(settings, "domains", Variant::from(args.domains.clone()));
    }
}

fn apply_edit_enterprise(args: &ProfileEditArgs, settings: &mut ProfileSettings) {
    if let Some(value) = args.eap {
        put_setting(settings, "enterprise.eap", Variant::from(value.as_str()));
    }
    if let Some(value) = &args.identity {
        put_setting(
            settings,
            "enterprise.identity",
            Variant::from(value.as_str()),
        );
    }
    if args.clear_anonymous_identity {
        put_setting(settings, "enterprise.anonymous_identity", Variant::from(""));
    } else if let Some(value) = &args.anonymous_identity {
        put_setting(
            settings,
            "enterprise.anonymous_identity",
            Variant::from(value.as_str()),
        );
    }
    if args.clear_phase2 {
        put_setting(settings, "enterprise.phase2", Variant::from(""));
    } else if let Some(value) = args.phase2 {
        put_setting(settings, "enterprise.phase2", Variant::from(value.as_str()));
    }
    if args.clear_ca_cert {
        put_setting(settings, "enterprise.ca_cert", Variant::from(""));
    } else if let Some(value) = &args.ca_cert {
        put_setting(
            settings,
            "enterprise.ca_cert",
            Variant::from(value.as_str()),
        );
    }
    if let Some(value) = args.system_ca {
        put_setting(settings, "enterprise.system_ca", Variant::from(value));
    }
    if args.clear_client_cert {
        put_setting(settings, "enterprise.client_cert", Variant::from(""));
    } else if let Some(value) = &args.client_cert {
        put_setting(
            settings,
            "enterprise.client_cert",
            Variant::from(value.as_str()),
        );
    }
    if args.clear_domain_suffix_match {
        put_setting(
            settings,
            "enterprise.domain_suffix_match",
            Variant::from(""),
        );
    } else if let Some(value) = &args.domain_suffix_match {
        put_setting(
            settings,
            "enterprise.domain_suffix_match",
            Variant::from(value.as_str()),
        );
    }
    if args.clear_altsubject_match {
        put_setting(
            settings,
            "enterprise.altsubject_match",
            Variant::from(Vec::<String>::new()),
        );
    } else if !args.altsubject_match.is_empty() {
        put_setting(
            settings,
            "enterprise.altsubject_match",
            Variant::from(args.altsubject_match.clone()),
        );
    }
}

async fn profile_json(profile: &ProfileProxy<'_>) -> CliResult<Value> {
    let settings = profile.settings().await?;
    let mut map = serde_json::Map::new();
    map.insert("id".into(), json!(profile.id().await?));
    let mut keys: Vec<&String> = settings.keys().collect();
    keys.sort();
    for key in keys {
        let value = settings[key]
            .try_clone()
            .map_err(|error| CliError::runtime(error.to_string()))?;
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

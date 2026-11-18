// SPDX-License-Identifier: LGPL-2.1-or-later

//! Profile settings as an `a{sv}` dictionary.
//!
//! | key           | type | meaning                                         |
//! |---------------|------|-------------------------------------------------|
//! | `name`        | s    | label (default: the SSID)                       |
//! | `ssid`        | s    | required on create                              |
//! | `security`    | s    | `open`, `owe`, `wpa-personal`, `wpa3-personal`, `wpa-enterprise`, `wpa3-enterprise` |
//! | `hidden`      | b    |                                                 |
//! | `autoconnect` | b    |                                                 |
//! | `priority`    | i    | higher wins                                     |
//! | `bssid`       | s    | `""` clears the pin                             |
//! | `l3`          | s    | `dhcp`, `static`, `unmanaged`                   |
//! | `ipv6`        | s    | `auto`, `disabled` (with `dhcp`)                |
//! | `addresses`   | as   | CIDR, with `static`                             |
//! | `gateway4`    | s    | with `static`; `""` for none                    |
//! | `gateway6`    | s    | with `static`; `""` for none                    |
//! | `dns`         | as   | with `static`                                   |
//! | `domains`     | as   | with `static`                                   |
//! | `enterprise.eap` | s | `tls`, `peap`, `ttls`, `pwd`                    |
//! | `enterprise.identity` | s | outer EAP identity                         |
//! | `enterprise.anonymous_identity` | s | optional outer identity        |
//! | `enterprise.phase2` | s | `mschapv2`, `pap`, `chap`, `mschap`, `gtc`   |
//! | `enterprise.ca_cert` | s | imported certificate UUID                 |
//! | `enterprise.system_ca` | b | trust host CA store                       |
//! | `enterprise.client_cert` | s | imported certificate UUID (EAP-TLS)   |
//! | `enterprise.domain_suffix_match` | s | RADIUS server domain match    |
//! | `enterprise.altsubject_match` | as | RADIUS `SubjectAltName` patterns    |
//!
//! Secrets never appear in this dictionary.

use std::collections::HashMap;

use kestrel_model::{
    CertId, EapMethod, EnterpriseConfig, HotspotConfig, HotspotSecurity, IpAddr, Ipv6Mode,
    L3Config, MacAddress, Phase2Auth, ProfileSecrets, ProfileSecurity, Secret, Ssid, StaticIp,
    WifiProfile,
};
use zbus::{OwnedVariant, Variant};

use crate::ApiError;

pub type ProfileSettings = HashMap<String, OwnedVariant>;
pub type HotspotSettings = HashMap<String, OwnedVariant>;
pub type SecretBundle = HashMap<String, String>;

const KEYS: &[&str] = &[
    "name",
    "ssid",
    "security",
    "hidden",
    "autoconnect",
    "priority",
    "bssid",
    "l3",
    "ipv6",
    "addresses",
    "gateway4",
    "gateway6",
    "dns",
    "domains",
    "enterprise.eap",
    "enterprise.identity",
    "enterprise.anonymous_identity",
    "enterprise.phase2",
    "enterprise.ca_cert",
    "enterprise.system_ca",
    "enterprise.client_cert",
    "enterprise.domain_suffix_match",
    "enterprise.altsubject_match",
];

fn get<T: TryFrom<OwnedVariant>>(
    settings: &ProfileSettings,
    key: &str,
) -> Result<Option<T>, ApiError> {
    match settings.get(key) {
        None => Ok(None),
        Some(value) => {
            let value = value
                .try_clone()
                .map_err(|e| ApiError::invalid(format!("{key}: {e}")))?;
            T::try_from(value)
                .map(Some)
                .map_err(|_| ApiError::invalid(format!("{key} has the wrong type")))
        }
    }
}

fn parse_list<T: std::str::FromStr>(key: &str, values: Vec<String>) -> Result<Vec<T>, ApiError>
where
    T::Err: std::fmt::Display,
{
    values
        .into_iter()
        .map(|v| {
            v.parse::<T>()
                .map_err(|e| ApiError::invalid(format!("{key}: {v:?}: {e}")))
        })
        .collect()
}

/// Applies `settings` on top of `base` (or a new profile when `None`).
/// The result is validated.
pub fn profile_from_settings(
    base: Option<WifiProfile>,
    settings: &ProfileSettings,
) -> Result<WifiProfile, ApiError> {
    if let Some(unknown) = settings.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(ApiError::invalid(format!("unknown setting {unknown:?}")));
    }
    let mut profile = if let Some(mut profile) = base {
        if let Some(ssid) = get::<String>(settings, "ssid")? {
            profile.ssid = Ssid::new(ssid).map_err(|e| ApiError::invalid(e.to_string()))?;
        }
        if let Some(security) = get::<String>(settings, "security")? {
            profile.security =
                ProfileSecurity::parse(&security).map_err(|e| ApiError::invalid(e.to_string()))?;
        }
        profile
    } else {
        let ssid: String =
            get(settings, "ssid")?.ok_or_else(|| ApiError::invalid("ssid is required"))?;
        let ssid = Ssid::new(ssid).map_err(|e| ApiError::invalid(e.to_string()))?;
        let security = match get::<String>(settings, "security")? {
            Some(s) => ProfileSecurity::parse(&s).map_err(|e| ApiError::invalid(e.to_string()))?,
            None => return Err(ApiError::invalid("security is required")),
        };
        WifiProfile::new(ssid, security)
    };
    if let Some(name) = get::<String>(settings, "name")? {
        profile.name = name;
    }
    if let Some(hidden) = get(settings, "hidden")? {
        profile.hidden = hidden;
    }
    if let Some(autoconnect) = get(settings, "autoconnect")? {
        profile.autoconnect = autoconnect;
    }
    if let Some(priority) = get(settings, "priority")? {
        profile.priority = priority;
    }
    if let Some(bssid) = get::<String>(settings, "bssid")? {
        profile.bssid = if bssid.is_empty() {
            None
        } else {
            Some(MacAddress::parse(&bssid).map_err(|e| ApiError::invalid(e.to_string()))?)
        };
    }
    apply_l3(&mut profile, settings)?;
    apply_enterprise(&mut profile, settings)?;
    profile
        .validate()
        .map_err(|e| ApiError::invalid(e.to_string()))?;
    Ok(profile)
}

fn opt_string(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.is_empty())
}

fn apply_enterprise(profile: &mut WifiProfile, settings: &ProfileSettings) -> Result<(), ApiError> {
    let touches_enterprise = settings.keys().any(|k| k.starts_with("enterprise."));
    if !profile.security.is_enterprise() {
        if touches_enterprise {
            return Err(ApiError::invalid(format!(
                "enterprise settings are not valid for {} networks",
                profile.security
            )));
        }
        profile.enterprise = None;
        return Ok(());
    }
    if !touches_enterprise && profile.enterprise.is_some() {
        return Ok(());
    }
    let current = profile.enterprise.clone();
    let eap = match get::<String>(settings, "enterprise.eap")? {
        Some(value) => EapMethod::parse(&value).map_err(|e| ApiError::invalid(e.to_string()))?,
        None => current
            .as_ref()
            .map(|c| c.eap)
            .ok_or_else(|| ApiError::invalid("enterprise.eap is required"))?,
    };
    let identity = match get::<String>(settings, "enterprise.identity")? {
        Some(value) => value,
        None => current
            .as_ref()
            .map(|c| c.identity.clone())
            .ok_or_else(|| ApiError::invalid("enterprise.identity is required"))?,
    };
    let anonymous_identity = match get::<String>(settings, "enterprise.anonymous_identity")? {
        Some(value) => opt_string(Some(value)),
        None => current.as_ref().and_then(|c| c.anonymous_identity.clone()),
    };
    let phase2 = match get::<String>(settings, "enterprise.phase2")? {
        Some(value) if value.is_empty() => None,
        Some(value) => {
            Some(Phase2Auth::parse(&value).map_err(|e| ApiError::invalid(e.to_string()))?)
        }
        None => current.as_ref().and_then(|c| c.phase2),
    };
    let ca_cert = match get::<String>(settings, "enterprise.ca_cert")? {
        Some(value) if value.is_empty() => None,
        Some(value) => Some(CertId::parse(&value).map_err(|e| ApiError::invalid(e.to_string()))?),
        None => current.as_ref().and_then(|c| c.ca_cert),
    };
    let system_ca = get::<bool>(settings, "enterprise.system_ca")?
        .unwrap_or_else(|| current.as_ref().is_some_and(|c| c.system_ca));
    let client_cert = match get::<String>(settings, "enterprise.client_cert")? {
        Some(value) if value.is_empty() => None,
        Some(value) => Some(CertId::parse(&value).map_err(|e| ApiError::invalid(e.to_string()))?),
        None => current.as_ref().and_then(|c| c.client_cert),
    };
    let domain_suffix_match = match get::<String>(settings, "enterprise.domain_suffix_match")? {
        Some(value) => opt_string(Some(value)),
        None => current.as_ref().and_then(|c| c.domain_suffix_match.clone()),
    };
    let altsubject_match = match get::<Vec<String>>(settings, "enterprise.altsubject_match")? {
        Some(list) => list,
        None => current
            .as_ref()
            .map(|c| c.altsubject_match.clone())
            .unwrap_or_default(),
    };
    profile.enterprise = Some(EnterpriseConfig {
        eap,
        identity,
        anonymous_identity,
        phase2,
        ca_cert,
        system_ca,
        client_cert,
        domain_suffix_match,
        altsubject_match,
    });
    Ok(())
}

/// Parses a `Hotspot.Start` `a{sv}` dictionary.
pub fn hotspot_from_settings(settings: &HotspotSettings) -> Result<HotspotConfig, ApiError> {
    const HOTSPOT_KEYS: &[&str] = &["ssid", "security", "frequency", "hidden"];
    if let Some(unknown) = settings
        .keys()
        .find(|k| !HOTSPOT_KEYS.contains(&k.as_str()))
    {
        return Err(ApiError::invalid(format!(
            "unknown hotspot setting {unknown:?}"
        )));
    }
    let ssid: String =
        get(settings, "ssid")?.ok_or_else(|| ApiError::invalid("ssid is required"))?;
    let ssid = Ssid::new(ssid).map_err(|e| ApiError::invalid(e.to_string()))?;
    let security = match get::<String>(settings, "security")? {
        Some(value) => {
            HotspotSecurity::parse(&value).map_err(|e| ApiError::invalid(e.to_string()))?
        }
        None => HotspotSecurity::WpaPersonal,
    };
    let frequency = match get::<u32>(settings, "frequency")? {
        Some(0) | None => None,
        Some(freq) => Some(freq),
    };
    let hidden = get::<bool>(settings, "hidden")?.unwrap_or(false);
    let config = HotspotConfig {
        ssid,
        security,
        frequency,
        hidden,
    };
    config
        .validate()
        .map_err(|e| ApiError::invalid(e.to_string()))?;
    Ok(config)
}

/// Parses a `ProfileSecrets` dictionary (`passphrase`, `private_key`, `private_key_password`).
pub fn secrets_from_bundle(bundle: &SecretBundle) -> Result<ProfileSecrets, ApiError> {
    const SECRET_KEYS: &[&str] = &["passphrase", "private_key", "private_key_password"];
    if let Some(unknown) = bundle.keys().find(|k| !SECRET_KEYS.contains(&k.as_str())) {
        return Err(ApiError::invalid(format!("unknown secret key {unknown:?}")));
    }
    Ok(ProfileSecrets {
        passphrase: bundle
            .get("passphrase")
            .filter(|v| !v.is_empty())
            .map(Secret::new),
        private_key: bundle
            .get("private_key")
            .filter(|v| !v.is_empty())
            .map(Secret::new),
        private_key_password: bundle
            .get("private_key_password")
            .filter(|v| !v.is_empty())
            .map(Secret::new),
    })
}

fn apply_l3(profile: &mut WifiProfile, settings: &ProfileSettings) -> Result<(), ApiError> {
    let method = get::<String>(settings, "l3")?;
    let touches_static = ["addresses", "gateway4", "gateway6", "dns", "domains"]
        .iter()
        .any(|k| settings.contains_key(*k));
    let method = method.unwrap_or_else(|| match &profile.l3 {
        L3Config::Dhcp { .. } => "dhcp".into(),
        L3Config::Static(_) => "static".into(),
        L3Config::Unmanaged => "unmanaged".into(),
    });
    match method.as_str() {
        "dhcp" => {
            if touches_static {
                return Err(ApiError::invalid("static settings require l3 = static"));
            }
            let current = match profile.l3 {
                L3Config::Dhcp { ipv6 } => ipv6,
                _ => Ipv6Mode::Auto,
            };
            let ipv6 = match get::<String>(settings, "ipv6")?.as_deref() {
                None => current,
                Some("auto") => Ipv6Mode::Auto,
                Some("disabled") => Ipv6Mode::Disabled,
                Some(other) => {
                    return Err(ApiError::invalid(format!("unknown ipv6 mode {other:?}")));
                }
            };
            profile.l3 = L3Config::Dhcp { ipv6 };
        }
        "static" => {
            if settings.contains_key("ipv6") {
                return Err(ApiError::invalid("ipv6 setting requires l3 = dhcp"));
            }
            let mut config = match &profile.l3 {
                L3Config::Static(config) => config.clone(),
                _ => StaticIp::default(),
            };
            if let Some(addresses) = get::<Vec<String>>(settings, "addresses")? {
                config.addresses = parse_list("addresses", addresses)?;
            }
            if let Some(gateway) = get::<String>(settings, "gateway4")? {
                config.gateway4 = if gateway.is_empty() {
                    None
                } else {
                    Some(
                        gateway
                            .parse()
                            .map_err(|e| ApiError::invalid(format!("gateway4: {e}")))?,
                    )
                };
            }
            if let Some(gateway) = get::<String>(settings, "gateway6")? {
                config.gateway6 = if gateway.is_empty() {
                    None
                } else {
                    Some(
                        gateway
                            .parse()
                            .map_err(|e| ApiError::invalid(format!("gateway6: {e}")))?,
                    )
                };
            }
            if let Some(dns) = get::<Vec<String>>(settings, "dns")? {
                config.dns = parse_list::<IpAddr>("dns", dns)?;
            }
            if let Some(domains) = get::<Vec<String>>(settings, "domains")? {
                config.domains = domains;
            }
            profile.l3 = L3Config::Static(config);
        }
        "unmanaged" => {
            if touches_static {
                return Err(ApiError::invalid("static settings require l3 = static"));
            }
            if settings.contains_key("ipv6") {
                return Err(ApiError::invalid("ipv6 setting requires l3 = dhcp"));
            }
            profile.l3 = L3Config::Unmanaged;
        }
        other => return Err(ApiError::invalid(format!("unknown l3 method {other:?}"))),
    }
    Ok(())
}

fn ov(value: Variant<'_>) -> OwnedVariant {
    OwnedVariant::try_from(value).expect("plain values convert")
}

/// The full settings of a profile (no secret).
pub fn settings_from_profile(profile: &WifiProfile) -> ProfileSettings {
    let mut s = ProfileSettings::new();
    s.insert("name".into(), ov(Variant::from(profile.name.clone())));
    s.insert(
        "ssid".into(),
        ov(Variant::from(profile.ssid.to_string_lossy())),
    );
    s.insert(
        "security".into(),
        ov(Variant::from(profile.security.as_str())),
    );
    s.insert("hidden".into(), ov(Variant::from(profile.hidden)));
    s.insert("autoconnect".into(), ov(Variant::from(profile.autoconnect)));
    s.insert("priority".into(), ov(Variant::from(profile.priority)));
    s.insert(
        "bssid".into(),
        ov(Variant::from(
            profile.bssid.map(|b| b.to_string()).unwrap_or_default(),
        )),
    );
    insert_l3(&mut s, &profile.l3);
    if let Some(ent) = &profile.enterprise {
        insert_enterprise(&mut s, ent);
    }
    s
}

fn insert_l3(s: &mut ProfileSettings, l3: &L3Config) {
    match l3 {
        L3Config::Dhcp { ipv6 } => {
            s.insert("l3".into(), ov(Variant::from("dhcp")));
            s.insert(
                "ipv6".into(),
                ov(Variant::from(match ipv6 {
                    Ipv6Mode::Auto => "auto",
                    Ipv6Mode::Disabled => "disabled",
                })),
            );
        }
        L3Config::Static(config) => {
            s.insert("l3".into(), ov(Variant::from("static")));
            let strings = |items: Vec<String>| ov(Variant::from(items));
            s.insert(
                "addresses".into(),
                strings(config.addresses.iter().map(ToString::to_string).collect()),
            );
            s.insert(
                "gateway4".into(),
                ov(Variant::from(
                    config.gateway4.map(|g| g.to_string()).unwrap_or_default(),
                )),
            );
            s.insert(
                "gateway6".into(),
                ov(Variant::from(
                    config.gateway6.map(|g| g.to_string()).unwrap_or_default(),
                )),
            );
            s.insert(
                "dns".into(),
                strings(config.dns.iter().map(ToString::to_string).collect()),
            );
            s.insert("domains".into(), strings(config.domains.clone()));
        }
        L3Config::Unmanaged => {
            s.insert("l3".into(), ov(Variant::from("unmanaged")));
        }
    }
}

fn insert_enterprise(s: &mut ProfileSettings, ent: &EnterpriseConfig) {
    s.insert("enterprise.eap".into(), ov(Variant::from(ent.eap.as_str())));
    s.insert(
        "enterprise.identity".into(),
        ov(Variant::from(ent.identity.clone())),
    );
    s.insert(
        "enterprise.anonymous_identity".into(),
        ov(Variant::from(
            ent.anonymous_identity.clone().unwrap_or_default(),
        )),
    );
    s.insert(
        "enterprise.phase2".into(),
        ov(Variant::from(ent.phase2.map_or("", Phase2Auth::as_str))),
    );
    s.insert(
        "enterprise.ca_cert".into(),
        ov(Variant::from(
            ent.ca_cert.map(|id| id.to_string()).unwrap_or_default(),
        )),
    );
    s.insert(
        "enterprise.system_ca".into(),
        ov(Variant::from(ent.system_ca)),
    );
    s.insert(
        "enterprise.client_cert".into(),
        ov(Variant::from(
            ent.client_cert.map(|id| id.to_string()).unwrap_or_default(),
        )),
    );
    s.insert(
        "enterprise.domain_suffix_match".into(),
        ov(Variant::from(
            ent.domain_suffix_match.clone().unwrap_or_default(),
        )),
    );
    s.insert(
        "enterprise.altsubject_match".into(),
        ov(Variant::from(ent.altsubject_match.clone())),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, Variant<'_>)]) -> ProfileSettings {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), ov(v.clone())))
            .collect()
    }

    #[test]
    fn creates_and_round_trips() {
        let created = profile_from_settings(
            None,
            &settings(&[
                ("ssid", Variant::from("home")),
                ("security", Variant::from("wpa-personal")),
                ("priority", Variant::from(5i32)),
                ("l3", Variant::from("static")),
                ("addresses", Variant::from(vec!["192.0.2.10/24".to_owned()])),
                ("gateway4", Variant::from("192.0.2.1")),
            ]),
        )
        .unwrap();
        assert_eq!(created.priority, 5);
        let again =
            profile_from_settings(Some(created.clone()), &settings_from_profile(&created)).unwrap();
        assert_eq!(again, created);
    }

    #[test]
    fn rejects_unknown_keys_bad_types_and_inconsistent_l3() {
        let base = profile_from_settings(
            None,
            &settings(&[
                ("ssid", Variant::from("x")),
                ("security", Variant::from("open")),
            ]),
        )
        .unwrap();
        for bad in [
            settings(&[("psk", Variant::from("secret"))]),
            settings(&[("priority", Variant::from("high"))]),
            settings(&[("dns", Variant::from(vec!["1.1.1.1".to_owned()]))]),
            settings(&[("l3", Variant::from("static"))]),
            settings(&[("security", Variant::from("wep"))]),
        ] {
            assert!(
                profile_from_settings(Some(base.clone()), &bad).is_err(),
                "{bad:?}"
            );
        }
    }
}

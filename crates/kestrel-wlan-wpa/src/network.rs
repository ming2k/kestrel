// SPDX-License-Identifier: LGPL-2.1-or-later

//! Translation of association and SoftAP requests into `wpa_supplicant`
//! network blocks, and BSS security classification.

use std::collections::HashMap;

use kestrel_model::{HotspotSecurity, ProfileSecurity, Security};
use kestrel_ports::ap::ApStartRequest;
use kestrel_ports::wlan::ConnectRequest;
use kestrel_ports::{PortError, PortResult};
use zbus::Variant as Value;

/// Every network block Kestrel adds carries this `id_str`, so a sweep can
/// find them after a crash without touching anyone else's.
pub(crate) const OWNER_TAG: &str = "kestrel";

/// Blob names uploaded via `AddBlob` for a single association.
#[derive(Debug, Default)]
pub(crate) struct BlobRefs {
    pub(crate) ca_cert: Option<String>,
    pub(crate) client_cert: Option<String>,
    pub(crate) private_key: Option<String>,
}

fn select_key_mgmt(supported: &[String], candidates: &[&str]) -> String {
    let matched: Vec<&str> = candidates
        .iter()
        .copied()
        .filter(|suite| {
            supported.is_empty() || supported.iter().any(|s| s.eq_ignore_ascii_case(suite))
        })
        .collect();
    if matched.is_empty() {
        candidates.join(" ")
    } else {
        matched.join(" ")
    }
}

fn insert_enterprise_args(
    args: &mut HashMap<&'static str, Value<'static>>,
    request: &ConnectRequest,
    blobs: &BlobRefs,
    supported_key_mgmt: &[String],
    system_ca: Option<&'static str>,
) -> PortResult<()> {
    let (candidates, pmf): (&[&str], u32) = if request.security == ProfileSecurity::Wpa3Enterprise {
        (&["WPA-EAP-SHA256", "WPA-EAP-SUITE-B-192"], 2)
    } else {
        (&["WPA-EAP", "WPA-EAP-SHA256"], 1)
    };
    args.insert(
        "key_mgmt",
        Value::from(select_key_mgmt(supported_key_mgmt, candidates)),
    );
    args.insert("ieee80211w", Value::from(pmf));
    if let Some(ent) = &request.enterprise {
        let cfg = &ent.config;
        args.insert("eap", Value::from(cfg.eap.wpa_supplicant_name()));
        args.insert("identity", Value::from(cfg.identity.clone()));
        if let Some(anon) = &cfg.anonymous_identity {
            args.insert("anonymous_identity", Value::from(anon.clone()));
        }
        if let Some(phase2) = cfg.phase2 {
            args.insert("phase2", Value::from(phase2.wpa_supplicant_phase2()));
        }
        if let Some(blob) = &blobs.ca_cert {
            args.insert("ca_cert", Value::from(format!("blob://{blob}")));
        } else if cfg.system_ca {
            let path = system_ca.ok_or_else(|| {
                PortError::Unavailable(
                    "system_ca is enabled but no system CA certificate bundle was found".to_owned(),
                )
            })?;
            args.insert("ca_cert", Value::from(path));
        }
        if let Some(blob) = &blobs.client_cert {
            args.insert("client_cert", Value::from(format!("blob://{blob}")));
        }
        if let Some(blob) = &blobs.private_key {
            args.insert("private_key", Value::from(format!("blob://{blob}")));
        }
        if let Some(domain) = &cfg.domain_suffix_match {
            args.insert("domain_suffix_match", Value::from(domain.clone()));
        }
        if !cfg.altsubject_match.is_empty() {
            args.insert(
                "altsubject_match",
                Value::from(cfg.altsubject_match.join(";")),
            );
        }
    }
    if let Some(pass) = &request.secrets.passphrase {
        args.insert("password", Value::from(pass.expose().to_owned()));
    }
    if let Some(key_pw) = &request.secrets.private_key_password {
        args.insert(
            "private_key_passwd",
            Value::from(key_pw.expose().to_owned()),
        );
    }
    Ok(())
}

/// The `AddNetwork` argument dictionary for station association.
pub(crate) fn network_args(
    request: &ConnectRequest,
    blobs: &BlobRefs,
    supported_key_mgmt: &[String],
    system_ca: Option<&'static str>,
) -> PortResult<HashMap<&'static str, Value<'static>>> {
    let mut args: HashMap<&'static str, Value<'static>> = HashMap::new();
    args.insert("ssid", Value::from(request.ssid.as_bytes().to_vec()));
    args.insert("id_str", Value::from(OWNER_TAG));
    if request.hidden {
        args.insert("scan_ssid", Value::from(1u32));
    }
    if let Some(bssid) = request.bssid {
        args.insert("bssid", Value::from(bssid.to_string()));
    }
    match request.security {
        ProfileSecurity::Open => {
            args.insert("key_mgmt", Value::from("NONE"));
        }
        ProfileSecurity::Owe => {
            args.insert("key_mgmt", Value::from("OWE"));
            args.insert("ieee80211w", Value::from(2u32));
        }
        ProfileSecurity::WpaPersonal => {
            args.insert(
                "key_mgmt",
                Value::from(select_key_mgmt(
                    supported_key_mgmt,
                    &["WPA-PSK", "WPA-PSK-SHA256", "SAE"],
                )),
            );
            args.insert("ieee80211w", Value::from(1u32));
            if let Some(secret) = &request.secrets.passphrase {
                insert_psk(&mut args, secret.expose());
            }
        }
        ProfileSecurity::Wpa3Personal => {
            args.insert("key_mgmt", Value::from("SAE"));
            args.insert("ieee80211w", Value::from(2u32));
            if let Some(secret) = &request.secrets.passphrase {
                args.insert("sae_password", Value::from(secret.expose().to_owned()));
            }
        }
        ProfileSecurity::WpaEnterprise | ProfileSecurity::Wpa3Enterprise => {
            insert_enterprise_args(&mut args, request, blobs, supported_key_mgmt, system_ca)?;
        }
    }
    Ok(args)
}

/// The `AddNetwork` argument dictionary for SoftAP (`mode = 2`).
pub(crate) fn ap_network_args(request: &ApStartRequest) -> HashMap<&'static str, Value<'static>> {
    let mut args: HashMap<&'static str, Value<'static>> = HashMap::new();
    args.insert("ssid", Value::from(request.ssid.as_bytes().to_vec()));
    args.insert("mode", Value::from(2u32));
    args.insert("frequency", Value::from(request.frequency.unwrap_or(2412)));
    args.insert("id_str", Value::from(OWNER_TAG));
    if request.hidden {
        args.insert("ignore_broadcast_ssid", Value::from(1u32));
    }
    match request.security {
        HotspotSecurity::Open => {
            args.insert("key_mgmt", Value::from("NONE"));
        }
        HotspotSecurity::WpaPersonal => {
            args.insert("proto", Value::from("RSN"));
            args.insert("key_mgmt", Value::from("WPA-PSK"));
            args.insert("pairwise", Value::from("CCMP"));
            args.insert("group", Value::from("CCMP"));
            if let Some(secret) = &request.secret {
                insert_psk(&mut args, secret.expose());
            }
        }
        HotspotSecurity::Wpa3Personal => {
            args.insert("proto", Value::from("RSN"));
            args.insert("key_mgmt", Value::from("SAE"));
            args.insert("pairwise", Value::from("CCMP"));
            args.insert("group", Value::from("CCMP"));
            args.insert("ieee80211w", Value::from(2u32));
            if let Some(secret) = &request.secret {
                args.insert("sae_password", Value::from(secret.expose().to_owned()));
            }
        }
    }
    args
}

pub(crate) fn insert_psk(args: &mut HashMap<&'static str, Value<'static>>, value: &str) {
    match decode_hex_psk(value) {
        Some(raw) => args.insert("psk", Value::from(raw)),
        None => args.insert("psk", Value::from(value.to_owned())),
    };
}

pub(crate) async fn system_ca_path() -> Option<&'static str> {
    for path in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
    ] {
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            return Some(path);
        }
    }
    None
}

fn decode_hex_psk(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..32)
        .map(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Classifies a BSS from `wpa_supplicant`'s `Privacy`, `WPA`, and `RSN`
/// properties. `wpa`/`rsn` are the `KeyMgmt` suites; empty means absent.
pub(crate) fn classify(privacy: bool, wpa: &[String], rsn: &[String]) -> Security {
    let has = |suites: &[String], name: &str| suites.iter().any(|s| s.eq_ignore_ascii_case(name));
    let rsn_psk = has(rsn, "wpa-psk") || has(rsn, "wpa-psk-sha256");
    let rsn_sae = has(rsn, "sae") || has(rsn, "sae-ext-key");
    let rsn_eap_legacy = has(rsn, "wpa-eap") || has(rsn, "ft-eap");
    let rsn_eap_sha256 =
        has(rsn, "wpa-eap-sha256") || has(rsn, "wpa-eap-suite-b-192") || has(rsn, "ft-eap-sha384");
    if has(rsn, "owe") {
        Security::Owe
    } else if rsn_sae && rsn_psk {
        Security::Wpa2Wpa3
    } else if rsn_sae {
        Security::Wpa3Sae
    } else if rsn_eap_sha256 && !rsn_eap_legacy {
        Security::Wpa3Enterprise
    } else if rsn_eap_legacy || rsn_eap_sha256 {
        Security::Enterprise
    } else if rsn_psk {
        Security::Wpa2Psk
    } else if has(wpa, "wpa-eap") {
        Security::Enterprise
    } else if has(wpa, "wpa-psk") {
        Security::WpaPsk
    } else if privacy {
        Security::Wep
    } else {
        Security::Open
    }
}

#[cfg(test)]
mod tests {
    use kestrel_model::{EapMethod, EnterpriseConfig, Phase2Auth, ProfileSecrets, Secret, Ssid};
    use kestrel_ports::wlan::EnterpriseConnect;

    use super::*;

    fn request(security: ProfileSecurity, secret: Option<&str>) -> ConnectRequest {
        ConnectRequest {
            ssid: Ssid::new("home").unwrap(),
            security,
            secrets: secret
                .map(|s| ProfileSecrets::from_passphrase(Secret::new(s)))
                .unwrap_or_default(),
            enterprise: None,
            hidden: false,
            bssid: None,
        }
    }

    #[test]
    fn wpa_personal_is_transition_mode_with_optional_pmf() {
        let args = network_args(
            &request(ProfileSecurity::WpaPersonal, Some("passphrase!")),
            &BlobRefs::default(),
            &[],
            None,
        )
        .unwrap();
        assert_eq!(args["key_mgmt"], Value::from("WPA-PSK WPA-PSK-SHA256 SAE"));
        assert_eq!(args["ieee80211w"], Value::from(1u32));
        assert_eq!(args["psk"], Value::from("passphrase!"));
        assert_eq!(args["id_str"], Value::from(OWNER_TAG));
    }

    #[test]
    fn hex_psk_is_sent_as_raw_bytes() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let args = network_args(
            &request(ProfileSecurity::WpaPersonal, Some(hex)),
            &BlobRefs::default(),
            &[],
            None,
        )
        .unwrap();
        let Value::Array(bytes) = &args["psk"] else {
            panic!("expected a byte array");
        };
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn wpa3_requires_pmf_and_uses_sae_password() {
        let args = network_args(
            &request(ProfileSecurity::Wpa3Personal, Some("x")),
            &BlobRefs::default(),
            &[],
            None,
        )
        .unwrap();
        assert_eq!(args["key_mgmt"], Value::from("SAE"));
        assert_eq!(args["ieee80211w"], Value::from(2u32));
        assert_eq!(args["sae_password"], Value::from("x"));
        assert!(!args.contains_key("psk"));
    }

    #[test]
    fn enterprise_uses_blob_references_and_strict_pmf_for_wpa3() {
        let req = ConnectRequest {
            ssid: Ssid::new("corp").unwrap(),
            security: ProfileSecurity::Wpa3Enterprise,
            secrets: ProfileSecrets::from_passphrase(Secret::new("hunter2")),
            enterprise: Some(EnterpriseConnect {
                config: EnterpriseConfig {
                    eap: EapMethod::Peap,
                    identity: "alice@corp.example".into(),
                    anonymous_identity: Some("anon@corp.example".into()),
                    phase2: Some(Phase2Auth::Mschapv2),
                    ca_cert: None,
                    system_ca: false,
                    client_cert: None,
                    domain_suffix_match: Some("radius.corp.example".into()),
                    altsubject_match: vec!["DNS:radius.corp.example".into()],
                },
                ca_cert_pem: None,
                client_cert_pem: None,
            }),
            hidden: false,
            bssid: None,
        };
        let blobs = BlobRefs {
            ca_cert: Some("kestrel-ca-1".into()),
            ..BlobRefs::default()
        };
        let args = network_args(&req, &blobs, &[], None).unwrap();
        assert_eq!(
            args["key_mgmt"],
            Value::from("WPA-EAP-SHA256 WPA-EAP-SUITE-B-192")
        );
        assert_eq!(args["ieee80211w"], Value::from(2u32));
        assert_eq!(args["eap"], Value::from("PEAP"));
        assert_eq!(args["phase2"], Value::from("auth=MSCHAPV2"));
        assert_eq!(args["ca_cert"], Value::from("blob://kestrel-ca-1"));
        assert_eq!(args["password"], Value::from("hunter2"));
    }

    #[test]
    fn missing_system_ca_fails_instead_of_bypassing_verification() {
        let req = ConnectRequest {
            ssid: Ssid::new("corp").unwrap(),
            security: ProfileSecurity::WpaEnterprise,
            secrets: ProfileSecrets::from_passphrase(Secret::new("hunter2")),
            enterprise: Some(EnterpriseConnect {
                config: EnterpriseConfig {
                    eap: EapMethod::Peap,
                    identity: "alice@corp.example".into(),
                    anonymous_identity: None,
                    phase2: Some(Phase2Auth::Mschapv2),
                    ca_cert: None,
                    system_ca: true,
                    client_cert: None,
                    domain_suffix_match: None,
                    altsubject_match: Vec::new(),
                },
                ca_cert_pem: None,
                client_cert_pem: None,
            }),
            hidden: false,
            bssid: None,
        };
        assert!(matches!(
            network_args(&req, &BlobRefs::default(), &[], None),
            Err(PortError::Unavailable(_))
        ));
    }

    #[test]
    fn open_and_owe() {
        assert_eq!(
            network_args(
                &request(ProfileSecurity::Open, None),
                &BlobRefs::default(),
                &[],
                None,
            )
            .unwrap()["key_mgmt"],
            Value::from("NONE")
        );
        let owe = network_args(
            &request(ProfileSecurity::Owe, None),
            &BlobRefs::default(),
            &[],
            None,
        )
        .unwrap();
        assert_eq!(owe["key_mgmt"], Value::from("OWE"));
        assert_eq!(owe["ieee80211w"], Value::from(2u32));
    }

    #[test]
    fn classifies_security() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(classify(false, &[], &[]), Security::Open);
        assert_eq!(classify(true, &[], &[]), Security::Wep);
        assert_eq!(classify(true, &s(&["wpa-psk"]), &[]), Security::WpaPsk);
        assert_eq!(classify(true, &[], &s(&["wpa-psk"])), Security::Wpa2Psk);
        assert_eq!(classify(true, &[], &s(&["sae"])), Security::Wpa3Sae);
        assert_eq!(
            classify(true, &[], &s(&["wpa-psk", "sae"])),
            Security::Wpa2Wpa3
        );
        assert_eq!(classify(true, &[], &s(&["owe"])), Security::Owe);
        assert_eq!(classify(true, &[], &s(&["wpa-eap"])), Security::Enterprise);
        assert_eq!(
            classify(true, &[], &s(&["wpa-eap-sha256"])),
            Security::Wpa3Enterprise
        );
    }

    #[test]
    fn builds_ap_network_args() {
        let req = ApStartRequest {
            ssid: Ssid::new("hotspot").unwrap(),
            security: HotspotSecurity::Wpa3Personal,
            secret: Some(Secret::new("sae-pass")),
            frequency: Some(5180),
            hidden: true,
        };
        let args = ap_network_args(&req);
        assert_eq!(args["mode"], Value::from(2u32));
        assert_eq!(args["frequency"], Value::from(5180u32));
        assert_eq!(args["ignore_broadcast_ssid"], Value::from(1u32));
        assert_eq!(args["key_mgmt"], Value::from("SAE"));
        assert_eq!(args["sae_password"], Value::from("sae-pass"));
    }
}

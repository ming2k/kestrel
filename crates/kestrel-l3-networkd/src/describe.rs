// SPDX-License-Identifier: LGPL-2.1-or-later

//! Parsing of networkd's `Describe()` JSON.
//!
//! The field names were verified against systemd 261. Parsing is
//! defensive: an unknown or missing field degrades to "not reported",
//! never to an error, because networkd adds fields over time.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use kestrel_model::{IpNet, MacAddress, OnlineState};
use kestrel_ports::l3::{DhcpLease, L3Phase, L3Status};
use serde_json::Value;

/// Builds an [`L3Status`] from one link's `Describe()` JSON.
///
/// `expected_unit` is the unit Kestrel installed. Until networkd reports a
/// unit of that file name as the link's `NetworkFile`, the link is still
/// `Pending`, even if a previous configuration had made it "configured".
pub fn parse_link_status(json: &Value, expected_unit: &Path) -> L3Status {
    // Compare by file name: the unit's directory may be reached through a
    // different path than networkd's (a container or test namespace), and
    // a file of the same name in /etc deliberately overrides ours.
    let network_file = json.get("NetworkFile").and_then(Value::as_str);
    let ours = network_file.is_some_and(|file| {
        Path::new(file).file_name().is_some()
            && Path::new(file).file_name() == expected_unit.file_name()
    });
    if !ours {
        return L3Status::pending();
    }
    let admin = json
        .get("AdministrativeState")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let phase = match admin {
        "configured" => L3Phase::Ready,
        "failed" => L3Phase::Failed("networkd failed to configure the link".to_owned()),
        _ => L3Phase::Pending,
    };
    let online = OnlineState::from_networkd(json.get("OnlineState").and_then(Value::as_str));
    L3Status {
        phase,
        addresses: addresses(json),
        gateways: gateways(json),
        dns: dns(json),
        online,
        leases: leases(json),
        dhcp_server: dhcp_server(json),
    }
}

/// Every address on every link in a `Manager.Describe()` document.
pub(crate) fn all_addresses(manager: &Value) -> Vec<IpNet> {
    manager
        .get("Interfaces")
        .and_then(Value::as_array)
        .map(|links| links.iter().flat_map(addresses).collect())
        .unwrap_or_default()
}

fn bytes(value: Option<&Value>) -> Option<Vec<u8>> {
    value?
        .as_array()?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect()
}

fn ip(value: Option<&Value>) -> Option<IpAddr> {
    let bytes = bytes(value)?;
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn addresses(json: &Value) -> Vec<IpNet> {
    json.get("Addresses")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|entry| {
                    let address = ip(entry.get("Address"))?;
                    let prefix = u8::try_from(entry.get("PrefixLength")?.as_u64()?).ok()?;
                    IpNet::new(address, prefix).ok()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn dedup_preserve_order<T: Eq>(items: Vec<T>) -> Vec<T> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn gateways(json: &Value) -> Vec<IpAddr> {
    let gateways: Vec<IpAddr> = json
        .get("Routes")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter(|route| {
                    route.get("DestinationPrefixLength").and_then(Value::as_u64) == Some(0)
                        && route
                            .get("Table")
                            .and_then(Value::as_u64)
                            .is_none_or(|t| t == 254)
                        && route
                            .get("Type")
                            .and_then(Value::as_u64)
                            .is_none_or(|t| t == 1)
                })
                .filter_map(|route| ip(route.get("Gateway")))
                .filter(|gateway| !gateway.is_unspecified())
                .collect()
        })
        .unwrap_or_default();
    dedup_preserve_order(gateways)
}

fn dns(json: &Value) -> Vec<IpAddr> {
    let servers: Vec<IpAddr> = json
        .get("DNS")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|entry| {
                    ip(entry.get("Address")).or_else(|| {
                        entry
                            .get("AddressString")
                            .and_then(Value::as_str)
                            .and_then(|s| s.parse().ok())
                    })
                })
                .filter(|server| !server.is_unspecified())
                .collect()
        })
        .unwrap_or_default();
    dedup_preserve_order(servers)
}

fn leases(json: &Value) -> Vec<DhcpLease> {
    json.get("DHCPServer")
        .and_then(|server| server.get("Leases"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|lease| {
                    let IpAddr::V4(address) = ip(lease.get("Address"))? else {
                        return None;
                    };
                    let client = bytes(lease.get("HardwareAddress"))
                        .and_then(|b| <[u8; 6]>::try_from(b).ok())
                        .or_else(|| {
                            // systemd 255-257 exposed ClientId (type 0x01 + 6-byte Ethernet MAC).
                            let cid = bytes(lease.get("ClientId"))?;
                            (cid.len() == 7 && cid[0] == 1)
                                .then(|| <[u8; 6]>::try_from(&cid[1..7]).ok())
                                .flatten()
                        })
                        .map(MacAddress::from_octets);
                    Some(DhcpLease { address, client })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// DHCP option 54 (server identifier) of our own lease, falling back to
/// `Addresses[*].ConfigProvider` for systemd 248–257 where `DHCPv4Client.Lease.Message`
/// is absent.
fn dhcp_server(json: &Value) -> Option<IpAddr> {
    dhcp_server_from_message(json).or_else(|| dhcp_server_from_address_provider(json))
}

fn dhcp_server_from_message(json: &Value) -> Option<IpAddr> {
    let options = json
        .get("DHCPv4Client")?
        .get("Lease")?
        .get("Message")?
        .get("options")?
        .as_array()?;
    let hex = options
        .iter()
        .find(|option| option.get("tag").and_then(Value::as_u64) == Some(54))?
        .get("data")?
        .as_str()?;
    let value = u32::from_str_radix(hex, 16).ok()?;
    (hex.len() == 8).then(|| IpAddr::V4(Ipv4Addr::from(value)))
}

fn dhcp_server_from_address_provider(json: &Value) -> Option<IpAddr> {
    json.get("Addresses")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("ConfigSource").and_then(Value::as_str) == Some("DHCPv4"))
        .and_then(|entry| ip(entry.get("ConfigProvider")))
        .filter(|addr| !addr.is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn group_owner_link_reports_its_lease() {
        let json = fixture("link-shared-subnet.json");
        let unit = Path::new("/run/systemd/network/10-kestrel-veth0.network");
        let status = parse_link_status(&json, unit);
        assert_eq!(status.phase, L3Phase::Ready);
        assert_eq!(
            status.addresses,
            vec!["192.168.49.1/24".parse::<IpNet>().unwrap()]
        );
        assert_eq!(status.leases.len(), 1);
        assert_eq!(status.leases[0].address, Ipv4Addr::new(192, 168, 49, 112));
        assert!(status.leases[0].client.is_some());
    }

    #[test]
    fn client_link_reports_the_server() {
        let mut json = fixture("link-dhcp-client.json");
        json["DNS"] = serde_json::json!([
            {
                "Family": 2,
                "Address": [192, 168, 49, 1],
                "AddressString": "192.168.49.1"
            },
            {
                "Family": 10,
                "AddressString": "2606:4700:4700::1111"
            }
        ]);
        let unit = Path::new("/run/systemd/network/10-kestrel-veth1.network");
        let status = parse_link_status(&json, unit);
        assert_eq!(status.phase, L3Phase::Ready);
        assert_eq!(status.online, OnlineState::Online);
        assert_eq!(
            status.addresses,
            vec!["192.168.49.112/24".parse::<IpNet>().unwrap()]
        );
        assert_eq!(
            status.dns,
            vec![
                "192.168.49.1".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(status.dhcp_server, "192.168.49.1".parse().ok());
    }

    #[test]
    fn another_units_configuration_is_not_ready() {
        let json = fixture("link-dhcp-client.json");
        let status = parse_link_status(&json, Path::new("/run/systemd/network/other.network"));
        assert_eq!(status, L3Status::pending());
    }

    #[test]
    fn dhcp_server_falls_back_to_config_provider_on_older_systemd() {
        let mut json = fixture("link-dhcp-client.json");
        json.as_object_mut().unwrap().remove("DHCPv4Client");
        let unit = Path::new("/run/systemd/network/10-kestrel-veth1.network");
        let status = parse_link_status(&json, unit);
        assert_eq!(status.dhcp_server, "192.168.49.1".parse().ok());
    }

    #[test]
    fn manager_document_lists_every_address() {
        let all = all_addresses(&fixture("manager.json"));
        assert!(all.contains(&"192.168.49.1/24".parse().unwrap()));
        assert!(all.contains(&"127.0.0.1/8".parse().unwrap()));
    }

    #[test]
    fn garbage_degrades_gracefully() {
        let status = parse_link_status(
            &serde_json::json!({"Addresses": [{"Address": [1, 2]}]}),
            Path::new("/x"),
        );
        assert_eq!(status, L3Status::pending());
    }
}

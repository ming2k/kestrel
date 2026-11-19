// SPDX-License-Identifier: LGPL-2.1-or-later

//! Wi-Fi Direct through `fi.w1.wpa_supplicant1.Interface.P2PDevice`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use kestrel_model::{InterfaceName, MacAddress, P2pPeer, P2pRole, Secret, Ssid, WpsMethod, WpsPin};
use kestrel_ports::p2p::{
    P2pConnectRequest, P2pDeviceConfig, P2pEvent, P2pGroupRequest, P2pProvider,
    PersistentGroupConnect,
};
use kestrel_ports::{PortError, PortResult, Subscription};
use zbus::{OwnedObjectPath, Variant as Value};

use crate::{MAIN, MAIN_PATH, P2P_DEVICE, PEER, WpaSupplicant, dbus_error, mac_from_bytes};

/// Peer object paths end in the device address as 12 hex digits.
pub(crate) fn peer_address(path: &OwnedObjectPath) -> Option<MacAddress> {
    let hex = path.as_str().rsplit('/').next()?;
    if hex.len() != 12 {
        return None;
    }
    let mut octets = [0u8; 6];
    for (i, octet) in octets.iter_mut().enumerate() {
        *octet = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(MacAddress::from_octets(octets))
}

fn format_device_type(bytes: &[u8]) -> Option<String> {
    // Category (2) - OUI (4) - Subcategory (2).
    let bytes: [u8; 8] = bytes.try_into().ok()?;
    Some(format!(
        "{}-{:02X}{:02X}{:02X}{:02X}-{}",
        u16::from_be_bytes([bytes[0], bytes[1]]),
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        u16::from_be_bytes([bytes[6], bytes[7]])
    ))
}

impl WpaSupplicant {
    /// The object that carries P2P methods for a device: its dedicated
    /// `p2p-dev-*` interface when the driver uses one, else the station.
    pub(crate) fn p2p_path(&self, device: &InterfaceName) -> PortResult<OwnedObjectPath> {
        self.lock()
            .p2p_path(device)
            .ok_or_else(|| PortError::NotFound(device.to_string()))
    }

    async fn p2p_proxy(&self, device: &InterfaceName) -> PortResult<zbus::Proxy<'static>> {
        let path = self.p2p_path(device)?;
        self.proxy(path.as_str(), P2P_DEVICE).await
    }

    pub(crate) async fn read_peer(&self, path: &OwnedObjectPath) -> Option<P2pPeer> {
        let props_proxy = self
            .proxy(path.as_str(), "org.freedesktop.DBus.Properties")
            .await
            .ok()?;
        let reply = props_proxy.call_method("GetAll", &(PEER,)).await.ok()?;
        let props: HashMap<String, zbus::OwnedVariant> = reply.body().deserialize().ok()?;
        let address = props
            .get("DeviceAddress")
            .and_then(|v| Vec::<u8>::try_from(v.clone()).ok())
            .and_then(|bytes| mac_from_bytes(&bytes))
            .or_else(|| peer_address(path))?;
        let name = props
            .get("DeviceName")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();
        let device_type = props
            .get("PrimaryDeviceType")
            .and_then(|v| Vec::<u8>::try_from(v.clone()).ok())
            .and_then(|bytes| format_device_type(&bytes));
        let raw_ies = props
            .get("IEs")
            .and_then(|v| Vec::<u8>::try_from(v.clone()).ok())
            .unwrap_or_default();
        let wfd_subelements = extract_wfd_subelements(&raw_ies);
        Some(P2pPeer {
            address,
            name,
            device_type,
            wfd_subelements,
        })
    }

    fn peer_path(
        &self,
        device: &InterfaceName,
        address: MacAddress,
    ) -> PortResult<OwnedObjectPath> {
        let base = self.p2p_path(device)?;
        let prefix = format!("{}/", base.as_str());
        if let Some(path) = self
            .lock()
            .peers
            .iter()
            .find(|(path, peer)| path.as_str().starts_with(&prefix) && peer.address == address)
            .map(|(path, _)| path.clone())
        {
            return Ok(path);
        }
        let hex = address.octets().iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        OwnedObjectPath::try_from(format!("{}/Peers/{hex}", base.as_str()))
            .map_err(|e| PortError::InvalidArgument(e.to_string()))
    }

    async fn add_persistent_group(
        &self,
        proxy: &zbus::Proxy<'static>,
        ssid: &Ssid,
        go_address: MacAddress,
        psk: &Secret,
        role: P2pRole,
    ) -> PortResult<OwnedObjectPath> {
        let mode = match role {
            P2pRole::GroupOwner => 3u32,
            P2pRole::Client => 0u32,
        };
        let mut args: HashMap<&'static str, Value<'static>> = HashMap::new();
        args.insert("ssid", Value::from(ssid.as_bytes().to_vec()));
        args.insert("bssid", Value::from(go_address.to_string()));
        crate::network::insert_psk(&mut args, psk.expose());
        args.insert("mode", Value::from(mode));
        args.insert("disabled", Value::from(2u32));
        self.lock().suppress_persistent_added += 1;
        let result = proxy.call_method("AddPersistentGroup", &(args,)).await;
        match result {
            Ok(reply) => {
                let path: OwnedObjectPath = reply.body().deserialize().map_err(dbus_error)?;
                let mut state = self.lock();
                state.suppress_persistent_added = state.suppress_persistent_added.saturating_sub(1);
                state.self_persistent_groups.insert(path.clone());
                Ok(path)
            }
            Err(error) => {
                let mut state = self.lock();
                state.suppress_persistent_added = state.suppress_persistent_added.saturating_sub(1);
                Err(dbus_error(error))
            }
        }
    }

    pub(crate) async fn remove_all_persistent_groups(&self, p2p_path: &OwnedObjectPath) {
        if let Ok(proxy) = self.proxy(p2p_path.as_str(), P2P_DEVICE).await {
            let _ = proxy.call_method("RemoveAllPersistentGroups", &()).await;
        }
    }
}

#[async_trait]
impl P2pProvider for WpaSupplicant {
    fn subscribe(&self) -> Subscription<P2pEvent> {
        self.inner.p2p_events.subscribe()
    }

    async fn configure(&self, device: &InterfaceName, config: &P2pDeviceConfig) -> PortResult<()> {
        let proxy = self.p2p_proxy(device).await?;
        let settings: HashMap<&str, Value<'_>> =
            HashMap::from([("DeviceName", Value::from(config.device_name.as_str()))]);
        proxy
            .set_property("P2PDeviceConfig", settings)
            .await
            .map_err(dbus_error)?;
        let main = self.proxy(MAIN_PATH, MAIN).await?;
        let ies = config.wfd_subelements.clone().unwrap_or_default();
        if let Err(error) = main.set_property("WFDIEs", ies).await
            && config.wfd_subelements.is_some()
        {
            return Err(dbus_error(error));
        }
        Ok(())
    }

    async fn find(&self, device: &InterfaceName, timeout: Duration) -> PortResult<()> {
        let proxy = self.p2p_proxy(device).await?;
        let seconds = i32::try_from(timeout.as_secs()).unwrap_or(i32::MAX);
        let args: HashMap<&str, Value<'_>> = HashMap::from([("Timeout", Value::from(seconds))]);
        proxy
            .call_method("Find", &(args,))
            .await
            .map(|_| ())
            .map_err(dbus_error)
    }

    async fn stop_find(&self, device: &InterfaceName) -> PortResult<()> {
        let proxy = self.p2p_proxy(device).await?;
        proxy
            .call_method("StopFind", &())
            .await
            .map(|_| ())
            .map_err(dbus_error)
    }

    async fn peers(&self, device: &InterfaceName) -> PortResult<Vec<P2pPeer>> {
        let base = self.p2p_path(device)?;
        let prefix = format!("{}/", base.as_str());
        Ok(self
            .lock()
            .peers
            .iter()
            .filter(|(path, _)| path.as_str().starts_with(&prefix))
            .map(|(_, peer)| peer.clone())
            .collect())
    }

    async fn connect(
        &self,
        device: &InterfaceName,
        request: &P2pConnectRequest,
    ) -> PortResult<Option<WpsPin>> {
        let proxy = self.p2p_proxy(device).await?;
        let peer = self.peer_path(device, request.peer)?;
        let mut args: HashMap<&str, Value<'_>> = HashMap::new();
        args.insert("peer", Value::from(peer));
        args.insert("wps_method", Value::from(request.method.as_str()));
        args.insert("go_intent", Value::from(i32::from(request.go_intent.get())));
        args.insert("persistent", Value::from(request.persistent));
        args.insert("join", Value::from(false));
        if let WpsMethod::EnterPin(pin) = &request.method {
            args.insert("pin", Value::from(pin.as_str().to_owned()));
        }
        let reply = proxy
            .call_method("Connect", &(args,))
            .await
            .map_err(dbus_error)?;
        let generated: String = reply.body().deserialize().unwrap_or_default();
        if matches!(request.method, WpsMethod::DisplayPin) && !generated.is_empty() {
            return WpsPin::new(generated).map(Some).map_err(|e| {
                PortError::Backend(format!("wpa_supplicant generated an invalid PIN: {e}"))
            });
        }
        Ok(None)
    }

    async fn start_group(
        &self,
        device: &InterfaceName,
        request: &P2pGroupRequest,
    ) -> PortResult<()> {
        let proxy = self.p2p_proxy(device).await?;
        let mut args: HashMap<&str, Value<'_>> = HashMap::new();
        args.insert("persistent", Value::from(request.persistent));
        if let Some(frequency) = request.frequency {
            let frequency = i32::try_from(frequency)
                .map_err(|_| PortError::InvalidArgument("frequency out of range".to_owned()))?;
            args.insert("frequency", Value::from(frequency));
        }
        proxy
            .call_method("GroupAdd", &(args,))
            .await
            .map(|_| ())
            .map_err(dbus_error)
    }

    async fn connect_persistent(
        &self,
        device: &InterfaceName,
        request: &PersistentGroupConnect,
    ) -> PortResult<()> {
        let p2p_path = self.p2p_path(device)?;
        let proxy = self.proxy(p2p_path.as_str(), P2P_DEVICE).await?;
        self.remove_all_persistent_groups(&p2p_path).await;
        let group_obj = self
            .add_persistent_group(
                &proxy,
                &request.ssid,
                request.go_address,
                &request.psk,
                request.role,
            )
            .await?;
        let peer = self.peer_path(device, request.peer)?;
        let mut args: HashMap<&str, Value<'_>> = HashMap::new();
        args.insert("peer", Value::from(peer));
        args.insert("persistent_group_object", Value::from(group_obj.clone()));
        if let Some(frequency) = request.frequency {
            let frequency = i32::try_from(frequency)
                .map_err(|_| PortError::InvalidArgument("frequency out of range".to_owned()))?;
            args.insert("frequency", Value::from(frequency));
        }
        if let Err(error) = proxy.call_method("Invite", &(args,)).await {
            let _ = proxy
                .call_method("RemovePersistentGroup", &(group_obj,))
                .await;
            return Err(dbus_error(error));
        }
        Ok(())
    }

    async fn start_persistent_group(
        &self,
        device: &InterfaceName,
        ssid: &Ssid,
        go_address: MacAddress,
        psk: &Secret,
        frequency: Option<u32>,
    ) -> PortResult<()> {
        let p2p_path = self.p2p_path(device)?;
        let proxy = self.proxy(p2p_path.as_str(), P2P_DEVICE).await?;
        self.remove_all_persistent_groups(&p2p_path).await;
        let group_obj = self
            .add_persistent_group(&proxy, ssid, go_address, psk, P2pRole::GroupOwner)
            .await?;
        let mut args: HashMap<&str, Value<'_>> = HashMap::new();
        args.insert("persistent_group_object", Value::from(group_obj.clone()));
        if let Some(frequency) = frequency {
            let frequency = i32::try_from(frequency)
                .map_err(|_| PortError::InvalidArgument("frequency out of range".to_owned()))?;
            args.insert("frequency", Value::from(frequency));
        }
        if let Err(error) = proxy.call_method("GroupAdd", &(args,)).await {
            let _ = proxy
                .call_method("RemovePersistentGroup", &(group_obj,))
                .await;
            return Err(dbus_error(error));
        }
        Ok(())
    }

    async fn authorize_group(
        &self,
        _device: &InterfaceName,
        group_if: &InterfaceName,
    ) -> PortResult<()> {
        let path = self
            .lock()
            .interfaces
            .iter()
            .find(|(_, iface)| &iface.ifname == group_if)
            .map(|(path, _)| path.clone())
            .ok_or_else(|| PortError::NotFound(group_if.to_string()))?;
        let proxy = self
            .proxy(path.as_str(), "fi.w1.wpa_supplicant1.Interface.WPS")
            .await?;
        let args: HashMap<&str, Value<'_>> = HashMap::from([
            ("Role", Value::from("registrar")),
            ("Type", Value::from("pbc")),
        ]);
        proxy
            .call_method("Start", &(args,))
            .await
            .map(|_| ())
            .map_err(dbus_error)
    }

    async fn cancel(&self, device: &InterfaceName) -> PortResult<()> {
        let proxy = self.p2p_proxy(device).await?;
        match proxy.call_method("Cancel", &()).await {
            Ok(_) => Ok(()),
            Err(error) if error.to_string().contains("Failed") => Ok(()),
            Err(error) => Err(dbus_error(error)),
        }
    }

    async fn remove_group(
        &self,
        device: &InterfaceName,
        group_if: &InterfaceName,
    ) -> PortResult<()> {
        let path = self
            .lock()
            .interfaces
            .iter()
            .find(|(_, iface)| &iface.ifname == group_if)
            .map(|(path, _)| path.clone());
        if let Some(path) = path {
            let proxy = self.proxy(path.as_str(), P2P_DEVICE).await?;
            match proxy.call_method("Disconnect", &()).await {
                Ok(_) => {}
                Err(error) if error.to_string().contains("UnknownObject") => {}
                Err(error) => return Err(dbus_error(error)),
            }
        }
        if let Ok(p2p_path) = self.p2p_path(device) {
            self.remove_all_persistent_groups(&p2p_path).await;
        }
        Ok(())
    }
}

/// Extracts bare WFD subelements from `wpa_supplicant`'s `Peer.IEs`.
///
/// `wpa_supplicant` exposes raw concatenated 802.11 vendor-specific IEs (`0xDD`,
/// length, OUI `50:6F:9A`, OUI type `0x0A`, subelements...) on `Peer.IEs`,
/// whereas `WFDIEs` and Kestrel's API carry the bare subelements. If `raw` is
/// already a bare subelement list (not starting with `0xDD`), it is returned
/// unchanged.
fn extract_wfd_subelements(raw: &[u8]) -> Vec<u8> {
    const VENDOR_SPECIFIC_IE: u8 = 0xdd;
    const WFA_WFD_HEADER: [u8; 4] = [0x50, 0x6f, 0x9a, 0x0a];

    if raw.first() != Some(&VENDOR_SPECIFIC_IE) {
        return raw.to_vec();
    }
    let mut offset = 0;
    let mut found = Vec::new();
    while offset + 2 <= raw.len() {
        let id = raw[offset];
        let len = usize::from(raw[offset + 1]);
        let body_start = offset + 2;
        let Some(body_end) = body_start.checked_add(len) else {
            break;
        };
        if body_end > raw.len() {
            break;
        }
        let body = &raw[body_start..body_end];
        if id == VENDOR_SPECIFIC_IE && body.starts_with(&WFA_WFD_HEADER) {
            found.extend_from_slice(&body[WFA_WFD_HEADER.len()..]);
        }
        offset = body_end;
    }
    if found.is_empty() && offset != raw.len() {
        // Not a valid IE stream; fall back to raw bytes rather than losing data.
        return raw.to_vec();
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_paths_encode_the_device_address() {
        let path =
            OwnedObjectPath::try_from("/fi/w1/wpa_supplicant1/Interfaces/0/Peers/02000000aa42")
                .unwrap();
        assert_eq!(
            peer_address(&path).unwrap().to_string(),
            "02:00:00:00:aa:42"
        );
        let bad =
            OwnedObjectPath::try_from("/fi/w1/wpa_supplicant1/Interfaces/0/Peers/xyz").unwrap();
        assert_eq!(peer_address(&bad), None);
    }

    #[test]
    fn formats_primary_device_type() {
        assert_eq!(
            format_device_type(&[0, 10, 0, 0x50, 0xf2, 4, 0, 5]).unwrap(),
            "10-0050F204-5"
        );
    }

    #[test]
    fn extracts_wfd_subelements_from_vendor_ies_or_passthrough() {
        // Vendor-specific 802.11 IEs: P2P IE (50:6F:9A:09) followed by WFD IE (50:6F:9A:0A).
        let raw = vec![
            0xdd, 0x05, 0x50, 0x6f, 0x9a, 0x09, 0xaa, // non-WFD vendor IE
            0xdd, 0x0d, 0x50, 0x6f, 0x9a, 0x0a, // WFD IE header
            0x00, 0x00, 0x06, 0x00, 0x11, 0x1c, 0x44, 0x00, 0x32,
        ];
        assert_eq!(
            extract_wfd_subelements(&raw),
            vec![0x00, 0x00, 0x06, 0x00, 0x11, 0x1c, 0x44, 0x00, 0x32]
        );
        // Bare subelements pass through untouched.
        let bare = vec![0x00, 0x00, 0x06, 0x00, 0x11, 0x1c, 0x44, 0x00, 0x32];
        assert_eq!(extract_wfd_subelements(&bare), bare);
    }
}

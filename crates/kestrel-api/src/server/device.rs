// SPDX-License-Identifier: LGPL-2.1-or-later

use std::time::Duration;

use kestrel_controller::{DeviceSnapshot, HotspotStatusSnapshot, StationState};
use kestrel_model::{GoIntent, InterfaceName, MacAddress, P2pPeer, WpsMethod, WpsPin};
use kestrel_ports::l3::L3Phase;
use zbus::OwnedObjectPath;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;

use super::Shared;
use crate::paths::profile_from_path;
use crate::{Action, ApiError, device_path, profile_path, session_path};

use crate::client::{PeerInfo, ScanResult};

#[derive(Debug)]
pub(crate) struct Device {
    shared: Shared,
    snapshot: DeviceSnapshot,
}

#[derive(Debug)]
pub(crate) struct P2p {
    shared: Shared,
    name: InterfaceName,
    finding: bool,
}

const MAX_WFD_SUBELEMENTS_BYTES: usize = 1024;

fn signal_for(snapshot: &DeviceSnapshot) -> i16 {
    let bssid = match &snapshot.station.state {
        StationState::Connected {
            bssid: Some(bssid), ..
        } => Some(*bssid),
        _ => None,
    };
    bssid
        .and_then(|bssid| {
            snapshot
                .station
                .visible
                .iter()
                .find(|bss| bss.bssid == bssid)
                .map(|bss| bss.signal)
        })
        .unwrap_or(0)
}

fn bssid_for(state: &StationState) -> Option<MacAddress> {
    match state {
        StationState::Connected { bssid, .. } => *bssid,
        _ => None,
    }
}

pub(crate) async fn export(shared: &Shared, snapshot: DeviceSnapshot) -> zbus::Result<()> {
    let path = device_path(&snapshot.name);
    let server = shared.connection.object_server();
    let p2p = snapshot.capabilities.p2p;
    let ap = snapshot.capabilities.access_point;
    let name = snapshot.name.clone();
    let finding = snapshot.p2p_finding;
    let hotspot = snapshot.hotspot.clone();
    let existing = server
        .at(
            path.clone(),
            Device {
                shared: shared.clone(),
                snapshot: snapshot.clone(),
            },
        )
        .await?;
    if existing.is_some() {
        return update(shared, snapshot).await;
    }
    if p2p {
        server
            .at(
                path.clone(),
                P2p {
                    shared: shared.clone(),
                    name: name.clone(),
                    finding,
                },
            )
            .await?;
    }
    if ap {
        server
            .at(
                path,
                Hotspot {
                    shared: shared.clone(),
                    name,
                    snapshot: hotspot,
                },
            )
            .await?;
    }
    Ok(())
}

pub(crate) async fn unexport(shared: &Shared, name: &InterfaceName) -> zbus::Result<()> {
    let server = shared.connection.object_server();
    let path = device_path(name);
    let _ = server.remove::<P2p, _>(path.clone()).await;
    let _ = server.remove::<Hotspot, _>(path.clone()).await;
    server.remove::<Device, _>(path).await.map(|_| ())
}

async fn update_hotspot(
    server: &zbus::ObjectServer,
    path: OwnedObjectPath,
    next: HotspotStatusSnapshot,
) -> zbus::Result<()> {
    let Ok(hotspot) = server.interface::<_, Hotspot>(path).await else {
        return Ok(());
    };
    let mut guard = hotspot.get_mut().await;
    let old = std::mem::replace(&mut guard.snapshot, next);
    let new = &guard.snapshot;
    let emitter = hotspot.signal_emitter();
    if old.ssid != new.ssid {
        guard.ssid_changed(emitter).await?;
    }
    if old.security != new.security {
        guard.security_changed(emitter).await?;
    }
    if old.frequency != new.frequency {
        guard.frequency_changed(emitter).await?;
    }
    if old.gateway != new.gateway {
        guard.gateway_changed(emitter).await?;
    }
    if old.leases != new.leases {
        guard.leases_changed(emitter).await?;
    }
    if old.clients != new.clients {
        guard.connected_clients_changed(emitter).await?;
    }
    if old.failure != new.failure {
        guard.failure_changed(emitter).await?;
        guard.failure_detail_changed(emitter).await?;
    }
    // Emit `state_changed` last so proxy caches observe updated properties
    // when reacting to a state transition.
    if old.state != new.state {
        guard.state_changed(emitter).await?;
    }
    Ok(())
}

pub(crate) async fn update(shared: &Shared, snapshot: DeviceSnapshot) -> zbus::Result<()> {
    let path = device_path(&snapshot.name);
    let server = shared.connection.object_server();
    if let Ok(p2p) = server.interface::<_, P2p>(path.clone()).await {
        let mut guard = p2p.get_mut().await;
        if guard.finding != snapshot.p2p_finding {
            guard.finding = snapshot.p2p_finding;
            guard.finding_changed(p2p.signal_emitter()).await?;
        }
    }
    update_hotspot(server, path.clone(), snapshot.hotspot.clone()).await?;
    let iface = server.interface::<_, Device>(path).await?;
    let mut guard = iface.get_mut().await;
    let old = std::mem::replace(&mut guard.snapshot, snapshot);
    let new = &guard.snapshot;
    let emitter = iface.signal_emitter();
    if old.address != new.address {
        guard.hardware_address_changed(emitter).await?;
    }
    if old.capabilities != new.capabilities {
        guard.capabilities_changed(emitter).await?;
    }
    if old.supported_security != new.supported_security {
        guard.supported_security_changed(emitter).await?;
    }
    if old.ssid != new.ssid {
        guard.ssid_changed(emitter).await?;
    }
    if old.frequency != new.frequency {
        guard.frequency_changed(emitter).await?;
    }
    if old.security != new.security {
        guard.security_changed(emitter).await?;
    }
    if old.l3.addresses != new.l3.addresses {
        guard.addresses_changed(emitter).await?;
    }
    if old.l3.gateways != new.l3.gateways {
        guard.gateways_changed(emitter).await?;
    }
    if old.l3.dns != new.l3.dns {
        guard.dns_changed(emitter).await?;
    }
    if old.l3.phase != new.l3.phase {
        guard.l3_phase_changed(emitter).await?;
    }
    if old.l3.online != new.l3.online {
        guard.online_state_changed(emitter).await?;
    }
    if signal_for(&old) != signal_for(new) {
        guard.signal_changed(emitter).await?;
    }
    if old.station.scanning != new.station.scanning {
        guard.scanning_changed(emitter).await?;
    }
    if old.station.last_failure != new.station.last_failure {
        guard.last_failure_changed(emitter).await?;
        guard.last_failure_detail_changed(emitter).await?;
    }
    if old.station.autoconnect_held != new.station.autoconnect_held {
        guard.autoconnect_held_changed(emitter).await?;
        guard.autoconnect_enabled_changed(emitter).await?;
    }
    if old.station.needs_secrets != new.station.needs_secrets {
        guard.profiles_needing_secrets_changed(emitter).await?;
    }
    if old.scan_results != new.scan_results {
        Device::scan_results_changed(emitter).await?;
    }
    if old.station.state.profile() != new.station.state.profile() {
        guard.active_profile_changed(emitter).await?;
    }
    if bssid_for(&old.station.state) != bssid_for(&new.station.state) {
        guard.bssid_changed(emitter).await?;
    }
    if old.station.state != new.station.state {
        guard.state_changed(emitter).await?;
    }
    Ok(())
}

pub(crate) async fn peer_found(
    shared: &Shared,
    device: &InterfaceName,
    peer: &P2pPeer,
) -> zbus::Result<()> {
    let emitter = SignalEmitter::new(&shared.connection, device_path(device))?;
    let (address, name, kind, wfd) = peer_info(peer);
    P2p::peer_found(&emitter, &address, &name, &kind, wfd).await
}

pub(crate) async fn peer_lost(
    shared: &Shared,
    device: &InterfaceName,
    address: MacAddress,
) -> zbus::Result<()> {
    let emitter = SignalEmitter::new(&shared.connection, device_path(device))?;
    P2p::peer_lost(&emitter, &address.to_string()).await
}

fn peer_info(peer: &P2pPeer) -> PeerInfo {
    (
        peer.address.to_string(),
        peer.name.clone(),
        peer.device_type.clone().unwrap_or_default(),
        peer.wfd_subelements.clone(),
    )
}

fn root() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("valid path")
}

#[zbus::interface(name = "com.hihusky.Kestrel.Device")]
impl Device {
    #[zbus(property)]
    fn interface(&self) -> String {
        self.snapshot.name.to_string()
    }

    #[zbus(property)]
    fn hardware_address(&self) -> String {
        self.snapshot
            .address
            .map(|a| a.to_string())
            .unwrap_or_default()
    }

    /// Subset of `station`, `p2p`, `access-point`.
    #[zbus(property)]
    fn capabilities(&self) -> Vec<String> {
        let caps = self.snapshot.capabilities;
        [
            (caps.station, "station"),
            (caps.p2p, "p2p"),
            (caps.access_point, "access-point"),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, name)| name.to_owned())
        .collect()
    }

    /// `disabled`, `idle`, `associating`, `configuring-l3`, `connected`,
    /// `reconnecting`, or `waiting`.
    #[zbus(property)]
    fn state(&self) -> String {
        self.snapshot.station.state.as_str().to_owned()
    }

    /// The profile in use, or `/`.
    #[zbus(property)]
    fn active_profile(&self) -> OwnedObjectPath {
        self.snapshot
            .station
            .state
            .profile()
            .map_or_else(root, profile_path)
    }

    #[zbus(property)]
    fn bssid(&self) -> String {
        match &self.snapshot.station.state {
            StationState::Connected {
                bssid: Some(bssid), ..
            } => bssid.to_string(),
            _ => String::new(),
        }
    }

    /// Centre frequency in MHz of the current BSS, or 0 when unknown.
    #[zbus(property)]
    fn frequency(&self) -> u32 {
        self.snapshot.frequency.unwrap_or(0)
    }

    /// Security of the active connection, or empty when idle.
    #[zbus(property)]
    fn security(&self) -> String {
        self.snapshot.security.clone().unwrap_or_default()
    }

    #[zbus(property)]
    fn scanning(&self) -> bool {
        self.snapshot.station.scanning
    }

    /// SSID of the active profile, or empty.
    #[zbus(property)]
    fn ssid(&self) -> String {
        self.snapshot
            .ssid
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
    }

    /// Addresses currently configured on the link.
    #[zbus(property)]
    fn addresses(&self) -> Vec<String> {
        self.snapshot
            .l3
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Default gateways currently configured on the link.
    #[zbus(property)]
    fn gateways(&self) -> Vec<String> {
        self.snapshot
            .l3
            .gateways
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// DNS servers currently configured on the link.
    #[zbus(property)]
    fn dns(&self) -> Vec<String> {
        self.snapshot
            .l3
            .dns
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// `pending`, `ready`, or `failed`.
    #[zbus(property)]
    fn l3_phase(&self) -> String {
        match &self.snapshot.l3.phase {
            L3Phase::Pending => "pending",
            L3Phase::Ready => "ready",
            L3Phase::Failed(_) => "failed",
        }
        .to_owned()
    }

    /// `offline`, `partial`, `online`, or `unknown`.
    #[zbus(property)]
    fn online_state(&self) -> String {
        self.snapshot.l3.online.as_str().to_owned()
    }

    /// Signal strength in dBm, or 0 when the current BSS is unknown.
    #[zbus(property)]
    fn signal(&self) -> i16 {
        signal_for(&self.snapshot)
    }

    /// Whether autoconnect is enabled (not held by a user disconnect or
    /// `SetAutoconnect(false)`).
    #[zbus(property)]
    fn autoconnect_enabled(&self) -> bool {
        !self.snapshot.station.autoconnect_held
    }

    /// Stable failure code (see `FailureReason::code`), or empty.
    #[zbus(property)]
    fn last_failure(&self) -> String {
        self.snapshot
            .station
            .last_failure
            .as_ref()
            .map(|f| f.code().to_owned())
            .unwrap_or_default()
    }

    /// Human-readable detail for diagnostics. Never parse it.
    #[zbus(property)]
    fn last_failure_detail(&self) -> String {
        self.snapshot
            .station
            .last_failure
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
    }

    /// True after a user disconnect, until the next explicit connect.
    #[zbus(property)]
    fn autoconnect_held(&self) -> bool {
        self.snapshot.station.autoconnect_held
    }

    #[zbus(property)]
    fn profiles_needing_secrets(&self) -> Vec<OwnedObjectPath> {
        self.snapshot
            .station
            .needs_secrets
            .iter()
            .map(|id| profile_path(*id))
            .collect()
    }

    /// Profile security types supported by the active driver/backend on this device.
    #[zbus(property)]
    fn supported_security(&self) -> Vec<String> {
        self.snapshot
            .supported_security
            .iter()
            .map(|s| s.as_str().to_owned())
            .collect()
    }

    async fn scan(&self, #[zbus(header)] header: Header<'_>) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        Ok(self
            .shared
            .controller
            .station()
            .scan(&self.snapshot.name)
            .await?)
    }

    async fn connect(
        &self,
        #[zbus(header)] header: Header<'_>,
        profile: OwnedObjectPath,
    ) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        let id = profile_from_path(profile.as_str())
            .ok_or_else(|| ApiError::NoSuchProfile(profile.as_str().to_owned()))?;
        Ok(self
            .shared
            .controller
            .station()
            .connect(&self.snapshot.name, id)
            .await?)
    }

    async fn disconnect(&self, #[zbus(header)] header: Header<'_>) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        Ok(self
            .shared
            .controller
            .station()
            .disconnect(&self.snapshot.name)
            .await?)
    }

    /// Enables or disables autoconnect without tearing down the link.
    async fn set_autoconnect(
        &self,
        #[zbus(header)] header: Header<'_>,
        enabled: bool,
    ) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        Ok(self
            .shared
            .controller
            .station()
            .set_autoconnect(&self.snapshot.name, enabled)
            .await?)
    }

    /// The latest scan results, strongest first.
    fn get_scan_results(&self) -> Vec<ScanResult> {
        let mut results: Vec<ScanResult> = self
            .snapshot
            .scan_results
            .iter()
            .map(|entry| {
                (
                    entry.bss.ssid.to_string_lossy(),
                    entry.bss.bssid.to_string(),
                    entry.bss.frequency,
                    entry.bss.signal,
                    entry.bss.security.as_str().to_owned(),
                    entry.profile.map_or_else(root, profile_path),
                )
            })
            .collect();
        results.sort_by_key(|r| std::cmp::Reverse(r.3));
        results
    }

    /// New scan results are available through `GetScanResults`.
    #[zbus(signal)]
    async fn scan_results_changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

#[zbus::interface(name = "com.hihusky.Kestrel.P2P")]
impl P2p {
    #[zbus(property)]
    fn finding(&self) -> bool {
        self.finding
    }

    async fn find(
        &self,
        #[zbus(header)] header: Header<'_>,
        timeout_seconds: u32,
    ) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        if !(1..=600).contains(&timeout_seconds) {
            return Err(ApiError::invalid("timeout must be 1..=600 seconds"));
        }
        let timeout = Duration::from_secs(u64::from(timeout_seconds));
        Ok(self
            .shared
            .controller
            .p2p()
            .find(&self.name, timeout)
            .await?)
    }

    async fn stop_find(&self, #[zbus(header)] header: Header<'_>) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        Ok(self.shared.controller.p2p().stop_find(&self.name).await?)
    }

    /// Sets the Wi-Fi Display subelements advertised during P2P discovery and
    /// group negotiation. An empty byte array disables WFD advertisement.
    async fn set_wfd_subelements(
        &self,
        #[zbus(header)] header: Header<'_>,
        subelements: Vec<u8>,
    ) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        if subelements.len() > MAX_WFD_SUBELEMENTS_BYTES {
            return Err(ApiError::invalid(format!(
                "WFD subelements exceed {MAX_WFD_SUBELEMENTS_BYTES} bytes"
            )));
        }
        let subelements = (!subelements.is_empty()).then_some(subelements);
        Ok(self
            .shared
            .controller
            .p2p()
            .set_wfd_subelements(&self.name, subelements)
            .await?)
    }

    async fn get_peers(&self) -> Result<Vec<PeerInfo>, ApiError> {
        Ok(self
            .shared
            .controller
            .p2p()
            .peers(&self.name)
            .await?
            .iter()
            .map(peer_info)
            .collect())
    }

    /// Starts a Wi-Fi Direct connection. `method` is `pbc`, `display` (we
    /// show a PIN, delivered to the agent), or `keypad` (enter the peer's
    /// `pin`). `go_intent` is 0..=15, or 255 for the configured default.
    async fn connect(
        &self,
        #[zbus(header)] header: Header<'_>,
        peer: String,
        method: String,
        pin: String,
        go_intent: u8,
        persistent: bool,
    ) -> Result<OwnedObjectPath, ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        let peer = MacAddress::parse(&peer).map_err(|e| ApiError::invalid(e.to_string()))?;
        let method = match method.as_str() {
            "pbc" => WpsMethod::PushButton,
            "display" => WpsMethod::DisplayPin,
            "keypad" => {
                WpsMethod::EnterPin(WpsPin::new(pin).map_err(|e| ApiError::invalid(e.to_string()))?)
            }
            other => return Err(ApiError::invalid(format!("unknown WPS method {other:?}"))),
        };
        let go_intent = if go_intent == u8::MAX {
            None
        } else {
            Some(GoIntent::new(go_intent).map_err(|e| ApiError::invalid(e.to_string()))?)
        };
        let p2p = self.shared.controller.p2p();
        let id = p2p
            .connect(&self.name, peer, method, go_intent, persistent)
            .await?;
        // A returned path must be usable at once: export before replying.
        // (A session that already closed has no object to export.)
        if let Ok(snapshot) = p2p.session(id).await {
            self.shared.ensure_session_exported(snapshot).await?;
        }
        Ok(session_path(id))
    }

    /// Starts a group as owner without GO negotiation (autonomous GO).
    /// `frequency` is the operating channel in MHz; 0 lets the backend
    /// choose. The group SSID is generated by the backend.
    async fn start_group(
        &self,
        #[zbus(header)] header: Header<'_>,
        frequency: u32,
        persistent: bool,
    ) -> Result<OwnedObjectPath, ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        let frequency = parse_p2p_frequency(frequency)?;
        let p2p = self.shared.controller.p2p();
        let id = p2p.start_group(&self.name, frequency, persistent).await?;
        if let Ok(snapshot) = p2p.session(id).await {
            self.shared.ensure_session_exported(snapshot).await?;
        }
        Ok(session_path(id))
    }

    /// Re-establishes or invites a peer into a saved persistent P2P group.
    /// Pass empty `peer` for autonomous GO or group-wide invite, and `0`
    /// for automatic channel selection.
    async fn connect_persistent(
        &self,
        #[zbus(header)] header: Header<'_>,
        group: OwnedObjectPath,
        peer: String,
        frequency: u32,
    ) -> Result<OwnedObjectPath, ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        let group_id = crate::p2p_group_from_path(group.as_str())
            .ok_or_else(|| ApiError::NoSuchP2pGroup(group.as_str().to_owned()))?;
        let peer = if peer.is_empty() {
            None
        } else {
            Some(MacAddress::parse(&peer).map_err(|e| ApiError::invalid(e.to_string()))?)
        };
        let frequency = parse_p2p_frequency(frequency)?;
        let p2p = self.shared.controller.p2p();
        let id = p2p
            .connect_persistent(&self.name, group_id, peer, frequency)
            .await?;
        if let Ok(snapshot) = p2p.session(id).await {
            self.shared.ensure_session_exported(snapshot).await?;
        }
        Ok(session_path(id))
    }

    /// Re-starts a saved persistent P2P group autonomously as group owner.
    async fn start_persistent_group(
        &self,
        #[zbus(header)] header: Header<'_>,
        group: OwnedObjectPath,
        frequency: u32,
    ) -> Result<OwnedObjectPath, ApiError> {
        self.shared.authorize(&header, Action::Connect).await?;
        let group_id = crate::p2p_group_from_path(group.as_str())
            .ok_or_else(|| ApiError::NoSuchP2pGroup(group.as_str().to_owned()))?;
        let frequency = parse_p2p_frequency(frequency)?;
        let p2p = self.shared.controller.p2p();
        let id = p2p
            .start_persistent_group(&self.name, group_id, frequency)
            .await?;
        if let Ok(snapshot) = p2p.session(id).await {
            self.shared.ensure_session_exported(snapshot).await?;
        }
        Ok(session_path(id))
    }

    #[zbus(signal)]
    async fn peer_found(
        emitter: &SignalEmitter<'_>,
        address: &str,
        name: &str,
        device_type: &str,
        wfd_subelements: Vec<u8>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn peer_lost(emitter: &SignalEmitter<'_>, address: &str) -> zbus::Result<()>;
}

fn parse_p2p_frequency(frequency: u32) -> Result<Option<u32>, ApiError> {
    match frequency {
        0 => Ok(None),
        2400..=7125 => Ok(Some(frequency)),
        _ => Err(ApiError::invalid(
            "frequency must be 0 (automatic) or a channel in MHz",
        )),
    }
}

#[derive(Debug)]
pub(crate) struct Hotspot {
    pub(crate) shared: Shared,
    pub(crate) name: InterfaceName,
    pub(crate) snapshot: HotspotStatusSnapshot,
}

#[zbus::interface(name = "com.hihusky.Kestrel.Hotspot")]
impl Hotspot {
    #[zbus(property)]
    fn state(&self) -> String {
        self.snapshot.state.to_owned()
    }

    #[zbus(property)]
    fn ssid(&self) -> String {
        self.snapshot
            .ssid
            .as_ref()
            .map_or_else(String::new, kestrel_model::Ssid::to_string_lossy)
    }

    #[zbus(property)]
    fn security(&self) -> String {
        self.snapshot
            .security
            .map_or_else(String::new, |s| s.as_str().to_owned())
    }

    #[zbus(property)]
    fn frequency(&self) -> u32 {
        self.snapshot.frequency.unwrap_or(0)
    }

    #[zbus(property)]
    fn gateway(&self) -> String {
        self.snapshot
            .gateway
            .map_or_else(String::new, |g| g.to_string())
    }

    /// Active DHCP leases `(ipv4_address, client_mac)` served by this hotspot.
    #[zbus(property)]
    fn leases(&self) -> Vec<(String, String)> {
        self.snapshot
            .leases
            .iter()
            .map(|l| {
                (
                    l.address.to_string(),
                    l.client.map_or_else(String::new, |m| m.to_string()),
                )
            })
            .collect()
    }

    #[zbus(property)]
    fn connected_clients(&self) -> Vec<String> {
        self.snapshot
            .clients
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[zbus(property)]
    fn failure(&self) -> String {
        self.snapshot
            .failure
            .as_ref()
            .map_or_else(String::new, |f| f.code().to_owned())
    }

    #[zbus(property)]
    fn failure_detail(&self) -> String {
        self.snapshot
            .failure
            .as_ref()
            .map_or_else(String::new, ToString::to_string)
    }

    async fn start(
        &self,
        #[zbus(header)] header: Header<'_>,
        settings: crate::HotspotSettings,
        secret: String,
    ) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Hotspot).await?;
        let config = crate::hotspot_from_settings(&settings)?;
        let secret = (!secret.is_empty()).then(|| kestrel_model::Secret::new(secret));
        Ok(self
            .shared
            .controller
            .hotspot()
            .start(&self.name, config, secret)
            .await?)
    }

    async fn stop(&self, #[zbus(header)] header: Header<'_>) -> Result<(), ApiError> {
        self.shared.authorize(&header, Action::Hotspot).await?;
        Ok(self.shared.controller.hotspot().stop(&self.name).await?)
    }
}

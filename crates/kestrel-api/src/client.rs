// SPDX-License-Identifier: LGPL-2.1-or-later

//! Typed client for `com.hihusky.Kestrel`.

#![allow(missing_docs)]

use std::collections::HashMap;

use zbus::{OwnedObjectPath, OwnedVariant};

use crate::{API_VERSION, BUS_NAME, HotspotSettings, ProfileSettings, ROOT_PATH, SecretBundle};

/// `(ssid, bssid, frequency MHz, signal dBm, security, matching profile path or "/")`.
pub type ScanResult = (String, String, u32, i16, String, OwnedObjectPath);
/// `(address, name, device type, WFD subelements)`.
pub type PeerInfo = (String, String, String, Vec<u8>);

#[zbus::proxy(
    interface = "com.hihusky.Kestrel.Manager",
    default_service = "com.hihusky.Kestrel",
    default_path = "/com/hihusky/Kestrel"
)]
pub trait Manager {
    #[zbus(property)]
    fn version(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn wireless_enabled(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn wireless_hardware_enabled(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn online_state(&self) -> zbus::Result<String>;
    fn set_wireless_enabled(&self, enabled: bool) -> zbus::Result<()>;
    fn add_profile(
        &self,
        settings: ProfileSettings,
        secrets: SecretBundle,
    ) -> zbus::Result<OwnedObjectPath>;
    fn import_certificate(&self, name: &str, pem: &str) -> zbus::Result<OwnedObjectPath>;
    /// `(unix_seconds, device, ssid, profile_id, outcome, detail)`
    fn history(
        &self,
        limit: u32,
    ) -> zbus::Result<Vec<(u64, String, String, String, String, String)>>;
    fn register_agent(&self, path: &zbus::ObjectPath<'_>) -> zbus::Result<()>;
    fn unregister_agent(&self, path: &zbus::ObjectPath<'_>) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "com.hihusky.Kestrel.Device",
    default_service = "com.hihusky.Kestrel"
)]
pub trait Device {
    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn hardware_address(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn capabilities(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn active_profile(&self) -> zbus::Result<OwnedObjectPath>;
    #[zbus(property)]
    fn bssid(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn frequency(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn security(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn scanning(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn ssid(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn addresses(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn gateways(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn dns(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn l3_phase(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn online_state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn signal(&self) -> zbus::Result<i16>;
    #[zbus(property)]
    fn last_failure(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn last_failure_detail(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn autoconnect_held(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn autoconnect_enabled(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn profiles_needing_secrets(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    #[zbus(property)]
    fn supported_security(&self) -> zbus::Result<Vec<String>>;
    fn scan(&self) -> zbus::Result<()>;
    fn connect(&self, profile: &zbus::ObjectPath<'_>) -> zbus::Result<()>;
    fn disconnect(&self) -> zbus::Result<()>;
    fn set_autoconnect(&self, enabled: bool) -> zbus::Result<()>;
    fn get_scan_results(&self) -> zbus::Result<Vec<ScanResult>>;
    #[zbus(signal)]
    fn scan_results_changed(&self) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "com.hihusky.Kestrel.P2P",
    default_service = "com.hihusky.Kestrel"
)]
pub trait P2p {
    #[zbus(property)]
    fn finding(&self) -> zbus::Result<bool>;
    fn find(&self, timeout_seconds: u32) -> zbus::Result<()>;
    fn stop_find(&self) -> zbus::Result<()>;
    fn set_wfd_subelements(&self, subelements: &[u8]) -> zbus::Result<()>;
    fn get_peers(&self) -> zbus::Result<Vec<PeerInfo>>;
    fn connect(
        &self,
        peer: &str,
        method: &str,
        pin: &str,
        go_intent: u8,
        persistent: bool,
    ) -> zbus::Result<OwnedObjectPath>;
    /// Starts a group as owner without GO negotiation. `frequency` is in
    /// MHz; 0 lets the backend choose.
    fn start_group(&self, frequency: u32, persistent: bool) -> zbus::Result<OwnedObjectPath>;
    fn connect_persistent(
        &self,
        group: &zbus::ObjectPath<'_>,
        peer: &str,
        frequency: u32,
    ) -> zbus::Result<OwnedObjectPath>;
    fn start_persistent_group(
        &self,
        group: &zbus::ObjectPath<'_>,
        frequency: u32,
    ) -> zbus::Result<OwnedObjectPath>;
    #[zbus(signal)]
    fn peer_found(
        &self,
        address: String,
        name: String,
        device_type: String,
        wfd_subelements: Vec<u8>,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    fn peer_lost(&self, address: String) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "com.hihusky.Kestrel.Hotspot",
    default_service = "com.hihusky.Kestrel"
)]
pub trait Hotspot {
    #[zbus(property)]
    fn state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn ssid(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn security(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn frequency(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn gateway(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn leases(&self) -> zbus::Result<Vec<(String, String)>>;
    #[zbus(property)]
    fn connected_clients(&self) -> zbus::Result<Vec<String>>;
    #[zbus(property)]
    fn failure(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn failure_detail(&self) -> zbus::Result<String>;
    fn start(&self, settings: HotspotSettings, secret: &str) -> zbus::Result<()>;
    fn stop(&self) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "com.hihusky.Kestrel.Certificate",
    default_service = "com.hihusky.Kestrel"
)]
pub trait Certificate {
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn fingerprint_sha256(&self) -> zbus::Result<String>;
    fn delete(&self) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "com.hihusky.Kestrel.P2pGroup",
    default_service = "com.hihusky.Kestrel"
)]
pub trait P2pGroup {
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn ssid(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn role(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn go_address(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn peer(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn last_connected(&self) -> zbus::Result<u64>;
    fn delete(&self) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "com.hihusky.Kestrel.Profile",
    default_service = "com.hihusky.Kestrel"
)]
pub trait Profile {
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn settings(&self) -> zbus::Result<ProfileSettings>;
    #[zbus(property)]
    fn has_secret(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn last_connected(&self) -> zbus::Result<u64>;
    fn update(
        &self,
        settings: ProfileSettings,
        secret_action: &str,
        secrets: SecretBundle,
    ) -> zbus::Result<()>;
    fn delete(&self) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "com.hihusky.Kestrel.Session",
    default_service = "com.hihusky.Kestrel"
)]
pub trait Session {
    #[zbus(property)]
    fn device(&self) -> zbus::Result<OwnedObjectPath>;
    #[zbus(property)]
    fn peer(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn incoming(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn autonomous(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn role(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn group_interface(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn peer_ip(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn failure(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn failure_detail(&self) -> zbus::Result<String>;
    fn close(&self) -> zbus::Result<()>;
}

type Objects = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedVariant>>>;

/// A connection to the Kestrel service.
#[derive(Debug, Clone)]
pub struct Client {
    connection: zbus::Connection,
}

impl Client {
    /// Connects and verifies the API version.
    pub async fn new(connection: zbus::Connection) -> zbus::Result<Self> {
        let client = Self { connection };
        let version = client.manager().await?.version().await?;
        if version != API_VERSION {
            return Err(zbus::Error::Failure(format!(
                "unsupported Kestrel API version {version} (expected {API_VERSION})"
            )));
        }
        Ok(client)
    }

    pub const fn connection(&self) -> &zbus::Connection {
        &self.connection
    }

    pub async fn manager(&self) -> zbus::Result<ManagerProxy<'static>> {
        ManagerProxy::new(&self.connection).await
    }

    async fn objects(&self) -> zbus::Result<Objects> {
        let proxy = zbus::fdo::ObjectManagerProxy::builder(&self.connection)
            .destination(BUS_NAME)
            .path(ROOT_PATH)
            .build()
            .await?;
        let objects = proxy.get_managed_objects().await?;
        Ok(objects
            .into_iter()
            .map(|(path, interfaces)| {
                (
                    path,
                    interfaces
                        .into_iter()
                        .map(|(name, props)| (name.to_string(), props))
                        .collect(),
                )
            })
            .collect())
    }

    async fn paths_with(&self, interface: &str) -> zbus::Result<Vec<OwnedObjectPath>> {
        let mut paths: Vec<OwnedObjectPath> = self
            .objects()
            .await?
            .into_iter()
            .filter(|(_, interfaces)| interfaces.contains_key(interface))
            .map(|(path, _)| path)
            .collect();
        paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(paths)
    }

    pub async fn devices(&self) -> zbus::Result<Vec<DeviceProxy<'static>>> {
        let mut proxies = Vec::new();
        for path in self.paths_with("com.hihusky.Kestrel.Device").await? {
            proxies.push(
                DeviceProxy::builder(&self.connection)
                    .path(path)
                    .cache_properties(zbus::proxy::CacheProperties::No)
                    .build()
                    .await?,
            );
        }
        Ok(proxies)
    }

    pub async fn device(&self, name: &str) -> zbus::Result<DeviceProxy<'static>> {
        let name = kestrel_model::InterfaceName::new(name)
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        DeviceProxy::builder(&self.connection)
            .path(crate::device_path(&name))
            .build()
            .await
    }

    pub async fn p2p(&self, name: &str) -> zbus::Result<P2pProxy<'static>> {
        let name = kestrel_model::InterfaceName::new(name)
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        P2pProxy::builder(&self.connection)
            .path(crate::device_path(&name))
            .build()
            .await
    }

    pub async fn hotspot(&self, name: &str) -> zbus::Result<HotspotProxy<'static>> {
        let name = kestrel_model::InterfaceName::new(name)
            .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        HotspotProxy::builder(&self.connection)
            .path(crate::device_path(&name))
            .build()
            .await
    }

    pub async fn certificates(&self) -> zbus::Result<Vec<CertificateProxy<'static>>> {
        let mut proxies = Vec::new();
        for path in self.paths_with("com.hihusky.Kestrel.Certificate").await? {
            proxies.push(
                CertificateProxy::builder(&self.connection)
                    .path(path)
                    .cache_properties(zbus::proxy::CacheProperties::No)
                    .build()
                    .await?,
            );
        }
        Ok(proxies)
    }

    pub async fn certificate(
        &self,
        path: OwnedObjectPath,
    ) -> zbus::Result<CertificateProxy<'static>> {
        CertificateProxy::builder(&self.connection)
            .path(path)
            .build()
            .await
    }

    pub async fn p2p_groups(&self) -> zbus::Result<Vec<P2pGroupProxy<'static>>> {
        let mut proxies = Vec::new();
        for path in self.paths_with("com.hihusky.Kestrel.P2pGroup").await? {
            proxies.push(
                P2pGroupProxy::builder(&self.connection)
                    .path(path)
                    .cache_properties(zbus::proxy::CacheProperties::No)
                    .build()
                    .await?,
            );
        }
        Ok(proxies)
    }

    pub async fn p2p_group(&self, path: OwnedObjectPath) -> zbus::Result<P2pGroupProxy<'static>> {
        P2pGroupProxy::builder(&self.connection)
            .path(path)
            .build()
            .await
    }

    pub async fn profiles(&self) -> zbus::Result<Vec<ProfileProxy<'static>>> {
        let mut proxies = Vec::new();
        for path in self.paths_with("com.hihusky.Kestrel.Profile").await? {
            proxies.push(
                ProfileProxy::builder(&self.connection)
                    .path(path)
                    .cache_properties(zbus::proxy::CacheProperties::No)
                    .build()
                    .await?,
            );
        }
        Ok(proxies)
    }

    pub async fn profile(&self, path: OwnedObjectPath) -> zbus::Result<ProfileProxy<'static>> {
        ProfileProxy::builder(&self.connection)
            .path(path)
            .build()
            .await
    }

    pub async fn sessions(&self) -> zbus::Result<Vec<SessionProxy<'static>>> {
        let mut proxies = Vec::new();
        for path in self.paths_with("com.hihusky.Kestrel.Session").await? {
            proxies.push(
                SessionProxy::builder(&self.connection)
                    .path(path)
                    .cache_properties(zbus::proxy::CacheProperties::No)
                    .build()
                    .await?,
            );
        }
        Ok(proxies)
    }

    pub async fn session(&self, path: OwnedObjectPath) -> zbus::Result<SessionProxy<'static>> {
        SessionProxy::builder(&self.connection)
            .path(path)
            .build()
            .await
    }
}

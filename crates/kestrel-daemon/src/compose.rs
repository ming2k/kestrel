// SPDX-License-Identifier: LGPL-2.1-or-later

//! The composition root: the only place that names concrete adapters.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kestrel_api::{AllowAll, Authorizer, Polkit, Server};
use kestrel_catalog::{Catalog, CatalogStores};
use kestrel_controller::{Controller, ControllerPorts, RadioControl};
use kestrel_l3_networkd::{Networkd, NetworkdConfig};
use kestrel_ports::l3::L3Provider;
use kestrel_ports::store::{
    CertStore, HistoryStore, P2pGroupStore, ProfileRepository, SecretStore, StateStore,
};
use kestrel_ports::wlan::WlanProvider;
use kestrel_store::{
    CertDirectory, CredsScope, HistoryFile, P2pGroupDirectory, ProfileDirectory, StateFile,
    SystemdCredsStore,
};
use kestrel_wlan_iwd::Iwd;
use kestrel_wlan_wpa::WpaSupplicant;
use thiserror::Error;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinHandle;

use crate::no_l3::NoL3;
use crate::notify::{notify, watchdog_interval};
use crate::power;
use crate::settings::{
    Authorization, L3Backend, SecretBackend, Settings, SettingsError, WirelessBackend,
};

#[derive(Debug, Error)]
pub(crate) enum DaemonError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error("cannot connect to the {bus} bus: {source}")]
    Bus { bus: String, source: zbus::Error },
    #[error("{0}")]
    Backend(String),
    #[error("cannot start: {0}")]
    Start(String),
    #[error("fatal runtime fault: {0}")]
    Fatal(String),
}

async fn connect(bus: &str) -> Result<zbus::Connection, DaemonError> {
    kestrel_api::bus::connect(bus)
        .await
        .map_err(|source| DaemonError::Bus {
            bus: bus.to_owned(),
            source,
        })
}

async fn has_owner(connection: &zbus::Connection, name: &str) -> bool {
    let Ok(proxy) = zbus::fdo::DBusProxy::new(connection).await else {
        return false;
    };
    match zbus::names::BusName::try_from(name) {
        Ok(name) => proxy.name_has_owner(name).await.unwrap_or(false),
        Err(_) => false,
    }
}

async fn wireless(
    settings: &Settings,
    connection: &zbus::Connection,
) -> Result<Arc<dyn WlanProvider>, DaemonError> {
    let backend = match settings.wireless.backend {
        WirelessBackend::Auto => {
            if has_owner(connection, "fi.w1.wpa_supplicant1").await {
                WirelessBackend::WpaSupplicant
            } else if has_owner(connection, "net.connman.iwd").await {
                WirelessBackend::Iwd
            } else {
                tracing::warn!(
                    "neither wpa_supplicant nor iwd is running; waiting for wpa_supplicant"
                );
                WirelessBackend::WpaSupplicant
            }
        }
        explicit => explicit,
    };
    let backend_error = |e: kestrel_ports::PortError| DaemonError::Backend(e.to_string());
    Ok(match backend {
        WirelessBackend::Iwd => {
            Arc::new(Iwd::new(connection.clone()).await.map_err(backend_error)?)
        }
        WirelessBackend::WpaSupplicant | WirelessBackend::Auto => Arc::new(
            WpaSupplicant::new(connection.clone())
                .await
                .map_err(backend_error)?,
        ),
    })
}

async fn l3(
    settings: &Settings,
    connection: &zbus::Connection,
) -> Result<Arc<dyn L3Provider>, DaemonError> {
    Ok(match settings.l3.backend {
        L3Backend::Networkd => Arc::new(
            Networkd::new(
                connection.clone(),
                NetworkdConfig {
                    unit_dir: settings.l3.unit_dir.clone(),
                    ..NetworkdConfig::default()
                },
            )
            .await
            .map_err(|e| DaemonError::Backend(e.to_string()))?,
        ),
        L3Backend::None => Arc::new(NoL3::default()),
    })
}

pub(crate) async fn run(config: &Path, bus: &str) -> Result<(), DaemonError> {
    let settings = Settings::load(config)?;
    let connection = connect(bus).await?;

    let wlan = wireless(&settings, &connection).await?;
    let l3 = l3(&settings, &connection).await?;
    let profiles: Arc<dyn ProfileRepository> =
        Arc::new(ProfileDirectory::new(&settings.storage.profiles));
    let scope = match settings.storage.secret_backend {
        SecretBackend::SystemdCreds => CredsScope::Host,
        SecretBackend::SystemdCredsUser => CredsScope::User,
    };
    let secrets: Arc<dyn SecretStore> =
        Arc::new(SystemdCredsStore::new(&settings.storage.secrets, scope));
    let certs: Arc<dyn CertStore> = Arc::new(CertDirectory::new(&settings.storage.certs));
    let p2p_groups: Arc<dyn P2pGroupStore> =
        Arc::new(P2pGroupDirectory::new(&settings.storage.p2p_groups));
    let history: Arc<dyn HistoryStore> = Arc::new(HistoryFile::new(&settings.storage.history));
    let state: Arc<dyn StateStore> = Arc::new(StateFile::new(&settings.storage.state));
    tracing::info!(
        wireless = wlan.name(),
        l3 = l3.name(),
        secrets = secrets.name(),
        "starting Kestrel"
    );

    let catalog = Catalog::open(CatalogStores {
        profiles,
        secrets,
        certs,
        p2p_groups,
        history,
    })
    .await
    .map_err(|e| DaemonError::Start(e.to_string()))?;

    let initial_hw = power::initial_hardware_enabled();
    let mut controller_config = settings.controller_config();
    controller_config.hardware_enabled = Some(initial_hw);
    let controller = Controller::start(
        controller_config,
        ControllerPorts { wlan, l3, state },
        catalog.clone(),
    )
    .await
    .map_err(|e| DaemonError::Start(e.to_string()))?;

    let power_task =
        power::watch(connection.clone(), controller.handle().radio(), initial_hw).await;

    let authorizer: Arc<dyn Authorizer> = match settings.api.authorization {
        Authorization::Polkit => Arc::new(Polkit::new(connection.clone())),
        Authorization::BusPolicy => {
            tracing::warn!("polkit authorization is disabled; only the bus policy applies");
            Arc::new(AllowAll)
        }
    };
    let mut server =
        match Server::serve(connection.clone(), controller.handle(), catalog, authorizer).await {
            Ok(server) => server,
            Err(error) => {
                power_task.abort();
                controller.shutdown().await;
                return Err(DaemonError::Start(format!("cannot serve the API: {error}")));
            }
        };
    let watchdog_task = spawn_watchdog(connection.clone(), controller.handle().radio());
    notify("READY=1\nSTATUS=running");
    tracing::info!("ready");

    let mut terminate =
        signal(SignalKind::terminate()).map_err(|e| DaemonError::Start(e.to_string()))?;
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|e| DaemonError::Start(e.to_string()))?;
    let fatal_fault = tokio::select! {
        _ = terminate.recv() => None,
        _ = interrupt.recv() => None,
        reason = server.wait_fault() => Some(reason),
    };
    notify("STOPPING=1\nSTATUS=stopping");
    if let Some(reason) = &fatal_fault {
        tracing::error!(%reason, "fatal runtime fault; shutting down for supervisor recovery");
    } else {
        tracing::info!("stopping");
    }
    if let Some(task) = watchdog_task {
        task.abort();
    }
    power_task.abort();
    server.stop().await;
    controller.shutdown().await;
    tracing::info!("stopped cleanly");
    if let Some(reason) = fatal_fault {
        Err(DaemonError::Fatal(reason))
    } else {
        Ok(())
    }
}

/// Starts an active-liveness systemd watchdog task when `WATCHDOG_USEC` is set.
///
/// Each tick proves both `RadioCoordinator` responsiveness and D-Bus round-trip
/// health before sending `WATCHDOG=1`. If either stalls, petting stops so
/// systemd restarts `kestrel.service` and startup sweep reconciles state.
fn spawn_watchdog(connection: zbus::Connection, radio: RadioControl) -> Option<JoinHandle<()>> {
    let watchdog = watchdog_interval()?;
    let period = (watchdog / 2).max(Duration::from_millis(250));
    let probe_timeout = (watchdog / 4).clamp(Duration::from_secs(1), Duration::from_secs(5));
    tracing::info!(
        watchdog_secs = watchdog.as_secs_f64(),
        period_secs = period.as_secs_f64(),
        "systemd watchdog enabled"
    );
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let radio_ok = matches!(
                tokio::time::timeout(probe_timeout, radio.wireless_enabled()).await,
                Ok(Ok(_))
            );
            let bus_ok = matches!(
                tokio::time::timeout(probe_timeout, async {
                    let proxy = zbus::fdo::DBusProxy::new(&connection).await?;
                    proxy.get_id().await
                })
                .await,
                Ok(Ok(_))
            );
            if radio_ok && bus_ok {
                notify("WATCHDOG=1");
            } else {
                tracing::error!(
                    radio_ok,
                    bus_ok,
                    "liveness probe failed; withholding systemd WATCHDOG=1"
                );
            }
        }
    }))
}

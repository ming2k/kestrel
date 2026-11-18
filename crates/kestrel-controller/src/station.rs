// SPDX-License-Identifier: LGPL-2.1-or-later

//! Station lifecycle driver: executes [`StationCommand`]s against `WlanProvider`,
//! `L3Provider`, `Catalog`, and `Agent`, and records connection history.

use std::sync::Arc;
use std::time::Duration;

use kestrel_catalog::Catalog;
use kestrel_machines::station::{
    StationCommand, StationCommandKind, StationSnapshot, StationState,
};
use kestrel_model::{
    ConnectionEvent, ConnectionOutcome, FailureReason, InterfaceName, L3Config, MacAddress,
    ProfileId, ProfileSecrets, SecretKey, WifiProfile,
};
use kestrel_ports::PortError;
use kestrel_ports::agent::{Agent, SecretRequest};
use kestrel_ports::l3::{L3Intent, L3Provider};
use kestrel_ports::wlan::{ConnectRequest, EnterpriseConnect, WlanProvider};
use tokio::sync::mpsc;

use crate::l3;
use crate::radio::Msg;

#[derive(Debug)]
pub(crate) enum StationJob {
    Scan {
        device: InterfaceName,
    },
    Associate {
        device: InterfaceName,
        profile: Box<WifiProfile>,
        bssid: Option<MacAddress>,
    },
    Disassociate {
        device: InterfaceName,
    },
    BindL3 {
        device: InterfaceName,
        intent: L3Intent,
    },
    UnbindL3 {
        device: InterfaceName,
    },
}

#[derive(Clone)]
pub(crate) struct StationExecContext {
    pub(crate) wlan: Arc<dyn WlanProvider>,
    pub(crate) l3: Arc<dyn L3Provider>,
    pub(crate) catalog: Catalog,
    pub(crate) tx: mpsc::UnboundedSender<Msg>,
}

fn fail(
    tx: &mpsc::UnboundedSender<Msg>,
    device: &InterfaceName,
    command: StationCommandKind,
    reason: FailureReason,
) {
    let _ = tx.send(Msg::StationFailed {
        device: device.clone(),
        command,
        reason,
    });
}

pub(crate) async fn execute_job(ctx: &StationExecContext, job: StationJob) {
    match job {
        StationJob::Scan { device } => {
            if let Err(error) = ctx.wlan.start_scan(&device).await {
                tracing::warn!(%device, %error, "scan request failed");
                fail(&ctx.tx, &device, StationCommandKind::Scan, error.into());
            }
        }
        StationJob::Associate {
            device,
            profile,
            bssid,
        } => {
            if let Err((command, reason)) = associate(ctx, &device, *profile, bssid).await {
                fail(&ctx.tx, &device, command, reason);
            }
        }
        StationJob::Disassociate { device } => {
            if let Err(error) = ctx.wlan.disconnect(&device).await {
                tracing::warn!(%device, %error, "disassociation failed; the sweep will retry");
                fail(
                    &ctx.tx,
                    &device,
                    StationCommandKind::Disassociate,
                    error.into(),
                );
            }
        }
        StationJob::BindL3 { device, intent } => {
            if let Err(reason) = l3::bind_intent(&*ctx.l3, &device, &intent).await {
                fail(&ctx.tx, &device, StationCommandKind::BindL3, reason);
            }
        }
        StationJob::UnbindL3 { device } => {
            if let Err(reason) = l3::unbind(&*ctx.l3, None, &device).await {
                fail(&ctx.tx, &device, StationCommandKind::UnbindL3, reason);
            }
        }
    }
}

async fn associate(
    ctx: &StationExecContext,
    device: &InterfaceName,
    profile: WifiProfile,
    bssid: Option<MacAddress>,
) -> Result<(), (StationCommandKind, FailureReason)> {
    let secrets = load_station_secrets(&ctx.catalog, &profile)
        .await
        .map_err(|reason| (StationCommandKind::Associate, reason))?;
    let enterprise = resolve_enterprise(&ctx.catalog, &profile)
        .map_err(|reason| (StationCommandKind::Associate, reason))?;

    let request = ConnectRequest {
        ssid: profile.ssid.clone(),
        security: profile.security,
        secrets,
        enterprise,
        hidden: profile.hidden,
        bssid,
    };
    tracing::info!(%device, profile = %profile.id, ssid = %profile.ssid, "associating");
    ctx.wlan.connect(device, request).await.map_err(|error| {
        tracing::warn!(%device, %error, "association request failed");
        (StationCommandKind::Associate, error.into())
    })
}

async fn load_station_secrets(
    catalog: &Catalog,
    profile: &WifiProfile,
) -> Result<ProfileSecrets, FailureReason> {
    if !profile.security.needs_secret() {
        return Ok(ProfileSecrets::default());
    }
    match catalog.load_secret(SecretKey::Profile(profile.id)).await {
        Ok(Some(secrets)) if secrets.satisfies(profile) => Ok(secrets),
        Ok(_) => Err(FailureReason::SecretsRequired),
        Err(PortError::CorruptSecret(reason)) => {
            tracing::warn!(
                profile = %profile.id,
                %reason,
                "stored secret cannot be unsealed; requesting a fresh secret"
            );
            Err(FailureReason::SecretsRequired)
        }
        Err(error) => {
            tracing::error!(profile = %profile.id, %error, "cannot read secret");
            Err(error.into())
        }
    }
}

fn resolve_enterprise(
    catalog: &Catalog,
    profile: &WifiProfile,
) -> Result<Option<EnterpriseConnect>, FailureReason> {
    let Some(config) = &profile.enterprise else {
        return Ok(None);
    };
    let ca_cert_pem = match config.ca_cert {
        Some(id) => {
            let cert = catalog
                .certificate(id)
                .map_err(|_| FailureReason::Backend(format!("CA certificate {id} is missing")))?;
            Some(cert.pem.as_bytes().to_vec())
        }
        None => None,
    };
    let client_cert_pem = match config.client_cert {
        Some(id) => {
            let cert = catalog.certificate(id).map_err(|_| {
                FailureReason::Backend(format!("client certificate {id} is missing"))
            })?;
            Some(cert.pem.as_bytes().to_vec())
        }
        None => None,
    };
    Ok(Some(EnterpriseConnect {
        config: config.clone(),
        ca_cert_pem,
        client_cert_pem,
    }))
}

pub(crate) fn plan_job(
    catalog: &Catalog,
    tx: &mpsc::UnboundedSender<Msg>,
    device: &InterfaceName,
    command: &StationCommand,
) -> Option<StationJob> {
    match command {
        StationCommand::Scan => Some(StationJob::Scan {
            device: device.clone(),
        }),
        StationCommand::Associate { profile, bssid } => {
            if let Ok(profile) = catalog.profile(*profile) {
                Some(StationJob::Associate {
                    device: device.clone(),
                    profile: Box::new(profile),
                    bssid: *bssid,
                })
            } else {
                fail(
                    tx,
                    device,
                    StationCommandKind::Associate,
                    FailureReason::Backend("profile vanished".to_owned()),
                );
                None
            }
        }
        StationCommand::Disassociate => Some(StationJob::Disassociate {
            device: device.clone(),
        }),
        StationCommand::BindL3 { profile } => {
            let l3 = catalog.profile(*profile).ok().map(|p| p.l3);
            let intent = match l3 {
                Some(L3Config::Dhcp { ipv6 }) => L3Intent::DhcpClient {
                    ipv6,
                    anonymize: false,
                    required_for_online: true,
                },
                Some(L3Config::Static(config)) => L3Intent::Static(config),
                Some(L3Config::Unmanaged) | None => {
                    fail(
                        tx,
                        device,
                        StationCommandKind::BindL3,
                        FailureReason::Backend("no managed L3 for profile".to_owned()),
                    );
                    return None;
                }
            };
            Some(StationJob::BindL3 {
                device: device.clone(),
                intent,
            })
        }
        StationCommand::UnbindL3 => Some(StationJob::UnbindL3 {
            device: device.clone(),
        }),
        StationCommand::StartTimer { kind, token, after } => {
            let tx = tx.clone();
            let device = device.clone();
            let kind = *kind;
            let token = *token;
            let after = *after;
            tokio::spawn(async move {
                tokio::time::sleep(after).await;
                let _ = tx.send(Msg::StationTimer {
                    device,
                    kind,
                    token,
                });
            });
            None
        }
        StationCommand::RequestSecrets { .. } | StationCommand::RecordConnected { .. } => {
            unreachable!("handled directly by coordinator")
        }
    }
}

pub(crate) fn spawn_secret_prompt(
    catalog: Catalog,
    agent: Option<Arc<dyn Agent>>,
    tx: mpsc::UnboundedSender<Msg>,
    timeout: Duration,
    device: InterfaceName,
    profile: WifiProfile,
    reason: FailureReason,
) {
    let id = profile.id;
    let request = SecretRequest {
        device,
        profile: id,
        ssid: profile.ssid,
        security: profile.security,
        reason,
    };
    tokio::spawn(async move {
        match agent {
            None => {
                tracing::info!(profile = %id, "secrets required but no agent is registered");
                catalog.notify_secrets_unavailable(id);
            }
            Some(agent) => match tokio::time::timeout(timeout, agent.request_secret(request)).await
            {
                Ok(Some(secret)) => {
                    let _ = catalog.supply_agent_secret(id, secret).await;
                }
                Ok(None) => catalog.notify_secrets_unavailable(id),
                Err(_) => {
                    tracing::warn!(profile = %id, "agent did not answer in time");
                    catalog.notify_secrets_unavailable(id);
                }
            },
        }
        let _ = tx.send(Msg::SecretPromptFinished(id));
    });
}

#[derive(Debug)]
pub(crate) enum HistoryJob {
    MarkConnected {
        id: ProfileId,
        at: u64,
        event: ConnectionEvent,
    },
    Record(ConnectionEvent),
}

pub(crate) async fn execute_history_job(catalog: Catalog, job: HistoryJob) {
    match job {
        HistoryJob::MarkConnected { id, at, event } => {
            if let Err(error) = catalog.mark_profile_connected(id, at).await {
                tracing::warn!(profile = %id, %error, "cannot record connection time");
            }
            catalog.record_history(&event).await;
        }
        HistoryJob::Record(event) => {
            catalog.record_history(&event).await;
        }
    }
}

pub(crate) fn plan_connected(
    catalog: &Catalog,
    device: &InterfaceName,
    id: ProfileId,
    at: u64,
) -> Option<HistoryJob> {
    let profile = catalog.profile(id).ok()?;
    let event = ConnectionEvent {
        at,
        device: device.to_string(),
        ssid: profile.ssid.to_string(),
        profile: Some(id),
        outcome: ConnectionOutcome::Connected,
        detail: None,
    };
    Some(HistoryJob::MarkConnected { id, at, event })
}

pub(crate) fn plan_transition(
    catalog: &Catalog,
    device: &InterfaceName,
    before: &StationSnapshot,
    after: &StationSnapshot,
    at: u64,
) -> Option<HistoryJob> {
    let id = after.state.profile().or(before.state.profile())?;
    let profile = catalog.profile(id).ok()?;
    let (outcome, detail) = if let Some(failure) = &after.last_failure
        && before.last_failure.as_ref() != Some(failure)
    {
        (ConnectionOutcome::Failed, Some(failure.code().to_owned()))
    } else if matches!(before.state, StationState::Connected { .. })
        && !matches!(after.state, StationState::Connected { .. })
        && matches!(
            after.state,
            StationState::Idle | StationState::Disabled | StationState::Waiting { .. }
        )
    {
        (ConnectionOutcome::Disconnected, None)
    } else {
        return None;
    };
    Some(HistoryJob::Record(ConnectionEvent {
        at,
        device: device.to_string(),
        ssid: profile.ssid.to_string(),
        profile: Some(id),
        outcome,
        detail,
    }))
}

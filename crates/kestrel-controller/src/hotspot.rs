// SPDX-License-Identifier: LGPL-2.1-or-later

//! SoftAP / hotspot lifecycle driver.

use std::sync::{Arc, Mutex};

use kestrel_machines::hotspot::{HotspotCommand, HotspotCommandKind};
use kestrel_model::{FailureReason, HotspotConfig as ModelHotspotConfig, InterfaceName, Secret};
use kestrel_ports::ap::{ApProvider, ApStartRequest};
use kestrel_ports::l3::L3Provider;
use tokio::sync::mpsc;

use crate::l3;
use crate::radio::Msg;
use crate::subnet::SubnetAllocator;

#[derive(Debug)]
pub(crate) enum HotspotJob {
    StartAp {
        device: InterfaceName,
        config: ModelHotspotConfig,
        secret: Option<Secret>,
    },
    StopAp {
        device: InterfaceName,
    },
    BindShared {
        device: InterfaceName,
    },
    UnbindL3 {
        device: InterfaceName,
    },
}

#[derive(Clone)]
pub(crate) struct HotspotExecContext {
    pub(crate) ap: Option<Arc<dyn ApProvider>>,
    pub(crate) l3: Arc<dyn L3Provider>,
    pub(crate) allocator: Arc<Mutex<SubnetAllocator>>,
    pub(crate) tx: mpsc::UnboundedSender<Msg>,
}

fn fail(
    tx: &mpsc::UnboundedSender<Msg>,
    device: &InterfaceName,
    command: HotspotCommandKind,
    reason: FailureReason,
) {
    let _ = tx.send(Msg::HotspotFailed {
        device: device.clone(),
        command,
        reason,
    });
}

pub(crate) async fn execute_job(ctx: &HotspotExecContext, job: HotspotJob) {
    match job {
        HotspotJob::StartAp {
            device,
            config,
            secret,
        } => {
            let Some(ap) = &ctx.ap else {
                fail(
                    &ctx.tx,
                    &device,
                    HotspotCommandKind::StartAp,
                    FailureReason::NotSupported("SoftAP".to_owned()),
                );
                return;
            };
            let req = ApStartRequest {
                ssid: config.ssid,
                security: config.security,
                secret,
                frequency: config.frequency,
                hidden: config.hidden,
            };
            tracing::info!(%device, ssid = %req.ssid, security = %req.security, "starting SoftAP");
            if let Err(error) = ap.start_ap(&device, &req).await {
                tracing::warn!(%device, %error, "SoftAP start failed");
                fail(&ctx.tx, &device, HotspotCommandKind::StartAp, error.into());
            }
        }
        HotspotJob::StopAp { device } => {
            if let Some(ap) = &ctx.ap
                && let Err(error) = ap.stop_ap(&device).await
            {
                tracing::warn!(%device, %error, "SoftAP stop failed; the sweep will retry");
                fail(&ctx.tx, &device, HotspotCommandKind::StopAp, error.into());
            }
        }
        HotspotJob::BindShared { device } => {
            match l3::bind_shared_subnet(&*ctx.l3, &ctx.allocator, &device, true, true).await {
                Ok(gateway) => {
                    let _ = ctx.tx.send(Msg::HotspotGateway { device, gateway });
                }
                Err(reason) => fail(&ctx.tx, &device, HotspotCommandKind::BindL3, reason),
            }
        }
        HotspotJob::UnbindL3 { device } => {
            if let Err(reason) = l3::unbind(&*ctx.l3, Some(&*ctx.allocator), &device).await {
                fail(&ctx.tx, &device, HotspotCommandKind::UnbindL3, reason);
            }
        }
    }
}

pub(crate) fn plan_job(
    tx: &mpsc::UnboundedSender<Msg>,
    device: &InterfaceName,
    secret: Option<Secret>,
    command: HotspotCommand,
) -> Option<HotspotJob> {
    match command {
        HotspotCommand::StartAp(config) => Some(HotspotJob::StartAp {
            device: device.clone(),
            config,
            secret,
        }),
        HotspotCommand::StopAp => Some(HotspotJob::StopAp {
            device: device.clone(),
        }),
        HotspotCommand::BindL3 => Some(HotspotJob::BindShared {
            device: device.clone(),
        }),
        HotspotCommand::UnbindL3 => Some(HotspotJob::UnbindL3 {
            device: device.clone(),
        }),
        HotspotCommand::StartTimer { kind, token, after } => {
            let tx = tx.clone();
            let device = device.clone();
            tokio::spawn(async move {
                tokio::time::sleep(after).await;
                let _ = tx.send(Msg::HotspotTimer {
                    device,
                    kind,
                    token,
                });
            });
            None
        }
    }
}

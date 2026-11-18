// SPDX-License-Identifier: LGPL-2.1-or-later

//! Wi-Fi Direct session driver: executes [`SessionCommand`]s against
//! `P2pProvider`, `L3Provider`, and `Catalog`.

use std::sync::{Arc, Mutex};

use kestrel_catalog::Catalog;
use kestrel_machines::p2p::{L3Request, SessionCommand, SessionCommandKind};
use kestrel_model::{
    FailureReason, InterfaceName, Ipv6Mode, MacAddress, P2pGroupId, P2pGroupProfile, P2pRole,
    Secret, SecretKey, SessionId, Ssid,
};
use kestrel_ports::l3::{L3Intent, L3Provider};
use kestrel_ports::p2p::{P2pConnectRequest, P2pGroupRequest, P2pProvider, PersistentGroupConnect};
use tokio::sync::mpsc;

use crate::l3;
use crate::radio::Msg;
use crate::subnet::SubnetAllocator;

#[derive(Debug)]
pub(crate) enum SessionJob {
    Connect {
        id: SessionId,
        device: InterfaceName,
        request: P2pConnectRequest,
    },
    StartGroup {
        id: SessionId,
        device: InterfaceName,
        request: P2pGroupRequest,
    },
    ConnectPersistent {
        id: SessionId,
        device: InterfaceName,
        group: Box<P2pGroupProfile>,
        peer: MacAddress,
        frequency: Option<u32>,
    },
    StartPersistentGroup {
        id: SessionId,
        device: InterfaceName,
        group: Box<P2pGroupProfile>,
        frequency: Option<u32>,
    },
    AuthorizeGroup {
        id: SessionId,
        device: InterfaceName,
        group_if: InterfaceName,
    },
    Cancel {
        id: SessionId,
        device: InterfaceName,
    },
    BindShared {
        id: SessionId,
        link: InterfaceName,
    },
    BindDhcp {
        id: SessionId,
        link: InterfaceName,
    },
    UnbindL3 {
        id: SessionId,
        link: InterfaceName,
    },
    RemoveGroup {
        id: SessionId,
        device: InterfaceName,
        group_if: InterfaceName,
    },
}

#[derive(Clone)]
pub(crate) struct SessionExecContext {
    pub(crate) p2p: Option<Arc<dyn P2pProvider>>,
    pub(crate) l3: Arc<dyn L3Provider>,
    pub(crate) catalog: Catalog,
    pub(crate) allocator: Arc<Mutex<SubnetAllocator>>,
    pub(crate) tx: mpsc::UnboundedSender<Msg>,
}

fn fail(
    tx: &mpsc::UnboundedSender<Msg>,
    id: SessionId,
    command: SessionCommandKind,
    reason: FailureReason,
) {
    let _ = tx.send(Msg::SessionFailed {
        id,
        command,
        reason,
    });
}

fn require_p2p(
    ctx: &SessionExecContext,
    id: SessionId,
    command: SessionCommandKind,
) -> Option<&Arc<dyn P2pProvider>> {
    if let Some(p2p) = &ctx.p2p {
        Some(p2p)
    } else {
        fail(
            &ctx.tx,
            id,
            command,
            FailureReason::NotSupported("P2P".to_owned()),
        );
        None
    }
}

async fn load_psk(
    ctx: &SessionExecContext,
    id: SessionId,
    command: SessionCommandKind,
    group_id: P2pGroupId,
) -> Option<Secret> {
    match ctx.catalog.load_secret(SecretKey::P2pGroup(group_id)).await {
        Ok(Some(secrets)) => {
            if let Some(psk) = secrets.passphrase {
                Some(psk)
            } else {
                fail(&ctx.tx, id, command, FailureReason::SecretsRequired);
                None
            }
        }
        Ok(None) => {
            fail(&ctx.tx, id, command, FailureReason::SecretsRequired);
            None
        }
        Err(error) => {
            fail(&ctx.tx, id, command, error.into());
            None
        }
    }
}

pub(crate) async fn execute_job(ctx: &SessionExecContext, job: SessionJob) {
    match job {
        SessionJob::Connect {
            id,
            device,
            request,
        } => execute_connect(ctx, id, &device, &request).await,
        SessionJob::StartGroup {
            id,
            device,
            request,
        } => execute_start_group(ctx, id, &device, &request).await,
        SessionJob::ConnectPersistent {
            id,
            device,
            group,
            peer,
            frequency,
        } => execute_connect_persistent(ctx, id, &device, *group, peer, frequency).await,
        SessionJob::StartPersistentGroup {
            id,
            device,
            group,
            frequency,
        } => execute_start_persistent_group(ctx, id, &device, &group, frequency).await,
        SessionJob::AuthorizeGroup {
            id,
            device,
            group_if,
        } => {
            if let Some(p2p) = &ctx.p2p {
                tracing::info!(%device, %group_if, "authorizing a client into the group");
                if let Err(error) = p2p.authorize_group(&device, &group_if).await {
                    tracing::warn!(%group_if, %error, "P2P group authorization failed");
                    fail(
                        &ctx.tx,
                        id,
                        SessionCommandKind::AuthorizeGroup,
                        error.into(),
                    );
                }
            }
        }
        SessionJob::Cancel { id, device } => {
            if let Some(p2p) = &ctx.p2p
                && let Err(error) = p2p.cancel(&device).await
            {
                fail(
                    &ctx.tx,
                    id,
                    SessionCommandKind::CancelNegotiation,
                    error.into(),
                );
            }
        }
        SessionJob::BindShared { id, link } => {
            if let Err(reason) =
                l3::bind_shared_subnet(&*ctx.l3, &ctx.allocator, &link, false, false).await
            {
                fail(&ctx.tx, id, SessionCommandKind::BindL3, reason);
            }
        }
        SessionJob::BindDhcp { id, link } => {
            let intent = L3Intent::DhcpClient {
                ipv6: Ipv6Mode::Disabled,
                anonymize: true,
                required_for_online: false,
            };
            if let Err(reason) = l3::bind_intent(&*ctx.l3, &link, &intent).await {
                fail(&ctx.tx, id, SessionCommandKind::BindL3, reason);
            }
        }
        SessionJob::UnbindL3 { id, link } => {
            if let Err(reason) = l3::unbind(&*ctx.l3, Some(&*ctx.allocator), &link).await {
                fail(&ctx.tx, id, SessionCommandKind::UnbindL3, reason);
            }
        }
        SessionJob::RemoveGroup {
            id,
            device,
            group_if,
        } => {
            if let Some(p2p) = &ctx.p2p
                && let Err(error) = p2p.remove_group(&device, &group_if).await
            {
                tracing::warn!(%group_if, %error, "group removal failed; the sweep will retry");
                fail(&ctx.tx, id, SessionCommandKind::RemoveGroup, error.into());
            }
        }
    }
}

async fn execute_connect(
    ctx: &SessionExecContext,
    id: SessionId,
    device: &InterfaceName,
    request: &P2pConnectRequest,
) {
    let Some(p2p) = require_p2p(ctx, id, SessionCommandKind::Connect) else {
        return;
    };
    tracing::info!(
        %device,
        peer = %request.peer,
        method = request.method.as_str(),
        go_intent = request.go_intent.get(),
        persistent = request.persistent,
        "starting P2P connection"
    );
    match p2p.connect(device, request).await {
        Ok(pin) => {
            let _ = ctx.tx.send(Msg::SessionConnectAccepted { id, pin });
        }
        Err(error) => {
            tracing::warn!(%device, %error, "P2P connect failed");
            fail(&ctx.tx, id, SessionCommandKind::Connect, error.into());
        }
    }
}

async fn execute_start_group(
    ctx: &SessionExecContext,
    id: SessionId,
    device: &InterfaceName,
    request: &P2pGroupRequest,
) {
    let Some(p2p) = require_p2p(ctx, id, SessionCommandKind::StartGroup) else {
        return;
    };
    tracing::info!(
        %device,
        frequency = ?request.frequency,
        persistent = request.persistent,
        "starting an autonomous P2P group"
    );
    if let Err(error) = p2p.start_group(device, request).await {
        tracing::warn!(%device, %error, "P2P group add failed");
        fail(&ctx.tx, id, SessionCommandKind::StartGroup, error.into());
    }
}

async fn execute_connect_persistent(
    ctx: &SessionExecContext,
    id: SessionId,
    device: &InterfaceName,
    group: P2pGroupProfile,
    peer: MacAddress,
    frequency: Option<u32>,
) {
    let Some(p2p) = require_p2p(ctx, id, SessionCommandKind::ConnectPersistent) else {
        return;
    };
    let Some(psk) = load_psk(ctx, id, SessionCommandKind::ConnectPersistent, group.id).await else {
        return;
    };
    let req = PersistentGroupConnect {
        peer,
        role: group.role,
        ssid: group.ssid,
        go_address: group.go_address,
        psk,
        frequency,
    };
    if let Err(error) = p2p.connect_persistent(device, &req).await {
        fail(
            &ctx.tx,
            id,
            SessionCommandKind::ConnectPersistent,
            error.into(),
        );
    }
}

async fn execute_start_persistent_group(
    ctx: &SessionExecContext,
    id: SessionId,
    device: &InterfaceName,
    group: &P2pGroupProfile,
    frequency: Option<u32>,
) {
    let Some(p2p) = require_p2p(ctx, id, SessionCommandKind::StartPersistentGroup) else {
        return;
    };
    let Some(psk) = load_psk(ctx, id, SessionCommandKind::StartPersistentGroup, group.id).await
    else {
        return;
    };
    if let Err(error) = p2p
        .start_persistent_group(device, &group.ssid, group.go_address, &psk, frequency)
        .await
    {
        fail(
            &ctx.tx,
            id,
            SessionCommandKind::StartPersistentGroup,
            error.into(),
        );
    }
}

pub(crate) fn plan_job(
    catalog: &Catalog,
    tx: &mpsc::UnboundedSender<Msg>,
    id: SessionId,
    device: &InterfaceName,
    command: SessionCommand,
) -> Option<SessionJob> {
    let device = device.clone();
    match command {
        SessionCommand::Connect {
            peer,
            method,
            go_intent,
            persistent,
        } => Some(SessionJob::Connect {
            id,
            device,
            request: P2pConnectRequest {
                peer,
                method,
                go_intent,
                persistent,
            },
        }),
        SessionCommand::StartGroup {
            frequency,
            persistent,
        } => Some(SessionJob::StartGroup {
            id,
            device,
            request: P2pGroupRequest {
                frequency,
                persistent,
            },
        }),
        SessionCommand::ConnectPersistent {
            group_id,
            peer,
            frequency,
        } => lookup_group(
            catalog,
            tx,
            id,
            group_id,
            SessionCommandKind::ConnectPersistent,
        )
        .map(|group| SessionJob::ConnectPersistent {
            id,
            device,
            group: Box::new(group),
            peer,
            frequency,
        }),
        SessionCommand::StartPersistentGroup {
            group_id,
            frequency,
        } => lookup_group(
            catalog,
            tx,
            id,
            group_id,
            SessionCommandKind::StartPersistentGroup,
        )
        .map(|group| SessionJob::StartPersistentGroup {
            id,
            device,
            group: Box::new(group),
            frequency,
        }),
        SessionCommand::AuthorizeGroup { group_if } => Some(SessionJob::AuthorizeGroup {
            id,
            device,
            group_if,
        }),
        SessionCommand::CancelNegotiation => Some(SessionJob::Cancel { id, device }),
        SessionCommand::BindL3 { link, request } => match request {
            L3Request::SharedSubnet => Some(SessionJob::BindShared { id, link }),
            L3Request::DhcpClient => Some(SessionJob::BindDhcp { id, link }),
        },
        SessionCommand::UnbindL3 { link } => Some(SessionJob::UnbindL3 { id, link }),
        SessionCommand::RemoveGroup { group_if } => Some(SessionJob::RemoveGroup {
            id,
            device,
            group_if,
        }),
        SessionCommand::StartTimer { kind, token, after } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(after).await;
                let _ = tx.send(Msg::SessionTimer { id, kind, token });
            });
            None
        }
    }
}

fn lookup_group(
    catalog: &Catalog,
    tx: &mpsc::UnboundedSender<Msg>,
    id: SessionId,
    group_id: P2pGroupId,
    command: SessionCommandKind,
) -> Option<P2pGroupProfile> {
    if let Ok(group) = catalog.p2p_group(group_id) {
        return Some(group);
    }
    fail(
        tx,
        id,
        command,
        FailureReason::Backend("persistent group vanished".to_owned()),
    );
    None
}

pub(crate) struct FormedGroup {
    pub(crate) role: P2pRole,
    pub(crate) ssid: Ssid,
    pub(crate) go_address: MacAddress,
    pub(crate) peer: Option<MacAddress>,
    pub(crate) fallback_name: String,
    pub(crate) psk: Secret,
    pub(crate) at: u64,
}

pub(crate) fn spawn_save_persistent_group(catalog: Catalog, group: FormedGroup) {
    tokio::spawn(async move {
        if let Err(error) = catalog
            .save_formed_p2p_group(
                group.role,
                group.ssid,
                group.go_address,
                group.peer,
                group.fallback_name,
                group.psk,
                group.at,
            )
            .await
        {
            tracing::warn!(%error, "cannot save persistent P2P group");
        }
    });
}

// SPDX-License-Identifier: LGPL-2.1-or-later

//! Shared L3 intent execution and peer address extraction helpers.

use std::net::IpAddr;
use std::sync::Mutex;

use kestrel_model::{FailureReason, InterfaceName, Ipv4Net, P2pRole};
use kestrel_ports::l3::{L3Intent, L3Provider, L3Status, SharedSubnet};

use crate::subnet::{SubnetAllocator, dhcp_pool, gateway_address};

pub(crate) async fn bind_intent(
    l3: &dyn L3Provider,
    link: &InterfaceName,
    intent: &L3Intent,
) -> Result<(), FailureReason> {
    tracing::info!(%link, ?intent, "binding L3");
    l3.bind(link, intent).await.map_err(|error| {
        tracing::warn!(%link, %error, "L3 bind failed");
        error.into()
    })
}

pub(crate) async fn bind_shared_subnet(
    l3: &dyn L3Provider,
    allocator: &Mutex<SubnetAllocator>,
    link: &InterfaceName,
    emit_router: bool,
    masquerade: bool,
) -> Result<Ipv4Net, FailureReason> {
    let in_use = l3.addresses_in_use().await?;
    let subnet = allocator
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .allocate(link, &in_use)
        .ok_or_else(|| {
            tracing::warn!(%link, "no free subnet in the configured pool");
            FailureReason::NoSubnet
        })?;
    let (pool_offset, pool_size) = dhcp_pool(subnet);
    let gateway = gateway_address(subnet);
    let intent = L3Intent::SharedSubnet(SharedSubnet {
        address: gateway,
        pool_offset,
        pool_size,
        emit_router,
        masquerade,
    });
    tracing::info!(%link, %subnet, masquerade, "binding shared L3 subnet");
    if let Err(error) = l3.bind(link, &intent).await {
        allocator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release(link);
        tracing::warn!(%link, %error, "L3 bind failed");
        return Err(error.into());
    }
    Ok(gateway)
}

pub(crate) async fn unbind(
    l3: &dyn L3Provider,
    allocator: Option<&Mutex<SubnetAllocator>>,
    link: &InterfaceName,
) -> Result<(), FailureReason> {
    let result = l3.unbind(link).await;
    if let Some(allocator) = allocator {
        allocator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release(link);
    }
    result.map_err(|error| {
        tracing::warn!(%link, %error, "L3 unbind failed; the sweep will retry");
        error.into()
    })
}

/// The peer's address: the lease we handed out as Group Owner, or the
/// Group Owner's address as client.
pub(crate) fn peer_ip(role: Option<P2pRole>, status: &L3Status) -> Option<IpAddr> {
    match role? {
        P2pRole::GroupOwner => status.leases.first().map(|lease| IpAddr::V4(lease.address)),
        P2pRole::Client => status.dhcp_server.or_else(|| {
            status
                .gateways
                .iter()
                .find(|gateway| gateway.is_ipv4())
                .or_else(|| status.gateways.first())
                .copied()
        }),
    }
}

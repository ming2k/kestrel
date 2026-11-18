// SPDX-License-Identifier: LGPL-2.1-or-later

//! The L3 provider for `l3.backend = "none"` (L2-only deployments).

use async_trait::async_trait;
use kestrel_model::{InterfaceName, IpNet};
use kestrel_ports::l3::{L3Event, L3Intent, L3Provider, L3Status};
use kestrel_ports::{EventBus, PortError, PortResult, Subscription};

#[derive(Debug, Default)]
pub(crate) struct NoL3 {
    events: EventBus<L3Event>,
}

#[async_trait]
impl L3Provider for NoL3 {
    fn name(&self) -> &'static str {
        "none"
    }

    fn subscribe(&self) -> Subscription<L3Event> {
        self.events.subscribe()
    }

    async fn bind(&self, link: &InterfaceName, _intent: &L3Intent) -> PortResult<()> {
        Err(PortError::NotSupported(format!(
            "no L3 provider is configured; set the profile for {link} to l3 = unmanaged"
        )))
    }

    async fn unbind(&self, _link: &InterfaceName) -> PortResult<()> {
        Ok(())
    }

    async fn status(&self, _link: &InterfaceName) -> PortResult<L3Status> {
        Ok(L3Status::pending())
    }

    async fn addresses_in_use(&self) -> PortResult<Vec<IpNet>> {
        Ok(Vec::new())
    }

    async fn sweep(&self) -> PortResult<Vec<InterfaceName>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_l3_reports_none_and_rejects_binding() {
        let provider = NoL3::default();
        assert_eq!(provider.name(), "none");
        let link = InterfaceName::new("wlan0").unwrap();
        let err = provider
            .bind(
                &link,
                &L3Intent::DhcpClient {
                    ipv6: kestrel_model::Ipv6Mode::Disabled,
                    anonymize: false,
                    required_for_online: true,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PortError::NotSupported(_)));
        provider.unbind(&link).await.unwrap();
        assert_eq!(provider.status(&link).await.unwrap(), L3Status::pending());
        assert_eq!(provider.addresses_in_use().await.unwrap().len(), 0);
        assert_eq!(provider.sweep().await.unwrap().len(), 0);
    }
}

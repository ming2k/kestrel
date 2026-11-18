// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kestrel_model::{InterfaceName, IpNet, OnlineState};
use kestrel_ports::l3::{DhcpLease, L3Event, L3Intent, L3Phase, L3Provider, L3Status};
use kestrel_ports::{EventBus, PortError, PortResult, Subscription};

#[derive(Debug, Default)]
struct State {
    bindings: BTreeMap<InterfaceName, L3Intent>,
    history: Vec<(InterfaceName, Option<L3Intent>)>,
    statuses: BTreeMap<InterfaceName, L3Status>,
    auto_ready: bool,
    dns: Vec<IpAddr>,
    online: OnlineState,
    leases: Vec<DhcpLease>,
    in_use: Vec<IpNet>,
    leftovers: Vec<InterfaceName>,
    fail_bind: Option<PortError>,
}

/// Fake L3 provider. Bindings become ready immediately by default.
#[derive(Debug, Clone)]
pub struct FakeL3 {
    state: Arc<Mutex<State>>,
    events: Arc<EventBus<L3Event>>,
}

impl Default for FakeL3 {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeL3 {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                auto_ready: true,
                online: OnlineState::Online,
                ..State::default()
            })),
            events: Arc::new(EventBus::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("fake l3 state")
    }

    pub fn set_auto_ready(&self, enabled: bool) {
        self.lock().auto_ready = enabled;
    }

    pub fn set_dns(&self, dns: Vec<IpAddr>) {
        self.lock().dns = dns;
    }

    pub fn set_online(&self, online: OnlineState) {
        self.lock().online = online;
    }

    /// DHCP leases reported for shared-subnet links once ready.
    pub fn set_leases(&self, leases: Vec<DhcpLease>) {
        self.lock().leases = leases;
    }

    pub fn set_in_use(&self, in_use: Vec<IpNet>) {
        self.lock().in_use = in_use;
    }

    /// Bindings a previous (crashed) process left behind.
    pub fn set_leftovers(&self, links: Vec<InterfaceName>) {
        self.lock().leftovers = links;
    }

    pub fn fail_next_bind(&self, error: PortError) {
        self.lock().fail_bind = Some(error);
    }

    pub fn bindings(&self) -> BTreeMap<InterfaceName, L3Intent> {
        self.lock().bindings.clone()
    }

    /// Every bind (`Some`) and unbind (`None`), in order.
    pub fn history(&self) -> Vec<(InterfaceName, Option<L3Intent>)> {
        self.lock().history.clone()
    }

    pub fn emit(&self, link: &InterfaceName, status: L3Status) {
        self.lock().statuses.insert(link.clone(), status.clone());
        self.events.publish(&L3Event {
            link: link.clone(),
            status,
        });
    }

    /// Marks a bound link ready, with the given status details.
    pub fn make_ready(&self, link: &InterfaceName) {
        let status = self.ready_status(link);
        self.emit(link, status);
    }

    fn ready_status(&self, link: &InterfaceName) -> L3Status {
        let state = self.lock();
        let (addresses, dns, leases, online) = match state.bindings.get(link) {
            Some(L3Intent::SharedSubnet(shared)) => (
                vec![IpNet::V4(shared.address)],
                Vec::new(),
                state.leases.clone(),
                OnlineState::Offline,
            ),
            Some(L3Intent::Static(config)) => (
                config.addresses.clone(),
                config.dns.clone(),
                Vec::new(),
                state.online,
            ),
            Some(L3Intent::DhcpClient {
                required_for_online,
                ..
            }) => (
                Vec::new(),
                state.dns.clone(),
                Vec::new(),
                if *required_for_online {
                    state.online
                } else {
                    OnlineState::Offline
                },
            ),
            None => (Vec::new(), Vec::new(), Vec::new(), OnlineState::Offline),
        };
        L3Status {
            phase: L3Phase::Ready,
            addresses,
            gateways: Vec::new(),
            dns,
            online,
            leases,
            dhcp_server: None,
        }
    }
}

#[async_trait]
impl L3Provider for FakeL3 {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn subscribe(&self) -> Subscription<L3Event> {
        self.events.subscribe()
    }

    async fn bind(&self, link: &InterfaceName, intent: &L3Intent) -> PortResult<()> {
        let auto = {
            let mut state = self.lock();
            if let Some(error) = state.fail_bind.take() {
                return Err(error);
            }
            state.bindings.insert(link.clone(), intent.clone());
            state.history.push((link.clone(), Some(intent.clone())));
            state.auto_ready
        };
        self.emit(link, L3Status::pending());
        if auto {
            self.make_ready(link);
        }
        Ok(())
    }

    async fn unbind(&self, link: &InterfaceName) -> PortResult<()> {
        let mut state = self.lock();
        state.bindings.remove(link);
        state.statuses.remove(link);
        state.history.push((link.clone(), None));
        Ok(())
    }

    async fn status(&self, link: &InterfaceName) -> PortResult<L3Status> {
        Ok(self
            .lock()
            .statuses
            .get(link)
            .cloned()
            .unwrap_or_else(L3Status::pending))
    }

    async fn addresses_in_use(&self) -> PortResult<Vec<IpNet>> {
        let state = self.lock();
        let mut in_use = state.in_use.clone();
        for intent in state.bindings.values() {
            if let L3Intent::SharedSubnet(shared) = intent {
                in_use.push(IpNet::V4(shared.address));
            }
        }
        Ok(in_use)
    }

    async fn sweep(&self) -> PortResult<Vec<InterfaceName>> {
        let mut state = self.lock();
        let mut swept: Vec<InterfaceName> = std::mem::take(&mut state.leftovers);
        swept.extend(std::mem::take(&mut state.bindings).into_keys());
        for link in &swept {
            state.history.push((link.clone(), None));
        }
        Ok(swept)
    }
}

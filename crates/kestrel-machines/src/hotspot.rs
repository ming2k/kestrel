// SPDX-License-Identifier: LGPL-2.1-or-later

//! SoftAP / hotspot lifecycle for one wireless device.
//!
//! ```text
//! Stopped ─start→ Starting ─ap started→ ConfiguringL3 ─l3 ready→ Active
//!    ▲               │ fail                 │ fail                 │
//!    └───────────────┴──────────────────────┴────── stop / lost ───┘
//! ```
//!
//! External resources (`Ap`, `L3Binding`) are recorded in order and released
//! in strict reverse order on every exit path.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use kestrel_model::{FailureReason, HotspotConfig as ModelHotspotConfig, MacAddress};

use crate::timer::{TimerToken, Timers};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotspotConfig {
    pub ap_timeout: Duration,
    pub l3_timeout: Duration,
}

impl Default for HotspotConfig {
    fn default() -> Self {
        Self {
            ap_timeout: Duration::from_secs(30),
            l3_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotspotState {
    Stopped,
    Starting,
    ConfiguringL3,
    Active,
}

impl HotspotState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::ConfiguringL3 => "configuring-l3",
            Self::Active => "active",
        }
    }

    pub const fn is_active_or_starting(&self) -> bool {
        !matches!(self, Self::Stopped)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HotspotTimer {
    StartAp,
    L3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotspotCommandKind {
    StartAp,
    StopAp,
    BindL3,
    UnbindL3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotspotInput {
    Start(ModelHotspotConfig),
    Stop,
    ApStarted {
        frequency: u32,
    },
    ApStopped,
    ApFailed(FailureReason),
    ClientConnected(MacAddress),
    ClientDisconnected(MacAddress),
    L3Ready,
    L3Failed(String),
    CommandFailed {
        command: HotspotCommandKind,
        reason: FailureReason,
    },
    DeviceUnavailable,
    Timer {
        kind: HotspotTimer,
        token: TimerToken,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotspotCommand {
    StartAp(ModelHotspotConfig),
    StopAp,
    BindL3,
    UnbindL3,
    StartTimer {
        kind: HotspotTimer,
        token: TimerToken,
        after: Duration,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotspotHeld {
    Ap,
    L3Binding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotspotSnapshot {
    pub state: HotspotState,
    pub config: Option<ModelHotspotConfig>,
    pub frequency: Option<u32>,
    pub clients: Vec<MacAddress>,
    pub last_failure: Option<FailureReason>,
}

#[derive(Debug)]
pub struct Hotspot {
    tunables: HotspotConfig,
    state: HotspotState,
    active_config: Option<ModelHotspotConfig>,
    frequency: Option<u32>,
    clients: BTreeSet<MacAddress>,
    last_failure: Option<FailureReason>,
    held: Vec<HotspotHeld>,
    timers: Timers<HotspotTimer>,
    out: Vec<HotspotCommand>,
}

impl Hotspot {
    pub fn new(tunables: HotspotConfig) -> Self {
        Self {
            tunables,
            state: HotspotState::Stopped,
            active_config: None,
            frequency: None,
            clients: BTreeSet::new(),
            last_failure: None,
            held: Vec::new(),
            timers: Timers::new(),
            out: Vec::new(),
        }
    }

    pub const fn state(&self) -> &HotspotState {
        &self.state
    }

    pub fn held(&self) -> &[HotspotHeld] {
        &self.held
    }

    pub fn snapshot(&self) -> HotspotSnapshot {
        HotspotSnapshot {
            state: self.state.clone(),
            config: self.active_config.clone(),
            frequency: self.frequency,
            clients: self.clients.iter().copied().collect(),
            last_failure: self.last_failure.clone(),
        }
    }

    pub fn handle(&mut self, _now: Instant, input: HotspotInput) -> Vec<HotspotCommand> {
        match input {
            HotspotInput::Start(config) => self.start(config),
            HotspotInput::Stop => self.stop(None),
            HotspotInput::ApStarted { frequency } => {
                if self.state == HotspotState::Starting {
                    self.timers.cancel(HotspotTimer::StartAp);
                    if frequency != 0 {
                        self.frequency = Some(frequency);
                    }
                    self.held.push(HotspotHeld::L3Binding);
                    self.out.push(HotspotCommand::BindL3);
                    self.arm(HotspotTimer::L3, self.tunables.l3_timeout);
                    self.state = HotspotState::ConfiguringL3;
                }
            }
            HotspotInput::ApStopped => {
                if self.state.is_active_or_starting() {
                    // AP already stopped externally; do not emit StopAp again.
                    self.held.retain(|h| *h != HotspotHeld::Ap);
                    self.stop(Some(FailureReason::DeviceUnavailable));
                }
            }
            HotspotInput::ApFailed(reason) => {
                if self.state.is_active_or_starting() {
                    self.stop(Some(reason));
                }
            }
            HotspotInput::ClientConnected(mac) => {
                if matches!(
                    self.state,
                    HotspotState::ConfiguringL3 | HotspotState::Active
                ) {
                    self.clients.insert(mac);
                }
            }
            HotspotInput::ClientDisconnected(mac) => {
                self.clients.remove(&mac);
            }
            HotspotInput::L3Ready => {
                if self.state == HotspotState::ConfiguringL3 {
                    self.timers.cancel(HotspotTimer::L3);
                    self.last_failure = None;
                    self.state = HotspotState::Active;
                }
            }
            HotspotInput::L3Failed(detail) => {
                if matches!(
                    self.state,
                    HotspotState::ConfiguringL3 | HotspotState::Active
                ) {
                    self.stop(Some(FailureReason::L3Failed(detail)));
                }
            }
            HotspotInput::CommandFailed { command, reason } => match command {
                HotspotCommandKind::StartAp => {
                    if self.state == HotspotState::Starting {
                        self.stop(Some(reason));
                    }
                }
                HotspotCommandKind::BindL3 => {
                    if self.state == HotspotState::ConfiguringL3 {
                        let mapped = match reason {
                            FailureReason::NoSubnet => FailureReason::NoSubnet,
                            other => FailureReason::L3Failed(other.to_string()),
                        };
                        self.stop(Some(mapped));
                    }
                }
                HotspotCommandKind::StopAp | HotspotCommandKind::UnbindL3 => {}
            },
            HotspotInput::DeviceUnavailable => {
                if self.state.is_active_or_starting() {
                    self.stop(Some(FailureReason::DeviceUnavailable));
                }
            }
            HotspotInput::Timer { kind, token } => {
                if self.timers.fire(kind, token) {
                    let stage = match kind {
                        HotspotTimer::StartAp => "AP startup",
                        HotspotTimer::L3 => "L3 configuration",
                    };
                    self.stop(Some(FailureReason::Timeout(stage.to_owned())));
                }
            }
        }
        std::mem::take(&mut self.out)
    }

    fn start(&mut self, config: ModelHotspotConfig) {
        if self.state.is_active_or_starting() {
            self.teardown();
        }
        self.last_failure = None;
        self.clients.clear();
        self.frequency = config.frequency;
        self.active_config = Some(config.clone());
        self.held.push(HotspotHeld::Ap);
        self.out.push(HotspotCommand::StartAp(config));
        self.arm(HotspotTimer::StartAp, self.tunables.ap_timeout);
        self.state = HotspotState::Starting;
    }

    fn stop(&mut self, reason: Option<FailureReason>) {
        self.teardown();
        self.active_config = None;
        self.frequency = None;
        self.clients.clear();
        if let Some(reason) = reason {
            self.last_failure = Some(reason);
        }
        self.state = HotspotState::Stopped;
    }

    fn teardown(&mut self) {
        while let Some(held) = self.held.pop() {
            self.out.push(match held {
                HotspotHeld::Ap => HotspotCommand::StopAp,
                HotspotHeld::L3Binding => HotspotCommand::UnbindL3,
            });
        }
        self.timers.clear();
    }

    fn arm(&mut self, kind: HotspotTimer, after: Duration) {
        let token = self.timers.arm(kind);
        self.out
            .push(HotspotCommand::StartTimer { kind, token, after });
    }
}

#[cfg(test)]
mod tests {
    use kestrel_model::{HotspotSecurity, Ssid};
    use proptest::prelude::*;

    use super::*;

    fn sample_config() -> ModelHotspotConfig {
        ModelHotspotConfig {
            ssid: Ssid::new("kestrel-ap").unwrap(),
            security: HotspotSecurity::WpaPersonal,
            frequency: Some(2412),
            hidden: false,
        }
    }

    #[test]
    fn happy_path_and_reverse_teardown() {
        let mut h = Hotspot::new(HotspotConfig::default());
        let now = Instant::now();
        let cmds = h.handle(now, HotspotInput::Start(sample_config()));
        assert!(matches!(cmds[0], HotspotCommand::StartAp(_)));
        assert_eq!(h.state(), &HotspotState::Starting);
        assert_eq!(h.held(), &[HotspotHeld::Ap]);

        let cmds = h.handle(now, HotspotInput::ApStarted { frequency: 2437 });
        assert_eq!(cmds[0], HotspotCommand::BindL3);
        assert_eq!(h.state(), &HotspotState::ConfiguringL3);
        assert_eq!(h.held(), &[HotspotHeld::Ap, HotspotHeld::L3Binding]);

        let cmds = h.handle(now, HotspotInput::L3Ready);
        assert_eq!(cmds, []);
        assert_eq!(h.state(), &HotspotState::Active);

        let mac = MacAddress::from_octets([2, 0, 0, 0, 0, 9]);
        h.handle(now, HotspotInput::ClientConnected(mac));
        assert_eq!(h.snapshot().clients, vec![mac]);

        let cmds = h.handle(now, HotspotInput::Stop);
        assert_eq!(cmds, vec![HotspotCommand::UnbindL3, HotspotCommand::StopAp]);
        assert_eq!(h.state(), &HotspotState::Stopped);
        assert_eq!(h.held(), []);
    }

    #[test]
    fn no_subnet_failure_rolls_back_ap() {
        let mut h = Hotspot::new(HotspotConfig::default());
        let now = Instant::now();
        h.handle(now, HotspotInput::Start(sample_config()));
        h.handle(now, HotspotInput::ApStarted { frequency: 2412 });
        let cmds = h.handle(
            now,
            HotspotInput::CommandFailed {
                command: HotspotCommandKind::BindL3,
                reason: FailureReason::NoSubnet,
            },
        );
        assert_eq!(cmds, vec![HotspotCommand::UnbindL3, HotspotCommand::StopAp]);
        assert_eq!(h.state(), &HotspotState::Stopped);
        assert_eq!(h.snapshot().last_failure, Some(FailureReason::NoSubnet));
        assert_eq!(h.held(), []);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn hotspot_never_doubles_or_leaks_resources(ops in prop::collection::vec(0u8..12, 1..60)) {
            let mut h = Hotspot::new(HotspotConfig::default());
            let mut now = Instant::now();
            let mut timers: Vec<(HotspotTimer, TimerToken)> = Vec::new();
            let mut ap_held = false;
            let mut l3_held = false;
            let mac = MacAddress::from_octets([2, 0, 0, 0, 0, 1]);

            for op in ops {
                now += Duration::from_secs(1);
                let input = match op {
                    0 => HotspotInput::Start(sample_config()),
                    1 => HotspotInput::Stop,
                    2 => HotspotInput::ApStarted { frequency: 2412 },
                    3 => HotspotInput::ApStopped,
                    4 => HotspotInput::ApFailed(FailureReason::Backend("boom".into())),
                    5 => HotspotInput::ClientConnected(mac),
                    6 => HotspotInput::ClientDisconnected(mac),
                    7 => HotspotInput::L3Ready,
                    8 => HotspotInput::L3Failed("dhcp".into()),
                    9 => HotspotInput::CommandFailed {
                        command: HotspotCommandKind::BindL3,
                        reason: FailureReason::NoSubnet,
                    },
                    10 => HotspotInput::DeviceUnavailable,
                    _ => {
                        if let Some((kind, token)) = timers.pop() {
                            HotspotInput::Timer { kind, token }
                        } else {
                            HotspotInput::Stop
                        }
                    }
                };
                if matches!(input, HotspotInput::ApStopped) {
                    ap_held = false;
                }
                let cmds = h.handle(now, input);
                for cmd in cmds {
                    match cmd {
                        HotspotCommand::StartAp(_) => {
                            prop_assert!(!ap_held, "AP started twice");
                            ap_held = true;
                        }
                        HotspotCommand::StopAp => {
                            prop_assert!(ap_held, "StopAp when not held");
                            prop_assert!(!l3_held, "StopAp before UnbindL3");
                            ap_held = false;
                        }
                        HotspotCommand::BindL3 => {
                            prop_assert!(ap_held, "BindL3 without AP");
                            prop_assert!(!l3_held, "BindL3 twice");
                            l3_held = true;
                        }
                        HotspotCommand::UnbindL3 => {
                            prop_assert!(l3_held, "UnbindL3 when not held");
                            l3_held = false;
                        }
                        HotspotCommand::StartTimer { kind, token, .. } => {
                            timers.push((kind, token));
                        }
                    }
                }
                if h.state() == &HotspotState::Stopped {
                    prop_assert!(h.held().is_empty());
                    prop_assert!(!ap_held);
                    prop_assert!(!l3_held);
                }
            }
            let cmds = h.handle(now, HotspotInput::Stop);
            for cmd in cmds {
                match cmd {
                    HotspotCommand::UnbindL3 => l3_held = false,
                    HotspotCommand::StopAp => ap_held = false,
                    _ => {}
                }
            }
            prop_assert!(h.held().is_empty());
            prop_assert!(!ap_held && !l3_held);
        }
    }
}

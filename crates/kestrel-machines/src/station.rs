// SPDX-License-Identifier: LGPL-2.1-or-later

//! Wi-Fi station lifecycle for one wireless device.
//!
//! ```text
//! Disabled ─enable→ Idle ─select/user→ Associating ─link up→ ConfiguringL3 ─ready→ Connected
//!                    ▲                     │ fail                 │ fail            │ link down
//!                    │                     ▼                      ▼                 ▼
//!                    └──── cooldown ◄── Waiting(retry n) ◄──────────────────── Reconnecting
//!                                                                   (grace expired)
//! ```
//!
//! The machine holds at most two external resources: the backend
//! association and the L3 binding. They are released in reverse order on
//! every exit path.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use kestrel_model::{Bss, FailureReason, MacAddress, ProfileId, Ssid, WifiProfile};

pub mod policy;
use crate::timer::{TimerToken, Timers};

/// Tunables. Defaults suit an interactive desktop or an embedded client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationConfig {
    pub scan_timeout: Duration,
    pub associate_timeout: Duration,
    pub l3_timeout: Duration,
    /// How long a dropped link may take to recover (roaming, a short
    /// outage) before the connection counts as lost.
    pub link_grace: Duration,
    /// Consecutive failures of one profile before it cools down.
    pub max_attempts: u32,
    pub retry_base: Duration,
    pub retry_max: Duration,
    pub cooldown: Duration,
    pub rescan_min: Duration,
    pub rescan_max: Duration,
}

impl Default for StationConfig {
    fn default() -> Self {
        Self {
            scan_timeout: Duration::from_secs(15),
            associate_timeout: Duration::from_secs(30),
            l3_timeout: Duration::from_secs(30),
            link_grace: Duration::from_secs(10),
            max_attempts: 3,
            retry_base: Duration::from_secs(2),
            retry_max: Duration::from_secs(60),
            cooldown: Duration::from_secs(300),
            rescan_min: Duration::from_secs(10),
            rescan_max: Duration::from_secs(300),
        }
    }
}

/// Observable station state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StationState {
    /// Wireless is off or the device is going away.
    Disabled,
    Idle,
    Associating {
        profile: ProfileId,
        attempt: u32,
    },
    ConfiguringL3 {
        profile: ProfileId,
    },
    Connected {
        profile: ProfileId,
        bssid: Option<MacAddress>,
    },
    /// The link dropped. The backend is given a grace period to recover.
    Reconnecting {
        profile: ProfileId,
    },
    /// Backing off before retrying `profile`.
    Waiting {
        profile: ProfileId,
        attempt: u32,
    },
}

impl StationState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Idle => "idle",
            Self::Associating { .. } => "associating",
            Self::ConfiguringL3 { .. } => "configuring-l3",
            Self::Connected { .. } => "connected",
            Self::Reconnecting { .. } => "reconnecting",
            Self::Waiting { .. } => "waiting",
        }
    }

    pub const fn profile(&self) -> Option<ProfileId> {
        match self {
            Self::Disabled | Self::Idle => None,
            Self::Associating { profile, .. }
            | Self::ConfiguringL3 { profile }
            | Self::Connected { profile, .. }
            | Self::Reconnecting { profile }
            | Self::Waiting { profile, .. } => Some(*profile),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StationTimer {
    Scan,
    Associate,
    L3,
    Grace,
    Retry,
    Rescan,
}

/// The commands a failure report can refer to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StationCommandKind {
    Scan,
    Associate,
    Disassociate,
    BindL3,
    UnbindL3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StationInput {
    SetEnabled(bool),
    /// System sleep or hardware rfkill block. Unlike `SetEnabled(true)`,
    /// resuming from `SetSuspended(false)` preserves a prior user
    /// disconnect (`autoconnect_held`) and clears stale scan caches.
    SetSuspended(bool),
    /// SoftAP / hotspot owns the radio on this device. Disables station
    /// orchestration cleanly while active and restores it when stopped,
    /// preserving `autoconnect_held`.
    SetHotspotActive(bool),
    /// Enable or disable autoconnect without tearing down the current link.
    SetAutoconnect(bool),
    /// The full, current set of saved profiles.
    ProfilesChanged(Vec<WifiProfile>),
    SecretsUpdated(ProfileId),
    SecretsUnavailable(ProfileId),
    Scan,
    Connect(ProfileId),
    Disconnect,
    ScanFinished(Result<Vec<Bss>, FailureReason>),
    LinkConnected {
        ssid: Ssid,
        bssid: Option<MacAddress>,
    },
    LinkDisconnected,
    AuthFailed,
    L3Ready,
    L3Failed(String),
    CommandFailed {
        command: StationCommandKind,
        reason: FailureReason,
    },
    Timer {
        kind: StationTimer,
        token: TimerToken,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StationCommand {
    Scan,
    /// Associate with the profile. The driver loads its secret.
    Associate {
        profile: ProfileId,
        bssid: Option<MacAddress>,
    },
    /// Leave the network and drop every backend object Kestrel created.
    Disassociate,
    BindL3 {
        profile: ProfileId,
    },
    UnbindL3,
    /// Ask an agent for credentials. Answered by `SecretsUpdated` or
    /// `SecretsUnavailable`.
    RequestSecrets {
        profile: ProfileId,
    },
    RecordConnected {
        profile: ProfileId,
    },
    StartTimer {
        kind: StationTimer,
        token: TimerToken,
        after: Duration,
    },
}

/// An external resource the station holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    Association,
    L3Binding,
}

/// What a consumer can observe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationSnapshot {
    pub state: StationState,
    pub scanning: bool,
    pub last_failure: Option<FailureReason>,
    /// True after a user disconnect: autoconnect waits for an explicit
    /// connect or a profile change.
    pub autoconnect_held: bool,
    pub visible: Vec<Bss>,
    pub needs_secrets: Vec<ProfileId>,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Station {
    config: StationConfig,
    enabled: bool,
    suspended: bool,
    hotspot_active: bool,
    state: StationState,
    profiles: BTreeMap<ProfileId, WifiProfile>,
    visible: Vec<Bss>,
    scanning: bool,
    needs_secrets: BTreeSet<ProfileId>,
    awaiting_secrets: Option<ProfileId>,
    cooldown: BTreeMap<ProfileId, Instant>,
    user_hold: bool,
    failures: u32,
    rescan_delay: Duration,
    pending_bssid: Option<MacAddress>,
    held: Vec<Held>,
    last_failure: Option<FailureReason>,
    timers: Timers<StationTimer>,
    out: Vec<StationCommand>,
}

impl Station {
    pub fn new(config: StationConfig) -> Self {
        let rescan_delay = config.rescan_min;
        Self {
            config,
            enabled: false,
            suspended: false,
            hotspot_active: false,
            state: StationState::Disabled,
            profiles: BTreeMap::new(),
            visible: Vec::new(),
            scanning: false,
            needs_secrets: BTreeSet::new(),
            awaiting_secrets: None,
            cooldown: BTreeMap::new(),
            user_hold: false,
            failures: 0,
            rescan_delay,
            pending_bssid: None,
            held: Vec::new(),
            last_failure: None,
            timers: Timers::new(),
            out: Vec::new(),
        }
    }

    pub const fn state(&self) -> &StationState {
        &self.state
    }

    pub fn held(&self) -> &[Held] {
        &self.held
    }

    pub fn snapshot(&self) -> StationSnapshot {
        StationSnapshot {
            state: self.state.clone(),
            scanning: self.scanning,
            last_failure: self.last_failure.clone(),
            autoconnect_held: self.user_hold,
            visible: self.visible.clone(),
            needs_secrets: self.needs_secrets.iter().copied().collect(),
        }
    }

    const fn active(&self) -> bool {
        self.enabled && !self.suspended && !self.hotspot_active
    }

    pub fn handle(&mut self, now: Instant, input: StationInput) -> Vec<StationCommand> {
        match input {
            StationInput::SetEnabled(enabled) => self.set_enabled(now, enabled),
            StationInput::SetSuspended(suspended) => self.set_suspended(now, suspended),
            StationInput::SetHotspotActive(active) => self.set_hotspot_active(now, active),
            StationInput::SetAutoconnect(enabled) => self.set_autoconnect(now, enabled),
            StationInput::ProfilesChanged(profiles) => self.profiles_changed(now, profiles),
            StationInput::SecretsUpdated(id) => self.secrets_updated(now, id),
            StationInput::SecretsUnavailable(id) => {
                if self.awaiting_secrets == Some(id) {
                    self.awaiting_secrets = None;
                    self.tick(now, true);
                }
            }
            StationInput::Scan => {
                if self.active() && !self.scanning {
                    self.start_scan();
                }
            }
            StationInput::Connect(id) => self.user_connect(now, id),
            StationInput::Disconnect => self.user_disconnect(),
            StationInput::ScanFinished(result) => self.scan_finished(now, result),
            StationInput::LinkConnected { ssid, bssid } => self.link_connected(&ssid, bssid),
            StationInput::LinkDisconnected => self.link_disconnected(now),
            StationInput::AuthFailed => {
                if matches!(
                    self.state,
                    StationState::Associating { .. } | StationState::Reconnecting { .. }
                ) {
                    self.fail(now, FailureReason::AuthFailed);
                }
            }
            StationInput::L3Ready => {
                if let StationState::ConfiguringL3 { profile } = self.state {
                    self.timers.cancel(StationTimer::L3);
                    let bssid = self.pending_bssid.take();
                    self.connected(profile, bssid);
                }
            }
            StationInput::L3Failed(detail) => {
                if matches!(
                    self.state,
                    StationState::ConfiguringL3 { .. }
                        | StationState::Connected { .. }
                        | StationState::Reconnecting { .. }
                ) {
                    self.fail(now, FailureReason::L3Failed(detail));
                }
            }
            StationInput::CommandFailed { command, reason } => {
                self.command_failed(now, command, reason);
            }
            StationInput::Timer { kind, token } => {
                if self.timers.fire(kind, token) {
                    self.timer_fired(now, kind);
                }
            }
        }
        std::mem::take(&mut self.out)
    }

    fn set_enabled(&mut self, now: Instant, enabled: bool) {
        if enabled == self.enabled {
            return;
        }
        self.enabled = enabled;
        if enabled {
            self.user_hold = false;
            self.visible.clear();
            self.rescan_delay = self.config.rescan_min;
            if !self.suspended && !self.hotspot_active {
                self.state = StationState::Idle;
                self.tick(now, true);
            }
        } else {
            self.deactivate();
        }
    }

    fn set_suspended(&mut self, now: Instant, suspended: bool) {
        if suspended == self.suspended {
            return;
        }
        self.suspended = suspended;
        if suspended {
            self.deactivate();
        } else {
            self.cooldown.clear();
            self.visible.clear();
            self.rescan_delay = self.config.rescan_min;
            if self.enabled && !self.hotspot_active {
                self.state = StationState::Idle;
                self.tick(now, true);
            }
        }
    }

    fn set_hotspot_active(&mut self, now: Instant, active: bool) {
        if active == self.hotspot_active {
            return;
        }
        self.hotspot_active = active;
        if active {
            self.deactivate();
        } else {
            self.visible.clear();
            self.rescan_delay = self.config.rescan_min;
            if self.enabled && !self.suspended {
                self.state = StationState::Idle;
                self.tick(now, true);
            }
        }
    }

    fn deactivate(&mut self) {
        self.teardown();
        self.timers.clear();
        self.scanning = false;
        self.awaiting_secrets = None;
        self.failures = 0;
        self.state = StationState::Disabled;
    }

    fn profiles_changed(&mut self, now: Instant, profiles: Vec<WifiProfile>) {
        let new: BTreeMap<ProfileId, WifiProfile> =
            profiles.into_iter().map(|p| (p.id, p)).collect();
        let changed: BTreeSet<ProfileId> = new
            .iter()
            .filter(|(id, profile)| {
                self.profiles
                    .get(id)
                    .is_none_or(|old| old.requires_reconnect(profile))
            })
            .map(|(id, _)| *id)
            .collect();
        self.cooldown
            .retain(|id, _| new.contains_key(id) && !changed.contains(id));
        self.needs_secrets
            .retain(|id| new.get(id).is_some_and(|p| p.security.needs_secret()));
        if self
            .awaiting_secrets
            .is_some_and(|id| new.get(&id).is_none_or(|p| !p.security.needs_secret()))
        {
            self.awaiting_secrets = None;
        }
        self.profiles = new;
        self.rescan_delay = self.config.rescan_min;
        self.timers.cancel(StationTimer::Rescan);

        if let Some(current) = self.state.profile() {
            if !self.profiles.contains_key(&current) {
                self.teardown();
                self.failures = 0;
                self.state = StationState::Idle;
            } else if changed.contains(&current) {
                self.failures = 0;
                self.begin(current);
                return;
            }
        }
        if !changed.is_empty() {
            // A new or edited profile is a fresh user decision.
            self.user_hold = false;
        }
        self.tick(now, true);
    }

    fn secrets_updated(&mut self, now: Instant, id: ProfileId) {
        self.needs_secrets.remove(&id);
        self.cooldown.remove(&id);
        if self.awaiting_secrets == Some(id) {
            self.awaiting_secrets = None;
            self.user_hold = false;
            self.failures = 0;
            if self.active() {
                self.begin(id);
            }
        } else {
            self.tick(now, true);
        }
    }

    fn set_autoconnect(&mut self, now: Instant, enabled: bool) {
        if enabled {
            if self.user_hold {
                self.user_hold = false;
                self.failures = 0;
                self.tick(now, true);
            }
        } else {
            self.user_hold = true;
        }
    }

    fn user_connect(&mut self, now: Instant, id: ProfileId) {
        if !self.active() || !self.profiles.contains_key(&id) {
            return;
        }
        self.user_hold = false;
        if self.state.profile() == Some(id) && !matches!(self.state, StationState::Waiting { .. }) {
            return;
        }
        let _ = now;
        self.cooldown.remove(&id);
        self.failures = 0;
        if self.needs_secrets.contains(&id) {
            if self.awaiting_secrets != Some(id) {
                self.request_secrets(id);
            }
        } else {
            self.awaiting_secrets = None;
            self.begin(id);
        }
    }

    fn user_disconnect(&mut self) {
        if !self.active() {
            return;
        }
        self.teardown();
        self.timers.cancel(StationTimer::Retry);
        self.timers.cancel(StationTimer::Rescan);
        self.user_hold = true;
        self.awaiting_secrets = None;
        self.failures = 0;
        self.last_failure = None;
        self.state = StationState::Idle;
    }

    fn scan_finished(&mut self, now: Instant, result: Result<Vec<Bss>, FailureReason>) {
        self.scanning = false;
        self.timers.cancel(StationTimer::Scan);
        if !self.active() {
            return;
        }
        if let Ok(visible) = result {
            self.visible = visible;
        }
        if self.state == StationState::Idle {
            self.tick(now, false);
            if self.state == StationState::Idle && self.autoconnect_wanted() {
                self.arm_rescan();
            }
        }
    }

    fn link_connected(&mut self, ssid: &Ssid, bssid: Option<MacAddress>) {
        let Some(profile) = self.state.profile() else {
            return;
        };
        if self.profiles.get(&profile).is_none_or(|p| &p.ssid != ssid) {
            // A stale event from a previous association.
            return;
        }
        match self.state {
            StationState::Associating { .. } => {
                self.timers.cancel(StationTimer::Associate);
                let managed = self.profiles[&profile].l3.is_managed();
                if managed {
                    self.held.push(Held::L3Binding);
                    self.pending_bssid = bssid;
                    self.out.push(StationCommand::BindL3 { profile });
                    self.arm(StationTimer::L3, self.config.l3_timeout);
                    self.state = StationState::ConfiguringL3 { profile };
                } else {
                    self.connected(profile, bssid);
                }
            }
            StationState::Reconnecting { .. } => {
                self.timers.cancel(StationTimer::Grace);
                self.state = StationState::Connected { profile, bssid };
            }
            StationState::Connected { .. } => {
                // Roamed within the ESS.
                self.state = StationState::Connected { profile, bssid };
            }
            _ => {}
        }
    }

    fn link_disconnected(&mut self, now: Instant) {
        match self.state {
            StationState::Connected { profile, .. } => {
                self.state = StationState::Reconnecting { profile };
                self.arm(StationTimer::Grace, self.config.link_grace);
            }
            StationState::ConfiguringL3 { .. } => self.fail(now, FailureReason::LinkLost),
            // During association the backend retries on its own; the
            // association timeout bounds it.
            _ => {}
        }
    }

    fn command_failed(&mut self, now: Instant, command: StationCommandKind, reason: FailureReason) {
        match command {
            StationCommandKind::Scan => self.scan_finished(now, Err(reason)),
            StationCommandKind::Associate => {
                if matches!(self.state, StationState::Associating { .. }) {
                    self.fail(now, reason);
                }
            }
            StationCommandKind::BindL3 => {
                if matches!(self.state, StationState::ConfiguringL3 { .. }) {
                    self.fail(now, FailureReason::L3Failed(reason.to_string()));
                }
            }
            // Cleanup is best effort. The driver logs it, and the startup
            // sweep removes anything left behind.
            StationCommandKind::Disassociate | StationCommandKind::UnbindL3 => {}
        }
    }

    fn timer_fired(&mut self, now: Instant, kind: StationTimer) {
        match kind {
            StationTimer::Scan => {
                self.scan_finished(now, Err(FailureReason::Timeout("scan".to_owned())));
            }
            StationTimer::Associate => {
                if matches!(self.state, StationState::Associating { .. }) {
                    self.fail(now, FailureReason::Timeout("association".to_owned()));
                }
            }
            StationTimer::L3 => {
                if matches!(self.state, StationState::ConfiguringL3 { .. }) {
                    self.fail(now, FailureReason::Timeout("L3 configuration".to_owned()));
                }
            }
            StationTimer::Grace => {
                if matches!(self.state, StationState::Reconnecting { .. }) {
                    self.fail(now, FailureReason::LinkLost);
                }
            }
            StationTimer::Retry => {
                if let StationState::Waiting { profile, .. } = self.state {
                    self.begin(profile);
                }
            }
            StationTimer::Rescan => {
                if self.state == StationState::Idle {
                    self.tick(now, true);
                }
            }
        }
    }

    /// Starts associating with `profile`, releasing whatever is held first.
    fn begin(&mut self, profile: ProfileId) {
        let Some(target) = self.profiles.get(&profile) else {
            self.teardown();
            self.state = StationState::Idle;
            return;
        };
        let bssid = target.bssid;
        self.teardown();
        self.timers.cancel(StationTimer::Retry);
        self.held.push(Held::Association);
        self.out.push(StationCommand::Associate { profile, bssid });
        self.arm(StationTimer::Associate, self.config.associate_timeout);
        self.state = StationState::Associating {
            profile,
            attempt: self.failures.saturating_add(1),
        };
    }

    fn connected(&mut self, profile: ProfileId, bssid: Option<MacAddress>) {
        self.failures = 0;
        self.last_failure = None;
        self.rescan_delay = self.config.rescan_min;
        self.timers.cancel(StationTimer::Rescan);
        self.state = StationState::Connected { profile, bssid };
        self.out.push(StationCommand::RecordConnected { profile });
    }

    fn request_secrets(&mut self, profile: ProfileId) {
        self.teardown();
        self.awaiting_secrets = Some(profile);
        self.last_failure = Some(FailureReason::SecretsRequired);
        self.state = StationState::Idle;
        self.out.push(StationCommand::RequestSecrets { profile });
    }

    fn fail(&mut self, now: Instant, reason: FailureReason) {
        let Some(profile) = self.state.profile() else {
            return;
        };
        self.teardown();
        self.pending_bssid = None;
        if matches!(
            reason,
            FailureReason::AuthFailed | FailureReason::SecretsRequired
        ) {
            self.needs_secrets.insert(profile);
            self.failures = 0;
            self.request_secrets(profile);
            self.last_failure = Some(reason);
            return;
        }
        self.last_failure = Some(reason.clone());
        self.failures = self.failures.saturating_add(1);
        if reason.is_transient() && self.failures < self.config.max_attempts {
            let delay = self.backoff(self.failures);
            self.state = StationState::Waiting {
                profile,
                attempt: self.failures,
            };
            self.arm(StationTimer::Retry, delay);
        } else {
            self.failures = 0;
            if let Some(until) = now.checked_add(self.config.cooldown) {
                self.cooldown.insert(profile, until);
            }
            self.state = StationState::Idle;
            self.tick(now, true);
        }
    }

    /// Releases every held resource in reverse order.
    fn teardown(&mut self) {
        while let Some(held) = self.held.pop() {
            self.out.push(match held {
                Held::Association => StationCommand::Disassociate,
                Held::L3Binding => StationCommand::UnbindL3,
            });
        }
        self.timers.cancel(StationTimer::Associate);
        self.timers.cancel(StationTimer::L3);
        self.timers.cancel(StationTimer::Grace);
    }

    fn excluded(&self, now: Instant, id: ProfileId) -> bool {
        self.needs_secrets.contains(&id) || self.cooldown.get(&id).is_some_and(|until| *until > now)
    }

    fn autoconnect_wanted(&self) -> bool {
        self.active()
            && !self.user_hold
            && self.awaiting_secrets.is_none()
            && policy::has_eligible(self.profiles.values(), |id| {
                self.needs_secrets.contains(&id)
            })
    }

    /// Runs autoconnect from `Idle`: connects to the best visible candidate,
    /// or, with `allow_scan`, scans for one.
    fn tick(&mut self, now: Instant, allow_scan: bool) {
        if self.state != StationState::Idle || !self.autoconnect_wanted() {
            return;
        }
        self.cooldown.retain(|_, until| *until > now);
        if let Some(id) = policy::select(self.profiles.values(), &self.visible, |id| {
            self.excluded(now, id)
        }) {
            self.failures = 0;
            self.begin(id);
            return;
        }
        if allow_scan && !self.scanning {
            self.start_scan();
        }
    }

    fn start_scan(&mut self) {
        self.scanning = true;
        self.out.push(StationCommand::Scan);
        self.arm(StationTimer::Scan, self.config.scan_timeout);
    }

    fn arm_rescan(&mut self) {
        let delay = self.rescan_delay;
        self.rescan_delay = self
            .rescan_delay
            .saturating_mul(2)
            .min(self.config.rescan_max);
        self.arm(StationTimer::Rescan, delay);
    }

    fn backoff(&self, failures: u32) -> Duration {
        let factor = 2u32.saturating_pow(failures.saturating_sub(1));
        self.config
            .retry_base
            .saturating_mul(factor)
            .min(self.config.retry_max)
    }

    fn arm(&mut self, kind: StationTimer, after: Duration) {
        let token = self.timers.arm(kind);
        self.out
            .push(StationCommand::StartTimer { kind, token, after });
    }
}

#[cfg(test)]
mod tests;

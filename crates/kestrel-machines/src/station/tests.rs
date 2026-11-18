// SPDX-License-Identifier: LGPL-2.1-or-later

use std::time::{Duration, Instant};

use kestrel_model::{
    Bss, FailureReason, L3Config, MacAddress, ProfileId, ProfileSecurity, Security, Ssid,
    WifiProfile,
};
use proptest::prelude::*;

use super::*;

fn profile(ssid: &str, priority: i32) -> WifiProfile {
    let mut profile = WifiProfile::new(Ssid::new(ssid).unwrap(), ProfileSecurity::WpaPersonal);
    profile.priority = priority;
    profile
}

fn bss(ssid: &str, signal: i16) -> Bss {
    Bss {
        ssid: Ssid::new(ssid).unwrap(),
        bssid: MacAddress::from_octets([2, 0, 0, 0, 0, 1]),
        frequency: 2412,
        signal,
        security: Security::Wpa2Psk,
    }
}

/// Test harness: a station plus a model of the external resources implied
/// by the commands it emitted.
struct Harness {
    now: Instant,
    station: Station,
    log: Vec<StationCommand>,
    timers: Vec<(StationTimer, TimerToken, Instant)>,
    associated: u32,
    bound: u32,
}

impl Harness {
    fn new() -> Self {
        Self {
            now: Instant::now(),
            station: Station::new(StationConfig::default()),
            log: Vec::new(),
            timers: Vec::new(),
            associated: 0,
            bound: 0,
        }
    }

    fn send(&mut self, input: StationInput) -> Vec<StationCommand> {
        let commands = self.station.handle(self.now, input);
        for command in &commands {
            match command {
                StationCommand::Associate { .. } => {
                    assert_eq!(self.associated, 0, "double association: {commands:?}");
                    self.associated += 1;
                }
                StationCommand::Disassociate => {
                    assert_eq!(self.bound, 0, "disassociated before unbinding L3");
                    assert_eq!(self.associated, 1, "disassociate without association");
                    self.associated -= 1;
                }
                StationCommand::BindL3 { .. } => {
                    assert_eq!(self.associated, 1, "L3 bound without association");
                    assert_eq!(self.bound, 0, "double L3 binding");
                    self.bound += 1;
                }
                StationCommand::UnbindL3 => {
                    assert_eq!(self.bound, 1, "unbind without binding");
                    self.bound -= 1;
                }
                StationCommand::StartTimer { kind, token, after } => {
                    self.timers.push((*kind, *token, self.now + *after));
                }
                _ => {}
            }
        }
        assert_eq!(
            u32::try_from(self.station.held().len()).unwrap(),
            self.associated + self.bound,
            "held list diverged from emitted commands"
        );
        self.log.extend(commands.iter().cloned());
        commands
    }

    /// Advances time and fires every due timer, in order.
    fn advance(&mut self, by: Duration) {
        let until = self.now + by;
        loop {
            self.timers.sort_by_key(|(_, _, at)| *at);
            let Some(index) = self.timers.iter().position(|(_, _, at)| *at <= until) else {
                break;
            };
            let (kind, token, at) = self.timers.remove(index);
            self.now = self.now.max(at);
            self.send(StationInput::Timer { kind, token });
        }
        self.now = until;
    }

    fn state(&self) -> &StationState {
        self.station.state()
    }
}

fn enabled_with(profiles: Vec<WifiProfile>) -> Harness {
    let mut h = Harness::new();
    h.send(StationInput::ProfilesChanged(profiles));
    h.send(StationInput::SetEnabled(true));
    h
}

#[test]
fn autoconnect_scans_then_connects_to_best_candidate() {
    let home = profile("home", 10);
    let cafe = profile("cafe", 0);
    let mut h = enabled_with(vec![home.clone(), cafe]);
    assert!(h.log.contains(&StationCommand::Scan));
    let commands = h.send(StationInput::ScanFinished(Ok(vec![
        bss("cafe", -30),
        bss("home", -70),
    ])));
    assert!(commands.contains(&StationCommand::Associate {
        profile: home.id,
        bssid: None
    }));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    assert_eq!(h.state(), &StationState::ConfiguringL3 { profile: home.id });
    let commands = h.send(StationInput::L3Ready);
    assert!(commands.contains(&StationCommand::RecordConnected { profile: home.id }));
    assert!(matches!(h.state(), StationState::Connected { profile, .. } if *profile == home.id));
}

#[test]
fn unmanaged_l3_skips_binding() {
    let mut home = profile("home", 0);
    home.l3 = L3Config::Unmanaged;
    let mut h = enabled_with(vec![home.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -50)])));
    let commands = h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    assert!(
        !commands
            .iter()
            .any(|c| matches!(c, StationCommand::BindL3 { .. }))
    );
    assert!(matches!(h.state(), StationState::Connected { .. }));
}

#[test]
fn no_candidate_backs_off_rescans() {
    let mut h = enabled_with(vec![profile("home", 0)]);
    h.send(StationInput::ScanFinished(Ok(vec![])));
    assert_eq!(h.state(), &StationState::Idle);
    let scans_before = h.log.iter().filter(|c| **c == StationCommand::Scan).count();
    h.advance(Duration::from_secs(9));
    assert_eq!(
        h.log.iter().filter(|c| **c == StationCommand::Scan).count(),
        scans_before
    );
    h.advance(Duration::from_secs(2));
    assert_eq!(
        h.log.iter().filter(|c| **c == StationCommand::Scan).count(),
        scans_before + 1
    );
    // The next empty result doubles the delay.
    h.send(StationInput::ScanFinished(Ok(vec![])));
    h.advance(Duration::from_secs(19));
    assert_eq!(
        h.log.iter().filter(|c| **c == StationCommand::Scan).count(),
        scans_before + 1
    );
    h.advance(Duration::from_secs(2));
    assert_eq!(
        h.log.iter().filter(|c| **c == StationCommand::Scan).count(),
        scans_before + 2
    );
}

#[test]
fn auth_failure_requests_secrets_and_never_retries_blindly() {
    let home = profile("home", 0);
    let mut h = enabled_with(vec![home.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -50)])));
    let commands = h.send(StationInput::AuthFailed);
    assert!(commands.contains(&StationCommand::Disassociate));
    assert!(commands.contains(&StationCommand::RequestSecrets { profile: home.id }));
    assert_eq!(h.state(), &StationState::Idle);
    assert_eq!(
        h.station.snapshot().last_failure,
        Some(FailureReason::AuthFailed)
    );
    // Without new secrets, nothing retries.
    h.advance(Duration::from_secs(3600));
    assert!(
        !h.log
            .iter()
            .skip_while(|c| !matches!(c, StationCommand::RequestSecrets { .. }))
            .any(|c| matches!(c, StationCommand::Associate { .. }))
    );
    // New secrets retry immediately.
    let commands = h.send(StationInput::SecretsUpdated(home.id));
    assert!(commands.contains(&StationCommand::Associate {
        profile: home.id,
        bssid: None
    }));
}

#[test]
fn transient_failures_back_off_then_cool_down_and_fall_back() {
    let home = profile("home", 10);
    let cafe = profile("cafe", 0);
    let mut h = enabled_with(vec![home.clone(), cafe.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![
        bss("home", -50),
        bss("cafe", -60),
    ])));
    // Three association timeouts for `home`.
    h.advance(Duration::from_secs(31));
    assert!(
        matches!(h.state(), StationState::Waiting { profile, attempt: 1 } if *profile == home.id)
    );
    h.advance(Duration::from_secs(2));
    assert!(
        matches!(h.state(), StationState::Associating { profile, attempt: 2 } if *profile == home.id)
    );
    h.advance(Duration::from_secs(31));
    h.advance(Duration::from_secs(4));
    assert!(
        matches!(h.state(), StationState::Associating { profile, attempt: 3 } if *profile == home.id)
    );
    h.advance(Duration::from_secs(31));
    // `home` is cooling down; autoconnect falls back to `cafe`.
    assert!(
        matches!(h.state(), StationState::Associating { profile, .. } if *profile == cafe.id),
        "{:?}",
        h.state()
    );
}

#[test]
fn link_loss_has_a_grace_period() {
    let home = profile("home", 0);
    let mut h = enabled_with(vec![home.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -50)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::L3Ready);
    let commands = h.send(StationInput::LinkDisconnected);
    assert!(
        commands
            .iter()
            .all(|c| matches!(c, StationCommand::StartTimer { .. }))
    );
    assert_eq!(h.state(), &StationState::Reconnecting { profile: home.id });
    h.advance(Duration::from_secs(5));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    assert!(matches!(h.state(), StationState::Connected { .. }));
    // A second loss without recovery tears down and retries.
    h.send(StationInput::LinkDisconnected);
    h.advance(Duration::from_secs(11));
    assert_eq!(
        h.station.snapshot().last_failure,
        Some(FailureReason::LinkLost)
    );
    assert!(matches!(h.state(), StationState::Waiting { .. }));
    assert_eq!(h.associated + h.bound, 0);
}

#[test]
fn autoconnect_can_be_disabled_and_resumed_without_a_teardown() {
    let home = profile("home", 0);
    let mut h = Harness::new();
    h.send(StationInput::SetEnabled(true));
    h.send(StationInput::ProfilesChanged(vec![home]));
    h.send(StationInput::SetAutoconnect(false));
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -50)])));
    assert_eq!(h.state(), &StationState::Idle);
    assert!(h.station.snapshot().autoconnect_held);
    h.send(StationInput::SetAutoconnect(true));
    assert!(matches!(h.state(), StationState::Associating { .. }));
}

#[test]
fn user_disconnect_holds_autoconnect_until_explicit_connect() {
    let home = profile("home", 0);
    let mut h = enabled_with(vec![home.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -50)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::L3Ready);
    let commands = h.send(StationInput::Disconnect);
    assert_eq!(
        commands,
        vec![StationCommand::UnbindL3, StationCommand::Disassociate]
    );
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -50)])));
    h.advance(Duration::from_secs(3600));
    assert_eq!(h.state(), &StationState::Idle);
    h.send(StationInput::Connect(home.id));
    assert!(matches!(h.state(), StationState::Associating { .. }));
}

#[test]
fn switching_profiles_releases_in_reverse_order_first() {
    let home = profile("home", 0);
    let cafe = profile("cafe", 0);
    let mut h = enabled_with(vec![home.clone(), cafe.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -40)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::L3Ready);
    let commands = h.send(StationInput::Connect(cafe.id));
    let kinds: Vec<_> = commands
        .iter()
        .filter(|c| !matches!(c, StationCommand::StartTimer { .. }))
        .cloned()
        .collect();
    assert_eq!(
        kinds,
        vec![
            StationCommand::UnbindL3,
            StationCommand::Disassociate,
            StationCommand::Associate {
                profile: cafe.id,
                bssid: None
            },
        ]
    );
    // A stale link-up for the old network is ignored.
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    assert!(matches!(h.state(), StationState::Associating { profile, .. } if *profile == cafe.id));
}

#[test]
fn deleting_the_active_profile_disconnects() {
    let home = profile("home", 0);
    let mut h = enabled_with(vec![home.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -40)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::ProfilesChanged(vec![]));
    assert_eq!(h.state(), &StationState::Idle);
    assert_eq!(h.associated + h.bound, 0);
}

#[test]
fn editing_the_active_profile_reconnects_but_renaming_does_not() {
    let home = profile("home", 0);
    let mut h = enabled_with(vec![home.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -40)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::L3Ready);
    let mut renamed = home.clone();
    renamed.name = "Home".into();
    let commands = h.send(StationInput::ProfilesChanged(vec![renamed.clone()]));
    assert!(commands.is_empty(), "{commands:?}");
    let mut edited = renamed;
    edited.l3 = L3Config::Unmanaged;
    let commands = h.send(StationInput::ProfilesChanged(vec![edited]));
    assert!(commands.contains(&StationCommand::UnbindL3));
    assert!(matches!(h.state(), StationState::Associating { .. }));
}

#[test]
fn disabling_releases_everything() {
    let home = profile("home", 0);
    let mut h = enabled_with(vec![home.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -40)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::SetEnabled(false));
    assert_eq!(h.state(), &StationState::Disabled);
    assert_eq!(h.station.held(), &[] as &[Held]);
    // Old timers are inert.
    h.advance(Duration::from_secs(3600));
    assert_eq!(h.state(), &StationState::Disabled);
}

#[test]
fn suspend_and_resume_tears_down_clears_stale_scan_and_preserves_user_hold() {
    let home = profile("home", 0);
    let mut h = enabled_with(vec![home.clone()]);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -40)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::L3Ready);
    assert!(matches!(h.state(), StationState::Connected { .. }));

    // Suspend releases L3 then L2.
    let commands = h.send(StationInput::SetSuspended(true));
    assert_eq!(
        commands,
        vec![StationCommand::UnbindL3, StationCommand::Disassociate]
    );
    assert_eq!(h.state(), &StationState::Disabled);

    // Resume clears the stale scan cache and immediately starts a fresh scan.
    let commands = h.send(StationInput::SetSuspended(false));
    assert_eq!(h.state(), &StationState::Idle);
    assert!(commands.contains(&StationCommand::Scan));
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -40)])));
    assert!(matches!(h.state(), StationState::Associating { .. }));

    // If the user explicitly disconnected before sleep, resume keeps autoconnect held.
    h.send(StationInput::Disconnect);
    assert!(h.station.snapshot().autoconnect_held);
    h.send(StationInput::SetSuspended(true));
    let commands = h.send(StationInput::SetSuspended(false));
    assert_eq!(h.state(), &StationState::Idle);
    assert!(h.station.snapshot().autoconnect_held);
    assert!(
        !commands
            .iter()
            .any(|c| matches!(c, StationCommand::Scan | StationCommand::Associate { .. }))
    );
}

// ---------------------------------------------------------------------------
// Property test: no sequence of inputs can leak or double-acquire resources.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Step {
    Enable(bool),
    Suspend(bool),
    Scan,
    ScanOk(Vec<usize>),
    ScanErr,
    Connect(usize),
    Disconnect,
    LinkUp(usize),
    LinkDown,
    Auth,
    L3Ready,
    L3Failed,
    FailAssociate,
    FailBind,
    Secrets(usize),
    NoSecrets(usize),
    DropProfile(usize),
    EditProfile(usize),
    Advance(u16),
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        any::<bool>().prop_map(Step::Enable),
        any::<bool>().prop_map(Step::Suspend),
        Just(Step::Scan),
        proptest::collection::vec(0..3usize, 0..3).prop_map(Step::ScanOk),
        Just(Step::ScanErr),
        (0..3usize).prop_map(Step::Connect),
        Just(Step::Disconnect),
        (0..3usize).prop_map(Step::LinkUp),
        Just(Step::LinkDown),
        Just(Step::Auth),
        Just(Step::L3Ready),
        Just(Step::L3Failed),
        Just(Step::FailAssociate),
        Just(Step::FailBind),
        (0..3usize).prop_map(Step::Secrets),
        (0..3usize).prop_map(Step::NoSecrets),
        (0..3usize).prop_map(Step::DropProfile),
        (0..3usize).prop_map(Step::EditProfile),
        (0..400u16).prop_map(Step::Advance),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn resources_are_never_leaked_or_doubled(steps in proptest::collection::vec(step(), 1..80)) {
        let names = ["a", "b", "c"];
        let mut profiles: Vec<WifiProfile> = names.iter().map(|n| profile(n, 0)).collect();
        profiles[2].l3 = L3Config::Unmanaged;
        let ids: Vec<ProfileId> = profiles.iter().map(|p| p.id).collect();
        let mut h = Harness::new();
        h.send(StationInput::ProfilesChanged(profiles.clone()));
        for step in steps {
            let input = match step {
                Step::Enable(on) => StationInput::SetEnabled(on),
                Step::Suspend(suspended) => StationInput::SetSuspended(suspended),
                Step::Scan => StationInput::Scan,
                Step::ScanOk(seen) => StationInput::ScanFinished(Ok(
                    seen.into_iter().map(|i| bss(names[i], -50)).collect(),
                )),
                Step::ScanErr => StationInput::ScanFinished(Err(FailureReason::Backend("x".into()))),
                Step::Connect(i) => StationInput::Connect(ids[i]),
                Step::Disconnect => StationInput::Disconnect,
                Step::LinkUp(i) => StationInput::LinkConnected { ssid: Ssid::new(names[i]).unwrap(), bssid: None },
                Step::LinkDown => StationInput::LinkDisconnected,
                Step::Auth => StationInput::AuthFailed,
                Step::L3Ready => StationInput::L3Ready,
                Step::L3Failed => StationInput::L3Failed("x".into()),
                Step::FailAssociate => StationInput::CommandFailed {
                    command: StationCommandKind::Associate,
                    reason: FailureReason::Backend("x".into()),
                },
                Step::FailBind => StationInput::CommandFailed {
                    command: StationCommandKind::BindL3,
                    reason: FailureReason::Backend("x".into()),
                },
                Step::Secrets(i) => StationInput::SecretsUpdated(ids[i]),
                Step::NoSecrets(i) => StationInput::SecretsUnavailable(ids[i]),
                Step::DropProfile(i) => {
                    let remaining: Vec<_> = profiles.iter().filter(|p| p.id != ids[i]).cloned().collect();
                    StationInput::ProfilesChanged(remaining)
                }
                Step::EditProfile(i) => {
                    let mut edited = profiles.clone();
                    edited[i].hidden = !edited[i].hidden;
                    profiles = edited.clone();
                    StationInput::ProfilesChanged(edited)
                }
                Step::Advance(secs) => {
                    h.advance(Duration::from_secs(u64::from(secs)));
                    continue;
                }
            };
            h.send(input);
            // Resource shape matches the state.
            let held = h.station.held().to_vec();
            match h.state() {
                StationState::Disabled | StationState::Idle | StationState::Waiting { .. } => {
                    prop_assert!(held.is_empty(), "{:?} holds {:?}", h.state(), held);
                }
                StationState::Associating { .. } => prop_assert_eq!(held, vec![Held::Association]),
                StationState::ConfiguringL3 { .. } => {
                    prop_assert_eq!(held, vec![Held::Association, Held::L3Binding]);
                }
                StationState::Connected { .. } | StationState::Reconnecting { .. } => {
                    prop_assert!(!held.is_empty() && held[0] == Held::Association);
                }
            }
        }
        h.send(StationInput::SetEnabled(false));
        prop_assert_eq!(h.associated + h.bound, 0);
    }
}

#[test]
fn hotspot_active_suspends_station_and_preserves_user_hold() {
    let mut h = Harness::new();
    let home = profile("home", 1);
    h.send(StationInput::SetEnabled(true));
    h.send(StationInput::ProfilesChanged(vec![home.clone()]));
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -45)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::L3Ready);
    assert!(matches!(h.state(), StationState::Connected { .. }));

    h.send(StationInput::SetHotspotActive(true));
    assert_eq!(h.state(), &StationState::Disabled);
    assert_eq!(h.associated + h.bound, 0);

    let cmds = h.send(StationInput::SetHotspotActive(false));
    assert!(cmds.contains(&StationCommand::Scan));
    assert_eq!(h.station.snapshot().visible, []);
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -45)])));
    assert!(matches!(h.state(), StationState::Associating { .. }));

    // If user disconnected before hotspot, user_hold stays preserved across hotspot.
    h.send(StationInput::Disconnect);
    assert!(h.station.snapshot().autoconnect_held);
    h.send(StationInput::SetHotspotActive(true));
    assert_eq!(h.state(), &StationState::Disabled);
    h.send(StationInput::SetHotspotActive(false));
    assert_eq!(h.state(), &StationState::Idle);
    assert!(h.station.snapshot().autoconnect_held);
}

#[test]
fn l3_failure_during_reconnecting_tears_down_and_retries() {
    let mut h = Harness::new();
    let home = profile("home", 1);
    h.send(StationInput::SetEnabled(true));
    h.send(StationInput::ProfilesChanged(vec![home.clone()]));
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -45)])));
    h.send(StationInput::LinkConnected {
        ssid: home.ssid.clone(),
        bssid: None,
    });
    h.send(StationInput::L3Ready);
    assert!(matches!(h.state(), StationState::Connected { .. }));

    h.send(StationInput::LinkDisconnected);
    assert!(matches!(h.state(), StationState::Reconnecting { .. }));

    h.send(StationInput::L3Failed("dhcp failed".into()));
    assert!(matches!(h.state(), StationState::Waiting { .. }));
    assert_eq!(h.associated + h.bound, 0);
}

#[test]
fn editing_profile_to_open_clears_needs_secrets() {
    let mut h = Harness::new();
    let mut home = profile("home", 1);
    h.send(StationInput::SetEnabled(true));
    h.send(StationInput::ProfilesChanged(vec![home.clone()]));
    h.send(StationInput::ScanFinished(Ok(vec![bss("home", -45)])));
    h.send(StationInput::AuthFailed);
    assert!(h.station.snapshot().needs_secrets.contains(&home.id));

    home.security = ProfileSecurity::Open;
    h.send(StationInput::ProfilesChanged(vec![home.clone()]));
    assert!(!h.station.snapshot().needs_secrets.contains(&home.id));
}

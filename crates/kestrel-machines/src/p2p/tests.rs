// SPDX-License-Identifier: LGPL-2.1-or-later

use std::time::Instant;

use kestrel_model::{
    FailureReason, GoIntent, InterfaceName, MacAddress, P2pRole, WpsMethod, WpsPin,
};
use proptest::prelude::*;

use super::*;

const PEER: MacAddress = MacAddress::from_octets([2, 0, 0, 0, 0, 0x42]);

fn group_if() -> InterfaceName {
    InterfaceName::new("p2p-wlan0-0").unwrap()
}

fn start() -> (P2pSession, Vec<SessionCommand>) {
    P2pSession::start(
        SessionConfig::default(),
        PEER,
        WpsMethod::PushButton,
        GoIntent::default(),
    )
}

fn non_timer(commands: Vec<SessionCommand>) -> Vec<SessionCommand> {
    commands
        .into_iter()
        .filter(|c| !matches!(c, SessionCommand::StartTimer { .. }))
        .collect()
}

#[test]
fn group_owner_role_serves_a_shared_subnet() {
    let now = Instant::now();
    let (mut s, commands) = start();
    assert_eq!(
        non_timer(commands),
        vec![SessionCommand::Connect {
            peer: PEER,
            method: WpsMethod::PushButton,
            go_intent: GoIntent::default(),
            persistent: false,
        }]
    );
    s.handle(
        now,
        SessionInput::GoNegotiationSucceeded {
            role: P2pRole::GroupOwner,
        },
    );
    let commands = s.handle(
        now,
        SessionInput::GroupStarted {
            group_if: group_if(),
            role: P2pRole::GroupOwner,
        },
    );
    assert_eq!(
        non_timer(commands),
        vec![SessionCommand::BindL3 {
            link: group_if(),
            request: L3Request::SharedSubnet,
        }]
    );
    let peer_ip = "192.168.49.10".parse().ok();
    s.handle(now, SessionInput::L3Ready { peer_ip: None });
    s.handle(now, SessionInput::L3Ready { peer_ip });
    assert_eq!(
        s.state(),
        &SessionState::Ready {
            role: P2pRole::GroupOwner,
            group_if: group_if(),
            peer_ip,
        }
    );
    let commands = s.handle(now, SessionInput::Close);
    assert_eq!(
        commands,
        vec![
            SessionCommand::UnbindL3 { link: group_if() },
            SessionCommand::RemoveGroup {
                group_if: group_if()
            },
        ]
    );
    assert_eq!(s.state(), &SessionState::Closed { reason: None });
    assert_eq!(s.held(), &[] as &[SessionHeld]);
}

#[test]
fn client_role_runs_a_dhcp_client() {
    let now = Instant::now();
    let (mut s, _) = start();
    // Some backends report the group without a separate negotiation event
    // (for example when joining an existing group).
    let commands = s.handle(
        now,
        SessionInput::GroupStarted {
            group_if: group_if(),
            role: P2pRole::Client,
        },
    );
    assert!(commands.contains(&SessionCommand::BindL3 {
        link: group_if(),
        request: L3Request::DhcpClient,
    }));
}

#[test]
fn negotiation_failure_cancels_and_closes_with_reason() {
    let now = Instant::now();
    let (mut s, _) = start();
    let commands = s.handle(now, SessionInput::GoNegotiationFailed { status: 9 });
    assert_eq!(commands, vec![SessionCommand::CancelNegotiation]);
    assert_eq!(
        s.state(),
        &SessionState::Closed {
            reason: Some(FailureReason::NegotiationFailed(9))
        }
    );
}

#[test]
fn display_pin_is_exposed_while_negotiating() {
    let now = Instant::now();
    let (mut s, _) = P2pSession::start(
        SessionConfig::default(),
        PEER,
        WpsMethod::DisplayPin,
        GoIntent::MAX,
    );
    let pin = WpsPin::new("12345670").unwrap();
    s.handle(
        now,
        SessionInput::ConnectAccepted {
            generated_pin: Some(pin.clone()),
        },
    );
    assert_eq!(s.state(), &SessionState::Negotiating { pin: Some(pin) });
}

#[test]
fn peer_leaving_unbinds_but_does_not_remove_the_finished_group() {
    let now = Instant::now();
    let (mut s, _) = start();
    s.handle(
        now,
        SessionInput::GroupStarted {
            group_if: group_if(),
            role: P2pRole::Client,
        },
    );
    s.handle(now, SessionInput::L3Ready { peer_ip: None });
    let commands = s.handle(
        now,
        SessionInput::GroupFinished {
            group_if: group_if(),
        },
    );
    assert_eq!(
        commands,
        vec![SessionCommand::UnbindL3 { link: group_if() }]
    );
    assert_eq!(
        s.state(),
        &SessionState::Closed {
            reason: Some(FailureReason::PeerDisconnected)
        }
    );
}

#[test]
fn l3_timeout_rolls_back_the_group() {
    let now = Instant::now();
    let (mut s, _) = start();
    let commands = s.handle(
        now,
        SessionInput::GroupStarted {
            group_if: group_if(),
            role: P2pRole::GroupOwner,
        },
    );
    let Some(SessionCommand::StartTimer { kind, token, .. }) = commands.into_iter().find(|c| {
        matches!(
            c,
            SessionCommand::StartTimer {
                kind: SessionTimer::L3,
                ..
            }
        )
    }) else {
        panic!("no L3 timer");
    };
    let commands = s.handle(now, SessionInput::Timer { kind, token });
    assert_eq!(
        commands,
        vec![
            SessionCommand::UnbindL3 { link: group_if() },
            SessionCommand::RemoveGroup {
                group_if: group_if()
            },
        ]
    );
}

#[test]
fn unrelated_group_events_are_ignored() {
    let now = Instant::now();
    let (mut s, _) = start();
    let commands = s.handle(
        now,
        SessionInput::GroupFinished {
            group_if: InterfaceName::new("p2p-wlan0-7").unwrap(),
        },
    );
    assert_eq!(commands, vec![]);
    assert!(matches!(s.state(), SessionState::Negotiating { .. }));
}

#[test]
fn closed_sessions_ignore_everything() {
    let now = Instant::now();
    let (mut s, _) = start();
    s.handle(now, SessionInput::Close);
    let commands = s.handle(
        now,
        SessionInput::GroupStarted {
            group_if: group_if(),
            role: P2pRole::GroupOwner,
        },
    );
    assert_eq!(commands, vec![]);
}

#[test]
fn autonomous_group_starts_without_negotiation() {
    let now = Instant::now();
    let (mut s, commands) = P2pSession::start_autonomous(SessionConfig::default(), Some(2412));
    assert_eq!(
        s.state(),
        &SessionState::Forming {
            role: P2pRole::GroupOwner
        }
    );
    assert!(s.is_autonomous());
    assert_eq!(s.peer(), None);
    assert_eq!(s.method(), None);
    assert_eq!(
        non_timer(commands),
        vec![SessionCommand::StartGroup {
            frequency: Some(2412),
            persistent: false,
        }]
    );

    let commands = s.handle(
        now,
        SessionInput::GroupStarted {
            group_if: group_if(),
            role: P2pRole::GroupOwner,
        },
    );
    assert_eq!(
        non_timer(commands),
        vec![
            SessionCommand::AuthorizeGroup {
                group_if: group_if()
            },
            SessionCommand::BindL3 {
                link: group_if(),
                request: L3Request::SharedSubnet,
            },
        ]
    );
    s.handle(now, SessionInput::L3Ready { peer_ip: None });
    assert_eq!(
        s.state(),
        &SessionState::Ready {
            role: P2pRole::GroupOwner,
            group_if: group_if(),
            peer_ip: None,
        }
    );
}

#[test]
fn autonomous_group_add_failure_cancels_and_closes() {
    let now = Instant::now();
    let (mut s, _) = P2pSession::start_autonomous(SessionConfig::default(), None);
    let commands = s.handle(
        now,
        SessionInput::CommandFailed {
            command: SessionCommandKind::StartGroup,
            reason: FailureReason::Backend("no channel".into()),
        },
    );
    assert_eq!(commands, vec![SessionCommand::CancelNegotiation]);
    assert!(matches!(
        s.state(),
        SessionState::Closed {
            reason: Some(FailureReason::Backend(_))
        }
    ));
}

#[test]
fn autonomous_group_authorization_failure_rolls_back() {
    let now = Instant::now();
    let (mut s, _) = P2pSession::start_autonomous(SessionConfig::default(), None);
    s.handle(
        now,
        SessionInput::GroupStarted {
            group_if: group_if(),
            role: P2pRole::GroupOwner,
        },
    );
    let commands = s.handle(
        now,
        SessionInput::CommandFailed {
            command: SessionCommandKind::AuthorizeGroup,
            reason: FailureReason::NotSupported("WPS".into()),
        },
    );
    assert_eq!(
        commands,
        vec![
            SessionCommand::UnbindL3 { link: group_if() },
            SessionCommand::RemoveGroup {
                group_if: group_if()
            },
        ]
    );
}

#[test]
fn autonomous_group_finished_before_started_closes() {
    let now = Instant::now();
    let (mut s, _) = P2pSession::start_autonomous(SessionConfig::default(), None);
    let commands = s.handle(
        now,
        SessionInput::GroupFinished {
            group_if: group_if(),
        },
    );
    assert_eq!(commands, vec![SessionCommand::CancelNegotiation]);
    assert!(matches!(
        s.state(),
        SessionState::Closed {
            reason: Some(FailureReason::PeerDisconnected)
        }
    ));
}

// ---------------------------------------------------------------------------
// Property test over arbitrary event orders.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Step {
    Close,
    Accepted,
    NegOk(bool),
    NegFail,
    Wps,
    Started(u8, bool),
    Finished(u8),
    L3Ready,
    L3Failed,
    FailConnect,
    FailBind,
    Device,
    FireTimer(u8),
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        Just(Step::Close),
        Just(Step::Accepted),
        any::<bool>().prop_map(Step::NegOk),
        Just(Step::NegFail),
        Just(Step::Wps),
        (0..2u8, any::<bool>()).prop_map(|(i, go)| Step::Started(i, go)),
        (0..2u8).prop_map(Step::Finished),
        Just(Step::L3Ready),
        Just(Step::L3Failed),
        Just(Step::FailConnect),
        Just(Step::FailBind),
        Just(Step::Device),
        (0..3u8).prop_map(Step::FireTimer),
    ]
}

fn role(go: bool) -> P2pRole {
    if go {
        P2pRole::GroupOwner
    } else {
        P2pRole::Client
    }
}

fn ifname(index: u8) -> InterfaceName {
    InterfaceName::new(format!("p2p-wlan0-{index}")).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn every_session_ends_with_nothing_held(steps in proptest::collection::vec(step(), 0..40)) {
        let now = Instant::now();
        let (mut s, initial) = start();
        let mut timers: Vec<(SessionTimer, TimerToken)> = Vec::new();
        let mut negotiation = 0i32;
        let mut negotiation_done = false;
        let mut groups: Vec<InterfaceName> = Vec::new();
        let mut bound: Vec<InterfaceName> = Vec::new();
        let mut apply = |commands: Vec<SessionCommand>,
                         timers: &mut Vec<(SessionTimer, TimerToken)>,
                         groups: &mut Vec<InterfaceName>,
                         finished: Option<InterfaceName>| -> Result<(), TestCaseError> {
            if let Some(gone) = finished {
                groups.retain(|g| *g != gone);
            }
            for command in commands {
                match command {
                    SessionCommand::Connect { .. } | SessionCommand::ConnectPersistent { .. } => {
                        negotiation += 1;
                    }
                    SessionCommand::StartGroup { .. }
                    | SessionCommand::StartPersistentGroup { .. }
                    | SessionCommand::AuthorizeGroup { .. } => {}
                    SessionCommand::CancelNegotiation => negotiation -= 1,
                    SessionCommand::BindL3 { link, .. } => {
                        prop_assert!(!bound.contains(&link), "double bind");
                        bound.push(link);
                    }
                    SessionCommand::UnbindL3 { link } => {
                        prop_assert!(bound.contains(&link), "unbind without bind");
                        bound.retain(|l| *l != link);
                    }
                    SessionCommand::RemoveGroup { group_if } => {
                        groups.retain(|g| *g != group_if);
                    }
                    SessionCommand::StartTimer { kind, token, .. } => timers.push((kind, token)),
                }
            }
            Ok(())
        };
        apply(initial, &mut timers, &mut groups, None)?;
        for step in steps {
            let mut finished = None;
            let input = match step {
                Step::Close => SessionInput::Close,
                Step::Accepted => SessionInput::ConnectAccepted { generated_pin: None },
                Step::NegOk(go) => SessionInput::GoNegotiationSucceeded { role: role(go) },
                Step::NegFail => SessionInput::GoNegotiationFailed { status: 1 },
                Step::Wps => SessionInput::WpsFailed,
                Step::Started(i, go) => {
                    // The backend creates the group interface.
                    if !groups.contains(&ifname(i)) {
                        groups.push(ifname(i));
                    }
                    SessionInput::GroupStarted { group_if: ifname(i), role: role(go) }
                }
                Step::Finished(i) => {
                    finished = Some(ifname(i));
                    SessionInput::GroupFinished { group_if: ifname(i) }
                }
                Step::L3Ready => SessionInput::L3Ready { peer_ip: None },
                Step::L3Failed => SessionInput::L3Failed("x".into()),
                Step::FailConnect => SessionInput::CommandFailed {
                    command: SessionCommandKind::Connect,
                    reason: FailureReason::Backend("x".into()),
                },
                Step::FailBind => SessionInput::CommandFailed {
                    command: SessionCommandKind::BindL3,
                    reason: FailureReason::NoSubnet,
                },
                Step::Device => SessionInput::DeviceUnavailable,
                Step::FireTimer(i) => {
                    if timers.is_empty() { continue; }
                    let (kind, token) = timers[usize::from(i) % timers.len()];
                    SessionInput::Timer { kind, token }
                }
            };
            let commands = s.handle(now, input);
            apply(commands, &mut timers, &mut groups, finished)?;
            if s.held().iter().any(|h| matches!(h, SessionHeld::Group(_))) {
                // The session adopted a group: negotiation is complete.
                negotiation_done = true;
            }
        }
        let commands = s.handle(now, SessionInput::Close);
        apply(commands, &mut timers, &mut groups, None)?;
        prop_assert!(s.is_closed());
        prop_assert!(s.held().is_empty());
        prop_assert!(bound.is_empty(), "leaked L3 bindings: {bound:?}");
        prop_assert!(negotiation_done || negotiation <= 0, "negotiation never cancelled");
        // Groups the session adopted were removed or finished. Groups it
        // ignored (second group while busy) are not its responsibility.
        let adopted_leak = groups.iter().any(|g| s.held().contains(&SessionHeld::Group(g.clone())));
        prop_assert!(!adopted_leak);
    }
}

// ---------------------------------------------------------------------------
// Autonomous groups: no negotiation, no peer.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum GroupStep {
    Close,
    Started(u8),
    Finished(u8),
    L3Ready,
    L3Failed,
    FailStart,
    FailBind,
    Device,
    FireTimer(u8),
}

fn group_step() -> impl Strategy<Value = GroupStep> {
    prop_oneof![
        Just(GroupStep::Close),
        (0..2u8).prop_map(GroupStep::Started),
        (0..2u8).prop_map(GroupStep::Finished),
        Just(GroupStep::L3Ready),
        Just(GroupStep::L3Failed),
        Just(GroupStep::FailStart),
        Just(GroupStep::FailBind),
        Just(GroupStep::Device),
        (0..3u8).prop_map(GroupStep::FireTimer),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn every_autonomous_group_ends_with_nothing_held(
        steps in proptest::collection::vec(group_step(), 0..40),
    ) {
        let now = Instant::now();
        let (mut s, initial) = P2pSession::start_autonomous(SessionConfig::default(), None);
        let mut timers: Vec<(SessionTimer, TimerToken)> = Vec::new();
        let mut groups: Vec<InterfaceName> = Vec::new();
        let mut bound: Vec<InterfaceName> = Vec::new();
        let mut apply = |commands: Vec<SessionCommand>,
                         timers: &mut Vec<(SessionTimer, TimerToken)>,
                         groups: &mut Vec<InterfaceName>,
                         finished: Option<InterfaceName>| -> Result<(), TestCaseError> {
            if let Some(gone) = finished {
                groups.retain(|g| *g != gone);
            }
            for command in commands {
                match command {
                    SessionCommand::StartGroup { .. }
                    | SessionCommand::StartPersistentGroup { .. }
                    | SessionCommand::AuthorizeGroup { .. }
                    | SessionCommand::Connect { .. }
                    | SessionCommand::ConnectPersistent { .. }
                    | SessionCommand::CancelNegotiation => {}
                    SessionCommand::BindL3 { link, request } => {
                        prop_assert_eq!(request, L3Request::SharedSubnet);
                        prop_assert!(!bound.contains(&link), "double bind");
                        bound.push(link);
                    }
                    SessionCommand::UnbindL3 { link } => {
                        prop_assert!(bound.contains(&link), "unbind without bind");
                        bound.retain(|l| *l != link);
                    }
                    SessionCommand::RemoveGroup { group_if } => {
                        groups.retain(|g| *g != group_if);
                    }
                    SessionCommand::StartTimer { kind, token, .. } => timers.push((kind, token)),
                }
            }
            Ok(())
        };
        apply(initial, &mut timers, &mut groups, None)?;
        for step in steps {
            let mut finished = None;
            let input = match step {
                GroupStep::Close => SessionInput::Close,
                GroupStep::Started(i) => {
                    if !groups.contains(&ifname(i)) {
                        groups.push(ifname(i));
                    }
                    SessionInput::GroupStarted {
                        group_if: ifname(i),
                        role: P2pRole::GroupOwner,
                    }
                }
                GroupStep::Finished(i) => {
                    finished = Some(ifname(i));
                    SessionInput::GroupFinished { group_if: ifname(i) }
                }
                GroupStep::L3Ready => SessionInput::L3Ready { peer_ip: None },
                GroupStep::L3Failed => SessionInput::L3Failed("x".into()),
                GroupStep::FailStart => SessionInput::CommandFailed {
                    command: SessionCommandKind::StartGroup,
                    reason: FailureReason::Backend("x".into()),
                },
                GroupStep::FailBind => SessionInput::CommandFailed {
                    command: SessionCommandKind::BindL3,
                    reason: FailureReason::NoSubnet,
                },
                GroupStep::Device => SessionInput::DeviceUnavailable,
                GroupStep::FireTimer(i) => {
                    if timers.is_empty() { continue; }
                    let (kind, token) = timers[usize::from(i) % timers.len()];
                    SessionInput::Timer { kind, token }
                }
            };
            let commands = s.handle(now, input);
            apply(commands, &mut timers, &mut groups, finished)?;
        }
        let commands = s.handle(now, SessionInput::Close);
        apply(commands, &mut timers, &mut groups, None)?;
        prop_assert!(s.is_closed());
        prop_assert!(s.held().is_empty());
        prop_assert!(bound.is_empty(), "leaked L3 bindings: {bound:?}");
        let adopted_leak = groups
            .iter()
            .any(|g| s.held().contains(&SessionHeld::Group(g.clone())));
        prop_assert!(!adopted_leak);
    }
}

#[test]
fn reused_persistent_group_skips_wps_authorization() {
    let now = Instant::now();
    let group_id = P2pGroupId::generate();
    let (mut s, commands) =
        P2pSession::start_persistent_group(SessionConfig::default(), group_id, Some(2412));
    assert!(s.is_persistent());
    assert_eq!(
        non_timer(commands),
        vec![SessionCommand::StartPersistentGroup {
            group_id,
            frequency: Some(2412),
        }]
    );
    let commands = s.handle(
        now,
        SessionInput::GroupStarted {
            group_if: group_if(),
            role: P2pRole::GroupOwner,
        },
    );
    // No AuthorizeGroup because the persistent group already carries PSK credentials.
    assert_eq!(
        non_timer(commands),
        vec![SessionCommand::BindL3 {
            link: group_if(),
            request: L3Request::SharedSubnet,
        }]
    );
}

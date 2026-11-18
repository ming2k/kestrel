// SPDX-License-Identifier: LGPL-2.1-or-later

//! Autoconnect candidate selection.
//!
//! This is a pure function of the saved profiles, the last scan, and which
//! profiles are currently excluded (secrets missing, cooling down after
//! repeated failures).

use std::cmp::Reverse;

use kestrel_model::{Bss, ProfileId, WifiProfile};

/// Whether `bss` can serve `profile`.
pub fn matches(profile: &WifiProfile, bss: &Bss) -> bool {
    bss.ssid == profile.ssid
        && profile.security.accepts(bss.security)
        && profile.bssid.is_none_or(|pin| pin == bss.bssid)
}

/// The highest-priority saved profile that can join `bss`, regardless of
/// whether autoconnect is enabled on the profile.
pub fn matching_profile<'a>(
    profiles: impl IntoIterator<Item = &'a WifiProfile>,
    bss: &Bss,
) -> Option<ProfileId> {
    profiles
        .into_iter()
        .filter(|profile| matches(profile, bss))
        .max_by_key(|profile| {
            (
                profile.priority,
                profile.security.strength(),
                profile.last_connected.unwrap_or(0),
                Reverse(profile.id),
            )
        })
        .map(|profile| profile.id)
}

/// The strongest matching signal for `profile`, if it is visible.
pub fn best_signal(profile: &WifiProfile, visible: &[Bss]) -> Option<i16> {
    visible
        .iter()
        .filter(|bss| matches(profile, bss))
        .map(|bss| bss.signal)
        .max()
}

/// Profiles that autoconnect may try, ignoring visibility.
pub fn has_eligible<'a>(
    profiles: impl IntoIterator<Item = &'a WifiProfile>,
    excluded: impl Fn(ProfileId) -> bool,
) -> bool {
    profiles
        .into_iter()
        .any(|profile| profile.autoconnect && !excluded(profile.id))
}

/// Picks the next autoconnect candidate.
///
/// A profile is a candidate when autoconnect is on, it is not excluded, and
/// it is visible (or marked hidden, since hidden networks may not appear in
/// passive scans). Ranking, highest first:
///
/// 1. profile priority;
/// 2. visible before hidden-but-unseen;
/// 3. security strength;
/// 4. best signal;
/// 5. most recently connected;
/// 6. profile id, so the choice is deterministic.
pub fn select<'a>(
    profiles: impl IntoIterator<Item = &'a WifiProfile>,
    visible: &[Bss],
    excluded: impl Fn(ProfileId) -> bool,
) -> Option<ProfileId> {
    profiles
        .into_iter()
        .filter(|profile| profile.autoconnect && !excluded(profile.id))
        .filter_map(|profile| {
            let signal = best_signal(profile, visible);
            if signal.is_none() && !profile.hidden {
                return None;
            }
            Some((
                (
                    profile.priority,
                    signal.is_some(),
                    profile.security.strength(),
                    signal.unwrap_or(i16::MIN),
                    profile.last_connected.unwrap_or(0),
                    Reverse(profile.id),
                ),
                profile.id,
            ))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, id)| id)
}

#[cfg(test)]
mod tests {
    use kestrel_model::{MacAddress, ProfileSecurity, Security, Ssid};

    use super::*;

    fn profile(ssid: &str, priority: i32) -> WifiProfile {
        let mut profile = WifiProfile::new(Ssid::new(ssid).unwrap(), ProfileSecurity::WpaPersonal);
        profile.priority = priority;
        profile
    }

    fn bss(ssid: &str, signal: i16, last: u8) -> Bss {
        Bss {
            ssid: Ssid::new(ssid).unwrap(),
            bssid: MacAddress::from_octets([2, 0, 0, 0, 0, last]),
            frequency: 2412,
            signal,
            security: Security::Wpa2Psk,
        }
    }

    #[test]
    fn priority_beats_signal() {
        let home = profile("home", 10);
        let cafe = profile("cafe", 0);
        let visible = [bss("home", -80, 1), bss("cafe", -30, 2)];
        assert_eq!(select([&home, &cafe], &visible, |_| false), Some(home.id));
    }

    #[test]
    fn signal_breaks_priority_ties() {
        let a = profile("a", 0);
        let b = profile("b", 0);
        let visible = [bss("a", -70, 1), bss("b", -40, 2)];
        assert_eq!(select([&a, &b], &visible, |_| false), Some(b.id));
    }

    #[test]
    fn invisible_profiles_are_skipped_unless_hidden() {
        let mut hidden = profile("secret", 0);
        let plain = profile("plain", 5);
        assert_eq!(select([&plain], &[], |_| false), None);
        hidden.hidden = true;
        assert_eq!(select([&plain, &hidden], &[], |_| false), Some(hidden.id));
    }

    #[test]
    fn excluded_and_manual_profiles_are_skipped() {
        let mut manual = profile("home", 10);
        manual.autoconnect = false;
        let other = profile("other", 0);
        let visible = [bss("home", -30, 1), bss("other", -60, 2)];
        assert_eq!(
            select([&manual, &other], &visible, |_| false),
            Some(other.id)
        );
        assert_eq!(
            select([&manual, &other], &visible, |id| id == other.id),
            None
        );
    }

    #[test]
    fn security_mismatch_is_not_a_match() {
        let mut wpa3 = profile("net", 0);
        wpa3.security = ProfileSecurity::Wpa3Personal;
        assert_eq!(select([&wpa3], &[bss("net", -40, 1)], |_| false), None);
    }

    #[test]
    fn bssid_pin_is_respected() {
        let mut pinned = profile("net", 0);
        pinned.bssid = Some(MacAddress::from_octets([2, 0, 0, 0, 0, 9]));
        assert_eq!(select([&pinned], &[bss("net", -40, 1)], |_| false), None);
        assert_eq!(
            select([&pinned], &[bss("net", -40, 9)], |_| false),
            Some(pinned.id)
        );
    }

    #[test]
    fn matching_profile_picks_highest_priority_including_manual_profiles() {
        let mut low = profile("home", 1);
        low.autoconnect = true;
        let mut high = profile("home", 10);
        high.autoconnect = false;
        let other = profile("cafe", 50);
        let target = bss("home", -45, 1);
        assert_eq!(
            matching_profile([&low, &high, &other], &target),
            Some(high.id)
        );
        assert_eq!(matching_profile([&other], &target), None);
    }
}

// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt::Write as _;

use kestrel_model::{CertId, InterfaceName, P2pGroupId, ProfileId, SessionId};
use zbus::OwnedObjectPath;

use crate::ROOT_PATH;

/// Escapes a string into a D-Bus path element: `[A-Za-z0-9]` pass
/// through; every other byte becomes `_XX`.
fn escape(value: &str) -> String {
    value.bytes().fold(String::new(), |mut out, byte| {
        if byte.is_ascii_alphanumeric() {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "_{byte:02x}");
        }
        out
    })
}

fn unescape(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'_' {
            let hex = value.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn path(value: String) -> OwnedObjectPath {
    OwnedObjectPath::try_from(value).expect("escaped paths are valid")
}

pub fn device_path(name: &InterfaceName) -> OwnedObjectPath {
    path(format!("{ROOT_PATH}/Device/{}", escape(name.as_str())))
}

pub fn profile_path(id: ProfileId) -> OwnedObjectPath {
    path(format!("{ROOT_PATH}/Profile/{}", id.simple()))
}

pub fn session_path(id: SessionId) -> OwnedObjectPath {
    path(format!("{ROOT_PATH}/Session/{}", id.0))
}

pub fn cert_path(id: CertId) -> OwnedObjectPath {
    path(format!("{ROOT_PATH}/Certificate/{}", id.simple()))
}

pub fn p2p_group_path(id: P2pGroupId) -> OwnedObjectPath {
    path(format!("{ROOT_PATH}/P2pGroup/{}", id.simple()))
}

pub fn device_from_path(value: &str) -> Option<InterfaceName> {
    let element = value.strip_prefix(&format!("{ROOT_PATH}/Device/"))?;
    InterfaceName::new(unescape(element)?).ok()
}

pub fn profile_from_path(value: &str) -> Option<ProfileId> {
    ProfileId::parse(value.strip_prefix(&format!("{ROOT_PATH}/Profile/"))?).ok()
}

pub fn session_from_path(value: &str) -> Option<SessionId> {
    value
        .strip_prefix(&format!("{ROOT_PATH}/Session/"))?
        .parse()
        .ok()
        .map(SessionId)
}

pub fn cert_from_path(value: &str) -> Option<CertId> {
    CertId::parse(value.strip_prefix(&format!("{ROOT_PATH}/Certificate/"))?).ok()
}

pub fn p2p_group_from_path(value: &str) -> Option<P2pGroupId> {
    P2pGroupId::parse(value.strip_prefix(&format!("{ROOT_PATH}/P2pGroup/"))?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_paths_round_trip() {
        for name in ["wlan0", "wlp2s0", "p2p-wlan0-0", "wl.a@b"] {
            let name = InterfaceName::new(name).unwrap();
            let path = device_path(&name);
            assert_eq!(device_from_path(path.as_str()), Some(name));
        }
        assert_eq!(
            device_path(&InterfaceName::new("p2p-wlan0-0").unwrap()).as_str(),
            "/com/hihusky/Kestrel/Device/p2p_2dwlan0_2d0"
        );
    }

    #[test]
    fn profile_and_session_paths_round_trip() {
        let id = ProfileId::generate();
        assert_eq!(profile_from_path(profile_path(id).as_str()), Some(id));
        assert_eq!(
            session_from_path(session_path(SessionId(7)).as_str()),
            Some(SessionId(7))
        );
        assert_eq!(profile_from_path("/com/hihusky/Kestrel/Profile/nope"), None);
    }
}

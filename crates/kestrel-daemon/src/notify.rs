// SPDX-License-Identifier: LGPL-2.1-or-later

//! Minimal `sd_notify(3)` and `sd_watchdog_enabled(3)` implementation.

use std::ffi::OsStr;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

pub(crate) fn notify(state: &str) {
    let socket = std::env::var_os("NOTIFY_SOCKET");
    notify_socket(socket.as_deref(), state);
}

/// Returns the systemd watchdog timeout when `WATCHDOG_USEC` is set for this
/// process (matching `sd_watchdog_enabled(3)`), or `None` when disabled.
pub(crate) fn watchdog_interval() -> Option<Duration> {
    parse_watchdog(
        std::env::var_os("WATCHDOG_USEC").as_deref(),
        std::env::var_os("WATCHDOG_PID").as_deref(),
        std::process::id(),
    )
}

fn parse_watchdog(usec: Option<&OsStr>, pid: Option<&OsStr>, current_pid: u32) -> Option<Duration> {
    if let Some(pid) = pid {
        let parsed: u32 = pid.to_str()?.parse().ok()?;
        if parsed != current_pid {
            return None;
        }
    }
    let micros: u64 = usec?.to_str()?.parse().ok()?;
    (micros > 0).then(|| Duration::from_micros(micros))
}

fn notify_socket(socket: Option<&OsStr>, state: &str) {
    let Some(socket) = socket else {
        return;
    };
    let socket = socket.to_string_lossy().into_owned();
    if socket.starts_with('@') {
        // Abstract sockets need a Linux-specific address type; systemd
        // always offers a filesystem socket for services.
        tracing::debug!("abstract NOTIFY_SOCKET not supported");
        return;
    }
    let result =
        UnixDatagram::unbound().and_then(|datagram| datagram.send_to(state.as_bytes(), &socket));
    if let Err(error) = result {
        tracing::warn!(%error, "sd_notify failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_ignores_missing_and_abstract_sockets() {
        notify_socket(None, "READY=1");
        notify_socket(Some(OsStr::new("@abstract-kestrel")), "READY=1");
    }

    #[test]
    fn notify_sends_datagram_to_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        notify_socket(Some(path.as_os_str()), "READY=1\nSTATUS=running");

        let mut buf = [0u8; 64];
        let len = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"READY=1\nSTATUS=running");
    }

    #[test]
    fn parses_watchdog_interval_and_pid_guard() {
        assert_eq!(parse_watchdog(None, None, 42), None);
        assert_eq!(parse_watchdog(Some(OsStr::new("0")), None, 42), None);
        assert_eq!(parse_watchdog(Some(OsStr::new("bogus")), None, 42), None);
        assert_eq!(
            parse_watchdog(Some(OsStr::new("30000000")), None, 42),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parse_watchdog(Some(OsStr::new("30000000")), Some(OsStr::new("42")), 42),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parse_watchdog(Some(OsStr::new("30000000")), Some(OsStr::new("99")), 42),
            None
        );
    }
}

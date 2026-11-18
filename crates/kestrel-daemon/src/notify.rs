// SPDX-License-Identifier: LGPL-2.1-or-later

//! Minimal `sd_notify(3)`: one datagram to `$NOTIFY_SOCKET`.

use std::ffi::OsStr;
use std::os::unix::net::UnixDatagram;

pub(crate) fn notify(state: &str) {
    let socket = std::env::var_os("NOTIFY_SOCKET");
    notify_socket(socket.as_deref(), state);
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
}

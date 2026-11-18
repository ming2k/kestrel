// SPDX-License-Identifier: LGPL-2.1-or-later

//! One way for every Kestrel binary to reach a bus.

use std::time::Duration;

/// Connects to `spec`: `system`, `session`, or a D-Bus address.
///
/// `KESTREL_BUS_UID`, if set, is the UID to claim in `EXTERNAL`
/// authentication. It is only needed when the bus runs in a different user
/// namespace (a container or a test lab), where the bus sees this process
/// under another UID than `getuid()` returns.
pub async fn connect(spec: &str) -> zbus::Result<zbus::Connection> {
    let mut builder = match spec {
        "system" => zbus::connection::Builder::system(),
        "session" => zbus::connection::Builder::session(),
        address => zbus::connection::Builder::address(address),
    };
    if let Ok(uid) = std::env::var("KESTREL_BUS_UID") {
        let uid = uid
            .parse()
            .map_err(|_| zbus::Error::Failure(format!("invalid KESTREL_BUS_UID {uid:?}")))?;
        builder = builder.user_id(uid);
    }
    builder
        // Interactive polkit authentication can take a while.
        .method_timeout(Duration::from_secs(120))
        .build()
        .await
}

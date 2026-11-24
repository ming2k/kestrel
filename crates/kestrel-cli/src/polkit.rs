// SPDX-License-Identifier: LGPL-2.1-or-later

//! Client-side polkit preflight and `pkttyagent` fallback for `kestrel`.
//!
//! Before prompting the user for a Wi-Fi passphrase, WPS PIN, or delete
//! confirmation, the CLI checks authorization against `org.freedesktop.PolicyKit1`
//! on the system bus. If interactive authentication is required on a terminal
//! without a desktop polkit agent, it spawns `pkttyagent --fallback` for the
//! lifetime of the command so authentication succeeds inline instead of failing
//! with `AccessDenied` after the user has already typed a secret.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use zbus::Variant;

pub(crate) const ACTION_CONNECT: &str = "com.hihusky.kestrel.connect";
pub(crate) const ACTION_HOTSPOT: &str = "com.hihusky.kestrel.hotspot";
pub(crate) const ACTION_MODIFY_PROFILES: &str = "com.hihusky.kestrel.modify-profiles";
pub(crate) const ACTION_TOGGLE_WIRELESS: &str = "com.hihusky.kestrel.toggle-wireless";
pub(crate) const ACTION_REGISTER_AGENT: &str = "com.hihusky.kestrel.register-agent";

const POLKIT_SERVICE: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// Keeps a fallback `pkttyagent` child alive for the duration of a CLI command
/// and terminates it cleanly on drop.
#[derive(Debug, Default)]
pub(crate) struct PolkitGuard {
    agent: Option<Child>,
}

impl Drop for PolkitGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.agent.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl PolkitGuard {
    /// Ensures the current system-bus connection is authorized for every polkit
    /// action in `actions`, reusing any already-running fallback `pkttyagent`
    /// held by this guard.
    ///
    /// On non-system buses (`session` or private test buses), or when polkitd is
    /// not present on the bus, this is a no-op and authorization is left to the
    /// daemon.
    pub(crate) async fn ensure_authorized(
        &mut self,
        connection: &zbus::Connection,
        bus: &str,
        actions: &[&str],
    ) -> zbus::Result<()> {
        if bus != "system" || actions.is_empty() {
            return Ok(());
        }
        let Some(unique_name) = connection.unique_name() else {
            return Ok(());
        };
        let sender = unique_name.as_str().to_owned();
        let Ok(proxy): zbus::Result<zbus::Proxy<'_>> = zbus::proxy::Builder::new(connection)
            .destination(POLKIT_SERVICE)
            .path(POLKIT_PATH)
            .interface(POLKIT_INTERFACE)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
        else {
            return Ok(());
        };

        for &action in actions {
            let Ok((authorized, challenge)) = check(&proxy, &sender, action, 0).await else {
                // If polkitd is unavailable (e.g. bus-policy mode), let the daemon decide.
                return Ok(());
            };
            if authorized {
                continue;
            }
            if !challenge {
                return Err(access_denied(action));
            }
            if self.agent.is_none() && std::io::stdin().is_terminal() {
                self.agent = spawn_tty_agent(&sender).await;
            }
            let (interactive_ok, _) = check(&proxy, &sender, action, 1)
                .await
                .map_err(|_| access_denied(action))?;
            if !interactive_ok {
                return Err(access_denied(action));
            }
        }
        Ok(())
    }
}

async fn check(
    proxy: &zbus::Proxy<'_>,
    sender: &str,
    action: &str,
    flags: u32,
) -> zbus::Result<(bool, bool)> {
    let subject = (
        "system-bus-name",
        HashMap::from([("name", Variant::from(sender))]),
    );
    let details: HashMap<&str, &str> = HashMap::new();
    let reply = proxy
        .call_method("CheckAuthorization", &(subject, action, details, flags, ""))
        .await?;
    let (authorized, challenge, _details): (bool, bool, HashMap<String, String>) =
        reply.body().deserialize()?;
    Ok((authorized, challenge))
}

async fn spawn_tty_agent(sender: &str) -> Option<Child> {
    let binary = if Path::new("/usr/bin/pkttyagent").is_file() {
        "/usr/bin/pkttyagent"
    } else {
        "pkttyagent"
    };
    let mut child = Command::new(binary)
        .arg("--system-bus-name")
        .arg(sender)
        .arg("--fallback")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .ok()?;
    // Give `pkttyagent` a brief moment to register its agent on the system bus.
    tokio::time::sleep(Duration::from_millis(150)).await;
    if let Ok(Some(_)) = child.try_wait() {
        return None;
    }
    Some(child)
}

fn access_denied(action: &str) -> zbus::Error {
    zbus::Error::Failure(format!("AccessDenied: not authorized for {action}"))
}

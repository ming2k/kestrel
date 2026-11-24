// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel agent`: a terminal agent that serializes prompts and
//! re-registers automatically if `kestrel-daemon` restarts.

use std::io::{BufRead, IsTerminal, Write};
use std::sync::Arc;

use futures_util::StreamExt;
use kestrel_api::BUS_NAME;
use kestrel_api::client::Client;
use tokio::sync::Mutex;
use zbus::OwnedObjectPath;
use zbus::message::Type;

use crate::common::{CliError, CliResult};

const AGENT_PATH: &str = "/com/hihusky/Kestrel/cli/agent";

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "com.hihusky.Kestrel.Agent.Error")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Declined(String),
}

struct TerminalAgent {
    prompt_lock: Arc<Mutex<()>>,
}

async fn ask(prompt: String, secret: bool) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        if secret {
            rpassword::prompt_password(prompt).ok()
        } else {
            eprint!("{prompt}");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line).ok()?;
            Some(line.trim().to_owned())
        }
    })
    .await
    .ok()
    .flatten()
}

// D-Bus methods take owned arguments.
#[allow(clippy::needless_pass_by_value)]
#[zbus::interface(name = "com.hihusky.Kestrel.Agent")]
impl TerminalAgent {
    async fn request_secret(
        &self,
        device: OwnedObjectPath,
        profile: OwnedObjectPath,
        ssid: String,
        security: String,
        reason: String,
    ) -> Result<String, AgentError> {
        let _ = (device, profile);
        let _guard = self.prompt_lock.lock().await;
        eprintln!("\nNetwork {ssid:?} ({security}) needs a passphrase ({reason}).");
        match ask("Passphrase (empty to decline): ".into(), true).await {
            Some(secret) if !secret.is_empty() => Ok(secret),
            _ => Err(AgentError::Declined("declined at the terminal".into())),
        }
    }

    async fn authorize_peer(
        &self,
        device: OwnedObjectPath,
        peer: String,
        name: String,
        method: String,
    ) -> Result<(String, String), AgentError> {
        let _ = device;
        let _guard = self.prompt_lock.lock().await;
        eprintln!("\nWi-Fi Direct request from {name:?} ({peer}), method {method}.");
        if method == "pbc" {
            return match ask("Accept? [y/N] ".into(), false).await.as_deref() {
                Some("y" | "Y" | "yes") => Ok(("pbc".into(), String::new())),
                _ => Err(AgentError::Declined("rejected".into())),
            };
        }
        match ask(
            "Enter the peer's PIN, or press Enter to show one, or type n to reject: ".into(),
            false,
        )
        .await
        .as_deref()
        {
            Some("n" | "N") | None => Err(AgentError::Declined("rejected".into())),
            Some("") => Ok(("display".into(), String::new())),
            Some(pin) => Ok(("keypad".into(), pin.to_owned())),
        }
    }

    #[allow(clippy::unused_self)]
    fn display_pin(&self, session: OwnedObjectPath, peer: String, pin: String) {
        let id = session
            .as_str()
            .rsplit('/')
            .next()
            .unwrap_or(session.as_str());
        eprintln!("\nEnter PIN {pin} on {peer} (session {id}).");
    }
}

pub(crate) async fn run(client: &Client) -> CliResult<()> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::runtime("the agent needs a terminal"));
    }
    let connection = client.connection();
    let rule = zbus::MatchRule::builder()
        .msg_type(Type::Signal)
        .sender("org.freedesktop.DBus")
        .interface("org.freedesktop.DBus")
        .member("NameOwnerChanged")
        .arg(0, BUS_NAME)
        .build()?;
    let mut owner_changes = zbus::MessageStream::for_match_rule(rule, connection, None).await?;
    let (reregister_tx, mut reregister_rx) = tokio::sync::mpsc::channel(16);
    let drain = tokio::spawn(async move {
        while let Some(item) = owner_changes.next().await {
            let Ok(message) = item else {
                continue;
            };
            let Ok((name, _old, new)) = message.body().deserialize::<(String, String, String)>()
            else {
                continue;
            };
            if name == BUS_NAME && !new.is_empty() {
                match reregister_tx.try_send(()) {
                    Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => return,
                }
            }
        }
    });

    connection
        .object_server()
        .at(
            AGENT_PATH,
            TerminalAgent {
                prompt_lock: Arc::new(Mutex::new(())),
            },
        )
        .await?;
    let path = zbus::ObjectPath::try_from(AGENT_PATH)?;
    let manager = client.manager().await?;
    manager.register_agent(&path).await?;
    eprintln!("agent registered; press Ctrl-C to stop");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = reregister_rx.recv() => {
                if event.is_none() {
                    break;
                }
                match manager.register_agent(&path).await {
                    Ok(()) => eprintln!("kestrel-daemon restarted; agent re-registered"),
                    Err(error) => eprintln!("kestrel: failed to re-register agent: {error}"),
                }
            }
        }
    }
    drain.abort();
    let _ = manager.unregister_agent(&path).await;
    Ok(())
}

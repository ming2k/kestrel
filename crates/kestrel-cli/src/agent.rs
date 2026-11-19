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
            print!("{prompt}");
            let _ = std::io::stdout().flush();
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
        println!("\nNetwork {ssid:?} ({security}) needs a passphrase ({reason}).");
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
        println!("\nWi-Fi Direct request from {name:?} ({peer}), method {method}.");
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
        println!(
            "\nEnter PIN {pin} on {peer} (session {}).",
            session.as_str()
        );
    }
}

pub(crate) async fn run(client: &Client) -> zbus::Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(zbus::Error::Failure("the agent needs a terminal".into()));
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
    let (reregister_tx, mut reregister_rx) = tokio::sync::mpsc::unbounded_channel();
    let drain = tokio::spawn(async move {
        while let Some(Ok(message)) = owner_changes.next().await {
            let Ok((name, _old, new)) = message.body().deserialize::<(String, String, String)>()
            else {
                continue;
            };
            if name == BUS_NAME && !new.is_empty() && reregister_tx.send(()).is_err() {
                return;
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
    println!("agent registered; press Ctrl-C to stop");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = reregister_rx.recv() => {
                if event.is_none() {
                    break;
                }
                match manager.register_agent(&path).await {
                    Ok(()) => println!("kestrel-daemon restarted; agent re-registered"),
                    Err(error) => eprintln!("kestrel: failed to re-register agent: {error}"),
                }
            }
        }
    }
    drain.abort();
    let _ = manager.unregister_agent(&path).await;
    Ok(())
}

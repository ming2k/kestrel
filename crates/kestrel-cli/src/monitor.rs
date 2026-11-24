// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel monitor`: stream D-Bus signals as they happen.

use std::collections::HashMap;

use futures_util::StreamExt;
use kestrel_api::client::Client;
use serde_json::{Map, Value, json};
use zbus::OwnedVariant;

use crate::common::CliResult;

pub(crate) async fn run(client: &Client, json_output: bool) -> CliResult<()> {
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(kestrel_api::BUS_NAME)
        .build()?;
    let mut stream = zbus::MessageStream::for_match_rule(rule, client.connection(), None).await?;
    if !json_output {
        eprintln!("watching {} (Ctrl-C to stop)", kestrel_api::BUS_NAME);
    }
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            next = stream.next() => {
                let Some(message) = next else { return Ok(()) };
                let message = message?;
                let header = message.header();
                let path = header.path().map(ToString::to_string).unwrap_or_default();
                let member = header.member().map(ToString::to_string).unwrap_or_default();
                if member == "PropertiesChanged"
                    && let Ok((interface, changed, invalidated)) = message
                        .body()
                        .deserialize::<(String, HashMap<String, OwnedVariant>, Vec<String>)>()
                {
                    let mut keys: Vec<_> = changed.into_iter().collect();
                    keys.sort_by(|a, b| a.0.cmp(&b.0));
                    if json_output {
                        let mut props = Map::new();
                        for (key, value) in keys {
                            props.insert(key, Value::String((*value).to_string()));
                        }
                        let event = json!({
                            "path": path,
                            "signal": member,
                            "interface": interface,
                            "changed": Value::Object(props),
                            "invalidated": invalidated,
                        });
                        println!("{}", serde_json::to_string(&event).unwrap_or_default());
                    } else {
                        let short_iface = interface.rsplit('.').next().unwrap_or("");
                        for (key, value) in keys {
                            println!("{path} {short_iface}.{key} = {}", *value);
                        }
                    }
                } else if json_output {
                    let event = json!({
                        "path": path,
                        "signal": member,
                    });
                    println!("{}", serde_json::to_string(&event).unwrap_or_default());
                } else {
                    println!("{path} {member}");
                }
            }
        }
    }
}

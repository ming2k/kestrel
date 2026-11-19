// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel`: the command-line client for the Kestrel orchestrator.
//!
//! It is deliberately a thin consumer of the public D-Bus API: scanning,
//! association, profiles, secrets, and policy all live in `kestrel-daemon`.
//! Interactive input and secrets never come from argv.

mod agent;
mod cert;
mod common;
mod hotspot;
mod monitor;
mod p2p;
mod polkit;
mod profile;
mod wifi;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use kestrel_api::client::Client;

use crate::cert::Certificate;
use crate::common::failure;
use crate::hotspot::Hotspot;
use crate::p2p::{P2p, P2pGroups};
use crate::profile::Profile;
use crate::wifi::Wifi;

#[derive(Debug, Parser)]
#[command(
    name = "kestrel",
    version,
    about = "Control the Kestrel wireless orchestrator"
)]
struct Cli {
    /// `system`, `session`, or a D-Bus address.
    #[arg(long, global = true, env = "KESTREL_BUS", default_value = "system")]
    bus: String,

    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Overview of every wireless device.
    Status {
        /// Redraw once a second until interrupted.
        #[arg(long)]
        watch: bool,
    },
    /// Wireless station commands.
    #[command(subcommand)]
    Wifi(Wifi),
    /// Saved network profiles.
    #[command(subcommand)]
    Profile(Profile),
    /// Wi-Fi Direct.
    #[command(subcommand)]
    P2p(P2p),
    /// SoftAP / hotspot.
    #[command(subcommand)]
    Hotspot(Hotspot),
    /// Imported X.509 certificates for 802.1X profiles.
    #[command(subcommand)]
    Certificate(Certificate),
    /// Run an interactive agent: answers secret prompts, peer requests, and
    /// shows PINs.
    Agent,
    /// Print raw D-Bus changes as they happen.
    Monitor,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kestrel: {}", describe(error));
            ExitCode::FAILURE
        }
    }
}

/// D-Bus errors print as their stable name plus message.
fn describe(error: zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, Some(message), _) => {
            let short = name
                .as_str()
                .rsplit('.')
                .next()
                .unwrap_or(name.as_str())
                .to_owned();
            format!("{short}: {message}")
        }
        other => other.to_string(),
    }
}

fn required_polkit_actions(command: &Command) -> &'static [&'static str] {
    match command {
        Command::Status { .. }
        | Command::Monitor
        | Command::Wifi(Wifi::Status { .. } | Wifi::List { .. } | Wifi::History { .. })
        | Command::Profile(Profile::List | Profile::Show { .. })
        | Command::Certificate(Certificate::List | Certificate::Show { .. })
        | Command::P2p(
            P2p::Peers { .. }
            | P2p::Sessions
            | P2p::Groups(P2pGroups::List | P2pGroups::Show { .. }),
        )
        | Command::Hotspot(Hotspot::Status { .. }) => &[],

        Command::Wifi(
            Wifi::Scan { .. }
            | Wifi::Join(_)
            | Wifi::Connect(_)
            | Wifi::Disconnect { .. }
            | Wifi::Autoconnect { .. },
        )
        | Command::P2p(
            P2p::Find { .. }
            | P2p::Wfd { .. }
            | P2p::Connect(_)
            | P2p::StartGroup { .. }
            | P2p::Reconnect { .. }
            | P2p::Close { .. },
        ) => &[polkit::ACTION_CONNECT],

        Command::Wifi(Wifi::On | Wifi::Off) => &[polkit::ACTION_TOGGLE_WIRELESS],

        Command::Wifi(Wifi::Forget { .. })
        | Command::Profile(Profile::Add(_) | Profile::Edit { .. } | Profile::Delete { .. })
        | Command::Certificate(Certificate::Add { .. } | Certificate::Delete { .. })
        | Command::P2p(P2p::Groups(P2pGroups::Delete { .. })) => &[polkit::ACTION_MODIFY_PROFILES],

        Command::Hotspot(Hotspot::Start(_) | Hotspot::Stop { .. }) => &[polkit::ACTION_HOTSPOT],

        Command::Agent => &[polkit::ACTION_REGISTER_AGENT],
    }
}

async fn run(cli: Cli) -> zbus::Result<()> {
    let connection = kestrel_api::bus::connect(&cli.bus)
        .await
        .map_err(|e| failure(format!("cannot connect to the {} bus: {e}", cli.bus)))?;
    let client = Client::new(connection).await?;
    let _polkit_guard = polkit::ensure_authorized(
        client.connection(),
        &cli.bus,
        required_polkit_actions(&cli.command),
    )
    .await?;
    let json = cli.json;
    match cli.command {
        Command::Status { watch } => wifi::status(&client, json, watch).await,
        Command::Wifi(command) => wifi::run(&client, &cli.bus, command, json).await,
        Command::Profile(command) => profile::run(&client, command, json).await,
        Command::P2p(command) => p2p::run(&client, command, json).await,
        Command::Hotspot(command) => hotspot::run(&client, command, json).await,
        Command::Certificate(command) => cert::run(&client, command, json).await,
        Command::Agent => agent::run(&client).await,
        Command::Monitor => monitor::run(&client, json).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_subcommands_and_global_flags() {
        let cli = Cli::try_parse_from([
            "kestrel",
            "--bus",
            "session",
            "--json",
            "wifi",
            "join",
            "wlan0",
            "my-ssid",
            "--secret-stdin",
            "--timeout",
            "15",
        ])
        .unwrap();
        assert_eq!(cli.bus, "session");
        assert!(cli.json);
        match cli.command {
            Command::Wifi(Wifi::Join(args)) => {
                assert_eq!(args.device, "wlan0");
                assert_eq!(args.ssid, "my-ssid");
                assert!(args.secret_stdin);
                assert_eq!(args.timeout, 15);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_p2p_and_profile_subcommands() {
        let cli = Cli::try_parse_from([
            "kestrel",
            "p2p",
            "connect",
            "wlan0",
            "02:00:00:00:aa:42",
            "--pin-stdin",
            "--go-intent",
            "5",
            "--wait",
            "--timeout",
            "45",
        ])
        .unwrap();
        match cli.command {
            Command::P2p(P2p::Connect(args)) => {
                assert_eq!(args.device, "wlan0");
                assert_eq!(args.peer, "02:00:00:00:aa:42");
                assert!(!args.keypad);
                assert!(args.pin_stdin);
                assert!(!args.display);
                assert_eq!(args.go_intent, Some(5));
                assert!(!args.persistent);
                assert!(args.wait);
                assert_eq!(args.timeout, 45);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // Legacy argv `--pin <PIN>` is deliberately rejected to avoid process-table secret leaks.
        assert!(
            Cli::try_parse_from([
                "kestrel",
                "p2p",
                "connect",
                "wlan0",
                "02:00:00:00:aa:42",
                "--pin",
                "12345678",
            ])
            .is_err()
        );

        let wfd =
            Cli::try_parse_from(["kestrel", "p2p", "wfd", "wlan0", "000600111c440032"]).unwrap();
        assert!(matches!(wfd.command, Command::P2p(P2p::Wfd { .. })));

        let profile_cli = Cli::try_parse_from([
            "kestrel",
            "profile",
            "add",
            "--ssid",
            "corp",
            "--security",
            "wpa-personal",
            "--priority",
            "10",
            "--autoconnect",
            "false",
        ])
        .unwrap();
        assert!(matches!(
            profile_cli.command,
            Command::Profile(Profile::Add(_))
        ));
    }

    #[test]
    fn parses_enterprise_list_clearing_and_hotspot_subcommands() {
        let cli = Cli::try_parse_from([
            "kestrel",
            "profile",
            "add",
            "--ssid",
            "corp",
            "--security",
            "wpa3-enterprise",
            "--eap",
            "tls",
            "--identity",
            "alice@corp.example",
            "--ca-cert",
            "Corp CA",
            "--system-ca",
            "false",
            "--client-cert",
            "Alice",
            "--domain-suffix-match",
            "corp.example",
            "--altsubject-match",
            "DNS:radius.corp.example",
            "--private-key-file",
            "/etc/kestrel/alice.key",
        ])
        .unwrap();
        match cli.command {
            Command::Profile(Profile::Add(args)) => {
                assert_eq!(args.eap.as_deref(), Some("tls"));
                assert_eq!(args.ca_cert.as_deref(), Some("Corp CA"));
                assert_eq!(args.system_ca, Some(false));
                assert_eq!(args.client_cert.as_deref(), Some("Alice"));
                assert_eq!(args.altsubject_match, ["DNS:radius.corp.example"]);
                assert_eq!(
                    args.private_key_file.as_deref(),
                    Some("/etc/kestrel/alice.key")
                );
                let map = profile::settings_from_args(&args);
                assert_eq!(
                    common::setting_bool(&map, "enterprise.system_ca"),
                    Some(false)
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let edit = Cli::try_parse_from([
            "kestrel",
            "profile",
            "edit",
            "corp",
            "--clear-dns",
            "--clear-domains",
            "--clear-altsubject-match",
        ])
        .unwrap();
        match edit.command {
            Command::Profile(Profile::Edit { args, .. }) => {
                let map = profile::settings_from_args(&args);
                assert!(map.contains_key("dns"));
                assert!(map.contains_key("domains"));
                assert!(map.contains_key("enterprise.altsubject_match"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_hotspot_and_p2p_reconnect_subcommands() {
        let hotspot = Cli::try_parse_from([
            "kestrel",
            "hotspot",
            "start",
            "wlan0",
            "--ssid",
            "lab-ap",
            "--security",
            "open",
            "--frequency",
            "2437",
            "--hidden",
        ])
        .unwrap();
        match hotspot.command {
            Command::Hotspot(Hotspot::Start(args)) => {
                assert_eq!(args.device, "wlan0");
                assert_eq!(args.ssid, "lab-ap");
                assert_eq!(args.security, "open");
                assert_eq!(args.frequency, Some(2437));
                assert!(args.hidden);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let reconnect = Cli::try_parse_from([
            "kestrel",
            "p2p",
            "reconnect",
            "wlan0",
            "group-id",
            "--peer",
            "02:11:22:33:44:55",
        ])
        .unwrap();
        match reconnect.command {
            Command::P2p(P2p::Reconnect {
                device,
                group,
                peer,
                frequency,
                wait,
                timeout,
            }) => {
                assert_eq!(device, "wlan0");
                assert_eq!(group, "group-id");
                assert_eq!(peer.as_deref(), Some("02:11:22:33:44:55"));
                assert_eq!(frequency, None);
                assert!(!wait);
                assert_eq!(timeout, 60);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn session_ref_and_wfd_parsing_validate_inputs() {
        let numeric = p2p::session_ref("42").unwrap();
        assert_eq!(numeric.as_str(), "/com/hihusky/Kestrel/Session/42");

        let full = p2p::session_ref("/com/hihusky/Kestrel/Session/7").unwrap();
        assert_eq!(full.as_str(), "/com/hihusky/Kestrel/Session/7");

        assert!(p2p::session_ref("").is_err());
        assert!(p2p::session_ref("not-a-valid-path").is_err());

        assert_eq!(p2p::parse_wfd_arg("clear").unwrap(), Vec::<u8>::new());
        assert_eq!(
            p2p::parse_wfd_arg("00:06:00:11").unwrap(),
            vec![0x00, 0x06, 0x00, 0x11]
        );
        assert!(p2p::parse_wfd_arg("001").is_err());
        assert!(p2p::parse_wfd_arg("zz").is_err());
    }

    #[test]
    fn bounded_reader_enforces_byte_limit() {
        let ok = common::read_bounded_reader(&b"hello"[..], 5, "test").unwrap();
        assert_eq!(ok, "hello");
        assert!(common::read_bounded_reader(&b"hello!"[..], 5, "test").is_err());
    }

    #[test]
    fn required_polkit_actions_cover_reads_and_mutations() {
        let read = Cli::try_parse_from(["kestrel", "wifi", "status", "wlan0"]).unwrap();
        assert_eq!(required_polkit_actions(&read.command), &[] as &[&str]);

        let join = Cli::try_parse_from(["kestrel", "wifi", "join", "wlan0", "home"]).unwrap();
        assert_eq!(
            required_polkit_actions(&join.command),
            &[polkit::ACTION_CONNECT]
        );

        let forget = Cli::try_parse_from(["kestrel", "wifi", "forget", "home"]).unwrap();
        assert_eq!(
            required_polkit_actions(&forget.command),
            &[polkit::ACTION_MODIFY_PROFILES]
        );

        let hotspot =
            Cli::try_parse_from(["kestrel", "hotspot", "start", "wlan0", "--ssid", "ap"]).unwrap();
        assert_eq!(
            required_polkit_actions(&hotspot.command),
            &[polkit::ACTION_HOTSPOT]
        );

        let toggle = Cli::try_parse_from(["kestrel", "wifi", "off"]).unwrap();
        assert_eq!(
            required_polkit_actions(&toggle.command),
            &[polkit::ACTION_TOGGLE_WIRELESS]
        );
    }
}

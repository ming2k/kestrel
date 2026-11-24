// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel`: the command-line client for the Kestrel wireless orchestrator.
//!
//! It is deliberately a thin, task-oriented consumer of the public D-Bus API:
//! scanning, association, profiles, secrets, and policy all live in
//! `kestrel-daemon`. Secrets and PINs are never accepted via `argv`.

mod agent;
mod cert;
mod common;
mod hotspot;
mod monitor;
mod p2p;
mod polkit;
mod profile;
mod status;
mod wifi;

use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use kestrel_api::client::Client;

use crate::cert::Certificate;
use crate::common::{CliError, CliResult, OnOff};
use crate::hotspot::Hotspot;
use crate::p2p::{P2p, P2pGroup, P2pPeer, P2pSession};
use crate::profile::Profile;
use crate::wifi::Wifi;

#[derive(Debug, Parser)]
#[command(
    name = "kestrel",
    version,
    about = "Control the Kestrel wireless orchestrator"
)]
struct Cli {
    /// Target D-Bus (`system`, `session`, or a D-Bus address).
    #[arg(long, global = true, env = "KESTREL_BUS", default_value = "system")]
    bus: String,

    /// Emit machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Show wireless overview or detailed status of one device.
    Status {
        /// Optional wireless interface name for detailed single-device status.
        device: Option<String>,
        /// Redraw once a second until interrupted.
        #[arg(short = 'w', long, conflicts_with = "json")]
        watch: bool,
    },
    /// Show or toggle the global wireless radio switch.
    Radio {
        /// Omit to query the current radio and rfkill state.
        #[arg(value_enum)]
        state: Option<OnOff>,
    },
    /// Wi-Fi station commands (scan, connect, disconnect, autoconnect, history).
    #[command(subcommand)]
    Wifi(Wifi),
    /// Manage saved network profiles.
    #[command(subcommand)]
    Profile(Profile),
    /// Manage imported X.509 certificates for 802.1X profiles.
    #[command(subcommand, alias = "cert")]
    Certificate(Certificate),
    /// Manage SoftAP / hotspot mode.
    #[command(subcommand)]
    Hotspot(Hotspot),
    /// Manage Wi-Fi Direct (P2P) peers, sessions, WFD, and persistent groups.
    #[command(subcommand)]
    P2p(P2p),
    /// Run an interactive terminal agent (secret prompts, P2P approvals, PIN display).
    Agent,
    /// Stream D-Bus signals from `kestrel-daemon` as they happen.
    Monitor,
    /// Generate shell completion scripts.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !matches!(error, CliError::Interrupted) {
                eprintln!("kestrel: {error}");
            }
            error.exit_code()
        }
    }
}

fn required_polkit_actions(command: &Command) -> &'static [&'static str] {
    match command {
        Command::Status { .. }
        | Command::Radio { state: None }
        | Command::Monitor
        | Command::Completions { .. }
        | Command::Wifi(
            Wifi::Scan { cached: true, .. }
            | Wifi::Autoconnect { state: None, .. }
            | Wifi::History { .. },
        )
        | Command::Profile(Profile::List | Profile::Show { .. })
        | Command::Certificate(Certificate::List | Certificate::Show { .. })
        | Command::Hotspot(Hotspot::Status { .. })
        | Command::P2p(
            P2p::Peer(P2pPeer::List { .. })
            | P2p::Session(P2pSession::List | P2pSession::Show { .. })
            | P2p::Group(P2pGroup::List | P2pGroup::Show { .. }),
        ) => &[],

        Command::Radio { state: Some(_) } => &[polkit::ACTION_TOGGLE_WIRELESS],

        Command::Wifi(
            Wifi::Scan { cached: false, .. }
            | Wifi::Connect(_)
            | Wifi::Disconnect { .. }
            | Wifi::Autoconnect { state: Some(_), .. },
        )
        | Command::P2p(
            P2p::Peer(P2pPeer::Find { .. })
            | P2p::Wfd(_)
            | P2p::Connect(_)
            | P2p::StartGroup(_)
            | P2p::Reconnect(_)
            | P2p::Session(P2pSession::Close { .. }),
        ) => &[polkit::ACTION_CONNECT],

        Command::Profile(Profile::Add(_) | Profile::Edit(_) | Profile::Delete { .. })
        | Command::Certificate(Certificate::Add { .. } | Certificate::Delete { .. })
        | Command::P2p(P2p::Group(P2pGroup::Delete { .. })) => &[polkit::ACTION_MODIFY_PROFILES],

        Command::Hotspot(Hotspot::Start(_) | Hotspot::Stop { .. }) => &[polkit::ACTION_HOTSPOT],

        Command::Agent => &[polkit::ACTION_REGISTER_AGENT],
    }
}

async fn run(cli: Cli) -> CliResult<()> {
    if let Command::Completions { shell } = cli.command {
        use std::io::Write as _;

        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        clap_complete::generate(shell, &mut cmd, "kestrel", &mut buf);
        if let Err(error) = std::io::stdout().write_all(&buf)
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(CliError::runtime(format!(
                "cannot write completions: {error}"
            )));
        }
        return Ok(());
    }

    if cli.json && matches!(cli.command, Command::Status { watch: true, .. }) {
        return Err(CliError::runtime("--watch cannot be combined with --json"));
    }

    let connection = kestrel_api::bus::connect(&cli.bus)
        .await
        .map_err(|e| CliError::runtime(format!("cannot connect to the {} bus: {e}", cli.bus)))?;
    let client = Client::new(connection).await?;
    let mut polkit_guard = polkit::PolkitGuard::default();
    polkit_guard
        .ensure_authorized(
            client.connection(),
            &cli.bus,
            required_polkit_actions(&cli.command),
        )
        .await?;
    let json = cli.json;
    match cli.command {
        Command::Status { device, watch } => {
            status::status(&client, device.as_deref(), json, watch).await
        }
        Command::Radio { state } => status::radio(&client, state, json).await,
        Command::Wifi(command) => {
            wifi::run(&client, &cli.bus, &mut polkit_guard, command, json).await
        }
        Command::Profile(command) => profile::run(&client, command, json).await,
        Command::Certificate(command) => cert::run(&client, command, json).await,
        Command::Hotspot(command) => hotspot::run(&client, command, json).await,
        Command::P2p(command) => p2p::run(&client, command, json).await,
        Command::Agent => agent::run(&client).await,
        Command::Monitor => monitor::run(&client, json).await,
        Command::Completions { .. } => unreachable!("handled before bus connect"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hotspot::HotspotSecurityMode;
    use crate::p2p::{P2pWfd, WpsMethod};
    use crate::profile::{EapMode, SecurityMode};

    #[test]
    fn parses_wifi_connect_without_device_and_with_device() {
        let implicit = Cli::try_parse_from([
            "kestrel",
            "--bus",
            "session",
            "--json",
            "wifi",
            "connect",
            "my-ssid",
            "--secret-stdin",
            "-t",
            "15",
        ])
        .unwrap();
        assert_eq!(implicit.bus, "session");
        assert!(implicit.json);
        match implicit.command {
            Command::Wifi(Wifi::Connect(args)) => {
                assert_eq!(args.target, "my-ssid");
                assert_eq!(args.device.device, None);
                assert!(args.secret_stdin);
                assert!(!args.no_wait);
                assert_eq!(args.timeout, 15);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let explicit = Cli::try_parse_from([
            "kestrel",
            "wifi",
            "connect",
            "home",
            "-d",
            "wlan1",
            "--no-wait",
        ])
        .unwrap();
        match explicit.command {
            Command::Wifi(Wifi::Connect(args)) => {
                assert_eq!(args.target, "home");
                assert_eq!(args.device.device.as_deref(), Some("wlan1"));
                assert!(args.no_wait);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // Legacy `wifi join` and `wifi forget` are deliberately removed.
        assert!(Cli::try_parse_from(["kestrel", "wifi", "join", "wlan0", "home"]).is_err());
        assert!(Cli::try_parse_from(["kestrel", "wifi", "forget", "home"]).is_err());
    }

    #[test]
    fn parses_status_watch_and_radio_commands() {
        let overview = Cli::try_parse_from(["kestrel", "status", "-w"]).unwrap();
        assert!(matches!(
            overview.command,
            Command::Status {
                device: None,
                watch: true
            }
        ));

        let single = Cli::try_parse_from(["kestrel", "status", "wlan0", "--watch"]).unwrap();
        assert!(matches!(
            single.command,
            Command::Status {
                device: Some(ref d),
                watch: true
            } if d == "wlan0"
        ));

        // `--watch` conflicts with `--json` when passed on the subcommand.
        assert!(Cli::try_parse_from(["kestrel", "status", "--json", "--watch"]).is_err());

        let radio_query = Cli::try_parse_from(["kestrel", "radio"]).unwrap();
        assert!(matches!(
            radio_query.command,
            Command::Radio { state: None }
        ));
        let radio_off = Cli::try_parse_from(["kestrel", "radio", "off"]).unwrap();
        assert!(matches!(
            radio_off.command,
            Command::Radio {
                state: Some(OnOff::Off)
            }
        ));
    }

    #[test]
    fn parses_p2p_subcommands_and_rejects_argv_pin() {
        let cli = Cli::try_parse_from([
            "kestrel",
            "p2p",
            "connect",
            "02:00:00:00:aa:42",
            "-d",
            "wlan0",
            "--pin-stdin",
            "--go-intent",
            "5",
            "-t",
            "45",
        ])
        .unwrap();
        match cli.command {
            Command::P2p(P2p::Connect(args)) => {
                assert_eq!(args.device.device.as_deref(), Some("wlan0"));
                assert_eq!(args.peer, "02:00:00:00:aa:42");
                assert_eq!(args.wps, None);
                assert!(args.pin_stdin);
                assert_eq!(args.go_intent, Some(5));
                assert!(!args.persistent);
                assert!(!args.no_wait);
                assert_eq!(args.timeout, 45);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let display = Cli::try_parse_from([
            "kestrel",
            "p2p",
            "connect",
            "02:00:00:00:aa:42",
            "--wps",
            "display",
            "--no-wait",
        ])
        .unwrap();
        match display.command {
            Command::P2p(P2p::Connect(args)) => {
                assert_eq!(args.wps, Some(WpsMethod::Display));
                assert!(args.no_wait);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // Legacy argv `--pin <PIN>` and out-of-range `--go-intent` are rejected.
        assert!(
            Cli::try_parse_from([
                "kestrel",
                "p2p",
                "connect",
                "02:00:00:00:aa:42",
                "--pin",
                "1234"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "kestrel",
                "p2p",
                "connect",
                "02:00:00:00:aa:42",
                "--go-intent",
                "16",
            ])
            .is_err()
        );

        let wfd_set =
            Cli::try_parse_from(["kestrel", "p2p", "wfd", "set", "000600111c440032"]).unwrap();
        assert!(matches!(
            wfd_set.command,
            Command::P2p(P2p::Wfd(P2pWfd::Set { .. }))
        ));
        let wfd_clear = Cli::try_parse_from(["kestrel", "p2p", "wfd", "clear"]).unwrap();
        assert!(matches!(
            wfd_clear.command,
            Command::P2p(P2p::Wfd(P2pWfd::Clear { .. }))
        ));

        let session_close =
            Cli::try_parse_from(["kestrel", "p2p", "session", "close", "1"]).unwrap();
        assert!(matches!(
            session_close.command,
            Command::P2p(P2p::Session(P2pSession::Close { .. }))
        ));

        let group_list = Cli::try_parse_from(["kestrel", "p2p", "group", "list"]).unwrap();
        assert!(matches!(
            group_list.command,
            Command::P2p(P2p::Group(P2pGroup::List))
        ));
    }

    #[test]
    fn parses_profile_add_and_edit_with_clear_flags() {
        // Missing required positional `<SSID>` or `--security` fails at parse time.
        assert!(Cli::try_parse_from(["kestrel", "profile", "add", "corp"]).is_err());

        let cli = Cli::try_parse_from([
            "kestrel",
            "profile",
            "add",
            "corp",
            "--security",
            "wpa3-enterprise",
            "--eap",
            "tls",
            "--identity",
            "alice@corp.example",
            "--ca-cert",
            "Corp CA",
            "--client-cert",
            "Alice",
            "--domain-suffix-match",
            "corp.example",
            "--altsubject-match",
            "DNS:radius.corp.example",
            "--private-key-file",
            "/etc/kestrel/alice.key",
            "--no-autoconnect",
        ])
        .unwrap();
        match cli.command {
            Command::Profile(Profile::Add(args)) => {
                assert_eq!(args.ssid, "corp");
                assert_eq!(args.security, SecurityMode::Wpa3Enterprise);
                assert_eq!(args.eap, Some(EapMode::Tls));
                assert_eq!(args.ca_cert.as_deref(), Some("Corp CA"));
                assert!(!args.system_ca);
                assert!(args.no_autoconnect);
                let map = profile::settings_from_add_args(&args);
                assert_eq!(common::setting_bool(&map, "autoconnect"), Some(false));
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let edit = Cli::try_parse_from([
            "kestrel",
            "profile",
            "edit",
            "corp",
            "--clear-bssid",
            "--clear-gateway4",
            "--clear-dns",
            "--clear-domains",
            "--clear-ca-cert",
            "--clear-altsubject-match",
            "--system-ca",
            "false",
        ])
        .unwrap();
        match edit.command {
            Command::Profile(Profile::Edit(args)) => {
                let map = profile::settings_from_edit_args(&args);
                assert_eq!(common::setting_string(&map, "bssid"), "");
                assert_eq!(common::setting_string(&map, "gateway4"), "");
                assert!(map.contains_key("dns"));
                assert!(map.contains_key("domains"));
                assert_eq!(common::setting_string(&map, "enterprise.ca_cert"), "");
                assert!(map.contains_key("enterprise.altsubject_match"));
                assert_eq!(
                    common::setting_bool(&map, "enterprise.system_ca"),
                    Some(false)
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_hotspot_cert_alias_and_completions() {
        let hotspot = Cli::try_parse_from([
            "kestrel",
            "hotspot",
            "start",
            "lab-ap",
            "-d",
            "wlan0",
            "--security",
            "open",
            "-f",
            "2437",
            "--hidden",
            "--no-wait",
        ])
        .unwrap();
        match hotspot.command {
            Command::Hotspot(Hotspot::Start(args)) => {
                assert_eq!(args.ssid, "lab-ap");
                assert_eq!(args.device.device.as_deref(), Some("wlan0"));
                assert_eq!(args.security, HotspotSecurityMode::Open);
                assert_eq!(args.frequency, Some(2437));
                assert!(args.hidden);
                assert!(args.no_wait);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cert_alias = Cli::try_parse_from(["kestrel", "cert", "add", "./corp-ca.pem"]).unwrap();
        assert!(matches!(
            cert_alias.command,
            Command::Certificate(Certificate::Add { name: None, .. })
        ));
        assert_eq!(
            cert::derive_cert_name("./corp-ca.pem", None).unwrap(),
            "corp-ca"
        );
        assert!(cert::derive_cert_name("-", None).is_err());
        assert_eq!(
            cert::derive_cert_name("-", Some("Stdin CA")).unwrap(),
            "Stdin CA"
        );

        let completions = Cli::try_parse_from(["kestrel", "completions", "fish"]).unwrap();
        assert!(matches!(
            completions.command,
            Command::Completions { shell: Shell::Fish }
        ));
    }

    #[test]
    fn session_ref_and_wfd_parsing_validate_inputs() {
        let numeric = p2p::session_ref("42").unwrap();
        assert_eq!(numeric.as_str(), "/com/hihusky/Kestrel/Session/42");
        assert_eq!(p2p::session_id_from_path(numeric.as_str()), "42");

        let full = p2p::session_ref("/com/hihusky/Kestrel/Session/7").unwrap();
        assert_eq!(full.as_str(), "/com/hihusky/Kestrel/Session/7");

        assert!(p2p::session_ref("").is_err());
        assert!(p2p::session_ref("not-a-valid-path").is_err());

        assert_eq!(
            p2p::parse_wfd_hex("00:06:00:11").unwrap(),
            vec![0x00, 0x06, 0x00, 0x11]
        );
        assert!(p2p::parse_wfd_hex("clear").is_err());
        assert!(p2p::parse_wfd_hex("001").is_err());
        assert!(p2p::parse_wfd_hex("zz").is_err());
    }

    #[test]
    fn bounded_reader_and_exit_codes_behave_as_specified() {
        let ok = common::read_bounded_reader(&b"hello"[..], 5, "test").unwrap();
        assert_eq!(ok, "hello");
        assert!(common::read_bounded_reader(&b"hello!"[..], 5, "test").is_err());

        assert_eq!(CliError::runtime("boom").exit_code(), ExitCode::from(1));
        assert_eq!(CliError::timeout("slow").exit_code(), ExitCode::from(124));
        assert_eq!(CliError::Interrupted.exit_code(), ExitCode::from(130));
    }

    #[test]
    fn required_polkit_actions_cover_reads_and_mutations() {
        let read_cases: &[&[&str]] = &[
            &["kestrel", "status", "wlan0"],
            &["kestrel", "radio"],
            &["kestrel", "wifi", "scan", "--cached"],
            &["kestrel", "wifi", "autoconnect"],
            &["kestrel", "wifi", "history"],
            &["kestrel", "p2p", "peer", "list"],
            &["kestrel", "p2p", "session", "list"],
            &["kestrel", "p2p", "session", "show", "1"],
            &["kestrel", "p2p", "group", "list"],
            &["kestrel", "hotspot", "status"],
        ];
        for argv in read_cases {
            let cli = Cli::try_parse_from(*argv).unwrap();
            assert_eq!(
                required_polkit_actions(&cli.command),
                &[] as &[&str],
                "{argv:?}"
            );
        }

        let connect = Cli::try_parse_from(["kestrel", "wifi", "connect", "home"]).unwrap();
        assert_eq!(
            required_polkit_actions(&connect.command),
            &[polkit::ACTION_CONNECT]
        );

        let delete = Cli::try_parse_from(["kestrel", "profile", "delete", "home"]).unwrap();
        assert_eq!(
            required_polkit_actions(&delete.command),
            &[polkit::ACTION_MODIFY_PROFILES]
        );

        let hotspot = Cli::try_parse_from(["kestrel", "hotspot", "start", "ap"]).unwrap();
        assert_eq!(
            required_polkit_actions(&hotspot.command),
            &[polkit::ACTION_HOTSPOT]
        );

        let radio_off = Cli::try_parse_from(["kestrel", "radio", "off"]).unwrap();
        assert_eq!(
            required_polkit_actions(&radio_off.command),
            &[polkit::ACTION_TOGGLE_WIRELESS]
        );
    }
}

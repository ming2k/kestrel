// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel-daemon`: the Kestrel orchestrator daemon.

mod compose;
mod no_l3;
mod notify;
mod power;
mod settings;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Kestrel: a control-plane orchestrator for Linux wireless networking.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Settings file.
    #[arg(
        long,
        env = "KESTREL_CONFIG",
        default_value = "/etc/kestrel/kestrel.toml"
    )]
    config: PathBuf,

    /// Bus for the API and every backend: `system`, `session`, or a D-Bus
    /// address.
    #[arg(long, env = "KESTREL_BUS", default_value = "system")]
    bus: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Logs go to stderr. Under systemd (JOURNAL_STREAM is set) the journal
    // adds its own timestamps, and colour codes would end up in it verbatim.
    let journal = std::env::var_os("JOURNAL_STREAM").is_some();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("KESTREL_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_ansi(!journal && std::io::stderr().is_terminal());
    if journal {
        builder.without_time().init();
    } else {
        builder.init();
    }
    let args = Args::parse();
    match compose::run(&args.config, &args.bus).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}

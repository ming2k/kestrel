// SPDX-License-Identifier: LGPL-2.1-or-later

//! A small, durable connection history. It is deliberately separate from
//! profiles: profiles hold configuration, history records what happened.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ProfileId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionOutcome {
    Connected,
    Disconnected,
    Failed,
}

impl ConnectionOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for ConnectionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One event in the connection history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionEvent {
    /// Seconds since the Unix epoch.
    pub at: u64,
    pub device: String,
    pub ssid: String,
    #[serde(default)]
    pub profile: Option<ProfileId>,
    pub outcome: ConnectionOutcome,
    /// Stable failure code or a short diagnostic, when relevant.
    #[serde(default)]
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_round_trip() {
        for outcome in [
            ConnectionOutcome::Connected,
            ConnectionOutcome::Disconnected,
            ConnectionOutcome::Failed,
        ] {
            let text = serde_json::to_string(&outcome).unwrap();
            assert_eq!(
                serde_json::from_str::<ConnectionOutcome>(&text).unwrap(),
                outcome
            );
        }
    }
}

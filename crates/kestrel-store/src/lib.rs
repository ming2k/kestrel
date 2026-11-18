// SPDX-License-Identifier: LGPL-2.1-or-later

//! Kestrel's own persistence.
//!
//! - [`ProfileDirectory`]: one TOML file per saved network, written
//!   atomically with mode 0600. Profiles never contain secrets.
//! - [`CertDirectory`]: imported public X.509 PEM certificates.
//! - [`P2pGroupDirectory`]: saved persistent Wi-Fi Direct groups.
//! - [`HistoryFile`]: a bounded JSON Lines connection history.
//! - [`StateFile`]: persistent radio enable state.
//! - [`SystemdCredsStore`]: secrets encrypted at rest with `systemd-creds`
//!   (TPM2 and/or host key, or the per-user key). Each credential is
//!   cryptographically bound to its profile or P2P group id, so swapping two
//!   encrypted files decrypts neither.

mod atomic;
mod certs;
mod creds;
mod history;
mod p2p_groups;
mod profiles;
mod state;
mod toml_dir;

pub use certs::CertDirectory;
pub use creds::{CredsScope, SystemdCredsStore};
pub use history::HistoryFile;
pub use p2p_groups::P2pGroupDirectory;
pub use profiles::ProfileDirectory;
pub use state::StateFile;

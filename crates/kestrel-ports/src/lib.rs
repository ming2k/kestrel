// SPDX-License-Identifier: LGPL-2.1-or-later

//! Southbound and interactive user-facing ports.
//!
//! `kestrel-controller` and `kestrel-catalog` depend only on these traits.
//! Each backend daemon (`wpa_supplicant`, iwd, systemd-networkd, a credential
//! store) is an adapter crate that implements one of them. Backends are
//! stateless executors: Kestrel owns the configuration, and every resource an
//! adapter creates is tagged as Kestrel's so `sweep` can remove leftovers after
//! a crash.
//!
//! Commands return once the backend has **accepted** a request. Outcomes
//! (association, scan results, GO negotiation, L3 readiness) arrive as
//! events, so a slow backend never blocks the caller.

pub mod agent;
pub mod ap;
mod error;
mod events;
pub mod l3;
pub mod p2p;
pub mod store;
pub mod wlan;

pub use error::{PortError, PortResult};
pub use events::{EventBus, Subscription};

// SPDX-License-Identifier: LGPL-2.1-or-later

//! Kestrel's sans-IO state machines.
//!
//! Every machine is a plain struct implementing `handle(now, input) -> Vec<Command>`.
//! It consumes an input (a user intent, a provider event, a command failure, or
//! a timer expiry) and returns the commands the controller must run. Nothing
//! here awaits, sleeps, or touches the OS:
//!
//! - **Time is an input.** Timers are commands (`StartTimer`), and expiries
//!   come back as inputs carrying a [`TimerToken`]. Stale expiries are
//!   ignored, so drivers never have to cancel a timer.
//! - **Rollback is data.** Each machine keeps an ordered list of the external
//!   resources it holds. Every exit path releases them in reverse order. When
//!   a machine is idle or closed, that list is empty, and the tests assert it.
//!
//! The async driver lives in `kestrel-controller`.

pub mod hotspot;
pub mod p2p;
pub mod station;
mod timer;

pub use timer::TimerToken;

// SPDX-License-Identifier: LGPL-2.1-or-later

//! Live radio controller driving `kestrel-machines` against `kestrel-ports`
//! and [`kestrel_catalog::Catalog`].
//!
//! One coordinator task owns all live state machines without awaiting I/O. It
//! routes southbound provider events, catalog mutations, and northbound
//! requests into the machines. Each device and each P2P session runs its
//! commands strictly in submission order via a generic per-entity `Executor`,
//! so a slow backend never stalls other devices and teardown commands are never
//! reordered.
//!
//! On start, the controller sweeps every backend for resources left behind by a
//! previous process. On shutdown, it releases everything it holds and sweeps
//! again.

mod config;
mod control;
mod error;
mod executor;
mod hotspot;
mod l3;
mod p2p;
mod radio;
mod snapshot;
mod station;
mod subnet;

pub use config::{ControllerConfig, HotspotConfig, SessionConfig, StationConfig};
pub use control::{ControllerHandle, HotspotControl, P2pControl, RadioControl, StationControl};
pub use error::ControllerError;
pub use kestrel_machines::station::StationState;
pub use kestrel_model::SessionId;
pub use radio::{Controller, ControllerPorts};
pub use snapshot::{
    ControllerEvent, DeviceSnapshot, HotspotStatusSnapshot, ScanEntry, SessionSnapshot,
};

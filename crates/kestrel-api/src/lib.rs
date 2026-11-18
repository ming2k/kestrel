// SPDX-License-Identifier: LGPL-2.1-or-later

//! Kestrel's northbound D-Bus API.
//!
//! - Bus name: `com.hihusky.Kestrel`
//! - Root object: `/com/hihusky/Kestrel`, implementing
//!   `org.freedesktop.DBus.ObjectManager` and `com.hihusky.Kestrel.Manager`.
//! - `.../Device/<name>`: `com.hihusky.Kestrel.Device` (plus
//!   `com.hihusky.Kestrel.P2P` on capable devices).
//! - `.../Profile/<id>`: `com.hihusky.Kestrel.Profile`.
//! - `.../Session/<n>`: `com.hihusky.Kestrel.Session`, one per Wi-Fi Direct
//!   connection.
//!
//! Consumers watch the `ObjectManager` and `PropertiesChanged` instead of
//! polling. Interactive input (secrets, peer authorization, PINs) goes
//! through an agent object that one consumer registers. Every mutating call
//! is authorized through polkit. Errors are named
//! `com.hihusky.Kestrel.Error.*`, and consumers branch on the name, never
//! on the message. See `docs/dbus-api.md`.

#[cfg(feature = "server")]
mod auth;
pub mod bus;
#[cfg(feature = "client")]
pub mod client;
mod convert;
mod error;
mod paths;
#[cfg(feature = "server")]
mod server;

#[cfg(feature = "server")]
pub use auth::{Action, AllowAll, Authorizer, Polkit};
pub use convert::{
    HotspotSettings, ProfileSettings, SecretBundle, hotspot_from_settings, profile_from_settings,
    secrets_from_bundle, settings_from_profile,
};
pub use error::ApiError;
pub use paths::{
    cert_from_path, cert_path, device_from_path, device_path, p2p_group_from_path, p2p_group_path,
    profile_from_path, profile_path, session_from_path, session_path,
};
#[cfg(feature = "server")]
pub use server::Server;

pub const BUS_NAME: &str = "com.hihusky.Kestrel";
pub const ROOT_PATH: &str = "/com/hihusky/Kestrel";
pub const API_VERSION: &str = "1";

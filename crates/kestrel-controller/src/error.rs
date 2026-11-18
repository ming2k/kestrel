// SPDX-License-Identifier: LGPL-2.1-or-later

//! Errors returned by live controller operations.

use kestrel_catalog::CatalogError;
use kestrel_model::SessionId;
use kestrel_ports::PortError;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ControllerError {
    #[error("no such device {0}")]
    NoSuchDevice(String),
    #[error("no such session {0}")]
    NoSuchSession(SessionId),
    #[error("wireless is disabled")]
    WirelessDisabled,
    #[error("not supported: {0}")]
    NotSupported(String),
    #[error("busy: {0}")]
    Busy(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error("backend: {0}")]
    Backend(PortError),
    #[error("the controller has stopped")]
    Stopped,
}

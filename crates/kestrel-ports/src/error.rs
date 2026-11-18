// SPDX-License-Identifier: LGPL-2.1-or-later

use kestrel_model::FailureReason;
use thiserror::Error;

/// A classified backend error. Callers decide on the variant; the message
/// is for diagnostics only.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PortError {
    #[error("{0} not found")]
    NotFound(String),

    #[error("not supported: {0}")]
    NotSupported(String),

    #[error("busy: {0}")]
    Busy(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("timed out: {0}")]
    Timeout(String),

    #[error("corrupt or unsealable secret: {0}")]
    CorruptSecret(String),

    #[error("backend unavailable: {0}")]
    Unavailable(String),

    #[error("backend error: {0}")]
    Backend(String),
}

pub type PortResult<T> = Result<T, PortError>;

impl From<PortError> for FailureReason {
    fn from(error: PortError) -> Self {
        match error {
            PortError::NotFound(_) => Self::NotFound,
            PortError::NotSupported(detail) => Self::NotSupported(detail),
            PortError::Timeout(detail) => Self::Timeout(detail),
            PortError::CorruptSecret(_) => Self::SecretsRequired,
            other => Self::Backend(other.to_string()),
        }
    }
}

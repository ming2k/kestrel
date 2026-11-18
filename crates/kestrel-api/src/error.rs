// SPDX-License-Identifier: LGPL-2.1-or-later

#[cfg(feature = "server")]
use kestrel_catalog::CatalogError;
#[cfg(feature = "server")]
use kestrel_controller::ControllerError;

/// D-Bus errors. The name (`com.hihusky.Kestrel.Error.<Variant>`) is the
/// contract; the message is for humans.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "com.hihusky.Kestrel.Error")]
pub enum ApiError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NoSuchDevice(String),
    NoSuchProfile(String),
    NoSuchCertificate(String),
    NoSuchP2pGroup(String),
    NoSuchSession(String),
    WirelessDisabled(String),
    NotSupported(String),
    Busy(String),
    InvalidArgument(String),
    AccessDenied(String),
    Storage(String),
    Backend(String),
    Stopped(String),
}

#[cfg(feature = "server")]
impl From<CatalogError> for ApiError {
    fn from(error: CatalogError) -> Self {
        let message = error.to_string();
        match error {
            CatalogError::NoSuchProfile(_) => Self::NoSuchProfile(message),
            CatalogError::NoSuchCertificate(_) => Self::NoSuchCertificate(message),
            CatalogError::NoSuchP2pGroup(_) => Self::NoSuchP2pGroup(message),
            CatalogError::Busy(_) => Self::Busy(message),
            CatalogError::InvalidArgument(_) => Self::InvalidArgument(message),
            CatalogError::Storage(_) => Self::Storage(message),
        }
    }
}

#[cfg(feature = "server")]
impl From<ControllerError> for ApiError {
    fn from(error: ControllerError) -> Self {
        let message = error.to_string();
        match error {
            ControllerError::NoSuchDevice(_) => Self::NoSuchDevice(message),
            ControllerError::NoSuchSession(_) => Self::NoSuchSession(message),
            ControllerError::WirelessDisabled => Self::WirelessDisabled(message),
            ControllerError::NotSupported(_) => Self::NotSupported(message),
            ControllerError::Busy(_) => Self::Busy(message),
            ControllerError::InvalidArgument(_) => Self::InvalidArgument(message),
            ControllerError::Catalog(inner) => Self::from(inner),
            ControllerError::Backend(_) => Self::Backend(message),
            ControllerError::Stopped => Self::Stopped(message),
        }
    }
}

impl ApiError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_helper_constructs_invalid_argument() {
        assert!(matches!(
            ApiError::invalid("bad ssid"),
            ApiError::InvalidArgument(msg) if msg == "bad ssid"
        ));
    }

    #[cfg(feature = "server")]
    #[test]
    fn catalog_and_controller_errors_map_to_matching_api_errors() {
        use kestrel_model::{ProfileId, SessionId};
        use kestrel_ports::PortError;

        assert!(matches!(
            ApiError::from(ControllerError::NoSuchDevice("wlan0".into())),
            ApiError::NoSuchDevice(_)
        ));
        assert!(matches!(
            ApiError::from(CatalogError::NoSuchProfile(ProfileId::generate())),
            ApiError::NoSuchProfile(_)
        ));
        assert!(matches!(
            ApiError::from(ControllerError::NoSuchSession(SessionId(1))),
            ApiError::NoSuchSession(_)
        ));
        assert!(matches!(
            ApiError::from(ControllerError::WirelessDisabled),
            ApiError::WirelessDisabled(_)
        ));
        assert!(matches!(
            ApiError::from(ControllerError::NotSupported("p2p".into())),
            ApiError::NotSupported(_)
        ));
        assert!(matches!(
            ApiError::from(ControllerError::Busy("scanning".into())),
            ApiError::Busy(_)
        ));
        assert!(matches!(
            ApiError::from(CatalogError::InvalidArgument("arg".into())),
            ApiError::InvalidArgument(_)
        ));
        assert!(matches!(
            ApiError::from(CatalogError::Storage(PortError::Backend("io".into()))),
            ApiError::Storage(_)
        ));
        assert!(matches!(
            ApiError::from(ControllerError::Backend(PortError::Backend("wpa".into()))),
            ApiError::Backend(_)
        ));
        assert!(matches!(
            ApiError::from(ControllerError::Stopped),
            ApiError::Stopped(_)
        ));
    }
}

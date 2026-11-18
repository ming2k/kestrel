// SPDX-License-Identifier: LGPL-2.1-or-later

use kestrel_model::Certificate as ModelCertificate;
use zbus::message::Header;

use super::Shared;
use crate::{Action, ApiError, cert_path};

#[derive(Debug)]
pub(crate) struct Certificate {
    shared: Shared,
    cert: ModelCertificate,
}

pub(crate) async fn export(shared: &Shared, cert: ModelCertificate) -> zbus::Result<()> {
    shared
        .connection
        .object_server()
        .at(
            cert_path(cert.id),
            Certificate {
                shared: shared.clone(),
                cert,
            },
        )
        .await
        .map(|_| ())
}

#[zbus::interface(name = "com.hihusky.Kestrel.Certificate")]
impl Certificate {
    #[zbus(property)]
    fn id(&self) -> String {
        self.cert.id.to_string()
    }

    #[zbus(property)]
    fn name(&self) -> String {
        self.cert.name.clone()
    }

    #[zbus(property)]
    fn fingerprint_sha256(&self) -> String {
        self.cert.fingerprint_sha256()
    }

    async fn delete(&self, #[zbus(header)] header: Header<'_>) -> Result<(), ApiError> {
        self.shared
            .authorize(&header, Action::ModifyProfiles)
            .await?;
        Ok(self.shared.catalog.delete_certificate(self.cert.id).await?)
    }
}

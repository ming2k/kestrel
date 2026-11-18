// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel certificate`: imported X.509 certificates for 802.1X profiles.

use clap::Subcommand;
use kestrel_api::client::{CertificateProxy, Client};
use serde_json::{Value, json};

use crate::common::{
    confirm_delete, print, print_table, read_bounded_file, read_bounded_stdin, resolve_certificate,
    short_id,
};

const MAX_CERT_PEM_BYTES: usize = 1024 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum Certificate {
    /// List imported certificates.
    List,
    /// Import a PEM certificate or CA bundle.
    Add {
        /// Path to the PEM file (`-` reads standard input).
        file: String,
        /// Label shown in listings.
        #[arg(long)]
        name: String,
    },
    /// Show one imported certificate.
    Show { certificate: String },
    /// Delete an imported certificate.
    Delete {
        certificate: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

pub(crate) async fn run(client: &Client, command: Certificate, json: bool) -> zbus::Result<()> {
    match command {
        Certificate::List => list(client, json).await,
        Certificate::Add { file, name } => add(client, &file, &name, json).await,
        Certificate::Show { certificate } => show(client, &certificate, json).await,
        Certificate::Delete { certificate, yes } => delete(client, &certificate, yes, json).await,
    }
}

async fn list(client: &Client, json: bool) -> zbus::Result<()> {
    let mut rows = Vec::new();
    for certificate in client.certificates().await? {
        rows.push(certificate_json(&certificate).await?);
    }
    print(json, &Value::Array(rows.clone()), || {
        let table: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                vec![
                    short_id(row["id"].as_str().unwrap_or("")),
                    row["name"].as_str().unwrap_or("").to_owned(),
                    row["fingerprint_sha256"].as_str().unwrap_or("").to_owned(),
                ]
            })
            .collect();
        print_table(&["ID", "NAME", "SHA-256 FINGERPRINT"], &table);
    });
    Ok(())
}

async fn add(client: &Client, file: &str, name: &str, json: bool) -> zbus::Result<()> {
    let pem = if file == "-" {
        read_bounded_stdin(MAX_CERT_PEM_BYTES)?
    } else {
        read_bounded_file(file, MAX_CERT_PEM_BYTES)?
    };
    let path = client
        .manager()
        .await?
        .import_certificate(name, &pem)
        .await?;
    let id = client.certificate(path).await?.id().await?;
    print(json, &json!({"id": id}), || println!("{id}"));
    Ok(())
}

async fn show(client: &Client, query: &str, json: bool) -> zbus::Result<()> {
    let path = resolve_certificate(client, query).await?;
    let certificate = client.certificate(path).await?;
    let value = certificate_json(&certificate).await?;
    print(json, &value, || {
        println!("ID: {}", value["id"].as_str().unwrap_or(""));
        println!("Name: {}", value["name"].as_str().unwrap_or(""));
        println!(
            "SHA-256: {}",
            value["fingerprint_sha256"].as_str().unwrap_or("")
        );
        println!("Path: {}", value["path"].as_str().unwrap_or(""));
    });
    Ok(())
}

async fn delete(client: &Client, query: &str, yes: bool, json: bool) -> zbus::Result<()> {
    let path = resolve_certificate(client, query).await?;
    let proxy = client.certificate(path).await?;
    let value = certificate_json(&proxy).await?;
    let name = value["name"].as_str().unwrap_or("").to_owned();
    if !confirm_delete(&format!("Delete certificate {name:?}? [y/N] "), yes)? {
        print(
            json,
            &json!({"name": name, "deleted": false, "cancelled": true}),
            || println!("cancelled"),
        );
        return Ok(());
    }
    proxy.delete().await?;
    print(json, &json!({"name": name, "deleted": true}), || {
        println!("deleted {name:?}");
    });
    Ok(())
}

async fn certificate_json(certificate: &CertificateProxy<'_>) -> zbus::Result<Value> {
    Ok(json!({
        "path": certificate.inner().path().as_str(),
        "id": certificate.id().await?,
        "name": certificate.name().await?,
        "fingerprint_sha256": certificate.fingerprint_sha256().await?,
    }))
}

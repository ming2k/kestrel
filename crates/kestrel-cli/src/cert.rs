// SPDX-License-Identifier: LGPL-2.1-or-later

//! `kestrel certificate` (alias `cert`): imported X.509 certificates for 802.1X profiles.

use std::path::Path;

use clap::Subcommand;
use kestrel_api::client::{CertificateProxy, Client};
use serde_json::{Value, json};

use crate::common::{
    CliError, CliResult, confirm_delete, print, print_table, read_bounded_file, read_bounded_stdin,
    resolve_certificate, short_id,
};

const MAX_CERT_PEM_BYTES: usize = 1024 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum Certificate {
    /// List imported certificates.
    List,
    /// Show one imported certificate.
    Show {
        /// Certificate UUID, 8+ char prefix, or name.
        certificate: String,
    },
    /// Import a PEM certificate or CA bundle.
    Add {
        /// Path to the PEM file (`-` reads standard input).
        file: String,
        /// Label shown in listings (defaults to the filename stem when reading a file).
        #[arg(long)]
        name: Option<String>,
    },
    /// Delete an imported certificate.
    Delete {
        /// Certificate UUID, 8+ char prefix, or name.
        certificate: String,
        /// Do not ask for confirmation.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

pub(crate) async fn run(client: &Client, command: Certificate, json: bool) -> CliResult<()> {
    match command {
        Certificate::List => list(client, json).await,
        Certificate::Show { certificate } => show(client, &certificate, json).await,
        Certificate::Add { file, name } => add(client, &file, name.as_deref(), json).await,
        Certificate::Delete { certificate, yes } => delete(client, &certificate, yes, json).await,
    }
}

pub(crate) fn derive_cert_name(file: &str, explicit: Option<&str>) -> CliResult<String> {
    if let Some(name) = explicit {
        if name.trim().is_empty() {
            return Err(CliError::runtime("--name must not be empty"));
        }
        return Ok(name.to_owned());
    }
    if file == "-" {
        return Err(CliError::runtime(
            "--name is required when reading a certificate from standard input",
        ));
    }
    Path::new(file)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| CliError::runtime("cannot derive certificate name from path; pass --name"))
}

async fn list(client: &Client, json: bool) -> CliResult<()> {
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
        print_table(
            &["ID", "NAME", "SHA-256 FINGERPRINT"],
            &table,
            Some("No imported certificates."),
        );
    });
    Ok(())
}

async fn add(client: &Client, file: &str, name: Option<&str>, json: bool) -> CliResult<()> {
    let label = derive_cert_name(file, name)?;
    let pem = if file == "-" {
        read_bounded_stdin(MAX_CERT_PEM_BYTES)?
    } else {
        read_bounded_file(file, MAX_CERT_PEM_BYTES)?
    };
    let path = client
        .manager()
        .await?
        .import_certificate(&label, &pem)
        .await?;
    let id = client.certificate(path).await?.id().await?;
    print(json, &json!({"id": id, "name": label}), || println!("{id}"));
    Ok(())
}

async fn show(client: &Client, query: &str, json: bool) -> CliResult<()> {
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
    });
    Ok(())
}

async fn delete(client: &Client, query: &str, yes: bool, json: bool) -> CliResult<()> {
    let path = resolve_certificate(client, query).await?;
    let proxy = client.certificate(path).await?;
    let value = certificate_json(&proxy).await?;
    let name = value["name"].as_str().unwrap_or("").to_owned();
    if !confirm_delete(&format!("Delete certificate {name:?}? [y/N] "), yes)? {
        print(
            json,
            &json!({"name": name, "deleted": false, "cancelled": true}),
            || eprintln!("cancelled"),
        );
        return Ok(());
    }
    proxy.delete().await?;
    print(json, &json!({"name": name, "deleted": true}), || {
        println!("deleted certificate {name:?}");
    });
    Ok(())
}

async fn certificate_json(certificate: &CertificateProxy<'_>) -> CliResult<Value> {
    Ok(json!({
        "path": certificate.inner().path().as_str(),
        "id": certificate.id().await?,
        "name": certificate.name().await?,
        "fingerprint_sha256": certificate.fingerprint_sha256().await?,
    }))
}

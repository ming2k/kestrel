// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::ModelError;

const MAX_CERT_PEM_BYTES: usize = 1024 * 1024;

/// Stable identity of an imported X.509 certificate or CA bundle.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CertId(Uuid);

impl CertId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| ModelError::InvalidCertId(value.to_owned()))
    }

    /// Lowercase hex without hyphens. Safe for file names and D-Bus paths.
    pub fn simple(&self) -> String {
        self.0.simple().to_string()
    }
}

impl fmt::Debug for CertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertId({})", self.0)
    }
}

impl fmt::Display for CertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for CertId {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A validated X.509 PEM certificate (or CA certificate bundle).
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CertificatePem(String);

impl<'de> Deserialize<'de> for CertificatePem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PemVisitor;

        impl Visitor<'_> for PemVisitor {
            type Value = CertificatePem;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a valid X.509 PEM certificate")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                CertificatePem::new(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(PemVisitor)
    }
}

impl CertificatePem {
    pub fn new(pem: impl Into<String>) -> Result<Self, ModelError> {
        let pem = pem.into();
        if pem.is_empty() || pem.len() > MAX_CERT_PEM_BYTES {
            return Err(ModelError::InvalidCertificate(format!(
                "PEM must be 1..={MAX_CERT_PEM_BYTES} bytes"
            )));
        }
        if pem.contains('\0') {
            return Err(ModelError::InvalidCertificate(
                "PEM must not contain NUL bytes".to_owned(),
            ));
        }
        if pem.contains("PRIVATE KEY") {
            return Err(ModelError::InvalidCertificate(
                "private keys cannot be imported into the public certificate store".to_owned(),
            ));
        }
        let blocks = parse_pem_certificates(&pem)?;
        if blocks.is_empty() {
            return Err(ModelError::InvalidCertificate(
                "expected at least one CERTIFICATE PEM block".to_owned(),
            ));
        }
        Ok(Self(pem))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Colon-separated uppercase hex SHA-256 fingerprint of the first
    /// certificate's DER encoding.
    pub fn fingerprint_sha256(&self) -> String {
        let blocks = parse_pem_certificates(&self.0).unwrap_or_default();
        let Some(first) = blocks.first() else {
            return String::new();
        };
        let digest = sha256(first);
        let mut out = String::with_capacity(digest.len() * 3 - 1);
        for (i, byte) in digest.iter().enumerate() {
            if i > 0 {
                out.push(':');
            }
            let _ = write!(out, "{byte:02X}");
        }
        out
    }
}

impl fmt::Debug for CertificatePem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificatePem")
            .field("bytes", &self.0.len())
            .field("fingerprint_sha256", &self.fingerprint_sha256())
            .finish()
    }
}

/// An imported X.509 certificate managed by Kestrel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub id: CertId,
    pub name: String,
    pub pem: CertificatePem,
}

impl Certificate {
    pub fn new(name: impl Into<String>, pem: CertificatePem) -> Result<Self, ModelError> {
        let cert = Self {
            id: CertId::generate(),
            name: name.into(),
            pem,
        };
        cert.validate()?;
        Ok(cert)
    }

    pub fn fingerprint_sha256(&self) -> String {
        self.pem.fingerprint_sha256()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.name.trim().is_empty() || self.name.chars().count() > 64 {
            return Err(ModelError::InvalidCertificate(
                "name must be 1..=64 characters".to_owned(),
            ));
        }
        if self.name.chars().any(char::is_control) {
            return Err(ModelError::InvalidCertificate(
                "name must not contain control characters".to_owned(),
            ));
        }
        let _ = CertificatePem::new(self.pem.as_str())?;
        Ok(())
    }
}

fn parse_pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>, ModelError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut encoded = String::new();
    for raw_line in pem.lines() {
        let line = raw_line.trim();
        if line == BEGIN {
            if in_block {
                return Err(ModelError::InvalidCertificate(
                    "nested BEGIN CERTIFICATE marker".to_owned(),
                ));
            }
            in_block = true;
            encoded.clear();
        } else if line == END {
            if !in_block {
                return Err(ModelError::InvalidCertificate(
                    "unexpected END CERTIFICATE marker".to_owned(),
                ));
            }
            in_block = false;
            let der = decode_base64(&encoded)?;
            if !is_valid_der_sequence(&der) {
                return Err(ModelError::InvalidCertificate(
                    "decoded certificate is not a valid ASN.1 DER SEQUENCE".to_owned(),
                ));
            }
            blocks.push(der);
        } else if in_block {
            encoded.push_str(line);
        } else if !line.is_empty() {
            return Err(ModelError::InvalidCertificate(
                "unexpected content outside CERTIFICATE PEM blocks".to_owned(),
            ));
        }
    }
    if in_block {
        return Err(ModelError::InvalidCertificate(
            "unterminated CERTIFICATE PEM block".to_owned(),
        ));
    }
    Ok(blocks)
}

/// Validates that `der` is a single well-formed ASN.1 DER SEQUENCE whose
/// encoded length matches `der.len()` exactly.
fn is_valid_der_sequence(der: &[u8]) -> bool {
    if der.len() < 4 || der[0] != 0x30 {
        return false;
    }
    let len_byte = der[1];
    if len_byte < 0x80 {
        return usize::from(len_byte) + 2 == der.len();
    }
    let num_octets = usize::from(len_byte & 0x7f);
    if num_octets == 0 || num_octets > 4 || der.len() < 2 + num_octets {
        return false;
    }
    // DER forbids non-minimal length encodings (leading zero length octet,
    // or long form for lengths < 128).
    if der[2] == 0 {
        return false;
    }
    let mut content_len = 0usize;
    for &b in &der[2..2 + num_octets] {
        content_len = (content_len << 8) | usize::from(b);
    }
    content_len >= 0x80 && 2 + num_octets + content_len == der.len()
}

fn decode_base64(input: &str) -> Result<Vec<u8>, ModelError> {
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return Err(ModelError::InvalidCertificate(
            "invalid base64 length in PEM block".to_owned(),
        ));
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for (idx, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let is_last = idx + 1 == bytes.len() / 4;
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let c = if chunk[2] == b'=' && is_last {
            None
        } else {
            Some(b64_val(chunk[2])?)
        };
        let d = if chunk[3] == b'=' && is_last {
            None
        } else {
            Some(b64_val(chunk[3])?)
        };
        if c.is_none() && d.is_some() {
            return Err(ModelError::InvalidCertificate(
                "invalid base64 padding".to_owned(),
            ));
        }
        out.push((a << 2) | (b >> 4));
        if let Some(c_val) = c {
            out.push((b << 4) | (c_val >> 2));
            if let Some(d_val) = d {
                out.push((c_val << 6) | d_val);
            }
        }
    }
    Ok(out)
}

fn b64_val(byte: u8) -> Result<u8, ModelError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(ModelError::InvalidCertificate(
            "invalid base64 character in PEM block".to_owned(),
        )),
    }
}

/// FIPS 180-4 SHA-256.
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, delta) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(delta);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nMAowAwIBAQMDAAEC\n-----END CERTIFICATE-----\n";

    #[test]
    fn validates_pem_and_rejects_private_keys() {
        let pem = CertificatePem::new(TEST_CERT_PEM).unwrap();
        assert_eq!(pem.fingerprint_sha256().split(':').count(), 32);

        let key = "-----BEGIN PRIVATE KEY-----\nMAowAwIBAQMDAAEC\n-----END PRIVATE KEY-----\n";
        assert!(CertificatePem::new(key).is_err());
        assert!(CertificatePem::new("not a cert").is_err());
        assert!(
            CertificatePem::new("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
                .is_err()
        );
        // Rejects truncated DER SEQUENCE whose length exceeds actual bytes.
        assert!(
            CertificatePem::new(
                "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----\n"
            )
            .is_err()
        );
        // Rejects smuggled text outside PEM blocks.
        assert!(CertificatePem::new(format!("extra-directive=yes\n{TEST_CERT_PEM}")).is_err());
        // Deserialization enforces validation.
        assert!(serde_json::from_str::<CertificatePem>("\"not a cert\"").is_err());
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }
}

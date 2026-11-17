// Copyright 2026 Philip Bonev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://apache.org
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Authentication credentials and TLS identities for the RFB security types.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::invalid_data;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use x509_parser::prelude::{ASN1Time, FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

/// Authentication settings. Secret values are deliberately not formatted with
/// `Debug`.
pub enum AuthenticationConfig {
    VeNCrypt {
        tls: Arc<rustls::ServerConfig>,
        username: Vec<u8>,
        password: Vec<u8>,
    },
    Vnc {
        password: Vec<u8>,
    },
    VncTls {
        tls: Arc<rustls::ServerConfig>,
        password: Vec<u8>,
    },
    AppleDh {
        username: Vec<u8>,
        password: Vec<u8>,
    },
}

impl Drop for AuthenticationConfig {
    fn drop(&mut self) {
        match self {
            Self::VeNCrypt {
                username, password, ..
            } => {
                username.fill(0);
                password.fill(0);
            }
            Self::Vnc { password } => password.fill(0),
            Self::VncTls { password, .. } => password.fill(0),
            Self::AppleDh { username, password } => {
                username.fill(0);
                password.fill(0);
            }
        }
    }
}

/// Load a TLS certificate/key pair and a private username/password file.
pub fn load_authentication(
    certificate_path: &Path,
    key_path: &Path,
    password_path: &Path,
) -> io::Result<AuthenticationConfig> {
    let password_file = File::open(password_path)?;
    let metadata = password_file.metadata()?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "password file must not be accessible by group or other users (chmod 600)",
        ));
    }

    let tls = load_tls_server_config(certificate_path, key_path)?;

    let mut password_contents = Vec::with_capacity(2050);
    password_file
        .take(2051)
        .read_to_end(&mut password_contents)?;
    if password_contents.len() > 2050 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "password file exceeds the 2050-byte limit",
        ));
    }
    if password_contents.last() == Some(&b'\n') {
        password_contents.pop();
    }
    if password_contents.last() == Some(&b'\r') {
        password_contents.pop();
    }
    let Some(separator) = password_contents.iter().position(|byte| *byte == b'\n') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "password file must contain username and password on separate lines",
        ));
    };
    let username_end = if password_contents.get(separator.wrapping_sub(1)) == Some(&b'\r') {
        separator - 1
    } else {
        separator
    };
    let username = password_contents[..username_end].to_vec();
    let password = password_contents[separator + 1..].to_vec();
    password_contents.fill(0);
    if username.is_empty() || password.is_empty() || username.len() > 1024 || password.len() > 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "username and password must each contain 1 to 1024 bytes",
        ));
    }

    Ok(AuthenticationConfig::VeNCrypt {
        tls,
        username,
        password,
    })
}

fn load_tls_server_config(
    certificate_path: &Path,
    key_path: &Path,
) -> io::Result<Arc<rustls::ServerConfig>> {
    let mut certificate_reader = BufReader::new(File::open(certificate_path)?);
    let certificates =
        rustls_pemfile::certs(&mut certificate_reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS certificate file contains no certificates",
        ));
    }

    let key_file = File::open(key_path)?;
    if key_file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TLS private key must not be accessible by group or other users (chmod 600)",
        ));
    }
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS key file contains no private key",
        )
    })?;

    // Describe the identity before it is moved into the configuration so that
    // the summary is only logged once the server has accepted it.
    let summary = certificate_summary(&certificates);

    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TLS identity: {error}"),
            )
        })?;

    crate::timestamped_log!("rfb: TLS certificate: {summary}");
    Ok(Arc::new(tls))
}

/// Build a single-line summary of the leaf certificate in `certificates`.
///
/// Only public certificate fields are included; private key material is never
/// written to the log. If the certificate cannot be parsed the summary falls
/// back to its fingerprint, because rustls has already accepted the identity
/// and refusing to start would be the wrong reaction to a cosmetic failure.
fn certificate_summary(certificates: &[CertificateDer<'static>]) -> String {
    let Some(leaf) = certificates.first() else {
        return "no certificate present".to_string();
    };
    let der = leaf.as_ref();
    let fingerprint = sha256_fingerprint(der);
    let chain = if certificates.len() > 1 {
        format!(" chain={}", certificates.len())
    } else {
        String::new()
    };

    let certificate = match X509Certificate::from_der(der) {
        Ok((_remaining, certificate)) => certificate,
        Err(error) => {
            return format!("sha256={fingerprint}{chain} (details unavailable: {error})");
        }
    };

    let validity = certificate.validity();
    let (not_before, not_after) = (validity.not_before, validity.not_after);
    let now = ASN1Time::now();
    let state = if now < not_before {
        " [NOT YET VALID]"
    } else if now > not_after {
        " [EXPIRED]"
    } else {
        ""
    };

    format!(
        "subject=\"{}\" issuer=\"{}\" serial={} notBefore={not_before} notAfter={not_after}{state} key={} sha256={fingerprint}{chain}",
        certificate.subject(),
        certificate.issuer(),
        certificate.raw_serial_as_string(),
        public_key_summary(&certificate),
    )
}

/// Describe the public key algorithm and, when it is known, its size in bits.
fn public_key_summary(certificate: &X509Certificate<'_>) -> String {
    let Some(key) = certificate.public_key().parsed().ok() else {
        return "unparsable".to_string();
    };
    let algorithm = match key {
        PublicKey::RSA(_) => "RSA",
        PublicKey::EC(_) => "ECDSA",
        PublicKey::DSA(_) => "DSA",
        PublicKey::GostR3410(_) => "GOST R 34.10-94",
        PublicKey::GostR3410_2012(_) => "GOST R 34.10-2012",
        PublicKey::Unknown(_) => "unrecognized",
    };
    let bits = key.key_size();
    if bits == 0 {
        algorithm.to_string()
    } else {
        format!("{algorithm} {bits} bit")
    }
}

/// Format the SHA-256 fingerprint of `der` as colon-separated uppercase hex.
fn sha256_fingerprint(der: &[u8]) -> String {
    use std::fmt::Write;

    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut fingerprint = String::with_capacity(95);
    for (index, byte) in digest.as_ref().iter().enumerate() {
        if index > 0 {
            fingerprint.push(':');
        }
        let _ = write!(fingerprint, "{byte:02X}");
    }
    fingerprint
}

pub fn load_vnc_authentication(password_path: &Path) -> io::Result<AuthenticationConfig> {
    Ok(AuthenticationConfig::Vnc {
        password: load_vnc_password(password_path)?,
    })
}

fn load_vnc_password(password_path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(password_path)?;
    if file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VNC password file must not be accessible by group or other users (chmod 600)",
        ));
    }
    let mut contents = Vec::with_capacity(2050);
    file.take(2051).read_to_end(&mut contents)?;
    if contents.len() > 2050 {
        contents.fill(0);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VNC credential file exceeds the 2050-byte limit",
        ));
    }
    if contents.last() == Some(&b'\n') {
        contents.pop();
    }
    if contents.last() == Some(&b'\r') {
        contents.pop();
    }
    let password_start = contents
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(0, |separator| separator + 1);
    if contents[password_start..].contains(&b'\n') || contents[password_start..].contains(&b'\r') {
        contents.fill(0);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VNC credential file must contain at most username and password lines",
        ));
    }
    let mut password = contents[password_start..].to_vec();
    contents.fill(0);
    if password.is_empty() || password.len() > 8 {
        password.fill(0);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VNC authentication requires a password of 1 to 8 bytes (the second line when username is present)",
        ));
    }
    Ok(password)
}

/// Load classic VNC password authentication protected by a TLS server identity.
pub fn load_vnc_tls_authentication(
    certificate_path: &Path,
    key_path: &Path,
    password_path: &Path,
) -> io::Result<AuthenticationConfig> {
    // Validate the TLS identity before reading the password into memory.
    let tls = load_tls_server_config(certificate_path, key_path)?;
    let password = load_vnc_password(password_path)?;
    Ok(AuthenticationConfig::VncTls { tls, password })
}

/// Read Apple DH credentials from a mode-0600 username/password file.
pub fn load_apple_dh_authentication(password_path: &Path) -> io::Result<AuthenticationConfig> {
    let config = load_auth_credentials(password_path)?;
    Ok(AuthenticationConfig::AppleDh {
        username: config.0,
        password: config.1,
    })
}

fn load_auth_credentials(path: &Path) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let file = File::open(path)?;
    if file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "credential file must not be accessible by group or other users (chmod 600)",
        ));
    }
    let mut bytes = Vec::new();
    file.take(2051).read_to_end(&mut bytes)?;
    if bytes.len() > 2050 {
        bytes.fill(0);
        return Err(invalid_data("credential file exceeds 2050 bytes"));
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let Some(split) = bytes.iter().position(|b| *b == b'\n') else {
        bytes.fill(0);
        return Err(invalid_data(
            "credential file must contain username and password on separate lines",
        ));
    };
    let username_end = if split > 0 && bytes[split - 1] == b'\r' {
        split - 1
    } else {
        split
    };
    let password_start = split + 1;
    if bytes[password_start..].contains(&b'\n') || bytes[password_start..].contains(&b'\r') {
        bytes.fill(0);
        return Err(invalid_data(
            "credential file must contain exactly two lines",
        ));
    }
    let user = bytes[..username_end].to_vec();
    let pass = bytes[password_start..].to_vec();
    bytes.fill(0);
    if user.is_empty() || user.len() > 64 || pass.is_empty() || pass.len() > 64 {
        return Err(invalid_data(
            "Apple DH username and password must each be 1 to 64 bytes",
        ));
    }
    Ok((user, pass))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Self-signed OpenSSL fixtures with fixed validity windows, so the expiry
    // checks do not depend on the clock: `valid_cert.der` is an RSA-3072
    // certificate valid from 2020 to 2120, `expired_cert.der` is a P-256
    // certificate that expired in 2021.
    const VALID_CERTIFICATE: &[u8] = include_bytes!("../../tests/fixtures/valid_cert.der");

    const EXPIRED_CERTIFICATE: &[u8] = include_bytes!("../../tests/fixtures/expired_cert.der");

    #[test]
    fn sha256_fingerprint_is_colon_separated_uppercase_hex() {
        let fingerprint = sha256_fingerprint(b"abc");
        assert_eq!(
            fingerprint,
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
        // 32 bytes as two hex digits plus a colon between each pair.
        assert_eq!(fingerprint.len(), 95);
    }

    #[test]
    fn certificate_summary_reports_the_leaf_certificate() {
        let certificate = CertificateDer::from(VALID_CERTIFICATE);
        let summary = certificate_summary(std::slice::from_ref(&certificate));

        assert!(
            summary.contains("subject=\"CN=rvncserver test, O=rvncserver tests\""),
            "{summary}"
        );
        assert!(
            summary.contains("issuer=\"CN=rvncserver test, O=rvncserver tests\""),
            "{summary}"
        );
        assert!(summary.contains("serial=10:02"), "{summary}");
        assert!(
            summary.contains("notBefore=Jan  1 00:00:00 2020 +00:00"),
            "{summary}"
        );
        assert!(
            summary.contains("notAfter=Jan  1 00:00:00 2120 +00:00"),
            "{summary}"
        );
        assert!(summary.contains("key=RSA 3072 bit"), "{summary}");
        assert!(
                summary.contains(
                    "sha256=E9:91:97:DD:06:71:33:04:94:7F:F5:4E:93:98:35:4A:8D:81:17:61:05:D7:F8:C7:A7:DD:78:E4:7D:5B:86:DC"
                ),
                "{summary}"
            );
        assert!(!summary.contains("chain="), "{summary}");
        assert!(!summary.contains("[EXPIRED]"), "{summary}");
        assert!(!summary.contains("[NOT YET VALID]"), "{summary}");
    }

    #[test]
    fn certificate_summary_marks_an_expired_certificate() {
        let certificate = CertificateDer::from(EXPIRED_CERTIFICATE);
        let summary = certificate_summary(std::slice::from_ref(&certificate));

        assert!(summary.contains("[EXPIRED]"), "{summary}");
        assert!(
            summary.contains("notBefore=Jan  1 00:00:00 2020 +00:00"),
            "{summary}"
        );
        assert!(
            summary.contains("notAfter=Jan  1 00:00:00 2021 +00:00"),
            "{summary}"
        );
        assert!(summary.contains("serial=10:00"), "{summary}");
        assert!(summary.contains("key=ECDSA 256 bit"), "{summary}");
        assert!(
                summary.contains(
                    "sha256=19:07:1E:45:BB:BB:3D:A6:21:41:3C:E2:72:41:B5:E6:E1:82:48:80:6D:8B:2C:FC:5B:36:A2:7F:F0:C1:C6:19"
                ),
                "{summary}"
            );
    }

    #[test]
    fn certificate_summary_counts_extra_chain_certificates() {
        let leaf = CertificateDer::from(VALID_CERTIFICATE);
        let summary = certificate_summary(&[leaf.clone(), leaf]);

        assert!(summary.contains("chain=2"), "{summary}");
    }

    #[test]
    fn certificate_summary_falls_back_to_the_fingerprint() {
        let certificate = CertificateDer::from(b"not a certificate".as_slice());
        let summary = certificate_summary(std::slice::from_ref(&certificate));

        assert!(summary.contains("details unavailable"), "{summary}");
        assert!(
            summary.contains(&sha256_fingerprint(b"not a certificate")),
            "{summary}"
        );
        assert!(!summary.contains("subject="), "{summary}");
    }

    #[test]
    fn certificate_summary_handles_an_empty_certificate_list() {
        assert_eq!(certificate_summary(&[]), "no certificate present");
    }

    #[test]
    fn loads_owner_only_vnc_password_file_formats() {
        let path = std::env::temp_dir().join(format!(
            "rvncserver-vnc-password-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let auth = load_vnc_authentication(&path).unwrap();
        assert!(matches!(
            &auth,
            AuthenticationConfig::Vnc { password } if password.as_slice() == b"secret"
        ));

        std::fs::write(&path, b"rvnc\nsecret\n").unwrap();
        assert!(matches!(
            &load_vnc_authentication(&path).unwrap(),
            AuthenticationConfig::Vnc { password } if password.as_slice() == b"secret"
        ));

        std::fs::write(&path, b"password-is-long\n").unwrap();
        assert!(load_vnc_authentication(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&path, b"secret\n").unwrap();
        assert_eq!(
            load_vnc_authentication(&path).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(path).unwrap();
    }
}

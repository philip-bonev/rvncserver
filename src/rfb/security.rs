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

//! RFB security negotiation and authentication crypto.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, KeyInit as AesKeyInit};
use crypto_bigint::zeroize::Zeroize;
use crypto_bigint::{BoxedUint, Odd, Resize};
use des::Des;
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use md5::{Digest, Md5};

use super::ClientStream;
use super::RfbVersion;
use super::{
    invalid_data, read_exact_interruptible, read_u8, read_u32, shutdown_error,
    write_all_interruptible,
};

pub(super) const SECURITY_TYPE_NONE: u32 = 1;

pub(super) const SECURITY_TYPE_VNC_AUTH: u8 = 2;

pub(super) const SECURITY_TYPE_VENCRYPT: u8 = 19;

pub(super) const SECURITY_TYPE_APPLE_DH: u8 = 30;

pub(super) const VENCRYPT_SUBTYPE_X509_PLAIN: u32 = 262;

pub(super) const VENCRYPT_SUBTYPE_X509_VNC: u32 = 261;

pub(super) fn negotiate_vnc_tls_with_fallback(
    mut tcp_stream: TcpStream,
    version: RfbVersion,
    tls: &Arc<rustls::ServerConfig>,
    password: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<ClientStream> {
    match version {
        RfbVersion::V3_3 => {
            crate::timestamped_log!(
                "security warning: client negotiated RFB 3.3; falling back to unencrypted VNC authentication"
            );
            negotiate_vnc_auth(&mut tcp_stream, version, password, true, shutdown)?;
            Ok(ClientStream::Plain(tcp_stream))
        }
        RfbVersion::V3_8 => {
            // Explicit combined mode permits clients to choose either TLS or
            // legacy VNC authentication. The latter is a plaintext downgrade.
            write_all_interruptible(
                &mut tcp_stream,
                &[2, SECURITY_TYPE_VENCRYPT, SECURITY_TYPE_VNC_AUTH],
                shutdown,
            )?;
            match read_u8(&mut tcp_stream, shutdown)? {
                SECURITY_TYPE_VNC_AUTH => {
                    crate::timestamped_log!(
                        "security warning: client selected unencrypted VNC authentication instead of VeNCrypt X509Vnc"
                    );
                    negotiate_vnc_auth(&mut tcp_stream, version, password, false, shutdown)?;
                    Ok(ClientStream::Plain(tcp_stream))
                }
                SECURITY_TYPE_VENCRYPT => {
                    let mut stream = negotiate_vencrypt_tls_after_security_type(
                        tcp_stream,
                        tls,
                        VENCRYPT_SUBTYPE_X509_VNC,
                        "VeNCrypt X509Vnc",
                        shutdown,
                    )?;
                    negotiate_vnc_auth(&mut stream, version, password, false, shutdown)?;
                    Ok(stream)
                }
                selected => Err(invalid_data(format!(
                    "client selected unsupported security type {selected}"
                ))),
            }
        }
        RfbVersion::Apple3_889 => Err(invalid_data(
            "X509Vnc with VNC fallback does not support Apple RFB 3.889",
        )),
    }
}

pub(super) fn negotiate_vencrypt(
    tcp_stream: TcpStream,
    tls: &Arc<rustls::ServerConfig>,
    expected_username: &[u8],
    expected_password: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<ClientStream> {
    let mut stream = negotiate_vencrypt_tls(
        tcp_stream,
        tls,
        VENCRYPT_SUBTYPE_X509_PLAIN,
        "VeNCrypt X509Plain",
        shutdown,
    )?;
    let username_length = read_u32(&mut stream, shutdown)?;
    let password_length = read_u32(&mut stream, shutdown)?;
    if username_length > 1024 || password_length > 1024 {
        return Err(invalid_data(
            "VeNCrypt username or password exceeds 1024 bytes",
        ));
    }
    let mut username = vec![0; username_length as usize];
    let mut password = vec![0; password_length as usize];
    read_exact_interruptible(&mut stream, &mut username, shutdown)?;
    read_exact_interruptible(&mut stream, &mut password, shutdown)?;
    let authenticated = constant_time_equal(&username, expected_username)
        & constant_time_equal(&password, expected_password);
    password.fill(0);
    username.fill(0);
    write_auth_result(&mut stream, authenticated, true, shutdown)?;
    if !authenticated {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VeNCrypt credentials rejected",
        ));
    }
    Ok(stream)
}

pub(super) fn negotiate_vencrypt_tls(
    mut tcp_stream: TcpStream,
    tls: &Arc<rustls::ServerConfig>,
    subtype: u32,
    subtype_name: &str,
    shutdown: &AtomicBool,
) -> io::Result<ClientStream> {
    negotiate_vencrypt_security_type(&mut tcp_stream, shutdown)?;
    negotiate_vencrypt_tls_after_security_type(tcp_stream, tls, subtype, subtype_name, shutdown)
}

pub(super) fn negotiate_vencrypt_security_type(
    stream: &mut TcpStream,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    write_all_interruptible(stream, &[1, SECURITY_TYPE_VENCRYPT], shutdown)?;
    if read_u8(stream, shutdown)? != SECURITY_TYPE_VENCRYPT {
        return Err(invalid_data(
            "client did not select VeNCrypt authentication",
        ));
    }
    Ok(())
}

pub(super) fn negotiate_vencrypt_tls_after_security_type(
    mut tcp_stream: TcpStream,
    tls: &Arc<rustls::ServerConfig>,
    subtype: u32,
    subtype_name: &str,
    shutdown: &AtomicBool,
) -> io::Result<ClientStream> {
    negotiate_vencrypt_subtype(&mut tcp_stream, subtype, subtype_name, shutdown)?;

    let mut connection = rustls::ServerConnection::new(Arc::clone(tls))
        .map_err(|error| io::Error::other(format!("could not create TLS connection: {error}")))?;
    while connection.is_handshaking() {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }
        if let Err(error) = connection.complete_io(&mut tcp_stream) {
            if error.kind() == io::ErrorKind::TimedOut
                || error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(error);
        }
    }

    Ok(ClientStream::Tls(Box::new(rustls::StreamOwned::new(
        connection, tcp_stream,
    ))))
}

pub(super) fn negotiate_vencrypt_subtype(
    stream: &mut TcpStream,
    subtype: u32,
    subtype_name: &str,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    write_all_interruptible(stream, &[0, 2], shutdown)?;
    let mut client_version = [0u8; 2];
    read_exact_interruptible(stream, &mut client_version, shutdown)?;
    if client_version != [0, 2] {
        return Err(invalid_data(
            "client selected an unsupported VeNCrypt version",
        ));
    }
    write_all_interruptible(stream, &[0], shutdown)?;
    write_all_interruptible(stream, &[1], shutdown)?;
    write_all_interruptible(stream, &subtype.to_be_bytes(), shutdown)?;
    if read_u32(stream, shutdown)? != subtype {
        write_all_interruptible(stream, &[0], shutdown)?;
        return Err(invalid_data(format!(
            "client did not select {subtype_name}"
        )));
    }
    write_all_interruptible(stream, &[1], shutdown)
}

pub(super) fn negotiate_vnc_auth(
    stream: &mut (impl Read + Write),
    version: RfbVersion,
    password: &[u8],
    negotiate_security_type: bool,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    if negotiate_security_type {
        match version {
            RfbVersion::V3_3 => {
                write_all_interruptible(
                    stream,
                    &(u32::from(SECURITY_TYPE_VNC_AUTH)).to_be_bytes(),
                    shutdown,
                )?;
            }
            RfbVersion::V3_8 => {
                write_all_interruptible(stream, &[1, SECURITY_TYPE_VNC_AUTH], shutdown)?;
                if read_u8(stream, shutdown)? != SECURITY_TYPE_VNC_AUTH {
                    return Err(invalid_data("client did not select VNC Authentication"));
                }
            }
            RfbVersion::Apple3_889 => {
                return Err(invalid_data(
                    "Apple RFB 3.889 requires Apple DH authentication",
                ));
            }
        }
    }

    let mut challenge = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut challenge)?;
    write_all_interruptible(stream, &challenge, shutdown)?;
    let mut response = [0u8; 16];
    read_exact_interruptible(stream, &mut response, shutdown)?;
    let expected = vnc_auth_response(password, &challenge)?;
    let authenticated = constant_time_equal(&response, &expected);
    write_auth_result(stream, authenticated, version == RfbVersion::V3_8, shutdown)
}

pub(super) fn negotiate_apple_dh(
    stream: &mut TcpStream,
    expected_username: &[u8],
    expected_password: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
    const PRIME_HEX: &str = concat!(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
    );
    let mut prime_bytes = [0u8; 256];
    for (i, pair) in PRIME_HEX.as_bytes().chunks_exact(2).enumerate() {
        prime_bytes[i] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    let prime = BoxedUint::from_be_slice(&prime_bytes, 2048)
        .map_err(|_| invalid_data("invalid Apple DH modulus"))?;
    let odd_prime = Odd::new(prime.clone())
        .into_option()
        .ok_or_else(|| invalid_data("invalid Apple DH modulus"))?;

    let mut private_bytes = [0u8; 256];
    File::open("/dev/urandom")?.read_exact(&mut private_bytes)?;
    let private = SecretDhExponent(
        BoxedUint::from_be_slice(&private_bytes, 2048)
            .map_err(|_| invalid_data("invalid Apple DH private value"))?,
    );
    private_bytes.fill(0);
    let generator = BoxedUint::from(2u8).resize(2048);
    let server_public = generator.pow_mod(&private.0, &odd_prime).to_be_bytes();

    write_all_interruptible(stream, &[1, SECURITY_TYPE_APPLE_DH], shutdown)?;
    let selected_type = read_u8(stream, shutdown)?;
    if selected_type != SECURITY_TYPE_APPLE_DH {
        return Err(invalid_data(format!(
            "client selected security type {selected_type}, but Apple DH (30) was offered"
        )));
    }
    let mut hello = [0u8; 4];
    hello[..2].copy_from_slice(&2u16.to_be_bytes());
    hello[2..].copy_from_slice(&256u16.to_be_bytes());
    write_all_interruptible(stream, &hello, shutdown)?;
    write_all_interruptible(stream, &prime_bytes, shutdown)?;
    write_all_interruptible(stream, &server_public, shutdown)?;

    let mut response = [0u8; 384];
    read_exact_interruptible(stream, &mut response, shutdown)?;
    let client_public_bytes = &response[128..];
    let client_public = BoxedUint::from_be_slice(client_public_bytes, 2048)
        .map_err(|_| invalid_data("invalid Apple DH client public value"))?;
    // Reject trivial/out-of-range public values before exponentiation.
    let two = BoxedUint::from(2u8).resize(2048);
    let upper = &prime - &two;
    if client_public < two || client_public > upper {
        response.fill(0);
        return Err(invalid_data("Apple DH client public value is out of range"));
    }
    let mut shared = client_public.pow_mod(&private.0, &odd_prime).to_be_bytes();
    let mut shared_256 = [0u8; 256];
    if shared.len() > shared_256.len() {
        response.fill(0);
        return Err(invalid_data("invalid Apple DH shared secret size"));
    }
    shared_256[256 - shared.len()..].copy_from_slice(&shared);
    shared.fill(0);
    let mut key = Md5::digest(shared_256);
    shared_256.fill(0);
    let cipher = Aes128::new_from_slice(&key)
        .map_err(|_| invalid_data("could not initialize Apple DH AES cipher"))?;
    key.fill(0);
    for block in response[..128].chunks_exact_mut(16) {
        let mut aes_block = aes::Block::default();
        aes_block.copy_from_slice(block);
        cipher.decrypt_block(&mut aes_block);
        block.copy_from_slice(&aes_block);
    }
    let credentials = &response[..128];
    let user_end = credentials[..64].iter().position(|b| *b == 0).unwrap_or(64);
    let pass_end = credentials[64..].iter().position(|b| *b == 0).unwrap_or(64);
    let authenticated = constant_time_equal(&credentials[..user_end], expected_username)
        & constant_time_equal(&credentials[64..64 + pass_end], expected_password);
    response.fill(0);
    write_auth_result(stream, authenticated, true, shutdown)?;
    if authenticated {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Apple DH credentials rejected",
        ))
    }
}

fn hex_nibble(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid_data("invalid hexadecimal Apple DH modulus")),
    }
}

struct SecretDhExponent(BoxedUint);

impl Drop for SecretDhExponent {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) fn vnc_auth_response(password: &[u8], challenge: &[u8; 16]) -> io::Result<[u8; 16]> {
    if password.is_empty() || password.len() > 8 {
        return Err(invalid_data("VNC password must contain 1 to 8 bytes"));
    }
    let mut key = [0u8; 8];
    for (target, source) in key.iter_mut().zip(password) {
        *target = source.reverse_bits();
    }
    let cipher = Des::new_from_slice(&key)
        .map_err(|_| invalid_data("could not initialize VNC DES cipher"))?;
    key.fill(0);

    let mut response = *challenge;
    for block_bytes in response.chunks_exact_mut(8) {
        let mut block = GenericArray::clone_from_slice(block_bytes);
        cipher.encrypt_block(&mut block);
        block_bytes.copy_from_slice(&block);
    }
    Ok(response)
}

fn write_auth_result(
    stream: &mut (impl Read + Write),
    authenticated: bool,
    include_failure_reason: bool,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    write_all_interruptible(stream, &u32::from(!authenticated).to_be_bytes(), shutdown)?;
    if !authenticated && include_failure_reason {
        let reason = b"authentication failed";
        write_all_interruptible(stream, &(reason.len() as u32).to_be_bytes(), shutdown)?;
        write_all_interruptible(stream, reason, shutdown)?;
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfb::listener::configure_stream;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn unused_test_tls_config() -> Arc<rustls::ServerConfig> {
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new())),
        )
    }

    #[test]
    fn boxed_dh_operands_are_resized_to_modulus_precision() {
        let precision = 2048;
        let modulus = BoxedUint::from(23u8).resize(precision);
        let odd_modulus = Odd::new(modulus).into_option().unwrap();
        let base = BoxedUint::from(2u8).resize(precision);
        let exponent = BoxedUint::from(3u8).resize(precision);
        let result = base.pow_mod(&exponent, &odd_modulus).to_be_bytes();
        assert_eq!(result.last(), Some(&8));
    }

    #[test]
    fn compares_authentication_values_without_content_early_exit() {
        assert!(constant_time_equal(b"credential", b"credential"));
        assert!(!constant_time_equal(b"credential", b"credentiaL"));
        assert!(!constant_time_equal(b"short", b"longer"));
    }

    #[test]
    fn vnc_auth_response_matches_des_reference_vector() {
        let challenge = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let response = vnc_auth_response(b"password", &challenge).unwrap();
        assert_eq!(
            response,
            [
                0xb8, 0x66, 0x92, 0x41, 0x25, 0xc8, 0xee, 0xbb, 0x9d, 0xeb, 0xc1, 0xdb, 0x61, 0xc5,
                0x38, 0xe2,
            ]
        );
    }

    #[test]
    fn vnc_auth_negotiates_rfb_38_security_type() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            negotiate_vnc_auth(
                &mut stream,
                RfbVersion::V3_8,
                b"password",
                true,
                &AtomicBool::new(false),
            )
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut security_types = [0; 2];
        client.read_exact(&mut security_types).unwrap();
        assert_eq!(security_types, [1, SECURITY_TYPE_VNC_AUTH]);
        client.write_all(&[SECURITY_TYPE_VNC_AUTH]).unwrap();
        let mut challenge = [0; 16];
        client.read_exact(&mut challenge).unwrap();
        client
            .write_all(&vnc_auth_response(b"password", &challenge).unwrap())
            .unwrap();
        let mut result = [0; 4];
        client.read_exact(&mut result).unwrap();
        assert_eq!(u32::from_be_bytes(result), 0);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn negotiates_vencrypt_x509_vnc_subtype() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            write_all_interruptible(
                &mut stream,
                &[2, SECURITY_TYPE_VENCRYPT, SECURITY_TYPE_VNC_AUTH],
                &AtomicBool::new(false),
            )?;
            if read_u8(&mut stream, &AtomicBool::new(false))? != SECURITY_TYPE_VENCRYPT {
                return Err(invalid_data("client selected wrong outer security type"));
            }
            negotiate_vencrypt_subtype(
                &mut stream,
                VENCRYPT_SUBTYPE_X509_VNC,
                "VeNCrypt X509Vnc",
                &AtomicBool::new(false),
            )
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut security_types = [0; 3];
        client.read_exact(&mut security_types).unwrap();
        assert_eq!(
            security_types,
            [2, SECURITY_TYPE_VENCRYPT, SECURITY_TYPE_VNC_AUTH]
        );
        client.write_all(&[SECURITY_TYPE_VENCRYPT]).unwrap();

        let mut version = [0; 2];
        client.read_exact(&mut version).unwrap();
        assert_eq!(version, [0, 2]);
        client.write_all(&[0, 2]).unwrap();
        let mut status = [0; 1];
        client.read_exact(&mut status).unwrap();
        assert_eq!(status, [0]);

        let mut subtype_count = [0; 1];
        client.read_exact(&mut subtype_count).unwrap();
        assert_eq!(subtype_count, [1]);
        let mut subtype = [0; 4];
        client.read_exact(&mut subtype).unwrap();
        assert_eq!(u32::from_be_bytes(subtype), VENCRYPT_SUBTYPE_X509_VNC);
        client.write_all(&subtype).unwrap();
        client.read_exact(&mut status).unwrap();
        assert_eq!(status, [1]);

        server.join().unwrap().unwrap();
    }

    #[test]
    fn vnc_auth_after_vencrypt_subtype_starts_with_challenge() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            negotiate_vnc_auth(
                &mut stream,
                RfbVersion::V3_8,
                b"password",
                false,
                &AtomicBool::new(false),
            )
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut challenge = [0; 16];
        client.read_exact(&mut challenge).unwrap();
        client
            .write_all(&vnc_auth_response(b"password", &challenge).unwrap())
            .unwrap();
        let mut result = [0; 4];
        client.read_exact(&mut result).unwrap();
        assert_eq!(u32::from_be_bytes(result), 0);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn combined_vnc_mode_allows_rfb_38_plaintext_fallback_when_client_selects_it() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let tls = unused_test_tls_config();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            let result = negotiate_vnc_tls_with_fallback(
                stream,
                RfbVersion::V3_8,
                &tls,
                b"password",
                &AtomicBool::new(false),
            )?;
            assert!(matches!(result, ClientStream::Plain(_)));
            Ok::<(), io::Error>(())
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut offered = [0; 3];
        client.read_exact(&mut offered).unwrap();
        assert_eq!(offered, [2, SECURITY_TYPE_VENCRYPT, SECURITY_TYPE_VNC_AUTH]);
        client.write_all(&[SECURITY_TYPE_VNC_AUTH]).unwrap();
        let mut challenge = [0; 16];
        client.read_exact(&mut challenge).unwrap();
        client
            .write_all(&vnc_auth_response(b"password", &challenge).unwrap())
            .unwrap();
        let mut result = [0; 4];
        client.read_exact(&mut result).unwrap();
        assert_eq!(u32::from_be_bytes(result), 0);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn combined_vnc_mode_uses_plain_auth_for_rfb_33_clients() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let tls = unused_test_tls_config();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            let result = negotiate_vnc_tls_with_fallback(
                stream,
                RfbVersion::V3_3,
                &tls,
                b"password",
                &AtomicBool::new(false),
            )?;
            assert!(matches!(result, ClientStream::Plain(_)));
            Ok::<(), io::Error>(())
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut security_type = [0; 4];
        client.read_exact(&mut security_type).unwrap();
        assert_eq!(
            u32::from_be_bytes(security_type),
            u32::from(SECURITY_TYPE_VNC_AUTH)
        );
        let mut challenge = [0; 16];
        client.read_exact(&mut challenge).unwrap();
        client
            .write_all(&vnc_auth_response(b"password", &challenge).unwrap())
            .unwrap();
        let mut result = [0; 4];
        client.read_exact(&mut result).unwrap();
        assert_eq!(u32::from_be_bytes(result), 0);
        server.join().unwrap().unwrap();
    }
}

//! Minimal RFB 3.3/3.8 server.
//!
//! This module intentionally depends only on the normalized [`Frame`] type and
//! the standard library. It currently supports:
//!
//! - RFB 3.3 and 3.8 version negotiation
//! - VeNCrypt X509Plain with TLS and username/password authentication in
//!   normal server operation
//! - A single client at a time
//! - 8-, 16-, and 32-bit true-color formats, including both byte orders
//! - Raw, Hextile, and ZRLE encodings, selected from the client's advertised list
//! - Incremental update requests with damage-region Raw rectangles
//!
//! Remote input and text clipboard transfer are enabled only when explicitly
//! requested and granted by the XDG Desktop Portal. The server does not claim
//! support for encodings or extensions that are not implemented here.

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use des::Des;
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use flate2::{Compress, Compression, FlushCompress, Status};

use crate::cli::RfbEncoding;
use crate::framebuffer::{DamageRect, Frame, FrameDamage, FrameStore};
use crate::input::ClientEvent;

const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";
const SECURITY_TYPE_NONE: u32 = 1;
const SECURITY_TYPE_VNC_AUTH: u8 = 2;
const SECURITY_TYPE_VENCRYPT: u8 = 19;
const ENCODING_COPY_RECT: i32 = 1;
const ENCODING_ZLIB: i32 = 6;
const VENCRYPT_SUBTYPE_X509_PLAIN: u32 = 262;
const MAX_ENCODINGS: u16 = 1024;
const MAX_CUT_TEXT: u32 = 1024 * 1024;
const READ_POLL_INTERVAL: Duration = Duration::from_millis(500);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_SLICE: Duration = Duration::from_millis(250);
const MAX_UPDATE_RECTS: usize = 128;

const ENCODING_RAW: i32 = 0;
const ENCODING_HEXTILE: i32 = 5;
const ENCODING_ZRLE: i32 = 16;

/// Protocol settings and optional capability gates for an RFB listener.
pub struct RfbConfig {
    /// Framebuffer dimensions.
    pub width: u16,
    /// Framebuffer height.
    pub height: u16,
    /// Name announced during ServerInit.
    pub name: String,
    /// Whether keyboard and pointer input are enabled.
    pub input_enabled: bool,
    /// Whether clipboard messages are enabled.
    pub clipboard_enabled: bool,
    /// Optional allowlist; Raw remains a required fallback.
    pub encodings: Option<Vec<RfbEncoding>>,
    /// Optional TLS/VeNCrypt authentication settings.
    pub authentication: Option<Arc<AuthenticationConfig>>,
}

/// TLS server identity and VeNCrypt credentials. Secret values are deliberately
/// not formatted with `Debug`.
pub enum AuthenticationConfig {
    VeNCrypt {
        tls: Arc<rustls::ServerConfig>,
        username: Vec<u8>,
        password: Vec<u8>,
    },
    Vnc {
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
        }
    }
}

enum ClientStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Read for ClientStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
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

    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TLS identity: {error}"),
            )
        })?;

    Ok(AuthenticationConfig::VeNCrypt {
        tls: Arc::new(tls),
        username,
        password,
    })
}

pub fn load_vnc_authentication(password_path: &Path) -> io::Result<AuthenticationConfig> {
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
    Ok(AuthenticationConfig::Vnc { password })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Raw,
    Hextile,
    Zlib,
    Zrle,
}

impl Encoding {
    fn rfb_value(self) -> i32 {
        match self {
            Self::Raw => ENCODING_RAW,
            Self::Hextile => ENCODING_HEXTILE,
            Self::Zlib => ENCODING_ZLIB,
            Self::Zrle => ENCODING_ZRLE,
        }
    }
}

struct ClientUpdateState {
    encoding: Encoding,
    copy_rect_enabled: bool,
    pixel_format: PixelFormat,
    last_sequence: u64,
    pending_damage: Vec<DamageRect>,
    pending_update: Option<DamageRect>,
    zrle_compressor: Compress,
    zlib_compressor: Compress,
    client_pixels: Option<Vec<[u8; 4]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncodingPreferences {
    preferred: Encoding,
    copy_rect: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PixelFormat {
    bits_per_pixel: u8,
    depth: u8,
    big_endian: bool,
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
}

impl PixelFormat {
    const DEFAULT: Self = Self {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };

    fn bytes_per_pixel(self) -> usize {
        usize::from(self.bits_per_pixel / 8)
    }

    fn zrle_bytes_per_pixel(self) -> usize {
        let used_bits = self.used_component_bits();
        if self.bits_per_pixel == 32
            && used_bits.count_ones() <= 24
            && (used_bits & 0xff00_0000 == 0 || used_bits & 0x0000_00ff == 0)
        {
            3
        } else {
            self.bytes_per_pixel()
        }
    }

    fn used_component_bits(self) -> u32 {
        (u32::from(self.red_max) << self.red_shift)
            | (u32::from(self.green_max) << self.green_shift)
            | (u32::from(self.blue_max) << self.blue_shift)
    }

    fn encode(self, bgra: &[u8]) -> [u8; 4] {
        if self == Self::DEFAULT {
            return [bgra[0], bgra[1], bgra[2], bgra[3]];
        }
        let red = scale_channel(bgra[2], self.red_max) << self.red_shift;
        let green = scale_channel(bgra[1], self.green_max) << self.green_shift;
        let blue = scale_channel(bgra[0], self.blue_max) << self.blue_shift;
        let mut value = red | green | blue;
        let used_bits = (u32::from(self.red_max) << self.red_shift)
            | (u32::from(self.green_max) << self.green_shift)
            | (u32::from(self.blue_max) << self.blue_shift);
        if self.bits_per_pixel == 32 && used_bits.count_ones() == 24 {
            if let Some(padding_shift) = (0..4)
                .map(|byte| byte * 8)
                .find(|shift| used_bits & (0xff << shift) == 0)
            {
                // Preserve captured alpha in a wholly unused byte. Some
                // 32-bit clients treat this padding byte as an alpha channel.
                value |= u32::from(bgra[3]) << padding_shift;
            }
        }
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        let mut encoded = [0; 4];
        let pixel_bytes = self.bytes_per_pixel();
        if self.big_endian {
            encoded[..pixel_bytes].copy_from_slice(&bytes[4 - pixel_bytes..]);
        } else {
            encoded[..pixel_bytes].copy_from_slice(&bytes[..pixel_bytes]);
        }
        encoded
    }

    fn encode_zrle(self, bgra: &[u8]) -> [u8; 4] {
        let encoded = self.encode(bgra);
        if self.zrle_bytes_per_pixel() != 3 {
            return encoded;
        }

        let high_byte_unused = self.used_component_bits() & 0xff00_0000 == 0;
        let omitted_byte = match (self.big_endian, high_byte_unused) {
            (false, true) | (true, false) => 3,
            (false, false) | (true, true) => 0,
        };
        let mut compact = [0; 4];
        let mut destination = 0;
        for (index, byte) in encoded[..4].iter().enumerate() {
            if index != omitted_byte {
                compact[destination] = *byte;
                destination += 1;
            }
        }
        compact
    }

    fn from_wire(format: &[u8; 16]) -> io::Result<Self> {
        if format[2] > 1 || format[3] != 1 {
            return Err(invalid_data(
                "indexed-color pixel formats are not supported; true-color is required",
            ));
        }
        let parsed = Self {
            bits_per_pixel: format[0],
            depth: format[1],
            big_endian: format[2] != 0,
            red_max: u16::from_be_bytes([format[4], format[5]]),
            green_max: u16::from_be_bytes([format[6], format[7]]),
            blue_max: u16::from_be_bytes([format[8], format[9]]),
            red_shift: format[10],
            green_shift: format[11],
            blue_shift: format[12],
        };
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(self) -> io::Result<()> {
        if !matches!(self.bits_per_pixel, 8 | 16 | 32)
            || self.depth == 0
            || self.depth > self.bits_per_pixel
        {
            return Err(invalid_data("unsupported client pixel bit depth"));
        }

        let channels = [
            (self.red_max, self.red_shift),
            (self.green_max, self.green_shift),
            (self.blue_max, self.blue_shift),
        ];
        let mut used_bits = 0u32;
        for (maximum, shift) in channels {
            let channel_bits = u16::BITS - maximum.leading_zeros();
            if maximum == 0 || maximum != ((1u32 << channel_bits) - 1) as u16 {
                return Err(invalid_data(
                    "true-color channel maxima must be contiguous bit masks",
                ));
            }
            let end = u32::from(shift) + channel_bits;
            if end > u32::from(self.bits_per_pixel) {
                return Err(invalid_data("true-color channel exceeds pixel width"));
            }
            let mask = u32::from(maximum) << shift;
            if used_bits & mask != 0 {
                return Err(invalid_data("true-color channels overlap"));
            }
            used_bits |= mask;
        }
        // Some clients report a nominal depth that differs from the number
        // of channel bits. Channel maxima and shifts define the actual
        // packed value, so validate the layout rather than rejecting that
        // metadata mismatch. ZRLE still needs its omitted high byte unused.
        if self.bits_per_pixel == 32 && self.depth == 24 && used_bits & 0xff00_0000 != 0 {
            return Err(invalid_data(
                "32bpp/depth-24 formats must leave the most significant byte unused",
            ));
        }
        Ok(())
    }
}

fn scale_channel(value: u8, maximum: u16) -> u32 {
    (u32::from(value) * u32::from(maximum) + 127) / 255
}

/// Start the RFB listener thread.
///
/// The listener is put into non-blocking mode so shutdown can be observed
/// without needing a separate wake-up connection.
pub fn spawn(
    listener: TcpListener,
    store: Arc<FrameStore>,
    config: RfbConfig,
    shutdown: Arc<AtomicBool>,
    input_tx: Option<tokio::sync::mpsc::Sender<ClientEvent>>,
    clipboard_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> io::Result<JoinHandle<()>> {
    listener.set_nonblocking(true)?;

    thread::Builder::new()
        .name("rfb-listener".to_string())
        .spawn(move || run_listener(listener, store, config, shutdown, input_tx, clipboard_rx))
}

fn run_listener(
    listener: TcpListener,
    store: Arc<FrameStore>,
    config: RfbConfig,
    shutdown: Arc<AtomicBool>,
    input_tx: Option<tokio::sync::mpsc::Sender<ClientEvent>>,
    mut clipboard_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, address)) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }

                crate::timestamped_log!("rfb: client connected from {address}");
                if let Err(error) = configure_stream(&stream) {
                    crate::timestamped_log!("rfb: could not configure client socket: {error}");
                    continue;
                }

                store.client_connected();
                let result = handle_client(
                    stream,
                    &store,
                    &config,
                    &shutdown,
                    input_tx.as_ref(),
                    &mut clipboard_rx,
                );
                store.client_disconnected();

                match result {
                    Ok(()) => crate::timestamped_log!("rfb: client disconnected"),
                    Err(error) if is_normal_disconnect(&error) => {
                        crate::timestamped_log!("rfb: client disconnected: {error}");
                    }
                    Err(error) => crate::timestamped_log!("rfb: client error: {error}"),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                crate::timestamped_log!("rfb: accept failed: {error}");
                break;
            }
        }
    }
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(READ_POLL_INTERVAL))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.set_nodelay(true)?;
    Ok(())
}

fn handle_client(
    stream: TcpStream,
    store: &FrameStore,
    config: &RfbConfig,
    shutdown: &AtomicBool,
    input_tx: Option<&tokio::sync::mpsc::Sender<ClientEvent>>,
    clipboard_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let mut tcp_stream = stream;
    write_all_interruptible(&mut tcp_stream, RFB_VERSION, shutdown)?;

    let mut version = [0u8; 12];
    read_exact_interruptible(&mut tcp_stream, &mut version, shutdown)?;
    let version = parse_client_version(&version)?;

    let mut stream = match config.authentication.as_deref() {
        Some(AuthenticationConfig::VeNCrypt {
            tls,
            username,
            password,
        }) => {
            if version != RfbVersion::V3_8 {
                return Err(invalid_data("VeNCrypt authentication requires RFB 3.8"));
            }
            negotiate_vencrypt(tcp_stream, tls, username, password, shutdown)?
        }
        Some(AuthenticationConfig::Vnc { password }) => {
            negotiate_vnc_auth(&mut tcp_stream, version, password, shutdown)?;
            ClientStream::Plain(tcp_stream)
        }
        None => {
            match version {
                RfbVersion::V3_3 => {
                    write_all_interruptible(
                        &mut tcp_stream,
                        &SECURITY_TYPE_NONE.to_be_bytes(),
                        shutdown,
                    )?;
                }
                RfbVersion::V3_8 => {
                    write_all_interruptible(
                        &mut tcp_stream,
                        &[1, SECURITY_TYPE_NONE as u8],
                        shutdown,
                    )?;
                    let security_type = read_u8(&mut tcp_stream, shutdown)?;
                    if u32::from(security_type) != SECURITY_TYPE_NONE {
                        return Err(invalid_data(format!(
                            "client selected unsupported security type {security_type}"
                        )));
                    }
                    write_all_interruptible(&mut tcp_stream, &0u32.to_be_bytes(), shutdown)?;
                }
            }
            ClientStream::Plain(tcp_stream)
        }
    };

    // ClientInit: shared flag. The initial server supports one client, so the
    // flag does not change behavior.
    let _shared = read_u8(&mut stream, shutdown)?;

    write_server_init(
        &mut stream,
        config.width,
        config.height,
        &config.name,
        shutdown,
    )?;

    let mut update_state = ClientUpdateState {
        encoding: Encoding::Raw,
        copy_rect_enabled: false,
        pixel_format: PixelFormat::DEFAULT,
        last_sequence: 0,
        pending_damage: Vec::new(),
        pending_update: None,
        zrle_compressor: Compress::new(Compression::default(), true),
        zlib_compressor: Compress::new(Compression::default(), true),
        client_pixels: None,
    };
    let mut keyboard_input_warned = false;
    let mut pointer_input_warned = false;
    let mut received_button_mask = 0u8;
    let mut held_input = if config.input_enabled {
        input_tx.map(ClientInputGuard::new)
    } else {
        None
    };

    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        if update_state.pending_update.is_some() {
            service_pending_update(
                &mut stream,
                store,
                config.width,
                config.height,
                &mut update_state,
                shutdown,
            )?;
        }

        let Some(message_type) = read_message_type(&mut stream, shutdown, clipboard_rx)? else {
            continue;
        };
        match message_type {
            0 => {
                update_state.pixel_format = handle_set_pixel_format(&mut stream, shutdown)?;
                update_state.client_pixels = None;
                crate::timestamped_log!(
                    "rfb: client pixel format: {}bpp depth {} {}-endian, RGB max=({},{},{}), shifts=({},{},{})",
                    update_state.pixel_format.bits_per_pixel,
                    update_state.pixel_format.depth,
                    if update_state.pixel_format.big_endian {
                        "big"
                    } else {
                        "little"
                    },
                    update_state.pixel_format.red_max,
                    update_state.pixel_format.green_max,
                    update_state.pixel_format.blue_max,
                    update_state.pixel_format.red_shift,
                    update_state.pixel_format.green_shift,
                    update_state.pixel_format.blue_shift,
                );
            }
            2 => {
                let preferences =
                    handle_set_encodings(&mut stream, config.encodings.as_deref(), shutdown)?;
                update_state.encoding = preferences.preferred;
                if update_state.copy_rect_enabled != preferences.copy_rect {
                    update_state.client_pixels = None;
                }
                update_state.copy_rect_enabled = preferences.copy_rect;
                crate::timestamped_log!(
                    "rfb: selected framebuffer encoding: {:?}, CopyRect {}",
                    preferences.preferred,
                    if preferences.copy_rect {
                        "enabled"
                    } else {
                        "not offered"
                    },
                );
            }
            3 => {
                handle_update_request(
                    &mut stream,
                    store,
                    config.width,
                    config.height,
                    &mut update_state,
                    shutdown,
                )?;
            }
            4 => {
                let down = read_u8(&mut stream, shutdown)? != 0;
                let mut padding = [0u8; 2];
                read_exact_interruptible(&mut stream, &mut padding, shutdown)?;
                let keysym = read_u32(&mut stream, shutdown)?;
                // Avoid logging keysyms or typed values, but expose whether
                // ordinary keys (for example, the C in Ctrl+C) reach RFB.
                crate::timestamped_log!(
                    "rfb: received keyboard key {}",
                    if down { "pressed" } else { "released" }
                );
                if is_modifier_keysym(keysym) {
                    crate::timestamped_log!(
                        "rfb: received modifier keysym {keysym:#x} {}",
                        if down { "down" } else { "up" }
                    );
                }
                if down && is_ascii_control_keysym(keysym) {
                    crate::timestamped_log!(
                        "rfb: received an ASCII control-character keysym (value redacted)"
                    );
                }
                if keysym > i32::MAX as u32 {
                    return Err(invalid_data(format!(
                        "RFB keysym {keysym:#x} exceeds the portal keysym range"
                    )));
                }
                if let Some(held_input) = &mut held_input {
                    held_input.key(keysym, down)?;
                } else if !keyboard_input_warned {
                    crate::timestamped_log!("rfb: keyboard input is disabled; event ignored");
                    keyboard_input_warned = true;
                }
            }
            5 => {
                // PointerEvent: button-mask (1), padding (2), x (2), y (2).
                let mut event = [0u8; 5];
                read_exact_interruptible(&mut stream, &mut event, shutdown)?;
                let buttons = event[0];
                let x = u16::from_be_bytes([event[1], event[2]]);
                let y = u16::from_be_bytes([event[3], event[4]]);
                if buttons != received_button_mask {
                    crate::timestamped_log!(
                        "rfb: received pointer button mask {received_button_mask:#04x} -> {buttons:#04x}"
                    );
                    received_button_mask = buttons;
                }
                if let Some(held_input) = &mut held_input {
                    held_input.pointer(x, y, buttons)?;
                } else if !pointer_input_warned {
                    crate::timestamped_log!("rfb: pointer input is disabled; event ignored");
                    pointer_input_warned = true;
                }
            }
            6 => {
                let mut padding = [0u8; 3];
                read_exact_interruptible(&mut stream, &mut padding, shutdown)?;
                let length = read_u32(&mut stream, shutdown)?;
                if length > MAX_CUT_TEXT {
                    return Err(invalid_data(format!(
                        "client cut text length {length} exceeds the limit"
                    )));
                }
                if config.clipboard_enabled {
                    let input_tx = input_tx.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "clipboard handler unavailable")
                    })?;
                    let mut text = vec![0u8; length as usize];
                    read_exact_interruptible(&mut stream, &mut text, shutdown)?;
                    crate::timestamped_log!("rfb: received ClientCutText ({} bytes)", text.len());
                    input_tx
                        .blocking_send(ClientEvent::Clipboard(text))
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::BrokenPipe, "input handler stopped")
                        })?;
                } else {
                    discard_exact(&mut stream, length as usize, shutdown)?;
                }
            }
            other => {
                return Err(invalid_data(format!(
                    "unsupported client message type {other}"
                )));
            }
        }
    }
}

fn negotiate_vencrypt(
    mut tcp_stream: TcpStream,
    tls: &Arc<rustls::ServerConfig>,
    expected_username: &[u8],
    expected_password: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<ClientStream> {
    write_all_interruptible(&mut tcp_stream, &[1, SECURITY_TYPE_VENCRYPT], shutdown)?;
    if read_u8(&mut tcp_stream, shutdown)? != SECURITY_TYPE_VENCRYPT {
        return Err(invalid_data(
            "client did not select VeNCrypt authentication",
        ));
    }

    write_all_interruptible(&mut tcp_stream, &[0, 2], shutdown)?;
    let mut client_version = [0u8; 2];
    read_exact_interruptible(&mut tcp_stream, &mut client_version, shutdown)?;
    if client_version != [0, 2] {
        return Err(invalid_data(
            "client selected an unsupported VeNCrypt version",
        ));
    }
    write_all_interruptible(&mut tcp_stream, &[0], shutdown)?;
    write_all_interruptible(&mut tcp_stream, &[1], shutdown)?;
    write_all_interruptible(
        &mut tcp_stream,
        &VENCRYPT_SUBTYPE_X509_PLAIN.to_be_bytes(),
        shutdown,
    )?;
    if read_u32(&mut tcp_stream, shutdown)? != VENCRYPT_SUBTYPE_X509_PLAIN {
        write_all_interruptible(&mut tcp_stream, &[0], shutdown)?;
        return Err(invalid_data("client did not select VeNCrypt X509Plain"));
    }
    write_all_interruptible(&mut tcp_stream, &[1], shutdown)?;

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

    let mut stream = ClientStream::Tls(Box::new(rustls::StreamOwned::new(connection, tcp_stream)));
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
    write_auth_result(&mut stream, authenticated, true, shutdown)?;
    if !authenticated {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VeNCrypt credentials rejected",
        ));
    }
    Ok(stream)
}

fn negotiate_vnc_auth(
    stream: &mut TcpStream,
    version: RfbVersion,
    password: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
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

fn vnc_auth_response(password: &[u8], challenge: &[u8; 16]) -> io::Result<[u8; 16]> {
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

fn write_server_init(
    stream: &mut (impl Read + Write),
    width: u16,
    height: u16,
    name: &str,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    write_all_interruptible(stream, &width.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, &height.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, &server_pixel_format(), shutdown)?;

    let name_bytes = name.as_bytes();
    let name_len = u32::try_from(name_bytes.len())
        .map_err(|_| invalid_data("server name is too long for RFB"))?;
    write_all_interruptible(stream, &name_len.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, name_bytes, shutdown)?;
    Ok(())
}

fn handle_set_pixel_format(
    stream: &mut (impl Read + Write),
    shutdown: &AtomicBool,
) -> io::Result<PixelFormat> {
    let mut padding = [0u8; 3];
    read_exact_interruptible(stream, &mut padding, shutdown)?;

    let mut format = [0u8; 16];
    read_exact_interruptible(stream, &mut format, shutdown)?;
    PixelFormat::from_wire(&format)
}

fn handle_set_encodings(
    stream: &mut (impl Read + Write),
    allowed: Option<&[RfbEncoding]>,
    shutdown: &AtomicBool,
) -> io::Result<EncodingPreferences> {
    let mut padding = [0u8; 1];
    read_exact_interruptible(stream, &mut padding, shutdown)?;

    let count = read_u16(stream, shutdown)?;
    if count > MAX_ENCODINGS {
        return Err(invalid_data(format!(
            "client advertised {count} encodings; limit is {MAX_ENCODINGS}"
        )));
    }

    let mut encodings = vec![0u8; count as usize * 4];
    read_exact_interruptible(stream, &mut encodings, shutdown)?;

    select_encodings_with_allowlist(&encodings, allowed)
}

#[cfg(test)]
fn select_encodings(encodings: &[u8]) -> io::Result<EncodingPreferences> {
    select_encodings_with_allowlist(encodings, None)
}

fn select_encodings_with_allowlist(
    encodings: &[u8],
    allowed: Option<&[RfbEncoding]>,
) -> io::Result<EncodingPreferences> {
    let mut preferred = None;
    let mut copy_rect = false;
    for encoding in encodings.chunks_exact(4) {
        let value = i32::from_be_bytes([encoding[0], encoding[1], encoding[2], encoding[3]]);
        let candidate = match value {
            ENCODING_COPY_RECT => {
                copy_rect =
                    allowed.is_none_or(|encodings| encodings.contains(&RfbEncoding::CopyRect));
                None
            }
            ENCODING_HEXTILE => Some(Encoding::Hextile),
            ENCODING_ZLIB => Some(Encoding::Zlib),
            ENCODING_ZRLE => Some(Encoding::Zrle),
            ENCODING_RAW => Some(Encoding::Raw),
            _ => None,
        };
        let candidate_allowed = match candidate {
            Some(Encoding::Raw) => {
                allowed.is_none_or(|encodings| encodings.contains(&RfbEncoding::Raw))
            }
            Some(Encoding::Hextile) => {
                allowed.is_none_or(|encodings| encodings.contains(&RfbEncoding::Hextile))
            }
            Some(Encoding::Zlib) => {
                allowed.is_none_or(|encodings| encodings.contains(&RfbEncoding::Zlib))
            }
            Some(Encoding::Zrle) => {
                allowed.is_none_or(|encodings| encodings.contains(&RfbEncoding::Zrle))
            }
            None => false,
        };
        if preferred.is_none() && candidate_allowed {
            preferred = candidate;
        }
    }
    preferred
        .or_else(|| {
            allowed
                .is_some_and(|encodings| encodings.contains(&RfbEncoding::Raw))
                .then_some(Encoding::Raw)
        })
        .map(|preferred| EncodingPreferences {
            preferred,
            copy_rect,
        })
        .ok_or_else(|| invalid_data("client did not offer a supported framebuffer encoding"))
}

fn handle_update_request(
    stream: &mut (impl Read + Write),
    store: &FrameStore,
    width: u16,
    height: u16,
    state: &mut ClientUpdateState,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let incremental = read_u8(stream, shutdown)? != 0;
    let x = read_u16(stream, shutdown)?;
    let y = read_u16(stream, shutdown)?;
    let rectangle_width = read_u16(stream, shutdown)?;
    let rectangle_height = read_u16(stream, shutdown)?;

    validate_rectangle(x, y, rectangle_width, rectangle_height, width, height)?;

    let requested = DamageRect {
        x: u32::from(x),
        y: u32::from(y),
        width: u32::from(rectangle_width),
        height: u32::from(rectangle_height),
    };

    if state.pending_update.take().is_some() {
        // A client should normally wait for its outstanding incremental
        // request, but finish the previous request safely if it pipelines one.
        send_empty_update(stream, shutdown)?;
    }

    if !incremental {
        let changes = match store.changes_since(state.last_sequence) {
            Some(changes) => changes,
            None => match store.latest() {
                Some((sequence, frame)) => crate::framebuffer::FrameChanges {
                    sequence,
                    frame,
                    damage: FrameDamage::Regions(Vec::new()),
                },
                None => match wait_for_frame(store, 0, INITIAL_FRAME_TIMEOUT, shutdown)? {
                    Some(changes) => changes,
                    None => return send_empty_update(stream, shutdown),
                },
            },
        };
        ensure_frame_dimensions(&changes.frame, width, height)?;
        accumulate_damage(
            &mut state.pending_damage,
            changes.damage,
            u32::from(width),
            u32::from(height),
        );
        state.last_sequence = changes.sequence;

        let updates = vec![requested];
        send_update(stream, &changes.frame, &updates, state, shutdown)?;
        subtract_damage(&mut state.pending_damage, requested);
        return Ok(());
    }

    state.pending_update = Some(requested);
    service_pending_update(stream, store, width, height, state, shutdown)
}

fn service_pending_update(
    stream: &mut (impl Read + Write),
    store: &FrameStore,
    width: u16,
    height: u16,
    state: &mut ClientUpdateState,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let requested = match state.pending_update {
        Some(requested) => requested,
        None => return Ok(()),
    };

    let changed_frame = if let Some(changes) = store.changes_since(state.last_sequence) {
        ensure_frame_dimensions(&changes.frame, width, height)?;
        accumulate_damage(
            &mut state.pending_damage,
            changes.damage,
            u32::from(width),
            u32::from(height),
        );
        state.last_sequence = changes.sequence;
        Some(changes.frame)
    } else {
        None
    };

    let updates = damage_within(&state.pending_damage, requested);
    if updates.is_empty() {
        return Ok(());
    }

    let updates = bounded_updates(updates, requested);
    let frame = match changed_frame {
        Some(frame) => frame,
        None => store
            .latest()
            .map(|(_, frame)| frame)
            .ok_or_else(|| invalid_data("framebuffer is unavailable"))?,
    };
    ensure_frame_dimensions(&frame, width, height)?;
    send_update(stream, &frame, &updates, state, shutdown)?;
    subtract_damage(&mut state.pending_damage, requested);
    state.pending_update = None;
    Ok(())
}

fn wait_for_frame(
    store: &FrameStore,
    last_sequence: u64,
    timeout: Duration,
    shutdown: &AtomicBool,
) -> io::Result<Option<crate::framebuffer::FrameChanges>> {
    let deadline = Instant::now() + timeout;

    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        if let Some(changes) = store.changes_since(last_sequence) {
            return Ok(Some(changes));
        }

        let _ = store.wait_next(last_sequence, WAIT_SLICE);

        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

fn ensure_frame_dimensions(frame: &Frame, width: u16, height: u16) -> io::Result<()> {
    if frame.width != u32::from(width) || frame.height != u32::from(height) {
        return Err(invalid_data(format!(
            "captured frame is {}x{}, but the RFB session is {}x{}",
            frame.width, frame.height, width, height
        )));
    }
    Ok(())
}

fn accumulate_damage(
    pending: &mut Vec<DamageRect>,
    damage: FrameDamage,
    frame_width: u32,
    frame_height: u32,
) {
    match damage {
        FrameDamage::Full => {
            pending.clear();
            pending.push(DamageRect {
                x: 0,
                y: 0,
                width: frame_width,
                height: frame_height,
            });
        }
        FrameDamage::Regions(regions) => {
            if pending.len().saturating_add(regions.len()) > MAX_UPDATE_RECTS {
                pending.clear();
                pending.push(DamageRect {
                    x: 0,
                    y: 0,
                    width: frame_width,
                    height: frame_height,
                });
                return;
            }
            pending.extend(regions.into_iter().filter_map(|rect| {
                intersection(
                    rect,
                    DamageRect {
                        x: 0,
                        y: 0,
                        width: frame_width,
                        height: frame_height,
                    },
                )
            }));
        }
    }
    merge_rectangles(pending);
}

fn damage_within(pending: &[DamageRect], requested: DamageRect) -> Vec<DamageRect> {
    let mut updates: Vec<_> = pending
        .iter()
        .filter_map(|rect| intersection(*rect, requested))
        .collect();
    merge_rectangles(&mut updates);
    updates
}

fn bounded_updates(mut updates: Vec<DamageRect>, requested: DamageRect) -> Vec<DamageRect> {
    if updates.len() > MAX_UPDATE_RECTS {
        updates.clear();
        updates.push(requested);
    }
    updates
}

fn subtract_damage(pending: &mut Vec<DamageRect>, served: DamageRect) {
    let mut remainder = Vec::with_capacity(pending.len().saturating_mul(2));
    for rect in pending.drain(..) {
        let Some(overlap) = intersection(rect, served) else {
            remainder.push(rect);
            continue;
        };

        let rect_right = rect.x + rect.width;
        let rect_bottom = rect.y + rect.height;
        let overlap_right = overlap.x + overlap.width;
        let overlap_bottom = overlap.y + overlap.height;

        if overlap.y > rect.y {
            remainder.push(DamageRect {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: overlap.y - rect.y,
            });
        }
        if overlap_bottom < rect_bottom {
            remainder.push(DamageRect {
                x: rect.x,
                y: overlap_bottom,
                width: rect.width,
                height: rect_bottom - overlap_bottom,
            });
        }
        if overlap.x > rect.x {
            remainder.push(DamageRect {
                x: rect.x,
                y: overlap.y,
                width: overlap.x - rect.x,
                height: overlap.height,
            });
        }
        if overlap_right < rect_right {
            remainder.push(DamageRect {
                x: overlap_right,
                y: overlap.y,
                width: rect_right - overlap_right,
                height: overlap.height,
            });
        }
    }
    *pending = remainder;
    merge_rectangles(pending);
}

fn intersection(left: DamageRect, right: DamageRect) -> Option<DamageRect> {
    let x = left.x.max(right.x);
    let y = left.y.max(right.y);
    let right_edge = left
        .x
        .checked_add(left.width)?
        .min(right.x.checked_add(right.width)?);
    let bottom_edge = left
        .y
        .checked_add(left.height)?
        .min(right.y.checked_add(right.height)?);
    if x >= right_edge || y >= bottom_edge {
        return None;
    }
    Some(DamageRect {
        x,
        y,
        width: right_edge - x,
        height: bottom_edge - y,
    })
}

fn merge_rectangles(rectangles: &mut Vec<DamageRect>) {
    let mut index = 0;
    while index < rectangles.len() {
        let mut other = index + 1;
        while other < rectangles.len() {
            if intersection(rectangles[index], rectangles[other]).is_some() {
                let left = rectangles[index];
                let right = rectangles.remove(other);
                let x = left.x.min(right.x);
                let y = left.y.min(right.y);
                let right_edge = (left.x + left.width).max(right.x + right.width);
                let bottom_edge = (left.y + left.height).max(right.y + right.height);
                rectangles[index] = DamageRect {
                    x,
                    y,
                    width: right_edge - x,
                    height: bottom_edge - y,
                };
                other = index + 1;
            } else {
                other += 1;
            }
        }
        index += 1;
    }
}

fn send_update(
    stream: &mut (impl Read + Write),
    frame: &Frame,
    rectangles: &[DamageRect],
    state: &mut ClientUpdateState,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let frame_width = frame.width as usize;
    let frame_height = frame.height as usize;
    if rectangles.len() > MAX_UPDATE_RECTS {
        return Err(invalid_data("too many rectangles in framebuffer update"));
    }

    let mut header = [0u8; 4];
    header[0] = 0; // FramebufferUpdate
    header[1] = 0; // padding
    header[2..4].copy_from_slice(&(rectangles.len() as u16).to_be_bytes());
    write_all_interruptible(stream, &header, shutdown)?;

    for rect in rectangles {
        let right = rect
            .x
            .checked_add(rect.width)
            .ok_or_else(|| invalid_data("rectangle overflows"))?;
        let bottom = rect
            .y
            .checked_add(rect.height)
            .ok_or_else(|| invalid_data("rectangle overflows"))?;
        if rect.width == 0
            || rect.height == 0
            || right > frame.width
            || bottom > frame.height
            || right > frame_width as u32
            || bottom > frame_height as u32
        {
            return Err(invalid_data("rectangle is outside the framebuffer"));
        }

        let x = u16::try_from(rect.x).map_err(|_| invalid_data("rectangle x exceeds RFB limit"))?;
        let y = u16::try_from(rect.y).map_err(|_| invalid_data("rectangle y exceeds RFB limit"))?;
        let width = u16::try_from(rect.width)
            .map_err(|_| invalid_data("rectangle width exceeds RFB limit"))?;
        let height = u16::try_from(rect.height)
            .map_err(|_| invalid_data("rectangle height exceeds RFB limit"))?;

        let copy_source = if state.copy_rect_enabled {
            state
                .client_pixels
                .as_deref()
                .and_then(|shadow| find_copy_source(frame, shadow, *rect, state.pixel_format))
        } else {
            None
        };
        let rectangle_encoding = if copy_source.is_some() {
            ENCODING_COPY_RECT
        } else {
            state.encoding.rfb_value()
        };
        let mut rectangle_header = [0u8; 12];
        rectangle_header[0..2].copy_from_slice(&x.to_be_bytes());
        rectangle_header[2..4].copy_from_slice(&y.to_be_bytes());
        rectangle_header[4..6].copy_from_slice(&width.to_be_bytes());
        rectangle_header[6..8].copy_from_slice(&height.to_be_bytes());
        rectangle_header[8..12].copy_from_slice(&rectangle_encoding.to_be_bytes());
        write_all_interruptible(stream, &rectangle_header, shutdown)?;

        if let Some((source_x, source_y)) = copy_source {
            write_all_interruptible(stream, &source_x.to_be_bytes(), shutdown)?;
            write_all_interruptible(stream, &source_y.to_be_bytes(), shutdown)?;
            if state.copy_rect_enabled {
                update_client_shadow(frame, *rect, state.pixel_format, &mut state.client_pixels)?;
            }
            continue;
        }

        if state.encoding == Encoding::Hextile {
            send_hextile_rectangle(stream, frame, *rect, state.pixel_format, shutdown)?;
            if state.copy_rect_enabled {
                update_client_shadow(frame, *rect, state.pixel_format, &mut state.client_pixels)?;
            }
            continue;
        }

        if state.encoding == Encoding::Zrle {
            send_zrle_rectangle(
                stream,
                frame,
                *rect,
                state.pixel_format,
                &mut state.zrle_compressor,
                shutdown,
            )?;
            if state.copy_rect_enabled {
                update_client_shadow(frame, *rect, state.pixel_format, &mut state.client_pixels)?;
            }
            continue;
        }

        if state.encoding == Encoding::Zlib {
            send_zlib_rectangle(
                stream,
                frame,
                *rect,
                state.pixel_format,
                &mut state.zlib_compressor,
                shutdown,
            )?;
            if state.copy_rect_enabled {
                update_client_shadow(frame, *rect, state.pixel_format, &mut state.client_pixels)?;
            }
            continue;
        }

        send_raw_rectangle(stream, frame, *rect, state.pixel_format, shutdown)?;
        if state.copy_rect_enabled {
            update_client_shadow(frame, *rect, state.pixel_format, &mut state.client_pixels)?;
        }
    }

    Ok(())
}

fn send_raw_rectangle(
    stream: &mut (impl Read + Write),
    frame: &Frame,
    rectangle: DamageRect,
    pixel_format: PixelFormat,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let bytes_per_pixel = pixel_format.bytes_per_pixel();
    let row_capacity = usize::try_from(rectangle.width)
        .ok()
        .and_then(|width| width.checked_mul(bytes_per_pixel))
        .ok_or_else(|| invalid_data("raw rectangle size overflows"))?;
    for y in rectangle.y..rectangle.y + rectangle.height {
        if pixel_format == PixelFormat::DEFAULT {
            let start = (y as usize)
                .checked_mul(frame.width as usize)
                .and_then(|row| row.checked_add(rectangle.x as usize))
                .and_then(|pixel| pixel.checked_mul(4))
                .ok_or_else(|| invalid_data("raw rectangle offset overflows"))?;
            let end = start
                .checked_add(row_capacity)
                .ok_or_else(|| invalid_data("raw rectangle offset overflows"))?;
            let row = frame
                .data
                .get(start..end)
                .ok_or_else(|| invalid_data("raw rectangle is outside the framebuffer"))?;
            write_all_interruptible(stream, row, shutdown)?;
            continue;
        }
        let mut row = Vec::with_capacity(row_capacity);
        for x in rectangle.x..rectangle.x + rectangle.width {
            let bgra = frame_pixel(frame, x, y)?;
            row.extend_from_slice(&pixel_format.encode(&bgra)[..bytes_per_pixel]);
        }
        write_all_interruptible(stream, &row, shutdown)?;
    }
    Ok(())
}

fn update_client_shadow(
    frame: &Frame,
    rectangle: DamageRect,
    pixel_format: PixelFormat,
    shadow: &mut Option<Vec<[u8; 4]>>,
) -> io::Result<()> {
    let frame_width = frame.width as usize;
    let frame_height = frame.height as usize;
    if shadow.is_none()
        && rectangle.x == 0
        && rectangle.y == 0
        && rectangle.width == frame.width
        && rectangle.height == frame.height
    {
        let capacity = frame_width
            .checked_mul(frame_height)
            .ok_or_else(|| invalid_data("client framebuffer shadow size overflows"))?;
        let mut initial = Vec::new();
        initial.try_reserve_exact(capacity).map_err(|error| {
            io::Error::other(format!(
                "could not allocate client framebuffer shadow: {error}"
            ))
        })?;
        for y in 0..frame.height {
            for x in 0..frame.width {
                initial.push(encoded_frame_pixel(frame, x, y, pixel_format)?);
            }
        }
        *shadow = Some(initial);
        return Ok(());
    }

    let Some(shadow) = shadow else {
        return Ok(());
    };
    for y in rectangle.y..rectangle.y + rectangle.height {
        for x in rectangle.x..rectangle.x + rectangle.width {
            let index = (y as usize)
                .checked_mul(frame_width)
                .and_then(|row| row.checked_add(x as usize))
                .ok_or_else(|| invalid_data("client framebuffer shadow offset overflows"))?;
            let slot = shadow
                .get_mut(index)
                .ok_or_else(|| invalid_data("client framebuffer shadow is incomplete"))?;
            *slot = encoded_frame_pixel(frame, x, y, pixel_format)?;
        }
    }
    Ok(())
}

fn find_copy_source(
    frame: &Frame,
    shadow: &[[u8; 4]],
    rectangle: DamageRect,
    pixel_format: PixelFormat,
) -> Option<(u16, u16)> {
    const SEARCH_RADIUS: i32 = 128;
    const MAX_CANDIDATES: usize = 65_536;
    const MAX_COMPARE_PIXELS: usize = 1_000_000;

    let frame_width = frame.width as usize;
    let frame_height = frame.height as usize;
    if shadow.len() != frame_width.checked_mul(frame_height)? {
        return None;
    }
    let area = usize::try_from(rectangle.width)
        .ok()?
        .checked_mul(rectangle.height as usize)?;
    if area == 0 || area > MAX_COMPARE_PIXELS {
        return None;
    }

    let last_x = frame.width.checked_sub(rectangle.width)?;
    let last_y = frame.height.checked_sub(rectangle.height)?;
    let destination_pixel =
        encoded_frame_pixel(frame, rectangle.x, rectangle.y, pixel_format).ok()?;
    let mut tested = 0usize;
    let mut comparison_budget = MAX_COMPARE_PIXELS;

    for radius in 1..=SEARCH_RADIUS {
        for offset_y in -radius..=radius {
            for offset_x in -radius..=radius {
                if offset_x.abs().max(offset_y.abs()) != radius {
                    continue;
                }
                let source_x = i64::from(rectangle.x) + i64::from(offset_x);
                let source_y = i64::from(rectangle.y) + i64::from(offset_y);
                if source_x < 0 || source_y < 0 {
                    continue;
                }
                let (source_x, source_y) = (source_x as u32, source_y as u32);
                if source_x > last_x
                    || source_y > last_y
                    || (source_x == rectangle.x && source_y == rectangle.y)
                {
                    continue;
                }
                let source_right = source_x + rectangle.width;
                let source_bottom = source_y + rectangle.height;
                let destination_right = rectangle.x + rectangle.width;
                let destination_bottom = rectangle.y + rectangle.height;
                if source_x < destination_right
                    && source_right > rectangle.x
                    && source_y < destination_bottom
                    && source_bottom > rectangle.y
                {
                    // Overlapping copies have client-dependent behavior; use
                    // the negotiated pixel encoding rather than risk a smear.
                    continue;
                }
                tested += 1;
                if tested > MAX_CANDIDATES {
                    return None;
                }
                let source_index = (source_y as usize)
                    .checked_mul(frame_width)?
                    .checked_add(source_x as usize)?;
                if shadow.get(source_index).copied()? != destination_pixel {
                    continue;
                }
                if area > comparison_budget {
                    return None;
                }
                comparison_budget -= area;

                let mut matches = true;
                'pixels: for row in 0..rectangle.height {
                    let target_y = rectangle.y + row;
                    let source_row = (source_y + row) as usize * frame_width + source_x as usize;
                    for column in 0..rectangle.width {
                        let target = encoded_frame_pixel(
                            frame,
                            rectangle.x + column,
                            target_y,
                            pixel_format,
                        )
                        .ok()?;
                        if shadow[source_row + column as usize] != target {
                            matches = false;
                            break 'pixels;
                        }
                    }
                }
                if matches {
                    return Some((u16::try_from(source_x).ok()?, u16::try_from(source_y).ok()?));
                }
            }
        }
    }
    None
}

fn encode_rectangle_pixels(
    frame: &Frame,
    rectangle: DamageRect,
    pixel_format: PixelFormat,
) -> io::Result<Vec<u8>> {
    let bytes_per_pixel = pixel_format.bytes_per_pixel();
    let capacity = usize::try_from(rectangle.width)
        .ok()
        .and_then(|width| width.checked_mul(rectangle.height as usize))
        .and_then(|pixels| pixels.checked_mul(bytes_per_pixel))
        .ok_or_else(|| invalid_data("encoded rectangle size overflows"))?;
    let mut pixels = Vec::new();
    pixels.try_reserve_exact(capacity).map_err(|error| {
        io::Error::other(format!("could not allocate encoded rectangle: {error}"))
    })?;
    for y in rectangle.y..rectangle.y + rectangle.height {
        for x in rectangle.x..rectangle.x + rectangle.width {
            let bgra = frame_pixel(frame, x, y)?;
            pixels.extend_from_slice(&pixel_format.encode(&bgra)[..bytes_per_pixel]);
        }
    }
    Ok(pixels)
}

fn send_zlib_rectangle(
    stream: &mut (impl Read + Write),
    frame: &Frame,
    rectangle: DamageRect,
    pixel_format: PixelFormat,
    compressor: &mut Compress,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let pixels = encode_rectangle_pixels(frame, rectangle, pixel_format)?;
    let compressed = compress_sync(compressor, &pixels)?;
    let length = u32::try_from(compressed.len())
        .map_err(|_| invalid_data("compressed Zlib rectangle exceeds RFB limit"))?;
    write_all_interruptible(stream, &length.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, &compressed, shutdown)
}

fn compress_sync(compressor: &mut Compress, input: &[u8]) -> io::Result<Vec<u8>> {
    compress_sync_with_buffer_size(compressor, input, 8192)
}

fn compress_sync_with_buffer_size(
    compressor: &mut Compress,
    input: &[u8],
    buffer_size: usize,
) -> io::Result<Vec<u8>> {
    if buffer_size == 0 {
        return Err(invalid_data("zlib output buffer cannot be empty"));
    }
    let mut compressed = Vec::new();
    let mut input_offset = 0;
    loop {
        let mut output = vec![0u8; buffer_size];
        let input_before = compressor.total_in();
        let output_before = compressor.total_out();
        let status = compressor
            .compress(&input[input_offset..], &mut output, FlushCompress::Sync)
            .map_err(|error| io::Error::other(format!("zlib compression failed: {error}")))?;
        let consumed = usize::try_from(compressor.total_in() - input_before)
            .map_err(|_| invalid_data("zlib compressor input count overflowed"))?;
        input_offset = input_offset
            .checked_add(consumed)
            .ok_or_else(|| invalid_data("zlib input offset overflows"))?;
        let produced = usize::try_from(compressor.total_out() - output_before)
            .map_err(|_| invalid_data("zlib compressor output count overflowed"))?;
        if produced > output.len() {
            return Err(invalid_data("zlib compressor exceeded its output buffer"));
        }
        compressed.try_reserve(produced).map_err(|error| {
            io::Error::other(format!("could not allocate compressed rectangle: {error}"))
        })?;
        compressed.extend_from_slice(&output[..produced]);
        if input_offset == input.len() && status == Status::Ok && produced < output.len() {
            return Ok(compressed);
        }
        if consumed == 0 && produced == 0 {
            return Err(invalid_data("zlib compressor made no progress"));
        }
    }
}

fn send_zrle_rectangle(
    stream: &mut (impl Read + Write),
    frame: &Frame,
    rectangle: DamageRect,
    pixel_format: PixelFormat,
    compressor: &mut Compress,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let right = rectangle
        .x
        .checked_add(rectangle.width)
        .ok_or_else(|| invalid_data("ZRLE rectangle overflows"))?;
    let bottom = rectangle
        .y
        .checked_add(rectangle.height)
        .ok_or_else(|| invalid_data("ZRLE rectangle overflows"))?;
    let tile_count = rectangle
        .width
        .div_ceil(64)
        .checked_mul(rectangle.height.div_ceil(64))
        .ok_or_else(|| invalid_data("ZRLE tile count overflows"))?;
    let pixel_count = rectangle
        .width
        .checked_mul(rectangle.height)
        .ok_or_else(|| invalid_data("ZRLE pixel count overflows"))?;
    let c_pixel_size = pixel_format.zrle_bytes_per_pixel();
    let capacity = usize::try_from(pixel_count)
        .ok()
        .and_then(|pixels| pixels.checked_mul(c_pixel_size))
        .and_then(|bytes| bytes.checked_add(tile_count as usize))
        .ok_or_else(|| invalid_data("ZRLE rectangle size overflows"))?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(capacity)
        .map_err(|error| io::Error::other(format!("could not allocate ZRLE rectangle: {error}")))?;

    for tile_y in (rectangle.y..bottom).step_by(64) {
        let tile_height = (bottom - tile_y).min(64);
        for tile_x in (rectangle.x..right).step_by(64) {
            let tile_width = (right - tile_x).min(64);
            // ZRLE subencoding 0 is Raw.
            raw.push(0);
            for y in tile_y..tile_y + tile_height {
                for x in tile_x..tile_x + tile_width {
                    let bgra = frame_pixel(frame, x, y)?;
                    let encoded = pixel_format.encode_zrle(&bgra);
                    raw.extend_from_slice(&encoded[..c_pixel_size]);
                }
            }
        }
    }

    let compressed = compress_sync(compressor, &raw)?;

    let compressed_len = u32::try_from(compressed.len())
        .map_err(|_| invalid_data("compressed ZRLE rectangle exceeds RFB limit"))?;
    write_all_interruptible(stream, &compressed_len.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, &compressed, shutdown)
}

#[derive(Clone, Copy)]
struct HextileSubrect {
    x: u8,
    y: u8,
    width: u8,
    height: u8,
    color: [u8; 4],
}

#[derive(Clone, Copy)]
struct HextileTile {
    x: u32,
    y: u32,
    width: u8,
    height: u8,
}

fn send_hextile_rectangle(
    stream: &mut (impl Read + Write),
    frame: &Frame,
    rectangle: DamageRect,
    pixel_format: PixelFormat,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let right = rectangle.x + rectangle.width;
    let bottom = rectangle.y + rectangle.height;

    for tile_y in (rectangle.y..bottom).step_by(16) {
        let tile_height = (bottom - tile_y).min(16) as u8;
        for tile_x in (rectangle.x..right).step_by(16) {
            let tile_width = (right - tile_x).min(16) as u8;
            send_hextile_tile(
                stream,
                frame,
                HextileTile {
                    x: tile_x,
                    y: tile_y,
                    width: tile_width,
                    height: tile_height,
                },
                pixel_format,
                shutdown,
            )?;
        }
    }

    Ok(())
}

fn send_hextile_tile(
    stream: &mut (impl Read + Write),
    frame: &Frame,
    tile: HextileTile,
    pixel_format: PixelFormat,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    const BACKGROUND_SPECIFIED: u8 = 2;
    const FOREGROUND_SPECIFIED: u8 = 4;
    const ANY_SUBRECTS: u8 = 8;
    const SUBRECTS_COLOURED: u8 = 16;

    let HextileTile {
        x: tile_x,
        y: tile_y,
        width: tile_width,
        height: tile_height,
    } = tile;
    let bytes_per_pixel = pixel_format.bytes_per_pixel();
    let mut frequencies = HashMap::<[u8; 4], usize>::with_capacity(16);
    let mut background = [0u8; 4];
    let mut most_frequent = 0usize;
    for y in 0..u32::from(tile_height) {
        for x in 0..u32::from(tile_width) {
            let color = encoded_frame_pixel(frame, tile_x + x, tile_y + y, pixel_format)?;
            let count = frequencies.entry(color).or_default();
            *count += 1;
            if *count > most_frequent {
                most_frequent = *count;
                background = color;
            }
        }
    }

    let mut subrects = Vec::<HextileSubrect>::new();
    for y in 0..tile_height {
        let mut x = 0u8;
        while x < tile_width {
            let color = encoded_frame_pixel(
                frame,
                tile_x + u32::from(x),
                tile_y + u32::from(y),
                pixel_format,
            )?;
            if color == background {
                x += 1;
                continue;
            }

            let run_start = x;
            x += 1;
            while x < tile_width
                && encoded_frame_pixel(
                    frame,
                    tile_x + u32::from(x),
                    tile_y + u32::from(y),
                    pixel_format,
                )? == color
            {
                x += 1;
            }
            let run_width = x - run_start;

            if let Some(previous) = subrects.iter_mut().rev().find(|candidate| {
                candidate.x == run_start
                    && candidate.width == run_width
                    && candidate.color == color
                    && candidate.y + candidate.height == y
            }) {
                previous.height += 1;
            } else {
                if subrects.len() == u8::MAX as usize {
                    return send_raw_hextile_tile(stream, frame, tile, pixel_format, shutdown);
                }
                subrects.push(HextileSubrect {
                    x: run_start,
                    y,
                    width: run_width,
                    height: 1,
                    color,
                });
            }
        }
    }

    let foreground = subrects.first().map(|subrect| subrect.color);
    let single_foreground =
        foreground.is_some_and(|color| subrects.iter().all(|subrect| subrect.color == color));
    let bytes_per_subrect = if single_foreground { 2 } else { 6 };
    let encoded_size = 1
        + 4
        + usize::from(!subrects.is_empty())
        + subrects.len() * bytes_per_subrect
        + if single_foreground { 4 } else { 0 };
    let raw_size = 1 + usize::from(tile_width) * usize::from(tile_height) * bytes_per_pixel;

    if !subrects.is_empty() && encoded_size >= raw_size {
        return send_raw_hextile_tile(stream, frame, tile, pixel_format, shutdown);
    }

    let mut flags = BACKGROUND_SPECIFIED;
    if !subrects.is_empty() {
        flags |= ANY_SUBRECTS;
        if single_foreground {
            flags |= FOREGROUND_SPECIFIED;
        } else {
            flags |= SUBRECTS_COLOURED;
        }
    }
    write_all_interruptible(stream, &[flags], shutdown)?;
    write_all_interruptible(stream, &background[..bytes_per_pixel], shutdown)?;

    if !subrects.is_empty() {
        if single_foreground {
            write_all_interruptible(
                stream,
                &foreground.unwrap_or([0; 4])[..bytes_per_pixel],
                shutdown,
            )?;
        }
        write_all_interruptible(stream, &[subrects.len() as u8], shutdown)?;
        for subrect in subrects {
            write_all_interruptible(stream, &[(subrect.x << 4) | subrect.y], shutdown)?;
            write_all_interruptible(
                stream,
                &[((subrect.width - 1) << 4) | (subrect.height - 1)],
                shutdown,
            )?;
            if !single_foreground {
                write_all_interruptible(stream, &subrect.color[..bytes_per_pixel], shutdown)?;
            }
        }
    }

    Ok(())
}

fn send_raw_hextile_tile(
    stream: &mut (impl Read + Write),
    frame: &Frame,
    tile: HextileTile,
    pixel_format: PixelFormat,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let HextileTile {
        x: tile_x,
        y: tile_y,
        width: tile_width,
        height: tile_height,
    } = tile;
    write_all_interruptible(stream, &[1], shutdown)?; // Raw tile subencoding
    for row in 0..u32::from(tile_height) {
        for column in 0..u32::from(tile_width) {
            let pixel = encoded_frame_pixel(frame, tile_x + column, tile_y + row, pixel_format)?;
            write_all_interruptible(stream, &pixel[..pixel_format.bytes_per_pixel()], shutdown)?;
        }
    }
    Ok(())
}

fn frame_pixel(frame: &Frame, x: u32, y: u32) -> io::Result<[u8; 4]> {
    let start = (y as usize)
        .checked_mul(frame.width as usize)
        .and_then(|pixel| pixel.checked_add(x as usize))
        .and_then(|pixel| pixel.checked_mul(4))
        .ok_or_else(|| invalid_data("Hextile pixel offset overflows"))?;
    let end = start
        .checked_add(4)
        .ok_or_else(|| invalid_data("Hextile pixel offset overflows"))?;
    let pixel = frame
        .data
        .get(start..end)
        .ok_or_else(|| invalid_data("Hextile pixel is outside the framebuffer"))?;
    Ok([pixel[0], pixel[1], pixel[2], pixel[3]])
}

fn encoded_frame_pixel(
    frame: &Frame,
    x: u32,
    y: u32,
    pixel_format: PixelFormat,
) -> io::Result<[u8; 4]> {
    Ok(pixel_format.encode(&frame_pixel(frame, x, y)?))
}

/// Tracks held remote inputs so a client disconnect can release them.
struct ClientInputGuard<'a> {
    sender: &'a tokio::sync::mpsc::Sender<ClientEvent>,
    pressed_keys: HashSet<u32>,
    pointer: Option<(u16, u16, u8)>,
}

impl<'a> ClientInputGuard<'a> {
    fn new(sender: &'a tokio::sync::mpsc::Sender<ClientEvent>) -> Self {
        Self {
            sender,
            pressed_keys: HashSet::new(),
            pointer: None,
        }
    }

    fn key(&mut self, keysym: u32, pressed: bool) -> io::Result<()> {
        self.sender
            .blocking_send(ClientEvent::Key { keysym, pressed })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "input handler stopped"))?;
        crate::timestamped_log!(
            "rfb: keyboard key {} queued for portal",
            if pressed { "press" } else { "release" }
        );
        if is_modifier_keysym(keysym) {
            crate::timestamped_log!(
                "rfb: modifier keysym {keysym:#x} {}",
                if pressed { "down" } else { "up" }
            );
        }
        if pressed && is_ascii_control_keysym(keysym) {
            crate::timestamped_log!(
                "rfb: queued an ASCII control-character keysym for portal (value redacted)"
            );
        }
        if pressed {
            self.pressed_keys.insert(keysym);
        } else {
            self.pressed_keys.remove(&keysym);
        }
        Ok(())
    }

    fn pointer(&mut self, x: u16, y: u16, buttons: u8) -> io::Result<()> {
        let previous_buttons = self.pointer.map_or(0, |(_, _, buttons)| buttons);
        self.sender
            .blocking_send(ClientEvent::Pointer { x, y, buttons })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "input handler stopped"))?;
        if previous_buttons != buttons {
            crate::timestamped_log!(
                "rfb: pointer button mask {previous_buttons:#04x} -> {buttons:#04x}"
            );
        }
        self.pointer = Some((x, y, buttons));
        Ok(())
    }
}

fn is_modifier_keysym(keysym: u32) -> bool {
    matches!(
        keysym,
        0xff7e // Mode_switch
            | 0xff7f // Num_Lock
            | 0xffe1..=0xffee // Shift, Control, Caps, Meta, Alt, Super, Hyper
    )
}

fn is_ascii_control_keysym(keysym: u32) -> bool {
    keysym < 0x20 || keysym == 0x7f
}

impl Drop for ClientInputGuard<'_> {
    fn drop(&mut self) {
        if let Some((x, y, buttons)) = self.pointer {
            if buttons != 0 {
                let _ = self
                    .sender
                    .try_send(ClientEvent::Pointer { x, y, buttons: 0 });
            }
        }
        for keysym in self.pressed_keys.drain() {
            let _ = self.sender.try_send(ClientEvent::Key {
                keysym,
                pressed: false,
            });
        }
    }
}

fn send_empty_update(stream: &mut (impl Read + Write), shutdown: &AtomicBool) -> io::Result<()> {
    write_all_interruptible(stream, &[0, 0, 0, 0], shutdown)
}

fn read_message_type(
    stream: &mut (impl Read + Write),
    shutdown: &AtomicBool,
    clipboard_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> io::Result<Option<u8>> {
    loop {
        while let Ok(text) = clipboard_rx.try_recv() {
            send_server_cut_text(stream, &text, shutdown)?;
        }
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        let mut message_type = [0u8; 1];
        match stream.read(&mut message_type) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client disconnected",
                ));
            }
            Ok(_) => return Ok(Some(message_type[0])),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn send_server_cut_text(
    stream: &mut (impl Read + Write),
    text: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
    if text.len() > MAX_CUT_TEXT as usize {
        return Err(invalid_data("server clipboard text exceeds the size limit"));
    }
    crate::timestamped_log!("rfb: sending ServerCutText ({} bytes)", text.len());
    let length = u32::try_from(text.len())
        .map_err(|_| invalid_data("server clipboard text exceeds the RFB limit"))?;
    let mut header = [0u8; 8];
    header[0] = 3; // ServerCutText
    header[4..8].copy_from_slice(&length.to_be_bytes());
    write_all_interruptible(stream, &header, shutdown)?;
    write_all_interruptible(stream, text, shutdown)
}

fn validate_rectangle(
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    framebuffer_width: u16,
    framebuffer_height: u16,
) -> io::Result<()> {
    if width == 0 || height == 0 {
        return Err(invalid_data("requested rectangle has zero width or height"));
    }

    let right = u32::from(x) + u32::from(width);
    let bottom = u32::from(y) + u32::from(height);
    if right > u32::from(framebuffer_width) || bottom > u32::from(framebuffer_height) {
        return Err(invalid_data(
            "requested rectangle is outside the framebuffer",
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RfbVersion {
    V3_3,
    V3_8,
}

fn parse_client_version(version: &[u8; 12]) -> io::Result<RfbVersion> {
    if &version[0..4] != b"RFB " || version[11] != b'\n' {
        return Err(invalid_data("malformed RFB version string"));
    }

    let major = parse_version_component(&version[4..7])
        .ok_or_else(|| invalid_data("malformed RFB major version"))?;
    let minor = parse_version_component(&version[8..11])
        .ok_or_else(|| invalid_data("malformed RFB minor version"))?;

    if major != 3 {
        return Err(invalid_data(format!(
            "unsupported RFB version {major}.{minor}"
        )));
    }

    match minor {
        3 => Ok(RfbVersion::V3_3),
        8 => Ok(RfbVersion::V3_8),
        _ => Err(invalid_data(format!(
            "unsupported RFB version {major}.{minor}; supported versions are 3.3 and 3.8"
        ))),
    }
}

fn parse_version_component(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }

    Some(
        u32::from(bytes[0] - b'0') * 100
            + u32::from(bytes[1] - b'0') * 10
            + u32::from(bytes[2] - b'0'),
    )
}

fn server_pixel_format() -> [u8; 16] {
    [
        32,  // bits per pixel
        24,  // depth
        0,   // little endian
        1,   // true color
        0,   // red max high byte
        255, // red max low byte
        0,   // green max high byte
        255, // green max low byte
        0,   // blue max high byte
        255, // blue max low byte
        16,  // red shift
        8,   // green shift
        0,   // blue shift
        0, 0, 0, // padding
    ]
}

fn read_u8(stream: &mut (impl Read + Write), shutdown: &AtomicBool) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    read_exact_interruptible(stream, &mut byte, shutdown)?;
    Ok(byte[0])
}

fn read_u16(stream: &mut (impl Read + Write), shutdown: &AtomicBool) -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    read_exact_interruptible(stream, &mut bytes, shutdown)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(stream: &mut (impl Read + Write), shutdown: &AtomicBool) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    read_exact_interruptible(stream, &mut bytes, shutdown)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_exact_interruptible(
    stream: &mut (impl Read + Write),
    buffer: &mut [u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client disconnected",
                ));
            }
            Ok(read) => offset += read,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn write_all_interruptible(
    stream: &mut (impl Read + Write),
    mut buffer: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
    while !buffer.is_empty() {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        match stream.write(buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "client stopped accepting data",
                ));
            }
            Ok(written) => buffer = &buffer[written..],
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(error);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn discard_exact(
    stream: &mut (impl Read + Write),
    mut remaining: usize,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        read_exact_interruptible(stream, &mut buffer[..chunk], shutdown)?;
        remaining -= chunk;
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn shutdown_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "server is shutting down")
}

fn is_normal_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    fn test_update_state(encoding: Encoding, copy_rect_enabled: bool) -> ClientUpdateState {
        ClientUpdateState {
            encoding,
            copy_rect_enabled,
            pixel_format: PixelFormat::DEFAULT,
            last_sequence: 0,
            pending_damage: Vec::new(),
            pending_update: None,
            zrle_compressor: Compress::new(Compression::default(), true),
            zlib_compressor: Compress::new(Compression::default(), true),
            client_pixels: None,
        }
    }

    #[test]
    fn accepts_rfb_38_and_sends_raw_update() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(FrameStore::new());
        let pixels = vec![
            1, 2, 3, 255, 4, 5, 6, 255, // row 0
            7, 8, 9, 255, 10, 11, 12, 255, // row 1
        ];
        store.publish(Arc::new(Frame::new(2, 2, pixels.clone()).unwrap()));

        let shutdown = Arc::new(AtomicBool::new(false));
        let (input_tx, mut input_rx) = tokio::sync::mpsc::channel(16);
        let server_store = Arc::clone(&store);
        let server_shutdown = Arc::clone(&shutdown);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            let (_clipboard_tx, mut clipboard_rx) = tokio::sync::mpsc::channel(1);
            let _ = handle_client(
                stream,
                &server_store,
                &RfbConfig {
                    width: 2,
                    height: 2,
                    name: "test".to_string(),
                    input_enabled: true,
                    clipboard_enabled: true,
                    encodings: None,
                    authentication: None,
                },
                &server_shutdown,
                Some(&input_tx),
                &mut clipboard_rx,
            );
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut version = [0u8; 12];
        client.read_exact(&mut version).unwrap();
        assert_eq!(&version, RFB_VERSION);

        client.write_all(RFB_VERSION).unwrap();

        let mut security = [0u8; 2];
        client.read_exact(&mut security).unwrap();
        assert_eq!(security, [1, 1]);
        client.write_all(&[1]).unwrap();

        let mut security_result = [0u8; 4];
        client.read_exact(&mut security_result).unwrap();
        assert_eq!(security_result, [0, 0, 0, 0]);

        client.write_all(&[1]).unwrap();

        let mut server_init = [0u8; 24];
        client.read_exact(&mut server_init).unwrap();
        assert_eq!(u16::from_be_bytes([server_init[0], server_init[1]]), 2);
        assert_eq!(u16::from_be_bytes([server_init[2], server_init[3]]), 2);
        assert_eq!(&server_init[4..20], &server_pixel_format());
        let name_len = u32::from_be_bytes([
            server_init[20],
            server_init[21],
            server_init[22],
            server_init[23],
        ]) as usize;
        let mut name = vec![0u8; name_len];
        client.read_exact(&mut name).unwrap();
        assert_eq!(name, b"test");

        let mut set_pixel_format = vec![0u8];
        set_pixel_format.extend_from_slice(&[0, 0, 0]);
        set_pixel_format.extend_from_slice(&server_pixel_format());
        client.write_all(&set_pixel_format).unwrap();

        let mut set_encodings = vec![2u8, 0];
        set_encodings.extend_from_slice(&1u16.to_be_bytes());
        set_encodings.extend_from_slice(&0i32.to_be_bytes());
        client.write_all(&set_encodings).unwrap();

        let mut request = vec![3u8, 0];
        for value in [0u16, 0, 2, 2] {
            request.extend_from_slice(&value.to_be_bytes());
        }
        client.write_all(&request).unwrap();

        let mut update_header = [0u8; 16];
        client.read_exact(&mut update_header).unwrap();
        assert_eq!(update_header[0], 0);
        assert_eq!(u16::from_be_bytes([update_header[2], update_header[3]]), 1);
        assert_eq!(u16::from_be_bytes([update_header[4], update_header[5]]), 0);
        assert_eq!(u16::from_be_bytes([update_header[6], update_header[7]]), 0);
        assert_eq!(u16::from_be_bytes([update_header[8], update_header[9]]), 2);
        assert_eq!(
            u16::from_be_bytes([update_header[10], update_header[11]]),
            2
        );
        assert_eq!(&update_header[12..16], &[0, 0, 0, 0]);

        let mut received = vec![0u8; 16];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, pixels);

        // A pointer event must be consumed without desynchronizing the stream.
        client.write_all(&[5, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            input_rx.blocking_recv(),
            Some(ClientEvent::Pointer {
                x: 0,
                y: 0,
                buttons: 0
            })
        );
        client.write_all(&[4, 1, 0, 0, 0, 0, 0, 0x61]).unwrap();
        assert_eq!(
            input_rx.blocking_recv(),
            Some(ClientEvent::Key {
                keysym: 0x61,
                pressed: true
            })
        );
        let text = b"hello";
        let mut cut_text = vec![6, 0, 0, 0];
        cut_text.extend_from_slice(&(text.len() as u32).to_be_bytes());
        cut_text.extend_from_slice(text);
        client.write_all(&cut_text).unwrap();
        assert_eq!(
            input_rx.blocking_recv(),
            Some(ClientEvent::Clipboard(text.to_vec()))
        );

        let mut second_request = vec![3u8, 0];
        for value in [0u16, 0, 2, 2] {
            second_request.extend_from_slice(&value.to_be_bytes());
        }
        client.write_all(&second_request).unwrap();

        let mut second_header = [0u8; 16];
        client.read_exact(&mut second_header).unwrap();
        assert_eq!(second_header[0], 0);
        assert_eq!(u16::from_be_bytes([second_header[2], second_header[3]]), 1);
        let mut second_pixels = vec![0u8; 16];
        client.read_exact(&mut second_pixels).unwrap();
        assert_eq!(second_pixels, pixels);

        let incremental_request = [3u8, 1, 0, 0, 0, 0, 0, 2, 0, 2];
        client.write_all(&incremental_request).unwrap();

        // Input must keep flowing while an incremental framebuffer request is
        // waiting for new damage.
        client.write_all(&[5, 1, 0, 0, 0, 0]).unwrap(); // left button down
        client.write_all(&[5, 0, 0, 0, 0, 0]).unwrap(); // left button up
        client.write_all(&[4, 1, 0, 0, 0, 0, 0xff, 0xe1]).unwrap(); // Shift_L down
        client.write_all(&[4, 1, 0, 0, 0, 0, 0xff, 0xe3]).unwrap(); // Control_L down
        client.write_all(&[4, 0, 0, 0, 0, 0, 0xff, 0xe3]).unwrap(); // Control_L up
        client.write_all(&[4, 0, 0, 0, 0, 0, 0xff, 0xe1]).unwrap(); // Shift_L up
        for expected in [
            ClientEvent::Pointer {
                x: 0,
                y: 0,
                buttons: 1,
            },
            ClientEvent::Pointer {
                x: 0,
                y: 0,
                buttons: 0,
            },
            ClientEvent::Key {
                keysym: 0xffe1,
                pressed: true,
            },
            ClientEvent::Key {
                keysym: 0xffe3,
                pressed: true,
            },
            ClientEvent::Key {
                keysym: 0xffe3,
                pressed: false,
            },
            ClientEvent::Key {
                keysym: 0xffe1,
                pressed: false,
            },
        ] {
            assert_eq!(input_rx.blocking_recv(), Some(expected));
        }

        let mut changed_pixels = pixels.clone();
        changed_pixels[4..8].copy_from_slice(&[21, 22, 23, 255]);
        let mut changed_frame = Frame::new(2, 2, changed_pixels).unwrap();
        changed_frame.damage = FrameDamage::Regions(vec![DamageRect {
            x: 1,
            y: 0,
            width: 1,
            height: 1,
        }]);
        store.publish(Arc::new(changed_frame));

        let mut incremental_header = [0u8; 16];
        client.read_exact(&mut incremental_header).unwrap();
        assert_eq!(incremental_header[0], 0);
        assert_eq!(
            u16::from_be_bytes([incremental_header[2], incremental_header[3]]),
            1
        );
        assert_eq!(
            u16::from_be_bytes([incremental_header[4], incremental_header[5]]),
            1
        );
        assert_eq!(
            u16::from_be_bytes([incremental_header[6], incremental_header[7]]),
            0
        );
        assert_eq!(
            u16::from_be_bytes([incremental_header[8], incremental_header[9]]),
            1
        );
        assert_eq!(
            u16::from_be_bytes([incremental_header[10], incremental_header[11]]),
            1
        );
        assert_eq!(&incremental_header[12..16], &[0, 0, 0, 0]);
        let mut incremental_pixels = [0u8; 4];
        client.read_exact(&mut incremental_pixels).unwrap();
        assert_eq!(incremental_pixels, [21, 22, 23, 255]);

        drop(client);
        server.join().unwrap();
        assert!(!shutdown.load(Ordering::Acquire));
    }

    #[test]
    fn parses_supported_versions() {
        assert_eq!(
            parse_client_version(b"RFB 003.003\n").unwrap(),
            RfbVersion::V3_3
        );
        assert_eq!(
            parse_client_version(b"RFB 003.008\n").unwrap(),
            RfbVersion::V3_8
        );
        assert!(parse_client_version(b"RFB 003.007\n").is_err());
        assert!(parse_client_version(b"RFB 003.009\n").is_err());
        assert!(parse_client_version(b"RFB 004.000\n").is_err());
        assert!(parse_client_version(b"RFB 003.00x\n").is_err());
        assert!(parse_client_version(b"NOT 003.008\n").is_err());
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

    #[test]
    fn vnc_auth_accepts_rfb_33_client_handshake() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(FrameStore::new());
        store.publish(Arc::new(Frame::new(2, 2, vec![0; 16]).unwrap()));
        let server_store = Arc::clone(&store);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            let (_clipboard_tx, mut clipboard_rx) = tokio::sync::mpsc::channel(1);
            let (input_tx, _input_rx) = tokio::sync::mpsc::channel(1);
            let config = RfbConfig {
                width: 2,
                height: 2,
                name: "test".to_string(),
                input_enabled: false,
                clipboard_enabled: false,
                encodings: None,
                authentication: Some(Arc::new(AuthenticationConfig::Vnc {
                    password: b"password".to_vec(),
                })),
            };
            handle_client(
                stream,
                &server_store,
                &config,
                &AtomicBool::new(false),
                Some(&input_tx),
                &mut clipboard_rx,
            )
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut version = [0; 12];
        client.read_exact(&mut version).unwrap();
        client.write_all(b"RFB 003.003\n").unwrap();
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
        client.write_all(&[1]).unwrap();
        let mut server_init = [0; 24];
        client.read_exact(&mut server_init).unwrap();
        assert_eq!(u16::from_be_bytes([server_init[0], server_init[1]]), 2);
        assert_eq!(u16::from_be_bytes([server_init[2], server_init[3]]), 2);
        drop(client);
        let _ = server.join().unwrap();
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
    fn accepts_rfb_33_security_none_handshake() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let store = FrameStore::new();
        let store = Arc::new(store);
        store.publish(Arc::new(Frame::new(2, 2, vec![0; 2 * 2 * 4]).unwrap()));

        let shutdown = Arc::new(AtomicBool::new(false));
        let server_store = Arc::clone(&store);
        let server_shutdown = Arc::clone(&shutdown);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            let (_clipboard_tx, mut clipboard_rx) = tokio::sync::mpsc::channel(1);
            let _ = handle_client(
                stream,
                &server_store,
                &RfbConfig {
                    width: 2,
                    height: 2,
                    name: "test".to_string(),
                    input_enabled: false,
                    clipboard_enabled: false,
                    encodings: None,
                    authentication: None,
                },
                &server_shutdown,
                None,
                &mut clipboard_rx,
            );
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut server_version = [0u8; 12];
        client.read_exact(&mut server_version).unwrap();
        assert_eq!(&server_version, RFB_VERSION);
        client.write_all(b"RFB 003.003\n").unwrap();

        let mut security_type = [0u8; 4];
        client.read_exact(&mut security_type).unwrap();
        assert_eq!(u32::from_be_bytes(security_type), SECURITY_TYPE_NONE);

        // In RFB 3.3 None security, the next message is ClientInit; there is
        // no client security selection or SecurityResult.
        client.write_all(&[1]).unwrap();
        let mut server_init = [0u8; 24];
        client.read_exact(&mut server_init).unwrap();
        assert_eq!(u16::from_be_bytes([server_init[0], server_init[1]]), 2);
        assert_eq!(u16::from_be_bytes([server_init[2], server_init[3]]), 2);
        assert_eq!(&server_init[4..20], &server_pixel_format());

        let name_len = u32::from_be_bytes(server_init[20..24].try_into().unwrap()) as usize;
        let mut name = vec![0u8; name_len];
        client.read_exact(&mut name).unwrap();
        assert_eq!(name, b"test");

        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn validates_pixel_formats() {
        assert!(PixelFormat::from_wire(&server_pixel_format()).is_ok());

        let mut rgb565 = server_pixel_format();
        rgb565[0] = 16;
        rgb565[1] = 16;
        rgb565[4..10].copy_from_slice(&[0, 31, 0, 63, 0, 31]);
        rgb565[10..13].copy_from_slice(&[11, 5, 0]);
        assert!(PixelFormat::from_wire(&rgb565).is_ok());

        let mut nominal_depth_mismatch = rgb565;
        nominal_depth_mismatch[0] = 32;
        nominal_depth_mismatch[1] = 24;
        assert!(PixelFormat::from_wire(&nominal_depth_mismatch).is_ok());

        let mut wrong = server_pixel_format();
        wrong[10] = 0;
        assert!(PixelFormat::from_wire(&wrong).is_err());
    }

    #[test]
    fn converts_pixels_for_rgb565_and_rgb332_formats() {
        let rgb565 = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            big_endian: false,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
        };
        rgb565.validate().unwrap();
        assert_eq!(&rgb565.encode(&[255, 128, 0, 255])[..2], &[0x1f, 0x04]);

        let rgb565_be = PixelFormat {
            big_endian: true,
            ..rgb565
        };
        assert_eq!(&rgb565_be.encode(&[255, 128, 0, 255])[..2], &[0x04, 0x1f]);

        let rgb888_be = PixelFormat {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        };
        assert_eq!(
            &rgb888_be.encode_zrle(&[255, 128, 0, 255])[..3],
            &[0, 128, 255]
        );
        assert_eq!(rgb888_be.encode(&[255, 128, 0, 255]), [255, 0, 128, 255]);

        let rgb888_32 = PixelFormat {
            depth: 32,
            big_endian: false,
            ..rgb888_be
        };
        assert_eq!(rgb888_32.encode(&[255, 128, 0, 255]), [255, 128, 0, 255]);
        assert_eq!(rgb888_32.zrle_bytes_per_pixel(), 3);
        assert_eq!(
            &rgb888_32.encode_zrle(&[255, 128, 0, 255])[..3],
            &[255, 128, 0]
        );

        let rgb332 = PixelFormat {
            bits_per_pixel: 8,
            depth: 8,
            big_endian: false,
            red_max: 7,
            green_max: 7,
            blue_max: 3,
            red_shift: 5,
            green_shift: 2,
            blue_shift: 0,
        };
        assert_eq!(rgb332.encode(&[255, 255, 255, 255])[0], 0xff);
    }

    #[test]
    fn rejects_zero_sized_rectangles() {
        assert!(validate_rectangle(0, 0, 0, 1, 10, 10).is_err());
        assert!(validate_rectangle(0, 0, 11, 1, 10, 10).is_err());
        assert!(validate_rectangle(0, 0, 10, 10, 10, 10).is_ok());
    }

    #[test]
    fn frame_wait_observes_shutdown() {
        let store = FrameStore::new();
        let shutdown = AtomicBool::new(true);
        let error = wait_for_frame(&store, 0, Duration::from_secs(1), &shutdown).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn sends_server_cut_text_message() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            send_server_cut_text(&mut stream, b"hello", &AtomicBool::new(false)).unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        let mut message = [0u8; 13];
        client.read_exact(&mut message).unwrap();
        assert_eq!(&message[..4], &[3, 0, 0, 0]);
        assert_eq!(u32::from_be_bytes(message[4..8].try_into().unwrap()), 5);
        assert_eq!(&message[8..], b"hello");
        server.join().unwrap();
    }

    #[test]
    fn honors_client_encoding_preference_with_raw_fallback() {
        let hextile = ENCODING_HEXTILE.to_be_bytes();
        let raw = ENCODING_RAW.to_be_bytes();
        let mut offered = Vec::new();
        offered.extend_from_slice(&hextile);
        offered.extend_from_slice(&raw);
        assert_eq!(
            select_encodings(&offered).unwrap().preferred,
            Encoding::Hextile
        );

        offered.clear();
        offered.extend_from_slice(&ENCODING_ZRLE.to_be_bytes());
        offered.extend_from_slice(&hextile);
        assert_eq!(
            select_encodings(&offered).unwrap().preferred,
            Encoding::Zrle
        );

        offered.clear();
        offered.extend_from_slice(&raw);
        offered.extend_from_slice(&hextile);
        assert_eq!(select_encodings(&offered).unwrap().preferred, Encoding::Raw);

        offered.clear();
        offered.extend_from_slice(&ENCODING_ZLIB.to_be_bytes());
        offered.extend_from_slice(&ENCODING_ZRLE.to_be_bytes());
        offered.extend_from_slice(&ENCODING_COPY_RECT.to_be_bytes());
        offered.extend_from_slice(&raw);
        assert_eq!(
            select_encodings(&offered).unwrap(),
            EncodingPreferences {
                preferred: Encoding::Zlib,
                copy_rect: true,
            }
        );
        let raw_only = [RfbEncoding::Raw];
        assert_eq!(
            select_encodings_with_allowlist(&offered, Some(&raw_only)).unwrap(),
            EncodingPreferences {
                preferred: Encoding::Raw,
                copy_rect: false,
            }
        );
        assert!(select_encodings(&42i32.to_be_bytes()).is_err());
    }

    #[test]
    fn sync_compression_drains_full_output_buffers() {
        let input: Vec<u8> = (0..65_536)
            .map(|index| ((index * 73 + index / 13) & 0xff) as u8)
            .collect();
        let mut compressor = Compress::new(Compression::default(), true);
        let compressed = compress_sync_with_buffer_size(&mut compressor, &input, 7).unwrap();

        let mut decompressor = flate2::Decompress::new(true);
        let mut decoded = vec![0; input.len()];
        let status = decompressor
            .decompress(&compressed, &mut decoded, flate2::FlushDecompress::Sync)
            .unwrap();
        assert_eq!(status, Status::Ok);
        assert_eq!(decompressor.total_out() as usize, input.len());
        assert_eq!(decoded, input);
    }

    #[test]
    fn zrle_encodes_raw_tiles_in_one_persistent_zlib_stream() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let frame = Frame::new(2, 1, vec![1, 2, 3, 255, 4, 5, 6, 255]).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut compressor = Compress::new(Compression::default(), true);
            let rectangle = DamageRect {
                x: 0,
                y: 0,
                width: 2,
                height: 1,
            };
            send_zrle_rectangle(
                &mut stream,
                &frame,
                rectangle,
                PixelFormat::DEFAULT,
                &mut compressor,
                &AtomicBool::new(false),
            )
            .unwrap();
            send_zrle_rectangle(
                &mut stream,
                &frame,
                rectangle,
                PixelFormat::DEFAULT,
                &mut compressor,
                &AtomicBool::new(false),
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        let mut decompressor = flate2::Decompress::new(true);
        for _ in 0..2 {
            let mut length = [0; 4];
            client.read_exact(&mut length).unwrap();
            let mut compressed = vec![0; u32::from_be_bytes(length) as usize];
            client.read_exact(&mut compressed).unwrap();
            let mut decoded = [0; 7];
            let before = decompressor.total_out();
            decompressor
                .decompress(&compressed, &mut decoded, flate2::FlushDecompress::Sync)
                .unwrap();
            let written = (decompressor.total_out() - before) as usize;
            assert_eq!(&decoded[..written], &[0, 1, 2, 3, 4, 5, 6]);
        }
        server.join().unwrap();
    }

    #[test]
    fn zlib_encodes_raw_pixels_in_one_persistent_stream() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let frame = Frame::new(2, 1, vec![1, 2, 3, 255, 4, 5, 6, 255]).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut compressor = Compress::new(Compression::default(), true);
            let rectangle = DamageRect {
                x: 0,
                y: 0,
                width: 2,
                height: 1,
            };
            for _ in 0..2 {
                send_zlib_rectangle(
                    &mut stream,
                    &frame,
                    rectangle,
                    PixelFormat::DEFAULT,
                    &mut compressor,
                    &AtomicBool::new(false),
                )
                .unwrap();
            }
        });

        let mut client = TcpStream::connect(address).unwrap();
        let mut decompressor = flate2::Decompress::new(true);
        for _ in 0..2 {
            let mut length = [0; 4];
            client.read_exact(&mut length).unwrap();
            let mut compressed = vec![0; u32::from_be_bytes(length) as usize];
            client.read_exact(&mut compressed).unwrap();
            let mut decoded = [0; 8];
            let before = decompressor.total_out();
            decompressor
                .decompress(&compressed, &mut decoded, flate2::FlushDecompress::Sync)
                .unwrap();
            let written = (decompressor.total_out() - before) as usize;
            assert_eq!(&decoded[..written], &[1, 2, 3, 255, 4, 5, 6, 255]);
        }
        server.join().unwrap();
    }

    #[test]
    fn sends_copyrect_only_from_known_client_pixels() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let old_frame = Frame::new(
            4,
            1,
            vec![1, 2, 3, 255, 4, 5, 6, 255, 7, 8, 9, 255, 10, 11, 12, 255],
        )
        .unwrap();
        let new_frame = Frame::new(
            4,
            1,
            vec![1, 2, 3, 255, 1, 2, 3, 255, 7, 8, 9, 255, 10, 11, 12, 255],
        )
        .unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut state = test_update_state(Encoding::Raw, true);
            send_update(
                &mut stream,
                &old_frame,
                &[DamageRect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 1,
                }],
                &mut state,
                &AtomicBool::new(false),
            )
            .unwrap();
            send_update(
                &mut stream,
                &new_frame,
                &[DamageRect {
                    x: 1,
                    y: 0,
                    width: 1,
                    height: 1,
                }],
                &mut state,
                &AtomicBool::new(false),
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        let mut initial = [0; 32];
        client.read_exact(&mut initial).unwrap();
        assert_eq!(
            i32::from_be_bytes(initial[12..16].try_into().unwrap()),
            ENCODING_RAW
        );
        let mut update = [0; 20];
        client.read_exact(&mut update).unwrap();
        assert_eq!(
            i32::from_be_bytes(update[12..16].try_into().unwrap()),
            ENCODING_COPY_RECT
        );
        assert_eq!(&update[16..], &[0, 0, 0, 0]);
        server.join().unwrap();
    }

    #[test]
    fn hextile_encodes_solid_and_subrect_tiles() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let solid_pixels = [10, 20, 30, 255].repeat(4);
        let solid_frame = Frame::new(2, 2, solid_pixels).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut state = test_update_state(Encoding::Hextile, false);
            send_update(
                &mut stream,
                &solid_frame,
                &[DamageRect {
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 2,
                }],
                &mut state,
                &AtomicBool::new(false),
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        let mut update = [0u8; 21];
        client.read_exact(&mut update).unwrap();
        assert_eq!(&update[..4], &[0, 0, 0, 1]);
        assert_eq!(
            i32::from_be_bytes(update[12..16].try_into().unwrap()),
            ENCODING_HEXTILE
        );
        assert_eq!(&update[16..], &[2, 10, 20, 30, 255]);
        server.join().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut pixels = [1, 2, 3, 255].repeat(16);
        pixels[24..28].copy_from_slice(&[4, 5, 6, 255]); // pixel (2, 1)
        let frame = Frame::new(4, 4, pixels).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut state = test_update_state(Encoding::Hextile, false);
            send_update(
                &mut stream,
                &frame,
                &[DamageRect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 4,
                }],
                &mut state,
                &AtomicBool::new(false),
            )
            .unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        let mut update = [0u8; 28];
        client.read_exact(&mut update).unwrap();
        assert_eq!(update[16], 14); // Background, foreground, one subrect.
        assert_eq!(&update[17..21], &[1, 2, 3, 255]);
        assert_eq!(&update[21..25], &[4, 5, 6, 255]);
        assert_eq!(update[25], 1);
        assert_eq!(update[26], 0x21); // x=2, y=1
        assert_eq!(update[27], 0x00); // 1x1 subrect
        server.join().unwrap();
    }

    #[test]
    fn releases_held_remote_inputs_when_client_guard_drops() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        {
            let mut guard = ClientInputGuard::new(&sender);
            guard.key(0x61, true).unwrap();
            guard.pointer(12, 34, 1).unwrap();
        }

        assert_eq!(
            receiver.blocking_recv(),
            Some(ClientEvent::Key {
                keysym: 0x61,
                pressed: true
            })
        );
        assert_eq!(
            receiver.blocking_recv(),
            Some(ClientEvent::Pointer {
                x: 12,
                y: 34,
                buttons: 1
            })
        );
        assert_eq!(
            receiver.blocking_recv(),
            Some(ClientEvent::Pointer {
                x: 12,
                y: 34,
                buttons: 0
            })
        );
        assert_eq!(
            receiver.blocking_recv(),
            Some(ClientEvent::Key {
                keysym: 0x61,
                pressed: false
            })
        );
    }

    #[test]
    fn damage_helpers_clip_merge_and_preserve_unserved_regions() {
        let mut pending = vec![
            DamageRect {
                x: 0,
                y: 0,
                width: 3,
                height: 2,
            },
            DamageRect {
                x: 2,
                y: 1,
                width: 2,
                height: 2,
            },
        ];
        merge_rectangles(&mut pending);
        assert_eq!(
            pending,
            vec![DamageRect {
                x: 0,
                y: 0,
                width: 4,
                height: 3,
            }]
        );

        let served = DamageRect {
            x: 1,
            y: 1,
            width: 2,
            height: 1,
        };
        assert_eq!(damage_within(&pending, served), vec![served]);
        subtract_damage(&mut pending, served);
        assert_eq!(
            pending,
            vec![
                DamageRect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 1,
                },
                DamageRect {
                    x: 0,
                    y: 2,
                    width: 4,
                    height: 1,
                },
                DamageRect {
                    x: 0,
                    y: 1,
                    width: 1,
                    height: 1,
                },
                DamageRect {
                    x: 3,
                    y: 1,
                    width: 1,
                    height: 1,
                },
            ]
        );
    }
}

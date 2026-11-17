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

//! RFB 3.3/3.8 server: protocol flow, client sessions, and wire I/O.
//!
//! The module is split by responsibility:
//!
//! - [`auth`] loads credentials, TLS identities, and certificate summaries.
//! - [`security`] performs security negotiation and authentication crypto.
//! - [`pixel`] describes client pixel formats.
//! - [`encoding`] encodes framebuffer updates and tracks update state.
//! - [`listener`] manages the TCP listener and per-client worker threads.

mod auth;
mod encoding;
mod listener;
mod pixel;
mod security;

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use flate2::{Compress, Compression};

use crate::cli::RfbEncoding;
use crate::framebuffer::FrameStore;
use crate::input::ClientEvent;

use encoding::{
    ClientUpdateState, Encoding, EncodingPreferences, handle_update_request,
    select_encodings_with_allowlist, service_pending_update,
};
use pixel::{PixelFormat, server_pixel_format};
use security::{
    SECURITY_TYPE_NONE, negotiate_apple_dh, negotiate_vencrypt, negotiate_vnc_auth,
    negotiate_vnc_tls_with_fallback,
};

pub use auth::{
    AuthenticationConfig, load_apple_dh_authentication, load_authentication,
    load_vnc_authentication, load_vnc_tls_authentication,
};
pub use listener::spawn;

const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";

/// Apple Remote Desktop's non-standard version token.
const APPLE_RFB_VERSION: &[u8; 12] = b"RFB 003.889\n";

const MAX_ENCODINGS: u16 = 1024;

const MAX_CUT_TEXT: u32 = 1024 * 1024;

const READ_POLL_INTERVAL: Duration = Duration::from_millis(500);

const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

const INITIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

const WAIT_SLICE: Duration = Duration::from_millis(250);

/// How often keyboard events are summarized in the log. Individual key events
/// are never logged at unbounded rates because typing would flood the log.
const KEY_EVENT_LOG_INTERVAL: Duration = Duration::from_secs(10);

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
    /// Whether separately rendered cursor pseudo-encodings are enabled.
    pub cursor_enabled: bool,
    /// Whether clipboard messages are enabled.
    pub clipboard_enabled: bool,
    /// Maximum number of simultaneous clients.
    pub max_clients: usize,
    /// Optional allowlist; Raw remains a required fallback.
    pub encodings: Option<Vec<RfbEncoding>>,
    /// Optional TLS/VeNCrypt authentication settings.
    pub authentication: Option<Arc<AuthenticationConfig>>,
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

fn handle_client(
    stream: TcpStream,
    store: &FrameStore,
    config: &RfbConfig,
    shutdown: &AtomicBool,
    input_tx: Option<&tokio::sync::mpsc::Sender<ClientEvent>>,
    clipboard_rx: &mut tokio::sync::broadcast::Receiver<Vec<u8>>,
    handshake_done: Option<&std::sync::mpsc::Sender<()>>,
) -> io::Result<()> {
    let mut tcp_stream = stream;
    let apple_auth = matches!(
        config.authentication.as_deref(),
        Some(AuthenticationConfig::AppleDh { .. })
    );
    write_all_interruptible(
        &mut tcp_stream,
        if apple_auth {
            APPLE_RFB_VERSION
        } else {
            RFB_VERSION
        },
        shutdown,
    )?;

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
            negotiate_vnc_auth(&mut tcp_stream, version, password, true, shutdown)?;
            ClientStream::Plain(tcp_stream)
        }
        Some(AuthenticationConfig::VncTls { tls, password }) => {
            negotiate_vnc_tls_with_fallback(tcp_stream, version, tls, password, shutdown)?
        }
        Some(AuthenticationConfig::AppleDh { username, password }) => {
            if version != RfbVersion::Apple3_889 {
                return Err(invalid_data("Apple DH authentication requires RFB 3.889"));
            }
            negotiate_apple_dh(&mut tcp_stream, username, password, shutdown)?;
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
                RfbVersion::Apple3_889 => {
                    return Err(invalid_data(
                        "Apple RFB 3.889 requires Apple DH authentication",
                    ));
                }
            }
            ClientStream::Plain(tcp_stream)
        }
    };

    // ClientInit: shared flag. Clients are always served concurrently, so the
    // flag does not disconnect existing clients.
    let _shared = read_u8(&mut stream, shutdown)?;

    write_server_init(
        &mut stream,
        config.width,
        config.height,
        &config.name,
        shutdown,
    )?;
    if let Some(done) = handshake_done {
        let _ = done.send(());
    }

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
        cursor_enabled: config.cursor_enabled,
        rich_cursor_enabled: false,
        pointer_pos_enabled: false,
        cursor_snapshot: crate::cursor::CursorSnapshot::default(),
        sent_cursor_shape_sequence: 0,
        sent_cursor_position_sequence: 0,
    };
    let mut keyboard_input_warned = false;
    let mut pointer_input_warned = false;
    let mut received_button_mask = 0u8;
    let mut key_events: usize = 0;
    let mut key_event_report = Instant::now();
    let mut held_input = if config.input_enabled {
        input_tx.map(|sender| ClientInputGuard::new(sender, shutdown))
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
                update_state.sent_cursor_shape_sequence = 0;
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
                if preferences.rich_cursor && !update_state.rich_cursor_enabled {
                    update_state.sent_cursor_shape_sequence = 0;
                }
                if preferences.pointer_pos && !update_state.pointer_pos_enabled {
                    update_state.sent_cursor_position_sequence = 0;
                }
                update_state.rich_cursor_enabled = preferences.rich_cursor;
                update_state.pointer_pos_enabled = preferences.pointer_pos;
                if update_state.copy_rect_enabled != preferences.copy_rect {
                    update_state.client_pixels = None;
                }
                update_state.copy_rect_enabled = preferences.copy_rect;
                crate::timestamped_log!(
                    "rfb: selected framebuffer encoding: {:?}, CopyRect {}, RichCursor {}, PointerPos {}",
                    preferences.preferred,
                    if preferences.copy_rect {
                        "enabled"
                    } else {
                        "not offered"
                    },
                    if preferences.rich_cursor {
                        "enabled"
                    } else {
                        "not offered"
                    },
                    if preferences.pointer_pos {
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
                // Avoid logging keysyms or typed values. Keyboard events are
                // summarized at a bounded rate so typing cannot flood the
                // log; modifiers and control characters are rare and are
                // logged individually for input diagnostics.
                key_events += 1;
                if key_event_report.elapsed() >= KEY_EVENT_LOG_INTERVAL {
                    crate::timestamped_log!(
                        "rfb: received {key_events} keyboard events in the last {} seconds",
                        KEY_EVENT_LOG_INTERVAL.as_secs()
                    );
                    key_events = 0;
                    key_event_report = Instant::now();
                }
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
                // PointerEvent: button-mask (1), x-position (2), y-position
                // (2) after the message-type byte — six bytes in total, with
                // no padding field.
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
                    send_input_event(input_tx, ClientEvent::Clipboard(text), shutdown)?;
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

/// Tracks held remote inputs so a client disconnect can release them.
struct ClientInputGuard<'a> {
    sender: &'a tokio::sync::mpsc::Sender<ClientEvent>,
    shutdown: &'a AtomicBool,
    pressed_keys: HashSet<u32>,
    pointer: Option<(u16, u16, u8)>,
}

impl<'a> ClientInputGuard<'a> {
    fn new(sender: &'a tokio::sync::mpsc::Sender<ClientEvent>, shutdown: &'a AtomicBool) -> Self {
        Self {
            sender,
            shutdown,
            pressed_keys: HashSet::new(),
            pointer: None,
        }
    }

    fn key(&mut self, keysym: u32, pressed: bool) -> io::Result<()> {
        send_input_event(
            self.sender,
            ClientEvent::Key { keysym, pressed },
            self.shutdown,
        )?;
        if pressed {
            self.pressed_keys.insert(keysym);
        } else {
            self.pressed_keys.remove(&keysym);
        }
        Ok(())
    }

    fn pointer(&mut self, x: u16, y: u16, buttons: u8) -> io::Result<()> {
        send_input_event(
            self.sender,
            ClientEvent::Pointer { x, y, buttons },
            self.shutdown,
        )?;
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
                try_send_release(self.sender, ClientEvent::Pointer { x, y, buttons: 0 });
            }
        }
        for keysym in self.pressed_keys.drain() {
            try_send_release(
                self.sender,
                ClientEvent::Key {
                    keysym,
                    pressed: false,
                },
            );
        }
    }
}

fn send_empty_update(stream: &mut (impl Read + Write), shutdown: &AtomicBool) -> io::Result<()> {
    write_all_interruptible(stream, &[0, 0, 0, 0], shutdown)
}

fn read_message_type(
    stream: &mut (impl Read + Write),
    shutdown: &AtomicBool,
    clipboard_rx: &mut tokio::sync::broadcast::Receiver<Vec<u8>>,
) -> io::Result<Option<u8>> {
    loop {
        loop {
            match clipboard_rx.try_recv() {
                Ok(text) => send_server_cut_text(stream, &text, shutdown)?,
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                // A slow client may miss intermediate clipboard values, but it
                // must keep receiving later updates and client messages.
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
            }
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
    Apple3_889,
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
        889 => Ok(RfbVersion::Apple3_889),
        _ => Err(invalid_data(format!(
            "unsupported RFB version {major}.{minor}; supported versions are 3.3, 3.8, and Apple 3.889"
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

/// Queue an input event for the portal-side handler without blocking forever.
///
/// The bounded event channel applies backpressure while the consumer is busy,
/// but the wait must stay interruptible: on shutdown the main loop stops
/// draining the channel, so an unconditional `blocking_send` could deadlock
/// the client thread and the shutdown join with it.
fn send_input_event(
    sender: &tokio::sync::mpsc::Sender<ClientEvent>,
    event: ClientEvent,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut event = event;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }
        match sender.try_send(event) {
            Ok(()) => return Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "input handler stopped",
                ));
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => {
                event = returned;
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Queue a release event when a client disconnects, bounded so teardown can
/// never hang on a full channel.
fn try_send_release(sender: &tokio::sync::mpsc::Sender<ClientEvent>, event: ClientEvent) {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut event = event;
    loop {
        match sender.try_send(event) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
            Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => {
                if Instant::now() >= deadline {
                    return;
                }
                event = returned;
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
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
pub(crate) fn test_rfb_config(max_clients: usize) -> RfbConfig {
    RfbConfig {
        width: 2,
        height: 2,
        name: "test".to_string(),
        input_enabled: false,
        cursor_enabled: false,
        clipboard_enabled: false,
        max_clients,
        encodings: None,
        authentication: None,
    }
}

#[cfg(test)]
mod tests {
    use super::listener::configure_stream;
    use super::security::{SECURITY_TYPE_NONE, SECURITY_TYPE_VNC_AUTH, vnc_auth_response};
    use super::*;
    use crate::framebuffer::{DamageRect, Frame, FrameDamage};
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

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
            let (_clipboard_tx, mut clipboard_rx) = tokio::sync::broadcast::channel(1);
            let _ = handle_client(
                stream,
                &server_store,
                &RfbConfig {
                    width: 2,
                    height: 2,
                    name: "test".to_string(),
                    input_enabled: true,
                    cursor_enabled: false,
                    clipboard_enabled: true,
                    max_clients: 4,
                    encodings: None,
                    authentication: None,
                },
                &server_shutdown,
                Some(&input_tx),
                &mut clipboard_rx,
                None,
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
        assert_eq!(APPLE_RFB_VERSION, b"RFB 003.889\n");
        assert_eq!(
            parse_client_version(b"RFB 003.003\n").unwrap(),
            RfbVersion::V3_3
        );
        assert_eq!(
            parse_client_version(b"RFB 003.008\n").unwrap(),
            RfbVersion::V3_8
        );
        assert_eq!(
            parse_client_version(b"RFB 003.889\n").unwrap(),
            RfbVersion::Apple3_889
        );
        assert!(parse_client_version(b"RFB 003.007\n").is_err());
        assert!(parse_client_version(b"RFB 003.009\n").is_err());
        assert!(parse_client_version(b"RFB 004.000\n").is_err());
        assert!(parse_client_version(b"RFB 003.00x\n").is_err());
        assert!(parse_client_version(b"NOT 003.008\n").is_err());
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
            let (_clipboard_tx, mut clipboard_rx) = tokio::sync::broadcast::channel(1);
            let (input_tx, _input_rx) = tokio::sync::mpsc::channel(1);
            let config = RfbConfig {
                width: 2,
                height: 2,
                name: "test".to_string(),
                input_enabled: false,
                cursor_enabled: false,
                clipboard_enabled: false,
                max_clients: 4,
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
                None,
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
            let (_clipboard_tx, mut clipboard_rx) = tokio::sync::broadcast::channel(1);
            let _ = handle_client(
                stream,
                &server_store,
                &RfbConfig {
                    width: 2,
                    height: 2,
                    name: "test".to_string(),
                    input_enabled: false,
                    cursor_enabled: false,
                    clipboard_enabled: false,
                    max_clients: 4,
                    encodings: None,
                    authentication: None,
                },
                &server_shutdown,
                None,
                &mut clipboard_rx,
                None,
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
    fn releases_held_remote_inputs_when_client_guard_drops() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let shutdown = AtomicBool::new(false);
        {
            let mut guard = ClientInputGuard::new(&sender, &shutdown);
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
}

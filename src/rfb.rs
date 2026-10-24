//! Minimal RFB 3.3/3.8 server.
//!
//! This module intentionally depends only on the normalized [`Frame`] type and
//! the standard library. It currently supports:
//!
//! - RFB 3.3 and 3.8 version negotiation
//! - Security type `None` (unencrypted)
//! - A single client at a time
//! - 32-bit true-color pixel format with BGRA byte order
//! - Raw and Hextile encodings, selected from the client's advertised list
//! - Incremental update requests with damage-region Raw rectangles
//!
//! Remote input and text clipboard transfer are enabled only when explicitly
//! requested and granted by the XDG Desktop Portal. The server does not claim
//! support for encodings or extensions that are not implemented here.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::framebuffer::{DamageRect, Frame, FrameDamage, FrameStore};
use crate::input::ClientEvent;

const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";
const SECURITY_TYPE_NONE: u32 = 1;
const MAX_ENCODINGS: u16 = 1024;
const MAX_CUT_TEXT: u32 = 1024 * 1024;
const READ_POLL_INTERVAL: Duration = Duration::from_millis(500);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const INCREMENTAL_TIMEOUT: Duration = Duration::from_secs(30);
const INITIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_SLICE: Duration = Duration::from_millis(250);
const MAX_UPDATE_RECTS: usize = 128;

const ENCODING_RAW: i32 = 0;
const ENCODING_HEXTILE: i32 = 5;

/// Protocol settings and optional capability gates for an RFB listener.
#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Raw,
    Hextile,
}

impl Encoding {
    fn rfb_value(self) -> i32 {
        match self {
            Self::Raw => ENCODING_RAW,
            Self::Hextile => ENCODING_HEXTILE,
        }
    }
}

#[derive(Debug)]
struct ClientUpdateState {
    encoding: Encoding,
    last_sequence: u64,
    pending_damage: Vec<DamageRect>,
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

                eprintln!("rfb: client connected from {address}");
                if let Err(error) = configure_stream(&stream) {
                    eprintln!("rfb: could not configure client socket: {error}");
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
                    Ok(()) => eprintln!("rfb: client disconnected"),
                    Err(error) if is_normal_disconnect(&error) => {
                        eprintln!("rfb: client disconnected: {error}");
                    }
                    Err(error) => eprintln!("rfb: client error: {error}"),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                eprintln!("rfb: accept failed: {error}");
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
    mut stream: TcpStream,
    store: &FrameStore,
    config: &RfbConfig,
    shutdown: &AtomicBool,
    input_tx: Option<&tokio::sync::mpsc::Sender<ClientEvent>>,
    clipboard_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    write_all_interruptible(&mut stream, RFB_VERSION, shutdown)?;

    let mut version = [0u8; 12];
    read_exact_interruptible(&mut stream, &mut version, shutdown)?;
    let version = parse_client_version(&version)?;

    match version {
        RfbVersion::V3_3 => {
            // RFB 3.3 sends a single 32-bit security type. Security type None
            // has no client selection or SecurityResult message.
            write_all_interruptible(&mut stream, &SECURITY_TYPE_NONE.to_be_bytes(), shutdown)?;
        }
        RfbVersion::V3_8 => {
            // RFB 3.7+ sends a count and list of supported security types.
            write_all_interruptible(&mut stream, &[1, SECURITY_TYPE_NONE as u8], shutdown)?;
            let security_type = read_u8(&mut stream, shutdown)?;
            if u32::from(security_type) != SECURITY_TYPE_NONE {
                return Err(invalid_data(format!(
                    "client selected unsupported security type {security_type}"
                )));
            }

            write_all_interruptible(&mut stream, &0u32.to_be_bytes(), shutdown)?;
        }
    }

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
        last_sequence: 0,
        pending_damage: Vec::new(),
    };
    let mut input_warned = false;
    let mut held_input = if config.input_enabled {
        input_tx.map(ClientInputGuard::new)
    } else {
        None
    };

    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        let message_type = read_message_type(&mut stream, shutdown, clipboard_rx)?;
        match message_type {
            0 => handle_set_pixel_format(&mut stream, shutdown)?,
            2 => update_state.encoding = handle_set_encodings(&mut stream, shutdown)?,
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
                if keysym > i32::MAX as u32 {
                    return Err(invalid_data(format!(
                        "RFB keysym {keysym:#x} exceeds the portal keysym range"
                    )));
                }
                if let Some(held_input) = &mut held_input {
                    held_input.key(keysym, down)?;
                } else if !input_warned {
                    eprintln!("rfb: keyboard input is disabled; event ignored");
                    input_warned = true;
                }
            }
            5 => {
                // PointerEvent: button-mask (1), padding (2), x (2), y (2).
                let mut event = [0u8; 5];
                read_exact_interruptible(&mut stream, &mut event, shutdown)?;
                let buttons = event[0];
                let x = u16::from_be_bytes([event[1], event[2]]);
                let y = u16::from_be_bytes([event[3], event[4]]);
                if let Some(held_input) = &mut held_input {
                    held_input.pointer(x, y, buttons)?;
                } else if !input_warned {
                    eprintln!("rfb: pointer input is disabled; event ignored");
                    input_warned = true;
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

fn write_server_init(
    stream: &mut TcpStream,
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

fn handle_set_pixel_format(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<()> {
    let mut padding = [0u8; 3];
    read_exact_interruptible(stream, &mut padding, shutdown)?;

    let mut format = [0u8; 16];
    read_exact_interruptible(stream, &mut format, shutdown)?;
    validate_client_pixel_format(&format)
}

fn handle_set_encodings(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<Encoding> {
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

    select_encoding(&encodings)
}

fn select_encoding(encodings: &[u8]) -> io::Result<Encoding> {
    for encoding in encodings.chunks_exact(4) {
        let value = i32::from_be_bytes([encoding[0], encoding[1], encoding[2], encoding[3]]);
        match value {
            ENCODING_HEXTILE => return Ok(Encoding::Hextile),
            ENCODING_RAW => return Ok(Encoding::Raw),
            _ => {}
        }
    }
    Err(invalid_data(
        "client did not offer a supported encoding (Raw or Hextile)",
    ))
}

fn handle_update_request(
    stream: &mut TcpStream,
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
        send_update(stream, &changes.frame, &updates, state.encoding, shutdown)?;
        subtract_damage(&mut state.pending_damage, requested);
        return Ok(());
    }

    let deadline = Instant::now() + INCREMENTAL_TIMEOUT;
    loop {
        let mut changed_frame = None;
        if let Some(changes) = store.changes_since(state.last_sequence) {
            ensure_frame_dimensions(&changes.frame, width, height)?;
            accumulate_damage(
                &mut state.pending_damage,
                changes.damage,
                u32::from(width),
                u32::from(height),
            );
            state.last_sequence = changes.sequence;
            changed_frame = Some(changes.frame);
        }

        let updates = damage_within(&state.pending_damage, requested);
        if !updates.is_empty() {
            let updates = bounded_updates(updates, requested);
            let frame = match changed_frame {
                Some(frame) => frame,
                None => store
                    .latest()
                    .map(|(_, frame)| frame)
                    .ok_or_else(|| invalid_data("framebuffer is unavailable"))?,
            };
            ensure_frame_dimensions(&frame, width, height)?;
            send_update(stream, &frame, &updates, state.encoding, shutdown)?;
            subtract_damage(&mut state.pending_damage, requested);
            return Ok(());
        }

        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }
        if Instant::now() >= deadline {
            return send_empty_update(stream, shutdown);
        }
        let _ = store.wait_next(state.last_sequence, WAIT_SLICE);
    }
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
    stream: &mut TcpStream,
    frame: &Frame,
    rectangles: &[DamageRect],
    encoding: Encoding,
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

        let mut rectangle_header = [0u8; 12];
        rectangle_header[0..2].copy_from_slice(&x.to_be_bytes());
        rectangle_header[2..4].copy_from_slice(&y.to_be_bytes());
        rectangle_header[4..6].copy_from_slice(&width.to_be_bytes());
        rectangle_header[6..8].copy_from_slice(&height.to_be_bytes());
        rectangle_header[8..12].copy_from_slice(&encoding.rfb_value().to_be_bytes());
        write_all_interruptible(stream, &rectangle_header, shutdown)?;

        if encoding == Encoding::Hextile {
            send_hextile_rectangle(stream, frame, *rect, shutdown)?;
            continue;
        }

        let row_bytes = (width as usize)
            .checked_mul(4)
            .ok_or_else(|| invalid_data("rectangle is too wide"))?;

        // A full-width rectangle is contiguous in the normalized framebuffer.
        // Write it as one slice instead of making one socket write per row.
        if rect.x == 0 && width as usize == frame_width {
            let start = (rect.y as usize)
                .checked_mul(frame_width)
                .and_then(|pixel| pixel.checked_mul(4))
                .ok_or_else(|| invalid_data("rectangle offset overflows"))?;
            let byte_len = row_bytes
                .checked_mul(height as usize)
                .ok_or_else(|| invalid_data("rectangle size overflows"))?;
            let end = start
                .checked_add(byte_len)
                .ok_or_else(|| invalid_data("rectangle offset overflows"))?;
            let pixels = frame
                .data
                .get(start..end)
                .ok_or_else(|| invalid_data("rectangle is outside the framebuffer"))?;
            write_all_interruptible(stream, pixels, shutdown)?;
            continue;
        }

        for row in rect.y as usize..bottom as usize {
            let start = row
                .checked_mul(frame_width)
                .and_then(|pixel| pixel.checked_add(rect.x as usize))
                .and_then(|pixel| pixel.checked_mul(4))
                .ok_or_else(|| invalid_data("rectangle offset overflows"))?;
            let end = start
                .checked_add(row_bytes)
                .ok_or_else(|| invalid_data("rectangle offset overflows"))?;
            let pixels = frame
                .data
                .get(start..end)
                .ok_or_else(|| invalid_data("rectangle is outside the framebuffer"))?;
            write_all_interruptible(stream, pixels, shutdown)?;
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct HextileSubrect {
    x: u8,
    y: u8,
    width: u8,
    height: u8,
    color: [u8; 4],
}

fn send_hextile_rectangle(
    stream: &mut TcpStream,
    frame: &Frame,
    rectangle: DamageRect,
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
                tile_x,
                tile_y,
                tile_width,
                tile_height,
                shutdown,
            )?;
        }
    }

    Ok(())
}

fn send_hextile_tile(
    stream: &mut TcpStream,
    frame: &Frame,
    tile_x: u32,
    tile_y: u32,
    tile_width: u8,
    tile_height: u8,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    const BACKGROUND_SPECIFIED: u8 = 2;
    const FOREGROUND_SPECIFIED: u8 = 4;
    const ANY_SUBRECTS: u8 = 8;
    const SUBRECTS_COLOURED: u8 = 16;

    let mut frequencies = HashMap::<[u8; 4], usize>::with_capacity(16);
    let mut background = [0u8; 4];
    let mut most_frequent = 0usize;
    for y in 0..u32::from(tile_height) {
        for x in 0..u32::from(tile_width) {
            let color = frame_pixel(frame, tile_x + x, tile_y + y)?;
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
            let color = frame_pixel(frame, tile_x + u32::from(x), tile_y + u32::from(y))?;
            if color == background {
                x += 1;
                continue;
            }

            let run_start = x;
            x += 1;
            while x < tile_width
                && frame_pixel(frame, tile_x + u32::from(x), tile_y + u32::from(y))? == color
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
                    return send_raw_hextile_tile(
                        stream,
                        frame,
                        tile_x,
                        tile_y,
                        tile_width,
                        tile_height,
                        shutdown,
                    );
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
    let raw_size = 1 + usize::from(tile_width) * usize::from(tile_height) * 4;

    if !subrects.is_empty() && encoded_size >= raw_size {
        return send_raw_hextile_tile(
            stream,
            frame,
            tile_x,
            tile_y,
            tile_width,
            tile_height,
            shutdown,
        );
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
    write_all_interruptible(stream, &background, shutdown)?;

    if !subrects.is_empty() {
        if single_foreground {
            write_all_interruptible(stream, &foreground.unwrap_or([0; 4]), shutdown)?;
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
                write_all_interruptible(stream, &subrect.color, shutdown)?;
            }
        }
    }

    Ok(())
}

fn send_raw_hextile_tile(
    stream: &mut TcpStream,
    frame: &Frame,
    tile_x: u32,
    tile_y: u32,
    tile_width: u8,
    tile_height: u8,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    write_all_interruptible(stream, &[1], shutdown)?; // Raw tile subencoding
    let row_bytes = usize::from(tile_width) * 4;
    for row in 0..u32::from(tile_height) {
        let start = ((tile_y + row) as usize)
            .checked_mul(frame.width as usize)
            .and_then(|pixel| pixel.checked_add(tile_x as usize))
            .and_then(|pixel| pixel.checked_mul(4))
            .ok_or_else(|| invalid_data("Hextile tile offset overflows"))?;
        let end = start
            .checked_add(row_bytes)
            .ok_or_else(|| invalid_data("Hextile tile offset overflows"))?;
        let pixels = frame
            .data
            .get(start..end)
            .ok_or_else(|| invalid_data("Hextile tile is outside the framebuffer"))?;
        write_all_interruptible(stream, pixels, shutdown)?;
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
        if pressed {
            self.pressed_keys.insert(keysym);
        } else {
            self.pressed_keys.remove(&keysym);
        }
        Ok(())
    }

    fn pointer(&mut self, x: u16, y: u16, buttons: u8) -> io::Result<()> {
        self.sender
            .blocking_send(ClientEvent::Pointer { x, y, buttons })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "input handler stopped"))?;
        self.pointer = Some((x, y, buttons));
        Ok(())
    }
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

fn send_empty_update(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<()> {
    write_all_interruptible(stream, &[0, 0, 0, 0], shutdown)
}

fn read_message_type(
    stream: &mut TcpStream,
    shutdown: &AtomicBool,
    clipboard_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> io::Result<u8> {
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
            Ok(_) => return Ok(message_type[0]),
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
}

fn send_server_cut_text(
    stream: &mut TcpStream,
    text: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
    if text.len() > MAX_CUT_TEXT as usize {
        return Err(invalid_data("server clipboard text exceeds the size limit"));
    }
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

fn validate_client_pixel_format(format: &[u8; 16]) -> io::Result<()> {
    let bits_per_pixel = format[0];
    let depth = format[1];
    let big_endian = format[2];
    let true_color = format[3];
    let red_max = u16::from_be_bytes([format[4], format[5]]);
    let green_max = u16::from_be_bytes([format[6], format[7]]);
    let blue_max = u16::from_be_bytes([format[8], format[9]]);
    let red_shift = format[10];
    let green_shift = format[11];
    let blue_shift = format[12];

    if bits_per_pixel != 32
        || depth != 24
        || big_endian != 0
        || true_color != 1
        || red_max != 255
        || green_max != 255
        || blue_max != 255
        || red_shift != 16
        || green_shift != 8
        || blue_shift != 0
    {
        return Err(invalid_data(
            "unsupported client pixel format; 32bpp little-endian BGRA is required",
        ));
    }

    Ok(())
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

fn read_u8(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    read_exact_interruptible(stream, &mut byte, shutdown)?;
    Ok(byte[0])
}

fn read_u16(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    read_exact_interruptible(stream, &mut bytes, shutdown)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    read_exact_interruptible(stream, &mut bytes, shutdown)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_exact_interruptible(
    stream: &mut TcpStream,
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
    stream: &mut TcpStream,
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
    stream: &mut TcpStream,
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
        assert!(validate_client_pixel_format(&server_pixel_format()).is_ok());

        let mut wrong = server_pixel_format();
        wrong[0] = 16;
        assert!(validate_client_pixel_format(&wrong).is_err());

        let mut wrong = server_pixel_format();
        wrong[10] = 0;
        assert!(validate_client_pixel_format(&wrong).is_err());
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
        assert_eq!(select_encoding(&offered).unwrap(), Encoding::Hextile);

        offered.clear();
        offered.extend_from_slice(&raw);
        offered.extend_from_slice(&hextile);
        assert_eq!(select_encoding(&offered).unwrap(), Encoding::Raw);
        assert!(select_encoding(&42i32.to_be_bytes()).is_err());
    }

    #[test]
    fn hextile_encodes_solid_and_subrect_tiles() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let solid_pixels = [10, 20, 30, 255].repeat(4);
        let solid_frame = Frame::new(2, 2, solid_pixels).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            send_update(
                &mut stream,
                &solid_frame,
                &[DamageRect {
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 2,
                }],
                Encoding::Hextile,
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
            send_update(
                &mut stream,
                &frame,
                &[DamageRect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 4,
                }],
                Encoding::Hextile,
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

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

//! Framebuffer update encodings and update scheduling.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use flate2::{Compress, FlushCompress, Status};

#[cfg(test)]
use flate2::Compression;

use crate::cli::RfbEncoding;
use crate::framebuffer::{DamageRect, Frame, FrameDamage, FrameStore};

use super::damage::{
    MAX_UPDATE_RECTS, accumulate_damage, bounded_updates, damage_within, subtract_damage,
};
use super::hextile::send_hextile_rectangle;
use super::pixel::PixelFormat;
use super::zrle::send_zrle_rectangle;
use super::{
    INITIAL_FRAME_TIMEOUT, WAIT_SLICE, invalid_data, read_u8, read_u16, send_empty_update,
    shutdown_error, validate_rectangle, write_all_interruptible,
};

const ENCODING_COPY_RECT: i32 = 1;

const ENCODING_ZLIB: i32 = 6;

const ENCODING_POINTER_POS: i32 = -232;

const ENCODING_RICH_CURSOR: i32 = -239;

/// Pseudo-encoding announcing a framebuffer size change (DesktopSize).
const ENCODING_DESKTOP_SIZE: i32 = -223;

/// Per-client bound for the CopyRect shadow of the client's framebuffer.
/// Without a shadow CopyRect is simply not used.
const MAX_SHADOW_PIXELS: usize = 4 * 1024 * 1024;

/// Bound on the CopyRect source search across all candidate offsets.
const MAX_OFFSET_VISITS: usize = 200_000;

const ENCODING_RAW: i32 = 0;

pub(super) const ENCODING_HEXTILE: i32 = 5;

pub(super) const ENCODING_ZRLE: i32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Encoding {
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

pub(super) struct ClientUpdateState {
    pub(super) encoding: Encoding,
    pub(super) copy_rect_enabled: bool,
    pub(super) pixel_format: PixelFormat,
    pub(super) last_sequence: u64,
    pub(super) pending_damage: Vec<DamageRect>,
    pub(super) pending_update: Option<DamageRect>,
    pub(super) zrle_compressor: Compress,
    pub(super) zlib_compressor: Compress,
    pub(super) client_pixels: Option<Vec<[u8; 4]>>,
    pub(super) cursor_enabled: bool,
    pub(super) rich_cursor_enabled: bool,
    pub(super) pointer_pos_enabled: bool,
    pub(super) cursor_snapshot: crate::cursor::CursorSnapshot,
    pub(super) sent_cursor_shape_sequence: u64,
    pub(super) sent_cursor_position_sequence: u64,
    /// Cursor rectangle and shape sequence most recently composited into the
    /// image for clients without cursor pseudo-encodings.
    pub(super) drawn_cursor: Option<(DamageRect, u64)>,
    /// Whether the client announced the DesktopSize pseudo-encoding.
    pub(super) desktop_size_enabled: bool,
    /// Framebuffer size most recently announced to this client.
    pub(super) session_size: (u16, u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EncodingPreferences {
    pub(super) preferred: Encoding,
    pub(super) copy_rect: bool,
    pub(super) rich_cursor: bool,
    pub(super) pointer_pos: bool,
    pub(super) desktop_size: bool,
}

#[cfg(test)]
fn select_encodings(encodings: &[u8]) -> io::Result<EncodingPreferences> {
    select_encodings_with_allowlist(encodings, None)
}

pub(super) fn select_encodings_with_allowlist(
    encodings: &[u8],
    allowed: Option<&[RfbEncoding]>,
) -> io::Result<EncodingPreferences> {
    let mut preferred = None;
    let mut copy_rect = false;
    let mut rich_cursor = false;
    let mut pointer_pos = false;
    let mut desktop_size = false;
    for encoding in encodings.chunks_exact(4) {
        let value = i32::from_be_bytes([encoding[0], encoding[1], encoding[2], encoding[3]]);
        if value == ENCODING_RICH_CURSOR {
            rich_cursor = true;
            continue;
        }
        if value == ENCODING_POINTER_POS {
            pointer_pos = true;
            continue;
        }
        if value == ENCODING_DESKTOP_SIZE {
            desktop_size = true;
            continue;
        }
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
            rich_cursor,
            pointer_pos,
            desktop_size,
        })
        .ok_or_else(|| invalid_data("client did not offer a supported framebuffer encoding"))
}

pub(super) fn handle_update_request(
    stream: &mut (impl Read + Write),
    store: &FrameStore,
    state: &mut ClientUpdateState,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let incremental = read_u8(stream, shutdown)? != 0;
    let x = read_u16(stream, shutdown)?;
    let y = read_u16(stream, shutdown)?;
    let rectangle_width = read_u16(stream, shutdown)?;
    let rectangle_height = read_u16(stream, shutdown)?;

    let (width, height) = state.session_size;
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
    state.cursor_snapshot = store.cursor_snapshot();

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
        if sync_session_size(stream, state, &changes.frame, shutdown)? {
            // The DesktopSize update answered this request; the client asks
            // again for the content of its new framebuffer.
            return Ok(());
        }
        accumulate_damage(
            &mut state.pending_damage,
            changes.damage,
            changes.frame.width,
            changes.frame.height,
        );
        state.last_sequence = changes.sequence;

        let updates = vec![requested];
        send_update(stream, &changes.frame, &updates, state, shutdown)?;
        subtract_damage(&mut state.pending_damage, requested);
        if embed_cursor(state) {
            // The full requested region was redrawn, so any embedded cursor
            // within it is up to date.
            state.drawn_cursor = state
                .cursor_snapshot
                .shape
                .as_deref()
                .zip(state.cursor_snapshot.position)
                .and_then(|(shape, position)| cursor_rect(shape, position, width, height))
                .map(|rect| (rect, state.cursor_snapshot.shape_sequence));
        }
        return Ok(());
    }

    state.pending_update = Some(requested);
    service_pending_update(stream, store, state, shutdown)
}

pub(super) fn service_pending_update(
    stream: &mut (impl Read + Write),
    store: &FrameStore,
    state: &mut ClientUpdateState,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let (width, height) = state.session_size;
    state.cursor_snapshot = store.cursor_snapshot();
    let requested = match state.pending_update {
        Some(requested) => requested,
        None => return Ok(()),
    };

    let changed_frame = if let Some(changes) = store.changes_since(state.last_sequence) {
        if sync_session_size(stream, state, &changes.frame, shutdown)? {
            // The DesktopSize update answered the pending request.
            state.pending_update = None;
            return Ok(());
        }
        accumulate_damage(
            &mut state.pending_damage,
            changes.damage,
            changes.frame.width,
            changes.frame.height,
        );
        state.last_sequence = changes.sequence;
        Some(changes.frame)
    } else {
        None
    };

    // With the cursor composited into the image, its movement and shape
    // changes are damage like any other content change.
    if embed_cursor(state) {
        let current = state
            .cursor_snapshot
            .shape
            .as_deref()
            .zip(state.cursor_snapshot.position)
            .and_then(|(shape, position)| cursor_rect(shape, position, width, height))
            .map(|rect| (rect, state.cursor_snapshot.shape_sequence));
        if current != state.drawn_cursor {
            let frame_width = u32::from(width);
            let frame_height = u32::from(height);
            for rect in [
                state.drawn_cursor.map(|(rect, _)| rect),
                current.map(|(rect, _)| rect),
            ]
            .into_iter()
            .flatten()
            {
                accumulate_damage(
                    &mut state.pending_damage,
                    FrameDamage::Regions(vec![rect]),
                    frame_width,
                    frame_height,
                );
            }
            state.drawn_cursor = current;
        }
    }

    let updates = damage_within(&state.pending_damage, requested);
    let cursor_update_pending = state.cursor_enabled
        && ((state.rich_cursor_enabled
            && state.cursor_snapshot.shape.is_some()
            && state.cursor_snapshot.shape_sequence != state.sent_cursor_shape_sequence)
            || (state.pointer_pos_enabled
                && state.cursor_snapshot.position.is_some()
                && state.cursor_snapshot.position_sequence != state.sent_cursor_position_sequence));
    if updates.is_empty() && !cursor_update_pending {
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

/// Send a DesktopSize pseudo-rectangle announcing a new framebuffer size.
fn send_desktop_size(
    stream: &mut (impl Read + Write),
    size: (u16, u16),
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut header = [0u8; 4];
    header[2..4].copy_from_slice(&1u16.to_be_bytes());
    write_all_interruptible(stream, &header, shutdown)?;
    let mut rectangle = [0u8; 12];
    rectangle[4..6].copy_from_slice(&size.0.to_be_bytes());
    rectangle[6..8].copy_from_slice(&size.1.to_be_bytes());
    rectangle[8..12].copy_from_slice(&ENCODING_DESKTOP_SIZE.to_be_bytes());
    write_all_interruptible(stream, &rectangle, shutdown)
}

/// Announce a framebuffer resize to the client when the frame no longer
/// matches the size it was told about.
///
/// The resize invalidates the client's framebuffer, so its cached state is
/// dropped and the caller must not reuse damage accumulated for the old
/// size. Returns `true` when a resize was announced.
pub(super) fn sync_session_size(
    stream: &mut (impl Read + Write),
    state: &mut ClientUpdateState,
    frame: &Frame,
    shutdown: &AtomicBool,
) -> io::Result<bool> {
    let size = match (u16::try_from(frame.width), u16::try_from(frame.height)) {
        (Ok(width), Ok(height)) => (width, height),
        _ => return Err(invalid_data("framebuffer size exceeds RFB limits")),
    };
    if size == state.session_size {
        return Ok(false);
    }
    if !state.desktop_size_enabled {
        return Err(invalid_data(format!(
            "desktop size changed to {}x{}, but the client does not support DesktopSize",
            size.0, size.1
        )));
    }
    send_desktop_size(stream, size, shutdown)?;
    state.session_size = size;
    state.client_pixels = None;
    state.pending_damage.clear();
    state.drawn_cursor = None;
    Ok(true)
}

pub(super) fn send_update(
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

    let send_cursor = state.cursor_enabled
        && state.rich_cursor_enabled
        && state.cursor_snapshot.shape.is_some()
        && state.cursor_snapshot.shape_sequence != state.sent_cursor_shape_sequence;
    let send_pointer_pos = state.cursor_enabled
        && state.pointer_pos_enabled
        && state.cursor_snapshot.position.is_some()
        && state.cursor_snapshot.position_sequence != state.sent_cursor_position_sequence;
    // Clients without cursor pseudo-encodings receive the cursor as part of
    // the image. CopyRect is disabled for them: the client's shadow would not
    // contain the overlaid pixels.
    let embed = embed_cursor(state);
    let view = FrameView::new(
        frame,
        if embed {
            state
                .cursor_snapshot
                .shape
                .as_deref()
                .zip(state.cursor_snapshot.position)
        } else {
            None
        },
    );
    let shadow_enabled = state.copy_rect_enabled && !embed;

    let rectangle_count =
        rectangles.len() + usize::from(send_cursor) + usize::from(send_pointer_pos);
    let rectangle_count = u16::try_from(rectangle_count)
        .map_err(|_| invalid_data("too many rectangles in framebuffer update"))?;

    let mut header = [0u8; 4];
    header[0] = 0; // FramebufferUpdate
    header[1] = 0; // padding
    header[2..4].copy_from_slice(&rectangle_count.to_be_bytes());
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

        let copy_source = if shadow_enabled {
            state
                .client_pixels
                .as_deref()
                .and_then(|shadow| find_copy_source(&view, shadow, *rect, state.pixel_format))
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
            if shadow_enabled {
                update_client_shadow(&view, *rect, state.pixel_format, &mut state.client_pixels)?;
            }
            continue;
        }

        if state.encoding == Encoding::Hextile {
            send_hextile_rectangle(stream, &view, *rect, state.pixel_format, shutdown)?;
            if shadow_enabled {
                update_client_shadow(&view, *rect, state.pixel_format, &mut state.client_pixels)?;
            }
            continue;
        }

        if state.encoding == Encoding::Zrle {
            send_zrle_rectangle(
                stream,
                &view,
                *rect,
                state.pixel_format,
                &mut state.zrle_compressor,
                shutdown,
            )?;
            if shadow_enabled {
                update_client_shadow(&view, *rect, state.pixel_format, &mut state.client_pixels)?;
            }
            continue;
        }

        if state.encoding == Encoding::Zlib {
            send_zlib_rectangle(
                stream,
                &view,
                *rect,
                state.pixel_format,
                &mut state.zlib_compressor,
                shutdown,
            )?;
            if shadow_enabled {
                update_client_shadow(&view, *rect, state.pixel_format, &mut state.client_pixels)?;
            }
            continue;
        }

        send_raw_rectangle(stream, &view, *rect, state.pixel_format, shutdown)?;
        if shadow_enabled {
            update_client_shadow(&view, *rect, state.pixel_format, &mut state.client_pixels)?;
        }
    }

    if send_cursor {
        if let Some(shape) = state.cursor_snapshot.shape.as_deref() {
            send_rich_cursor(stream, shape, state.pixel_format, shutdown)?;
            state.sent_cursor_shape_sequence = state.cursor_snapshot.shape_sequence;
        }
    }
    if send_pointer_pos {
        if let Some(position) = state.cursor_snapshot.position {
            send_pointer_position(stream, position, frame.width, frame.height, shutdown)?;
            state.sent_cursor_position_sequence = state.cursor_snapshot.position_sequence;
        }
    }

    Ok(())
}

fn send_rich_cursor(
    stream: &mut (impl Read + Write),
    shape: &crate::cursor::CursorShape,
    pixel_format: PixelFormat,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let expected_pixels = usize::from(shape.width)
        .checked_mul(usize::from(shape.height))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| invalid_data("cursor dimensions overflow"))?;
    if shape.width == 0
        || shape.height == 0
        || shape.hotspot.0 >= shape.width
        || shape.hotspot.1 >= shape.height
        || expected_pixels > 4 * 1024 * 1024
        || shape.pixels.len() != expected_pixels
    {
        return Err(invalid_data("cursor shape is invalid or too large"));
    }
    let mut header = [0u8; 12];
    header[0..2].copy_from_slice(&shape.hotspot.0.to_be_bytes());
    header[2..4].copy_from_slice(&shape.hotspot.1.to_be_bytes());
    header[4..6].copy_from_slice(&shape.width.to_be_bytes());
    header[6..8].copy_from_slice(&shape.height.to_be_bytes());
    header[8..12].copy_from_slice(&ENCODING_RICH_CURSOR.to_be_bytes());
    write_all_interruptible(stream, &header, shutdown)?;

    let bytes_per_pixel = pixel_format.bytes_per_pixel();
    for bgra in shape.pixels.chunks_exact(4) {
        let encoded = pixel_format.encode(bgra);
        write_all_interruptible(stream, &encoded[..bytes_per_pixel], shutdown)?;
    }

    let width = usize::from(shape.width);
    let height = usize::from(shape.height);
    let mask_stride = width.div_ceil(8);
    let mut mask = vec![0u8; mask_stride * height];
    for y in 0..height {
        for x in 0..width {
            let alpha = shape.pixels[(y * width + x) * 4 + 3];
            if alpha != 0 {
                mask[y * mask_stride + x / 8] |= 1 << (7 - x % 8);
            }
        }
    }
    write_all_interruptible(stream, &mask, shutdown)
}

fn send_pointer_position(
    stream: &mut (impl Read + Write),
    position: (i32, i32),
    framebuffer_width: u32,
    framebuffer_height: u32,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    if framebuffer_width == 0 || framebuffer_height == 0 {
        return Err(invalid_data("framebuffer dimensions are invalid"));
    }
    let x = position.0.clamp(0, framebuffer_width as i32 - 1) as u16;
    let y = position.1.clamp(0, framebuffer_height as i32 - 1) as u16;
    let mut header = [0u8; 12];
    header[0..2].copy_from_slice(&x.to_be_bytes());
    header[2..4].copy_from_slice(&y.to_be_bytes());
    header[4..6].copy_from_slice(&0u16.to_be_bytes());
    header[6..8].copy_from_slice(&0u16.to_be_bytes());
    header[8..12].copy_from_slice(&ENCODING_POINTER_POS.to_be_bytes());
    write_all_interruptible(stream, &header, shutdown)
}

fn send_raw_rectangle(
    stream: &mut (impl Read + Write),
    view: &FrameView<'_>,
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
        // Layout-equivalent formats need no per-pixel encoding: the captured
        // bytes are already the client's bytes. The nominal depth does not
        // matter here, only the channel layout.
        if pixel_format.matches_bgra_layout() && !view.has_cursor() {
            let start = (y as usize)
                .checked_mul(view.frame.width as usize)
                .and_then(|row| row.checked_add(rectangle.x as usize))
                .and_then(|pixel| pixel.checked_mul(4))
                .ok_or_else(|| invalid_data("raw rectangle offset overflows"))?;
            let end = start
                .checked_add(row_capacity)
                .ok_or_else(|| invalid_data("raw rectangle offset overflows"))?;
            let row = view
                .frame
                .data
                .get(start..end)
                .ok_or_else(|| invalid_data("raw rectangle is outside the framebuffer"))?;
            write_all_interruptible(stream, row, shutdown)?;
            continue;
        }
        let mut row = Vec::with_capacity(row_capacity);
        for x in rectangle.x..rectangle.x + rectangle.width {
            let bgra = view.pixel(x, y)?;
            row.extend_from_slice(&pixel_format.encode(&bgra)[..bytes_per_pixel]);
        }
        write_all_interruptible(stream, &row, shutdown)?;
    }
    Ok(())
}

fn update_client_shadow(
    view: &FrameView<'_>,
    rectangle: DamageRect,
    pixel_format: PixelFormat,
    shadow: &mut Option<Vec<[u8; 4]>>,
) -> io::Result<()> {
    let frame = view.frame;
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
        if capacity > MAX_SHADOW_PIXELS {
            // Bounded per-client memory wins over CopyRect; without a shadow
            // the encoding is simply not used.
            return Ok(());
        }
        let mut initial = Vec::new();
        initial.try_reserve_exact(capacity).map_err(|error| {
            io::Error::other(format!(
                "could not allocate client framebuffer shadow: {error}"
            ))
        })?;
        for y in 0..frame.height {
            for x in 0..frame.width {
                initial.push(encoded_frame_pixel(
                    &FrameView::plain(frame),
                    x,
                    y,
                    pixel_format,
                )?);
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
            *slot = encoded_frame_pixel(&FrameView::plain(frame), x, y, pixel_format)?;
        }
    }
    Ok(())
}

fn find_copy_source(
    view: &FrameView<'_>,
    shadow: &[[u8; 4]],
    rectangle: DamageRect,
    pixel_format: PixelFormat,
) -> Option<(u16, u16)> {
    let frame = view.frame;
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
        encoded_frame_pixel(view, rectangle.x, rectangle.y, pixel_format).ok()?;
    let mut tested = 0usize;
    let mut visited = 0usize;
    let mut comparison_budget = MAX_COMPARE_PIXELS;

    for radius in 1..=SEARCH_RADIUS {
        for offset_y in -radius..=radius {
            for offset_x in -radius..=radius {
                visited += 1;
                if visited > MAX_OFFSET_VISITS {
                    return None;
                }
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
                        let target =
                            encoded_frame_pixel(view, rectangle.x + column, target_y, pixel_format)
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
    view: &FrameView<'_>,
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
    if pixel_format.matches_bgra_layout() && !view.has_cursor() {
        // Encoded pixels are the captured bytes unchanged, so whole rows can
        // be copied instead of encoded pixel by pixel.
        let row_bytes = usize::try_from(rectangle.width)
            .ok()
            .and_then(|width| width.checked_mul(bytes_per_pixel))
            .ok_or_else(|| invalid_data("encoded rectangle size overflows"))?;
        for y in rectangle.y..rectangle.y + rectangle.height {
            let start = (y as usize)
                .checked_mul(view.frame.width as usize)
                .and_then(|row| row.checked_add(rectangle.x as usize))
                .and_then(|pixel| pixel.checked_mul(4))
                .ok_or_else(|| invalid_data("encoded rectangle offset overflows"))?;
            let end = start
                .checked_add(row_bytes)
                .ok_or_else(|| invalid_data("encoded rectangle offset overflows"))?;
            let row = view
                .frame
                .data
                .get(start..end)
                .ok_or_else(|| invalid_data("encoded rectangle is outside the framebuffer"))?;
            pixels.extend_from_slice(row);
        }
        return Ok(pixels);
    }
    for y in rectangle.y..rectangle.y + rectangle.height {
        for x in rectangle.x..rectangle.x + rectangle.width {
            let bgra = view.pixel(x, y)?;
            pixels.extend_from_slice(&pixel_format.encode(&bgra)[..bytes_per_pixel]);
        }
    }
    Ok(pixels)
}

fn send_zlib_rectangle(
    stream: &mut (impl Read + Write),
    view: &FrameView<'_>,
    rectangle: DamageRect,
    pixel_format: PixelFormat,
    compressor: &mut Compress,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let pixels = encode_rectangle_pixels(view, rectangle, pixel_format)?;
    let compressed = compress_sync(compressor, &pixels)?;
    let length = u32::try_from(compressed.len())
        .map_err(|_| invalid_data("compressed Zlib rectangle exceeds RFB limit"))?;
    write_all_interruptible(stream, &length.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, &compressed, shutdown)
}

pub(super) fn compress_sync(compressor: &mut Compress, input: &[u8]) -> io::Result<Vec<u8>> {
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

pub(super) fn frame_pixel(frame: &Frame, x: u32, y: u32) -> io::Result<[u8; 4]> {
    let start = (y as usize)
        .checked_mul(frame.width as usize)
        .and_then(|pixel| pixel.checked_add(x as usize))
        .and_then(|pixel| pixel.checked_mul(4))
        .ok_or_else(|| invalid_data("frame pixel offset overflows"))?;
    let end = start
        .checked_add(4)
        .ok_or_else(|| invalid_data("frame pixel offset overflows"))?;
    let pixel = frame
        .data
        .get(start..end)
        .ok_or_else(|| invalid_data("frame pixel is outside the framebuffer"))?;
    Ok([pixel[0], pixel[1], pixel[2], pixel[3]])
}

/// A framebuffer view that blends an optional cursor image into the pixels at
/// encoding time, for clients without cursor pseudo-encodings.
pub(super) struct FrameView<'a> {
    frame: &'a Frame,
    /// Cursor image and the image coordinates of its top-left corner.
    cursor: Option<(&'a crate::cursor::CursorShape, i32, i32)>,
}

impl<'a> FrameView<'a> {
    /// View `frame`, drawing `cursor` at the pointer position when given.
    pub(super) fn new(
        frame: &'a Frame,
        cursor: Option<(&'a crate::cursor::CursorShape, (i32, i32))>,
    ) -> Self {
        let cursor = cursor.map(|(shape, position)| {
            (
                shape,
                position.0 - i32::from(shape.hotspot.0),
                position.1 - i32::from(shape.hotspot.1),
            )
        });
        Self { frame, cursor }
    }

    /// The frame without any cursor overlay.
    pub(super) fn plain(frame: &'a Frame) -> Self {
        Self {
            frame,
            cursor: None,
        }
    }

    pub(super) fn has_cursor(&self) -> bool {
        self.cursor.is_some()
    }

    /// One pixel, with the cursor blended over the frame when present.
    pub(super) fn pixel(&self, x: u32, y: u32) -> io::Result<[u8; 4]> {
        let mut pixel = frame_pixel(self.frame, x, y)?;
        if let Some((shape, left, top)) = self.cursor {
            let x = i32::try_from(x).unwrap_or(i32::MAX);
            let y = i32::try_from(y).unwrap_or(i32::MAX);
            if let Some(cursor_pixel) = cursor_pixel_at(shape, left, top, x, y) {
                pixel = blend_over(pixel, cursor_pixel);
            }
        }
        Ok(pixel)
    }
}

/// The cursor pixel covering an image coordinate, if any.
fn cursor_pixel_at(
    shape: &crate::cursor::CursorShape,
    left: i32,
    top: i32,
    x: i32,
    y: i32,
) -> Option<[u8; 4]> {
    let offset_x = x.checked_sub(left)?;
    let offset_y = y.checked_sub(top)?;
    if offset_x < 0
        || offset_y < 0
        || offset_x >= i32::from(shape.width)
        || offset_y >= i32::from(shape.height)
    {
        return None;
    }
    let index = (offset_y as usize * usize::from(shape.width) + offset_x as usize) * 4;
    let pixel = shape.pixels.get(index..index + 4)?;
    Some([pixel[0], pixel[1], pixel[2], pixel[3]])
}

/// Source-over alpha blend of a cursor pixel onto a frame pixel.
fn blend_over(destination: [u8; 4], source: [u8; 4]) -> [u8; 4] {
    let alpha = u32::from(source[3]);
    if alpha == 0 {
        return destination;
    }
    if alpha == 255 {
        return source;
    }
    let inverse = 255 - alpha;
    let blend = |source: u8, destination: u8| {
        ((u32::from(source) * alpha + u32::from(destination) * inverse + 127) / 255) as u8
    };
    [
        blend(source[0], destination[0]),
        blend(source[1], destination[1]),
        blend(source[2], destination[2]),
        ((alpha * 255 + u32::from(destination[3]) * inverse + 127) / 255) as u8,
    ]
}

/// The on-image rectangle covered by an embedded cursor, clipped to the frame.
fn cursor_rect(
    shape: &crate::cursor::CursorShape,
    position: (i32, i32),
    width: u16,
    height: u16,
) -> Option<DamageRect> {
    let left = position.0 - i32::from(shape.hotspot.0);
    let top = position.1 - i32::from(shape.hotspot.1);
    let right = left + i32::from(shape.width);
    let bottom = top + i32::from(shape.height);
    let left = left.clamp(0, i32::from(width));
    let top = top.clamp(0, i32::from(height));
    let right = right.clamp(left, i32::from(width));
    let bottom = bottom.clamp(top, i32::from(height));
    if left == right || top == bottom {
        return None;
    }
    Some(DamageRect {
        x: left as u32,
        y: top as u32,
        width: (right - left) as u32,
        height: (bottom - top) as u32,
    })
}

/// Clients without cursor pseudo-encodings get the cursor composited into
/// the image instead.
fn embed_cursor(state: &ClientUpdateState) -> bool {
    state.cursor_enabled && !state.rich_cursor_enabled && !state.pointer_pos_enabled
}

pub(super) fn encoded_frame_pixel(
    view: &FrameView<'_>,
    x: u32,
    y: u32,
    pixel_format: PixelFormat,
) -> io::Result<[u8; 4]> {
    Ok(pixel_format.encode(&view.pixel(x, y)?))
}

#[cfg(test)]
pub(crate) fn test_update_state(encoding: Encoding, copy_rect_enabled: bool) -> ClientUpdateState {
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
        cursor_enabled: false,
        rich_cursor_enabled: false,
        pointer_pos_enabled: false,
        cursor_snapshot: crate::cursor::CursorSnapshot::default(),
        sent_cursor_shape_sequence: 0,
        sent_cursor_position_sequence: 0,
        drawn_cursor: None,
        desktop_size_enabled: false,
        session_size: (1, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use std::io::{Cursor, Read};
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::thread;

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
                rich_cursor: false,
                pointer_pos: false,
                desktop_size: false,
            }
        );
        let raw_only = [RfbEncoding::Raw];
        assert_eq!(
            select_encodings_with_allowlist(&offered, Some(&raw_only)).unwrap(),
            EncodingPreferences {
                preferred: Encoding::Raw,
                copy_rect: false,
                rich_cursor: false,
                pointer_pos: false,
                desktop_size: false,
            }
        );
        assert!(select_encodings(&42i32.to_be_bytes()).is_err());
    }

    #[test]
    fn negotiates_cursor_pseudo_encodings_separately_from_frame_encoding() {
        let mut offered = ENCODING_RAW.to_be_bytes().to_vec();
        offered.extend_from_slice(&ENCODING_RICH_CURSOR.to_be_bytes());
        offered.extend_from_slice(&ENCODING_POINTER_POS.to_be_bytes());
        let selected = select_encodings(&offered).unwrap();
        assert_eq!(selected.preferred, Encoding::Raw);
        assert!(selected.rich_cursor);
        assert!(selected.pointer_pos);
    }

    #[test]
    fn sends_rich_cursor_shape_and_pointer_position_pseudo_rectangles() {
        let frame = Frame::new(2, 1, vec![0; 8]).unwrap();
        let shape = crate::cursor::CursorShape {
            width: 2,
            height: 1,
            hotspot: (1, 0),
            pixels: Arc::new(vec![1, 2, 3, 255, 4, 5, 6, 0]),
        };
        let mut state = test_update_state(Encoding::Raw, false);
        state.cursor_enabled = true;
        state.rich_cursor_enabled = true;
        state.pointer_pos_enabled = true;
        state.cursor_snapshot = crate::cursor::CursorSnapshot {
            position: Some((1, 0)),
            position_sequence: 1,
            shape: Some(Arc::new(shape)),
            shape_sequence: 1,
        };
        let mut output = std::io::Cursor::new(Vec::new());

        send_update(
            &mut output,
            &frame,
            &[],
            &mut state,
            &AtomicBool::new(false),
        )
        .unwrap();

        let output = output.into_inner();
        assert_eq!(&output[..4], &[0, 0, 0, 2]);
        let cursor_rect = &output[4..16];
        assert_eq!(&cursor_rect[..8], &[0, 1, 0, 0, 0, 2, 0, 1]);
        assert_eq!(
            i32::from_be_bytes(cursor_rect[8..12].try_into().unwrap()),
            ENCODING_RICH_CURSOR
        );
        assert_eq!(&output[16..24], &[1, 2, 3, 255, 4, 5, 6, 0]);
        assert_eq!(output[24], 0x80);
        let pointer_rect = &output[25..37];
        assert_eq!(&pointer_rect[..8], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            i32::from_be_bytes(pointer_rect[8..12].try_into().unwrap()),
            ENCODING_POINTER_POS
        );
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
                    &FrameView::plain(&frame),
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
    fn bgra_layout_fast_paths_copy_captured_bytes() {
        let frame = Frame::new(
            2,
            2,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .unwrap();
        // macOS Screen Sharing negotiates this layout with depth 32; the
        // fast paths must apply to it and copy the captured bytes.
        let mut depth_32 = PixelFormat::DEFAULT;
        depth_32.depth = 32;
        let rectangle = DamageRect {
            x: 1,
            y: 0,
            width: 1,
            height: 2,
        };

        // The Zlib/ZRLE pixel path copies rows for layout-equivalent formats.
        let pixels =
            encode_rectangle_pixels(&FrameView::plain(&frame), rectangle, depth_32).unwrap();
        assert_eq!(pixels, vec![5, 6, 7, 8, 13, 14, 15, 16]);

        // The Raw socket path does the same.
        let mut sink = Cursor::new(Vec::new());
        send_raw_rectangle(
            &mut sink,
            &FrameView::plain(&frame),
            rectangle,
            depth_32,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(sink.into_inner(), vec![5, 6, 7, 8, 13, 14, 15, 16]);
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
    fn cursor_blend_uses_alpha_and_the_cursor_origin() {
        let frame = Frame::new(2, 1, vec![10, 20, 30, 255, 10, 20, 30, 255]).unwrap();
        let opaque = crate::cursor::CursorShape {
            width: 1,
            height: 1,
            hotspot: (0, 0),
            pixels: Arc::new(vec![1, 2, 3, 255]),
        };
        // The image origin is the pointer position minus the hotspot.
        let view = FrameView::new(&frame, Some((&opaque, (1, 0))));
        assert_eq!(view.pixel(0, 0).unwrap(), [10, 20, 30, 255]);
        assert_eq!(view.pixel(1, 0).unwrap(), [1, 2, 3, 255]);

        let transparent = crate::cursor::CursorShape {
            pixels: Arc::new(vec![1, 2, 3, 0]),
            ..opaque.clone()
        };
        let view = FrameView::new(&frame, Some((&transparent, (0, 0))));
        assert_eq!(view.pixel(0, 0).unwrap(), [10, 20, 30, 255]);
    }

    #[test]
    fn cursor_rect_clips_to_the_frame() {
        let shape = crate::cursor::CursorShape {
            width: 2,
            height: 2,
            hotspot: (1, 1),
            pixels: Arc::new(vec![0; 16]),
        };
        assert_eq!(
            cursor_rect(&shape, (1, 1), 4, 4),
            Some(DamageRect {
                x: 0,
                y: 0,
                width: 2,
                height: 2
            })
        );
        // A cursor sticking out past the top-left corner covers one pixel.
        assert_eq!(
            cursor_rect(&shape, (0, 0), 4, 4),
            Some(DamageRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1
            })
        );
        assert_eq!(cursor_rect(&shape, (-10, -10), 4, 4), None);
    }

    #[test]
    fn desktop_size_announcement_invalidates_client_state() {
        let mut state = test_update_state(Encoding::Raw, false);
        state.desktop_size_enabled = true;
        state.session_size = (2, 2);
        state.pending_damage = vec![DamageRect {
            x: 0,
            y: 0,
            width: 2,
            height: 2,
        }];
        state.drawn_cursor = Some((
            DamageRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
            3,
        ));
        state.client_pixels = Some(vec![[0; 4]; 4]);

        let frame = Frame::new(3, 3, vec![7; 36]).unwrap();
        let mut out = Cursor::new(Vec::new());
        assert!(sync_session_size(&mut out, &mut state, &frame, &AtomicBool::new(false)).unwrap());
        assert_eq!(state.session_size, (3, 3));
        assert!(state.client_pixels.is_none());
        assert!(state.pending_damage.is_empty());
        assert!(state.drawn_cursor.is_none());
        // A DesktopSize update: header (4) and one rectangle (12), no data.
        let bytes = out.into_inner();
        assert_eq!(bytes.len(), 4 + 12);
        assert_eq!(&bytes[4..6], &[0, 0]);
        assert_eq!(&bytes[8..10], &[0, 3]);
        assert_eq!(&bytes[10..12], &[0, 3]);
        assert_eq!(i32::from_be_bytes(bytes[12..16].try_into().unwrap()), -223);

        // The same size announces nothing.
        let mut out = Cursor::new(Vec::new());
        assert!(!sync_session_size(&mut out, &mut state, &frame, &AtomicBool::new(false)).unwrap());
        assert!(out.into_inner().is_empty());

        // Clients without the pseudo-encoding are disconnected instead.
        let mut plain = test_update_state(Encoding::Raw, false);
        plain.session_size = (2, 2);
        assert!(
            sync_session_size(
                &mut Cursor::new(Vec::new()),
                &mut plain,
                &frame,
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }

    #[test]
    fn desktop_size_support_is_detected_from_the_encoding_list() {
        let mut offered = ENCODING_RAW.to_be_bytes().to_vec();
        offered.extend_from_slice(&ENCODING_DESKTOP_SIZE.to_be_bytes());
        assert!(select_encodings(&offered).unwrap().desktop_size);
        assert!(
            !select_encodings(&ENCODING_RAW.to_be_bytes())
                .unwrap()
                .desktop_size
        );
    }

    #[test]
    fn embedded_cursor_is_blended_into_raw_updates() {
        let frame = Frame::new(2, 2, [9u8, 9, 9, 255].repeat(4)).unwrap();
        let shape = crate::cursor::CursorShape {
            width: 1,
            height: 1,
            hotspot: (0, 0),
            pixels: Arc::new(vec![1, 2, 3, 255]),
        };
        let mut state = test_update_state(Encoding::Raw, false);
        state.cursor_enabled = true;
        state.cursor_snapshot = crate::cursor::CursorSnapshot {
            position: Some((1, 0)),
            position_sequence: 1,
            shape: Some(Arc::new(shape)),
            shape_sequence: 1,
        };
        let mut out = Cursor::new(Vec::new());
        send_update(
            &mut out,
            &frame,
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

        let bytes = out.into_inner();
        // FramebufferUpdate header (4), rectangle header (12), four pixels.
        assert_eq!(bytes.len(), 4 + 12 + 16);
        assert_eq!(&bytes[4 + 12..4 + 12 + 4], &[9, 9, 9, 255]);
        assert_eq!(&bytes[4 + 12 + 4..4 + 12 + 8], &[1, 2, 3, 255]);
    }
}

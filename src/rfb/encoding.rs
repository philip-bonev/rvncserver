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

//! Framebuffer update encodings, damage tracking, and update scheduling.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use flate2::{Compress, FlushCompress, Status};

use crate::cli::RfbEncoding;
use crate::framebuffer::{DamageRect, Frame, FrameDamage, FrameStore};

use super::pixel::PixelFormat;
use super::{
    INITIAL_FRAME_TIMEOUT, WAIT_SLICE, invalid_data, read_u8, read_u16, send_empty_update,
    shutdown_error, validate_rectangle, write_all_interruptible,
};

const ENCODING_COPY_RECT: i32 = 1;

const ENCODING_ZLIB: i32 = 6;

const ENCODING_POINTER_POS: i32 = -232;

const ENCODING_RICH_CURSOR: i32 = -239;

const MAX_UPDATE_RECTS: usize = 128;

/// Per-client bound for the CopyRect shadow of the client's framebuffer.
/// Without a shadow CopyRect is simply not used.
const MAX_SHADOW_PIXELS: usize = 4 * 1024 * 1024;

/// Bound on the CopyRect source search across all candidate offsets.
const MAX_OFFSET_VISITS: usize = 200_000;

const ENCODING_RAW: i32 = 0;

const ENCODING_HEXTILE: i32 = 5;

const ENCODING_ZRLE: i32 = 16;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EncodingPreferences {
    pub(super) preferred: Encoding,
    pub(super) copy_rect: bool,
    pub(super) rich_cursor: bool,
    pub(super) pointer_pos: bool,
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
        })
        .ok_or_else(|| invalid_data("client did not offer a supported framebuffer encoding"))
}

pub(super) fn handle_update_request(
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

pub(super) fn service_pending_update(
    stream: &mut (impl Read + Write),
    store: &FrameStore,
    width: u16,
    height: u16,
    state: &mut ClientUpdateState,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    state.cursor_snapshot = store.cursor_snapshot();
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

    let send_cursor = state.cursor_enabled
        && state.rich_cursor_enabled
        && state.cursor_snapshot.shape.is_some()
        && state.cursor_snapshot.shape_sequence != state.sent_cursor_shape_sequence;
    let send_pointer_pos = state.cursor_enabled
        && state.pointer_pos_enabled
        && state.cursor_snapshot.position.is_some()
        && state.cursor_snapshot.position_sequence != state.sent_cursor_position_sequence;
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

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use std::io::Read;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::sync::Arc;
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
            cursor_enabled: false,
            rich_cursor_enabled: false,
            pointer_pos_enabled: false,
            cursor_snapshot: crate::cursor::CursorSnapshot::default(),
            sent_cursor_shape_sequence: 0,
            sent_cursor_position_sequence: 0,
        }
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

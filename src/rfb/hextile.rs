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

//! Hextile framebuffer-update encoding.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::atomic::AtomicBool;

use crate::framebuffer::DamageRect;

use super::encoding::{FrameView, encoded_frame_pixel};
use super::pixel::PixelFormat;
use super::write_all_interruptible;

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

pub(super) fn send_hextile_rectangle(
    stream: &mut (impl Read + Write),
    view: &FrameView<'_>,
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
                view,
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
    view: &FrameView<'_>,
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
            let color = encoded_frame_pixel(view, tile_x + x, tile_y + y, pixel_format)?;
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
                view,
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
                    view,
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
                    return send_raw_hextile_tile(stream, view, tile, pixel_format, shutdown);
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
        return send_raw_hextile_tile(stream, view, tile, pixel_format, shutdown);
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
    view: &FrameView<'_>,
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
            let pixel = encoded_frame_pixel(view, tile_x + column, tile_y + row, pixel_format)?;
            write_all_interruptible(stream, &pixel[..pixel_format.bytes_per_pixel()], shutdown)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::{DamageRect, Frame};
    use crate::rfb::encoding::{ENCODING_HEXTILE, Encoding, send_update, test_update_state};
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

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
}

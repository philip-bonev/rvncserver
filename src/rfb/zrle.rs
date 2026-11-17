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

//! ZRLE framebuffer-update encoding.
//!
//! Every tile is emitted with the smallest of its applicable subencodings:
//! solid (1), packed palette (2-16), palette RLE (130-255), plain RLE (128),
//! or raw (0). Runs may continue from one tile row to the next, as the
//! protocol allows.

use std::io::{self, Read, Write};
use std::sync::atomic::AtomicBool;

use flate2::Compress;

use crate::framebuffer::{DamageRect, Frame};

use super::encoding::{compress_sync, frame_pixel};
use super::pixel::PixelFormat;
use super::{invalid_data, write_all_interruptible};

/// Palette RLE subencodings (130-255) allow at most 127 palette entries.
const MAX_RLE_PALETTE: usize = 127;
/// Packed palette subencodings (2-16) allow at most 16 palette entries.
const MAX_PACKED_PALETTE: usize = 16;

pub(super) fn send_zrle_rectangle(
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
            let mut pixels = Vec::with_capacity(tile_width as usize * tile_height as usize);
            for y in tile_y..tile_y + tile_height {
                for x in tile_x..tile_x + tile_width {
                    let bgra = frame_pixel(frame, x, y)?;
                    pixels.push(pixel_format.encode_zrle(&bgra));
                }
            }
            encode_tile(&mut raw, &pixels, tile_width, c_pixel_size);
        }
    }

    let compressed = compress_sync(compressor, &raw)?;

    let compressed_len = u32::try_from(compressed.len())
        .map_err(|_| invalid_data("compressed ZRLE rectangle exceeds RFB limit"))?;
    write_all_interruptible(stream, &compressed_len.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, &compressed, shutdown)
}

/// The ZRLE tile subencodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TileEncoding {
    Solid,
    PackedPalette,
    PaletteRle,
    PlainRle,
    Raw,
}

/// Encode one tile with its smallest subencoding.
///
/// `pixels` are ZRLE CPIXEL values in row-major order, each stored in four
/// bytes of which only `c_pixel_size` are sent on the wire.
fn encode_tile(out: &mut Vec<u8>, pixels: &[[u8; 4]], width: u32, c_pixel_size: usize) {
    let runs = pixel_runs(pixels);
    let palette = build_palette(pixels);

    let run_length_bytes = |length: usize| (length - 1) / 255 + 1;
    let raw_size = 1 + pixels.len() * c_pixel_size;
    let plain_rle_size = 1 + runs
        .iter()
        .map(|(_, length)| c_pixel_size + run_length_bytes(*length))
        .sum::<usize>();

    let mut best = (raw_size, TileEncoding::Raw);
    let mut consider = |size: usize, encoding: TileEncoding| {
        if size < best.0 {
            best = (size, encoding);
        }
    };
    consider(plain_rle_size, TileEncoding::PlainRle);
    if let Some(palette) = palette.as_deref() {
        match palette.len() {
            0..=1 => {}
            2..=MAX_RLE_PALETTE => {
                let size = 1
                    + palette.len() * c_pixel_size
                    + runs
                        .iter()
                        .map(|(_, length)| {
                            1 + if *length > 1 {
                                run_length_bytes(*length)
                            } else {
                                0
                            }
                        })
                        .sum::<usize>();
                consider(size, TileEncoding::PaletteRle);
            }
            _ => {}
        }
        if (2..=MAX_PACKED_PALETTE).contains(&palette.len()) {
            let bits = packed_bits(palette.len());
            let row_bytes = (width as usize * bits).div_ceil(8);
            let rows = pixels.len() / width as usize;
            consider(
                1 + palette.len() * c_pixel_size + row_bytes * rows,
                TileEncoding::PackedPalette,
            );
        }
        if palette.len() == 1 {
            consider(1 + c_pixel_size, TileEncoding::Solid);
        }
    }

    match best.1 {
        TileEncoding::Solid => {
            out.push(1);
            out.extend_from_slice(&pixels[0][..c_pixel_size]);
        }
        TileEncoding::PackedPalette => {
            let palette = palette.as_deref().unwrap_or_default();
            out.push(palette.len() as u8);
            for color in palette {
                out.extend_from_slice(&color[..c_pixel_size]);
            }
            let bits = packed_bits(palette.len());
            for row in pixels.chunks(width as usize) {
                let mut byte = 0u8;
                let mut filled = 0u32;
                for pixel in row {
                    let index = palette_index(palette, pixel);
                    byte = (byte << bits) | index;
                    filled += bits as u32;
                    if filled == 8 {
                        out.push(byte);
                        byte = 0;
                        filled = 0;
                    }
                }
                if filled > 0 {
                    out.push(byte << (8 - filled));
                }
            }
        }
        TileEncoding::PaletteRle => {
            let palette = palette.as_deref().unwrap_or_default();
            out.push(128 + palette.len() as u8);
            for color in palette {
                out.extend_from_slice(&color[..c_pixel_size]);
            }
            for (pixel, length) in &runs {
                let index = palette_index(palette, pixel);
                if *length == 1 {
                    out.push(index);
                } else {
                    out.push(index + 128);
                    push_run_length(out, *length);
                }
            }
        }
        TileEncoding::PlainRle => {
            out.push(128);
            for (pixel, length) in &runs {
                out.extend_from_slice(&pixel[..c_pixel_size]);
                push_run_length(out, *length);
            }
        }
        TileEncoding::Raw => {
            out.push(0);
            for pixel in pixels {
                out.extend_from_slice(&pixel[..c_pixel_size]);
            }
        }
    }
}

/// Split pixels into maximal runs of equal values. Runs may cross row
/// boundaries, as ZRLE allows.
fn pixel_runs(pixels: &[[u8; 4]]) -> Vec<(&[u8; 4], usize)> {
    let mut runs = Vec::new();
    let mut start = 0;
    for index in 1..=pixels.len() {
        if index == pixels.len() || pixels[index] != pixels[start] {
            runs.push((&pixels[start], index - start));
            start = index;
        }
    }
    runs
}

/// Distinct colors in first-seen order, or `None` when the tile has more than
/// palette RLE can represent.
fn build_palette(pixels: &[[u8; 4]]) -> Option<Vec<[u8; 4]>> {
    let mut palette: Vec<[u8; 4]> = Vec::new();
    for pixel in pixels {
        if !palette.contains(pixel) {
            palette.push(*pixel);
            if palette.len() > MAX_RLE_PALETTE {
                return None;
            }
        }
    }
    Some(palette)
}

/// Palette index of a pixel; every tile pixel is a palette member by
/// construction.
fn palette_index(palette: &[[u8; 4]], pixel: &[u8; 4]) -> u8 {
    palette
        .iter()
        .position(|color| color == pixel)
        .map_or(0, |index| index as u8)
}

/// Bit width of a packed palette index field.
fn packed_bits(palette_size: usize) -> usize {
    match palette_size {
        2 => 1,
        3..=4 => 2,
        _ => 4,
    }
}

/// Append a run length: one or more bytes whose sum plus one is the length,
/// where 255 continues and any other byte terminates.
fn push_run_length(out: &mut Vec<u8>, length: usize) {
    let mut remaining = length - 1;
    while remaining >= 255 {
        out.push(255);
        remaining -= 255;
    }
    out.push(remaining as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::{DamageRect, Frame};
    use flate2::Compression;
    use std::io::{Cursor, Read};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

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

    /// Independent ZRLE decoder used to verify the encoder against the spec.
    struct ZrleDecoder<'a> {
        data: &'a [u8],
        position: usize,
    }

    impl<'a> ZrleDecoder<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data, position: 0 }
        }

        fn byte(&mut self) -> u8 {
            let byte = self.data[self.position];
            self.position += 1;
            byte
        }

        fn c_pixel(&mut self, size: usize) -> Vec<u8> {
            let pixel = self.data[self.position..self.position + size].to_vec();
            self.position += size;
            pixel
        }

        fn run_length(&mut self) -> usize {
            // The length is one more than the sum of its bytes; 255 continues.
            let mut length = 1;
            loop {
                let byte = self.byte();
                length += usize::from(byte);
                if byte != 255 {
                    return length;
                }
            }
        }
    }

    fn decode_zrle(data: &[u8], width: u32, height: u32, c_pixel_size: usize) -> Vec<Vec<u8>> {
        let mut decoder = ZrleDecoder::new(data);
        let mut grid: Vec<Option<Vec<u8>>> = vec![None; (width * height) as usize];
        for tile_y in (0..height).step_by(64) {
            let tile_height = (height - tile_y).min(64);
            for tile_x in (0..width).step_by(64) {
                let tile_width = (width - tile_x).min(64);
                let tile = decode_tile(&mut decoder, tile_width, tile_height, c_pixel_size);
                for row in 0..tile_height {
                    for column in 0..tile_width {
                        let index = ((tile_y + row) * width + tile_x + column) as usize;
                        grid[index] = Some(tile[(row * tile_width + column) as usize].clone());
                    }
                }
            }
        }
        assert_eq!(decoder.position, data.len(), "ZRLE data has trailing bytes");
        grid.into_iter().map(|pixel| pixel.unwrap()).collect()
    }

    fn decode_tile(
        decoder: &mut ZrleDecoder<'_>,
        width: u32,
        height: u32,
        c_pixel_size: usize,
    ) -> Vec<Vec<u8>> {
        let pixel_count = (width * height) as usize;
        let subencoding = decoder.byte();
        let mut pixels: Vec<Vec<u8>> = Vec::with_capacity(pixel_count);
        match subencoding {
            0 => {
                while pixels.len() < pixel_count {
                    pixels.push(decoder.c_pixel(c_pixel_size));
                }
            }
            1 => {
                let color = decoder.c_pixel(c_pixel_size);
                pixels = vec![color; pixel_count];
            }
            2..=16 => {
                let palette: Vec<Vec<u8>> = (0..subencoding)
                    .map(|_| decoder.c_pixel(c_pixel_size))
                    .collect();
                let bits = match subencoding {
                    2 => 1,
                    3..=4 => 2,
                    _ => 4,
                };
                for _ in 0..height {
                    let mut byte = 0u8;
                    let mut remaining = 0u32;
                    for _ in 0..width {
                        if remaining == 0 {
                            byte = decoder.byte();
                            remaining = 8;
                        }
                        remaining -= bits as u32;
                        let index = (byte >> remaining) & ((1 << bits) - 1);
                        pixels.push(palette[index as usize].clone());
                    }
                }
            }
            128 => {
                while pixels.len() < pixel_count {
                    let color = decoder.c_pixel(c_pixel_size);
                    let length = decoder.run_length();
                    pixels.extend(std::iter::repeat_n(color, length));
                }
            }
            130..=255 => {
                let palette_size = usize::from(subencoding) - 128;
                let palette: Vec<Vec<u8>> = (0..palette_size)
                    .map(|_| decoder.c_pixel(c_pixel_size))
                    .collect();
                while pixels.len() < pixel_count {
                    let byte = decoder.byte();
                    if byte < 128 {
                        pixels.push(palette[byte as usize].clone());
                    } else {
                        let color = palette[usize::from(byte) - 128].clone();
                        let length = decoder.run_length();
                        pixels.extend(std::iter::repeat_n(color, length));
                    }
                }
            }
            other => panic!("invalid ZRLE subencoding {other}"),
        }
        assert_eq!(
            pixels.len(),
            pixel_count,
            "tile decoded to a wrong pixel count"
        );
        pixels
    }

    /// Round-trip one tile through the encoder and the spec decoder.
    fn assert_tile_round_trip(
        pixels: &[[u8; 4]],
        width: u32,
        pixel_format: PixelFormat,
    ) -> Vec<u8> {
        let c_pixel_size = pixel_format.zrle_bytes_per_pixel();
        let mut encoded = Vec::new();
        encode_tile(&mut encoded, pixels, width, c_pixel_size);
        let decoded = decode_tile(
            &mut ZrleDecoder::new(&encoded),
            width,
            (pixels.len() / width as usize) as u32,
            c_pixel_size,
        );
        let expected: Vec<Vec<u8>> = pixels
            .iter()
            .map(|pixel| pixel[..c_pixel_size].to_vec())
            .collect();
        assert_eq!(decoded, expected);
        encoded
    }

    #[test]
    fn zrle_round_trips_solid_tiles() {
        let pixels = vec![[9, 8, 7, 255]; 64 * 64];
        let encoded = assert_tile_round_trip(&pixels, 64, PixelFormat::DEFAULT);
        assert_eq!(encoded[0], 1);
        assert_eq!(encoded.len(), 1 + 3);
    }

    #[test]
    fn zrle_round_trips_packed_palette_tiles() {
        // A checkerboard has one-pixel runs: the packed palette wins.
        let pixels: Vec<[u8; 4]> = (0..64 * 64)
            .map(|index| {
                if index % 2 == 0 {
                    [1, 2, 3, 255]
                } else {
                    [4, 5, 6, 255]
                }
            })
            .collect();
        let encoded = assert_tile_round_trip(&pixels, 64, PixelFormat::DEFAULT);
        assert_eq!(encoded[0], 2);

        // Sixteen colors need four-bit index fields.
        let pixels: Vec<[u8; 4]> = (0..64 * 64)
            .map(|index| {
                let color = (index % 16) as u8;
                [color, color, color, 255]
            })
            .collect();
        let encoded = assert_tile_round_trip(&pixels, 64, PixelFormat::DEFAULT);
        assert_eq!(encoded[0], 16);
    }

    #[test]
    fn zrle_round_trips_palette_rle_tiles_with_long_runs() {
        // Two colors with runs of 255, 256, 511, 512, and 514 pixels exercise
        // every run-length encoding shape across row boundaries.
        let colors = [[10, 20, 30, 255], [200, 100, 50, 255]];
        let mut pixels = Vec::new();
        for (index, length) in [255, 256, 511, 512, 514].into_iter().enumerate() {
            pixels.extend(std::iter::repeat_n(colors[index % 2], length));
        }
        assert_eq!(pixels.len(), 512 * 4);
        let encoded = assert_tile_round_trip(&pixels, 512, PixelFormat::DEFAULT);
        assert_eq!(encoded[0], 128 + 2);
    }

    #[test]
    fn zrle_round_trips_plain_rle_tiles() {
        // More colors than palette RLE allows, but with long runs.
        let mut pixels = Vec::new();
        for color in 0..200u8 {
            pixels.extend(std::iter::repeat_n([color, color, color, 255], 20));
        }
        assert_eq!(pixels.len(), 200 * 20);
        let encoded = assert_tile_round_trip(&pixels, 200, PixelFormat::DEFAULT);
        assert_eq!(encoded[0], 128);
    }

    #[test]
    fn zrle_falls_back_to_raw_for_noise() {
        // All pixels distinct: palettes are impossible and RLE wastes space.
        let pixels: Vec<[u8; 4]> = (0..64 * 64)
            .map(|index| {
                let value = index as u32;
                [
                    (value & 0xff) as u8,
                    ((value >> 8) & 0xff) as u8,
                    ((value >> 16) & 0x3f) as u8,
                    255,
                ]
            })
            .collect();
        let encoded = assert_tile_round_trip(&pixels, 64, PixelFormat::DEFAULT);
        assert_eq!(encoded[0], 0);
    }

    #[test]
    fn zrle_round_trips_four_byte_and_big_endian_c_pixels() {
        let four_byte = PixelFormat {
            depth: 32,
            ..PixelFormat::DEFAULT
        };
        let pixels: Vec<[u8; 4]> = (0..128).map(|index| [index as u8 % 8, 2, 3, 4]).collect();
        let encoded = assert_tile_round_trip(&pixels, 16, four_byte);
        assert_eq!(encoded[0], 8);

        let big_endian = PixelFormat {
            big_endian: true,
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..PixelFormat::DEFAULT
        };
        let pixels: Vec<[u8; 4]> = (0..128)
            .map(|index| [index as u8 % 4, index as u8 % 4, index as u8 % 4, 255])
            .collect();
        let encoded = assert_tile_round_trip(&pixels, 16, big_endian);
        assert_eq!(encoded[0], 4);
    }

    #[test]
    fn zrle_encodes_mixed_multi_tile_rectangles() {
        // 130x70 covers solid, checkered, and gradient regions in six tiles.
        let width = 130;
        let height = 70;
        let mut data = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let pixel = if x < 64 && y < 64 {
                    [9, 9, 9, 255]
                } else if (x + y) % 2 == 0 {
                    [1, 2, 3, 255]
                } else {
                    [200, 100, 50, 255]
                };
                data.extend_from_slice(&pixel);
            }
        }
        let frame = Frame::new(width, height, data).unwrap();
        let rectangle = DamageRect {
            x: 0,
            y: 0,
            width,
            height,
        };
        let mut compressor = Compress::new(Compression::default(), true);
        let mut stream = Cursor::new(Vec::new());
        send_zrle_rectangle(
            &mut stream,
            &frame,
            rectangle,
            PixelFormat::DEFAULT,
            &mut compressor,
            &AtomicBool::new(false),
        )
        .unwrap();

        let payload = stream.into_inner();
        let compressed_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
        assert_eq!(compressed_len + 4, payload.len());
        let mut decompressor = flate2::Decompress::new(true);
        let mut uncompressed = vec![0u8; 200 * 1024];
        decompressor
            .decompress(
                &payload[4..],
                &mut uncompressed,
                flate2::FlushDecompress::Sync,
            )
            .unwrap();
        let written = decompressor.total_out() as usize;
        let decoded = decode_zrle(&uncompressed[..written], width, height, 3);
        let mut expected = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let index = (y * width + x) as usize * 4;
                expected.push(frame.data[index..index + 3].to_vec());
            }
        }
        assert_eq!(decoded, expected);
    }
}

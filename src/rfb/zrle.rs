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

use std::io::{self, Read, Write};
use std::sync::atomic::AtomicBool;

use flate2::Compress;

use crate::framebuffer::{DamageRect, Frame};

use super::encoding::{compress_sync, frame_pixel};
use super::pixel::PixelFormat;
use super::{invalid_data, write_all_interruptible};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::{DamageRect, Frame};
    use flate2::Compression;
    use std::io::Read;
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
}

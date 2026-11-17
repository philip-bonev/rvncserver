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

//! Client pixel-format parsing and pixel encoding.

use std::io;

use super::invalid_data;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PixelFormat {
    pub(super) bits_per_pixel: u8,
    pub(super) depth: u8,
    pub(super) big_endian: bool,
    pub(super) red_max: u16,
    pub(super) green_max: u16,
    pub(super) blue_max: u16,
    pub(super) red_shift: u8,
    pub(super) green_shift: u8,
    pub(super) blue_shift: u8,
}

impl PixelFormat {
    pub(super) const DEFAULT: Self = Self {
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

    pub(super) fn bytes_per_pixel(self) -> usize {
        usize::from(self.bits_per_pixel / 8)
    }

    pub(super) fn zrle_bytes_per_pixel(self) -> usize {
        let used_bits = self.used_component_bits();
        // RFB ZRLE CPIXEL: 32-bit pixels are sent in three bytes only when the
        // negotiated depth is 24 or less and every used bit fits into either
        // the three least or the three most significant bytes.
        if self.bits_per_pixel == 32
            && self.depth <= 24
            && (used_bits & 0xff00_0000 == 0 || used_bits & 0x0000_00ff == 0)
        {
            3
        } else {
            self.bytes_per_pixel()
        }
    }

    pub(super) fn used_component_bits(self) -> u32 {
        (u32::from(self.red_max) << self.red_shift)
            | (u32::from(self.green_max) << self.green_shift)
            | (u32::from(self.blue_max) << self.blue_shift)
    }

    pub(super) fn encode(self, bgra: &[u8]) -> [u8; 4] {
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

    pub(super) fn encode_zrle(self, bgra: &[u8]) -> [u8; 4] {
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

    pub(super) fn from_wire(format: &[u8; 16]) -> io::Result<Self> {
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

    pub(super) fn validate(self) -> io::Result<()> {
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
        // metadata mismatch. Formats whose used bits sit in either byte-aligned
        // trio are served with 3-byte ZRLE CPIXELs; `encode_zrle` omits the
        // correct byte whichever end of the pixel is unused.
        Ok(())
    }
}

fn scale_channel(value: u8, maximum: u16) -> u32 {
    (u32::from(value) * u32::from(maximum) + 127) / 255
}

pub(super) fn server_pixel_format() -> [u8; 16] {
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

#[cfg(test)]
mod tests {
    use super::*;

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

        // A depth-24 layout with channels packed into the three most
        // significant bytes (for example RGBA byte order) is valid; ZRLE
        // serves it with 3-byte CPIXELs.
        let mut rgba_order = server_pixel_format();
        rgba_order[10] = 24;
        rgba_order[11] = 16;
        rgba_order[12] = 8;
        assert!(PixelFormat::from_wire(&rgba_order).is_ok());

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
        // CPIXEL stays four bytes when the negotiated depth exceeds 24.
        assert_eq!(rgb888_32.zrle_bytes_per_pixel(), 4);
        assert_eq!(
            rgb888_32.encode_zrle(&[255, 128, 0, 255]),
            rgb888_32.encode(&[255, 128, 0, 255])
        );

        let rgb888_le = PixelFormat {
            depth: 24,
            big_endian: false,
            ..rgb888_be
        };
        assert_eq!(rgb888_le.zrle_bytes_per_pixel(), 3);
        assert_eq!(
            &rgb888_le.encode_zrle(&[255, 128, 0, 255])[..3],
            &[255, 128, 0]
        );

        // Channels in the three most significant bytes: the CPIXEL keeps
        // those and omits the unused low byte.
        let rgb888_rgba = PixelFormat {
            big_endian: false,
            red_shift: 24,
            green_shift: 16,
            blue_shift: 8,
            ..rgb888_le
        };
        assert_eq!(rgb888_rgba.zrle_bytes_per_pixel(), 3);
        assert_eq!(
            &rgb888_rgba.encode_zrle(&[255, 128, 0, 255])[..3],
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
}

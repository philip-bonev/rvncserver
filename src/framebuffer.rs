//! Transport-neutral framebuffer representation.
//!
//! Captured frames are normalized to tightly packed, top-down BGRA pixels.
//! The RFB implementation only sees this type, so it does not depend on
//! PipeWire formats, strides, crops, or buffer orientation.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use lamco_pipewire::{FrameBuffer, PixelFormat, VideoFrame};

/// A normalized frame ready for transmission.
///
/// `data` is always tightly packed, top-down BGRA with exactly
/// `width * height * 4` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Tightly packed BGRA pixel data.
    pub data: Arc<Vec<u8>>,
}

impl Frame {
    /// Create a normalized frame from already tightly packed BGRA data.
    pub fn new(width: u32, height: u32, data: Vec<u8>) -> Result<Self, FrameError> {
        if width == 0 || height == 0 {
            return Err(FrameError::InvalidDimensions);
        }

        let expected = expected_len(width, height)?;
        if data.len() != expected {
            return Err(FrameError::InvalidBufferSize {
                expected,
                actual: data.len(),
            });
        }

        Ok(Self {
            width,
            height,
            data: Arc::new(data),
        })
    }

    /// Normalize a PipeWire frame.
    ///
    /// The initial implementation supports CPU-mapped 32-bit formats only.
    /// It handles padded strides, crops, and bottom-up buffers. Non-identity
    /// transforms are rejected rather than transmitted incorrectly.
    pub fn from_video_frame(frame: &VideoFrame) -> Result<Self, FrameError> {
        let data = match &frame.buffer {
            FrameBuffer::Memory(data) => data,
            FrameBuffer::DmaBuf(_) => return Err(FrameError::UnsupportedBuffer),
        };

        if frame.width == 0 || frame.height == 0 {
            return Err(FrameError::InvalidDimensions);
        }

        if frame.transform() != 0 {
            return Err(FrameError::UnsupportedTransform(frame.transform()));
        }

        if data.is_empty() {
            return Err(FrameError::EmptyBuffer);
        }

        if frame.flags.is_corrupted() || frame.flags.is_incomplete() {
            return Err(FrameError::IncompleteFrame);
        }

        let source_bpp = frame.format.bytes_per_pixel();
        if source_bpp != 4 {
            return Err(FrameError::UnsupportedFormat(frame.format));
        }

        let (crop_x, crop_y, output_width, output_height) = match &frame.meta.crop {
            Some(crop) => {
                if crop.x < 0 || crop.y < 0 || crop.width == 0 || crop.height == 0 {
                    return Err(FrameError::InvalidCrop);
                }

                let x = crop.x as u32;
                let y = crop.y as u32;
                let right = x.checked_add(crop.width).ok_or(FrameError::InvalidCrop)?;
                let bottom = y.checked_add(crop.height).ok_or(FrameError::InvalidCrop)?;

                if right > frame.width || bottom > frame.height {
                    return Err(FrameError::InvalidCrop);
                }

                (x, y, crop.width, crop.height)
            }
            None => (0, 0, frame.width, frame.height),
        };

        let source_width = frame.width as usize;
        let stride = frame.stride as usize;
        let source_height = frame.height as usize;

        let required_row_bytes = source_width
            .checked_mul(source_bpp)
            .ok_or(FrameError::InvalidDimensions)?;
        if stride < required_row_bytes {
            return Err(FrameError::InvalidStride {
                stride,
                minimum: required_row_bytes,
            });
        }

        let required_source = stride
            .checked_mul(source_height)
            .ok_or(FrameError::InvalidDimensions)?;
        if data.len() < required_source {
            return Err(FrameError::InvalidBufferSize {
                expected: required_source,
                actual: data.len(),
            });
        }

        let output_width_usize = output_width as usize;
        let output_height_usize = output_height as usize;
        let output_stride = output_width_usize
            .checked_mul(4)
            .ok_or(FrameError::InvalidDimensions)?;
        let output_len = expected_len(output_width, output_height)?;

        let is_fast_path = frame.meta.crop.is_none()
            && !frame.is_bottom_up()
            && frame.stride as usize == output_stride
            && matches!(frame.format, PixelFormat::BGRA | PixelFormat::BGRx);

        if is_fast_path {
            return Ok(Self {
                width: output_width,
                height: output_height,
                data: Arc::clone(data),
            });
        }

        let mut output = vec![0u8; output_len];
        let crop_x_bytes = (crop_x as usize)
            .checked_mul(4)
            .ok_or(FrameError::InvalidCrop)?;
        let row_bytes = output_stride;

        for row in 0..output_height_usize {
            let source_row = crop_y as usize + row;
            let source_row = if frame.is_bottom_up() {
                source_height
                    .checked_sub(1 + source_row)
                    .ok_or(FrameError::InvalidCrop)?
            } else {
                source_row
            };

            let source_start = source_row
                .checked_mul(stride)
                .and_then(|offset| offset.checked_add(crop_x_bytes))
                .ok_or(FrameError::InvalidDimensions)?;
            let source_end = source_start
                .checked_add(row_bytes)
                .ok_or(FrameError::InvalidDimensions)?;
            let destination_start = row
                .checked_mul(row_bytes)
                .ok_or(FrameError::InvalidDimensions)?;
            let destination_end = destination_start
                .checked_add(row_bytes)
                .ok_or(FrameError::InvalidDimensions)?;

            let source_row = data
                .get(source_start..source_end)
                .ok_or(FrameError::BufferTooSmall)?;
            let destination_row = output
                .get_mut(destination_start..destination_end)
                .ok_or(FrameError::BufferTooSmall)?;

            match frame.format {
                PixelFormat::BGRA | PixelFormat::BGRx => {
                    destination_row.copy_from_slice(source_row);
                }
                PixelFormat::RGBA | PixelFormat::RGBx => {
                    for (source, destination) in source_row
                        .chunks_exact(4)
                        .zip(destination_row.chunks_exact_mut(4))
                    {
                        destination[0] = source[2];
                        destination[1] = source[1];
                        destination[2] = source[0];
                        destination[3] = 255;
                    }
                }
                other => return Err(FrameError::UnsupportedFormat(other)),
            }
        }

        Ok(Self {
            width: output_width,
            height: output_height,
            data: Arc::new(output),
        })
    }

    /// Write this frame as a binary PPM (P6) file.
    pub fn write_ppm(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let expected = expected_len(self.width, self.height)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if self.data.len() != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame data does not match its dimensions",
            ));
        }

        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        write!(writer, "P6\n{} {}\n255\n", self.width, self.height)?;

        let row_bytes = self.width as usize * 3;
        let mut rgb = vec![0u8; row_bytes];

        for row in self.data.chunks_exact(self.width as usize * 4) {
            for (source, destination) in row.chunks_exact(4).zip(rgb.chunks_exact_mut(3)) {
                destination[0] = source[2];
                destination[1] = source[1];
                destination[2] = source[0];
            }
            writer.write_all(&rgb)?;
        }

        writer.flush()
    }
}

/// Errors produced while normalizing a captured frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The frame uses DMA-BUF memory, which this build cannot map.
    UnsupportedBuffer,
    /// The frame has no CPU pixel data.
    EmptyBuffer,
    /// The producer marked the frame as corrupted or incomplete.
    IncompleteFrame,
    /// Width or height is zero or cannot be represented.
    InvalidDimensions,
    /// The source stride is too small for its width.
    InvalidStride { stride: usize, minimum: usize },
    /// The source or destination buffer is smaller than expected.
    InvalidBufferSize { expected: usize, actual: usize },
    /// The source buffer is shorter than its advertised stride and height.
    BufferTooSmall,
    /// The compositor supplied a transform that is not implemented.
    UnsupportedTransform(u32),
    /// The pixel format is not supported by the initial implementation.
    UnsupportedFormat(PixelFormat),
    /// The crop rectangle is invalid or outside the frame.
    InvalidCrop,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBuffer => {
                write!(f, "DMA-BUF frames are not supported by this build")
            }
            Self::EmptyBuffer => write!(f, "captured frame contains no pixel data"),
            Self::IncompleteFrame => {
                write!(f, "captured frame is marked corrupted or incomplete")
            }
            Self::InvalidDimensions => write!(f, "captured frame has invalid dimensions"),
            Self::InvalidStride { stride, minimum } => {
                write!(
                    f,
                    "captured frame stride {stride} is smaller than {minimum}"
                )
            }
            Self::InvalidBufferSize { expected, actual } => {
                write!(
                    f,
                    "captured frame buffer has {actual} bytes; expected {expected}"
                )
            }
            Self::BufferTooSmall => write!(f, "captured frame buffer is truncated"),
            Self::UnsupportedTransform(transform) => {
                write!(f, "captured frame transform {transform} is not supported")
            }
            Self::UnsupportedFormat(format) => {
                write!(f, "captured pixel format {format:?} is not supported")
            }
            Self::InvalidCrop => write!(f, "captured frame has an invalid crop rectangle"),
        }
    }
}

impl Error for FrameError {}

fn expected_len(width: u32, height: u32) -> Result<usize, FrameError> {
    (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(FrameError::InvalidDimensions)
}

/// Shared latest-frame store used to decouple capture from network clients.
///
/// The capture loop publishes frames only while at least one client is
/// connected. Clients wait on a condition variable instead of polling.
#[derive(Debug, Default)]
pub struct FrameStore {
    inner: Mutex<FrameStoreInner>,
    ready: Condvar,
}

#[derive(Debug, Default)]
struct FrameStoreInner {
    latest: Option<(u64, Arc<Frame>)>,
    clients: usize,
}

impl FrameStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a frame and return its sequence number.
    pub fn publish(&self, frame: Arc<Frame>) -> u64 {
        let mut inner = self.lock();
        let sequence = inner
            .latest
            .as_ref()
            .map_or(1, |(sequence, _)| sequence + 1);
        inner.latest = Some((sequence, frame));
        self.ready.notify_all();
        sequence
    }

    /// Return the latest frame and its sequence number.
    pub fn latest(&self) -> Option<(u64, Arc<Frame>)> {
        self.lock()
            .latest
            .as_ref()
            .map(|(sequence, frame)| (*sequence, Arc::clone(frame)))
    }

    /// Wait for a frame newer than `last_sequence`.
    ///
    /// Returns `None` if no newer frame arrives within `timeout`.
    pub fn wait_next(&self, last_sequence: u64, timeout: Duration) -> Option<(u64, Arc<Frame>)> {
        let deadline = Instant::now() + timeout;
        let mut inner = self.lock();

        loop {
            if let Some((sequence, frame)) = &inner.latest {
                if *sequence != last_sequence {
                    return Some((*sequence, Arc::clone(frame)));
                }
            }

            let now = Instant::now();
            if now >= deadline {
                return None;
            }

            let remaining = deadline.saturating_duration_since(now);
            let (guard, _) = self
                .ready
                .wait_timeout(inner, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner = guard;
        }
    }

    /// Record that a client connected.
    pub fn client_connected(&self) {
        self.lock().clients += 1;
    }

    /// Record that a client disconnected.
    pub fn client_disconnected(&self) {
        let mut inner = self.lock();
        inner.clients = inner.clients.saturating_sub(1);
    }

    /// Return true while at least one client is connected.
    pub fn has_clients(&self) -> bool {
        self.lock().clients > 0
    }

    fn lock(&self) -> MutexGuard<'_, FrameStoreInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn video_frame(
        width: u32,
        height: u32,
        stride: u32,
        format: PixelFormat,
        data: Vec<u8>,
    ) -> VideoFrame {
        VideoFrame::with_data(1, width, height, stride, format, 0, data)
    }

    #[test]
    fn converts_tight_bgra_without_copying() {
        let data = vec![1, 2, 3, 255, 4, 5, 6, 255, 7, 8, 9, 255, 10, 11, 12, 255];
        let source = video_frame(2, 2, 8, PixelFormat::BGRA, data.clone());
        let frame = Frame::from_video_frame(&source).unwrap();

        assert_eq!(frame.width, 2);
        assert_eq!(frame.height, 2);
        assert_eq!(frame.data.as_slice(), data.as_slice());
    }

    #[test]
    fn converts_rgba_to_bgra() {
        let data = vec![
            10, 20, 30, 255, 40, 50, 60, 128, 70, 80, 90, 255, 100, 110, 120, 0,
        ];
        let source = video_frame(2, 2, 8, PixelFormat::RGBA, data);
        let frame = Frame::from_video_frame(&source).unwrap();

        assert_eq!(
            frame.data.as_slice(),
            &[
                30, 20, 10, 255, 60, 50, 40, 255, 90, 80, 70, 255, 120, 110, 100, 255,
            ]
        );
    }

    #[test]
    fn removes_row_padding() {
        let data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 99, 99, 99, 99, // first row plus padding
            9, 10, 11, 12, 13, 14, 15, 16, 99, 99, 99, 99, // second row plus padding
        ];
        let source = video_frame(2, 2, 12, PixelFormat::BGRA, data);
        let frame = Frame::from_video_frame(&source).unwrap();

        assert_eq!(
            frame.data.as_slice(),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn flips_bottom_up_frames() {
        let mut source = video_frame(
            1,
            2,
            4,
            PixelFormat::BGRA,
            vec![10, 11, 12, 13, 20, 21, 22, 23],
        );
        source.meta.chunk_stride = -4;

        let frame = Frame::from_video_frame(&source).unwrap();
        assert_eq!(frame.data.as_slice(), &[20, 21, 22, 23, 10, 11, 12, 13]);
    }

    #[test]
    fn applies_crop() {
        let data = vec![
            1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, // row 0
            4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, // row 1
        ];
        let mut source = video_frame(3, 2, 12, PixelFormat::BGRA, data);
        source.meta.crop = Some(lamco_pipewire::CropRegion {
            x: 1,
            y: 0,
            width: 2,
            height: 2,
        });

        let frame = Frame::from_video_frame(&source).unwrap();
        assert_eq!(frame.width, 2);
        assert_eq!(frame.height, 2);
        assert_eq!(
            frame.data.as_slice(),
            &[2, 2, 2, 2, 3, 3, 3, 3, 5, 5, 5, 5, 6, 6, 6, 6]
        );
    }

    #[test]
    fn rejects_invalid_inputs() {
        let source = video_frame(0, 1, 0, PixelFormat::BGRA, vec![]);
        assert_eq!(
            Frame::from_video_frame(&source),
            Err(FrameError::InvalidDimensions)
        );

        let source = video_frame(2, 2, 4, PixelFormat::BGRA, vec![0; 16]);
        assert_eq!(
            Frame::from_video_frame(&source),
            Err(FrameError::InvalidStride {
                stride: 4,
                minimum: 8
            })
        );

        let source = video_frame(2, 2, 8, PixelFormat::RGB, vec![0; 12]);
        assert_eq!(
            Frame::from_video_frame(&source),
            Err(FrameError::UnsupportedFormat(PixelFormat::RGB))
        );

        let mut source = video_frame(2, 2, 8, PixelFormat::BGRA, vec![0; 16]);
        source.flags.set_corrupted();
        assert_eq!(
            Frame::from_video_frame(&source),
            Err(FrameError::IncompleteFrame)
        );
    }

    #[test]
    fn writes_ppm() {
        let frame = Frame::new(2, 1, vec![1, 2, 3, 255, 4, 5, 6, 255]).unwrap();
        let path = std::env::temp_dir().join(format!(
            "rvncserver-frame-{}-{}.ppm",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        frame.write_ppm(&path).unwrap();
        let contents = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(contents, b"P6\n2 1\n255\n\x03\x02\x01\x06\x05\x04");
    }

    #[test]
    fn frame_store_tracks_latest_and_clients() {
        let store = FrameStore::new();
        assert!(!store.has_clients());
        assert_eq!(store.latest(), None);

        store.client_connected();
        assert!(store.has_clients());

        let frame = Arc::new(Frame::new(1, 1, vec![1, 2, 3, 255]).unwrap());
        assert_eq!(store.publish(Arc::clone(&frame)), 1);
        assert_eq!(store.publish(frame), 2);
        assert_eq!(store.latest().unwrap().0, 2);

        store.client_disconnected();
        assert!(!store.has_clients());
        store.client_disconnected();
        assert!(!store.has_clients());
    }
}

//! Cursor data shared between capture and the RFB protocol.

use std::sync::{Arc, Mutex, MutexGuard};

use lamco_pipewire::meta::CursorBitmap;
use lamco_pipewire::{CursorMeta, PixelFormat, VideoFrame};

const MAX_CURSOR_PIXELS: usize = 1024 * 1024;

/// A normalized cursor image in tightly packed BGRA format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    /// Cursor width in pixels.
    pub width: u16,
    /// Cursor height in pixels.
    pub height: u16,
    /// Hotspot inside the cursor image.
    pub hotspot: (u16, u16),
    /// Tightly packed BGRA pixels.
    pub pixels: Arc<Vec<u8>>,
}

impl CursorShape {
    /// Convert supported PipeWire cursor bitmap formats to packed BGRA.
    pub fn from_pipewire(bitmap: &CursorBitmap, hotspot: (i32, i32)) -> Result<Self, &'static str> {
        let width = u16::try_from(bitmap.width).map_err(|_| "cursor width exceeds RFB limits")?;
        let height =
            u16::try_from(bitmap.height).map_err(|_| "cursor height exceeds RFB limits")?;
        if width == 0 || height == 0 || (width as usize) * (height as usize) > MAX_CURSOR_PIXELS {
            return Err("cursor dimensions are invalid or too large");
        }
        let hotspot_x = u16::try_from(hotspot.0).map_err(|_| "cursor hotspot is invalid")?;
        let hotspot_y = u16::try_from(hotspot.1).map_err(|_| "cursor hotspot is invalid")?;
        if hotspot_x >= width || hotspot_y >= height {
            return Err("cursor hotspot is outside the cursor image");
        }

        let format = bitmap.format;
        let bgra = PixelFormat::BGRA.to_spa().as_raw() as u32;
        let bgrx = PixelFormat::BGRx.to_spa().as_raw() as u32;
        let rgba = PixelFormat::RGBA.to_spa().as_raw() as u32;
        let rgbx = PixelFormat::RGBx.to_spa().as_raw() as u32;
        if ![bgra, bgrx, rgba, rgbx].contains(&format) {
            return Err("PipeWire cursor pixel format is unsupported");
        }

        let stride = bitmap.stride.unsigned_abs() as usize;
        let source_row_size = (width as usize)
            .checked_mul(4)
            .ok_or("cursor dimensions overflow")?;
        let source_size = stride
            .checked_mul(height as usize)
            .ok_or("cursor dimensions overflow")?;
        if stride < source_row_size || source_size > bitmap.pixels.len() {
            return Err("PipeWire cursor bitmap buffer is truncated");
        }
        let output_size = source_row_size
            .checked_mul(height as usize)
            .ok_or("cursor dimensions overflow")?;
        let mut pixels = vec![0; output_size];

        for y in 0..height as usize {
            let source_y = if bitmap.stride < 0 {
                height as usize - 1 - y
            } else {
                y
            };
            let source_start = source_y * stride;
            let output_start = y * source_row_size;
            for x in 0..width as usize {
                let source = source_start + x * 4;
                let output = output_start + x * 4;
                match format {
                    value if value == bgra => {
                        pixels[output..output + 4]
                            .copy_from_slice(&bitmap.pixels[source..source + 4]);
                    }
                    value if value == bgrx => {
                        pixels[output..output + 3]
                            .copy_from_slice(&bitmap.pixels[source..source + 3]);
                        pixels[output + 3] = 255;
                    }
                    value if value == rgba || value == rgbx => {
                        pixels[output] = bitmap.pixels[source + 2];
                        pixels[output + 1] = bitmap.pixels[source + 1];
                        pixels[output + 2] = bitmap.pixels[source];
                        pixels[output + 3] = if value == rgba {
                            bitmap.pixels[source + 3]
                        } else {
                            255
                        };
                    }
                    _ => return Err("PipeWire cursor pixel format is unsupported"),
                }
            }
        }

        Ok(Self {
            width,
            height,
            hotspot: (hotspot_x, hotspot_y),
            pixels: Arc::new(pixels),
        })
    }
}

/// One cursor metadata update from PipeWire.
#[derive(Debug, Clone)]
pub struct CursorUpdate {
    /// Pointer position in the captured stream.
    pub position: (i32, i32),
    /// New shape, if this metadata carried a bitmap.
    pub shape: Option<CursorShape>,
}

impl CursorUpdate {
    /// Normalize the cursor data in PipeWire metadata.
    pub fn from_pipewire(metadata: &CursorMeta) -> Self {
        let shape = metadata.bitmap.as_ref().and_then(|bitmap| {
            match CursorShape::from_pipewire(bitmap, metadata.hotspot) {
                Ok(shape) => Some(shape),
                Err(error) => {
                    crate::timestamped_log!("capture: ignoring unsupported cursor shape: {error}");
                    None
                }
            }
        });
        Self {
            position: metadata.position,
            shape,
        }
    }

    /// Extract cursor metadata from a captured frame and map it into cropped-frame coordinates.
    pub fn from_video_frame(frame: &VideoFrame) -> Option<Self> {
        let metadata = frame.meta.cursor.as_ref()?;
        let mut update = Self::from_pipewire(metadata);
        if let Some(crop) = frame.meta.crop.as_ref() {
            update.position.0 = update.position.0.saturating_sub(crop.x);
            update.position.1 = update.position.1.saturating_sub(crop.y);
        }
        Some(update)
    }
}

/// Snapshot consumed by an RFB client when sending cursor pseudo-encodings.
#[derive(Debug, Clone, Default)]
pub struct CursorSnapshot {
    /// Latest position update, if the compositor has supplied one.
    pub position: Option<(i32, i32)>,
    /// Monotonic position-change sequence.
    pub position_sequence: u64,
    /// Latest cursor shape, if the compositor has supplied one.
    pub shape: Option<Arc<CursorShape>>,
    /// Monotonic shape-change sequence.
    pub shape_sequence: u64,
}

/// Thread-safe current cursor state.
#[derive(Debug, Default)]
pub struct CursorStore {
    inner: Mutex<CursorSnapshot>,
}

impl CursorStore {
    /// Create an empty cursor store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish compositor cursor metadata, preserving shape on position-only updates.
    pub fn publish(&self, update: CursorUpdate) {
        let mut state = self.lock();
        if state.position != Some(update.position) {
            state.position = Some(update.position);
            state.position_sequence = state.position_sequence.wrapping_add(1);
        }
        if let Some(shape) = update.shape {
            if state.shape.as_deref() != Some(&shape) {
                state.shape = Some(Arc::new(shape));
                state.shape_sequence = state.shape_sequence.wrapping_add(1);
            }
        }
    }

    /// Clone the latest cursor state without holding the lock during network I/O.
    pub fn snapshot(&self) -> CursorSnapshot {
        self.lock().clone()
    }

    fn lock(&self) -> MutexGuard<'_, CursorSnapshot> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_store_preserves_shape_for_position_only_updates() {
        let store = CursorStore::new();
        let shape = CursorShape {
            width: 1,
            height: 1,
            hotspot: (0, 0),
            pixels: Arc::new(vec![1, 2, 3, 255]),
        };
        store.publish(CursorUpdate {
            position: (10, 20),
            shape: Some(shape.clone()),
        });
        store.publish(CursorUpdate {
            position: (11, 20),
            shape: None,
        });

        let snapshot = store.snapshot();
        assert_eq!(snapshot.position, Some((11, 20)));
        assert_eq!(snapshot.position_sequence, 2);
        assert_eq!(snapshot.shape_sequence, 1);
        assert_eq!(snapshot.shape.as_deref(), Some(&shape));
    }

    #[test]
    fn pipewire_bgra_cursor_is_normalized_with_its_hotspot() {
        let bitmap = CursorBitmap {
            format: PixelFormat::BGRA.to_spa().as_raw() as u32,
            width: 1,
            height: 1,
            stride: 4,
            pixels: vec![10, 20, 30, 255],
        };
        let shape = CursorShape::from_pipewire(&bitmap, (0, 0)).unwrap();
        assert_eq!((shape.width, shape.height), (1, 1));
        assert_eq!(&*shape.pixels, &[10, 20, 30, 255]);
    }
}

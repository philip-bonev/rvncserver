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

//! Multi-monitor layout and frame composition.
//!
//! The monitors of a desktop capture are arranged at their logical positions
//! and blitted into one composite framebuffer, which the RFB layer serves as
//! the single desktop. Gaps between monitors stay black.

use std::sync::Arc;

use crate::framebuffer::{DamageRect, Frame, FrameDamage, FrameError};

/// A monitor as reported by the portal: node id, logical position, and size.
pub type MonitorSpec = (u32, (i32, i32), (u32, u32));

/// Where one captured monitor sits in the composite framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorPlacement {
    /// PipeWire node id of the monitor's stream.
    pub node_id: u32,
    /// Top-left corner of the monitor in composite coordinates.
    pub offset: (u32, u32),
    /// Monitor size in pixels.
    pub size: (u32, u32),
}

/// The arrangement of the captured monitors inside one framebuffer.
#[derive(Debug, Clone)]
pub struct MonitorLayout {
    monitors: Vec<MonitorPlacement>,
    size: (u32, u32),
}

impl MonitorLayout {
    /// Place monitors at their logical desktop positions, normalized so the
    /// composite starts at (0, 0). Relative placement, including gaps and
    /// negative desktop coordinates, is preserved.
    pub fn from_monitors(monitors: &[MonitorSpec]) -> Result<Self, String> {
        if monitors.is_empty() {
            return Err("no monitor streams to compose".to_string());
        }
        let origin_x = monitors.iter().map(|(_, (x, _), _)| *x).min().unwrap_or(0);
        let origin_y = monitors.iter().map(|(_, (_, y), _)| *y).min().unwrap_or(0);

        let mut placements = Vec::with_capacity(monitors.len());
        let mut right = 0u32;
        let mut bottom = 0u32;
        for (node_id, (x, y), (width, height)) in monitors {
            if *width == 0 || *height == 0 {
                return Err(format!("monitor {node_id} has an empty size"));
            }
            let offset_x = u32::try_from(i64::from(*x) - i64::from(origin_x))
                .map_err(|_| format!("monitor {node_id} has a negative offset"))?;
            let offset_y = u32::try_from(i64::from(*y) - i64::from(origin_y))
                .map_err(|_| format!("monitor {node_id} has a negative offset"))?;
            right = right.max(offset_x.saturating_add(*width));
            bottom = bottom.max(offset_y.saturating_add(*height));
            placements.push(MonitorPlacement {
                node_id: *node_id,
                offset: (offset_x, offset_y),
                size: (*width, *height),
            });
        }
        if right == 0
            || bottom == 0
            || u16::try_from(right).is_err()
            || u16::try_from(bottom).is_err()
        {
            return Err(format!(
                "composite size {right}x{bottom} exceeds RFB limits"
            ));
        }
        Ok(Self {
            monitors: placements,
            size: (right, bottom),
        })
    }

    /// Size of the composite framebuffer.
    pub fn size(&self) -> (u32, u32) {
        self.size
    }

    /// The monitors in composite order; the index is the stream id.
    pub fn monitors(&self) -> &[MonitorPlacement] {
        &self.monitors
    }

    /// Route a composite pointer coordinate to a monitor and a monitor-local
    /// coordinate. Points in gaps between monitors go to the nearest monitor,
    /// clamped to its edges.
    pub fn route_pointer(&self, x: i32, y: i32) -> (usize, (i32, i32)) {
        let mut best = (0usize, i64::MAX);
        for (index, monitor) in self.monitors.iter().enumerate() {
            let local_x = (i64::from(x) - i64::from(monitor.offset.0))
                .clamp(0, i64::from(monitor.size.0) - 1);
            let local_y = (i64::from(y) - i64::from(monitor.offset.1))
                .clamp(0, i64::from(monitor.size.1) - 1);
            let distance_x = i64::from(x) - (i64::from(monitor.offset.0) + local_x);
            let distance_y = i64::from(y) - (i64::from(monitor.offset.1) + local_y);
            let distance = distance_x * distance_x + distance_y * distance_y;
            if distance < best.1 {
                best = (index, distance);
            }
        }
        let monitor = self.monitors[best.0];
        let local_x =
            (i64::from(x) - i64::from(monitor.offset.0)).clamp(0, i64::from(monitor.size.0) - 1);
        let local_y =
            (i64::from(y) - i64::from(monitor.offset.1)).clamp(0, i64::from(monitor.size.1) - 1);
        (best.0, (local_x as i32, local_y as i32))
    }

    /// Translate a monitor-local point into composite coordinates.
    pub fn translate_point(&self, monitor: usize, point: (i32, i32)) -> (i32, i32) {
        let placement = &self.monitors[monitor];
        (
            point.0 + placement.offset.0 as i32,
            point.1 + placement.offset.1 as i32,
        )
    }

    /// Translate monitor-local damage into composite coordinates.
    pub fn translate_damage(&self, monitor: usize, damage: &FrameDamage) -> FrameDamage {
        let placement = &self.monitors[monitor];
        match damage {
            FrameDamage::Full => FrameDamage::Full,
            FrameDamage::Regions(regions) => FrameDamage::Regions(
                regions
                    .iter()
                    .map(|region| DamageRect {
                        x: region.x + placement.offset.0,
                        y: region.y + placement.offset.1,
                        width: region.width,
                        height: region.height,
                    })
                    .collect(),
            ),
        }
    }
}

/// Assembles per-monitor frames into one composite framebuffer.
pub struct Composite {
    layout: MonitorLayout,
    buffer: Vec<u8>,
    /// Last source sequence seen per monitor, for dropped-frame detection.
    sequences: Vec<Option<u64>>,
    /// Whether each monitor has painted its area at least once.
    painted: Vec<bool>,
}

impl Composite {
    /// Create a black composite of the layout's size.
    pub fn new(layout: MonitorLayout) -> Result<Self, String> {
        let (width, height) = layout.size();
        let length = (width as usize)
            .checked_mul(height as usize)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or_else(|| "composite size overflows".to_string())?;
        let monitors = layout.monitors().len();
        Ok(Self {
            layout,
            buffer: vec![0; length],
            sequences: vec![None; monitors],
            painted: vec![false; monitors],
        })
    }

    pub fn layout(&self) -> &MonitorLayout {
        &self.layout
    }

    /// Blit a normalized monitor frame into the composite and return the
    /// resulting composite damage. A gap in the monitor's source sequence
    /// forces a full refresh.
    pub fn blit(&mut self, monitor: usize, frame: &Frame) -> Result<FrameDamage, FrameError> {
        let placement = &self.layout.monitors()[monitor];
        if (frame.width, frame.height) != placement.size {
            return Err(FrameError::InvalidDimensions);
        }
        let mut damage = self.layout.translate_damage(monitor, &frame.damage);
        if !self.painted[monitor] {
            // The monitor's area was black before its first blit, so the
            // whole area needs painting regardless of the frame's damage.
            self.painted[monitor] = true;
            damage = FrameDamage::Full;
        }
        if let Some(sequence) = frame.source_sequence {
            if self.sequences[monitor].is_some_and(|previous| sequence != previous.wrapping_add(1))
            {
                damage = FrameDamage::Full;
            }
            self.sequences[monitor] = Some(sequence);
        } else {
            self.sequences[monitor] = None;
        }

        let (offset_x, offset_y) = placement.offset;
        let (width, height) = placement.size;
        let composite_width = self.layout.size().0 as usize;
        for row in 0..height as usize {
            let source_start = row * width as usize * 4;
            let target_start =
                ((offset_y as usize + row) * composite_width + offset_x as usize) * 4;
            let length = width as usize * 4;
            self.buffer[target_start..target_start + length]
                .copy_from_slice(&frame.data[source_start..source_start + length]);
        }
        Ok(damage)
    }

    /// A publishable copy of the composite. The buffer is copied because
    /// clients may still be encoding the previous snapshot.
    pub fn snapshot(&self) -> Arc<Vec<u8>> {
        Arc::new(self.buffer.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitors() -> Vec<MonitorSpec> {
        // A 2x1 monitor at the origin and a 2x2 monitor down and to its
        // right, with a one-pixel gap between them.
        vec![(10, (0, 0), (2, 1)), (20, (3, 1), (2, 2))]
    }

    #[test]
    fn layout_normalizes_logical_positions() {
        let layout = MonitorLayout::from_monitors(&monitors()).unwrap();
        assert_eq!(layout.size(), (5, 3));
        assert_eq!(
            layout.monitors()[0],
            MonitorPlacement {
                node_id: 10,
                offset: (0, 0),
                size: (2, 1),
            }
        );
        assert_eq!(
            layout.monitors()[1],
            MonitorPlacement {
                node_id: 20,
                offset: (3, 1),
                size: (2, 2),
            }
        );

        // Negative desktop coordinates normalize to the origin.
        let shifted =
            MonitorLayout::from_monitors(&[(10, (-100, -50), (2, 1)), (20, (-97, -49), (2, 2))])
                .unwrap();
        assert_eq!(shifted.monitors()[0].offset, (0, 0));
        assert_eq!(shifted.monitors()[1].offset, (3, 1));
        assert!(MonitorLayout::from_monitors(&[]).is_err());
        assert!(MonitorLayout::from_monitors(&[(10, (0, 0), (0, 1))]).is_err());
    }

    #[test]
    fn pointer_routes_to_the_owning_monitor() {
        let layout = MonitorLayout::from_monitors(&monitors()).unwrap();
        assert_eq!(layout.route_pointer(1, 0), (0, (1, 0)));
        assert_eq!(layout.route_pointer(4, 2), (1, (1, 1)));
        // The gap goes to the nearest monitor, clamped to its edge.
        let (monitor, (x, y)) = layout.route_pointer(2, 2);
        assert_eq!(monitor, 1);
        assert_eq!((x, y), (0, 1));
        let (monitor, (x, y)) = layout.route_pointer(-10, -10);
        assert_eq!(monitor, 0);
        assert_eq!((x, y), (0, 0));
    }

    #[test]
    fn composite_blits_monitors_at_their_offsets() {
        let mut composite =
            Composite::new(MonitorLayout::from_monitors(&monitors()).unwrap()).unwrap();
        let first = Frame::new(2, 1, vec![1, 1, 1, 255, 2, 2, 2, 255]).unwrap();
        let damage = composite.blit(0, &first).unwrap();
        assert_eq!(
            damage,
            FrameDamage::Full,
            "the first blit must refresh the composite"
        );

        // The first blit of a monitor paints its whole area.
        let warmup = Frame::new(2, 2, vec![3; 16]).unwrap();
        composite.blit(1, &warmup).unwrap();

        let mut second = Frame::new(2, 2, vec![3; 16]).unwrap();
        second.damage = FrameDamage::Regions(vec![DamageRect {
            x: 1,
            y: 0,
            width: 1,
            height: 1,
        }]);
        let damage = composite.blit(1, &second).unwrap();
        assert_eq!(
            damage,
            FrameDamage::Regions(vec![DamageRect {
                x: 4,
                y: 1,
                width: 1,
                height: 1,
            }])
        );

        let snapshot = composite.snapshot();
        assert_eq!(snapshot.len(), 5 * 3 * 4);
        // First monitor at (0,0) and (1,0).
        assert_eq!(&snapshot[0..4], &[1, 1, 1, 255]);
        assert_eq!(&snapshot[4..8], &[2, 2, 2, 255]);
        // The gap between monitors stays black.
        assert_eq!(&snapshot[8..12], &[0, 0, 0, 0]);
        // Second monitor at offset (3, 1).
        assert_eq!(&snapshot[(5 + 3) * 4..(5 + 3) * 4 + 4], &[3, 3, 3, 3]);

        // A frame of the wrong size cannot be blitted.
        let wrong = Frame::new(1, 1, vec![0; 4]).unwrap();
        assert!(composite.blit(0, &wrong).is_err());
    }

    #[test]
    fn blit_forces_full_damage_after_a_source_sequence_gap() {
        let mut composite =
            Composite::new(MonitorLayout::from_monitors(&monitors()).unwrap()).unwrap();
        let mut first = Frame::new(2, 1, vec![1; 8]).unwrap();
        first.damage = FrameDamage::Regions(Vec::new());
        first.source_sequence = Some(1);
        composite.blit(0, &first).unwrap();

        let mut second = Frame::new(2, 1, vec![2; 8]).unwrap();
        second.damage = FrameDamage::Regions(vec![DamageRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        }]);
        second.source_sequence = Some(5);
        assert_eq!(composite.blit(0, &second).unwrap(), FrameDamage::Full);
    }

    #[test]
    fn cursor_positions_translate_across_monitors() {
        let layout = MonitorLayout::from_monitors(&monitors()).unwrap();
        assert_eq!(layout.translate_point(1, (0, 0)), (3, 1));
        assert_eq!(layout.translate_point(0, (1, 0)), (1, 0));
    }
}

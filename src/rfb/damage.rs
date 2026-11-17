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

//! Damage-region accumulation and rectangle math for framebuffer updates.

use crate::framebuffer::{DamageRect, FrameDamage};

/// Bound on the rectangles accumulated and sent in one framebuffer update.
pub(super) const MAX_UPDATE_RECTS: usize = 128;

pub(super) fn accumulate_damage(
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

pub(super) fn damage_within(pending: &[DamageRect], requested: DamageRect) -> Vec<DamageRect> {
    let mut updates: Vec<_> = pending
        .iter()
        .filter_map(|rect| intersection(*rect, requested))
        .collect();
    merge_rectangles(&mut updates);
    updates
}

pub(super) fn bounded_updates(
    mut updates: Vec<DamageRect>,
    requested: DamageRect,
) -> Vec<DamageRect> {
    if updates.len() > MAX_UPDATE_RECTS {
        updates.clear();
        updates.push(requested);
    }
    updates
}

pub(super) fn subtract_damage(pending: &mut Vec<DamageRect>, served: DamageRect) {
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

#[cfg(test)]
mod tests {
    use super::*;

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

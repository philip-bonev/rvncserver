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

//! A lightweight VNC server for Wayland desktops.
//!
//! The crate is split into independent layers:
//!
//! - [`cli`] parses and validates command-line arguments.
//! - [`capture`] owns the XDG Desktop Portal and PipeWire capture session.
//! - [`framebuffer`] normalizes captured frames into a transport-neutral form.
//! - [`rfb`] implements the RFB protocol without depending on Wayland or
//!   PipeWire.
//! - [`server`] wires capture and RFB together.

pub mod capture;
pub mod cli;
pub mod clipboard;
pub mod cursor;
pub mod error;
pub mod framebuffer;
pub mod input;
pub mod logging;
pub mod rfb;
pub mod server;

/// Print a diagnostic message with a UTC timestamp, without logging secrets
/// or requiring an external logging dependency.
#[macro_export]
macro_rules! timestamped_log {
    ($($argument:tt)*) => {{
        $crate::logging::log(format_args!("[{}] {}", $crate::logging::timestamp(), format_args!($($argument)*)));
    }};
}

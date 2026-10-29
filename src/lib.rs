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

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
pub mod error;
pub mod framebuffer;
pub mod rfb;
pub mod server;

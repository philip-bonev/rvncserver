//! Application-level error type.

use std::fmt;
use std::io;

use lamco_pipewire::PipeWireError;
use lamco_portal::PortalError;

use crate::cli::CliError;
use crate::framebuffer::FrameError;

/// Errors that can terminate the application.
#[derive(Debug)]
pub enum AppError {
    /// Invalid command-line arguments.
    Cli(CliError),
    /// XDG Desktop Portal failure.
    Portal(PortalError),
    /// PipeWire failure.
    PipeWire(PipeWireError),
    /// Frame conversion failure.
    Frame(FrameError),
    /// Local I/O failure.
    Io(io::Error),
    /// Capture session failure with additional context.
    Capture(String),
    /// Network or RFB failure with additional context.
    Network(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli(error) => write!(f, "{error}"),
            Self::Portal(error) => write!(f, "portal error: {error}"),
            Self::PipeWire(error) => write!(f, "PipeWire error: {error}"),
            Self::Frame(error) => write!(f, "frame error: {error}"),
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Capture(message) => write!(f, "capture error: {message}"),
            Self::Network(message) => write!(f, "network error: {message}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cli(error) => Some(error),
            Self::Portal(error) => Some(error),
            Self::PipeWire(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Capture(_) | Self::Network(_) => None,
        }
    }
}

impl From<CliError> for AppError {
    fn from(error: CliError) -> Self {
        Self::Cli(error)
    }
}

impl From<PortalError> for AppError {
    fn from(error: PortalError) -> Self {
        Self::Portal(error)
    }
}

impl From<PipeWireError> for AppError {
    fn from(error: PipeWireError) -> Self {
        Self::PipeWire(error)
    }
}

impl From<FrameError> for AppError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

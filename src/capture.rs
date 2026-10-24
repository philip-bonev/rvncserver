//! XDG Desktop Portal and PipeWire capture session.
//!
//! This module owns the portal permission session and the dedicated PipeWire
//! thread. Frames are handed to the rest of the application as raw
//! [`VideoFrame`] values; normalization happens in [`crate::framebuffer`].

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use lamco_pipewire::{
    PipeWireThreadCommand, PipeWireThreadManager, PwStreamState, StreamConfig, VideoFrame,
};
use lamco_portal::{PortalConfig, PortalManager, PortalSessionHandle};
use tokio::sync::Notify;

use crate::error::AppError;
use crate::framebuffer::Frame;

/// Capture configuration.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Requested frame rate.
    pub framerate: u32,
    /// Number of PipeWire buffers requested.
    pub buffer_count: u32,
    /// Whether to request DMA-BUF buffers. The initial implementation only
    /// consumes CPU-mapped memory, so this defaults to `false`.
    pub use_dmabuf: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            framerate: 30,
            buffer_count: 3,
            use_dmabuf: false,
        }
    }
}

/// An active portal and PipeWire capture session.
///
/// The portal session is kept alive for as long as this value exists. Dropping
/// the value closes the PipeWire stream and then releases the portal session.
pub struct CaptureSession {
    // Keep PipeWire first so its Drop runs before the portal session is
    // released.
    pipewire: PipeWireThreadManager,
    _session: PortalSessionHandle,
    _manager: PortalManager,
    stream_id: u32,
    stream_size: (u32, u32),
}

impl CaptureSession {
    /// Create a portal session and connect the first advertised screen stream
    /// to a PipeWire stream.
    pub async fn start(config: CaptureConfig) -> Result<Self, AppError> {
        // Capture only: request no input devices and no source-type
        // restriction. COSMIC's portal returns no streams when a combined
        // RemoteDesktop session requests Monitor|Window sources, so let the
        // backend choose its default source type. Persistence is disabled so
        // the portal asks for permission each time; this also avoids the
        // portal rejecting a persisted RemoteDesktop session.
        let portal_config = PortalConfig {
            allow_multiple: false,
            source_type: Default::default(),
            devices: Default::default(),
            persist_mode: Default::default(),
            ..PortalConfig::default()
        };

        let manager = PortalManager::new(portal_config).await?;
        let (session, restore_token) = manager
            .create_session("rvncserver".to_string(), None)
            .await?;

        if restore_token.is_some() {
            eprintln!("capture: portal returned a restore token (not persisted)");
        }

        let stream = session.streams().first().ok_or_else(|| {
            AppError::Capture("portal session did not provide a screen stream".to_string())
        })?;

        let stream_size = stream.size;
        let node_id = stream.node_id;

        if stream_size.0 == 0 || stream_size.1 == 0 {
            return Err(AppError::Capture(format!(
                "portal returned an empty stream size {}x{}",
                stream_size.0, stream_size.1
            )));
        }

        let pipewire_fd = session.pipewire_fd();
        let mut pipewire = PipeWireThreadManager::new(pipewire_fd)?;

        let stream_config = StreamConfig::new("rvncserver")
            .with_resolution(stream_size.0, stream_size.1)
            .with_framerate(config.framerate)
            .with_dmabuf(config.use_dmabuf)
            .with_buffer_count(config.buffer_count);

        let (response_tx, response_rx) = mpsc::sync_channel(1);
        if let Err(error) = pipewire.send_command(PipeWireThreadCommand::CreateStream {
            stream_id: 0,
            node_id,
            config: stream_config,
            response_tx,
        }) {
            let _ = pipewire.shutdown();
            return Err(error.into());
        }

        match response_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = pipewire.shutdown();
                return Err(error.into());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = pipewire.shutdown();
                return Err(AppError::Capture(
                    "timed out waiting for the PipeWire stream to be created".to_string(),
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = pipewire.shutdown();
                return Err(AppError::Capture(
                    "PipeWire thread exited while creating the stream".to_string(),
                ));
            }
        }

        Ok(Self {
            pipewire,
            _session: session,
            _manager: manager,
            stream_id: 0,
            stream_size,
        })
    }

    /// Receive a captured frame without blocking.
    pub fn try_recv_frame(&self) -> Option<VideoFrame> {
        self.pipewire.try_recv_frame()
    }

    /// Notification signalled after a frame is queued.
    pub fn frame_notify(&self) -> Arc<Notify> {
        self.pipewire.frame_notify()
    }

    /// Drain pending PipeWire stream state changes.
    pub fn drain_state_events(&self) -> Vec<lamco_pipewire::StreamStateEvent> {
        self.pipewire.drain_state_events()
    }

    /// Size reported by the portal for the selected stream.
    pub fn stream_size(&self) -> (u32, u32) {
        self.stream_size
    }

    /// Wait for the first usable frame, normalizing it before returning.
    ///
    /// Frames that cannot be normalized are skipped and reported at a bounded
    /// rate. This is used both by the server startup path and by the capture
    /// probe.
    pub async fn wait_for_first_frame(&self, timeout: Duration) -> Result<Frame, AppError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let notify = self.pipewire.frame_notify();
        let mut last_error_log = std::time::Instant::now();

        loop {
            while let Some(video_frame) = self.pipewire.try_recv_frame() {
                match Frame::from_video_frame(&video_frame) {
                    Ok(frame) => return Ok(frame),
                    Err(error) => {
                        if last_error_log.elapsed() >= Duration::from_secs(5) {
                            eprintln!("capture: skipping unusable frame: {error}");
                            last_error_log = std::time::Instant::now();
                        }
                    }
                }
            }

            for event in self.pipewire.drain_state_events() {
                match &event.state {
                    PwStreamState::Error(message) => {
                        eprintln!(
                            "capture: stream {} reported an error: {message}",
                            event.stream_id
                        );
                    }
                    state => {
                        eprintln!("capture: stream {} state: {state:?}", event.stream_id);
                    }
                }
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(AppError::Capture(format!(
                    "timed out after {} seconds waiting for a usable frame",
                    timeout.as_secs()
                )));
            }

            let remaining = deadline - now;
            let wait = remaining.min(Duration::from_millis(250));
            let _ = tokio::time::timeout(wait, notify.notified()).await;
        }
    }

    /// Stop the PipeWire stream and join the capture thread.
    pub fn shutdown(&mut self) {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        match self
            .pipewire
            .send_command(PipeWireThreadCommand::DestroyStream {
                stream_id: self.stream_id,
                response_tx,
            }) {
            Ok(()) => match response_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    eprintln!("capture: stream destruction failed: {error}");
                }
                Err(error) => {
                    eprintln!("capture: stream destruction did not complete: {error}");
                }
            },
            Err(error) => {
                eprintln!("capture: could not request stream destruction: {error}");
            }
        }

        if let Err(error) = self.pipewire.shutdown() {
            eprintln!("capture: PipeWire shutdown failed: {error}");
        }
    }
}

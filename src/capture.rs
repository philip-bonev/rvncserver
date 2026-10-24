//! XDG Desktop Portal and PipeWire capture session.
//!
//! This module owns the portal permission session and the dedicated PipeWire
//! thread. Frames are handed to the rest of the application as raw
//! [`VideoFrame`] values; normalization happens in [`crate::framebuffer`].

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use ashpd::desktop::PersistMode;
use ashpd::desktop::remote_desktop::DeviceType;
use lamco_pipewire::{
    PipeWireThreadCommand, PipeWireThreadManager, PwStreamState, StreamConfig, VideoFrame,
};
use lamco_portal::{
    ClipboardManager, PortalConfig, PortalError, PortalManager, PortalSessionHandle,
};
use tokio::sync::{Notify, mpsc as tokio_mpsc};

use crate::error::AppError;
use crate::framebuffer::Frame;
use crate::input::ClientEvent;

const HELD_POINTER_BUTTON_MASK: u8 = 0b0110_0111;
const WHEEL_BUTTON_MASK: u8 = 0b0001_1000;

/// Capture configuration.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Requested frame rate.
    pub framerate: u32,
    /// Number of PipeWire buffers requested.
    pub buffer_count: u32,
    /// Whether to negotiate DMA-BUF buffers. Lamco maps and copies supported
    /// linear DMA-BUFs into CPU memory; direct FD passthrough remains disabled.
    pub use_dmabuf: bool,
    /// Request keyboard and pointer injection permission from the portal.
    pub enable_input: bool,
    /// Request clipboard permission and enable text clipboard forwarding.
    pub enable_clipboard: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            framerate: 30,
            buffer_count: 3,
            use_dmabuf: true,
            enable_input: false,
            enable_clipboard: false,
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
    session: PortalSessionHandle,
    manager: PortalManager,
    clipboard: Option<Arc<ClipboardManager>>,
    remote_clipboard: Vec<u8>,
    pointer_buttons: u8,
    stream_id: u32,
    stream_size: (u32, u32),
}

impl CaptureSession {
    /// Create a portal session and connect the first advertised screen stream
    /// to a PipeWire stream.
    pub async fn start(config: CaptureConfig) -> Result<Self, AppError> {
        // Keep the source-type mask unrestricted. COSMIC's portal returns no
        // streams when a combined RemoteDesktop session requests Monitor|Window
        // sources, so let the backend choose its default source type.
        let clipboard = if config.enable_clipboard {
            match ClipboardManager::new().await {
                Ok(clipboard) => Some(Arc::new(clipboard)),
                Err(error) => {
                    crate::timestamped_log!(
                        "clipboard: portal clipboard is unavailable; continuing without clipboard sharing: {error}"
                    );
                    None
                }
            }
        } else {
            None
        };
        let manager =
            PortalManager::new(portal_config(PersistMode::Application, config.enable_input))
                .await?;
        let (manager, (session, restore_token)) = match manager
            .create_session("rvncserver".to_string(), clipboard.as_deref())
            .await
        {
            Ok(result) => (manager, result),
            Err(error) if persistence_is_unsupported(&error) => {
                crate::timestamped_log!(
                    "capture: portal does not support persisted permissions; retrying without persistence"
                );
                drop(manager);
                let manager =
                    PortalManager::new(portal_config(PersistMode::DoNot, config.enable_input))
                        .await?;
                let result = manager
                    .create_session("rvncserver".to_string(), clipboard.as_deref())
                    .await?;
                (manager, result)
            }
            Err(error) => return Err(error.into()),
        };

        if restore_token.is_some() {
            crate::timestamped_log!("capture: portal returned a restore token");
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
            session,
            manager,
            clipboard,
            remote_clipboard: Vec::new(),
            pointer_buttons: 0,
            stream_id: 0,
            stream_size,
        })
    }

    /// Receive a captured frame without blocking.
    pub fn try_recv_frame(&self) -> Option<VideoFrame> {
        self.pipewire.try_recv_frame()
    }

    /// Whether portal clipboard support initialized successfully.
    pub fn clipboard_enabled(&self) -> bool {
        self.clipboard.is_some()
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

    /// Start portal clipboard signal listeners for an enabled clipboard session.
    pub async fn start_clipboard_listeners(
        &self,
    ) -> Result<
        (
            tokio_mpsc::UnboundedReceiver<lamco_portal::clipboard::SelectionTransferEvent>,
            tokio_mpsc::UnboundedReceiver<Vec<String>>,
        ),
        AppError,
    > {
        let clipboard = self
            .clipboard
            .as_ref()
            .ok_or_else(|| AppError::Capture("clipboard support is disabled".to_string()))?;
        let (transfer_tx, transfer_rx) = tokio_mpsc::unbounded_channel();
        let (owner_tx, owner_rx) = tokio_mpsc::unbounded_channel();
        clipboard
            .start_selection_transfer_listener(transfer_tx)
            .await?;
        clipboard.start_owner_changed_listener(owner_tx).await?;
        Ok((transfer_rx, owner_rx))
    }

    /// Forward an RFB event through the permission-controlled portal session.
    pub async fn handle_client_event(&mut self, event: ClientEvent) -> Result<(), AppError> {
        match event {
            ClientEvent::Key { keysym, pressed } => {
                self.manager
                    .remote_desktop()
                    .notify_keyboard_keysym(
                        self.session.ashpd_session(),
                        i32::try_from(keysym).map_err(|_| {
                            AppError::Capture(format!("RFB keysym {keysym:#x} is out of range"))
                        })?,
                        pressed,
                    )
                    .await?;
                crate::timestamped_log!(
                    "input: portal keyboard key {} forwarded",
                    if pressed { "press" } else { "release" }
                );
                if matches!(keysym, 0xffe1..=0xffee) {
                    crate::timestamped_log!(
                        "input: portal modifier keysym {keysym:#x} {}",
                        if pressed { "pressed" } else { "released" }
                    );
                }
            }
            ClientEvent::Pointer { x, y, buttons } => {
                let stream = self.session.streams.first().ok_or_else(|| {
                    AppError::Capture("portal session has no input target stream".to_string())
                })?;
                let x = x.min(self.stream_size.0.saturating_sub(1) as u16);
                let y = y.min(self.stream_size.1.saturating_sub(1) as u16);
                let old_buttons = self.pointer_buttons;
                self.manager
                    .remote_desktop()
                    .notify_pointer_motion_absolute(
                        self.session.ashpd_session(),
                        stream.node_id,
                        f64::from(x),
                        f64::from(y),
                    )
                    .await?;

                for (rfb_bit, evdev_button) in [
                    (0, 0x110), // BTN_LEFT
                    (1, 0x112), // BTN_MIDDLE
                    (2, 0x111), // BTN_RIGHT
                    (5, 0x113), // BTN_SIDE
                    (6, 0x114), // BTN_EXTRA
                ] {
                    let bit = 1 << rfb_bit;
                    if (buttons ^ self.pointer_buttons) & bit != 0 {
                        let pressed = buttons & bit != 0;
                        self.manager
                            .remote_desktop()
                            .notify_pointer_button(
                                self.session.ashpd_session(),
                                evdev_button,
                                pressed,
                            )
                            .await?;
                        crate::timestamped_log!(
                            "input: portal pointer button {evdev_button:#x} {}",
                            if pressed { "pressed" } else { "released" }
                        );
                        if pressed {
                            self.pointer_buttons |= bit;
                        } else {
                            self.pointer_buttons &= !bit;
                        }
                    }
                }

                // RFB represents wheel ticks as transient button presses.
                for (rfb_bit, dy) in [(3, -1.0), (4, 1.0)] {
                    let bit = 1 << rfb_bit;
                    if buttons & bit != 0 && old_buttons & bit == 0 {
                        self.manager
                            .remote_desktop()
                            .notify_pointer_axis(self.session.ashpd_session(), 0.0, dy)
                            .await?;
                    }
                }
                self.pointer_buttons = merge_pointer_button_mask(self.pointer_buttons, buttons);
            }
            ClientEvent::Clipboard(data) => {
                let clipboard = self.clipboard.as_ref().ok_or_else(|| {
                    AppError::Capture("clipboard support is disabled".to_string())
                })?;
                self.remote_clipboard = latin1_to_utf8(&data);
                clipboard
                    .announce_rdp_formats(
                        self.session.ashpd_session(),
                        vec![
                            "text/plain;charset=utf-8".to_string(),
                            "text/plain".to_string(),
                        ],
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Provide remote-owned text when the local clipboard portal requests it.
    pub async fn handle_selection_transfer(
        &self,
        event: lamco_portal::clipboard::SelectionTransferEvent,
    ) -> Result<(), AppError> {
        let clipboard = self
            .clipboard
            .as_ref()
            .ok_or_else(|| AppError::Capture("clipboard support is disabled".to_string()))?;
        if event.mime_type != "text/plain" && event.mime_type != "text/plain;charset=utf-8" {
            clipboard
                .write_selection_data(self.session.ashpd_session(), event.serial, Vec::new())
                .await?;
            return Ok(());
        }
        clipboard
            .write_selection_data(
                self.session.ashpd_session(),
                event.serial,
                self.remote_clipboard.clone(),
            )
            .await?;
        Ok(())
    }

    /// Read local text for delivery to the connected RFB client.
    pub async fn read_local_clipboard(
        &self,
        mime_types: &[String],
    ) -> Result<Option<Vec<u8>>, AppError> {
        let Some(clipboard) = &self.clipboard else {
            return Ok(None);
        };
        let mime_type = ["text/plain;charset=utf-8", "text/plain"]
            .into_iter()
            .find(|supported| mime_types.iter().any(|mime| mime == supported));
        let Some(mime_type) = mime_type else {
            return Ok(None);
        };
        let data = clipboard
            .read_local_clipboard(self.session.ashpd_session(), mime_type)
            .await?;
        let mut text = utf8_to_latin1(&data);
        text.truncate(1024 * 1024);
        Ok(Some(text))
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
                let buffer_type = match video_frame.meta.buffer_type {
                    1 => "MemPtr",
                    2 => "MemFd",
                    3 => "DMA-BUF",
                    _ => "unknown",
                };
                match Frame::from_video_frame(&video_frame) {
                    Ok(frame) => {
                        crate::timestamped_log!(
                            "capture: first usable PipeWire buffer type: {buffer_type}"
                        );
                        return Ok(frame);
                    }
                    Err(error) => {
                        if last_error_log.elapsed() >= Duration::from_secs(5) {
                            crate::timestamped_log!("capture: skipping unusable frame: {error}");
                            last_error_log = std::time::Instant::now();
                        }
                    }
                }
            }

            for event in self.pipewire.drain_state_events() {
                match &event.state {
                    PwStreamState::Error(message) => {
                        crate::timestamped_log!(
                            "capture: stream {} reported an error: {message}",
                            event.stream_id
                        );
                    }
                    state => {
                        crate::timestamped_log!(
                            "capture: stream {} state: {state:?}",
                            event.stream_id
                        );
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
                    crate::timestamped_log!("capture: stream destruction failed: {error}");
                }
                Err(error) => {
                    crate::timestamped_log!(
                        "capture: stream destruction did not complete: {error}"
                    );
                }
            },
            Err(error) => {
                crate::timestamped_log!("capture: could not request stream destruction: {error}");
            }
        }

        if let Err(error) = self.pipewire.shutdown() {
            crate::timestamped_log!("capture: PipeWire shutdown failed: {error}");
        }
    }
}

fn portal_config(persist_mode: PersistMode, enable_input: bool) -> PortalConfig {
    PortalConfig {
        allow_multiple: false,
        source_type: Default::default(),
        devices: if enable_input {
            DeviceType::Keyboard | DeviceType::Pointer
        } else {
            Default::default()
        },
        persist_mode,
        ..PortalConfig::default()
    }
}

fn merge_pointer_button_mask(current: u8, event: u8) -> u8 {
    (current & HELD_POINTER_BUTTON_MASK) | (event & WHEEL_BUTTON_MASK)
}

fn latin1_to_utf8(data: &[u8]) -> Vec<u8> {
    let mut text = String::with_capacity(data.len());
    for byte in data {
        text.push(char::from(*byte));
    }
    text.into_bytes()
}

fn utf8_to_latin1(data: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(data)
        .chars()
        .map(|character| u8::try_from(u32::from(character)).unwrap_or(b'?'))
        .collect()
}

fn persistence_is_unsupported(error: &PortalError) -> bool {
    match error {
        PortalError::SessionCreation(message) => {
            message.to_ascii_lowercase().contains("cannot persist")
        }
        PortalError::PortalRequest(error) => error
            .to_string()
            .to_ascii_lowercase()
            .contains("cannot persist"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_dmabuf_negotiation_without_fd_passthrough() {
        assert!(CaptureConfig::default().use_dmabuf);
        assert!(!CaptureConfig::default().enable_input);
        assert!(!CaptureConfig::default().enable_clipboard);
        assert!(!StreamConfig::new("test").dmabuf_passthrough);
    }

    #[test]
    fn converts_rfb_latin1_and_portal_utf8_clipboard_text() {
        assert_eq!(latin1_to_utf8(&[b'A', 0xe9]), "Aé".as_bytes());
        assert_eq!(utf8_to_latin1("Aé€".as_bytes()), [b'A', 0xe9, b'?']);
    }

    #[test]
    fn pointer_mask_retains_button_state_until_release() {
        let pressed = merge_pointer_button_mask(0b0000_0001, 0b0000_0001);
        assert_eq!(pressed & 0b0000_0111, 0b0000_0001);

        let released = merge_pointer_button_mask(0, 0);
        assert_eq!(released & 0b0000_0111, 0);

        let with_wheel = merge_pointer_button_mask(0b0100_0010, 0b0001_1000);
        assert_eq!(with_wheel, 0b0101_1010);
    }

    #[test]
    fn only_falls_back_for_explicit_persistence_rejection() {
        assert!(persistence_is_unsupported(&PortalError::SessionCreation(
            "Source selection: InvalidArgument: Remote desktop sessions cannot persist".into()
        )));
        assert!(!persistence_is_unsupported(&PortalError::SessionCreation(
            "User denied permission".into()
        )));
    }
}

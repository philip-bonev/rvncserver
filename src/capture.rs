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

//! XDG Desktop Portal and PipeWire capture session.
//!
//! This module owns the portal permission session and the dedicated PipeWire
//! thread. Frames are handed to the rest of the application as raw
//! [`VideoFrame`] values; normalization happens in [`crate::framebuffer`].

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use ashpd::desktop::PersistMode;
use ashpd::desktop::remote_desktop::DeviceType;
use lamco_pipewire::{PipeWireThreadCommand, PipeWireThreadManager, PwStreamState, StreamConfig};
use lamco_portal::{
    ClipboardManager, PortalConfig, PortalError, PortalManager, PortalSessionHandle,
};
use tokio::sync::Notify;

use crate::clipboard::portal::PortalClipboard;
use crate::composite::{Composite, MonitorLayout, MonitorSpec};
use crate::cursor::CursorUpdate;
use crate::error::AppError;
use crate::framebuffer::{Frame, FrameDamage};
use crate::input::ClientEvent;

/// RFB button bits held down between events: left, middle, right, and Back
/// (RFB buttons 1, 2, 3, and 8).
const HELD_POINTER_BUTTON_MASK: u8 = 0b1000_0111;
/// RFB button bits that represent transient wheel ticks: scroll up, down,
/// left, and right (RFB buttons 4-7).
const WHEEL_BUTTON_MASK: u8 = 0b0111_1000;

/// Owner-only file holding the portal restore token across restarts.
const RESTORE_TOKEN_FILE: &str = "portal-restore-token";

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
    session: Arc<PortalSessionHandle>,
    manager: PortalManager,
    clipboard: Option<Arc<ClipboardManager>>,
    pointer_buttons: u8,
    layout: MonitorLayout,
    composite: Composite,
    frame_error_log: Option<std::time::Instant>,
}

/// A composited desktop update and the cursor metadata received with it.
pub struct CapturedFrame {
    /// Composite framebuffer covering every captured monitor.
    pub frame: Arc<Frame>,
    /// Cursor state translated into composite coordinates.
    pub cursor: Option<CursorUpdate>,
}

/// Linux evdev keycodes for the non-printable keysyms.
///
/// The RemoteDesktop portal takes raw evdev keycodes on the keycode path
/// ("evdev keycodes and xkb keysyms"). Several compositors silently ignore
/// special keysyms, so the keycode path is the reliable one.
fn special_keycode(keysym: u32) -> Option<i32> {
    Some(match keysym {
        // Stateful modifiers.
        0xffe1 => 42,  // Shift_L
        0xffe2 => 54,  // Shift_R
        0xffe3 => 29,  // Control_L
        0xffe4 => 97,  // Control_R
        0xffe7 => 125, // Meta_L
        0xffe8 => 126, // Meta_R
        0xffe9 => 56,  // Alt_L
        0xffea => 100, // Alt_R
        0xffeb => 125, // Super_L
        0xffec => 126, // Super_R
        0xffed => 125, // Hyper_L
        0xffee => 126, // Hyper_R
        0xfe03 => 100, // ISO_Level3_Shift (AltGr)
        // Lock keys.
        0xffe5 => 58, // Caps_Lock
        0xff7f => 69, // Num_Lock
        0xff14 => 70, // Scroll_Lock
        // Editing and navigation.
        0xff08 => 14,  // BackSpace
        0xff09 => 15,  // Tab
        0xff0d => 28,  // Return
        0xff1b => 1,   // Escape
        0xff13 => 119, // Pause
        0xff61 => 99,  // Print
        0xff67 => 127, // Menu
        0xff8d => 96,  // KP_Enter
        0xffff => 111, // Delete
        0xff50 => 102, // Home
        0xff51 => 105, // Left
        0xff52 => 103, // Up
        0xff53 => 106, // Right
        0xff54 => 108, // Down
        0xff55 => 104, // Page_Up
        0xff56 => 109, // Page_Down
        0xff57 => 107, // End
        0xff63 => 110, // Insert
        // Function keys.
        0xffbe => 59, // F1
        0xffbf => 60, // F2
        0xffc0 => 61, // F3
        0xffc1 => 62, // F4
        0xffc2 => 63, // F5
        0xffc3 => 64, // F6
        0xffc4 => 65, // F7
        0xffc5 => 66, // F8
        0xffc6 => 67, // F9
        0xffc7 => 68, // F10
        0xffc8 => 87, // F11
        0xffc9 => 88, // F12
        _ => return None,
    })
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
        let token_path = restore_token_path();
        let stored_token = token_path.as_deref().and_then(load_restore_token);
        if stored_token.is_some() {
            crate::timestamped_log!("capture: using stored portal restore token");
        } else if token_path.is_none() {
            crate::timestamped_log!(
                "capture: cannot persist portal restore token; set XDG_STATE_HOME or HOME"
            );
        }

        let mut persist_mode = PersistMode::Application;
        let mut restore_token = stored_token.clone();
        let mut token_rejected = false;
        let (manager, (session, new_restore_token)) = loop {
            let manager = PortalManager::new(portal_config(
                persist_mode,
                config.enable_input,
                restore_token.clone(),
            ))
            .await?;
            match manager
                .create_session("rvncserver".to_string(), clipboard.as_deref())
                .await
            {
                Ok(result) => break (manager, result),
                Err(error)
                    if persist_mode == PersistMode::Application
                        && persistence_is_unsupported(&error) =>
                {
                    crate::timestamped_log!(
                        "capture: portal does not support persisted permissions; retrying without persistence"
                    );
                    if let Some(path) = token_path.as_deref() {
                        remove_restore_token(path);
                    }
                    persist_mode = PersistMode::DoNot;
                    restore_token = None;
                }
                Err(error)
                    if restore_token.is_some()
                        && !matches!(&error, PortalError::PermissionDenied) =>
                {
                    crate::timestamped_log!(
                        "capture: portal rejected the stored restore token; retrying without it: {error}"
                    );
                    token_rejected = true;
                    restore_token = None;
                }
                Err(error) => return Err(error.into()),
            }
        };

        if let Some(token) = new_restore_token.as_deref() {
            if persist_mode == PersistMode::DoNot {
                crate::timestamped_log!(
                    "capture: portal returned a restore token without persistence; not saving it"
                );
            } else if let Some(path) = token_path.as_deref() {
                match save_restore_token(path, token) {
                    Ok(()) if !token_rejected && stored_token.as_deref() == Some(token) => {
                        crate::timestamped_log!("capture: portal reused the stored restore token");
                    }
                    Ok(()) => crate::timestamped_log!("capture: saved portal restore token"),
                    Err(error) => crate::timestamped_log!(
                        "capture: could not save portal restore token: {error}"
                    ),
                }
            } else {
                crate::timestamped_log!(
                    "capture: portal returned a restore token but no state directory is available"
                );
            }
        } else if token_rejected {
            // The portal accepted a session without the stored token and did
            // not issue a replacement, so the old token is no longer useful.
            if let Some(path) = token_path.as_deref() {
                remove_restore_token(path);
            }
        }

        let streams = session.streams();
        if streams.is_empty() {
            return Err(AppError::Capture(
                "portal session did not provide a screen stream".to_string(),
            ));
        }
        let monitors: Vec<MonitorSpec> = streams
            .iter()
            .map(|stream| (stream.node_id, stream.position, stream.size))
            .collect();
        for (node_id, _, (width, height)) in &monitors {
            if *width == 0 || *height == 0 {
                return Err(AppError::Capture(format!(
                    "portal returned an empty stream size {width}x{height} for node {node_id}"
                )));
            }
        }
        let layout = MonitorLayout::from_monitors(&monitors).map_err(AppError::Capture)?;
        let composite = Composite::new(layout.clone()).map_err(AppError::Capture)?;

        let pipewire_fd = session.pipewire_fd();
        let mut pipewire = PipeWireThreadManager::new(pipewire_fd)?;

        for (index, monitor) in monitors.iter().enumerate() {
            let (node_id, _, size) = monitor;
            let stream_config = StreamConfig::new("rvncserver")
                .with_resolution(size.0, size.1)
                .with_framerate(config.framerate)
                .with_dmabuf(config.use_dmabuf)
                .with_buffer_count(config.buffer_count);
            let (response_tx, response_rx) = mpsc::sync_channel(1);
            if let Err(error) = pipewire.send_command(PipeWireThreadCommand::CreateStream {
                stream_id: index as u32,
                node_id: *node_id,
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
                    return Err(AppError::Capture(format!(
                        "timed out waiting for PipeWire stream {index} to be created"
                    )));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = pipewire.shutdown();
                    return Err(AppError::Capture(
                        "PipeWire thread exited while creating the stream".to_string(),
                    ));
                }
            }
        }

        let (width, height) = layout.size();
        crate::timestamped_log!(
            "capture: composing {} monitor stream(s) into {width}x{height}",
            monitors.len()
        );

        Ok(Self {
            pipewire,
            session: Arc::new(session),
            manager,
            clipboard,
            pointer_buttons: 0,
            layout,
            composite,
            frame_error_log: None,
        })
    }

    /// Receive the next composited update without blocking.
    ///
    /// Every queued monitor frame is blitted into the composite before an
    /// update is returned, so one update covers all monitors that changed.
    /// With a single monitor the normalized frame is returned directly and no
    /// composite copy is made.
    pub fn try_recv_frame(&mut self) -> Option<CapturedFrame> {
        let single = self.layout.monitors().len() == 1;
        let mut cursor = None;
        let mut damage = FrameDamage::Regions(Vec::new());
        let mut composited = false;
        let mut direct = None;
        while let Some(video_frame) = self.pipewire.try_recv_frame() {
            let monitor = match usize::try_from(video_frame.monitor_index)
                .ok()
                .filter(|index| *index < self.layout.monitors().len())
            {
                Some(monitor) => monitor,
                None => continue,
            };
            let frame = match Frame::from_video_frame(&video_frame) {
                Ok(frame) => frame,
                Err(error) => {
                    self.log_frame_error(&error.to_string());
                    continue;
                }
            };
            if let Some(update) = CursorUpdate::from_video_frame(&video_frame) {
                cursor = Some(self.translate_cursor(monitor, update));
            }
            if single {
                direct = Some(Arc::new(frame));
                continue;
            }
            match self.composite.blit(monitor, &frame) {
                Ok(monitor_damage) => {
                    damage = combine_damage(damage, monitor_damage);
                    composited = true;
                }
                Err(error) => self.log_frame_error(&error.to_string()),
            }
        }
        if let Some(frame) = direct {
            return Some(CapturedFrame { frame, cursor });
        }
        if !composited {
            return None;
        }
        let (width, height) = self.layout.size();
        Some(CapturedFrame {
            frame: Arc::new(Frame {
                width,
                height,
                data: self.composite.snapshot(),
                damage,
                source_sequence: None,
            }),
            cursor,
        })
    }

    /// Translate monitor-local cursor metadata into composite coordinates.
    fn translate_cursor(&self, monitor: usize, update: CursorUpdate) -> CursorUpdate {
        CursorUpdate {
            position: update
                .position
                .map(|position| self.layout.translate_point(monitor, position)),
            shape: update.shape,
        }
    }

    fn log_frame_error(&mut self, message: &str) {
        if self
            .frame_error_log
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(5))
        {
            crate::timestamped_log!("capture: skipping unusable frame: {message}");
            self.frame_error_log = Some(std::time::Instant::now());
        }
    }

    /// Create a backend adapter for the active portal clipboard session.
    pub fn portal_clipboard_backend(&self) -> Option<PortalClipboard> {
        Some(PortalClipboard::new(
            Arc::clone(self.clipboard.as_ref()?),
            Arc::clone(&self.session),
        ))
    }

    /// Notification signalled after a frame is queued.
    pub fn frame_notify(&self) -> Arc<Notify> {
        self.pipewire.frame_notify()
    }

    /// Drain pending PipeWire stream state changes.
    pub fn drain_state_events(&self) -> Vec<lamco_pipewire::StreamStateEvent> {
        self.pipewire.drain_state_events()
    }

    /// Forward an RFB event through the permission-controlled portal session.
    pub async fn handle_client_event(&mut self, event: ClientEvent) -> Result<(), AppError> {
        match event {
            ClientEvent::Key { keysym, pressed } => {
                // Special keysyms are silently ignored by some compositors
                // and can even cancel an already-held key there, while the
                // keycode path is reliable. Non-printable keys are injected
                // as evdev keycodes; the keysym path is used only as a
                // fallback when the keycode path fails, never together with
                // it.
                let mut injected = false;
                if let Some(keycode) = special_keycode(keysym) {
                    match self
                        .manager
                        .remote_desktop()
                        .notify_keyboard_keycode(self.session.ashpd_session(), keycode, pressed)
                        .await
                    {
                        Ok(()) => injected = true,
                        Err(error) => crate::timestamped_log!(
                            "input: portal rejected special keycode {keycode}: {error}"
                        ),
                    }
                }
                if !injected {
                    match self
                        .manager
                        .remote_desktop()
                        .notify_keyboard_keysym(
                            self.session.ashpd_session(),
                            i32::try_from(keysym).map_err(|_| {
                                AppError::Capture(format!("RFB keysym {keysym:#x} is out of range"))
                            })?,
                            pressed,
                        )
                        .await
                    {
                        Ok(()) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            ClientEvent::Pointer { x, y, buttons } => {
                // Composite coordinates are routed to the owning monitor and
                // converted to that monitor's stream coordinates.
                let (monitor, (local_x, local_y)) =
                    self.layout.route_pointer(i32::from(x), i32::from(y));
                let node_id = self.layout.monitors()[monitor].node_id;
                let old_buttons = self.pointer_buttons;
                self.manager
                    .remote_desktop()
                    .notify_pointer_motion_absolute(
                        self.session.ashpd_session(),
                        node_id,
                        f64::from(local_x),
                        f64::from(local_y),
                    )
                    .await?;

                for (rfb_bit, evdev_button) in [
                    (0, 0x110), // BTN_LEFT
                    (1, 0x112), // BTN_MIDDLE
                    (2, 0x111), // BTN_RIGHT
                    (7, 0x116), // BTN_BACK (RFB button 8)
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

                // RFB represents wheel steps as transient button presses:
                // buttons 4-7 are scroll up, down, left, and right.
                for (rfb_bit, dx, dy) in
                    [(3, 0.0, -1.0), (4, 0.0, 1.0), (5, -1.0, 0.0), (6, 1.0, 0.0)]
                {
                    let bit = 1 << rfb_bit;
                    if buttons & bit != 0 && old_buttons & bit == 0 {
                        self.manager
                            .remote_desktop()
                            .notify_pointer_axis(self.session.ashpd_session(), dx, dy)
                            .await?;
                    }
                }
                self.pointer_buttons = merge_pointer_button_mask(self.pointer_buttons, buttons);
            }
            ClientEvent::Clipboard(data) => {
                return Err(AppError::Capture(format!(
                    "clipboard event must be handled by ClipboardService ({} bytes)",
                    data.len()
                )));
            }
        }
        Ok(())
    }

    /// Wait for the first usable composited update.
    ///
    /// Updates that cannot be produced are skipped and reported at a bounded
    /// rate. This is used both by the server startup path and by the capture
    /// probe.
    pub async fn wait_for_first_frame(
        &mut self,
        timeout: Duration,
        capture_cursor: bool,
    ) -> Result<CapturedFrame, AppError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let notify = self.pipewire.frame_notify();

        loop {
            if let Some(update) = self.try_recv_frame() {
                let (width, height) = self.layout.size();
                crate::timestamped_log!(
                    "capture: first usable update at {}x{} from {} monitor stream(s)",
                    width,
                    height,
                    self.layout.monitors().len()
                );
                return Ok(CapturedFrame {
                    frame: update.frame,
                    cursor: if capture_cursor { update.cursor } else { None },
                });
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
        for index in 0..self.layout.monitors().len() {
            let (response_tx, response_rx) = mpsc::sync_channel(1);
            match self
                .pipewire
                .send_command(PipeWireThreadCommand::DestroyStream {
                    stream_id: index as u32,
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
                    crate::timestamped_log!(
                        "capture: could not request stream destruction: {error}"
                    );
                }
            }
        }

        if let Err(error) = self.pipewire.shutdown() {
            crate::timestamped_log!("capture: PipeWire shutdown failed: {error}");
        }
    }
}

fn portal_config(
    persist_mode: PersistMode,
    enable_input: bool,
    restore_token: Option<String>,
) -> PortalConfig {
    PortalConfig {
        allow_multiple: false,
        source_type: Default::default(),
        devices: if enable_input {
            DeviceType::Keyboard | DeviceType::Pointer
        } else {
            Default::default()
        },
        persist_mode,
        restore_token,
        ..PortalConfig::default()
    }
}

fn restore_token_path() -> Option<PathBuf> {
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/state"))
        });
    state_home.map(|path| path.join("rvncserver").join(RESTORE_TOKEN_FILE))
}

fn load_restore_token(path: &Path) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(token) => {
            let token = token.trim();
            if token.is_empty() {
                None
            } else {
                Some(token.to_string())
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            crate::timestamped_log!("capture: could not read portal restore token: {error}");
            None
        }
    }
}

fn save_restore_token(path: &Path, token: &str) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "portal restore token path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;

    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let result = (|| {
        // Remove a stale temporary file so create_new cannot follow a
        // pre-existing symlink.
        let _ = fs::remove_file(&temporary);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_restore_token(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            crate::timestamped_log!("capture: could not remove stale portal restore token: {error}")
        }
    }
}

/// Merge the damage of coalesced monitor updates into one composite damage.
fn combine_damage(left: FrameDamage, right: FrameDamage) -> FrameDamage {
    match (left, right) {
        (FrameDamage::Full, _) | (_, FrameDamage::Full) => FrameDamage::Full,
        (FrameDamage::Regions(mut left), FrameDamage::Regions(right)) => {
            left.extend(right);
            FrameDamage::Regions(left)
        }
    }
}

fn merge_pointer_button_mask(current: u8, event: u8) -> u8 {
    (current & HELD_POINTER_BUTTON_MASK) | (event & WHEEL_BUTTON_MASK)
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
    fn special_keys_map_to_evdev_keycodes() {
        assert_eq!(special_keycode(0xffe3), Some(29)); // Control_L
        assert_eq!(special_keycode(0xffe1), Some(42)); // Shift_L
        assert_eq!(special_keycode(0xffe9), Some(56)); // Alt_L
        assert_eq!(special_keycode(0xffeb), Some(125)); // Super_L
        assert_eq!(special_keycode(0xfe03), Some(100)); // AltGr
        assert_eq!(special_keycode(0xffe5), Some(58)); // Caps_Lock
        assert_eq!(special_keycode(0xff51), Some(105)); // Left
        assert_eq!(special_keycode(0xffc2), Some(63)); // F5
        assert_eq!(special_keycode(0xff0d), Some(28)); // Return
        assert_eq!(special_keycode(0x72), None); // 'r'
        assert_eq!(special_keycode(0x41), None); // 'A'
    }

    #[test]
    fn pointer_mask_retains_button_state_until_release() {
        let pressed = merge_pointer_button_mask(0b0000_0001, 0b0000_0001);
        assert_eq!(pressed & HELD_POINTER_BUTTON_MASK, 0b0000_0001);

        let released = merge_pointer_button_mask(0, 0);
        assert_eq!(released & HELD_POINTER_BUTTON_MASK, 0);

        // Held buttons (including Back) persist across events; wheel ticks
        // are only remembered for edge detection and cleared afterwards.
        let with_wheel = merge_pointer_button_mask(0b1000_0010, 0b0111_1000);
        assert_eq!(with_wheel, 0b1111_1010);
        assert_eq!(merge_pointer_button_mask(with_wheel, 0), 0b1000_0010);
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

    #[test]
    fn restore_token_round_trips_with_private_permissions() {
        let directory = std::env::temp_dir().join(format!(
            "rvncserver-token-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let path = directory.join(RESTORE_TOKEN_FILE);
        let _ = fs::remove_dir_all(&directory);
        assert_eq!(load_restore_token(&path), None);

        save_restore_token(&path, "first-token").unwrap();
        assert_eq!(load_restore_token(&path).as_deref(), Some("first-token"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        save_restore_token(&path, "second-token").unwrap();
        assert_eq!(load_restore_token(&path).as_deref(), Some("second-token"));

        remove_restore_token(&path);
        assert_eq!(load_restore_token(&path), None);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn empty_restore_token_is_treated_as_absent() {
        let path = std::env::temp_dir().join(format!(
            "rvncserver-empty-token-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&path, "  \n").unwrap();
        assert_eq!(load_restore_token(&path), None);
        fs::remove_file(path).unwrap();
    }
}

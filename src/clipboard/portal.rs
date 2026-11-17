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

//! XDG Desktop Portal clipboard backend.

use std::future::Future;
use std::os::fd::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;

use lamco_portal::{ClipboardManager, PortalSessionHandle};

use super::{ClipboardBackend, ClipboardListenerEvent, ListenerFuture, TextFuture};
use tokio::sync::mpsc;

/// Largest clipboard payload accepted from the desktop; matches the RFB
/// cut-text limit.
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// Clipboard backend attached to an already-authorized portal session.
pub struct PortalClipboard {
    manager: Arc<ClipboardManager>,
    session: Arc<PortalSessionHandle>,
    mime_types: Vec<String>,
    remote_text: Vec<u8>,
    listeners_started: bool,
}

impl PortalClipboard {
    /// Attach the clipboard manager to the active desktop portal session.
    pub fn new(manager: Arc<ClipboardManager>, session: Arc<PortalSessionHandle>) -> Self {
        Self {
            manager,
            session,
            mime_types: vec![
                "text/plain;charset=utf-8".to_string(),
                "text/plain".to_string(),
            ],
            remote_text: Vec::new(),
            listeners_started: false,
        }
    }

    /// MIME types accepted for text clipboard interchange.
    pub fn mime_types(&self) -> &[String] {
        &self.mime_types
    }

    /// Announce remote-owned text to the portal and cache it on success, so a
    /// failed announcement can never serve text that was never offered.
    pub async fn set_remote_text(&mut self, text: Vec<u8>) -> Result<(), String> {
        self.manager
            .announce_rdp_formats(self.session.ashpd_session(), self.mime_types.clone())
            .await
            .map_err(|error| error.to_string())?;
        self.remote_text = text;
        Ok(())
    }

    /// Reply to a portal selection-transfer request.
    pub async fn provide_selection(&self, serial: u32, mime_type: &str) -> Result<(), String> {
        let bytes = if self.mime_types.iter().any(|mime| mime == mime_type) {
            self.remote_text.clone()
        } else {
            Vec::new()
        };
        self.manager
            .write_selection_data(self.session.ashpd_session(), serial, bytes)
            .await
            .map_err(|error| error.to_string())
    }
}

impl ClipboardBackend for PortalClipboard {
    fn start_listeners<'a>(&'a mut self) -> ListenerFuture<'a> {
        Box::pin(async move {
            if self.listeners_started {
                return Err("portal clipboard listeners already started".to_string());
            }
            self.listeners_started = true;
            let (transfer_tx, mut transfer_rx) = mpsc::unbounded_channel();
            let (owner_tx, mut owner_rx) = mpsc::unbounded_channel();
            self.manager
                .start_selection_transfer_listener(transfer_tx)
                .await
                .map_err(|error| error.to_string())?;
            self.manager
                .start_owner_changed_listener(owner_tx)
                .await
                .map_err(|error| error.to_string())?;

            let (event_tx, event_rx) = mpsc::unbounded_channel();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        transfer = transfer_rx.recv() => match transfer {
                            Some(transfer) => {
                                if event_tx.send(ClipboardListenerEvent::TransferRequest {
                                    serial: transfer.serial,
                                    mime_type: transfer.mime_type,
                                }).is_err() { break; }
                            }
                            None => break,
                        },
                        owner = owner_rx.recv() => match owner {
                            Some(mime_types) => {
                                if event_tx.send(ClipboardListenerEvent::LocalSelectionChanged(mime_types)).is_err() { break; }
                            }
                            None => break,
                        },
                    }
                }
            });
            Ok(event_rx)
        })
    }

    fn read_text<'a>(&'a mut self) -> TextFuture<'a> {
        Box::pin(async move {
            // A selection owner may offer only plain `text/plain`; try every
            // accepted text MIME type before giving up.
            let mut last_error = None;
            for mime_type in &self.mime_types {
                match read_portal_selection(&self.manager, &self.session, mime_type).await {
                    Ok(text) => return Ok(Some(text)),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| "no text MIME type was offered".to_string()))
        })
    }

    fn write_text<'a>(
        &'a mut self,
        text: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.set_remote_text(text).await })
    }

    fn provide_transfer<'a>(
        &'a mut self,
        serial: u32,
        mime_type: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.provide_selection(serial, &mime_type).await })
    }
}

/// Read one portal selection with a hard payload bound.
///
/// `ClipboardManager::read_local_clipboard` reads the transfer to completion
/// before any bound can be applied, so a large local selection would be
/// allocated in full first. Reading the selection fd directly keeps the bound
/// in force while the data is transferred.
async fn read_portal_selection(
    manager: &ClipboardManager,
    session: &PortalSessionHandle,
    mime_type: &str,
) -> Result<Vec<u8>, String> {
    let fd: OwnedFd = manager
        .portal_clipboard()
        .selection_read(session.ashpd_session(), mime_type)
        .await
        .map_err(|error| error.to_string())?
        .into();
    tokio::task::spawn_blocking(move || read_fd_bounded(fd))
        .await
        .map_err(|error| format!("clipboard read task failed: {error}"))?
}

fn read_fd_bounded(fd: OwnedFd) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let mut file = std::fs::File::from(fd);
    // The portal returns a non-blocking pipe descriptor; make reads blocking
    // for the bounded loop below.
    let raw_fd = file.as_raw_fd();
    // SAFETY: raw_fd is a valid descriptor owned by `file` and fcntl reports
    // failure through its return value.
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
    if flags != -1 {
        // SAFETY: as above; clearing O_NONBLOCK makes reads blocking.
        unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    }

    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    while output.len() < MAX_CLIPBOARD_BYTES {
        let limit = buffer.len().min(MAX_CLIPBOARD_BYTES - output.len());
        match file.read(&mut buffer[..limit]) {
            Ok(0) => break,
            // Only real end-of-data stops the transfer; an interrupted read
            // must not silently truncate the selection.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("could not read local clipboard: {error}")),
            Ok(size) => output.extend_from_slice(&buffer[..size]),
        }
    }
    Ok(output)
}

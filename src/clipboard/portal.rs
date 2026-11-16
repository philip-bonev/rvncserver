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
use std::pin::Pin;
use std::sync::Arc;

use lamco_portal::{ClipboardManager, PortalSessionHandle};

use super::{ClipboardBackend, ClipboardListenerEvent};
use tokio::sync::mpsc;

/// Clipboard backend attached to an already-authorized portal session.
pub struct PortalClipboard {
    manager: Arc<ClipboardManager>,
    session: Arc<PortalSessionHandle>,
    mime_types: Vec<String>,
    remote_text: Vec<u8>,
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
        }
    }

    /// MIME types accepted for text clipboard interchange.
    pub fn mime_types(&self) -> &[String] {
        &self.mime_types
    }

    /// Cache remote-owned text and announce it to the portal.
    pub async fn set_remote_text(&mut self, text: Vec<u8>) -> Result<(), String> {
        self.remote_text = text;
        self.manager
            .announce_rdp_formats(self.session.ashpd_session(), self.mime_types.clone())
            .await
            .map_err(|error| error.to_string())
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
    fn start_listeners<'a>(
        &'a mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<mpsc::UnboundedReceiver<ClipboardListenerEvent>, String>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
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

    fn read_text<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, String>> + Send + 'a>> {
        Box::pin(async move {
            let data = self
                .manager
                .read_local_clipboard(self.session.ashpd_session(), &self.mime_types[0])
                .await
                .map_err(|error| error.to_string())?;
            let mut text = data;
            text.truncate(1024 * 1024);
            Ok(Some(text))
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

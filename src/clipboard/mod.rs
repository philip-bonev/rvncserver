//! Backend-independent clipboard service and events.
//!
//! Desktop clipboard access is deliberately isolated from the RFB protocol.
//! Backends translate to and from UTF-8; the RFB layer remains responsible for
//! its Latin-1 wire representation.

pub mod portal;
pub mod wayland;

use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;

/// Clipboard events normalized across desktop backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardEvent {
    /// The local desktop clipboard now has text available.
    LocalText(Vec<u8>),
    /// A remote client supplied new text for the local desktop clipboard.
    RemoteText(Vec<u8>),
}

/// Notifications emitted by a backend's listener task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardListenerEvent {
    /// The set of MIME types available on the local selection changed.
    LocalSelectionChanged(Vec<String>),
    /// The local clipboard owner requests data for a MIME type.
    TransferRequest { serial: u32, mime_type: String },
}

/// Common operations provided by a desktop clipboard backend.
///
/// Implementations are expected to bound clipboard payloads and to report
/// unsupported formats as `None`, rather than treating them as errors.
pub trait ClipboardBackend: Send {
    /// Initialize backend connection and capabilities.
    fn initialize<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    /// Start backend-specific clipboard listeners.
    fn start_listeners<'a>(
        &'a mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<mpsc::UnboundedReceiver<ClipboardListenerEvent>, String>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err("clipboard listeners are not implemented for this backend".into()) })
    }

    /// Read the current local clipboard text, if available.
    fn read_text<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, String>> + Send + 'a>>;

    /// Publish text supplied by the connected remote client.
    fn write_text<'a>(
        &'a mut self,
        text: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Answer a backend-local transfer request with the current remote text.
    fn provide_transfer<'a>(
        &'a mut self,
        _serial: u32,
        _mime_type: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("clipboard transfer responses are unsupported".into()) })
    }

    /// Release backend resources.
    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

/// Coordinates one selected backend and exposes normalized events to RFB.
pub struct ClipboardService {
    backend: Option<Box<dyn ClipboardBackend>>,
}

impl ClipboardService {
    /// Construct a service around an already initialized backend.
    pub fn new(backend: impl ClipboardBackend + 'static) -> Self {
        Self {
            backend: Some(Box::new(backend)),
        }
    }

    /// Select and start a usable backend.
    ///
    /// Backend selection is supplied by the caller so portal permission
    /// failures can be distinguished from unavailable portal clipboard support.
    pub async fn initialize(backend: impl ClipboardBackend + 'static) -> Result<Self, String> {
        let mut service = Self::new(backend);
        service
            .backend
            .as_mut()
            .ok_or_else(|| "clipboard backend is unavailable".to_string())?
            .initialize()
            .await?;
        Ok(service)
    }

    /// Whether clipboard synchronization has an active backend.
    pub fn is_enabled(&self) -> bool {
        self.backend.is_some()
    }

    /// Start listeners and return normalized backend notifications.
    pub async fn start_listeners(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<ClipboardListenerEvent>, String> {
        self.backend
            .as_mut()
            .ok_or_else(|| "clipboard service is not initialized".to_string())?
            .start_listeners()
            .await
    }

    /// Publish remote text to the desktop clipboard.
    pub async fn set_remote_text(&mut self, text: Vec<u8>) -> Result<(), String> {
        self.backend
            .as_mut()
            .ok_or_else(|| "clipboard service is not initialized".to_string())?
            .write_text(text)
            .await
    }

    /// Respond to a backend transfer request using the cached remote text.
    pub async fn provide_transfer(&mut self, serial: u32, mime_type: String) -> Result<(), String> {
        self.backend
            .as_mut()
            .ok_or_else(|| "clipboard service is not initialized".to_string())?
            .provide_transfer(serial, mime_type)
            .await
    }

    /// Read local text for forwarding to a remote client.
    pub async fn read_local_text(&mut self) -> Result<Option<ClipboardEvent>, String> {
        self.backend
            .as_mut()
            .ok_or_else(|| "clipboard service is not initialized".to_string())?
            .read_text()
            .await
            .map(|text| text.map(ClipboardEvent::LocalText))
    }

    /// Alias retained for callers that describe this operation as a local
    /// clipboard read.
    pub async fn local_text(&mut self) -> Result<Option<ClipboardEvent>, String> {
        self.read_local_text().await
    }

    /// Stop listeners and release backend resources.
    pub async fn shutdown(&mut self) {
        if let Some(mut backend) = self.backend.take() {
            backend.shutdown().await;
        }
    }
}

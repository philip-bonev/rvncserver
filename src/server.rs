//! Application wiring: capture lifecycle and RFB listener.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use lamco_pipewire::PwStreamState;
use tokio::sync::mpsc;

use crate::capture::{CaptureConfig, CaptureSession};
use crate::cli::{AuthMode, Config};
use crate::clipboard::{
    ClipboardBackend, ClipboardEvent, ClipboardListenerEvent, ClipboardService,
    wayland::WaylandClipboard,
};
use crate::error::AppError;
use crate::framebuffer::{Frame, FrameStore};
use crate::input::ClientEvent;
use crate::rfb;

const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(20);
const FRAME_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(5);

/// Run the capture and RFB server until Ctrl+C.
pub async fn run(config: Config) -> Result<(), AppError> {
    let password_path = config.password_file.as_deref().ok_or_else(|| {
        AppError::Network(
            "authentication requires password_file in config.json or --password-file".to_string(),
        )
    })?;

    let authentication = match config.auth_mode {
        AuthMode::VeNCrypt => {
            let certificate = config.tls_cert.as_deref().ok_or_else(|| {
                AppError::Network("VeNCrypt authentication requires tls_cert".to_string())
            })?;
            let key = config.tls_key.as_deref().ok_or_else(|| {
                AppError::Network("VeNCrypt authentication requires tls_key".to_string())
            })?;
            rfb::load_authentication(certificate, key, password_path)
        }
        AuthMode::Vnc => rfb::load_vnc_authentication(password_path),
    }
    .map(Arc::new)
    .map_err(|error| AppError::Network(format!("failed to initialize authentication: {error}")))?;

    let address = SocketAddr::new(config.listen, config.port);
    let listener = TcpListener::bind(address)
        .map_err(|error| AppError::Network(format!("failed to bind {address}: {error}")))?;

    if config.auth_mode == AuthMode::Vnc {
        crate::timestamped_log!(
            "warning: classic VNC authentication uses weak DES and does not encrypt session traffic; do not use on untrusted networks"
        );
    }
    if config.enable_input || config.enable_clipboard {
        crate::timestamped_log!(
            "warning: any authenticated client can use enabled input/clipboard features"
        );
    }

    let capture_config = CaptureConfig {
        enable_input: config.enable_input,
        enable_clipboard: config.enable_clipboard,
        ..CaptureConfig::default()
    };
    let mut capture = CaptureSession::start(capture_config).await?;
    let (mut clipboard_service, mut clipboard_events) = if config.enable_clipboard {
        initialize_clipboard(&capture).await
    } else {
        (None, None)
    };
    let clipboard_enabled = clipboard_events.is_some();

    crate::timestamped_log!("capture: waiting for the first frame...");
    let first_frame = capture.wait_for_first_frame(FIRST_FRAME_TIMEOUT).await?;

    let width = u16::try_from(first_frame.width).map_err(|_| {
        AppError::Capture(format!(
            "captured frame width {} exceeds the RFB limit",
            first_frame.width
        ))
    })?;
    let height = u16::try_from(first_frame.height).map_err(|_| {
        AppError::Capture(format!(
            "captured frame height {} exceeds the RFB limit",
            first_frame.height
        ))
    })?;

    let store = Arc::new(FrameStore::new());
    store.publish(Arc::new(first_frame));

    crate::timestamped_log!("rfb: listening on {address}");
    let shutdown = Arc::new(AtomicBool::new(false));

    let mut has_remote_events = config.enable_input || clipboard_enabled;
    let (client_event_tx, mut client_event_rx) = mpsc::channel::<ClientEvent>(256);
    let (server_clipboard_tx, server_clipboard_rx) = mpsc::channel::<Vec<u8>>(4);

    let rfb_thread = rfb::spawn(
        listener,
        Arc::clone(&store),
        rfb::RfbConfig {
            width,
            height,
            name: "rvncserver".to_string(),
            input_enabled: config.enable_input,
            clipboard_enabled,
            encodings: config.encodings.clone(),
            authentication: Some(authentication),
        },
        Arc::clone(&shutdown),
        has_remote_events.then_some(client_event_tx),
        server_clipboard_rx,
    )
    .map_err(|error| AppError::Network(format!("failed to start RFB listener: {error}")))?;

    let notify = capture.frame_notify();
    let mut last_frame_error: Option<Instant> = None;

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        while let Some(video_frame) = capture.try_recv_frame() {
            if !store.has_clients() {
                continue;
            }

            match Frame::from_video_frame(&video_frame) {
                Ok(frame) => {
                    store.publish(Arc::new(frame));
                }
                Err(error) => {
                    let should_log = last_frame_error
                        .is_none_or(|last| last.elapsed() >= FRAME_ERROR_LOG_INTERVAL);
                    if should_log {
                        crate::timestamped_log!("capture: skipping unusable frame: {error}");
                        last_frame_error = Some(Instant::now());
                    }
                }
            }
        }

        for event in capture.drain_state_events() {
            match event.state {
                PwStreamState::Error(message) => {
                    crate::timestamped_log!(
                        "capture: stream {} reported an error: {message}",
                        event.stream_id
                    );
                }
                state => {
                    crate::timestamped_log!("capture: stream {} state: {state:?}", event.stream_id);
                }
            }
        }

        tokio::select! {
            _ = notify.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            event = client_event_rx.recv(), if has_remote_events => {
                if let Some(event) = event {
                    match event {
                        ClientEvent::Clipboard(data) => {
                            if let Some(service) = clipboard_service.as_mut() {
                                crate::timestamped_log!("clipboard: received remote text ({} bytes)", data.len());
                                let text = latin1_to_utf8(&data);
                                if let Err(error) = service.set_remote_text(text).await {
                                    crate::timestamped_log!("clipboard: could not publish remote text: {error}");
                                }
                            }
                        }
                        input_event => if let Err(error) = capture.handle_client_event(input_event).await {
                            crate::timestamped_log!("input: portal rejected client event: {error}");
                        }
                    }
                } else {
                    has_remote_events = false;
                }
            }
            event = recv_clipboard_event(&mut clipboard_events), if clipboard_enabled => {
                if let Some(event) = event {
                    match event {
                        ClipboardListenerEvent::TransferRequest { serial, mime_type } => {
                            if let Some(service) = clipboard_service.as_mut() {
                                if let Err(error) = service.provide_transfer(serial, mime_type).await {
                                    crate::timestamped_log!("clipboard: could not provide remote text: {error}");
                                }
                            }
                        }
                        ClipboardListenerEvent::LocalSelectionChanged(mime_types) => {
                            if !mime_types.iter().any(|mime| mime == "text/plain" || mime == "text/plain;charset=utf-8") {
                                continue;
                            }
                            if let Some(service) = clipboard_service.as_mut() {
                                match service.read_local_text().await {
                                    Ok(Some(ClipboardEvent::LocalText(text))) => {
                                        crate::timestamped_log!("clipboard: read local text ({} bytes)", text.len());
                                        let text = utf8_to_latin1(&text);
                                        if server_clipboard_tx.try_send(text).is_err() {
                                            crate::timestamped_log!("clipboard: client update queue is full; dropping update");
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(error) => crate::timestamped_log!("clipboard: could not read local text: {error}"),
                                }
                            }
                        }
                    }
                } else {
                    crate::timestamped_log!("clipboard: event listener ended");
                    clipboard_events = None;
                }
            }
            result = &mut ctrl_c => {
                if let Err(error) = result {
                    crate::timestamped_log!("server: could not listen for Ctrl+C: {error}");
                }
                break;
            }
        }
    }

    crate::timestamped_log!("server: shutting down...");
    shutdown.store(true, Ordering::Release);

    if rfb_thread.join().is_err() {
        crate::timestamped_log!("rfb: listener thread panicked");
    }

    capture.shutdown();
    if let Some(service) = clipboard_service.as_mut() {
        service.shutdown().await;
    }
    Ok(())
}

async fn recv_clipboard_event(
    receiver: &mut Option<mpsc::UnboundedReceiver<ClipboardListenerEvent>>,
) -> Option<ClipboardListenerEvent> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

async fn initialize_clipboard(
    capture: &CaptureSession,
) -> (
    Option<ClipboardService>,
    Option<mpsc::UnboundedReceiver<ClipboardListenerEvent>>,
) {
    if let Some(backend) = capture.portal_clipboard_backend() {
        match start_clipboard_backend(backend).await {
            Ok((service, events)) => {
                crate::timestamped_log!("clipboard: using XDG Desktop Portal backend");
                return (Some(service), Some(events));
            }
            Err(error) if is_permission_denial(&error) => {
                crate::timestamped_log!(
                    "clipboard: portal permission was denied; fallback will not bypass the user's choice: {error}"
                );
                return (None, None);
            }
            Err(error) => {
                crate::timestamped_log!(
                    "clipboard: portal backend unavailable ({error}); trying Wayland fallback"
                );
            }
        }
    } else {
        crate::timestamped_log!("clipboard: portal clipboard unavailable; trying Wayland fallback");
    }

    match WaylandClipboard::connect() {
        Ok(backend) => match start_clipboard_backend(backend).await {
            Ok((service, events)) => {
                crate::timestamped_log!("clipboard: using ext_data_control_v1 backend");
                (Some(service), Some(events))
            }
            Err(error) => {
                crate::timestamped_log!("clipboard: Wayland fallback unavailable: {error}");
                (None, None)
            }
        },
        Err(error) => {
            crate::timestamped_log!("clipboard: Wayland fallback unavailable: {error}");
            (None, None)
        }
    }
}

async fn start_clipboard_backend(
    backend: impl ClipboardBackend + 'static,
) -> Result<
    (
        ClipboardService,
        mpsc::UnboundedReceiver<ClipboardListenerEvent>,
    ),
    String,
> {
    let mut service = ClipboardService::initialize(backend).await?;
    match service.start_listeners().await {
        Ok(events) => Ok((service, events)),
        Err(error) => {
            service.shutdown().await;
            Err(error)
        }
    }
}

fn is_permission_denial(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("denied")
        || lower.contains("cancelled")
        || lower.contains("canceled")
        || lower.contains("permission")
        || lower.contains("not authorized")
}

fn latin1_to_utf8(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|byte| char::from(*byte))
        .collect::<String>()
        .into_bytes()
}

fn utf8_to_latin1(data: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(data)
        .chars()
        .map(|character| u8::try_from(u32::from(character)).unwrap_or(b'?'))
        .collect()
}

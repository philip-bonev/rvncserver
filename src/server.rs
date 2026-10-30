//! Application wiring: capture lifecycle and RFB listener.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use lamco_pipewire::PwStreamState;
use lamco_portal::PortalError;
use tokio::sync::mpsc;

use crate::capture::{CaptureConfig, CaptureSession};
use crate::cli::{AuthMode, Config};
use crate::clipboard::{
    ClipboardBackend, ClipboardEvent, ClipboardListenerEvent, ClipboardService,
    wayland::WaylandClipboard,
};
use crate::error::AppError;
use crate::framebuffer::{Frame, FrameDamage, FrameStore};
use crate::input::ClientEvent;
use crate::rfb;

const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(20);
const FRAME_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(5);
const CAPTURE_RESTART_ATTEMPTS: usize = 3;
const CAPTURE_RESTART_TIMEOUT: Duration = Duration::from_secs(30);
const CAPTURE_RESTART_DELAYS: [Duration; CAPTURE_RESTART_ATTEMPTS - 1] =
    [Duration::from_secs(1), Duration::from_secs(5)];

/// Run the capture and RFB server until Ctrl+C or SIGTERM.
pub async fn run(config: Config) -> Result<(), AppError> {
    // Install handlers before portal setup so stop requests during startup are
    // queued and handled through the same orderly cleanup path.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| {
        AppError::Network(format!("could not register SIGTERM handler: {error}"))
    })?;

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
        AuthMode::Vnc => match (config.tls_cert.as_deref(), config.tls_key.as_deref()) {
            (Some(certificate), Some(key)) => {
                rfb::load_vnc_tls_authentication(certificate, key, password_path)
            }
            (None, None) => rfb::load_vnc_authentication(password_path),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VNC mode requires tls_cert and tls_key together when enabling X509Vnc",
            )),
        },
        AuthMode::AppleDh => rfb::load_apple_dh_authentication(password_path),
    }
    .map(Arc::new)
    .map_err(|error| AppError::Network(format!("failed to initialize authentication: {error}")))?;

    let address = SocketAddr::new(config.listen, config.port);
    let listener = TcpListener::bind(address)
        .map_err(|error| AppError::Network(format!("failed to bind {address}: {error}")))?;

    if config.auth_mode == AuthMode::Vnc && config.tls_cert.is_none() {
        crate::timestamped_log!(
            "warning: classic VNC authentication uses weak DES and does not encrypt session traffic; do not use on untrusted networks"
        );
    }
    if config.auth_mode == AuthMode::Vnc && config.tls_cert.is_some() {
        crate::timestamped_log!(
            "security warning: VNC mode permits plaintext fallback (RFB 3.3 uses it; RFB 3.8 clients may select it); use vencrypt to require TLS"
        );
    }
    if config.auth_mode == AuthMode::AppleDh {
        crate::timestamped_log!(
            "warning: Apple DH authentication is Apple-specific and does not encrypt session traffic"
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
    let mut capture = CaptureSession::start(capture_config.clone()).await?;
    let (mut clipboard_service, mut clipboard_events) = if config.enable_clipboard {
        initialize_clipboard(&capture).await
    } else {
        (None, None)
    };
    let mut clipboard_enabled = clipboard_events.is_some();
    // The RFB capability is fixed for the listener's lifetime. Keep accepting
    // client clipboard messages even if the local clipboard service is later
    // lost, so client threads never block on a full event channel.
    let rfb_clipboard_enabled = clipboard_enabled;

    crate::timestamped_log!("capture: waiting for the first frame...");
    let first_capture = capture
        .wait_for_first_frame(FIRST_FRAME_TIMEOUT, config.enable_cursor)
        .await?;
    let first_frame = first_capture.frame;

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
    if config.enable_cursor {
        if let Some(cursor) = first_capture.cursor {
            store.publish_cursor(cursor);
        }
    }

    crate::timestamped_log!("rfb: listening on {address}");
    let shutdown = Arc::new(AtomicBool::new(false));

    let mut has_remote_events = config.enable_input || clipboard_enabled;
    let (client_event_tx, mut client_event_rx) = mpsc::channel::<ClientEvent>(256);
    let (server_clipboard_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(4);

    let rfb_thread = rfb::spawn(
        listener,
        Arc::clone(&store),
        rfb::RfbConfig {
            width,
            height,
            name: "rvncserver".to_string(),
            input_enabled: config.enable_input,
            cursor_enabled: config.enable_cursor,
            clipboard_enabled,
            max_clients: config.max_clients,
            encodings: config.encodings.clone(),
            authentication: Some(authentication),
        },
        Arc::clone(&shutdown),
        has_remote_events.then_some(client_event_tx),
        server_clipboard_tx.clone(),
    )
    .map_err(|error| AppError::Network(format!("failed to start RFB listener: {error}")))?;

    let mut notify = capture.frame_notify();
    let mut last_frame_error: Option<Instant> = None;
    // Startup transitions may still be queued after the first frame. Discard
    // them so they are not mistaken for a later capture loss.
    let _ = capture.drain_state_events();
    let mut capture_lost = false;

    loop {
        while let Some(video_frame) = capture.try_recv_frame() {
            if config.enable_cursor
                && let Some(cursor) = crate::cursor::CursorUpdate::from_video_frame(&video_frame)
            {
                store.publish_cursor(cursor);
            }
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
                PwStreamState::Streaming => {
                    crate::timestamped_log!("capture: stream {} is streaming", event.stream_id);
                    capture_lost = false;
                }
                PwStreamState::Error(message) => {
                    crate::timestamped_log!(
                        "capture: stream {} reported an error: {message}",
                        event.stream_id
                    );
                    capture_lost = true;
                }
                PwStreamState::Unconnected => {
                    crate::timestamped_log!("capture: stream {} disconnected", event.stream_id);
                    capture_lost = true;
                }
                state => {
                    crate::timestamped_log!("capture: stream {} state: {state:?}", event.stream_id);
                }
            }
        }

        if capture_lost {
            crate::timestamped_log!("capture: session lost; reinitializing capture");
            if let Some(service) = clipboard_service.as_mut() {
                service.shutdown().await;
            }
            clipboard_service = None;
            clipboard_events = None;

            capture.shutdown();
            drop(capture);

            let mut restarted = None;
            for attempt in 0..CAPTURE_RESTART_ATTEMPTS {
                if attempt > 0 {
                    tokio::time::sleep(CAPTURE_RESTART_DELAYS[attempt - 1]).await;
                }
                match tokio::time::timeout(
                    CAPTURE_RESTART_TIMEOUT,
                    CaptureSession::start(capture_config.clone()),
                )
                .await
                {
                    Ok(Ok(session)) => {
                        restarted = Some(session);
                        break;
                    }
                    Ok(Err(error)) => {
                        crate::timestamped_log!(
                            "capture: reinitialization attempt {} failed: {error}",
                            attempt + 1
                        );
                        if matches!(&error, AppError::Portal(PortalError::PermissionDenied)) {
                            crate::timestamped_log!(
                                "capture: portal permission was denied; not retrying"
                            );
                            break;
                        }
                    }
                    Err(_) => {
                        crate::timestamped_log!(
                            "capture: reinitialization attempt {} timed out after {} seconds",
                            attempt + 1,
                            CAPTURE_RESTART_TIMEOUT.as_secs()
                        );
                        // A timed-out request may still be waiting for local
                        // approval; do not stack another prompt on top of it.
                        break;
                    }
                }
            }
            let Some(mut session) = restarted else {
                return Err(AppError::Capture(
                    "capture session could not be reinitialized".to_string(),
                ));
            };

            let first = match session
                .wait_for_first_frame(FIRST_FRAME_TIMEOUT, config.enable_cursor)
                .await
            {
                Ok(first) => first,
                Err(error) => {
                    session.shutdown();
                    return Err(error);
                }
            };
            // Discard the restarted stream's startup transitions for the same
            // reason as at initial startup.
            let _ = session.drain_state_events();
            if first.frame.width != u32::from(width) || first.frame.height != u32::from(height) {
                crate::timestamped_log!(
                    "capture: restarted stream is {}x{}, but the RFB session is fixed at {}x{}; exiting for supervisor restart",
                    first.frame.width,
                    first.frame.height,
                    width,
                    height
                );
                session.shutdown();
                return Err(AppError::Capture(
                    "capture stream dimensions changed after reinitialization".to_string(),
                ));
            }
            let mut first_frame = first.frame;
            // The restarted capture has no continuity with the old stream.
            // Force a full refresh so every client replaces its framebuffer.
            first_frame.damage = FrameDamage::Full;
            store.publish(Arc::new(first_frame));
            if config.enable_cursor
                && let Some(cursor) = first.cursor
            {
                store.publish_cursor(cursor);
            }

            if config.enable_clipboard {
                let (service, events) = initialize_clipboard(&session).await;
                clipboard_service = service;
                clipboard_events = events;
            }
            has_remote_events = config.enable_input || rfb_clipboard_enabled;
            clipboard_enabled = clipboard_events.is_some();
            // Input and clipboard events queued while capture was down refer to
            // the old session; discard them instead of applying them late.
            while client_event_rx.try_recv().is_ok() {}
            notify = session.frame_notify();
            capture = session;
            capture_lost = false;
            last_frame_error = None;
            crate::timestamped_log!("capture: session reinitialized");
            continue;
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
                                        if store.has_clients() && server_clipboard_tx.send(text).is_err() {
                                            crate::timestamped_log!("clipboard: no client is receiving updates; dropping update");
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
            _ = terminate.recv() => {
                crate::timestamped_log!("server: received SIGTERM");
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

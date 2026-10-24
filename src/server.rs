//! Application wiring: capture lifecycle and RFB listener.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use lamco_pipewire::PwStreamState;
use tokio::sync::mpsc;

use crate::capture::{CaptureConfig, CaptureSession};
use crate::cli::{AuthMode, Config};
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
        eprintln!(
            "warning: classic VNC authentication uses weak DES and does not encrypt session traffic; do not use on untrusted networks"
        );
    }
    if config.enable_input || config.enable_clipboard {
        eprintln!("warning: any authenticated client can use enabled input/clipboard features");
    }

    let capture_config = CaptureConfig {
        enable_input: config.enable_input,
        enable_clipboard: config.enable_clipboard,
        ..CaptureConfig::default()
    };
    let mut capture = CaptureSession::start(capture_config).await?;

    eprintln!("capture: waiting for the first frame...");
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

    eprintln!("rfb: listening on {address}");
    let shutdown = Arc::new(AtomicBool::new(false));

    let mut has_remote_events = config.enable_input || config.enable_clipboard;
    let (client_event_tx, mut client_event_rx) = mpsc::channel::<ClientEvent>(256);
    let (server_clipboard_tx, server_clipboard_rx) = mpsc::channel::<Vec<u8>>(4);
    let (mut selection_transfer_rx, mut clipboard_owner_rx) = if config.enable_clipboard {
        let (transfer, owner) = capture.start_clipboard_listeners().await?;
        (Some(transfer), Some(owner))
    } else {
        (None, None)
    };

    let rfb_thread = rfb::spawn(
        listener,
        Arc::clone(&store),
        rfb::RfbConfig {
            width,
            height,
            name: "rvncserver".to_string(),
            input_enabled: config.enable_input,
            clipboard_enabled: config.enable_clipboard,
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
                        eprintln!("capture: skipping unusable frame: {error}");
                        last_frame_error = Some(Instant::now());
                    }
                }
            }
        }

        for event in capture.drain_state_events() {
            match event.state {
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

        tokio::select! {
            _ = notify.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            event = client_event_rx.recv(), if has_remote_events => {
                if let Some(event) = event {
                    if let Err(error) = capture.handle_client_event(event).await {
                        eprintln!("input: portal rejected client event: {error}");
                    }
                } else {
                    has_remote_events = false;
                }
            }
            transfer = recv_optional(&mut selection_transfer_rx), if config.enable_clipboard => {
                if let Some(transfer) = transfer {
                    if let Err(error) = capture.handle_selection_transfer(transfer).await {
                        eprintln!("clipboard: could not provide remote text: {error}");
                    }
                } else {
                    eprintln!("clipboard: transfer listener ended");
                    selection_transfer_rx = None;
                }
            }
            owner = recv_optional(&mut clipboard_owner_rx), if config.enable_clipboard => {
                if let Some(mime_types) = owner {
                    match capture.read_local_clipboard(&mime_types).await {
                        Ok(Some(text)) => {
                            if server_clipboard_tx.try_send(text).is_err() {
                                eprintln!("clipboard: client update queue is full; dropping update");
                            }
                        }
                        Ok(None) => {}
                        Err(error) => eprintln!("clipboard: could not read local text: {error}"),
                    }
                } else {
                    eprintln!("clipboard: owner-change listener ended");
                    clipboard_owner_rx = None;
                }
            }
            result = &mut ctrl_c => {
                if let Err(error) = result {
                    eprintln!("server: could not listen for Ctrl+C: {error}");
                }
                break;
            }
        }
    }

    eprintln!("server: shutting down...");
    shutdown.store(true, Ordering::Release);

    if rfb_thread.join().is_err() {
        eprintln!("rfb: listener thread panicked");
    }

    capture.shutdown();
    Ok(())
}

async fn recv_optional<T>(receiver: &mut Option<mpsc::UnboundedReceiver<T>>) -> Option<T> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

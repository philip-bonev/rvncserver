//! Application wiring: capture lifecycle and RFB listener.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use lamco_pipewire::PwStreamState;

use crate::capture::{CaptureConfig, CaptureSession};
use crate::cli::Config;
use crate::error::AppError;
use crate::framebuffer::{Frame, FrameStore};
use crate::rfb;

const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(20);
const FRAME_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(5);

/// Run the capture and RFB server until Ctrl+C.
pub async fn run(config: Config) -> Result<(), AppError> {
    let address = SocketAddr::new(config.listen, config.port);
    let listener = TcpListener::bind(address)
        .map_err(|error| AppError::Network(format!("failed to bind {address}: {error}")))?;

    if !config.listen.is_loopback() {
        eprintln!(
            "warning: listening on a non-loopback address; VNC traffic is unencrypted and unauthenticated"
        );
    }

    let mut capture = CaptureSession::start(CaptureConfig::default()).await?;

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
    let rfb_thread = rfb::spawn(
        listener,
        Arc::clone(&store),
        width,
        height,
        "rvncserver".to_string(),
        Arc::clone(&shutdown),
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

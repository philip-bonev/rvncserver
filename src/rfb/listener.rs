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

//! TCP listener and per-client RFB worker threads.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::framebuffer::FrameStore;
use crate::input::ClientEvent;

use super::{
    AuthLimiter, READ_POLL_INTERVAL, RfbConfig, WRITE_TIMEOUT, handle_client, is_normal_disconnect,
};

/// Start the RFB listener thread.
///
/// The listener is put into non-blocking mode so shutdown can be observed
/// without needing a separate wake-up connection.
pub fn spawn(
    listener: TcpListener,
    store: Arc<FrameStore>,
    config: RfbConfig,
    shutdown: Arc<AtomicBool>,
    input_tx: Option<tokio::sync::mpsc::Sender<ClientEvent>>,
    clipboard_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
) -> io::Result<JoinHandle<()>> {
    listener.set_nonblocking(true)?;

    let config = Arc::new(config);
    thread::Builder::new()
        .name("rfb-listener".to_string())
        .spawn(move || run_listener(listener, store, config, shutdown, input_tx, clipboard_tx))
}

/// Keeps the listener's active-client count accurate even if a worker panics.
struct ActiveClientGuard(Arc<AtomicUsize>);

impl Drop for ActiveClientGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Keeps the frame store's client count accurate even if a worker panics.
struct ClientConnectionGuard<'a>(&'a FrameStore);

impl Drop for ClientConnectionGuard<'_> {
    fn drop(&mut self) {
        self.0.client_disconnected();
    }
}

/// Warn when a connecting client would start from a stale framebuffer.
const STALE_FRAMEBUFFER_WARNING: Duration = Duration::from_secs(5);

fn run_listener(
    listener: TcpListener,
    store: Arc<FrameStore>,
    config: Arc<RfbConfig>,
    shutdown: Arc<AtomicBool>,
    input_tx: Option<tokio::sync::mpsc::Sender<ClientEvent>>,
    clipboard_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
) {
    let active_clients = Arc::new(AtomicUsize::new(0));
    let auth_limiter = Arc::new(AuthLimiter::new());
    let mut workers = Vec::new();

    while !shutdown.load(Ordering::Acquire) {
        reap_finished_workers(&mut workers);
        match listener.accept() {
            Ok((stream, address)) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                if let Err(error) = configure_stream(&stream) {
                    crate::timestamped_log!("rfb: could not configure client socket: {error}");
                    continue;
                }

                let current = active_clients.fetch_add(1, Ordering::AcqRel);
                if current >= config.max_clients {
                    active_clients.fetch_sub(1, Ordering::AcqRel);
                    crate::timestamped_log!(
                        "rfb: rejecting client from {address}: {} active clients (max {})",
                        current,
                        config.max_clients
                    );
                    crate::rfb::reject_client(
                        stream,
                        address,
                        "too many connected clients",
                        &shutdown,
                    );
                    continue;
                }
                let guard = ActiveClientGuard(Arc::clone(&active_clients));
                let (handshake_tx, handshake_watchdog) =
                    match spawn_handshake_watchdog(&stream, address, config.handshake_timeout) {
                        Ok((done_tx, handle)) => (Some(done_tx), Some(handle)),
                        Err(error) => {
                            crate::timestamped_log!(
                                "rfb: could not start handshake timeout: {error}"
                            );
                            (None, None)
                        }
                    };

                let store = Arc::clone(&store);
                let config = Arc::clone(&config);
                let shutdown = Arc::clone(&shutdown);
                let auth_limiter = Arc::clone(&auth_limiter);
                let input_tx = input_tx.clone();
                let mut clipboard_rx = clipboard_tx.subscribe();
                let worker =
                    thread::Builder::new()
                        .name("rfb-client".to_string())
                        .spawn(move || {
                            let _guard = guard;
                            crate::timestamped_log!("rfb: client connected from {address}");
                            store.client_connected();
                            if let Some(age) = store.latest_age()
                                && age >= STALE_FRAMEBUFFER_WARNING
                            {
                                crate::timestamped_log!(
                                    "rfb: newest framebuffer is {}s old; the client starts with stale content until capture delivers a new frame",
                                    age.as_secs()
                                );
                            }
                            let result = {
                                let _connection_guard = ClientConnectionGuard(store.as_ref());
                                handle_client(
                                    stream,
                                    &store,
                                    &config,
                                    &shutdown,
                                    input_tx.as_ref(),
                                    &mut clipboard_rx,
                                    handshake_tx.as_ref(),
                                    &auth_limiter,
                                )
                            };
                            drop(handshake_tx);
                            if let Some(watchdog) = handshake_watchdog {
                                let _ = watchdog.join();
                            }

                            match result {
                                Ok(()) => crate::timestamped_log!("rfb: client disconnected"),
                                Err(error) if is_normal_disconnect(&error) => {
                                    crate::timestamped_log!("rfb: client disconnected: {error}");
                                }
                                Err(error) => crate::timestamped_log!("rfb: client error: {error}"),
                            }
                        });
                match worker {
                    Ok(handle) => workers.push(handle),
                    Err(error) => {
                        crate::timestamped_log!("rfb: could not start client thread: {error}");
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                crate::timestamped_log!("rfb: accept failed: {error}");
                break;
            }
        }
    }

    for worker in workers {
        if worker.join().is_err() {
            crate::timestamped_log!("rfb: client thread panicked");
        }
    }
}

/// Close a connection that has not completed authentication and initialization
/// within `timeout`. The returned sender reports completion to the watchdog.
fn spawn_handshake_watchdog(
    stream: &TcpStream,
    address: std::net::SocketAddr,
    timeout: Duration,
) -> io::Result<(std::sync::mpsc::Sender<()>, JoinHandle<()>)> {
    let handshake_stream = stream.try_clone()?;
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let handle = thread::Builder::new()
        .name("rfb-handshake".to_string())
        .spawn(move || {
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = done_rx.recv_timeout(timeout) {
                let _ = handshake_stream.shutdown(std::net::Shutdown::Both);
                crate::timestamped_log!(
                    "rfb: closing client from {address} after handshake timeout"
                );
            }
        })?;
    Ok((done_tx, handle))
}

/// Join client threads that have already exited so the handle list stays small.
fn reap_finished_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            if worker.join().is_err() {
                crate::timestamped_log!("rfb: client thread panicked");
            }
        } else {
            index += 1;
        }
    }
}

pub(super) fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(READ_POLL_INTERVAL))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.set_nodelay(true)?;
    if let Err(error) = configure_tcp_keepalive(stream) {
        crate::timestamped_log!("rfb: could not enable TCP keepalive: {error}");
    }
    Ok(())
}

/// Detect peers that disappeared without closing the TCP connection. This is
/// best-effort so restricted environments can still serve clients.
#[cfg(target_os = "linux")]
fn configure_tcp_keepalive(stream: &TcpStream) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    const IDLE_SECONDS: libc::c_int = 60;
    const INTERVAL_SECONDS: libc::c_int = 10;
    const PROBES: libc::c_int = 3;

    fn set_option(
        fd: libc::c_int,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        // SAFETY: `fd` is a live socket owned by the caller, and `value` points
        // to an initialized c_int with the size passed to setsockopt.
        let result = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    let fd = stream.as_raw_fd();
    set_option(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    set_option(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, IDLE_SECONDS)?;
    set_option(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, INTERVAL_SECONDS)?;
    set_option(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, PROBES)
}

#[cfg(not(target_os = "linux"))]
fn configure_tcp_keepalive(_stream: &TcpStream) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framebuffer::Frame;
    use crate::rfb::RFB_VERSION;
    use crate::rfb::test_rfb_config;
    use std::io::{Read, Write};
    use std::thread;
    use std::time::Instant;

    #[test]
    fn listener_serves_multiple_clients_concurrently() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(FrameStore::new());
        store.publish(Arc::new(Frame::new(2, 2, vec![0; 16]).unwrap()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (clipboard_tx, _) = tokio::sync::broadcast::channel(1);
        let listener_thread = spawn(
            listener,
            Arc::clone(&store),
            test_rfb_config(2),
            Arc::clone(&shutdown),
            None,
            clipboard_tx,
        )
        .unwrap();

        let mut first = TcpStream::connect(address).unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut version = [0u8; 12];
        first.read_exact(&mut version).unwrap();
        assert_eq!(&version, RFB_VERSION);

        // The first client remains connected. A serialized listener would not
        // send this version until that client disconnected.
        let mut second = TcpStream::connect(address).unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut second_version = [0u8; 12];
        second.read_exact(&mut second_version).unwrap();
        assert_eq!(&second_version, RFB_VERSION);

        drop(first);
        drop(second);
        shutdown.store(true, Ordering::Release);
        listener_thread.join().unwrap();
    }

    #[test]
    fn listener_rejects_clients_above_the_configured_limit() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(FrameStore::new());
        store.publish(Arc::new(Frame::new(2, 2, vec![0; 16]).unwrap()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (clipboard_tx, _) = tokio::sync::broadcast::channel(1);
        let listener_thread = spawn(
            listener,
            Arc::clone(&store),
            test_rfb_config(1),
            Arc::clone(&shutdown),
            None,
            clipboard_tx,
        )
        .unwrap();

        let first = TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !store.has_clients() {
            assert!(Instant::now() < deadline, "first client was not accepted");
            thread::sleep(Duration::from_millis(10));
        }

        let mut second = TcpStream::connect(address).unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // The rejection follows the protocol: version exchange first, then a
        // failure security negotiation with a human-readable reason.
        let mut version = [0u8; 12];
        second.read_exact(&mut version).unwrap();
        assert_eq!(&version, RFB_VERSION);
        second.write_all(RFB_VERSION).unwrap();
        let mut security_types = [0u8; 1];
        second.read_exact(&mut security_types).unwrap();
        assert_eq!(security_types[0], 0, "zero security types means failure");
        let mut length = [0u8; 4];
        second.read_exact(&mut length).unwrap();
        let mut reason = vec![0u8; u32::from_be_bytes(length) as usize];
        second.read_exact(&mut reason).unwrap();
        assert!(
            String::from_utf8_lossy(&reason).contains("too many"),
            "unexpected reason: {}",
            String::from_utf8_lossy(&reason)
        );

        drop(first);
        shutdown.store(true, Ordering::Release);
        listener_thread.join().unwrap();
    }

    #[test]
    fn handshake_watchdog_closes_stalled_connections() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (server_stream, peer) = listener.accept().unwrap();
        let (_done_tx, watchdog) =
            spawn_handshake_watchdog(&server_stream, peer, Duration::from_millis(100)).unwrap();
        watchdog.join().unwrap();

        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0u8; 1];
        match client.read(&mut byte) {
            Ok(0) => {}
            Ok(read) => panic!("stalled client unexpectedly received {read} bytes"),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ),
                "unexpected timeout error: {error}"
            ),
        }
    }

    #[test]
    fn handshake_watchdog_stops_after_initialization() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server_stream, peer) = listener.accept().unwrap();
        let (done_tx, watchdog) =
            spawn_handshake_watchdog(&server_stream, peer, Duration::from_secs(5)).unwrap();
        done_tx.send(()).unwrap();
        watchdog.join().unwrap();

        // Completion must leave the connection open for normal RFB traffic.
        server_stream.write_all(&[42]).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [42]);
    }

    #[test]
    fn connection_guard_releases_frame_store_client_on_drop() {
        let store = FrameStore::new();
        assert!(!store.has_clients());
        store.client_connected();
        assert!(store.has_clients());
        drop(ClientConnectionGuard(&store));
        assert!(!store.has_clients());
    }
}

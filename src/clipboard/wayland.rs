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

//! Wayland `ext_data_control_v1` clipboard backend.
//!
//! A dedicated Wayland connection is driven on a worker thread. Clipboard
//! payloads travel through protocol-provided file descriptors, never through
//! the event loop itself.

use std::collections::HashMap;
use std::ffi::CString;
use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tokio::sync::mpsc;
use wayrs_client::core::ObjectId;
use wayrs_client::global::GlobalExt;
use wayrs_client::object::Proxy;
use wayrs_client::protocol::wl_seat::WlSeat;
use wayrs_client::{Connection, EventCtx, IoMode};
use wayrs_protocols::ext_data_control_v1::ext_data_control_device_v1;
use wayrs_protocols::ext_data_control_v1::ext_data_control_offer_v1;
use wayrs_protocols::ext_data_control_v1::ext_data_control_source_v1;
use wayrs_protocols::ext_data_control_v1::{
    ExtDataControlDeviceV1, ExtDataControlManagerV1, ExtDataControlOfferV1, ExtDataControlSourceV1,
};

use super::{ClipboardBackend, ClipboardListenerEvent, ListenerFuture, TextFuture};

const TEXT_MIME_TYPES: [&str; 2] = ["text/plain;charset=utf-8", "text/plain"];
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

enum Command {
    SetText(Vec<u8>),
    Stop,
}

/// State of the visible selection, mutated under a single lock so content and
/// generation can never change independently of each other.
#[derive(Default)]
struct SelectionState {
    /// Text currently visible to local clipboard readers.
    current: Option<Vec<u8>>,
    /// Text most recently published to the compositor by this backend. Used
    /// to recognize the echo of our own selection so it is not sent back to
    /// the remote client as a "local" change.
    published: Option<Vec<u8>>,
    /// Incremented whenever the visible selection changes so a slower
    /// transfer that finishes late cannot overwrite newer content.
    generation: u64,
}

struct SharedText {
    state: Mutex<SelectionState>,
}

impl SharedText {
    fn new() -> Self {
        Self {
            state: Mutex::new(SelectionState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SelectionState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Clipboard backend using the compositor's ext-data-control-v1 global.
pub struct WaylandClipboard {
    command_tx: std_mpsc::Sender<Command>,
    /// Wake-up pipe write end; a byte here gets the worker out of its poll.
    wake_tx: UnixStream,
    event_rx: Option<mpsc::UnboundedReceiver<ClipboardListenerEvent>>,
    text: Arc<SharedText>,
    worker: Option<JoinHandle<()>>,
}

struct Offer {
    proxy: ExtDataControlOfferV1,
    mime_types: Vec<CString>,
}

struct State {
    manager: ExtDataControlManagerV1,
    device: ExtDataControlDeviceV1,
    offers: HashMap<ObjectId, Offer>,
    selected_offer: Option<ObjectId>,
    selected_primary_offer: Option<ObjectId>,
    /// Cleared by the protocol's `finished` event; the device must then not be
    /// used for further requests.
    device_alive: bool,
    text: Arc<SharedText>,
    events: mpsc::UnboundedSender<ClipboardListenerEvent>,
}

/// Bound on concurrent clipboard-send threads: a paste storm from a local
/// application must not spawn unbounded threads.
static ACTIVE_SENDS: AtomicUsize = AtomicUsize::new(0);
const MAX_CONCURRENT_SENDS: usize = 16;

fn acquire_send_slot() -> bool {
    let previous = ACTIVE_SENDS.fetch_add(1, Ordering::SeqCst);
    if previous < MAX_CONCURRENT_SENDS {
        return true;
    }
    ACTIVE_SENDS.fetch_sub(1, Ordering::SeqCst);
    false
}

struct SendSlotGuard;

impl Drop for SendSlotGuard {
    fn drop(&mut self) {
        ACTIVE_SENDS.fetch_sub(1, Ordering::SeqCst);
    }
}

impl WaylandClipboard {
    /// Connect to Wayland, bind a seat and the ext-data-control-v1 manager,
    /// and start its private protocol event-loop worker.
    pub fn connect() -> Result<Self, String> {
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        let (command_tx, command_rx) = std_mpsc::channel();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (wake_tx, wake_rx) = UnixStream::pair()
            .map_err(|error| format!("could not create a wake-up pipe: {error}"))?;
        // Non-blocking on both ends: wake-ups are advisory and must never
        // stall a sender or the worker's drain loop.
        wake_tx
            .set_nonblocking(true)
            .map_err(|error| format!("could not configure the wake-up pipe: {error}"))?;
        wake_rx
            .set_nonblocking(true)
            .map_err(|error| format!("could not configure the wake-up pipe: {error}"))?;
        let text = Arc::new(SharedText::new());
        let worker_text = Arc::clone(&text);
        let worker_events = events_tx.clone();
        let worker = thread::Builder::new()
            .name("rvnc-wayland-clipboard".into())
            .spawn(move || {
                let result = worker_init(worker_text, worker_events);
                match result {
                    Ok(mut connection_state) => {
                        let _ = ready_tx.send(Ok(()));
                        worker_loop(&mut connection_state, command_rx, wake_rx);
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                    }
                }
            })
            .map_err(|error| format!("could not start Wayland clipboard worker: {error}"))?;

        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                command_tx,
                wake_tx,
                event_rx: Some(events_rx),
                text,
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(error) => {
                // Never join on the timeout path: a wedged compositor can
                // leave the worker blocked in a Wayland roundtrip forever.
                // Dropping the command sender lets the worker exit as soon as
                // it becomes responsive again.
                drop(command_tx);
                Err(format!("timed out initializing Wayland clipboard: {error}"))
            }
        }
    }

    /// Queue a worker command and wake the worker's poll so it is handled
    /// promptly instead of waiting for the next protocol event.
    fn send_command(&self, command: Command) -> Result<(), String> {
        self.command_tx
            .send(command)
            .map_err(|_| "Wayland clipboard worker has stopped".to_string())?;
        // The write is advisory and the pipe is non-blocking; a full pipe
        // already means the worker has wake-ups pending.
        let _ = (&self.wake_tx).write_all(&[1]);
        Ok(())
    }
}

impl ClipboardBackend for WaylandClipboard {
    fn start_listeners<'a>(&'a mut self) -> ListenerFuture<'a> {
        Box::pin(async move {
            self.event_rx
                .take()
                .ok_or_else(|| "Wayland clipboard listeners already started".into())
        })
    }

    fn read_text<'a>(&'a mut self) -> TextFuture<'a> {
        Box::pin(async move {
            let text = self.text.lock().current.clone();
            Ok(text)
        })
    }

    fn write_text<'a>(
        &'a mut self,
        text: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let text = text
                .into_iter()
                .take(MAX_CLIPBOARD_BYTES)
                .collect::<Vec<_>>();
            // The shared state is updated by the worker when the selection is
            // actually published; caching here would report text that a failed
            // send never made visible.
            self.send_command(Command::SetText(text))
        })
    }

    fn provide_transfer<'a>(
        &'a mut self,
        _serial: u32,
        _mime_type: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let _ = self.send_command(Command::Stop);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        })
    }
}

fn worker_init(
    text: Arc<SharedText>,
    events: mpsc::UnboundedSender<ClipboardListenerEvent>,
) -> Result<(Connection<State>, State), String> {
    let mut connection = Connection::<State>::connect()
        .map_err(|error| format!("could not connect to Wayland: {error}"))?;
    connection
        .blocking_roundtrip()
        .map_err(|error| format!("Wayland registry roundtrip failed: {error}"))?;

    let seat_global = connection
        .globals()
        .iter()
        .find(|global| global.is::<WlSeat>())
        .cloned()
        .ok_or_else(|| "Wayland compositor did not advertise wl_seat".to_string())?;
    let manager_global = connection
        .globals()
        .iter()
        .find(|global| global.is::<ExtDataControlManagerV1>())
        .cloned()
        .ok_or_else(|| "compositor does not advertise ext_data_control_v1".to_string())?;

    let seat = seat_global
        .bind::<WlSeat, State>(&mut connection, 1..=9)
        .map_err(|error| format!("could not bind Wayland seat: {error}"))?;
    let manager = manager_global
        .bind::<ExtDataControlManagerV1, State>(&mut connection, 1..=1)
        .map_err(|error| format!("could not bind ext_data_control_v1: {error}"))?;
    let device = manager.get_data_device(&mut connection, seat);
    let state = State {
        manager,
        device,
        offers: HashMap::new(),
        selected_offer: None,
        selected_primary_offer: None,
        device_alive: true,
        text,
        events,
    };
    // Install the data-device callback after creation, keeping all event-owned
    // state on the protocol worker.
    connection.set_callback_for(state.device, data_device_callback);
    connection
        .blocking_roundtrip()
        .map_err(|error| format!("Wayland data-device initialization failed: {error}"))?;
    Ok((connection, state))
}

fn worker_loop(
    connection_state: &mut (Connection<State>, State),
    commands: std_mpsc::Receiver<Command>,
    wake_rx: UnixStream,
) {
    let (connection, state) = connection_state;
    let mut wake_buffer = [0u8; 64];
    loop {
        loop {
            match commands.try_recv() {
                Ok(Command::SetText(text)) => publish_text(connection, state, text),
                Ok(Command::Stop) | Err(std_mpsc::TryRecvError::Disconnected) => return,
                Err(std_mpsc::TryRecvError::Empty) => break,
            }
        }
        if let Err(error) = connection.recv_events(IoMode::NonBlocking) {
            if error.kind() != ErrorKind::WouldBlock {
                crate::timestamped_log!("clipboard: Wayland event loop stopped: {error}");
                return;
            }
        }
        connection.dispatch_events(state);
        match connection.flush(IoMode::NonBlocking) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                // A full socket buffer must be retried promptly; the poll
                // below only waits for readable events.
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => {
                crate::timestamped_log!("clipboard: Wayland request flush failed: {error}");
                return;
            }
        }

        // Block until the Wayland socket or the command wake-up pipe becomes
        // readable instead of polling on a timer.
        wait_for_work(connection.as_raw_fd(), &wake_rx);
        drain_wake_ups(&wake_rx, &mut wake_buffer);
    }
}

/// Block until the Wayland socket or the command wake-up pipe is readable.
///
/// The timeout is only a safety net for missed wake-ups; it is not a poll
/// interval.
fn wait_for_work(wayland_fd: std::os::fd::RawFd, wake_rx: &UnixStream) {
    let mut descriptors = [
        libc::pollfd {
            fd: wayland_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_rx.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: descriptors reference live file descriptors owned by the
        // caller; poll reports failures through its return value.
        let ready = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                1000,
            )
        };
        if ready >= 0 {
            return;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

/// Consume pending wake-up bytes. End-of-file simply ends the drain; the
/// command check at the top of the loop shuts the worker down.
fn drain_wake_ups(wake_rx: &UnixStream, buffer: &mut [u8; 64]) {
    // `Read` is implemented for `&UnixStream`; keep a mutable handle to it.
    let mut handle = wake_rx;
    loop {
        match handle.read(buffer) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

fn publish_text(connection: &mut Connection<State>, state: &mut State, text: Vec<u8>) {
    if !state.device_alive {
        crate::timestamped_log!("clipboard: Wayland data device is gone; dropping published text");
        return;
    }
    crate::timestamped_log!(
        "clipboard: publishing {} bytes through ext_data_control_v1",
        text.len()
    );
    let source = state.manager.create_data_source(connection);
    for mime_type in TEXT_MIME_TYPES {
        if let Ok(mime_type) = CString::new(mime_type) {
            source.offer(connection, mime_type);
        }
    }
    // Each source serves exactly the text it was created for. Reading shared
    // state at paste time would serve whatever happens to be current by then.
    let published_text = text.clone();
    connection.set_callback_for(
        source,
        move |ctx: EventCtx<'_, State, ExtDataControlSourceV1>| match ctx.event {
            ext_data_control_source_v1::Event::Send(args) => {
                let fd = args.fd;
                if !acquire_send_slot() {
                    crate::timestamped_log!(
                        "clipboard: too many concurrent transfers; dropping one"
                    );
                    return;
                }
                let text = published_text.clone();
                let _ = thread::Builder::new()
                    .name("rvnc-clipboard-send".into())
                    .spawn(move || {
                        let _guard = SendSlotGuard;
                        write_fd(fd, text)
                    });
            }
            ext_data_control_source_v1::Event::Cancelled => {
                ctx.proxy.destroy(ctx.conn);
            }
            _ => {}
        },
    );
    state.device.set_selection(connection, Some(source));
    {
        let mut selection = state.text.lock();
        selection.current = Some(text.clone());
        selection.published = Some(text);
        selection.generation += 1;
    }
}

fn data_device_callback(ctx: EventCtx<'_, State, ExtDataControlDeviceV1>) {
    match ctx.event {
        ext_data_control_device_v1::Event::DataOffer(offer) => {
            let offer_id = offer.id();
            ctx.state.offers.insert(
                offer_id,
                Offer {
                    proxy: offer,
                    mime_types: Vec::new(),
                },
            );
            ctx.conn.set_callback_for(offer, offer_callback);
        }
        ext_data_control_device_v1::Event::Selection(Some(id)) => {
            if let Some(old_id) = ctx.state.selected_offer.replace(id) {
                if old_id != id {
                    if let Some(old_offer) = ctx.state.offers.remove(&old_id) {
                        old_offer.proxy.destroy(ctx.conn);
                    }
                }
            }
            // In-flight transfers for older selections must not overwrite the
            // content that arrives after this event.
            let generation = {
                let mut selection = ctx.state.text.lock();
                selection.generation += 1;
                selection.generation
            };
            let Some(offer) = ctx.state.offers.get(&id) else {
                return;
            };
            let Some(mime_type) = offer
                .mime_types
                .iter()
                .find(|mime| {
                    let mime = mime.to_string_lossy();
                    TEXT_MIME_TYPES.contains(&mime.as_ref())
                })
                .cloned()
            else {
                let mut selection = ctx.state.text.lock();
                selection.current = None;
                selection.published = None;
                return;
            };
            let mime = mime_type.to_string_lossy().into_owned();
            crate::timestamped_log!("clipboard: receiving local Wayland selection as {mime}");
            let proxy = offer.proxy;
            let event_tx = ctx.state.events.clone();
            let text = Arc::clone(&ctx.state.text);
            let Ok((reader, writer)) = UnixStream::pair() else {
                crate::timestamped_log!(
                    "clipboard: could not create a transfer socket; selection dropped"
                );
                let mut selection = text.lock();
                selection.current = None;
                selection.published = None;
                return;
            };
            let writer: OwnedFd = writer.into();
            proxy.receive(ctx.conn, mime_type, writer);
            let _ = thread::Builder::new()
                .name("rvnc-clipboard-receive".into())
                .spawn(move || {
                    let bytes = read_fd(reader);
                    let echoed = {
                        let mut selection = text.lock();
                        if selection.generation != generation {
                            return;
                        }
                        // The compositor also reports the selection we
                        // published ourselves; forwarding it would echo the
                        // remote client's own clipboard back at it.
                        let echoed = selection.published.as_deref() == Some(bytes.as_slice());
                        selection.current = Some(bytes);
                        if !echoed {
                            // The selection is genuinely local-owned again.
                            selection.published = None;
                        }
                        echoed
                    };
                    if echoed {
                        return;
                    }
                    let _ =
                        event_tx.send(ClipboardListenerEvent::LocalSelectionChanged(vec![mime]));
                });
        }
        ext_data_control_device_v1::Event::Selection(None) => {
            if let Some(old_id) = ctx.state.selected_offer.take() {
                if let Some(old_offer) = ctx.state.offers.remove(&old_id) {
                    old_offer.proxy.destroy(ctx.conn);
                }
            }
            let mut selection = ctx.state.text.lock();
            selection.generation += 1;
            selection.current = None;
            selection.published = None;
        }
        ext_data_control_device_v1::Event::PrimarySelection(Some(id)) => {
            // Primary-selection offers are unused, but the protocol requires
            // destroying each offer once it is superseded; without this every
            // mouse-selection change leaks an offer object.
            if let Some(old_id) = ctx.state.selected_primary_offer.replace(id) {
                if old_id != id {
                    if let Some(old_offer) = ctx.state.offers.remove(&old_id) {
                        old_offer.proxy.destroy(ctx.conn);
                    }
                }
            }
        }
        ext_data_control_device_v1::Event::PrimarySelection(None) => {
            if let Some(old_id) = ctx.state.selected_primary_offer.take() {
                if let Some(old_offer) = ctx.state.offers.remove(&old_id) {
                    old_offer.proxy.destroy(ctx.conn);
                }
            }
        }
        ext_data_control_device_v1::Event::Finished => {
            crate::timestamped_log!(
                "clipboard: Wayland data control device is no longer valid; clipboard sharing stopped"
            );
            if let Some(old_id) = ctx.state.selected_offer.take()
                && let Some(old_offer) = ctx.state.offers.remove(&old_id)
            {
                old_offer.proxy.destroy(ctx.conn);
            }
            if let Some(old_id) = ctx.state.selected_primary_offer.take()
                && let Some(old_offer) = ctx.state.offers.remove(&old_id)
            {
                old_offer.proxy.destroy(ctx.conn);
            }
            ctx.state.device.destroy(ctx.conn);
            ctx.state.device_alive = false;
            let mut selection = ctx.state.text.lock();
            selection.generation += 1;
            selection.current = None;
            selection.published = None;
        }
        _ => {}
    }
}

fn offer_callback(ctx: EventCtx<'_, State, ExtDataControlOfferV1>) {
    if let ext_data_control_offer_v1::Event::Offer(mime_type) = ctx.event {
        if let Some(offer) = ctx.state.offers.get_mut(&ctx.proxy.id()) {
            offer.mime_types.push(mime_type);
        }
    }
}

fn read_fd(mut stream: UnixStream) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    while output.len() < MAX_CLIPBOARD_BYTES {
        let limit = buffer.len().min(MAX_CLIPBOARD_BYTES - output.len());
        match stream.read(&mut buffer[..limit]) {
            Ok(0) => break,
            // Only real end-of-data stops the transfer; an interrupted read
            // must not silently truncate the selection.
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
            Ok(size) => output.extend_from_slice(&buffer[..size]),
        }
    }
    output
}

fn write_fd(fd: OwnedFd, text: Vec<u8>) {
    // SAFETY: ownership of this descriptor was transferred to us by the
    // Wayland protocol event and it is consumed exactly once here.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) };
    if let Err(error) = file.write_all(&text) {
        crate::timestamped_log!("clipboard: could not send selection data: {error}");
    }
}

use std::os::fd::IntoRawFd;

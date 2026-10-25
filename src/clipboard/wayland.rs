//! Wayland `ext_data_control_v1` clipboard backend.
//!
//! A dedicated Wayland connection is driven on a worker thread. Clipboard
//! payloads travel through protocol-provided file descriptors, never through
//! the event loop itself.

use std::collections::HashMap;
use std::ffi::CString;
use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
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

use super::{ClipboardBackend, ClipboardListenerEvent};

const TEXT_MIME_TYPES: [&str; 2] = ["text/plain;charset=utf-8", "text/plain"];
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

enum Command {
    SetText(Vec<u8>),
    Stop,
}

struct SharedText {
    current: Mutex<Option<Vec<u8>>>,
}

/// Clipboard backend using the compositor's ext-data-control-v1 global.
pub struct WaylandClipboard {
    command_tx: std_mpsc::Sender<Command>,
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
    text: Arc<SharedText>,
    events: mpsc::UnboundedSender<ClipboardListenerEvent>,
}

impl WaylandClipboard {
    /// Connect to Wayland, bind a seat and the ext-data-control-v1 manager,
    /// and start its private protocol event-loop worker.
    pub fn connect() -> Result<Self, String> {
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        let (command_tx, command_rx) = std_mpsc::channel();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let text = Arc::new(SharedText {
            current: Mutex::new(None),
        });
        let worker_text = Arc::clone(&text);
        let worker_events = events_tx.clone();
        let worker = thread::Builder::new()
            .name("rvnc-wayland-clipboard".into())
            .spawn(move || {
                let result = worker_init(worker_text, worker_events);
                match result {
                    Ok(mut connection_state) => {
                        let _ = ready_tx.send(Ok(()));
                        worker_loop(&mut connection_state, command_rx);
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
                event_rx: Some(events_rx),
                text,
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(error) => {
                let _ = worker.join();
                Err(format!("timed out initializing Wayland clipboard: {error}"))
            }
        }
    }
}

impl ClipboardBackend for WaylandClipboard {
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
            self.event_rx
                .take()
                .ok_or_else(|| "Wayland clipboard listeners already started".into())
        })
    }

    fn read_text<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, String>> + Send + 'a>> {
        Box::pin(async move {
            let text = self
                .text
                .current
                .lock()
                .map_err(|_| "Wayland clipboard text lock was poisoned".to_string())?
                .clone();
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
            *self
                .text
                .current
                .lock()
                .map_err(|_| "Wayland clipboard text lock was poisoned".to_string())? =
                Some(text.clone());
            self.command_tx
                .send(Command::SetText(text))
                .map_err(|_| "Wayland clipboard worker has stopped".to_string())
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
            let _ = self.command_tx.send(Command::Stop);
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
) {
    let (connection, state) = connection_state;
    loop {
        match commands.try_recv() {
            Ok(Command::SetText(text)) => publish_text(connection, state, text),
            Ok(Command::Stop) | Err(std_mpsc::TryRecvError::Disconnected) => break,
            Err(std_mpsc::TryRecvError::Empty) => {}
        }
        if let Err(error) = connection.recv_events(IoMode::NonBlocking) {
            if error.kind() != ErrorKind::WouldBlock {
                crate::timestamped_log!("clipboard: Wayland event loop stopped: {error}");
                break;
            }
        }
        connection.dispatch_events(state);
        if let Err(error) = connection.flush(IoMode::NonBlocking) {
            if error.kind() != ErrorKind::WouldBlock {
                crate::timestamped_log!("clipboard: Wayland request flush failed: {error}");
                break;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn publish_text(connection: &mut Connection<State>, state: &State, text: Vec<u8>) {
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
    let shared_text = Arc::clone(&state.text);
    connection.set_callback_for(
        source,
        move |ctx: EventCtx<'_, State, ExtDataControlSourceV1>| match ctx.event {
            ext_data_control_source_v1::Event::Send(args) => {
                let text = shared_text
                    .current
                    .lock()
                    .ok()
                    .and_then(|text| text.clone())
                    .unwrap_or_default();
                let fd = args.fd;
                let _ = thread::Builder::new()
                    .name("rvnc-clipboard-send".into())
                    .spawn(move || write_fd(fd, text));
            }
            ext_data_control_source_v1::Event::Cancelled => {
                ctx.proxy.destroy(ctx.conn);
            }
            _ => {}
        },
    );
    state.device.set_selection(connection, Some(source));
    if let Ok(mut current) = state.text.current.lock() {
        *current = Some(text);
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
            let Some(offer) = ctx.state.offers.get(&id) else {
                return;
            };
            let Some(mime_type) = offer.mime_types.iter().find(|mime| {
                let mime = mime.to_string_lossy();
                TEXT_MIME_TYPES.contains(&mime.as_ref())
            }) else {
                if let Ok(mut current) = ctx.state.text.current.lock() {
                    *current = None;
                }
                return;
            };
            let mime = mime_type.to_string_lossy().into_owned();
            crate::timestamped_log!("clipboard: receiving local Wayland selection as {mime}");
            let proxy = offer.proxy;
            let event_tx = ctx.state.events.clone();
            let text = Arc::clone(&ctx.state.text);
            let Ok((reader, writer)) = UnixStream::pair() else {
                return;
            };
            let writer: OwnedFd = writer.into();
            let Ok(mime_cstring) = CString::new(mime.clone()) else {
                return;
            };
            proxy.receive(ctx.conn, mime_cstring, writer);
            let _ = thread::Builder::new()
                .name("rvnc-clipboard-receive".into())
                .spawn(move || {
                    let bytes = read_fd(reader);
                    if let Ok(mut current) = text.current.lock() {
                        *current = Some(bytes);
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
            if let Ok(mut current) = ctx.state.text.current.lock() {
                *current = None;
            }
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
            Ok(0) | Err(_) => break,
            Ok(size) => output.extend_from_slice(&buffer[..size]),
        }
    }
    output
}

fn write_fd(fd: OwnedFd, text: Vec<u8>) {
    // SAFETY: ownership of this descriptor was transferred to us by the
    // Wayland protocol event and it is consumed exactly once here.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd.into_raw_fd()) };
    let _ = file.write_all(&text);
}

use std::os::fd::IntoRawFd;

//! Minimal RFB 3.8 server.
//!
//! This module intentionally depends only on the normalized [`Frame`] type and
//! the standard library. It currently supports:
//!
//! - RFB 3.8 version negotiation
//! - Security type `None` (unencrypted)
//! - A single client at a time
//! - 32-bit true-color pixel format with BGRA byte order
//! - Raw encoding only
//!
//! Keyboard, pointer, and clipboard messages are consumed but not acted upon.
//! The server does not claim support for encodings or extensions that are not
//! implemented here.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::framebuffer::{Frame, FrameStore};

const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";
const MAX_ENCODINGS: u16 = 1024;
const MAX_CUT_TEXT: u32 = 1024 * 1024;
const READ_POLL_INTERVAL: Duration = Duration::from_millis(500);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const INCREMENTAL_TIMEOUT: Duration = Duration::from_secs(30);
const INITIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_SLICE: Duration = Duration::from_millis(250);

/// Start the RFB listener thread.
///
/// The listener is put into non-blocking mode so shutdown can be observed
/// without needing a separate wake-up connection.
pub fn spawn(
    listener: TcpListener,
    store: Arc<FrameStore>,
    width: u16,
    height: u16,
    name: String,
    shutdown: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    listener.set_nonblocking(true)?;

    thread::Builder::new()
        .name("rfb-listener".to_string())
        .spawn(move || run_listener(listener, store, width, height, name, shutdown))
}

fn run_listener(
    listener: TcpListener,
    store: Arc<FrameStore>,
    width: u16,
    height: u16,
    name: String,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, address)) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }

                eprintln!("rfb: client connected from {address}");
                if let Err(error) = configure_stream(&stream) {
                    eprintln!("rfb: could not configure client socket: {error}");
                    continue;
                }

                store.client_connected();
                let result = handle_client(stream, &store, width, height, &name, &shutdown);
                store.client_disconnected();

                match result {
                    Ok(()) => eprintln!("rfb: client disconnected"),
                    Err(error) if is_normal_disconnect(&error) => {
                        eprintln!("rfb: client disconnected: {error}");
                    }
                    Err(error) => eprintln!("rfb: client error: {error}"),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                eprintln!("rfb: accept failed: {error}");
                break;
            }
        }
    }
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(READ_POLL_INTERVAL))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.set_nodelay(true)?;
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    store: &FrameStore,
    width: u16,
    height: u16,
    name: &str,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    write_all_interruptible(&mut stream, RFB_VERSION, shutdown)?;

    let mut version = [0u8; 12];
    read_exact_interruptible(&mut stream, &mut version, shutdown)?;
    parse_client_version(&version)?;

    // Security types: one type, None.
    write_all_interruptible(&mut stream, &[1, 1], shutdown)?;
    let security_type = read_u8(&mut stream, shutdown)?;
    if security_type != 1 {
        return Err(invalid_data(format!(
            "client selected unsupported security type {security_type}"
        )));
    }

    write_all_interruptible(&mut stream, &0u32.to_be_bytes(), shutdown)?;

    // ClientInit: shared flag. The initial server supports one client, so the
    // flag does not change behavior.
    let _shared = read_u8(&mut stream, shutdown)?;

    write_server_init(&mut stream, width, height, name, shutdown)?;

    let mut last_sequence = 0u64;
    let mut input_warned = false;

    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        let message_type = read_u8(&mut stream, shutdown)?;
        match message_type {
            0 => handle_set_pixel_format(&mut stream, shutdown)?,
            2 => handle_set_encodings(&mut stream, shutdown)?,
            3 => {
                handle_update_request(
                    &mut stream,
                    store,
                    width,
                    height,
                    &mut last_sequence,
                    shutdown,
                )?;
            }
            4 => {
                let mut event = [0u8; 7];
                read_exact_interruptible(&mut stream, &mut event, shutdown)?;
                if !input_warned {
                    eprintln!("rfb: keyboard input is not supported yet; event ignored");
                    input_warned = true;
                }
            }
            5 => {
                // PointerEvent: button-mask (1), padding (2), x (2), y (2).
                let mut event = [0u8; 7];
                read_exact_interruptible(&mut stream, &mut event, shutdown)?;
                if !input_warned {
                    eprintln!("rfb: pointer input is not supported yet; event ignored");
                    input_warned = true;
                }
            }
            6 => {
                let mut padding = [0u8; 3];
                read_exact_interruptible(&mut stream, &mut padding, shutdown)?;
                let length = read_u32(&mut stream, shutdown)?;
                if length > MAX_CUT_TEXT {
                    return Err(invalid_data(format!(
                        "client cut text length {length} exceeds the limit"
                    )));
                }
                discard_exact(&mut stream, length as usize, shutdown)?;
            }
            other => {
                return Err(invalid_data(format!(
                    "unsupported client message type {other}"
                )));
            }
        }
    }
}

fn write_server_init(
    stream: &mut TcpStream,
    width: u16,
    height: u16,
    name: &str,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    write_all_interruptible(stream, &width.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, &height.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, &server_pixel_format(), shutdown)?;

    let name_bytes = name.as_bytes();
    let name_len = u32::try_from(name_bytes.len())
        .map_err(|_| invalid_data("server name is too long for RFB"))?;
    write_all_interruptible(stream, &name_len.to_be_bytes(), shutdown)?;
    write_all_interruptible(stream, name_bytes, shutdown)?;
    Ok(())
}

fn handle_set_pixel_format(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<()> {
    let mut padding = [0u8; 3];
    read_exact_interruptible(stream, &mut padding, shutdown)?;

    let mut format = [0u8; 16];
    read_exact_interruptible(stream, &mut format, shutdown)?;
    validate_client_pixel_format(&format)
}

fn handle_set_encodings(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<()> {
    let mut padding = [0u8; 1];
    read_exact_interruptible(stream, &mut padding, shutdown)?;

    let count = read_u16(stream, shutdown)?;
    if count > MAX_ENCODINGS {
        return Err(invalid_data(format!(
            "client advertised {count} encodings; limit is {MAX_ENCODINGS}"
        )));
    }

    let mut encodings = vec![0u8; count as usize * 4];
    read_exact_interruptible(stream, &mut encodings, shutdown)?;

    let raw_supported = encodings.chunks_exact(4).any(|encoding| {
        i32::from_be_bytes([encoding[0], encoding[1], encoding[2], encoding[3]]) == 0
    });

    if !raw_supported {
        return Err(invalid_data(
            "client did not offer Raw encoding; only Raw is supported",
        ));
    }

    Ok(())
}

fn handle_update_request(
    stream: &mut TcpStream,
    store: &FrameStore,
    width: u16,
    height: u16,
    last_sequence: &mut u64,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let incremental = read_u8(stream, shutdown)? != 0;
    let x = read_u16(stream, shutdown)?;
    let y = read_u16(stream, shutdown)?;
    let rectangle_width = read_u16(stream, shutdown)?;
    let rectangle_height = read_u16(stream, shutdown)?;

    validate_rectangle(x, y, rectangle_width, rectangle_height, width, height)?;

    let frame = if incremental {
        wait_for_frame(store, *last_sequence, INCREMENTAL_TIMEOUT, shutdown)?
    } else {
        match store.latest() {
            Some(frame) => Some(frame),
            None => wait_for_frame(store, 0, INITIAL_FRAME_TIMEOUT, shutdown)?,
        }
    };

    match frame {
        Some((sequence, frame)) => {
            if frame.width != u32::from(width) || frame.height != u32::from(height) {
                return Err(invalid_data(format!(
                    "captured frame is {}x{}, but the RFB session is {}x{}",
                    frame.width, frame.height, width, height
                )));
            }

            send_update(
                stream,
                &frame,
                x,
                y,
                rectangle_width,
                rectangle_height,
                shutdown,
            )?;
            *last_sequence = sequence;
            Ok(())
        }
        None => send_empty_update(stream, shutdown),
    }
}

fn wait_for_frame(
    store: &FrameStore,
    last_sequence: u64,
    timeout: Duration,
    shutdown: &AtomicBool,
) -> io::Result<Option<(u64, Arc<Frame>)>> {
    let deadline = Instant::now() + timeout;

    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        if let Some(frame) = store.wait_next(last_sequence, WAIT_SLICE) {
            return Ok(Some(frame));
        }

        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

fn send_update(
    stream: &mut TcpStream,
    frame: &Frame,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut header = [0u8; 16];
    header[0] = 0; // FramebufferUpdate
    header[1] = 0; // padding
    header[2..4].copy_from_slice(&1u16.to_be_bytes()); // one rectangle
    header[4..6].copy_from_slice(&x.to_be_bytes());
    header[6..8].copy_from_slice(&y.to_be_bytes());
    header[8..10].copy_from_slice(&width.to_be_bytes());
    header[10..12].copy_from_slice(&height.to_be_bytes());
    header[12..16].copy_from_slice(&0i32.to_be_bytes()); // Raw encoding

    write_all_interruptible(stream, &header, shutdown)?;

    let frame_width = frame.width as usize;
    let frame_height = frame.height as usize;
    let x = x as usize;
    let y = y as usize;
    let width = width as usize;
    let height = height as usize;

    let right = x
        .checked_add(width)
        .ok_or_else(|| invalid_data("rectangle overflows"))?;
    let bottom = y
        .checked_add(height)
        .ok_or_else(|| invalid_data("rectangle overflows"))?;
    if right > frame_width || bottom > frame_height {
        return Err(invalid_data("rectangle is outside the framebuffer"));
    }

    let row_bytes = width
        .checked_mul(4)
        .ok_or_else(|| invalid_data("rectangle is too wide"))?;

    for row in 0..height {
        let start = (y + row)
            .checked_mul(frame_width)
            .and_then(|pixel| pixel.checked_add(x))
            .and_then(|pixel| pixel.checked_mul(4))
            .ok_or_else(|| invalid_data("rectangle offset overflows"))?;
        let end = start
            .checked_add(row_bytes)
            .ok_or_else(|| invalid_data("rectangle offset overflows"))?;
        let pixels = frame
            .data
            .get(start..end)
            .ok_or_else(|| invalid_data("rectangle is outside the framebuffer"))?;
        write_all_interruptible(stream, pixels, shutdown)?;
    }

    Ok(())
}

fn send_empty_update(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<()> {
    write_all_interruptible(stream, &[0, 0, 0, 0], shutdown)
}

fn validate_rectangle(
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    framebuffer_width: u16,
    framebuffer_height: u16,
) -> io::Result<()> {
    if width == 0 || height == 0 {
        return Err(invalid_data("requested rectangle has zero width or height"));
    }

    let right = u32::from(x) + u32::from(width);
    let bottom = u32::from(y) + u32::from(height);
    if right > u32::from(framebuffer_width) || bottom > u32::from(framebuffer_height) {
        return Err(invalid_data(
            "requested rectangle is outside the framebuffer",
        ));
    }

    Ok(())
}

fn parse_client_version(version: &[u8; 12]) -> io::Result<()> {
    if &version[0..4] != b"RFB " || version[11] != b'\n' {
        return Err(invalid_data("malformed RFB version string"));
    }

    let major = parse_version_component(&version[4..7])
        .ok_or_else(|| invalid_data("malformed RFB major version"))?;
    let minor = parse_version_component(&version[8..11])
        .ok_or_else(|| invalid_data("malformed RFB minor version"))?;

    if major != 3 || minor != 8 {
        return Err(invalid_data(format!(
            "unsupported RFB version {major}.{minor}; RFB 3.8 is required"
        )));
    }

    Ok(())
}

fn parse_version_component(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }

    Some(
        u32::from(bytes[0] - b'0') * 100
            + u32::from(bytes[1] - b'0') * 10
            + u32::from(bytes[2] - b'0'),
    )
}

fn validate_client_pixel_format(format: &[u8; 16]) -> io::Result<()> {
    let bits_per_pixel = format[0];
    let depth = format[1];
    let big_endian = format[2];
    let true_color = format[3];
    let red_max = u16::from_be_bytes([format[4], format[5]]);
    let green_max = u16::from_be_bytes([format[6], format[7]]);
    let blue_max = u16::from_be_bytes([format[8], format[9]]);
    let red_shift = format[10];
    let green_shift = format[11];
    let blue_shift = format[12];

    if bits_per_pixel != 32
        || depth != 24
        || big_endian != 0
        || true_color != 1
        || red_max != 255
        || green_max != 255
        || blue_max != 255
        || red_shift != 16
        || green_shift != 8
        || blue_shift != 0
    {
        return Err(invalid_data(
            "unsupported client pixel format; 32bpp little-endian BGRA is required",
        ));
    }

    Ok(())
}

fn server_pixel_format() -> [u8; 16] {
    [
        32,  // bits per pixel
        24,  // depth
        0,   // little endian
        1,   // true color
        0,   // red max high byte
        255, // red max low byte
        0,   // green max high byte
        255, // green max low byte
        0,   // blue max high byte
        255, // blue max low byte
        16,  // red shift
        8,   // green shift
        0,   // blue shift
        0, 0, 0, // padding
    ]
}

fn read_u8(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    read_exact_interruptible(stream, &mut byte, shutdown)?;
    Ok(byte[0])
}

fn read_u16(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    read_exact_interruptible(stream, &mut bytes, shutdown)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(stream: &mut TcpStream, shutdown: &AtomicBool) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    read_exact_interruptible(stream, &mut bytes, shutdown)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_exact_interruptible(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client disconnected",
                ));
            }
            Ok(read) => offset += read,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn write_all_interruptible(
    stream: &mut TcpStream,
    mut buffer: &[u8],
    shutdown: &AtomicBool,
) -> io::Result<()> {
    while !buffer.is_empty() {
        if shutdown.load(Ordering::Acquire) {
            return Err(shutdown_error());
        }

        match stream.write(buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "client stopped accepting data",
                ));
            }
            Ok(written) => buffer = &buffer[written..],
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(error);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn discard_exact(
    stream: &mut TcpStream,
    mut remaining: usize,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        read_exact_interruptible(stream, &mut buffer[..chunk], shutdown)?;
        remaining -= chunk;
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn shutdown_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "server is shutting down")
}

fn is_normal_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn accepts_rfb_38_and_sends_raw_update() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(FrameStore::new());
        let pixels = vec![
            1, 2, 3, 255, 4, 5, 6, 255, // row 0
            7, 8, 9, 255, 10, 11, 12, 255, // row 1
        ];
        store.publish(Arc::new(Frame::new(2, 2, pixels.clone()).unwrap()));

        let shutdown = Arc::new(AtomicBool::new(false));
        let server_store = Arc::clone(&store);
        let server_shutdown = Arc::clone(&shutdown);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            configure_stream(&stream).unwrap();
            let _ = handle_client(stream, &server_store, 2, 2, "test", &server_shutdown);
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut version = [0u8; 12];
        client.read_exact(&mut version).unwrap();
        assert_eq!(&version, RFB_VERSION);

        client.write_all(RFB_VERSION).unwrap();

        let mut security = [0u8; 2];
        client.read_exact(&mut security).unwrap();
        assert_eq!(security, [1, 1]);
        client.write_all(&[1]).unwrap();

        let mut security_result = [0u8; 4];
        client.read_exact(&mut security_result).unwrap();
        assert_eq!(security_result, [0, 0, 0, 0]);

        client.write_all(&[1]).unwrap();

        let mut server_init = [0u8; 24];
        client.read_exact(&mut server_init).unwrap();
        assert_eq!(u16::from_be_bytes([server_init[0], server_init[1]]), 2);
        assert_eq!(u16::from_be_bytes([server_init[2], server_init[3]]), 2);
        assert_eq!(&server_init[4..20], &server_pixel_format());
        let name_len = u32::from_be_bytes([
            server_init[20],
            server_init[21],
            server_init[22],
            server_init[23],
        ]) as usize;
        let mut name = vec![0u8; name_len];
        client.read_exact(&mut name).unwrap();
        assert_eq!(name, b"test");

        let mut set_pixel_format = vec![0u8];
        set_pixel_format.extend_from_slice(&[0, 0, 0]);
        set_pixel_format.extend_from_slice(&server_pixel_format());
        client.write_all(&set_pixel_format).unwrap();

        let mut set_encodings = vec![2u8, 0];
        set_encodings.extend_from_slice(&1u16.to_be_bytes());
        set_encodings.extend_from_slice(&0i32.to_be_bytes());
        client.write_all(&set_encodings).unwrap();

        let mut request = vec![3u8, 0];
        for value in [0u16, 0, 2, 2] {
            request.extend_from_slice(&value.to_be_bytes());
        }
        client.write_all(&request).unwrap();

        let mut update_header = [0u8; 16];
        client.read_exact(&mut update_header).unwrap();
        assert_eq!(update_header[0], 0);
        assert_eq!(u16::from_be_bytes([update_header[2], update_header[3]]), 1);
        assert_eq!(u16::from_be_bytes([update_header[4], update_header[5]]), 0);
        assert_eq!(u16::from_be_bytes([update_header[6], update_header[7]]), 0);
        assert_eq!(u16::from_be_bytes([update_header[8], update_header[9]]), 2);
        assert_eq!(
            u16::from_be_bytes([update_header[10], update_header[11]]),
            2
        );
        assert_eq!(&update_header[12..16], &[0, 0, 0, 0]);

        let mut received = vec![0u8; 16];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, pixels);

        // A pointer event must be consumed without desynchronizing the stream.
        client.write_all(&[5, 0, 0, 0, 0, 0, 0, 0]).unwrap();

        let mut second_request = vec![3u8, 0];
        for value in [0u16, 0, 2, 2] {
            second_request.extend_from_slice(&value.to_be_bytes());
        }
        client.write_all(&second_request).unwrap();

        let mut second_header = [0u8; 16];
        client.read_exact(&mut second_header).unwrap();
        assert_eq!(second_header[0], 0);
        assert_eq!(u16::from_be_bytes([second_header[2], second_header[3]]), 1);
        let mut second_pixels = vec![0u8; 16];
        client.read_exact(&mut second_pixels).unwrap();
        assert_eq!(second_pixels, pixels);

        drop(client);
        server.join().unwrap();
        assert!(!shutdown.load(Ordering::Acquire));
    }

    #[test]
    fn parses_supported_versions() {
        assert!(parse_client_version(b"RFB 003.008\n").is_ok());
        assert!(parse_client_version(b"RFB 003.007\n").is_err());
        assert!(parse_client_version(b"RFB 003.009\n").is_err());
        assert!(parse_client_version(b"RFB 004.000\n").is_err());
        assert!(parse_client_version(b"RFB 003.00x\n").is_err());
        assert!(parse_client_version(b"NOT 003.008\n").is_err());
    }

    #[test]
    fn validates_pixel_formats() {
        assert!(validate_client_pixel_format(&server_pixel_format()).is_ok());

        let mut wrong = server_pixel_format();
        wrong[0] = 16;
        assert!(validate_client_pixel_format(&wrong).is_err());

        let mut wrong = server_pixel_format();
        wrong[10] = 0;
        assert!(validate_client_pixel_format(&wrong).is_err());
    }

    #[test]
    fn rejects_zero_sized_rectangles() {
        assert!(validate_rectangle(0, 0, 0, 1, 10, 10).is_err());
        assert!(validate_rectangle(0, 0, 11, 1, 10, 10).is_err());
        assert!(validate_rectangle(0, 0, 10, 10, 10, 10).is_ok());
    }

    #[test]
    fn frame_wait_observes_shutdown() {
        let store = FrameStore::new();
        let shutdown = AtomicBool::new(true);
        let error = wait_for_frame(&store, 0, Duration::from_secs(1), &shutdown).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }
}

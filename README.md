# rvncserver

A small VNC server for Wayland desktops. It captures the desktop through the
XDG Desktop Portal and PipeWire and serves the frames over the RFB protocol.

The application is a console process. It does not create a compositor, a
separate desktop session, or a graphical interface.

## Requirements

- Linux with an existing Wayland session
- `xdg-desktop-portal` and a compositor-specific portal backend
- PipeWire
- The PipeWire development files needed to build `lamco-pipewire`
  (for example `libpipewire-0.3-dev` on Debian/Ubuntu)

## Build

```sh
cargo build --release
```

## Run

```sh
./target/release/rvncserver
```

On startup the desktop portal asks which screen source to share. The server
then waits for the first captured frame and listens for a VNC client.

Defaults:

- Listen address: `127.0.0.1`
- Port: `5900`

```sh
./target/release/rvncserver --listen 127.0.0.1 --port 5900
```

Use `--help` for the complete command-line interface.

### Capture probe

To verify portal and PipeWire capture without starting the RFB listener:

```sh
./target/release/rvncserver --capture-probe /tmp/desktop.ppm
```

This captures one normalized frame and writes it as a binary PPM file.

## Supported RFB behavior

- RFB 3.3 and 3.8 version negotiation
- Security type `None`
- One client at a time
- 32-bit true-color framebuffer, little-endian BGRA byte order
- Raw encoding
- Full responses for non-incremental requests and damage-region rectangles for
  incremental requests when PipeWire supplies reliable damage metadata
- Bounded damage history; missed or unavailable damage falls back to a full
  framebuffer region to preserve correctness
- Clean handling of client disconnects and partial socket reads/writes

## Current limitations

- VNC traffic is unencrypted and unauthenticated. The default listener is
  loopback-only. Do not expose it to an untrusted network.
- Only the first stream advertised by the portal is used. Multi-monitor
  selection is not implemented.
- The cursor is not embedded in the captured image.
- The portal session is created for capture only; no input devices are
  requested.
- Keyboard, pointer, and clipboard messages are consumed but ignored.
- Only Raw encoding is supported. Tight, ZRLE, Hextile, and other encodings
  are not implemented.
- Raw is the only pixel encoding; incremental updates still transmit uncompressed
  pixel rectangles.
- DMA-BUF capture is disabled. The server uses CPU-mapped memory frames.
- Non-identity buffer transforms are rejected rather than displayed
  incorrectly.
- The framebuffer dimensions are fixed at startup. A later display resolution
  change causes the client connection to be closed rather than resized.
- The server requests application-scoped portal permission persistence. If the
  backend explicitly rejects persistence, it reports the fallback and retries
  capture with non-persistent permissions. Other portal errors are not retried.
- The portal source type is left to the backend default. This is required for
  COSMIC's combined RemoteDesktop session; other portal backends may interpret
  an empty source-type mask differently.

## Tested environments

- COSMIC Wayland session on Pop!_OS, with `xdg-desktop-portal-cosmic`,
  PipeWire 1.6.8, and a 1920x1080 output. Capture and a full 1920x1080 Raw
  framebuffer update were verified with a local RFB protocol client. COSMIC
  rejects application-scoped persistence; the non-persistent fallback works.
- GNOME, KDE Plasma, Sway, and Hyprland have not been tested yet. A graphical
  VNC client has not been tested yet.

## Project layout

- `src/cli.rs`: command-line parsing and validation
- `src/capture.rs`: portal session and PipeWire capture
- `src/framebuffer.rs`: frame normalization and the shared latest-frame store
- `src/rfb.rs`: RFB 3.8 protocol implementation
- `src/server.rs`: capture/RFB wiring and shutdown
- `src/error.rs`: application error type

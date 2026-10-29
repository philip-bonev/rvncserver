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

To build the release binary and Debian package together, use cargo-deb:

```sh
cargo deb
```

The `.deb` is written to `target/debian/`. It declares `xdg-desktop-portal` and
uses cargo-deb's `$auto` dependency detection for linked system libraries.

## Run

Configure an authentication mode and credential file as described below before
the first server start. VeNCrypt is the default and requires its TLS settings;
VNC mode does not use TLS.

```sh
./target/release/rvncserver
```

On startup the desktop portal asks which screen source to share. The server
then waits for the first captured frame and listens for an authenticated VNC
client.

Defaults:

- Listen address: `127.0.0.1`
- Port: `5900`

```sh
./target/release/rvncserver --listen 127.0.0.1 --port 5900
```

Remote input and clipboard sharing are disabled by default. Enable either
capability explicitly when needed. VeNCrypt/TLS authentication is the default;
classic VNC authentication can be selected for clients that need it:

```sh
./target/release/rvncserver --enable-input --enable-clipboard
```

To restrict framebuffer encodings, set an allowlist in the configuration or on
the command line. `raw` is required as the fallback; when the list is omitted,
the server uses the client's preferred supported encoding. For example, use Raw
only to troubleshoot a client's compressed-image rendering:

```sh
./target/release/rvncserver --encodings raw
```

Supported names are `raw`, `hextile`, `zlib`, `zrle`, and `copyrect`.

By default, settings are loaded from `$XDG_CONFIG_HOME/rvncserver/config.json`
or `~/.config/rvncserver/config.json`. Pass `--config <PATH>` to select another
file. Command-line options override values from JSON. Paths in the JSON file are
relative to that file's directory; command-line paths are relative to the
current directory.

The server stays in the foreground by default. Set `"daemonize": true` in JSON
or pass `--daemonize` to fork into a detached session. Use `--foreground` to
override a JSON daemon setting. Select diagnostics output with
`"log_target": "file"` or `"log_target": "journald"` in JSON, or
`--log-target file|journald`. File logging requires `log_file` or
`--log-file <PATH>` and appends to an owner-only file; JSON paths are relative to
the config file. Journald logging uses the system syslog interface and is
collected by systemd-journald. File logs rotate at 50 MB by default and retain
10 compressed backups. Override these with `log_max_size` and
`log_max_rotations` in JSON, or `--log-max-size <SIZE>` and
`--log-max-rotations <N>`. Sizes accept `B`, `KB`, `MB`, and `GB` suffixes
(case-insensitive, binary units where 1 KB = 1024 bytes); a bare number means
bytes. Rotated files are named `<log>.1.gz`, `<log>.2.gz`, etc. Set rotations to
`0` to keep no backups. Rotation checks the size before each application log
entry, so one large entry can exceed the threshold. The default target is
stderr; daemonized stderr goes to `/dev/null` unless a log target is selected.
The 50 MB/10-backup defaults apply when file logging is selected; they do not
affect stderr or journald. Set `enable_cursor: true` in JSON or pass
`--enable-cursor` to send the cursor shape (`RichCursor`) and movement
(`PointerPos`) separately when a client advertises support. Cursor updates are
disabled by default and depend on the compositor providing cursor metadata
through PipeWire.
Manage the daemon by its
PID with `rvncserver --stop`, which sends SIGTERM and waits up to 10 seconds for
graceful shutdown. The daemon writes and removes a PID file at
`$XDG_RUNTIME_DIR/rvncserver.pid` (falling back to
`$XDG_STATE_HOME/rvncserver/rvncserver.pid` or
`$HOME/.local/state/rvncserver/rvncserver.pid`). Override it with `pid_file` in
JSON or `--pid-file <PATH>`; pass the same path to `--stop` if needed. PID files
include process start-time data to avoid signaling a reused PID. This is not a
service-manager integration.

Example configuration:

```json
{
  "listen": "127.0.0.1",
  "port": 5900,
  "capture_probe": null,
  "enable_input": false,
  "enable_cursor": false,
  "enable_clipboard": false,
  "daemonize": false,
  "log_target": "file",
  "log_file": "rvncserver.log",
  "log_max_size": "50MB",
  "log_max_rotations": 10,
  "pid_file": null,
  "encodings": ["raw", "zrle", "copyrect"],
  "auth_mode": "vencrypt",
  "tls_cert": "server.crt",
  "tls_key": "server.key",
  "password_file": "credentials.txt"
}
```

For VeNCrypt, generate a server certificate/key and owner-only credentials
file (replace the sample password with a long unique value):

```sh
mkdir -p ~/.config/rvncserver
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout ~/.config/rvncserver/server.key \
  -out ~/.config/rvncserver/server.crt \
  -subj '/CN=rvncserver' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'
printf 'rvnc\nreplace-this-with-a-long-unique-password\n' \
  > ~/.config/rvncserver/credentials.txt
chmod 600 ~/.config/rvncserver/server.key ~/.config/rvncserver/credentials.txt
```

Add the generated `server.crt` to the VNC client's trusted certificates. For
remote access, issue a certificate with the actual DNS name/IP in its subject
alternative names and keep the private key and credential file private.

VeNCrypt uses `X509Plain`; clients must support that security subtype and trust
the configured server certificate. Its password file contains username and
password on separate lines. For `auth_mode: "vnc"` (or `--auth vnc`), clients
use classic VNC Authentication; the password is limited to 8 bytes and may be
provided as a one-line file, or as the second line of the same two-line file.
Both credential-file formats require owner-only permissions (`chmod 600`).
Classic VNC Authentication does not encrypt the session and its DES challenge
response is weak; use VeNCrypt unless compatibility requires VNC mode. The
desktop portal requests permission for enabled input and clipboard capabilities.
If the portal does not provide clipboard support, the server warns and continues
without clipboard sharing. Authenticated clients can use any enabled capability.

To select classic VNC authentication from the command line, provide a
password-only file (maximum 8 bytes) and use `--auth vnc`; the same mode can be
selected with `"auth_mode": "vnc"` in JSON. When using the two-line VeNCrypt
credential file, VNC mode uses the second line as its password.

Apple's legacy DH authentication is experimental and currently not working
with macOS Screen Sharing. It can be selected with `--auth apple-dh` or
`"auth_mode": "apple-dh"` for testing. It requires an owner-only credential
file with username and password on separate lines (each at most 64 bytes), and
advertises Apple's non-standard `RFB 003.889` version and SecurityType 30. Even
if authentication succeeds, Apple-specific RFB messages are not fully
implemented, so the session may disconnect. The DH/AES exchange protects only
credentials; framebuffer, input, and clipboard traffic remain unencrypted.

Use `--help` for the complete command-line interface.

### Capture probe

To verify portal and PipeWire capture without starting the RFB listener:

```sh
./target/release/rvncserver --capture-probe /tmp/desktop.ppm
```

This captures one normalized frame and writes it as a binary PPM file.

## Supported RFB behavior

- RFB 3.8 version negotiation for authenticated server sessions
- VeNCrypt X509Plain (TLS plus username/password authentication; default)
- Classic VNC Authentication (RFB SecurityType 2), selectable with `--auth vnc`
- Experimental Apple DH authentication (SecurityType 30 and RFB 3.889), opt-in
  with `--auth apple-dh`; currently not working with macOS Screen Sharing
- One client at a time
- 8-, 16-, and 32-bit true-color client pixel formats, including RGB332,
  RGB565, and 24-bit color in 32-bit pixels with either byte order
- Zlib, ZRLE, Hextile, and Raw when offered by the client, selected according
  to its encoding preference order. CopyRect is used opportunistically when
  the server can verify a matching source in the client's known framebuffer.
- Keyboard keysym events and pointer motion/buttons/scroll through the
  permission-controlled RemoteDesktop portal when `--enable-input` is set
- Bidirectional text clipboard transfer through the portal when
  `--enable-clipboard` is set
- Full responses for non-incremental requests and damage-region rectangles for
  incremental requests when PipeWire supplies reliable damage metadata
- Bounded damage history; missed or unavailable damage falls back to a full
  framebuffer region to preserve correctness
- Clean handling of client disconnects and partial socket reads/writes

## Current limitations

- TLS certificate trust must be configured on each client using VeNCrypt.
  Protect the private key and credential file; the server rejects either file
  if it has group/other permission bits set.
- VNC mode is unencrypted, uses obsolete DES, truncates password security to
  at most 8 bytes, and permits offline guessing from captured challenges. Do
  not use it on untrusted networks.
- Apple DH mode is experimental and currently not working with macOS Screen
  Sharing. Apple-specific client messages remain unsupported. The mode does
  not encrypt session traffic.
- VeNCrypt requires RFB 3.8; VNC Authentication also supports RFB 3.3.
- macOS Screen Sharing compatibility with VNC Authentication has not yet been
  verified against an actual Mac client.
- VeNCrypt X509Plain client compatibility varies; use a client that supports
  this subtype. Authentication attempts are not currently rate-limited.
- Only the first stream advertised by the portal is used. Multi-monitor
  selection is not implemented.
- The cursor is not embedded in the captured image.
- Input and clipboard forwarding are disabled by default and require explicit
  CLI opt-in and portal permission. Clipboard support is text-only; RFB's
  Latin-1 text is converted to/from UTF-8 for the desktop portal.
- Tight and other encodings are not implemented. ZRLE currently emits Raw
  tiles, so it provides zlib compression but does not yet use its palette or
  run-length tile modes. CopyRect source discovery is deliberately bounded to
  nearby regions and only runs after the client has received a full framebuffer.
  Hextile sends complex or noisy 16×16 tiles as Raw within the Hextile rectangle.
- DMA-BUF negotiation is requested where available, but direct FD passthrough
  is disabled. Lamco maps and copies supported linear DMA-BUFs into CPU memory;
  non-linear or non-mappable buffers may be skipped or unreadable.
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

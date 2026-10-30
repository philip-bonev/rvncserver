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
VNC mode offers TLS-protected authentication when both `tls_cert` and
`tls_key` are configured. The TLS certificate authenticates the server to the
client; client certificates are not required.

```sh
./target/release/rvncserver
```

On startup the desktop portal asks which screen source to share. The server
then waits for the first captured frame and listens for authenticated VNC
clients.

Defaults:

- Listen address: `127.0.0.1`
- Port: `5900`
- Simultaneous clients: `4` (configurable from 1 to 32)

```sh
./target/release/rvncserver --listen 127.0.0.1 --port 5900
```

Raise or lower the simultaneous client limit with `--max-clients <N>` or
`"max_clients": N` in JSON. Connections above the limit are closed immediately.
With multiple clients, clipboard text is broadcast to every client, and input
events from all clients share the same remote desktop.

For long-running sessions, finished client threads are joined and reaped, and
client/frame-store counters are released even if a worker panics. TCP keepalive
closes peers that disappear without closing the connection, while idle
authenticated clients remain connected. A connection that does not complete
authentication and initialization within 60 seconds is closed.

The portal restore token is stored in an owner-only file at
`$XDG_STATE_HOME/rvncserver/portal-restore-token` (falling back to
`~/.local/state/rvncserver/portal-restore-token`) and reused on later starts, so
restarts usually do not require a new local permission dialog. If the portal
rejects the stored token, session creation is retried without it, and the stale
file is removed when the retry succeeds without issuing a replacement. The
token is never logged.

If the portal or PipeWire stream ends, the server stops serving the frozen
framebuffer and tries to recreate the capture session, reusing the stored token.
It makes at most three attempts with short backoff, each bounded by a timeout.
If reinitialization fails, or the restarted stream has different dimensions than
the running RFB session, the process exits with an error so a service manager
can restart it.

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
service-manager integration. Use `rvncserver --status` to report whether the
daemon is running, starting, or stopped. When running, status also prints the
active effective configuration (including command-line overrides) from a
private sidecar file next to the PID file. The sidecar contains configuration
values and credential-file paths, but never credential contents. A second
daemon launch using the same PID-file path is rejected while the first instance
is starting or running.

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
`auth_mode: "vnc"` uses TLS when both `tls_cert` and `tls_key` are configured.
In that case it offers VeNCrypt `X509Vnc` plus plaintext VNC. RFB 3.8 clients
may select either; RFB 3.3 clients use plaintext VNC because VeNCrypt is not
available in that version. This explicitly permits a plaintext downgrade, and
the server logs a warning when it is used. Without both TLS settings, VNC mode
is plaintext only. Clients must support X509Vnc and trust the server certificate
to use TLS; client certificates are not required. The desktop portal requests
permission for enabled input and clipboard capabilities.
If the portal does not provide clipboard support, the server warns and continues
without clipboard sharing. Authenticated clients can use any enabled capability.

To select VNC password authentication from the command line, provide a
password-only file (maximum 8 bytes) and use `--auth vnc`; it can also be
selected with `"auth_mode": "vnc"` in JSON. Configure the TLS certificate and
key to enable X509Vnc in VNC mode. RFB 3.8 clients can then choose X509Vnc or
plaintext VNC; RFB 3.3 clients use plaintext VNC. When using the two-line
credential file, VNC mode uses the second line as the password.

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
- VNC Authentication with optional TLS via VeNCrypt X509Vnc when both TLS files
  are configured; VNC mode also offers plaintext fallback
- Experimental Apple DH authentication (SecurityType 30 and RFB 3.889), opt-in
  with `--auth apple-dh`; currently not working with macOS Screen Sharing
- Up to `max_clients` simultaneous clients (default 4, maximum 32); excess
  connections are closed immediately
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
- TLS-protected VNC requires RFB 3.8 and a client that supports X509Vnc. VNC
  mode permits plaintext fallback: RFB 3.3 clients use it, and RFB 3.8 clients
  may select it. Use `vencrypt` when TLS must be mandatory. No client
  certificate is required.
- Plain VNC mode is unencrypted, uses obsolete DES, truncates password security
  to at most 8 bytes, and permits offline guessing from captured challenges. Do
  not use it on untrusted networks.
- Apple DH mode is experimental and currently not working with macOS Screen
  Sharing. Apple-specific client messages remain unsupported. The mode does
  not encrypt session traffic.
- VeNCrypt requires RFB 3.8; plaintext VNC Authentication also supports RFB 3.3.
- macOS Screen Sharing compatibility with VNC Authentication has not yet been
  verified against an actual Mac client.
- VeNCrypt X509Plain client compatibility varies; use a client that supports
  this subtype. Authentication attempts are not currently rate-limited.
- Only the first stream advertised by the portal is used. Multi-monitor
  selection is not implemented.
- Multiple clients share one input stream and one clipboard: the most recent
  keyboard or pointer event from any client wins, and clipboard updates are
  broadcast. There is no per-client input ownership or arbitration.
- The RFB ClientInit shared flag is ignored; new clients never disconnect
  existing clients.
- Connections above `max_clients` are dropped before RFB negotiation; clients
  see a closed connection rather than a protocol error.
- Authenticated clients have no idle timeout. Dead peers are detected through
  TCP keepalive (60 seconds idle, then three probes at 10-second intervals).
- The authentication and initialization phase has a fixed 60-second timeout;
  it is not configurable.
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
- The server requests application-scoped portal permission persistence and
  stores the restore token in an owner-only state file. If the backend
  explicitly rejects persistence, it reports the fallback and retries capture
  with non-persistent permissions. A rejected stored token is discarded and
  session creation is retried once without it. Other portal errors are not
  retried.
- Capture loss is handled by recreating the portal and PipeWire session. The
  restarted stream must have the same dimensions as the running RFB session;
  otherwise the server exits so a service manager can restart it with a new
  framebuffer size. Live RFB desktop resizing is not implemented.
- Capture-loss detection uses PipeWire stream state events (`Error` and
  `Unconnected`). A stream that stops producing frames without reporting a
  state change is not treated as lost, and a paused stream is left alone. A
  silent failure that emits no state event may therefore not be detected.
- Restore-token persistence depends on the portal backend honoring
  application-scoped tokens. A backend that does not return a token will still
  prompt for permission after a restart.
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

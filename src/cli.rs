//! Command-line parsing and validation.
//!
//! The initial server deliberately uses only the standard library. Arguments
//! are validated before any portal or network resources are created.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use serde::Deserialize;

/// Default listening address. The server is not exposed on the network unless
/// the user explicitly changes this.
pub const DEFAULT_LISTEN: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Default RFB port.
pub const DEFAULT_PORT: u16 = 5900;

/// Default file-log rotation threshold (50 MiB).
pub const DEFAULT_LOG_MAX_SIZE: u64 = 50 * 1024 * 1024;

/// RFB encodings that the server may negotiate with a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfbEncoding {
    Raw,
    Hextile,
    Zlib,
    Zrle,
    CopyRect,
}

impl RfbEncoding {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "raw" => Some(Self::Raw),
            "hextile" => Some(Self::Hextile),
            "zlib" => Some(Self::Zlib),
            "zrle" => Some(Self::Zrle),
            "copyrect" => Some(Self::CopyRect),
            _ => None,
        }
    }
}

/// Supported RFB authentication modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// VeNCrypt with TLS and username/password authentication.
    #[default]
    VeNCrypt,
    /// Legacy VNC DES challenge-response (no session encryption).
    Vnc,
    /// Apple-specific DH authentication (no session encryption).
    AppleDh,
}

/// Destination for application diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogTarget {
    /// Keep output on the existing stderr (or `/dev/null` when daemonized).
    #[default]
    Stderr,
    /// Append output to `log_file`.
    File,
    /// Send output to the system log, which systemd-journald collects.
    Journald,
}

/// Validated runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Local address on which the RFB listener binds.
    pub listen: IpAddr,
    /// TCP port on which the RFB listener binds.
    pub port: u16,
    /// If set, capture one frame to this PPM path and exit instead of serving
    /// RFB clients.
    pub capture_probe: Option<PathBuf>,
    /// Request portal permission for remote keyboard and pointer input.
    pub enable_input: bool,
    /// Send cursor shape and pointer position as RFB pseudo-encodings.
    pub enable_cursor: bool,
    /// Request portal permission for bidirectional clipboard sharing.
    pub enable_clipboard: bool,
    /// Optional allowlist of framebuffer encodings; Raw must be included.
    pub encodings: Option<Vec<RfbEncoding>>,
    /// TLS server certificate PEM path.
    pub tls_cert: Option<PathBuf>,
    /// TLS server private-key PEM path.
    pub tls_key: Option<PathBuf>,
    /// Restrictive-permission file containing the VeNCrypt username/password.
    pub password_file: Option<PathBuf>,
    /// Authentication mode selected from CLI or JSON.
    pub auth_mode: AuthMode,
    /// Run detached from the invoking terminal.
    pub daemonize: bool,
    /// Append stdout/stderr output to this file.
    pub log_file: Option<PathBuf>,
    /// Destination for application diagnostics.
    pub log_target: LogTarget,
    /// Rotate file logs when they reach this size, in bytes. `None` disables rotation.
    pub log_max_size: u64,
    /// Number of compressed rotated log files to retain (default: 10).
    pub log_max_rotations: usize,
    /// PID file used to stop a daemonized instance.
    pub pid_file: Option<PathBuf>,
    /// Path from which this configuration was loaded, if any.
    pub config_file: Option<PathBuf>,
}

/// Parsed command-line command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the server with the given configuration.
    Run(Config),
    /// Print help and exit.
    Help,
    /// Print the application version and exit.
    Version,
    /// Stop the daemon identified by its PID file.
    Stop(PathBuf),
}

/// Command-line validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// An argument was not recognized.
    UnknownArgument(String),
    /// An option that requires a value was not given one.
    MissingValue(&'static str),
    /// An option value was empty.
    EmptyValue(&'static str),
    /// The listening address was not a valid IP address.
    InvalidListen(String),
    /// The port was not a valid non-zero TCP port.
    InvalidPort(String),
    /// An option was specified more than once.
    DuplicateOption(&'static str),
    /// An argument was not valid UTF-8.
    InvalidUtf8,
    /// Mutually exclusive or meaningless options were combined.
    IncompatibleOptions(&'static str),
    /// Configuration file could not be read or decoded.
    ConfigFile(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArgument(argument) => {
                write!(f, "unknown argument: {argument}")
            }
            Self::MissingValue(option) => {
                write!(f, "missing value for {option}")
            }
            Self::EmptyValue(option) => {
                write!(f, "empty value for {option}")
            }
            Self::InvalidListen(value) => {
                write!(
                    f,
                    "invalid listening address {value:?}; expected an IP address such as 127.0.0.1 or ::1"
                )
            }
            Self::InvalidPort(value) => {
                write!(
                    f,
                    "invalid port {value:?}; expected an integer from 1 to 65535"
                )
            }
            Self::DuplicateOption(option) => {
                write!(f, "{option} was specified more than once")
            }
            Self::InvalidUtf8 => write!(f, "arguments must be valid UTF-8"),
            Self::IncompatibleOptions(message) => write!(f, "{message}"),
            Self::ConfigFile(message) => write!(f, "configuration error: {message}"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ConfigLogSize {
    Bytes(u64),
    Unit(String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: Option<String>,
    port: Option<u16>,
    capture_probe: Option<PathBuf>,
    enable_input: Option<bool>,
    enable_cursor: Option<bool>,
    enable_clipboard: Option<bool>,
    encodings: Option<Vec<String>>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    password_file: Option<PathBuf>,
    auth_mode: Option<String>,
    log_target: Option<String>,
    daemonize: Option<bool>,
    log_file: Option<PathBuf>,
    log_max_size: Option<ConfigLogSize>,
    log_max_rotations: Option<usize>,
    pid_file: Option<PathBuf>,
}

impl Error for CliError {}

/// Parse command-line arguments, excluding the program name.
///
/// `--help` and `--version` short-circuit parsing. All other arguments are
/// validated and collected into [`Config`].
pub fn parse_args<I>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut listen = DEFAULT_LISTEN;
    let mut port = DEFAULT_PORT;
    let mut capture_probe = None;
    let mut enable_input = false;
    let mut enable_cursor = false;
    let mut enable_clipboard = false;
    let mut encodings = None;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut password_file = None;
    let mut auth_mode = AuthMode::default();
    let mut daemonize = false;
    let mut log_file = None;
    let mut cli_log_target = None;
    let mut cli_log_max_size = None;
    let mut cli_log_max_rotations = None;
    let mut pid_file = None;
    let mut config_path = None;

    let mut listen_set = false;
    let mut port_set = false;
    let mut capture_probe_set = false;
    let mut enable_input_set = false;
    let mut enable_cursor_set = false;
    let mut enable_clipboard_set = false;
    let mut encodings_set = false;
    let mut tls_cert_set = false;
    let mut tls_key_set = false;
    let mut password_file_set = false;
    let mut auth_mode_set = false;
    let mut daemonize_set = false;
    let mut log_file_set = false;
    let mut pid_file_set = false;
    let mut stop_requested = false;
    let mut config_path_set = false;

    let mut args = args.into_iter();
    while let Some(raw) = args.next() {
        let raw = raw.into_string().map_err(|_| CliError::InvalidUtf8)?;
        let (name, inline_value) = match raw.split_once('=') {
            Some((name, value)) => (name.to_string(), Some(value.to_string())),
            None => (raw.clone(), None),
        };

        match name.as_str() {
            "--help" | "-h" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                return Ok(Command::Help);
            }
            "--version" | "-V" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                return Ok(Command::Version);
            }
            "--stop" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                if stop_requested {
                    return Err(CliError::DuplicateOption("--stop"));
                }
                stop_requested = true;
            }
            "--listen" => {
                if listen_set {
                    return Err(CliError::DuplicateOption("--listen"));
                }
                listen_set = true;
                let value = take_value(inline_value, &mut args, "--listen")?;
                listen = value.parse().map_err(|_| CliError::InvalidListen(value))?;
            }
            "--port" => {
                if port_set {
                    return Err(CliError::DuplicateOption("--port"));
                }
                port_set = true;
                let value = take_value(inline_value, &mut args, "--port")?;
                let parsed: u16 = value
                    .parse()
                    .map_err(|_| CliError::InvalidPort(value.clone()))?;
                if parsed == 0 {
                    return Err(CliError::InvalidPort(value));
                }
                port = parsed;
            }
            "--capture-probe" => {
                if capture_probe_set {
                    return Err(CliError::DuplicateOption("--capture-probe"));
                }
                capture_probe_set = true;
                let value = take_value(inline_value, &mut args, "--capture-probe")?;
                capture_probe = Some(PathBuf::from(value));
            }
            "--config" => {
                if config_path_set {
                    return Err(CliError::DuplicateOption("--config"));
                }
                config_path_set = true;
                config_path = Some(PathBuf::from(take_value(
                    inline_value,
                    &mut args,
                    "--config",
                )?));
            }
            "--tls-cert" => {
                if tls_cert_set {
                    return Err(CliError::DuplicateOption("--tls-cert"));
                }
                tls_cert_set = true;
                tls_cert = Some(PathBuf::from(take_value(
                    inline_value,
                    &mut args,
                    "--tls-cert",
                )?));
            }
            "--tls-key" => {
                if tls_key_set {
                    return Err(CliError::DuplicateOption("--tls-key"));
                }
                tls_key_set = true;
                tls_key = Some(PathBuf::from(take_value(
                    inline_value,
                    &mut args,
                    "--tls-key",
                )?));
            }
            "--password-file" => {
                if password_file_set {
                    return Err(CliError::DuplicateOption("--password-file"));
                }
                password_file_set = true;
                password_file = Some(PathBuf::from(take_value(
                    inline_value,
                    &mut args,
                    "--password-file",
                )?));
            }
            "--auth" => {
                if auth_mode_set {
                    return Err(CliError::DuplicateOption("--auth"));
                }
                auth_mode_set = true;
                let value = take_value(inline_value, &mut args, "--auth")?;
                auth_mode = parse_auth_mode(&value)?;
            }
            "--daemonize" | "--foreground" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                if daemonize_set {
                    return Err(CliError::DuplicateOption("--daemonize/--foreground"));
                }
                daemonize_set = true;
                daemonize = name == "--daemonize";
            }
            "--log-file" => {
                if log_file_set {
                    return Err(CliError::DuplicateOption("--log-file"));
                }
                log_file_set = true;
                log_file = Some(PathBuf::from(take_value(
                    inline_value,
                    &mut args,
                    "--log-file",
                )?));
            }
            "--log-target" => {
                if cli_log_target.is_some() {
                    return Err(CliError::DuplicateOption("--log-target"));
                }
                cli_log_target = Some(parse_log_target(&take_value(
                    inline_value,
                    &mut args,
                    "--log-target",
                )?)?);
            }
            "--log-max-size" => {
                if cli_log_max_size.is_some() {
                    return Err(CliError::DuplicateOption("--log-max-size"));
                }
                let value = take_value(inline_value, &mut args, "--log-max-size")?;
                let size = parse_log_size(&value)?;
                if size == 0 {
                    return Err(CliError::IncompatibleOptions(
                        "--log-max-size must be a positive byte count",
                    ));
                }
                cli_log_max_size = Some(size);
            }
            "--log-max-rotations" => {
                if cli_log_max_rotations.is_some() {
                    return Err(CliError::DuplicateOption("--log-max-rotations"));
                }
                let value = take_value(inline_value, &mut args, "--log-max-rotations")?;
                cli_log_max_rotations = Some(value.parse::<usize>().map_err(|_| {
                    CliError::IncompatibleOptions(
                        "--log-max-rotations must be a non-negative integer",
                    )
                })?);
            }
            "--pid-file" => {
                if pid_file_set {
                    return Err(CliError::DuplicateOption("--pid-file"));
                }
                pid_file_set = true;
                pid_file = Some(PathBuf::from(take_value(
                    inline_value,
                    &mut args,
                    "--pid-file",
                )?));
            }
            "--enable-input" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                if enable_input_set {
                    return Err(CliError::DuplicateOption("--enable-input"));
                }
                enable_input_set = true;
                enable_input = true;
            }
            "--disable-input" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                if enable_input_set {
                    return Err(CliError::DuplicateOption("--enable-input/--disable-input"));
                }
                enable_input_set = true;
                enable_input = false;
            }
            "--enable-cursor" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                if enable_cursor_set {
                    return Err(CliError::DuplicateOption(
                        "--enable-cursor/--disable-cursor",
                    ));
                }
                enable_cursor_set = true;
                enable_cursor = true;
            }
            "--disable-cursor" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                if enable_cursor_set {
                    return Err(CliError::DuplicateOption(
                        "--enable-cursor/--disable-cursor",
                    ));
                }
                enable_cursor_set = true;
                enable_cursor = false;
            }
            "--enable-clipboard" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                if enable_clipboard_set {
                    return Err(CliError::DuplicateOption("--enable-clipboard"));
                }
                enable_clipboard_set = true;
                enable_clipboard = true;
            }
            "--disable-clipboard" => {
                if inline_value.is_some() {
                    return Err(CliError::UnknownArgument(raw));
                }
                if enable_clipboard_set {
                    return Err(CliError::DuplicateOption(
                        "--enable-clipboard/--disable-clipboard",
                    ));
                }
                enable_clipboard_set = true;
                enable_clipboard = false;
            }
            "--encodings" => {
                if encodings_set {
                    return Err(CliError::DuplicateOption("--encodings"));
                }
                encodings_set = true;
                encodings = Some(parse_encodings(&take_value(
                    inline_value,
                    &mut args,
                    "--encodings",
                )?)?);
            }
            _ => return Err(CliError::UnknownArgument(raw)),
        }
    }

    let selected_config = config_path.clone().or_else(default_config_path);
    let file_config = match selected_config.as_ref() {
        Some(path) => match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str::<FileConfig>(&text)
                .map_err(|error| CliError::ConfigFile(format!("{}: {error}", path.display())))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !config_path_set => {
                FileConfig::default()
            }
            Err(error) => return Err(CliError::ConfigFile(format!("{}: {error}", path.display()))),
        },
        None => FileConfig::default(),
    };

    if !listen_set {
        if let Some(value) = file_config.listen {
            listen = value.parse().map_err(|_| CliError::InvalidListen(value))?;
        }
    }
    if !port_set {
        if let Some(value) = file_config.port {
            if value == 0 {
                return Err(CliError::InvalidPort("0".to_string()));
            }
            port = value;
        }
    }
    if !capture_probe_set {
        capture_probe = file_config.capture_probe;
    }
    if !enable_input_set {
        enable_input = file_config.enable_input.unwrap_or(false);
    }
    if !enable_cursor_set {
        enable_cursor = file_config.enable_cursor.unwrap_or(false);
    }
    if !enable_clipboard_set {
        enable_clipboard = file_config.enable_clipboard.unwrap_or(false);
    }
    if !encodings_set {
        encodings = file_config
            .encodings
            .map(|values| parse_encodings(&values.join(",")))
            .transpose()?;
    }
    if !tls_cert_set {
        tls_cert = file_config.tls_cert;
    }
    if !tls_key_set {
        tls_key = file_config.tls_key;
    }
    if !password_file_set {
        password_file = file_config.password_file;
    }
    if !auth_mode_set {
        if let Some(value) = file_config.auth_mode {
            auth_mode = parse_auth_mode(&value)?;
        }
    }
    if !daemonize_set {
        daemonize = file_config.daemonize.unwrap_or(false);
    }
    if !log_file_set {
        log_file = file_config.log_file;
    }
    if !pid_file_set {
        pid_file = file_config.pid_file;
    }
    let configured_log_max_size = file_config
        .log_max_size
        .map(|value| match value {
            ConfigLogSize::Bytes(bytes) => Ok(bytes),
            ConfigLogSize::Unit(value) => parse_log_size(&value),
        })
        .transpose()?;
    let log_max_size = cli_log_max_size
        .or(configured_log_max_size)
        .unwrap_or(DEFAULT_LOG_MAX_SIZE);
    let log_max_rotations = cli_log_max_rotations
        .or(file_config.log_max_rotations)
        .unwrap_or(10);
    let log_target = match cli_log_target {
        Some(target) => target,
        None if log_file_set => LogTarget::File,
        None => match file_config.log_target.as_deref() {
            Some(target) => parse_log_target(target)?,
            None if log_file.is_some() => LogTarget::File,
            None => LogTarget::Stderr,
        },
    };
    if cli_log_target.is_some() && log_target != LogTarget::File && !log_file_set {
        log_file = None;
    }
    if let Some(base) = selected_config.as_ref().and_then(|path| path.parent()) {
        if !capture_probe_set {
            resolve_relative(&mut capture_probe, base);
        }
        if !tls_cert_set {
            resolve_relative(&mut tls_cert, base);
        }
        if !tls_key_set {
            resolve_relative(&mut tls_key, base);
        }
        if !password_file_set {
            resolve_relative(&mut password_file, base);
        }
        if !log_file_set {
            resolve_relative(&mut log_file, base);
        }
        if !pid_file_set {
            resolve_relative(&mut pid_file, base);
        }
    }

    if stop_requested {
        let pid_file =
            pid_file
                .or_else(default_pid_file_path)
                .ok_or(CliError::IncompatibleOptions(
                    "cannot determine PID file; set XDG_RUNTIME_DIR, HOME, or --pid-file",
                ))?;
        return Ok(Command::Stop(pid_file));
    }

    let any_credential_setting = tls_cert.is_some() || tls_key.is_some() || password_file.is_some();
    if auth_mode == AuthMode::VeNCrypt
        && any_credential_setting
        && (tls_cert.is_none() || tls_key.is_none() || password_file.is_none())
    {
        return Err(CliError::IncompatibleOptions(
            "VeNCrypt authentication requires tls_cert, tls_key, and password_file together",
        ));
    }
    if auth_mode == AuthMode::Vnc && password_file.is_none() {
        return Err(CliError::IncompatibleOptions(
            "VNC authentication requires password_file",
        ));
    }
    if auth_mode == AuthMode::AppleDh && password_file.is_none() {
        return Err(CliError::IncompatibleOptions(
            "Apple DH authentication requires password_file",
        ));
    }

    if capture_probe.is_some() && (enable_input || enable_clipboard || enable_cursor) {
        return Err(CliError::IncompatibleOptions(
            "--enable-input, --enable-clipboard, and --enable-cursor require server mode and cannot be used with --capture-probe",
        ));
    }
    if capture_probe.is_some() && daemonize {
        return Err(CliError::IncompatibleOptions(
            "--daemonize cannot be used with --capture-probe",
        ));
    }
    match log_target {
        LogTarget::File if log_file.is_none() => {
            return Err(CliError::IncompatibleOptions(
                "file logging requires log_file or --log-file",
            ));
        }
        LogTarget::Stderr | LogTarget::Journald if log_file.is_some() => {
            return Err(CliError::IncompatibleOptions(
                "log_file requires the file log target",
            ));
        }
        LogTarget::File | LogTarget::Stderr | LogTarget::Journald => {}
    }
    if log_max_size == 0 {
        return Err(CliError::IncompatibleOptions(
            "log_max_size must be a positive byte count",
        ));
    }
    if log_target != LogTarget::File
        && (cli_log_max_size.is_some()
            || configured_log_max_size.is_some()
            || cli_log_max_rotations.is_some()
            || file_config.log_max_rotations.is_some())
    {
        return Err(CliError::IncompatibleOptions(
            "log rotation requires the file log target",
        ));
    }

    Ok(Command::Run(Config {
        listen,
        port,
        capture_probe,
        enable_input,
        enable_cursor,
        enable_clipboard,
        encodings,
        tls_cert,
        tls_key,
        password_file,
        auth_mode,
        daemonize,
        log_file,
        log_target,
        log_max_size,
        log_max_rotations,
        pid_file: pid_file.or_else(default_pid_file_path),
        config_file: selected_config.filter(|path| path.exists()),
    }))
}

fn parse_encodings(value: &str) -> Result<Vec<RfbEncoding>, CliError> {
    if value.is_empty() {
        return Err(CliError::EmptyValue("--encodings"));
    }
    let mut encodings = Vec::new();
    for item in value.split(',') {
        let encoding = RfbEncoding::parse(item).ok_or({
            CliError::IncompatibleOptions(
                "invalid encoding; expected raw, hextile, zlib, zrle, or copyrect",
            )
        })?;
        if encodings.contains(&encoding) {
            return Err(CliError::IncompatibleOptions(
                "encoding list contains a duplicate entry",
            ));
        }
        encodings.push(encoding);
    }
    if !encodings.contains(&RfbEncoding::Raw) {
        return Err(CliError::IncompatibleOptions(
            "encoding list must include raw as a fallback",
        ));
    }
    Ok(encodings)
}

fn default_config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(path).join("rvncserver/config.json"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/rvncserver/config.json"))
}

fn default_pid_file_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(path).join("rvncserver.pid"));
    }
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    state_home.map(|path| path.join("rvncserver/rvncserver.pid"))
}

fn parse_auth_mode(value: &str) -> Result<AuthMode, CliError> {
    match value {
        "vencrypt" => Ok(AuthMode::VeNCrypt),
        "vnc" => Ok(AuthMode::Vnc),
        "apple-dh" => Ok(AuthMode::AppleDh),
        _ => Err(CliError::IncompatibleOptions(
            "invalid auth mode; expected vencrypt, vnc, or apple-dh",
        )),
    }
}

fn parse_log_target(value: &str) -> Result<LogTarget, CliError> {
    match value {
        "file" => Ok(LogTarget::File),
        "journald" => Ok(LogTarget::Journald),
        "stderr" => Ok(LogTarget::Stderr),
        _ => Err(CliError::IncompatibleOptions(
            "invalid log target; expected stderr, file, or journald",
        )),
    }
}

fn parse_log_size(value: &str) -> Result<u64, CliError> {
    let value = value.trim();
    let split_at = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    if split_at == 0 {
        return Err(CliError::IncompatibleOptions(
            "log size must be a positive integer with optional B, KB, MB, or GB suffix",
        ));
    }
    let number = value[..split_at].parse::<u64>().map_err(|_| {
        CliError::IncompatibleOptions("log size is outside the supported integer range")
    })?;
    let suffix = value[split_at..].trim().to_ascii_uppercase();
    let multiplier = match suffix.as_str() {
        "" | "B" => 1,
        "KB" => 1024,
        "MB" => 1024 * 1024,
        "GB" => 1024 * 1024 * 1024,
        _ => {
            return Err(CliError::IncompatibleOptions(
                "unsupported log size unit; use B, KB, MB, or GB",
            ));
        }
    };
    let bytes = number
        .checked_mul(multiplier)
        .ok_or(CliError::IncompatibleOptions(
            "log size is outside the supported integer range",
        ))?;
    if bytes == 0 {
        return Err(CliError::IncompatibleOptions(
            "log size must be greater than zero",
        ));
    }
    Ok(bytes)
}

fn resolve_relative(path: &mut Option<PathBuf>, base: &std::path::Path) {
    if let Some(path) = path {
        if path.is_relative() {
            *path = base.join(&*path);
        }
    }
}

fn take_value<I>(
    inline: Option<String>,
    args: &mut I,
    option: &'static str,
) -> Result<String, CliError>
where
    I: Iterator<Item = OsString>,
{
    let value = match inline {
        Some(value) => value,
        None => args
            .next()
            .ok_or(CliError::MissingValue(option))?
            .into_string()
            .map_err(|_| CliError::InvalidUtf8)?,
    };

    if value.is_empty() {
        return Err(CliError::EmptyValue(option));
    }

    Ok(value)
}

/// Return the help text shown by `--help`.
pub fn help_text() -> String {
    format!(
        "rvncserver {version}
A lightweight VNC server for Wayland desktops.

Usage: rvncserver [OPTIONS]

Options:
  --listen <ADDRESS>       IP address to bind (default: 127.0.0.1)
  --port <PORT>            TCP port to bind (default: 5900)
  --capture-probe <PATH>   Capture one frame to a PPM file and exit
  --config <PATH>          Load JSON settings (default: ~/.config/rvncserver/config.json)
  --tls-cert <PATH>        TLS server certificate PEM for VeNCrypt
  --tls-key <PATH>         TLS private key PEM
  --password-file <PATH>   Authentication credentials file (owner-only permissions)
  --auth <MODE>            Authentication: vencrypt (default), vnc, or apple-dh
  --daemonize              Detach from the terminal and run in the background
  --foreground             Override daemonize=true from JSON
  --pid-file <PATH>        PID file for daemon control (default: XDG runtime dir)
  --stop                   Request graceful shutdown of the daemon
  --log-file <PATH>        Append stdout and stderr to this file
  --log-target <TARGET>    Log destination: stderr (default), file, or journald
  --log-max-size <SIZE>    Rotate file logs at this size (default: 50MB)
                           Supports B, KB, MB, GB; bare numbers are bytes
  --log-max-rotations <N>  Number of compressed rotated logs to keep (default: 10)
  --enable-input           Request portal permission for keyboard/pointer control
  --disable-input          Disable keyboard/pointer control from the config file
  --enable-cursor          Send cursor shape/position separately to VNC clients
  --disable-cursor         Disable separate cursor updates from the config file
  --enable-clipboard       Request portal permission for clipboard sharing
  --disable-clipboard      Disable clipboard sharing from the config file
  --encodings <LIST>       Allowed encodings, comma-separated (must include raw)
  -h, --help               Print this help
  -V, --version            Print the application version

The captured screen source is selected in the desktop portal dialog.
Input and clipboard are disabled unless explicitly enabled. VeNCrypt is the
secure default; VNC mode uses weak DES and does not encrypt traffic.
The default address is loopback only.
In capture-probe mode, --listen and --port are accepted but unused.
",
        version = env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, CliError> {
        if args
            .iter()
            .any(|argument| argument.starts_with("--config="))
            || args.contains(&"--config")
        {
            return parse_args(args.iter().map(|argument| OsString::from(*argument)));
        }

        let config_path = std::env::temp_dir().join(format!(
            "rvncserver-empty-config-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&config_path, "{}").unwrap();
        let mut isolated_args = vec![
            OsString::from("--config"),
            config_path.as_os_str().to_owned(),
        ];
        isolated_args.extend(args.iter().map(OsString::from));
        let result = parse_args(isolated_args);
        fs::remove_file(config_path).unwrap();
        result
    }

    fn config(args: &[&str]) -> Config {
        match parse(args) {
            Ok(Command::Run(config)) => config,
            other => panic!("expected Run command, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_loopback_and_5900() {
        let config = config(&[]);
        assert_eq!(config.listen, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(config.port, 5900);
        assert_eq!(config.capture_probe, None);
        assert!(!config.enable_input);
        assert!(!config.enable_cursor);
        assert!(!config.enable_clipboard);
        assert_eq!(config.encodings, None);
        assert!(config.tls_cert.is_none());
        assert!(config.tls_key.is_none());
        assert!(config.password_file.is_none());
        assert_eq!(config.auth_mode, AuthMode::VeNCrypt);
        assert!(!config.daemonize);
        assert!(config.log_file.is_none());
        assert_eq!(config.log_target, LogTarget::Stderr);
        assert_eq!(config.log_max_size, 50 * 1024 * 1024);
        assert_eq!(config.log_max_rotations, 10);
    }

    #[test]
    fn parses_separate_values() {
        let config = config(&["--listen", "0.0.0.0", "--port", "5901"]);
        assert_eq!(config.listen, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(config.port, 5901);
    }

    #[test]
    fn parses_inline_values() {
        let config = config(&["--listen=::1", "--port=6000"]);
        assert_eq!(config.listen, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(config.port, 6000);
    }

    #[test]
    fn parses_capture_probe_path() {
        let config = config(&["--capture-probe", "/tmp/capture.ppm"]);
        assert_eq!(
            config.capture_probe,
            Some(PathBuf::from("/tmp/capture.ppm"))
        );
    }

    #[test]
    fn parses_input_and_clipboard_flags() {
        let selected = config(&["--enable-input", "--enable-clipboard", "--enable-cursor"]);
        assert!(selected.enable_input);
        assert!(selected.enable_clipboard);
        assert!(selected.enable_cursor);
        assert!(parse(&["--enable-cursor", "--disable-cursor"]).is_err());
    }

    #[test]
    fn parses_daemon_and_log_options() {
        let selected = config(&["--daemonize", "--log-file", "/tmp/rvncserver.log"]);
        assert!(selected.daemonize);
        assert_eq!(
            selected.log_file,
            Some(PathBuf::from("/tmp/rvncserver.log"))
        );
        assert_eq!(
            parse(&["--daemonize", "--foreground"]),
            Err(CliError::DuplicateOption("--daemonize/--foreground"))
        );
    }

    #[test]
    fn parses_stop_and_pid_file_options() {
        assert_eq!(
            parse(&["--stop", "--pid-file", "/tmp/rvncserver.pid"]),
            Ok(Command::Stop(PathBuf::from("/tmp/rvncserver.pid")))
        );
        assert_eq!(
            config(&["--pid-file", "/tmp/rvncserver.pid"]).pid_file,
            Some(PathBuf::from("/tmp/rvncserver.pid"))
        );
        assert_eq!(
            parse(&["--stop", "--stop"]),
            Err(CliError::DuplicateOption("--stop"))
        );
    }

    #[test]
    fn parses_and_validates_log_targets() {
        assert_eq!(
            config(&["--log-target", "journald"]).log_target,
            LogTarget::Journald
        );
        assert_eq!(
            config(&["--log-target", "file", "--log-file", "/tmp/server.log"]).log_target,
            LogTarget::File
        );
        assert!(parse(&["--log-target", "file"]).is_err());
        assert!(parse(&["--log-target", "journald", "--log-file", "/tmp/server.log"]).is_err());
    }

    #[test]
    fn parses_and_validates_log_rotation_options() {
        let selected = config(&[
            "--log-file",
            "/tmp/rvncserver.log",
            "--log-max-size",
            "1MB",
            "--log-max-rotations",
            "3",
        ]);
        assert_eq!(selected.log_max_size, 1024 * 1024);
        assert_eq!(selected.log_max_rotations, 3);

        for (value, expected) in [
            ("2GB", 2 * 1024 * 1024 * 1024),
            ("3MB", 3 * 1024 * 1024),
            ("4KB", 4 * 1024),
            ("5B", 5),
            ("6", 6),
        ] {
            assert_eq!(parse_log_size(value).unwrap(), expected);
        }
        assert!(parse_log_size("1TB").is_err());
        assert!(parse_log_size("0MB").is_err());

        assert!(parse(&["--log-max-size", "100"]).is_err());
        assert!(parse(&["--log-file", "/tmp/rvncserver.log", "--log-max-size", "0"]).is_err());
    }

    #[test]
    fn parses_encoding_allowlist_and_requires_raw_fallback() {
        assert_eq!(
            config(&["--encodings=raw,zrle"]).encodings.unwrap(),
            [RfbEncoding::Raw, RfbEncoding::Zrle]
        );
        assert_eq!(
            parse(&["--encodings", "zlib"]),
            Err(CliError::IncompatibleOptions(
                "encoding list must include raw as a fallback"
            ))
        );
        assert_eq!(
            parse(&["--encodings", "raw,unknown"]),
            Err(CliError::IncompatibleOptions(
                "invalid encoding; expected raw, hextile, zlib, zrle, or copyrect"
            ))
        );
    }

    #[test]
    fn selects_vnc_authentication_mode() {
        let selected = config(&["--auth", "vnc", "--password-file", "/tmp/pass"]);
        assert_eq!(selected.auth_mode, AuthMode::Vnc);
        assert_eq!(
            config(&["--auth", "vencrypt"]).auth_mode,
            AuthMode::VeNCrypt
        );
        assert_eq!(
            parse(&["--auth", "vnc"]),
            Err(CliError::IncompatibleOptions(
                "VNC authentication requires password_file"
            ))
        );
    }

    #[test]
    fn selects_apple_dh_authentication_mode() {
        assert_eq!(
            config(&["--auth", "apple-dh", "--password-file", "/tmp/credentials"]).auth_mode,
            AuthMode::AppleDh
        );
        assert!(parse(&["--auth", "apple-dh"]).is_err());
    }

    #[test]
    fn rejects_input_options_with_capture_probe() {
        assert_eq!(
            parse(&["--capture-probe", "/tmp/frame.ppm", "--enable-input"]),
            Err(CliError::IncompatibleOptions(
                "--enable-input, --enable-clipboard, and --enable-cursor require server mode and cannot be used with --capture-probe"
            ))
        );
        assert!(parse(&["--capture-probe", "/tmp/frame.ppm", "--enable-cursor"]).is_err());
    }

    #[test]
    fn loads_json_settings_and_cli_values_override_them() {
        let path = std::env::temp_dir().join(format!(
            "rvncserver-config-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::write(
            &path,
            r#"{"listen":"0.0.0.0","port":5901,"enable_input":true,"enable_cursor":true,"enable_clipboard":true,"auth_mode":"vnc","tls_cert":"cert.pem","tls_key":"key.pem","password_file":"credentials.txt","encodings":["raw","zrle"],"daemonize":true,"log_file":"rvncserver.log","log_max_size":"2MB","log_max_rotations":2}"#,
        )
        .unwrap();
        let path_argument = path.to_string_lossy().into_owned();
        let loaded = config(&["--config", &path_argument, "--port", "5902"]);
        assert_eq!(loaded.listen, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(loaded.port, 5902);
        assert!(loaded.enable_input);
        assert!(loaded.enable_cursor);
        assert!(loaded.enable_clipboard);
        assert_eq!(
            loaded.encodings,
            Some(vec![RfbEncoding::Raw, RfbEncoding::Zrle])
        );
        assert_eq!(
            config(&["--config", &path_argument, "--encodings", "raw"]).encodings,
            Some(vec![RfbEncoding::Raw])
        );
        assert_eq!(loaded.auth_mode, AuthMode::Vnc);
        assert!(loaded.daemonize);
        assert_eq!(
            loaded.log_file,
            Some(path.parent().unwrap().join("rvncserver.log"))
        );
        assert_eq!(loaded.log_max_size, 2 * 1024 * 1024);
        assert_eq!(loaded.log_max_rotations, 2);
        assert!(!config(&["--config", &path_argument, "--foreground"]).daemonize);
        assert_eq!(
            loaded.password_file,
            Some(PathBuf::from("/tmp/credentials.txt"))
        );
        assert_eq!(
            config(&["--config", &path_argument, "--auth", "vencrypt"]).auth_mode,
            AuthMode::VeNCrypt
        );
        assert_eq!(loaded.config_file, Some(path.clone()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_unknown_json_settings() {
        let path =
            std::env::temp_dir().join(format!("rvncserver-bad-config-{}.json", std::process::id()));
        fs::write(&path, r#"{"unknown":true}"#).unwrap();
        let result = parse(&["--config", &path.to_string_lossy()]);
        assert!(matches!(result, Err(CliError::ConfigFile(_))));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_help_and_version() {
        assert_eq!(parse(&["--help"]), Ok(Command::Help));
        assert_eq!(parse(&["-h"]), Ok(Command::Help));
        assert_eq!(parse(&["--version"]), Ok(Command::Version));
        assert_eq!(parse(&["-V"]), Ok(Command::Version));
    }

    #[test]
    fn rejects_unknown_arguments() {
        assert_eq!(
            parse(&["--unknown"]),
            Err(CliError::UnknownArgument("--unknown".to_string()))
        );
        assert_eq!(
            parse(&["positional"]),
            Err(CliError::UnknownArgument("positional".to_string()))
        );
    }

    #[test]
    fn rejects_missing_values() {
        assert_eq!(
            parse(&["--listen"]),
            Err(CliError::MissingValue("--listen"))
        );
        assert_eq!(parse(&["--port"]), Err(CliError::MissingValue("--port")));
        assert_eq!(
            parse(&["--capture-probe"]),
            Err(CliError::MissingValue("--capture-probe"))
        );
    }

    #[test]
    fn rejects_empty_values() {
        assert_eq!(parse(&["--listen="]), Err(CliError::EmptyValue("--listen")));
        assert_eq!(parse(&["--port="]), Err(CliError::EmptyValue("--port")));
        assert_eq!(
            parse(&["--capture-probe="]),
            Err(CliError::EmptyValue("--capture-probe"))
        );
    }

    #[test]
    fn rejects_invalid_ports() {
        assert_eq!(
            parse(&["--port", "0"]),
            Err(CliError::InvalidPort("0".to_string()))
        );
        assert_eq!(
            parse(&["--port", "65536"]),
            Err(CliError::InvalidPort("65536".to_string()))
        );
        assert_eq!(
            parse(&["--port", "abc"]),
            Err(CliError::InvalidPort("abc".to_string()))
        );
    }

    #[test]
    fn rejects_invalid_listen_addresses() {
        assert_eq!(
            parse(&["--listen", "localhost"]),
            Err(CliError::InvalidListen("localhost".to_string()))
        );
        assert_eq!(
            parse(&["--listen", "127.0.0.1:5900"]),
            Err(CliError::InvalidListen("127.0.0.1:5900".to_string()))
        );
    }

    #[test]
    fn rejects_duplicate_options() {
        assert_eq!(
            parse(&["--port", "5900", "--port", "5901"]),
            Err(CliError::DuplicateOption("--port"))
        );
        assert_eq!(
            parse(&["--listen", "127.0.0.1", "--listen=::1"]),
            Err(CliError::DuplicateOption("--listen"))
        );
        assert_eq!(
            parse(&[
                "--capture-probe",
                "/tmp/a.ppm",
                "--capture-probe",
                "/tmp/b.ppm"
            ]),
            Err(CliError::DuplicateOption("--capture-probe"))
        );
        assert_eq!(
            parse(&["--enable-input", "--enable-input"]),
            Err(CliError::DuplicateOption("--enable-input"))
        );
        assert_eq!(
            parse(&["--enable-clipboard", "--enable-clipboard"]),
            Err(CliError::DuplicateOption("--enable-clipboard"))
        );
    }

    #[test]
    fn rejects_values_on_flags() {
        assert_eq!(
            parse(&["--help=yes"]),
            Err(CliError::UnknownArgument("--help=yes".to_string()))
        );
        assert_eq!(
            parse(&["--version=1"]),
            Err(CliError::UnknownArgument("--version=1".to_string()))
        );
    }
}

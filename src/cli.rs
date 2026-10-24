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
    /// Request portal permission for bidirectional clipboard sharing.
    pub enable_clipboard: bool,
    /// TLS server certificate PEM path.
    pub tls_cert: Option<PathBuf>,
    /// TLS server private-key PEM path.
    pub tls_key: Option<PathBuf>,
    /// Restrictive-permission file containing the VeNCrypt username/password.
    pub password_file: Option<PathBuf>,
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: Option<String>,
    port: Option<u16>,
    capture_probe: Option<PathBuf>,
    enable_input: Option<bool>,
    enable_clipboard: Option<bool>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    password_file: Option<PathBuf>,
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
    let mut enable_clipboard = false;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut password_file = None;
    let mut config_path = None;

    let mut listen_set = false;
    let mut port_set = false;
    let mut capture_probe_set = false;
    let mut enable_input_set = false;
    let mut enable_clipboard_set = false;
    let mut tls_cert_set = false;
    let mut tls_key_set = false;
    let mut password_file_set = false;
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
    if !enable_clipboard_set {
        enable_clipboard = file_config.enable_clipboard.unwrap_or(false);
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
    }

    let any_tls_setting = tls_cert.is_some() || tls_key.is_some() || password_file.is_some();
    if any_tls_setting && (tls_cert.is_none() || tls_key.is_none() || password_file.is_none()) {
        return Err(CliError::IncompatibleOptions(
            "TLS authentication requires tls_cert, tls_key, and password_file together",
        ));
    }

    if capture_probe.is_some() && (enable_input || enable_clipboard) {
        return Err(CliError::IncompatibleOptions(
            "--enable-input and --enable-clipboard require server mode and cannot be used with --capture-probe",
        ));
    }

    Ok(Command::Run(Config {
        listen,
        port,
        capture_probe,
        enable_input,
        enable_clipboard,
        tls_cert,
        tls_key,
        password_file,
        config_file: selected_config.filter(|path| path.exists()),
    }))
}

fn default_config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(path).join("rvncserver/config.json"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/rvncserver/config.json"))
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
  --tls-cert <PATH>        TLS server certificate PEM (enables VeNCrypt/TLSPlain)
  --tls-key <PATH>         TLS private key PEM
  --password-file <PATH>   Username/password file (restrict permissions to owner)
  --enable-input           Request portal permission for keyboard/pointer control
  --disable-input          Disable keyboard/pointer control from the config file
  --enable-clipboard       Request portal permission for clipboard sharing
  --disable-clipboard      Disable clipboard sharing from the config file
  -h, --help               Print this help
  -V, --version            Print the application version

The captured screen source is selected in the desktop portal dialog.
Input and clipboard are disabled unless explicitly enabled. TLS authentication
is enabled only when all three TLS paths are configured.
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
        parse_args(args.iter().map(|argument| OsString::from(*argument)))
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
        assert!(!config.enable_clipboard);
        assert!(config.tls_cert.is_none());
        assert!(config.tls_key.is_none());
        assert!(config.password_file.is_none());
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
        let config = config(&["--enable-input", "--enable-clipboard"]);
        assert!(config.enable_input);
        assert!(config.enable_clipboard);
    }

    #[test]
    fn rejects_input_options_with_capture_probe() {
        assert_eq!(
            parse(&["--capture-probe", "/tmp/frame.ppm", "--enable-input"]),
            Err(CliError::IncompatibleOptions(
                "--enable-input and --enable-clipboard require server mode and cannot be used with --capture-probe"
            ))
        );
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
            r#"{"listen":"0.0.0.0","port":5901,"enable_input":true,"enable_clipboard":true}"#,
        )
        .unwrap();
        let path_argument = path.to_string_lossy().into_owned();
        let loaded = config(&["--config", &path_argument, "--port", "5902"]);
        assert_eq!(loaded.listen, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(loaded.port, 5902);
        assert!(loaded.enable_input);
        assert!(loaded.enable_clipboard);
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

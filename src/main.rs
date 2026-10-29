//! Command-line entry point.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use rvncserver::capture::{CaptureConfig, CaptureSession};
use rvncserver::cli::{self, AuthMode, Command, Config, LogTarget, RfbEncoding};
use rvncserver::error::AppError;
use rvncserver::server;

const CAPTURE_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

fn main() -> ExitCode {
    let command = match cli::parse_args(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            rvncserver::timestamped_log!("rvncserver: {error}\n");
            eprint!("{}", cli::help_text());
            return ExitCode::from(2);
        }
    };

    match command {
        Command::Help => {
            print!("{}", cli::help_text());
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("rvncserver {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Stop(pid_file) => match stop_daemon(&pid_file) {
            Ok(true) => {
                println!("rvncserver: stop requested; daemon exited");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                println!("rvncserver: no daemon is running");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("rvncserver: could not stop daemon: {error}");
                ExitCode::FAILURE
            }
        },
        Command::Status(pid_file) => match daemon_status(&pid_file) {
            Ok(DaemonStatus::Running { pid, config }) => {
                println!("rvncserver: running (PID {pid})");
                match config {
                    Some(config) => println!("Active configuration:\n{config}"),
                    None => println!("Active configuration is not available."),
                }
                ExitCode::SUCCESS
            }
            Ok(DaemonStatus::Starting) => {
                println!("rvncserver: starting (PID file is reserved; PID not recorded yet)");
                ExitCode::from(2)
            }
            Ok(DaemonStatus::Stopped) => {
                println!("rvncserver: not running");
                ExitCode::from(1)
            }
            Err(error) => {
                eprintln!("rvncserver: could not determine daemon status: {error}");
                ExitCode::FAILURE
            }
        },
        Command::Run(config) => match configure_process(&config) {
            Ok(ProcessSetup::DaemonParent(pid)) => {
                rvncserver::timestamped_log!("rvncserver: daemon started with pid {pid}");
                ExitCode::SUCCESS
            }
            Ok(ProcessSetup::Run(_pid_file_guard)) => {
                match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => match runtime.block_on(run_server(config)) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(error) => report_error(error),
                    },
                    Err(error) => {
                        rvncserver::timestamped_log!(
                            "rvncserver: failed to initialize runtime: {error}"
                        );
                        ExitCode::FAILURE
                    }
                }
            }
            Err(error) => {
                rvncserver::timestamped_log!("rvncserver: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn report_error(error: AppError) -> ExitCode {
    if let AppError::Cli(error) = error {
        rvncserver::timestamped_log!("rvncserver: {error}\n");
        eprint!("{}", cli::help_text());
        ExitCode::from(2)
    } else {
        rvncserver::timestamped_log!("rvncserver: {error}");
        ExitCode::FAILURE
    }
}

async fn run_server(config: Config) -> Result<(), AppError> {
    if let Some(path) = config.capture_probe.clone() {
        let mut capture = CaptureSession::start(CaptureConfig::default()).await?;
        rvncserver::timestamped_log!("capture: waiting for the first frame...");
        let captured = capture
            .wait_for_first_frame(CAPTURE_PROBE_TIMEOUT, false)
            .await?;
        captured.frame.write_ppm(&path)?;
        rvncserver::timestamped_log!(
            "capture: wrote {}x{} frame to {}",
            captured.frame.width,
            captured.frame.height,
            path.display()
        );
        capture.shutdown();
        Ok(())
    } else {
        server::run(config).await
    }
}

/// Configure logging output and optionally detach before Tokio creates threads.
fn configure_process(config: &Config) -> io::Result<ProcessSetup> {
    if config.daemonize && config.pid_file.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot determine PID file; set XDG_RUNTIME_DIR, HOME, or --pid-file",
        ));
    }
    if !config.daemonize {
        match config.log_target {
            LogTarget::Stderr => return Ok(ProcessSetup::Run(None)),
            LogTarget::File => {
                let path = config.log_file.as_deref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "file log target requires a path",
                    )
                })?;
                rvncserver::logging::use_rotating_file(
                    path,
                    config.log_max_size,
                    config.log_max_rotations,
                )?;
                return Ok(ProcessSetup::Run(None));
            }
            LogTarget::Journald => {
                rvncserver::logging::use_journald();
                return Ok(ProcessSetup::Run(None));
            }
        }
    }

    let pid_file_path = config.pid_file.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot determine PID file; set XDG_RUNTIME_DIR, HOME, or --pid-file",
        )
    })?;
    // Reserve the PID file before forking. A second launch then fails in its
    // original process instead of reporting success while its child exits.
    let pid_file_reservation = PidFileReservation::acquire(pid_file_path)?;

    let output = match config.log_target {
        LogTarget::File => {
            let path = config.log_file.as_deref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file log target requires a path",
                )
            })?;
            open_log_file(path)?
        }
        LogTarget::Stderr | LogTarget::Journald => {
            OpenOptions::new().write(true).open("/dev/null")?
        }
    };

    // SAFETY: fork is performed before Tokio or any worker threads are started.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        return Ok(ProcessSetup::DaemonParent(pid));
    }

    // Child process: redirect diagnostics before operations that may fail.
    redirect_output(output)?;
    let null_input = File::open("/dev/null")?;
    // SAFETY: both descriptors are valid process file descriptors; dup2 only
    // replaces the child's stdin and returns an error if the operation fails.
    if unsafe { libc::dup2(null_input.as_raw_fd(), libc::STDIN_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: this is the single-threaded post-fork child. setsid creates a
    // session and process group for the detached server.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    if config.log_target == LogTarget::Journald {
        rvncserver::logging::use_journald();
    }
    if config.log_target == LogTarget::File {
        let path = config.log_file.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "file log target requires a path",
            )
        })?;
        rvncserver::logging::use_rotating_file(
            path,
            config.log_max_size,
            config.log_max_rotations,
        )?;
    }
    let pid_file_guard = pid_file_reservation.activate(config)?;
    Ok(ProcessSetup::Run(Some(pid_file_guard)))
}

enum ProcessSetup {
    DaemonParent(libc::pid_t),
    Run(Option<PidFileGuard>),
}

struct PidFileGuard {
    path: std::path::PathBuf,
    contents: String,
    _lock_file: File,
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        remove_pid_file_if_matches(&self.path, &self.contents);
    }
}

struct PidFileReservation {
    path: std::path::PathBuf,
    file: File,
}

impl PidFileReservation {
    fn acquire(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        // SAFETY: flock operates on the valid descriptor owned by `file`.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK)
                || error.raw_os_error() == Some(libc::EAGAIN)
            {
                let running_pid = fs::read_to_string(path)
                    .ok()
                    .and_then(|contents| parse_pid_file(&contents).ok())
                    .filter(|(pid, start)| process_start_time(*pid).ok() == Some(*start))
                    .map(|(pid, _)| format!(" (PID {pid})"))
                    .unwrap_or_default();
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("daemon is already running or starting{running_pid}"),
                ));
            }
            return Err(error);
        }

        file.seek(SeekFrom::Start(0))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        if let Ok((pid, start_time)) = parse_pid_file(&contents)
            && process_start_time(pid).ok() == Some(start_time)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("daemon is already running with PID {pid}"),
            ));
        }
        if !contents.is_empty() {
            let _ = fs::remove_file(active_config_path(path));
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    fn activate(mut self, config: &Config) -> io::Result<PidFileGuard> {
        // SAFETY: getpid has no preconditions and returns this process's PID.
        let pid = unsafe { libc::getpid() };
        let start_time = process_start_time(pid)?;
        let contents = format!("{pid}\n{start_time}\n");
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(contents.as_bytes())?;
        self.file.sync_all()?;

        let active_config = active_config_json(config)?;
        let active_config_path = active_config_path(&self.path);
        let mut config_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&active_config_path)?;
        config_file.set_permissions(fs::Permissions::from_mode(0o600))?;
        config_file.write_all(active_config.as_bytes())?;
        config_file.sync_all()?;

        Ok(PidFileGuard {
            path: self.path.clone(),
            contents,
            _lock_file: self.file,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DaemonStatus {
    Stopped,
    Starting,
    Running {
        pid: libc::pid_t,
        config: Option<String>,
    },
}

fn daemon_status(path: &Path) -> io::Result<DaemonStatus> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(DaemonStatus::Stopped),
        Err(error) => return Err(error),
    };

    if let Ok((pid, start_time)) = parse_pid_file(&contents)
        && process_start_time(pid).ok() == Some(start_time)
    {
        let config_path = active_config_path(path);
        let config = match fs::read_to_string(config_path) {
            Ok(text) if serde_json::from_str::<serde_json::Value>(&text).is_ok() => Some(text),
            Ok(_) => None,
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        return Ok(DaemonStatus::Running { pid, config });
    }

    if pid_file_lock_is_held(path)? {
        return Ok(DaemonStatus::Starting);
    }
    if !contents.is_empty() {
        remove_pid_file_if_matches(path, &contents);
    }
    Ok(DaemonStatus::Stopped)
}

fn pid_file_lock_is_held(path: &Path) -> io::Result<bool> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    // SAFETY: flock operates on the valid descriptor owned by `file`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK)
            || error.raw_os_error() == Some(libc::EAGAIN)
        {
            return Ok(true);
        }
        return Err(error);
    }
    // SAFETY: this unlocks the exclusive flock acquired above.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(false)
}

fn active_config_path(pid_file: &Path) -> std::path::PathBuf {
    let mut path = pid_file.as_os_str().to_os_string();
    path.push(".config.json");
    path.into()
}

fn active_config_json(config: &Config) -> io::Result<String> {
    let encodings = config.encodings.as_ref().map(|encodings| {
        encodings
            .iter()
            .map(|encoding| match encoding {
                RfbEncoding::Raw => "raw",
                RfbEncoding::Hextile => "hextile",
                RfbEncoding::Zlib => "zlib",
                RfbEncoding::Zrle => "zrle",
                RfbEncoding::CopyRect => "copyrect",
            })
            .collect::<Vec<_>>()
    });
    let auth_mode = match config.auth_mode {
        AuthMode::VeNCrypt => "vencrypt",
        AuthMode::Vnc => "vnc",
        AuthMode::AppleDh => "apple-dh",
    };
    let log_target = match config.log_target {
        LogTarget::Stderr => "stderr",
        LogTarget::File => "file",
        LogTarget::Journald => "journald",
    };
    let path_value = |path: Option<&Path>| path.map(|path| path.to_string_lossy().into_owned());
    let value = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "listen": config.listen.to_string(),
        "port": config.port,
        "capture_probe": path_value(config.capture_probe.as_deref()),
        "enable_input": config.enable_input,
        "enable_cursor": config.enable_cursor,
        "enable_clipboard": config.enable_clipboard,
        "encodings": encodings,
        "auth_mode": auth_mode,
        "tls_cert": path_value(config.tls_cert.as_deref()),
        "tls_key": path_value(config.tls_key.as_deref()),
        "password_file": path_value(config.password_file.as_deref()),
        "daemonize": config.daemonize,
        "log_target": log_target,
        "log_file": path_value(config.log_file.as_deref()),
        "log_max_size": config.log_max_size,
        "log_max_rotations": config.log_max_rotations,
        "pid_file": path_value(config.pid_file.as_deref()),
        "config_file": path_value(config.config_file.as_deref()),
    });
    serde_json::to_string_pretty(&value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn stop_daemon(path: &Path) -> io::Result<bool> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let (pid, expected_start_time) = parse_pid_file(&contents)?;
    if process_start_time(pid).ok() != Some(expected_start_time) {
        remove_pid_file_if_matches(path, &contents);
        return Ok(false);
    }

    // SAFETY: pid was parsed and validated against /proc; SIGTERM requests a
    // graceful shutdown and does not access memory in this process.
    if unsafe { libc::kill(pid, libc::SIGTERM) } < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            remove_pid_file_if_matches(path, &contents);
            return Ok(false);
        }
        return Err(error);
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if process_start_time(pid).ok() != Some(expected_start_time) {
            remove_pid_file_if_matches(path, &contents);
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("daemon PID {pid} did not exit after SIGTERM"),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn parse_pid_file(contents: &str) -> io::Result<(libc::pid_t, u64)> {
    let mut fields = contents.split_whitespace();
    let pid = fields
        .next()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|pid| *pid > 1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid daemon PID file"))?;
    let start_time = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid daemon PID file"))?;
    Ok((pid, start_time))
}

fn process_start_time(pid: libc::pid_t) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let closing_paren = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proc stat"))?;
    stat[closing_paren + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing process start time"))
}

fn remove_pid_file_if_matches(path: &Path, expected_contents: &str) {
    if fs::read_to_string(path).is_ok_and(|contents| contents == expected_contents) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(active_config_path(path));
    }
}

fn open_log_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

fn redirect_output(output: File) -> io::Result<()> {
    let source_fd = output.as_raw_fd();
    for target_fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: source_fd refers to the open output file and target_fd is a
        // standard output descriptor; dup2 reports any OS-level failure.
        if unsafe { libc::dup2(source_fd, target_fd) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let source_fd = output.into_raw_fd();
    if source_fd > libc::STDERR_FILENO {
        // SAFETY: into_raw_fd transfers ownership, so close source_fd here
        // after stdout/stderr have their own duplicated descriptors.
        if unsafe { libc::close(source_fd) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pid_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rvncserver-main-test-{}-{}.pid",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn pid_file_reservation_rejects_a_second_instance_and_reports_starting() {
        let path = test_pid_path();
        let _ = fs::remove_file(&path);
        let reservation = PidFileReservation::acquire(&path).unwrap();

        assert_eq!(daemon_status(&path).unwrap(), DaemonStatus::Starting);
        let second = match PidFileReservation::acquire(&path) {
            Ok(_) => panic!("second reservation unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(second.kind(), io::ErrorKind::AlreadyExists);

        drop(reservation);
        assert_eq!(daemon_status(&path).unwrap(), DaemonStatus::Stopped);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn status_reads_the_active_config_sidecar_for_a_live_pid() {
        let path = test_pid_path();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(active_config_path(&path));
        let pid = unsafe { libc::getpid() };
        let start_time = process_start_time(pid).unwrap();
        let contents = format!("{pid}\n{start_time}\n");
        fs::write(&path, &contents).unwrap();
        fs::write(active_config_path(&path), "{\"port\": 5901}").unwrap();

        assert_eq!(
            daemon_status(&path).unwrap(),
            DaemonStatus::Running {
                pid,
                config: Some("{\"port\": 5901}".to_string()),
            }
        );
        remove_pid_file_if_matches(&path, &contents);
    }

    #[test]
    fn active_config_snapshot_is_valid_json_and_includes_effective_defaults() {
        let config_path = test_pid_path().with_extension("config.json");
        fs::write(&config_path, "{}").unwrap();
        let command = cli::parse_args([
            std::ffi::OsString::from("--config"),
            config_path.as_os_str().to_owned(),
        ])
        .unwrap();
        fs::remove_file(config_path).unwrap();
        let Command::Run(config) = command else {
            panic!("expected default run configuration");
        };
        let snapshot = active_config_json(&config).unwrap();
        let value: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
        assert_eq!(value["listen"], config.listen.to_string());
        assert_eq!(value["port"], config.port);
        assert_eq!(value["enable_cursor"], config.enable_cursor);
        assert_eq!(value["daemonize"], config.daemonize);
    }
}

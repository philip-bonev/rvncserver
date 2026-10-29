//! Command-line entry point.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use rvncserver::capture::{CaptureConfig, CaptureSession};
use rvncserver::cli::{self, Command, Config, LogTarget};
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
        let frame = capture.wait_for_first_frame(CAPTURE_PROBE_TIMEOUT).await?;
        frame.write_ppm(&path)?;
        rvncserver::timestamped_log!(
            "capture: wrote {}x{} frame to {}",
            frame.width,
            frame.height,
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
    let pid_file_path = config.pid_file.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot determine PID file; set XDG_RUNTIME_DIR, HOME, or --pid-file",
        )
    })?;
    let pid_file_guard = create_pid_file(pid_file_path)?;
    Ok(ProcessSetup::Run(Some(pid_file_guard)))
}

enum ProcessSetup {
    DaemonParent(libc::pid_t),
    Run(Option<PidFileGuard>),
}

struct PidFileGuard {
    path: std::path::PathBuf,
    contents: String,
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        remove_pid_file_if_matches(&self.path, &self.contents);
    }
}

fn create_pid_file(path: &Path) -> io::Result<PidFileGuard> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    // Remove a stale file left behind by a crash, but refuse to replace a live
    // daemon's PID file.
    match fs::read_to_string(path) {
        Ok(contents) => {
            if let Ok((pid, start_time)) = parse_pid_file(&contents)
                && process_start_time(pid).ok() == Some(start_time)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("daemon already appears to be running with PID {pid}"),
                ));
            }
            remove_pid_file_if_matches(path, &contents);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    // SAFETY: getpid has no preconditions and returns this process's PID.
    let pid = unsafe { libc::getpid() };
    let start_time = process_start_time(pid)?;
    let contents = format!("{pid}\n{start_time}\n");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    use std::io::Write;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;

    Ok(PidFileGuard {
        path: path.to_path_buf(),
        contents,
    })
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

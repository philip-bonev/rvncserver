//! Command-line entry point.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::fs::OpenOptionsExt;
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
        Command::Run(config) => match configure_process(&config) {
            Ok(Some(pid)) => {
                rvncserver::timestamped_log!("rvncserver: daemon started with pid {pid}");
                ExitCode::SUCCESS
            }
            Ok(None) => match tokio::runtime::Builder::new_multi_thread()
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
            },
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
/// Returns the daemon PID in the original parent process.
fn configure_process(config: &Config) -> io::Result<Option<libc::pid_t>> {
    if !config.daemonize {
        match config.log_target {
            LogTarget::Stderr => return Ok(None),
            LogTarget::File => {
                let path = config.log_file.as_deref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "file log target requires a path",
                    )
                })?;
                redirect_output(open_log_file(path)?)?;
                return Ok(None);
            }
            LogTarget::Journald => {
                rvncserver::logging::use_journald();
                return Ok(None);
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
        return Ok(Some(pid));
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
    Ok(None)
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

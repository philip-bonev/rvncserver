//! Command-line entry point.

use std::process::ExitCode;
use std::time::Duration;

use rvncserver::capture::{CaptureConfig, CaptureSession};
use rvncserver::cli::{self, Command};
use rvncserver::error::AppError;
use rvncserver::server;

const CAPTURE_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(AppError::Cli(error)) => {
            eprintln!("rvncserver: {error}\n");
            eprint!("{}", cli::help_text());
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("rvncserver: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), AppError> {
    match cli::parse_args(std::env::args_os().skip(1))? {
        Command::Help => {
            print!("{}", cli::help_text());
            Ok(())
        }
        Command::Version => {
            println!("rvncserver {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Run(config) => {
            if let Some(path) = config.capture_probe.clone() {
                let mut capture = CaptureSession::start(CaptureConfig::default()).await?;
                eprintln!("capture: waiting for the first frame...");
                let frame = capture.wait_for_first_frame(CAPTURE_PROBE_TIMEOUT).await?;
                frame.write_ppm(&path)?;
                eprintln!(
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
    }
}

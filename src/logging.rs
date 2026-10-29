//! Small standard-library-only logging support.

use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;

static JOURNAL_ENABLED: AtomicBool = AtomicBool::new(false);
static ROTATING_FILE: Mutex<Option<RotatingFile>> = Mutex::new(None);
static ROTATION_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct RotatingFile {
    path: PathBuf,
    file: File,
    max_size: u64,
    max_rotations: usize,
}

/// Redirect stdout/stderr to an append-only file and gzip-rotate it at `max_size`.
/// Rotated files are named `<path>.1.gz`, `<path>.2.gz`, and so on.
pub fn use_rotating_file(path: &Path, max_size: u64, max_rotations: usize) -> io::Result<()> {
    let file = open_log_file(path)?;
    redirect_output(&file)?;
    *ROTATING_FILE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(RotatingFile {
        path: path.to_path_buf(),
        file,
        max_size,
        max_rotations,
    });
    Ok(())
}

/// Direct application diagnostics to syslog, which systemd-journald collects.
/// Must be called before worker threads are started.
pub fn use_journald() {
    // SAFETY: openlog receives a static, NUL-terminated identifier that remains
    // valid for the process lifetime.
    unsafe {
        libc::openlog(
            c"rvncserver".as_ptr(),
            libc::LOG_PID | libc::LOG_NDELAY,
            libc::LOG_DAEMON,
        );
    }
    JOURNAL_ENABLED.store(true, Ordering::Release);
}

/// Write a diagnostic to the selected sink; stderr remains the default.
pub fn log(message: fmt::Arguments<'_>) {
    let message = message.to_string();
    if let Some(rotating) = ROTATING_FILE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        if let Err(error) = rotating.rotate_if_needed(message.len().saturating_add(1) as u64) {
            eprintln!("rvncserver: log rotation failed: {error}");
        }
        eprintln!("{message}");
        return;
    }
    if !JOURNAL_ENABLED.load(Ordering::Acquire) {
        eprintln!("{message}");
        return;
    }

    // Syslog's message parameter is a C string. Replace embedded NUL bytes and
    // use a fixed format string so diagnostic text cannot affect formatting.
    let message = message.replace('\0', "�");
    let Ok(message) = CString::new(message) else {
        return;
    };
    // SAFETY: the format string is static and the variadic argument is a valid
    // NUL-terminated string for the duration of the call.
    unsafe {
        libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), message.as_ptr());
    }
}

impl RotatingFile {
    fn rotate_if_needed(&mut self, incoming_size: u64) -> io::Result<()> {
        io::stdout().flush()?;
        io::stderr().flush()?;
        if self.file.metadata()?.len().saturating_add(incoming_size) <= self.max_size {
            return Ok(());
        }

        rotate_paths(&self.path, self.max_rotations)?;
        let file = open_log_file(&self.path)?;
        redirect_output(&file)?;
        self.file = file;
        Ok(())
    }
}

fn rotate_paths(path: &Path, max_rotations: usize) -> io::Result<()> {
    if max_rotations == 0 {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    }

    let source = match File::open(path) {
        Ok(source) => source,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let temporary = temporary_gzip_path(path);
    let result = (|| {
        let destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let mut encoder = GzEncoder::new(destination, Compression::default());
        let mut source = source;
        io::copy(&mut source, &mut encoder)?;
        encoder.finish()?.sync_all()?;

        let oldest = rotated_path(path, max_rotations);
        match fs::remove_file(&oldest) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        for index in (1..max_rotations).rev() {
            let source = rotated_path(path, index);
            let destination = rotated_path(path, index + 1);
            match fs::rename(source, destination) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        fs::rename(&temporary, rotated_path(path, 1))?;
        fs::remove_file(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_gzip_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    // SAFETY: getpid has no preconditions and returns the current process ID.
    let pid = unsafe { libc::getpid() };
    let sequence = ROTATION_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    value.push(format!(".1.gz.tmp-{pid}-{sequence}"));
    PathBuf::from(value)
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{index}.gz"));
    PathBuf::from(value)
}

fn open_log_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

fn redirect_output(file: &File) -> io::Result<()> {
    for target_fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: file is open and target_fd is a standard output descriptor.
        if unsafe { libc::dup2(file.as_raw_fd(), target_fd) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Format the current time as an ISO-like UTC timestamp with milliseconds.
pub fn timestamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = elapsed.as_secs();
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;

    // Convert days since 1970-01-01 to a Gregorian calendar date.
    let shifted_days = days + 719_468;
    let era = shifted_days / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let millis = elapsed.subsec_millis();

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn timestamp_has_utc_date_and_millisecond_fields() {
        let value = timestamp();
        assert_eq!(value.len(), 27);
        assert!(value.ends_with(" UTC"));
        assert_eq!(&value[4..5], "-");
        assert_eq!(&value[10..11], " ");
    }

    #[test]
    fn rotation_keeps_only_the_configured_number_of_backups() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rvncserver-log-{}-{unique}", std::process::id()));
        fs::write(&path, "current").unwrap();
        for (index, value) in [(1, "previous"), (2, "oldest")] {
            let file = File::create(rotated_path(&path, index)).unwrap();
            let mut encoder = GzEncoder::new(file, Compression::default());
            encoder.write_all(value.as_bytes()).unwrap();
            encoder.finish().unwrap();
        }

        rotate_paths(&path, 2).unwrap();

        let read_gzip = |index| {
            let file = File::open(rotated_path(&path, index)).unwrap();
            let mut decoder = GzDecoder::new(file);
            let mut content = String::new();
            decoder.read_to_string(&mut content).unwrap();
            content
        };
        assert_eq!(read_gzip(1), "current");
        assert_eq!(read_gzip(2), "previous");
        assert!(!path.exists());
        fs::remove_file(rotated_path(&path, 1)).unwrap();
        fs::remove_file(rotated_path(&path, 2)).unwrap();
    }
}

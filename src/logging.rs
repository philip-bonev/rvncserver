// Copyright 2026 Philip Bonev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://apache.org
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Small standard-library-only logging support.

use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;

static JOURNAL_ENABLED: AtomicBool = AtomicBool::new(false);
static ROTATING_FILE: Mutex<Option<RotatingFile>> = Mutex::new(None);
/// Serializes the slow archive pipeline (compression and the backup chain)
/// so rotated files stay in order. Never held while log lines are written.
static ROTATION_WORK: Mutex<()> = Mutex::new(());
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
    let mut slot = ROTATING_FILE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(rotating) = slot.as_mut() {
        let staged = match rotating.swap_if_needed(message.len().saturating_add(1) as u64) {
            Ok(staged) => staged,
            Err(error) => {
                write_stderr(&format!("rvncserver: log rotation failed: {error}"));
                None
            }
        };
        write_stderr(&message);
        if let Some(staged) = staged {
            let path = rotating.path.clone();
            let max_rotations = rotating.max_rotations;
            // Compression is slow and must never block writers; the log lock
            // is released first and the work lock keeps backups in order.
            drop(slot);
            let _work = ROTATION_WORK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(error) = archive_staged_log(&staged, &path, max_rotations) {
                write_stderr(&format!("rvncserver: log rotation failed: {error}"));
            }
        }
        return;
    }
    drop(slot);
    if !JOURNAL_ENABLED.load(Ordering::Acquire) {
        write_stderr(&message);
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

/// Write one diagnostic line to stderr without ever panicking.
///
/// `eprintln!` aborts the process when the write fails (for example on a full
/// disk), and a logging failure must never take the server down.
fn write_stderr(message: &str) {
    let mut stderr = io::stderr();
    let _ = stderr.write_all(message.as_bytes());
    let _ = stderr.write_all(b"\n");
}

impl RotatingFile {
    /// Swap in a fresh log file when the size threshold would be exceeded and
    /// return the staged old file for archiving.
    ///
    /// Only the cheap rename/reopen happens here; the slow compression runs
    /// outside the log lock so concurrent writers never wait on a rotation.
    fn swap_if_needed(&mut self, incoming_size: u64) -> io::Result<Option<PathBuf>> {
        io::stdout().flush()?;
        io::stderr().flush()?;
        if self.file.metadata()?.len().saturating_add(incoming_size) <= self.max_size {
            return Ok(None);
        }

        let staged = staged_log_path(&self.path);
        fs::rename(&self.path, &staged)?;
        match open_log_file(&self.path) {
            Ok(file) => match redirect_output(&file) {
                Ok(()) => {
                    self.file = file;
                    Ok(Some(staged))
                }
                Err(error) => {
                    restore_staged_log(&self.path, &staged);
                    Err(error)
                }
            },
            Err(error) => {
                restore_staged_log(&self.path, &staged);
                Err(error)
            }
        }
    }
}

/// Put a staged log file back after a failed swap so already-written lines
/// stay in place.
fn restore_staged_log(path: &Path, staged: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::rename(staged, path);
}

/// Compress a staged log into the `.1.gz` backup chain and shift older
/// backups. On failure the staged file is kept: it is the only copy of those
/// lines, and the error message reports where it lives.
fn archive_staged_log(staged: &Path, path: &Path, max_rotations: usize) -> io::Result<()> {
    compress_and_shift(staged, path, max_rotations).map_err(|error| {
        io::Error::other(format!(
            "{error}; unarchived log kept at {}",
            staged.display()
        ))
    })
}

fn compress_and_shift(staged: &Path, path: &Path, max_rotations: usize) -> io::Result<()> {
    if max_rotations == 0 {
        return remove_if_exists(staged);
    }

    let temporary = temporary_gzip_path(path);
    if let Err(error) = gzip_file(staged, &temporary) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    let shift = (|| {
        remove_if_exists(&rotated_path(path, max_rotations))?;
        for index in (1..max_rotations).rev() {
            let source = rotated_path(path, index);
            let destination = rotated_path(path, index + 1);
            match fs::rename(source, destination) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        fs::rename(&temporary, rotated_path(path, 1))
    })();
    if let Err(error) = shift {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    remove_if_exists(staged)
}

fn gzip_file(source_path: &Path, destination_path: &Path) -> io::Result<()> {
    let mut source = File::open(source_path)?;
    let destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination_path)?;
    let mut encoder = GzEncoder::new(destination, Compression::default());
    io::copy(&mut source, &mut encoder)?;
    encoder.finish()?.sync_all()?;
    Ok(())
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Unique name for a log file waiting to be archived.
fn staged_log_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    // SAFETY: getpid has no preconditions and returns the current process ID.
    let pid = unsafe { libc::getpid() };
    let sequence = ROTATION_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    value.push(format!(".staged-{pid}-{sequence}"));
    PathBuf::from(value)
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

/// Open (or create) the log file with owner-only permissions.
///
/// Symlinked log files are refused (`O_NOFOLLOW`): the configured path is a
/// full path, and following a replacement link would redirect diagnostics
/// wherever the link points.
pub fn open_log_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("log file {} must not be a symbolic link", path.display()),
                )
            } else {
                error
            }
        })?;
    // The creation mode only applies to new files; tighten pre-existing ones
    // so log content is never world-readable.
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(file)
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
    fn archiving_keeps_only_the_configured_number_of_backups() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rvncserver-log-{}-{unique}", std::process::id()));
        let staged = staged_log_path(&path);
        fs::write(&staged, "current").unwrap();
        for (index, value) in [(1, "previous"), (2, "oldest")] {
            let file = File::create(rotated_path(&path, index)).unwrap();
            let mut encoder = GzEncoder::new(file, Compression::default());
            encoder.write_all(value.as_bytes()).unwrap();
            encoder.finish().unwrap();
        }

        archive_staged_log(&staged, &path, 2).unwrap();

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
        assert!(!staged.exists());
        fs::remove_file(rotated_path(&path, 1)).unwrap();
        fs::remove_file(rotated_path(&path, 2)).unwrap();
    }

    #[test]
    fn log_file_symlinks_are_refused() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rvncserver-log-link-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target.log");
        fs::write(&target, "content").unwrap();
        let link = directory.join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(open_log_file(&link).is_err());
        assert!(open_log_file(&target).is_ok());

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_failed_archive_keeps_the_staged_log() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rvncserver-log-fail-{}-{unique}",
            std::process::id()
        ));
        let staged = staged_log_path(&path);
        fs::write(&staged, "current").unwrap();
        // A directory at the backup name makes the shift fail.
        fs::create_dir(rotated_path(&path, 1)).unwrap();

        assert!(archive_staged_log(&staged, &path, 1).is_err());
        assert!(staged.exists());
        assert_eq!(fs::read_to_string(&staged).unwrap(), "current");

        let _ = fs::remove_file(&staged);
        let _ = fs::remove_dir(rotated_path(&path, 1));
    }
}

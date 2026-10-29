//! Small standard-library-only logging support.

use std::ffi::CString;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static JOURNAL_ENABLED: AtomicBool = AtomicBool::new(false);

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

    #[test]
    fn timestamp_has_utc_date_and_millisecond_fields() {
        let value = timestamp();
        assert_eq!(value.len(), 27);
        assert!(value.ends_with(" UTC"));
        assert_eq!(&value[4..5], "-");
        assert_eq!(&value[10..11], " ");
    }
}

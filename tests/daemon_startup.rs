//! Daemon startup handshake tests: a failure that prevents normal startup
//! must be reported by the original process instead of a false
//! "daemon started with pid" message.

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;

/// Run the server with `--daemonize` against an already-bound port and
/// assert that the failure is reported and no daemon is left behind.
#[test]
fn daemon_reports_a_taken_port_instead_of_claiming_success() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
    let port = listener.local_addr().expect("probe address").port();

    let sandbox = std::env::temp_dir().join(format!(
        "rvncserver-daemon-startup-test-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&sandbox);
    fs::create_dir_all(&sandbox).expect("create sandbox");
    let password_file = sandbox.join("passwords");
    fs::write(&password_file, "secret\n").expect("write password file");
    let mut permissions = fs::metadata(&password_file)
        .expect("password file metadata")
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&password_file, permissions).expect("restrict password file");
    let pid_file = sandbox.join("rvncserver.pid");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rvncserver"))
        .arg("--daemonize")
        .arg("--listen")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--auth")
        .arg("vnc")
        .arg("--password-file")
        .arg(&password_file)
        .arg("--pid-file")
        .arg(&pid_file)
        // Isolate the run from the developer's own configuration.
        .env("HOME", &sandbox)
        .env("XDG_CONFIG_HOME", sandbox.join("config"))
        .env("XDG_RUNTIME_DIR", &sandbox)
        .output()
        .expect("run rvncserver");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a taken port must fail the launch; stderr: {stderr}"
    );
    assert!(
        stderr.contains("failed to bind"),
        "the bind failure must be displayed; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("daemon started with pid"),
        "no daemon start must be claimed; stderr: {stderr}"
    );
    assert!(
        !pid_file.exists(),
        "the PID file must be released after the failed start"
    );

    let _ = fs::remove_dir_all(&sandbox);
}

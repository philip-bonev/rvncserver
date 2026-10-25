# AGENTS.md — Wayland VNC Server

## 1. Project Overview

Develop a lightweight VNC server in Rust for Linux desktops running Wayland.

The application must run as a regular user-space process inside an existing Wayland session. It must capture the current desktop and, eventually, allow remote clients to interact with it through the VNC Remote Framebuffer (RFB) protocol.

The application is initially a command-line application. It must not create its own graphical interface, start a separate desktop session, or implement a Wayland compositor.

The primary goal is to support multiple Wayland desktop environments, including:

- GNOME
- KDE Plasma
- Sway
- Hyprland
- Other compatible Wayland environments

Use standard desktop interfaces whenever possible instead of relying on compositor-specific functionality.

## 2. Core Technology

The project uses:

- **Rust** as the primary programming language.
- **lamco-portal** for XDG Desktop Portal integration.
- **lamco-pipewire** for PipeWire-based screen capture.
- **Cargo** for dependency management.

Use the `lamco-portal` and `lamco-pipewire` crates for their intended purposes. Do not reimplement their functionality unless a concrete limitation makes this necessary.

Before using either crate, inspect its current public API, documentation, examples, feature flags, and compatibility requirements. Do not assume that APIs from older versions remain valid.

Use compatible versions of both crates and avoid unnecessary dependencies.

Do not introduce a GUI framework. The application is a console-based server.

## 3. Dependency Policy

Keeping the dependency tree small is a project requirement.

### 3.1 General Rules

- Prefer the Rust standard library when it provides an adequate solution.
- Reuse dependencies already present in the project.
- Prefer existing functionality in `lamco-portal` and `lamco-pipewire` over adding another crate for the same purpose.
- Avoid introducing dependencies for trivial functionality that can be implemented clearly and safely with a small amount of code.
- Do not add multiple crates that solve substantially the same problem.
- Avoid large frameworks when a small, focused library is sufficient.
- Do not add dependencies merely for convenience without evaluating their cost and benefit.
- Keep the dependency graph understandable and maintainable.
- Prefer well-maintained crates with clear documentation, appropriate licenses, and a history of stable releases.

### 3.2 Explicit Approval Required

**Never add, remove, or replace a dependency without asking the user for explicit approval first.**

This rule applies to both direct dependencies and development dependencies, including:

- Cargo dependencies
- Optional dependencies
- Build dependencies
- Development and testing dependencies
- New workspace dependencies
- New system-library requirements that materially affect installation or deployment

Before proposing a new dependency, explain:

1. What functionality is needed.
2. Why the standard library and existing dependencies are insufficient.
3. Which crate or system library is proposed.
4. Its maintenance status, license, and relevant technical limitations, when these can be established.
5. Its expected effect on the dependency tree and deployment requirements.
6. Whether a simpler alternative exists.

Wait for explicit approval before modifying `Cargo.toml`, `Cargo.lock`, workspace manifests, or build configuration to introduce the dependency.

Do not interpret a request to implement a feature as automatic approval to add dependencies.

If the user declines the proposed dependency, explore a reasonable alternative using the existing dependencies or ask how they would like to proceed.

### 3.3 Existing Dependencies

Before adding anything, inspect:

- `Cargo.toml`
- `Cargo.lock`
- Workspace manifests, if present
- Existing module structure
- Existing dependency features

Do not replace an existing dependency simply because another library is more popular or convenient.

Do not run commands that silently add or upgrade dependencies.

## 4. Command-Line Interface

The application must initially operate exclusively through command-line arguments.

Use a simple, predictable interface. The initial options should include:

- `--listen <ADDRESS>` — the local address on which the server listens.
- `--port <PORT>` — the TCP port on which the server listens.
- `--help` — display usage information.
- `--version` — display the application version.

Additional options may be proposed when justified by an actual requirement.

Do not introduce a command-line parsing crate without explicit user approval.

Until a parsing dependency is approved, use the standard library to parse arguments.

### Command-Line Requirements

- Validate all arguments before starting the server.
- Report invalid arguments clearly.
- Reject invalid port values.
- Detect and report address-binding failures.
- Do not silently ignore unknown arguments.
- Provide useful help output.
- Use sensible defaults only when their behavior is documented.
- Do not silently bind to all network interfaces unless explicitly configured or documented as the intended default.
- Clearly distinguish the listening address from the remote desktop's capture configuration.

The exact default listening address and port should be documented and must not be assumed to provide network security.

## 5. Wayland Session Integration

The server must operate inside the current user's existing Wayland session.

It must not:

- Start a new Wayland compositor.
- Create a separate graphical login session.
- Depend on X11 or XWayland.
- Require root privileges for normal operation.
- Attempt to bypass Wayland security restrictions.
- Assume that all compositors expose identical capabilities.

Use XDG Desktop Portal and PipeWire through the selected Lamco crates.

Handle portal permissions and session lifecycle explicitly.

The application must report meaningful errors when:

- No suitable Wayland session is available.
- The required portal service is unavailable.
- Screen capture is unsupported.
- The user denies a permission request.
- The PipeWire connection fails.
- The capture session is terminated.
- The selected desktop environment does not support a required capability.

Do not assume that successful ScreenCast initialization automatically provides permission to inject keyboard or pointer events.

Remote input support must use an appropriate, supported, permission-controlled mechanism. Implement it only after confirming the relevant API and permission requirements.

## 6. Architecture

Keep the code modular without introducing unnecessary abstraction.

Use clear boundaries between the following responsibilities:

### CLI and Configuration

Parse arguments, validate configuration, and initialize the application.

### Session Management

Coordinate desktop portal sessions, permissions, and shutdown.

### Screen Capture

Use `lamco-pipewire` to receive captured desktop frames.

Keep PipeWire-specific implementation details isolated from the RFB protocol implementation.

### Framebuffer

Maintain the image state needed by the VNC server.

Separate captured frame formats from the pixel format transmitted to remote clients.

Avoid unnecessary image copies and conversions.

### RFB Protocol

Implement the VNC Remote Framebuffer protocol independently of Wayland and PipeWire.

The protocol implementation must not depend directly on compositor-specific APIs.

### Network Transport

Manage listening sockets, client connections, and network errors.

Keep transport-specific code separate from framebuffer processing.

### Input Handling

When implemented, translate remote keyboard and pointer events into the supported local input mechanism.

### Logging and Errors

Use consistent error handling and diagnostics throughout the application.

Do not introduce separate modules or traits unless they improve a real architectural boundary.

## 7. RFB Protocol Implementation

The VNC server must implement the RFB protocol according to the applicable protocol specification.

Do not invent protocol behavior or assume that all VNC clients support the same extensions.

Implement features incrementally.

A reasonable initial progression is:

1. TCP listener and client connection.
2. RFB version negotiation.
3. Security negotiation and authentication.
4. Server initialization and pixel format negotiation.
5. Initial framebuffer transmission.
6. Incremental framebuffer updates.
7. Keyboard and pointer events.
8. Additional encodings and extensions.

Start with a small, clearly defined set of supported features.

Raw encoding may be used for an initial interoperability prototype, provided the implementation correctly handles the negotiated pixel format and framebuffer dimensions.

Do not claim compatibility with a feature until it has been implemented and tested.

Document unsupported encodings and extensions.

### Protocol Correctness

- Handle partial reads and writes.
- Validate lengths and dimensions received from clients.
- Avoid unbounded allocations based on untrusted network input.
- Handle client disconnections cleanly.
- Handle malformed messages without panicking.
- Respect negotiated protocol parameters.
- Keep network operations from blocking screen-capture processing.
- Avoid holding shared-state locks while performing potentially blocking network I/O.

## 8. Security

Security must be considered from the beginning.

- Never implement custom cryptographic algorithms.
- Do not treat an unencrypted VNC connection as secure.
- Do not expose the service on public interfaces by default.
- Do not log passwords, credentials, private keys, or other secrets.
- Validate all client-controlled data.
- Avoid unsafe Rust unless strictly necessary.
- When unsafe code is required, isolate it, document its invariants, and minimize its scope.
- Do not use unsafe code to bypass problems that can be solved with safe Rust.
- Do not bypass Wayland permission mechanisms.
- Fail securely when a required security mechanism cannot be initialized.

Before implementing authentication or TLS, identify the intended RFB security types and client compatibility requirements.

Do not invent a custom authentication protocol.

If the required security functionality would introduce a new dependency, obtain explicit approval before adding it.

## 9. Performance and Resource Management

The application should be efficient without premature optimization.

- Avoid unnecessary framebuffer copies.
- Avoid processing every captured frame when no update needs to be transmitted.
- Use incremental updates when supported by the implementation.
- Avoid blocking the capture loop on slow clients.
- Bound queues and buffers where appropriate.
- Handle client backpressure explicitly.
- Avoid unnecessary allocation in hot paths.
- Release PipeWire resources correctly.
- Avoid holding frame buffers longer than necessary.
- Do not introduce additional concurrency frameworks without approval.

Measure performance before introducing complex optimizations.

Prefer simple implementations that can be measured, tested, and improved incrementally.

## 10. Error Handling

Use Rust's type system and `Result` for recoverable failures.

- Do not use `unwrap()` or `expect()` in normal runtime paths when failure is reasonably possible.
- Do not silently discard important errors.
- Add context to errors where it helps diagnose the failure.
- Distinguish configuration errors, permission failures, protocol errors, and network failures.
- Ensure resources are released when initialization or operation fails.
- Do not use panics as a substitute for normal error handling.

Avoid adding an error-handling crate without explicit approval.

## 11. Logging

The initial application is a console-based server.

Provide useful diagnostic messages for:

- Startup and configuration.
- Listening address and port.
- Portal session initialization.
- Screen-capture initialization.
- Client connections and disconnections.
- Negotiated protocol capabilities.
- Recoverable failures.
- Shutdown.

Do not log sensitive information.

Do not add a logging framework without explicit approval. Initially, use the standard library or existing project facilities.

Keep normal informational output concise. Error messages should include enough context to diagnose failures.

## 12. Testing

Test the application incrementally.

### Unit Tests

Test argument parsing, validation, protocol serialization, pixel-format conversion, and other logic that does not require a live desktop session.

### Protocol Tests

Test RFB handshake handling, message parsing, framebuffer updates, and malformed input.

Test partial reads, partial writes, and disconnects.

### Integration Tests

Where practical, test against an actual VNC client and a running Wayland session.

Verify that the server can:

- Initialize screen capture.
- Transmit a valid framebuffer.
- Handle client disconnections.
- Shut down cleanly.
- Recover from supported session lifecycle events.

### Compatibility Tests

Test multiple Wayland environments.

Record which environments and versions have actually been tested. Do not claim universal compatibility based solely on protocol compliance.

Do not add testing frameworks or new development dependencies without explicit approval.

## 13. Code Quality

Follow idiomatic, readable Rust.

- Use descriptive names.
- Prefer small functions with clear responsibilities.
- Keep modules focused.
- Avoid unnecessary generic abstractions.
- Avoid premature plugin architectures.
- Avoid global mutable state.
- Document public interfaces and non-obvious behavior.
- Keep comments focused on reasoning, invariants, and limitations.
- Follow the formatting conventions enforced by `rustfmt`.

Prefer maintainability and correctness over cleverness.

Do not rewrite unrelated code merely to accommodate a small feature.

## 14. Build and Development Workflow

### Command Environment

Run all project commands with this `PATH`:

```text
/home/fi4o/.cargo/bin:/home/fi4o/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

If the current shell does not already provide this `PATH`, set it explicitly before running commands, for example:

```sh
PATH=/home/fi4o/.cargo/bin:/home/fi4o/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin cargo check
```

Before modifying the project:

1. Inspect the existing repository and its instructions.
2. Read the relevant source files and dependency manifests.
3. Understand the current architecture.
4. Identify the smallest implementation that satisfies the requirement.
5. Identify whether the change requires new dependencies.
6. Ask for approval before introducing dependencies.

After making changes:

1. Run `cargo fmt --check`.
2. Run `cargo check`.
3. Run the existing tests with `cargo test`, where applicable.
4. Run additional targeted tests when appropriate.
5. Report any checks that could not be run and explain why.

Do not upgrade dependencies or regenerate the lockfile unnecessarily.

When preparing a release, keep the package version in `Cargo.toml`, the root
package entry in `Cargo.lock`, and the Git release tag in sync. Update the
manifest and lockfile before creating/pushing the matching tag.

Do not change unrelated files.

Do not claim that a build or test passed unless the command was actually executed successfully.

If a build fails because a system library or development package is missing, report the exact requirement instead of silently changing the architecture.

## 15. Implementation Workflow

Work in small, independently verifiable steps.

Before a substantial change, provide a brief explanation of:

- The intended change.
- The files or modules affected.
- The relevant technical decisions.
- Any unresolved design questions.
- Any proposed dependency additions.

Ask for clarification when a decision could significantly affect architecture, compatibility, security, or deployment.

Do not make large speculative changes.

Do not implement future features merely because they might eventually be useful.

When requirements are ambiguous, prefer the smallest reasonable implementation or ask the user.

## 16. Initial Development Priorities

Implement the project in this order:

1. Establish the Rust project structure and command-line interface.
2. Initialize the Wayland portal session.
3. Receive screen frames through PipeWire.
4. Verify capture behavior independently of the VNC protocol.
5. Implement a minimal RFB server.
6. Transmit captured frames to a standard VNC client.
7. Implement permission-controlled remote input.
8. Add authentication and secure transport according to the agreed security requirements.
9. Improve framebuffer update efficiency.
10. Add multi-monitor support, clipboard synchronization, and additional protocol encodings as needed.

Do not implement all stages in a single change.

Each stage should leave the project in a buildable and testable state.

## 17. Decision-Making Principles

When choosing between alternative implementations, prioritize:

1. Correctness.
2. Security.
3. Compatibility with standard Wayland interfaces.
4. Minimal dependencies.
5. Simplicity.
6. Maintainability.
7. Performance.

Do not sacrifice correctness or security merely to minimize code size.

Do not add a dependency solely to reduce a few lines of code.

Do not choose a compositor-specific solution when a suitable standard interface is available.

If no standard interface provides a required capability, explain the limitation and propose alternatives before implementing a workaround.

## 18. Definition of Done

A change is complete when:

- It meets the stated requirements.
- It follows the project's dependency policy.
- It handles expected failures correctly.
- Relevant tests pass.
- Formatting and compilation checks pass where applicable.
- Documentation is updated when behavior or configuration changes.
- Unsupported behavior and known limitations are documented.
- No unrelated modifications have been introduced.

The project should evolve through small, reviewable changes rather than large rewrites.

//! Where the runtime's own diagnostics go.
//!
//! Node's process-level output has three disjoint channels and a program owns
//! two of them. `console.log` and `process.stdout.write` reach stdout,
//! `console.error` and `process.stderr.write` reach stderr, and the runtime's
//! *own* complaints — a deprecation warning, an `ExperimentalWarning`, a
//! rejected flag — go to stderr through `process.emitWarning`, which never
//! touches the program's stdout. That last distinction is the whole point of
//! this module: `rustnode app.js | jq .` has to work when `app.js` starts a
//! worker, and a program's stdout is not a place the runtime may write.
//!
//! # Why the previous arrangement was wrong in two ways at once
//!
//! `tracing_subscriber::fmt()` with no writer writes to **stdout**, and the
//! `warn` filter made every `tracing::warn!` in the runtime visible by default.
//! So a single `tracing::warn!` on the worker-bootstrap path printed a line into
//! the program's stdout on every `new Worker(...)`, corrupting any program whose
//! output was machine-readable. The warning itself was reporting a real defect
//! (`ensure_inspector` had no isolate on the worker's thread), but a diagnostic
//! that damages the output it is embedded in is not a usable report either way.
//!
//! # The decision
//!
//! Move the subscriber to **stderr**, and default it to **`off`**.
//!
//! * stderr, because that is where every Node process puts its own
//!   diagnostics, and because a caller redirecting `2>` can see them without the
//!   program's data being affected. Writing runtime diagnostics into stdout is
//!   not something Node has a notion of; `node --version | jq` works.
//! * `off` by default, because these are `tracing` events — an implementation
//!   detail of this runtime, not part of Node's surface — and the oracle prints
//!   nothing comparable. Measured: the pinned Node 28 nightly running a program
//!   that starts a worker emits zero bytes on both stdout and stderr. A default
//!   that differs from that is a divergence even on stderr, so the default has
//!   to be silence.
//! * `RUST_LOG` still works, which is how anyone debugging this runtime turns
//!   the events back on: `RUST_LOG=warn rustnode app.js` or
//!   `RUST_LOG=rn_bind_inspector=debug`. That is an explicit opt-in by the person
//!   running the binary, which is exactly the condition under which diagnostics
//!   should appear.
//!
//! A defect that used to be a `warn!` therefore no longer reaches a user by
//! accident. That is correct: the defects behind this module are fixed rather
//! than muted, and a failure a user must know about belongs on stderr through
//! `eprintln!` (which the CLI already uses for every startup error) or through
//! `process.emitWarning` (which a program can intercept), not through a
//! `tracing` event nobody configured.

/// Installs the `tracing` subscriber: stderr, and silent unless `RUST_LOG` asks.
///
/// Called once, first thing in `main`, so anything logged during startup is
/// routed the same way as everything after it.
pub fn install() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        // `fmt()` writes to stdout by default. This is the line that keeps the
        // runtime's diagnostics out of a program's output.
        .with_writer(std::io::stderr)
        .init();
}

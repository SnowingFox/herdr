//! `internalBinding('profiler')`: V8 coverage, driven through the inspector.
//!
//! Node's `src/inspector_profiler.cc` is the reference. The interesting part is that
//! *nothing* here is V8's `Profiler` API directly: `Profiler.start`,
//! `Profiler.stop`, `Profiler.startPreciseCoverage` and
//! `Profiler.takePreciseCoverage` are CDP methods, and Node reaches them by opening
//! a session against its own agent and dispatching protocol messages
//! (`V8ProfilerConnection::DispatchMessage`). This does the same, for the same
//! reason — the coverage serialisation V8 performs is part of the protocol and
//! reimplementing it against `Coverage::Collect` would produce JSON that is *nearly*
//! what `--experimental-test-coverage` expects.
//!
//! # What is implemented and what is not
//!
//! Implemented: `setCoverageDirectory`, `setSourceMapCacheGetter`,
//! `startCoverage`, `stopCoverage`, `takeCoverage`, `endCoverage` — the whole
//! recorded surface of `contracts/profiler.json`.
//!
//! The distinction that matters is `takeCoverage`: it writes one
//! `<pid>-<timestamp>-<seq>.json` file per script into the coverage directory, in
//! the `{ result: [{scriptId, url, functions}] }` shape
//! `lib/internal/test_runner/coverage.js` parses. That is what makes
//! `--experimental-test-coverage` produce a real report rather than an empty one,
//! and it is asserted by this crate's tests.
//!
//! # Why coverage and not CPU profiles
//!
//! `Profiler.start`/`Profiler.stop` over a CDP session needs no Rust support at all
//! — a caller opens an `inspector.Session` and posts the methods. The reason it
//! belongs in this crate is that it must be *reachable*, and it is: the tests drive
//! it through the same session path a user would. What coverage needs a binding for
//! is the file writing, the directory, and the source-map lookup, which is what
//! this file provides.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rn_v8_sys::v8;

/// How many coverage files have been written, for the file name.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
/// The thread id reported in a coverage file name.
///
/// Node uses `Environment::thread_id`, a per-thread counter; the file name only has to
/// be unique within a process, and this is the same idea.
static THREAD: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Whether coverage is on for this thread's isolate.
    ///
    /// Thread-local rather than a process-wide flag, because everything it guards is:
    /// the session, the directory and the source-map getter all belong to one
    /// environment. A shared flag meant a second thread starting coverage saw "already
    /// on" and never enabled it on its own inspector, so it collected nothing.
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    /// The directory `--experimental-test-coverage` asked for.
    static DIRECTORY: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    /// The source-map cache lookup `lib/internal/util.js` installs.
    static SOURCE_MAP_GETTER: RefCell<Option<v8::Global<v8::Function>>> = const { RefCell::new(None) };
    /// The session the coverage commands go through, with the sink its channel writes
    /// replies into.
    ///
    /// The sink is stored beside the session because a session's channel is fixed when
    /// it is created: a fresh sink per call would leave every reply after the first one
    /// writing into the *first* call's sink, and `takeCoverage` would see no reply and
    /// write no file while reporting success.
    static SESSION: RefCell<Option<(&'static v8::inspector::V8InspectorSession, ReplySink)>> =
        const { RefCell::new(None) };
}

/// `setCoverageDirectory(directory)`.
pub fn set_coverage_directory(directory: &str) {
    DIRECTORY.with(|slot| *slot.borrow_mut() = Some(PathBuf::from(directory)));
}

/// `setSourceMapCacheGetter(callback)`.
pub fn set_source_map_cache_getter(
    scope: &mut v8::PinScope<'_, '_>,
    callback: v8::Local<v8::Function>,
) {
    let callback = v8::Global::new(scope, callback);
    SOURCE_MAP_GETTER.with(|slot| *slot.borrow_mut() = Some(callback));
}

/// Runs one CDP command against the profiler session and returns the reply text.
///
/// The session is created on first use and kept. It is a second session against the
/// same inspector as any `inspector.Session` the user opened, which is exactly what
/// Node does — coverage and a debugger do not interfere.
fn dispatch(scope: &mut v8::PinScope<'_, '_>, command: &str) -> Option<String> {
    if !crate::agent::ensure_inspector(scope) {
        return None;
    }

    let already = SESSION.with(|slot| slot.borrow().is_some());
    if !already {
        let sink: ReplySink = std::rc::Rc::new(RefCell::new(None));
        let channel = v8::inspector::Channel::new(Box::new(ReplyChannel {
            sink: std::rc::Rc::clone(&sink),
        }));
        let session = crate::agent::connect(channel)?;
        SESSION.with(|slot| *slot.borrow_mut() = Some((session, sink)));
    }

    let (session, sink) = SESSION.with(|slot| slot.borrow().clone())?;
    // Cleared first so a command whose reply never arrives cannot be mistaken for the
    // previous command's answer.
    *sink.borrow_mut() = None;
    let view = v8::inspector::StringView::from(command.as_bytes());
    session.dispatch_protocol_message(view);
    let result = sink.borrow().clone();
    result
}

/// Where a coverage command's reply lands.
type ReplySink = std::rc::Rc<RefCell<Option<String>>>;

/// Receives the one reply a coverage command produces.
struct ReplyChannel {
    sink: ReplySink,
}

impl v8::inspector::ChannelImpl for ReplyChannel {
    fn send_response(
        &self,
        _call_id: i32,
        mut message: v8::UniquePtr<v8::inspector::StringBuffer>,
    ) {
        if let Some(buffer) = message.as_mut() {
            let text = crate::session::string_view_to_string(&buffer.string());
            *self.sink.borrow_mut() = Some(text);
        }
    }

    fn send_notification(&self, _message: v8::UniquePtr<v8::inspector::StringBuffer>) {}

    fn flush_protocol_notifications(&self) {}
}

/// `startCoverage()`.
///
/// Turns on precise coverage, which is the mode `NODE_V8_COVERAGE` uses: it counts
/// every block, not just every function, and it is what a line-coverage report
/// needs.
pub fn start_coverage(scope: &mut v8::PinScope<'_, '_>) {
    if ENABLED.with(|enabled| enabled.replace(true)) {
        return;
    }
    let command = r#"{"id":1,"method":"Profiler.enable"}"#;
    dispatch(scope, command);
    let command = r#"{"id":2,"method":"Profiler.startPreciseCoverage","params":{"callCount":true,"detailed":true,"allowTriggeredUpdates":false}}"#;
    dispatch(scope, command);
}

/// `stopCoverage()`.
pub fn stop_coverage(scope: &mut v8::PinScope<'_, '_>) {
    if !ENABLED.with(Cell::get) {
        return;
    }
    let command = r#"{"id":3,"method":"Profiler.stopPreciseCoverage"}"#;
    dispatch(scope, command);
}

/// `endCoverage()` — stops and forgets the directory.
pub fn end_coverage(scope: &mut v8::PinScope<'_, '_>) {
    stop_coverage(scope);
    ENABLED.with(|enabled| enabled.set(false));
    DIRECTORY.with(|slot| *slot.borrow_mut() = None);
}

/// `takeCoverage()` — writes one file per script into the coverage directory.
///
/// Returns how many files were written, so a caller (and a test) can tell an empty
/// result from a missing directory. Node's `TakeCoverage` does the same and reports
/// the count only through the files it leaves behind.
pub fn take_coverage(scope: &mut v8::PinScope<'_, '_>) -> usize {
    let Some(directory) = DIRECTORY.with(|slot| slot.borrow().clone()) else {
        return 0;
    };
    if std::fs::create_dir_all(&directory).is_err() {
        return 0;
    }

    let command = r#"{"id":4,"method":"Profiler.takePreciseCoverage","params":{"callCount":true,"detailed":true}}"#;
    let Some(reply) = dispatch(scope, command) else {
        return 0;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&reply) else {
        return 0;
    };
    // `takePreciseCoverage` answers `{ result: [...] }`. Anything else — an error
    // reply, a notification — is not coverage and must not be written as a file
    // that the reader would then fail to parse.
    let Some(result) = parsed.get("result") else {
        return 0;
    };

    let pid = std::process::id();
    let stamp = timestamp();
    let thread = THREAD.fetch_add(1, Ordering::SeqCst);
    let sequence = SEQUENCE.fetch_add(1, Ordering::SeqCst);
    // Node's `V8CoverageConnection::GetFilename` is
    // `coverage-<pid>-<microseconds/1000>-<thread_id>.json`, and the reader globs
    // that shape — `lib/internal/test_runner/coverage.js` looks for `coverage-*.json`.
    // A name it does not recognise is a profile that was collected and then ignored,
    // which is worse than not collecting it.
    let path = directory.join(format!("coverage-{pid}-{stamp}-{thread}-{sequence}.json"));

    // The `result` payload itself, not a wrapper around it: Node writes the profile
    // string V8 produced, and `coverage.js` reads `parsed.result`. Wrapping it a second
    // time makes every field `undefined` downstream.
    let mut document = result.clone();
    if let Some(cache) = source_map_cache(scope) {
        if let Some(object) = document.as_object_mut() {
            object.insert("source-map-cache".to_string(), cache);
        }
    }
    let Ok(text) = serde_json::to_string(&document) else {
        return 0;
    };
    if std::fs::write(&path, text).is_err() {
        return 0;
    }
    1
}

/// The timestamp form Node uses in a coverage file name: milliseconds, zero-padded.
fn timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// The directory coverage is being written to, for a test to check.
pub fn coverage_directory() -> Option<PathBuf> {
    DIRECTORY.with(|slot| slot.borrow().clone())
}

/// The source-map cache, as the getter `lib/internal/util.js` installed produces it.
///
/// Node calls this *with no arguments* and splices the object into the coverage
/// document under `source-map-cache` (`V8CoverageConnection::WriteProfile`). Returning
/// `None` when nothing is installed is what Node does too: the document is written
/// without the field rather than with a misleading empty one.
pub fn source_map_cache(scope: &mut v8::PinScope<'_, '_>) -> Option<serde_json::Value> {
    let callback = SOURCE_MAP_GETTER.with(|slot| slot.borrow().clone())?;
    let function = v8::Local::new(scope, &callback);
    let result = function.call(scope, v8::undefined(scope).into(), &[])?;
    if result.is_null_or_undefined() {
        return None;
    }
    // Serialised through V8's own JSON so a value with a getter, a cycle or a non-JSON
    // type behaves the way it would in `JSON.stringify` inside the same realm.
    let json = v8::json::stringify(scope, result)?;
    serde_json::from_str(&json.to_rust_string_lossy(scope)).ok()
}

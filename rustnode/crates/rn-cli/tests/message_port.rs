//! `MessagePort`'s close path, transfer-list errors and loop liveness.
//!
//! Every case here is a divergence that was measured against the pinned Node
//! oracle and has since been fixed, so each one is a regression test for a
//! specific mechanism rather than a description of the API:
//!
//! * A port whose peer closed kept the process alive forever. The close marker
//!   was delivered as the `close` event and the receiver was never marked
//!   closing, so `keeps_loop_alive` went on answering `true`.
//! * A `MessagePort` could be transferred twice, and the receiver got the message
//!   twice. Nothing tested whether the port was already detached.
//! * Every transfer-list error was a `TypeError` where Node raises
//!   `DataCloneError` (code 25). The duplicate check already existed and produced
//!   the right message; the class was the defect.
//! * A port named in its own transfer list did not throw at all. The source-port
//!   guard was missing, which is a different mechanism from the detached check
//!   even though both live in the same loop.
//!
//! # Why the process must exit by itself
//!
//! Half of these are loop-liveness questions, and a script that calls
//! `process.exit()` proves nothing about the loop: it forces the exit whichever
//! way the handles are ref'd. So every case here either asserts that the process
//! exits *without* an explicit exit call, under a timeout, or asserts the exit
//! code and elapsed time of a run that must be killed. The distinction is the
//! whole test.
//!
//! # Where the expectations come from
//!
//! Each transcript below is what the pinned `node`
//! (`v28.0.0-nightly20261111e8c1160d20`) prints for the same script. Half the
//! assertions run that binary directly and compare, so a change in the oracle is
//! visible rather than silently absorbed; the other half assert the recorded
//! transcript, so the test still says something on a machine with no oracle.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rn_node_oracle::Oracle;

/// The `rustnode` binary this test spawns.
///
/// `CARGO_BIN_EXE_rustnode` is set by cargo for a test target in the same package
/// as the binary, so this cannot pick up a stale build from another directory.
fn rustnode() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustnode"))
}

/// How long a run may take before it counts as "did not exit".
///
/// Node finishes each of these in tens of milliseconds. The bound is loose
/// because the assertion is "the loop released the handle", not a timing claim.
const EXIT_BOUND: Duration = Duration::from_secs(5);

/// One run of a script, with the exit status and how long it took.
struct Run {
    stdout: String,
    stderr: String,
    /// `None` when the timeout fired, which is the only way to observe "the
    /// process never exited" without the test itself hanging.
    status: Option<i32>,
    elapsed: Duration,
}

impl Run {
    fn exited(&self) -> bool {
        self.status.is_some()
    }

    fn transcript(&self) -> String {
        let status = match self.status {
            Some(code) => format!("exit {code}"),
            None => "killed after timeout".to_string(),
        };
        format!(
            "{status} in {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.elapsed, self.stdout, self.stderr
        )
    }
}

/// Runs `script` under `binary`, killing it once [`EXIT_BOUND`] elapses.
///
/// The kill is what makes a hang observable: waiting for the child would hang the
/// test instead, and treating a hang as a pass is the defect this file exists to
/// catch.
fn run_with_timeout(binary: &std::path::Path, script: &str) -> Run {
    let started = Instant::now();
    let mut child = Command::new(binary)
        .arg("-e")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));

    // Poll until the deadline, so a hung child is killed rather than stalling the
    // runner. `wait()` runs unconditionally afterwards: `try_wait` already reaps
    // the child when it reports an exit, and calling it again is what keeps every
    // path reaping (clippy's `zombie_processes` lint is right about this).
    let mut timed_out = false;
    while started.elapsed() < EXIT_BOUND {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("waiting for {} failed: {error}", binary.display()),
        }
    }
    if child.try_wait().ok().flatten().is_none() {
        timed_out = true;
        let _ = child.kill();
    }
    let status = child.wait().ok().and_then(|exit| exit.code());
    let status = status.filter(|_| !timed_out);

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    Run {
        stdout,
        stderr,
        status,
        elapsed: started.elapsed(),
    }
}

/// The pinned oracle, or `None` when this machine has none.
fn oracle() -> Option<&'static Oracle> {
    static ORACLE: std::sync::OnceLock<Option<Oracle>> = std::sync::OnceLock::new();
    ORACLE
        .get_or_init(|| rn_node_oracle::require_oracle("rn-cli message port"))
        .as_ref()
}

/// Asserts the script exits on its own, with `expected` stdout, under both
/// runtimes.
///
/// Running the oracle too is what keeps this from being a test of rustnode's own
/// habits: if Node's answer moves, this fails and names the change.
fn both_exit_on_their_own(script: &str, expected: &str) {
    let ours = run_with_timeout(&rustnode(), script);
    assert!(
        ours.exited(),
        "rustnode did not exit on its own; the loop is still holding the port: {}",
        ours.transcript()
    );
    assert_eq!(
        ours.stdout.trim_end(),
        expected.trim_end(),
        "rustnode printed the wrong transcript: {}",
        ours.transcript()
    );

    let Some(oracle) = oracle() else {
        return;
    };
    let theirs = run_with_timeout(&oracle.path, script);
    assert!(
        theirs.exited(),
        "the oracle did not exit, so this expectation is stale: {}",
        theirs.transcript()
    );
    assert_eq!(
        theirs.stdout.trim_end(),
        expected.trim_end(),
        "the recorded transcript no longer matches {}: {}",
        oracle.describe(),
        theirs.transcript()
    );
}

// ---------------------------------------------------------------------------
// Finding 1: a port whose peer closed must not pin the process
// ---------------------------------------------------------------------------

#[test]
fn a_port_whose_peer_closed_exits_on_its_own() {
    // The reported repro, verbatim. Before the fix this never exited: the close
    // marker became a `close` event and the receiving port was never marked
    // closing, so `keeps_loop_alive` stayed true forever.
    both_exit_on_their_own(
        "const {port1, port2} = new MessageChannel();\n\
         port2.on('message', () => {});\n\
         port1.close();",
        "",
    );
}

#[test]
fn a_close_listener_alone_does_not_pin_the_process() {
    // The same liveness question with no `message` listener at all: the port is
    // unref'd from birth, so the loop has nothing to run for and the process
    // exits before the close event is ever dispatched. Node behaves identically.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const {port1, port2} = new MessageChannel();\n\
         port2.on('close', () => console.log('close event'));\n\
         port1.close();",
        "",
    );
}

#[test]
fn a_pending_timer_delivers_the_close_event() {
    // Node dispatches `close` only when something else keeps the loop turning.
    // This is the positive half of the two tests above, and it is what proves the
    // fix did not simply stop delivering the event.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const {port1, port2} = new MessageChannel();\n\
         port2.on('message', () => {});\n\
         port2.on('close', () => console.log('close event'));\n\
         port1.close();\n\
         setTimeout(() => {}, 20);",
        "close event\n",
    );
}

#[test]
fn the_closing_port_dispatches_its_own_close_event() {
    // libuv keeps the loop alive for `closing_handles`, so a port that closed
    // still earns the one iteration that runs its own close phase. The event for
    // the port that called `close()` is therefore delivered even with nothing else
    // pending; only the *peer's* marker needs an extra iteration.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const {port1} = new MessageChannel();\n\
         port1.on('close', () => console.log('port1 close'));\n\
         port1.close();",
        "port1 close\n",
    );
}

#[test]
fn calling_close_twice_is_harmless() {
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const {port1, port2} = new MessageChannel();\n\
         port2.on('message', () => {});\n\
         port1.close();\n\
         port1.close();\n\
         port2.close();\n\
         port2.close();",
        "",
    );
}

#[test]
fn has_ref_tracks_the_handle_the_way_libuv_does() {
    // `HandleWrap::HasRef` is `IsAlive(wrap) && uv_has_ref(handle)`, and
    // `IsAlive` excludes `kClosed` but not `kClosing`. So `hasRef()` is `true`
    // both before and immediately after `close()`, and `false` once the close
    // event has run.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const {port1, port2} = new MessageChannel();\n\
         console.log('fresh', port1.hasRef());\n\
         port2.on('message', () => {});\n\
         console.log('with listener', port2.hasRef(), port1.hasRef());\n\
         port2.unref();\n\
         console.log('unref', port2.hasRef());\n\
         port2.ref();\n\
         console.log('ref', port2.hasRef());\n\
         port2.close();\n\
         console.log('closed', port2.hasRef());",
        "fresh false\nwith listener true false\nunref false\nref true\nclosed true\n",
    );
}

#[test]
fn start_alone_does_not_ref_the_port() {
    // `MessagePort::Start` sets `receiving_messages_` and nothing else; the ref
    // comes from `io.js`'s `setupPortReferencing`. A port started but never
    // listened to is unref'd, so the process exits.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const {port2} = new MessageChannel();\n\
         port2.start();\n\
         console.log('hasRef', port2.hasRef());",
        "hasRef false\n",
    );
}

#[test]
fn ref_without_a_listener_pins_the_process() {
    // The other direction, and the one that a `start()`-based liveness predicate
    // got wrong: `uv_async_init` leaves a port's handle active, so `ref()` alone
    // keeps the process alive. Measured on the oracle: this hangs until killed.
    const SCRIPT: &str = "const {MessageChannel} = require('worker_threads');\n\
                          const {port2} = new MessageChannel();\n\
                          port2.ref();";

    let ours = run_with_timeout(&rustnode(), SCRIPT);
    assert!(
        !ours.exited(),
        "a ref'd port with no listener must hold the loop open, and this exited: {}",
        ours.transcript()
    );

    if let Some(oracle) = oracle() {
        let theirs = run_with_timeout(&oracle.path, SCRIPT);
        assert!(
            !theirs.exited(),
            "the oracle exited on a ref'd port, so this expectation is stale: {}",
            theirs.transcript()
        );
    }
}

#[test]
fn an_unref_d_port_does_not_pin_the_process() {
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const {port1, port2} = new MessageChannel();\n\
         port2.on('message', () => {});\n\
         port2.unref();\n\
         port1.close();",
        "",
    );
}

// ---------------------------------------------------------------------------
// Finding 2: a port cannot be transferred twice
// ---------------------------------------------------------------------------

#[test]
fn transferring_a_port_twice_throws_and_delivers_once() {
    // The reported repro. Before the fix the second `postMessage` succeeded and
    // the receiver got both messages, because nothing checked whether the port was
    // already detached. The delivery count is asserted as well as the throw: a
    // silent duplicate delivery is worse than a lost message, since nothing in the
    // API reports it.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const a = new MessageChannel();\n\
         const b = new MessageChannel();\n\
         a.port1.postMessage('first', [b.port1]);\n\
         try { a.port1.postMessage('second', [b.port1]); }\n\
         catch (e) { console.log('second threw', e.name); }\n\
         let seen = 0;\n\
         a.port2.on('message', () => { seen++; });\n\
         a.port2.on('close', () => console.log('delivered', seen));\n\
         a.port1.close();",
        "second threw DataCloneError\ndelivered 1\n",
    );
}

#[test]
fn a_transferred_port_reports_itself_detached() {
    // `MessagePort::IsDetached` is `data_ == nullptr || IsHandleClosing()`, so a
    // port that was handed over and not yet rebuilt on the other side is detached
    // for the purpose of a second transfer.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const a = new MessageChannel();\n\
         const b = new MessageChannel();\n\
         a.port1.postMessage('x', [b.port1]);\n\
         for (const [label, value] of [['again', b.port1]]) {\n\
           try { a.port1.postMessage('y', [value]); }\n\
           catch (e) { console.log(label, e.name, e.code); }\n\
         }\n\
         a.port1.close();\n\
         a.port2.close();",
        "again DataCloneError 25\n",
    );
}

// ---------------------------------------------------------------------------
// Finding 3: every transfer-list error is a DataCloneError
// ---------------------------------------------------------------------------

/// Runs the transfer-list script and returns rustnode's transcript.
///
/// The script closes every port it creates, so the process exits on its own and
/// the transcript is the whole output. Every row prints the error's name, `code`
/// and message, which is what distinguishes a `TypeError` from the
/// `DOMException`/`DataCloneError` Node raises.
fn transfer_rows(script: &str) -> String {
    let ours = run_with_timeout(&rustnode(), script);
    assert!(
        ours.exited(),
        "the transfer-list script must exit on its own: {}",
        ours.transcript()
    );
    assert_eq!(
        ours.status,
        Some(0),
        "the transfer-list script must exit 0: {}",
        ours.transcript()
    );
    ours.stdout
}

#[test]
fn every_transfer_list_entry_error_is_a_data_clone_error() {
    // Four rows, each a different rejection path, all of which were a `TypeError`
    // with no `code` before the fix. The messages and classes are the oracle's.
    const ROWS: &str = "\
const assert = require('assert');\n\
const {MessageChannel} = require('worker_threads');\n\
function t(label, fn) {\n\
  try { fn(); console.log(label, 'NO THROW'); }\n\
  catch (e) { console.log(label, e.name, e.code, JSON.stringify(e.message)); }\n\
}\n\
const {port1, port2} = new MessageChannel();\n\
t('invalid', () => port1.postMessage('x', [{}]));\n\
t('primitive', () => port1.postMessage('x', [5]));\n\
const ab = new ArrayBuffer(8);\n\
port1.postMessage('y', [ab]);\n\
t('detached', () => port1.postMessage('z', [ab]));\n\
const ab2 = new ArrayBuffer(8);\n\
t('duplicate', () => port1.postMessage('w', [ab2, ab2]));\n\
t('source', () => port1.postMessage('v', [port1]));\n\
const other = new MessageChannel();\n\
t('duplicate-port', () => port1.postMessage('u', [other.port1, other.port1]));\n\
other.port1.close();\n\
t('detached-port', () => port1.postMessage('t', [other.port1]));\n\
port1.close();\n\
port2.close();\n\
other.port2.close();\n";

    let printed = transfer_rows(ROWS);
    assert_eq!(
        printed.trim_end(),
        "invalid DataCloneError 25 \"Found invalid value in transferList.\"\n\
         primitive DataCloneError 25 \"Found invalid value in transferList.\"\n\
         detached DataCloneError 25 \"Cannot transfer object of unsupported type.\"\n\
         duplicate DataCloneError 25 \"Transfer list contains duplicate ArrayBuffer\"\n\
         source DataCloneError 25 \"Transfer list contains source port\"\n\
         duplicate-port DataCloneError 25 \"Transfer list contains duplicate MessagePort\"\n\
         detached-port DataCloneError 25 \"MessagePort in transfer list is already detached\"",
        "wrong transfer-list transcript:\n{printed}"
    );

    if let Some(oracle) = oracle() {
        let theirs = run_with_timeout(&oracle.path, ROWS);
        assert!(
            theirs.exited(),
            "the oracle did not exit on the transfer-list script: {}",
            theirs.transcript()
        );
        assert_eq!(
            printed.trim_end(),
            theirs.stdout.trim_end(),
            "the transfer-list transcript differs from {}: {}",
            oracle.describe(),
            theirs.transcript()
        );
    }
}

#[test]
fn the_already_detached_buffer_and_a_closed_port_are_one_check() {
    // Node folds `!IsDetachable() || WasDetached()` into one branch with one
    // message, and "already handed over" and "explicitly closed" are the same
    // `IsDetached()` on a port. Pinning them together is what stops the two
    // drifting apart again: a fix for one that leaves the other is a half fix.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         function name(fn) { try { fn(); return 'none'; } catch (e) { return e.name + ':' + e.message; } }\n\
         const a = new MessageChannel();\n\
         const ab = new ArrayBuffer(4);\n\
         a.port1.postMessage('x', [ab]);\n\
         console.log('buffer', name(() => a.port1.postMessage('y', [ab])));\n\
         const b = new MessageChannel();\n\
         b.port1.close();\n\
         console.log('closed port', name(() => a.port1.postMessage('z', [b.port1])));\n\
         const c = new MessageChannel();\n\
         a.port1.postMessage('x', [c.port1]);\n\
         console.log('handed over', name(() => a.port1.postMessage('y', [c.port1])));\n\
         b.port2.close();\n\
         a.port1.close();\n\
         a.port2.close();",
        "buffer DataCloneError:Cannot transfer object of unsupported type.\n\
         closed port DataCloneError:MessagePort in transfer list is already detached\n\
         handed over DataCloneError:MessagePort in transfer list is already detached\n",
    );
}

#[test]
fn a_port_in_its_own_transfer_list_is_refused_even_when_open() {
    // The fourth defect: the source-port guard was missing entirely, so this did
    // not throw at all. Node checks it before the detached test, so an *open* port
    // reports "source port" and a *closed* one reports "source port" too rather
    // than "already detached".
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         function name(fn) { try { fn(); return 'none'; } catch (e) { return e.name + ':' + e.message; } }\n\
         const open = new MessageChannel();\n\
         console.log('open', name(() => open.port1.postMessage('x', [open.port1])));\n\
         const closed = new MessageChannel();\n\
         closed.port1.close();\n\
         console.log('closed', name(() => closed.port1.postMessage('x', [closed.port1])));\n\
         open.port1.close();\n\
         open.port2.close();\n\
         closed.port2.close();",
        "open DataCloneError:Transfer list contains source port\n\
         closed DataCloneError:Transfer list contains source port\n",
    );
}

#[test]
fn a_non_iterable_transfer_list_is_a_type_error() {
    // The one row that is *not* a `DataCloneError`: `GetTransferList` rejects a
    // value that is not an object with `THROW_ERR_INVALID_ARG_TYPE`. The `code`
    // matters as much as the class, because that is what feature detection reads.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         function name(fn) { try { fn(); return 'none'; } catch (e) { return e.name + ':' + e.code; } }\n\
         const {port1, port2} = new MessageChannel();\n\
         console.log('string', name(() => port1.postMessage('x', 'abc')));\n\
         console.log('number', name(() => port1.postMessage('x', 7)));\n\
         port1.close();\n\
         port2.close();",
        "string TypeError:ERR_INVALID_ARG_TYPE\nnumber TypeError:ERR_INVALID_ARG_TYPE\n",
    );
}

#[test]
fn an_iterable_transfer_list_is_accepted() {
    // The counterpart to the row above: a `Set` and an `options.transfer` object
    // are both legal, and the object form is why a non-iterable object is an
    // *empty* list rather than an error. Only `structuredClone` insists on a
    // sequence, which the next test pins.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const {port1, port2} = new MessageChannel();\n\
         const a = new ArrayBuffer(4);\n\
         port1.postMessage('x', new Set([a]));\n\
         console.log('set detached', a.byteLength === 0);\n\
         const b = new ArrayBuffer(4);\n\
         port1.postMessage('y', {transfer: [b]});\n\
         console.log('options detached', b.byteLength === 0);\n\
         console.log('empty object', port1.postMessage('z', {}));\n\
         port1.close();\n\
         port2.close();",
        "set detached true\noptions detached true\nempty object true\n",
    );
}

#[test]
fn structured_clone_rejects_a_transfer_that_is_not_a_sequence() {
    // `structuredClone`'s `transfer` goes through `webidl`, which coerces it to a
    // sequence before the native layer sees it. So the same `{}` that
    // `postMessage` accepts is a `TypeError` here — the two paths must not share
    // one validation rule.
    both_exit_on_their_own(
        "function name(fn) { try { fn(); return 'none'; } catch (e) { return e.name + ':' + e.code; } }\n\
         console.log('object', name(() => structuredClone({}, {transfer: {}})));\n\
         console.log('number', name(() => structuredClone({}, {transfer: 5})));\n\
         const ab = new ArrayBuffer(4);\n\
         structuredClone({}, {transfer: [ab]});\n\
         console.log('detached', ab.byteLength === 0);\n\
         console.log('detached again', name(() => structuredClone({}, {transfer: [ab]})));",
        "object TypeError:ERR_INVALID_ARG_TYPE\n\
         number TypeError:ERR_INVALID_ARG_TYPE\n\
         detached true\n\
         detached again DataCloneError:25\n",
    );
}

// ---------------------------------------------------------------------------
// Adjacent surfaces the same change touched
// ---------------------------------------------------------------------------

#[test]
fn post_message_reports_could_not_post_as_undefined() {
    // `PostMessage` returns nothing when the port is closing or unentangled, and
    // `io.js` treats `undefined` as "could not post". Returning a boolean made a
    // `BroadcastChannel` report success where Node reports failure.
    both_exit_on_their_own(
        "const {MessageChannel} = require('worker_threads');\n\
         const a = new MessageChannel();\n\
         const b = new MessageChannel();\n\
         console.log('healthy', String(a.port1.postMessage('x')));\n\
         a.port1.postMessage('y', [b.port1]);\n\
         a.port1.close();\n\
         console.log('closed', String(a.port1.postMessage('z')));\n\
         a.port2.close();\n\
         b.port2.close();",
        "healthy true\nclosed undefined\n",
    );
}

#[test]
fn receive_message_on_port_closes_a_port_holding_a_close_marker() {
    // `ReceiveMessage` honours a close marker before the receiving test, so a
    // forced read drains the marker and closes the port. The forced read is also
    // the reason the process exits: the read closed the handle, and a `close`
    // listener registered afterwards is on an already-retired handle, so Node
    // never dispatches it. Both lines are measured, not assumed.
    both_exit_on_their_own(
        "const {MessageChannel, receiveMessageOnPort} = require('worker_threads');\n\
         const a = new MessageChannel();\n\
         a.port1.close();\n\
         console.log('read', receiveMessageOnPort(a.port2));\n\
         console.log('hasRef', a.port2.hasRef());\n\
         a.port2.on('close', () => console.log('closed'));",
        "read undefined\nhasRef false\n",
    );
}

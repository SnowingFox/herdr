//! `process._exiting` and `process.exitCode`, one set per environment.
//!
//! Node keeps both on `node::Environment`, not on a process-wide object:
//! `Environment::exit_code()` and the private-symbol fields
//! `bootstrap/node.js` defines (`kExiting`, `kExitCode`, `kHasExitCode`) belong
//! to the environment that installed them. A worker therefore has its own pair,
//! and its `process.exit()` can neither change the parent's exit status nor trip
//! the "the exit sequence already ran" guard the parent's own `exit` handlers
//! are checked against.
//!
//! # Why this is per thread and not one value for the process
//!
//! One thread hosts exactly one realm at a time — that is the invariant
//! [`crate::realm`] is built on, and a worker gets a freshly spawned thread per
//! `new Worker()`. So the thread *is* the environment here, and a thread-local
//! is a faithful model of Node's per-`Environment` state rather than a
//! convenience.
//!
//! A process-wide `static` was the earlier shape, and it was wrong in a way that
//! is observable from a three-line program: a worker that exits 1 made the
//! parent exit 1. Nothing about the accessors' callbacks needs process-wide
//! reach — they are plain `fn`s with no captured state, which a thread-local
//! satisfies exactly as well as a `static` did.
//!
//! # Why no atomics
//!
//! Every read and write happens on the thread that owns the environment: the JS
//! accessors and the exit path both run there. The one value that crosses
//! threads — the exit code a worker reports to its parent — does not travel
//! through here; it goes through the worker handle's own `Arc<AtomicI32>`.

use std::cell::Cell;

thread_local! {
    static STATE: ExitState = const { ExitState::new() };
}

/// The exit status an environment is about to end with.
///
/// `exit_code` is `Option` rather than a value plus a "was set" bit because Node
/// distinguishes "absent" from "set to 0": `exitCode` reads `undefined` until it
/// is assigned, and `process.exitCode = 0` is a different state from never
/// assigning it even though both exit 0.
#[derive(Debug)]
struct ExitState {
    /// `process._exiting`: the exit sequence has already run in this environment.
    exiting: Cell<bool>,
    /// `process.exitCode`, or `None` while it is unset.
    exit_code: Cell<Option<i32>>,
}

impl ExitState {
    const fn new() -> Self {
        Self {
            exiting: Cell::new(false),
            exit_code: Cell::new(None),
        }
    }
}

/// Whether this environment is on its way out, as `process._exiting` reports it.
#[must_use]
pub fn exiting() -> bool {
    STATE.with(|state| state.exiting.get())
}

/// Sets `process._exiting`.
pub fn set_exiting(exiting: bool) {
    STATE.with(|state| state.exiting.set(exiting));
}

/// `process.exitCode`, or `None` when it is unset.
#[must_use]
pub fn exit_code() -> Option<i32> {
    STATE.with(|state| state.exit_code.get())
}

/// Records `process.exitCode`.
pub fn set_exit_code(code: i32) {
    STATE.with(|state| state.exit_code.set(Some(code)));
}

/// Clears `process.exitCode`, so it reads `undefined` again.
pub fn clear_exit_code() {
    STATE.with(|state| state.exit_code.set(None));
}

/// Returns this environment to the state a newly created one has.
///
/// A worker gets a fresh thread and therefore a fresh value already; this exists
/// for a thread that bootstraps a second realm, which must not inherit the flags
/// of the one before it. Node's equivalent is constructing a new `Environment`.
pub fn reset() {
    STATE.with(|state| {
        state.exiting.set(false);
        state.exit_code.set(None);
    });
}

/// Who this environment is, for the diagnostics that name it.
///
/// Node's `Environment::Exit` writes `(node:PID)` on the main thread and
/// `(node:PID, thread:ID)` in a worker (`src/env.cc:2152-2158`), and the two
/// `--trace-exit` shapes are exactly those prefixes. That is the only consumer,
/// which is why this is one small fact rather than a general realm registry.
///
/// `is_main_thread` is the default because a thread that never recorded a realm
/// is the main thread — the same reason [`crate::realm`]'s registry defaults to
/// nothing installed rather than to a worker. The worker bootstrap calls
/// [`set_environment_identity`] before its realm runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvironmentIdentity {
    /// Whether this environment is the process's main one.
    pub is_main_thread: bool,
    /// `AllocateEnvironmentThreadId()`'s id: `0` on the main thread.
    pub thread_id: i32,
}

impl Default for EnvironmentIdentity {
    fn default() -> Self {
        Self {
            is_main_thread: true,
            thread_id: 0,
        }
    }
}

thread_local! {
    static IDENTITY: Cell<EnvironmentIdentity> = const { Cell::new(EnvironmentIdentity {
        is_main_thread: true,
        thread_id: 0,
    }) };
}

/// Records whether this thread hosts the main environment, and its thread id.
pub fn set_environment_identity(identity: EnvironmentIdentity) {
    IDENTITY.with(|slot| slot.set(identity));
}

/// This thread's environment identity.
#[must_use]
pub fn environment_identity() -> EnvironmentIdentity {
    IDENTITY.with(Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_environment_has_no_exit_code_and_is_not_exiting() {
        // The two defaults are observable: `process.exitCode` reads `undefined`,
        // and an unset `_exiting` is what lets the natural exit emit `exit` at
        // all.
        assert_eq!(exit_code(), None);
        assert!(!exiting());
    }

    #[test]
    fn the_values_round_trip_including_zero() {
        set_exit_code(0);
        assert_eq!(
            exit_code(),
            Some(0),
            "zero is a set code, not an absent one"
        );
        clear_exit_code();
        assert_eq!(exit_code(), None);

        set_exiting(true);
        assert!(exiting());
        reset();
        assert!(!exiting());
        assert_eq!(exit_code(), None);
    }

    #[test]
    fn another_thread_does_not_see_this_environments_state() {
        // This is the defect in one assertion. While the state was a
        // process-wide `static`, a worker's nonzero exit wrote the value the
        // main thread read, so the parent exited with the worker's status.
        set_exit_code(7);
        set_exiting(true);

        let seen = std::thread::spawn(|| (exit_code(), exiting()))
            .join()
            .expect("the probe thread runs");
        assert_eq!(
            seen,
            (None, false),
            "a second environment must start with its own unset exit state"
        );

        reset();
    }
}

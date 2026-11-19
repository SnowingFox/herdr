//! `internalBinding('fs')` for rustnode.
//!
//! The JavaScript side of this namespace is Node's own `lib/fs.js` and
//! `lib/internal/fs/**`, which are frozen and never edited. Everything they
//! call has to exist here with the same shape.
//!
//! There are three calling conventions in that JavaScript, and all are
//! reproduced:
//!
//! * **Synchronous** calls omit the trailing request argument. They return the
//!   result directly and throw a `UVException`-shaped `Error` on failure.
//! * **Asynchronous** calls pass an `FSReqCallback` instance and return
//!   `undefined`; the binding later calls `req.oncomplete(err, value)`.
//! * Calls whose request slot holds the `kUsePromises` symbol return a
//!   `Promise` instead.
//!
//! Node runs the blocking syscall on the libuv thread pool. rustnode keeps the
//! same callback contract but runs the syscall inline and defers the completion
//! with a microtask, so `oncomplete` never runs inside the native call that
//! started the work. The crate `README.md` explains that choice and lists every
//! member that is deliberately deferred.

pub mod args;
pub mod complete;
pub mod copy_tree;
pub mod cp;
pub mod dirent;
pub mod error;
pub mod filehandle;
pub mod filehandle_stream;
pub mod flags;
pub mod fsops;
pub mod jobs;
pub mod legacy_main;
pub mod permission;
pub mod request;
pub mod stats;
pub mod watch;

mod install;

#[cfg(test)]
mod testsupport;

mod filehandle_transfer;

pub use install::Fs;

/// Registers the `fs` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Fs);
    // A native `FileHandle` is a host object that can only move. `promises.js`
    // lists it in `[kTransferList]`, so the messaging layer has to know how to
    // take the descriptor out and rebuild a handle around it; without this the
    // nested entry was skipped and `postMessage(fh, [fh])` failed with
    // "Found invalid value in transferList.".
    rn_core::host_object::register_transfer_kind(
        filehandle_transfer::FILE_HANDLE_KIND,
        filehandle_transfer::transfer_for_messaging,
    );
}

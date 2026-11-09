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
pub mod dirent;
pub mod error;
pub mod flags;
pub mod fsops;
pub mod request;
pub mod stats;

mod install;

#[cfg(test)]
mod testsupport;

pub use install::Fs;

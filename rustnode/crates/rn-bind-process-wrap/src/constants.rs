//! The three process flags `spawn()`'s options translate into.
//!
//! `src/process_wrap.cc` defines an unnamed `ProcessFlags` enum and publishes
//! three of its four values as `NODE_DEFINE_CONSTANT`s. Only the three are
//! observable; `kProcessFlagNone` is zero and has no name on the namespace
//! because `NODE_DEFINE_CONSTANT` is never called for it.
//!
//! `lib/internal/child_process.js` ORs these into `spawnFlags` and
//! `src/process_wrap.cc` maps each onto the matching `UV_PROCESS_*` bit, so the
//! numbers have to be this enum's, not libuv's.

/// `kProcessFlagDetached` — `{ detached: true }`.
pub const PROCESS_FLAG_DETACHED: i32 = 1 << 0;
/// `kProcessFlagWindowsHide` — `{ windowsHide: true }`.
pub const PROCESS_FLAG_WINDOWS_HIDE: i32 = 1 << 1;
/// `kProcessFlagWindowsVerbatimArguments` — `{ windowsVerbatimArguments: true }`.
pub const PROCESS_FLAG_WINDOWS_VERBATIM_ARGUMENTS: i32 = 1 << 2;

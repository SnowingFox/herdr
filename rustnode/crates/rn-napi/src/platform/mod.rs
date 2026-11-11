//! Platform-specific shared-library loading.
//!
//! `dlopen`/`dlsym`/`dlclose` are the POSIX spelling; Windows spells the same
//! operations `LoadLibraryExW`/`GetProcAddress`/`FreeLibrary`. Per the project's
//! layering rule, the OS behaviour lives in `platform/<os>.rs` and this file holds
//! only the contract both must satisfy — no `#[cfg(target_os)]` in core modules.
//!
//! `libloading` already implements both spellings, so the split here is not about
//! writing the syscalls; it is about keeping the *error strings* honest. Node's
//! `ERR_DLOPEN_FAILED` message is whatever the platform's loader said, and a user
//! comparing runtimes sees that text. Each backend returns its loader's own
//! message rather than a normalised one, so the comparison holds.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::Library;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Library;

/// A loaded shared object.
///
/// The concrete type differs per platform; what both must provide is `open`,
/// `symbol`, and a `Drop` that closes the handle. `symbol` is intentionally
/// unsafe-but-hidden: the caller supplies the type, and the only types anything in
/// this crate asks for are Node-API entry points whose signatures come from the
/// headers.
///
/// There is no `#[cfg(not(any(unix, windows)))]` fallback. An unsupported target
/// should fail to compile rather than silently report that every addon is
/// unavailable, which is what a stub `Library` would do.
const _: () = {
    // A compile-time reminder that the two backends must stay in step. If a third
    // platform family is added, this assertion is where the decision is recorded.
    assert!(cfg!(unix) || cfg!(windows));
};

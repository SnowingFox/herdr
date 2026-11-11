//! `dlopen` on Unix.
//!
//! `libloading`'s `Library::new` is `dlopen(path, RTLD_LAZY | RTLD_LOCAL)`, which
//! is the same pair Node's `uv_dlopen` uses. Two details are worth recording
//! because they are what make the symbols work at all:
//!
//! * **`RTLD_LOCAL` is correct here, not `RTLD_GLOBAL`.** The addon's `napi_*`
//!   imports are resolved against the *executable*, whose symbols are global by
//!   virtue of `--export-dynamic-symbol=napi_*` at link time. Nothing needs this
//!   library's symbols to become globally visible, and making them global would
//!   let two addons collide on each other's exports.
//! * **Resolution is not attempted at open time** for `napi_*`; `RTLD_LAZY`
//!   defers function-call relocations to first use. That is why an addon with a
//!   missing `napi_*` import opens successfully and then fails on the call, which
//!   is exactly the failure mode a clear deferred-symbol list avoids.

use std::ffi::OsStr;
use std::path::Path;

/// A loaded shared object.
pub struct Library {
    inner: libloading::Library,
}

impl Library {
    /// Opens the shared object at `path`.
    ///
    /// The error is the dynamic loader's own message, which Node passes straight
    /// into `ERR_DLOPEN_FAILED`. It already contains the path and the reason
    ///
    /// * `cannot open shared object file: No such file or directory`
    /// * `file too short`
    /// * `invalid ELF header`
    /// * `cannot read file data: Is a directory`
    ///
    /// so this does not prefix it a second time.
    pub fn open(path: &Path) -> Result<Self, String> {
        // SAFETY: `dlopen` on a path is safe to call; the contract this crate has
        // to keep is that no symbol taken from the handle outlives it, which the
        // `Library` ownership in `load.rs` enforces.
        unsafe { libloading::Library::new(OsStr::new(path)) }
            .map(|inner| Self { inner })
            .map_err(|error| error.to_string())
    }

    /// Looks up one exported symbol.
    ///
    /// Returns the symbol's address as a `T`. The caller names the type, and the
    /// only types asked for are entry points whose signatures come from Node's
    /// headers.
    ///
    /// # Safety
    ///
    /// The symbol must genuinely have the type `T`. Nothing about a dynamic symbol
    /// table carries a type, so a mismatch here is the classic way to get an
    /// unexplainable crash inside an addon — hence the narrow set of call sites.
    pub unsafe fn symbol<T>(&self, name: &str) -> Result<libloading::Symbol<'_, T>, String> {
        let name = std::ffi::CString::new(name).map_err(|error| error.to_string())?;
        // SAFETY: delegated to this function's caller.
        unsafe { self.inner.get::<T>(name.as_bytes_with_nul()) }.map_err(|error| error.to_string())
    }
}

impl std::fmt::Debug for Library {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Library").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_reports_the_loaders_own_message() {
        // Node's message for this case is the loader's text verbatim, so the
        // wording is part of the contract rather than an implementation detail.
        let error =
            Library::open(Path::new("/definitely/not/here/addon.node")).expect_err("must fail");
        assert!(
            error.contains("cannot open shared object file"),
            "unexpected text: {error}"
        );
        assert!(
            error.contains("/definitely/not/here/addon.node"),
            "the path must be named: {error}"
        );
    }

    #[test]
    fn a_directory_reports_that_it_could_not_be_read() {
        let error = Library::open(Path::new("/tmp")).expect_err("must fail");
        assert!(
            error.contains("Is a directory") || error.contains("cannot read file data"),
            "unexpected text: {error}"
        );
    }

    #[test]
    fn a_non_shared_object_reports_a_bad_header() {
        let path = std::env::temp_dir().join(format!(
            "rn-napi-notso-{}-{:?}.node",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"this is not a shared object").expect("write");
        let error = Library::open(&path).expect_err("must fail");
        let _ = std::fs::remove_file(&path);
        // `file too short` for a small file; an ELF-header complaint for a large
        // one. Either names the file, which is what the error contract needs.
        assert!(
            error.contains("file too short")
                || error.contains("invalid ELF header")
                || error.contains("cannot read file data"),
            "unexpected text: {error}"
        );
    }
}

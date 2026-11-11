//! `LoadLibraryExW` on Windows.
//!
//! `libloading` maps `Library::new` to `LoadLibraryExW` with
//! `LOAD_WITH_ALTERED_SEARCH_PATH`, and `get` to `GetProcAddress`. Node uses
//! `LoadLibraryExW` with the same flags in `uv_dlopen`, so the search behaviour
//! matches.
//!
//! The one place the platforms genuinely differ is the error text: Windows returns
//! a numeric `GetLastError` code, and Node appends the filename to the message
//! itself (`dlib->errmsg_ + filename`) because the Win32 text does not name the
//! file. This backend does the same, so the message a user sees names the addon on
//! both platforms.

use std::path::Path;

/// A loaded shared object.
pub struct Library {
    inner: libloading::Library,
}

impl Library {
    /// Opens the shared object at `path`.
    ///
    /// The returned message is the Win32 error text with the path appended, which
    /// is what `node_binding.cc` builds for this platform:
    ///
    /// ```c
    /// errmsg += filename.ToStringView();
    /// ```
    pub fn open(path: &Path) -> Result<Self, String> {
        // SAFETY: `LoadLibraryExW` on a path is safe to call; what this crate must
        // keep is that no symbol taken from the handle outlives it, which the
        // `Library` ownership in `load.rs` enforces.
        unsafe { libloading::Library::new(path) }
            .map(|inner| Self { inner })
            .map_err(|error| format!("{error}{}", path.display()))
    }

    /// Looks up one exported symbol.
    ///
    /// # Safety
    ///
    /// The symbol must genuinely have the type `T`; see the Unix backend for why
    /// that is the caller's burden.
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

/// Windows shared-object suffix, for callers building a filename.
pub const DYLIB_SUFFIX: &str = "dll";

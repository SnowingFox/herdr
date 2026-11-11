//! The three memory-BIO operations this crate needs.
//!
//! `openssl-sys` exports `BIO_new`, `BIO_s_mem` and `BIO_free` but not the
//! accessors, and it cannot: `BIO_get_mem_data` is a macro over `BIO_ctrl`, and
//! `BIO_write` is a macro over `BIO_write_ex`. Declaring the macros as `extern
//! "C"` fns compiles and then fails to link, which is why the `BIO_ctrl` form is
//! used here.
//!
//! One module rather than a copy in each formatter: five copies of the same
//! `BIO_ctrl` invocation is five places for the `BIO_CTRL_INFO` constant to drift.

use openssl_sys as ffi;

extern "C" {
    fn BIO_new(kind: *const ffi::BIO_METHOD) -> *mut ffi::BIO;
    fn BIO_s_mem() -> *const ffi::BIO_METHOD;
    fn BIO_free(bio: *mut ffi::BIO) -> std::ffi::c_int;
    fn BIO_ctrl(
        bio: *mut ffi::BIO,
        cmd: std::ffi::c_int,
        larg: std::ffi::c_long,
        parg: *mut std::ffi::c_void,
    ) -> std::ffi::c_long;
    fn BIO_write(
        bio: *mut ffi::BIO,
        data: *const std::ffi::c_void,
        length: std::ffi::c_int,
    ) -> std::ffi::c_int;
}

/// `BIO_CTRL_INFO`, the `BIO_ctrl` command `BIO_get_mem_data` expands to.
const BIO_CTRL_INFO: std::ffi::c_int = 3;

/// A memory BIO that frees itself, and whose contents are read as bytes.
pub struct MemoryBio(*mut ffi::BIO);

impl MemoryBio {
    /// Allocates one, or `None` when the allocator fails.
    pub fn new() -> Option<Self> {
        // SAFETY: `BIO_s_mem` returns a static method table and `BIO_new`
        // allocates one BIO over it.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        (!bio.is_null()).then_some(Self(bio))
    }

    /// The raw handle, for the few callers that print into a BIO directly.
    pub fn raw(&self) -> *mut ffi::BIO {
        self.0
    }

    /// Appends bytes, reporting whether the whole slice was written.
    pub fn write(&mut self, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        // SAFETY: the BIO is live and `bytes` outlives the call.
        unsafe {
            BIO_write(
                self.0,
                bytes.as_ptr().cast::<std::ffi::c_void>(),
                bytes.len() as std::ffi::c_int,
            ) as usize
                == bytes.len()
        }
    }

    /// The contents as a string, or `None` when they are not valid UTF-8.
    ///
    /// Every producer here is either OpenSSL's ASCII name printer or a literal
    /// like `"Bad time value"`, so invalid UTF-8 means something is wrong rather
    /// than that a lossy decode is owed.
    pub fn to_string(&mut self) -> Option<String> {
        let bytes = self.to_bytes()?;
        String::from_utf8(bytes).ok()
    }

    /// The contents as bytes.
    pub fn to_bytes(&mut self) -> Option<Vec<u8>> {
        let mut data: *mut std::ffi::c_char = std::ptr::null_mut();
        // SAFETY: `BIO_ctrl(BIO_CTRL_INFO)` writes the buffer pointer into `parg`
        // and returns its length. The pointer refers to the BIO's own buffer,
        // which stays valid until the next write or the free.
        let length = unsafe {
            BIO_ctrl(
                self.0,
                BIO_CTRL_INFO,
                0,
                (&mut data as *mut *mut std::ffi::c_char).cast::<std::ffi::c_void>(),
            )
        };
        if length < 0 || (length > 0 && data.is_null()) {
            return None;
        }
        if length == 0 {
            return Some(Vec::new());
        }
        // SAFETY: `length` bytes at `data` belong to the BIO, which outlives this
        // borrow because the copy happens before it is dropped.
        Some(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length as usize) }.to_vec())
    }
}

impl Drop for MemoryBio {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `BIO_new` and is freed exactly once.
        unsafe { BIO_free(self.0) };
    }
}

/// Runs `body` against a fresh memory BIO and returns its contents.
///
/// The common shape: allocate, print into it, read it back, free it.
pub fn with_memory_bio(body: impl FnOnce(&mut MemoryBio) -> bool) -> Option<String> {
    let mut bio = MemoryBio::new()?;
    if !body(&mut bio) {
        return None;
    }
    bio.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_bio_round_trips_bytes() {
        let mut bio = MemoryBio::new().expect("a memory BIO");
        assert!(bio.write(b"hello"));
        assert_eq!(bio.to_string().as_deref(), Some("hello"));
    }

    #[test]
    fn writes_append() {
        let mut bio = MemoryBio::new().expect("a memory BIO");
        assert!(bio.write(b"one"));
        assert!(bio.write(b"two"));
        assert_eq!(bio.to_string().as_deref(), Some("onetwo"));
    }

    #[test]
    fn an_empty_bio_reads_as_an_empty_string() {
        // `ToV8Value` maps an empty BIO to an empty string, not `undefined`; the
        // difference matters for `infoAccess` on a certificate with an empty
        // extension.
        let mut bio = MemoryBio::new().expect("a memory BIO");
        assert_eq!(bio.to_string().as_deref(), Some(""));
    }
}

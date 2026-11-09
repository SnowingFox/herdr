//! `internalBinding('zlib')` for rustnode.
//!
//! The JavaScript in `vendor/libnode-js/lib/zlib.js` is unchanged Node code. It
//! owns every stream, error and option decision; this crate is only the native
//! handle it drives. The handle contract is the one `src/node_zlib.cc` defines:
//!
//! * `init(level, windowBits, memLevel, strategy, writeState, writeCb,
//!   dictionary[, rejectGarbageAfterEnd])` for `new binding.Zlib(mode)`.
//! * `writeSync(flush, in, inOff, inLen, out, outOff, outLen)` compresses once
//!   and leaves the remaining space in `writeState`.
//! * `write(..)` is the asynchronous form; it must not run the compression
//!   inside the call, and reports completion by invoking `writeCb`.
//! * `params(level, strategy)`, `reset()` and `close()`.
//!
//! `writeState` is a `Uint32Array(2)`: `[availOutAfter, availInAfter]`, in that
//! order. Both offsets are read by the JS after every write, so they have to be
//! written back before any callback runs.

pub mod brotli;
pub mod constants;
pub mod crc;
pub mod handle;
pub mod zlib;

pub use zlib::ZlibMode;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// What a single `write`/`writeSync` step left over, in the order Node stores
/// it into `writeState`.
///
/// `lib/zlib.js` reads `state[0]` as `availOutAfter` and `state[1]` as
/// `availInAfter`, while `node_zlib.cc` fills them as
/// `GetAfterWriteOffsets(&write_result_[1], &write_result_[0])`. Naming the
/// fields keeps that inversion from being a silent bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AfterWrite {
    /// Input bytes the stream did not consume.
    pub avail_in: u32,
    /// Output bytes still free in the caller's buffer.
    pub avail_out: u32,
}

/// How many handle states are currently allocated.
///
/// Incremented when a handle's state is installed and decremented by its
/// finalizer. Exposed so the integration test can prove that a GC actually
/// reclaims handles that were never `close()`d, rather than leaking them.
#[doc(hidden)]
pub fn live_handle_count() -> usize {
    LIVE_HANDLES.with(|cell| cell.get())
}

thread_local! {
    static LIVE_HANDLES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(crate) fn note_handle_allocated() {
    LIVE_HANDLES.with(|cell| cell.set(cell.get() + 1));
}

pub(crate) fn note_handle_released() {
    LIVE_HANDLES.with(|cell| cell.set(cell.get().saturating_sub(1)));
}

/// The `zlib` namespace.
pub struct Zlib;

impl BindingModule for Zlib {
    fn namespace(&self) -> &'static str {
        "zlib"
    }

    fn members(&self) -> &'static [&'static str] {
        &[
            "Zlib",
            "BrotliEncoder",
            "BrotliDecoder",
            "crc32",
            "ZLIB_VERSION",
        ]
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        handle::install_constructors(scope, object)?;
        crc::install(scope, object)?;
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::Zlib;
    use rn_core::BindingModule;

    #[test]
    fn namespace_and_members_match_the_javascript_call_sites() {
        let binding = Zlib;
        assert_eq!(binding.namespace(), "zlib");
        assert_eq!(
            binding.members(),
            &[
                "Zlib",
                "BrotliEncoder",
                "BrotliDecoder",
                "crc32",
                "ZLIB_VERSION"
            ]
        );
    }
}

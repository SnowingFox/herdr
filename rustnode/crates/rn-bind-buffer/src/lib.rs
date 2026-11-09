//! `internalBinding('buffer')` for rustnode.
//!
//! `lib/buffer.js`, `lib/internal/buffer.js` and
//! `lib/internal/webstreams/util.js` are unchanged Node code. Between them they
//! call all 40 members `Initialize()` in `src/node_buffer.cc` installs, and the
//! crate reproduces each one with the argument order those call sites use.
//!
//! # Shape of the work
//!
//! Three layers, each testable on its own:
//!
//! * [`rn_core::codec`] is the byte arithmetic: hex, base64, UTF-8, UCS-2 and the
//!   byte search. It has no V8 types at all, so it is unit-tested directly and
//!   compared against a real `node` binary in `tests/`. It lives in the kernel
//!   crate rather than here because `StreamBase`'s write path encodes strings
//!   too, and `rn-uv` cannot depend on a binding crate.
//! * [`args`] lifts JavaScript arguments out of V8 — the `ParseArrayIndex`,
//!   `ParseEncoding` and `ArrayBufferView` accessors `node_buffer.cc` uses.
//! * [`encoding`], [`bytes`] and [`misc`] are the members themselves, written as
//!   the C++ functions they replace.
//!
//! [`install`] wires them onto the namespace object and is the only place V8
//! function templates are created.
//!
//! # What is done where
//!
//! Where Node calls simdutf — `isUtf8`, `isAscii`, `atob`, `btoa`, and the
//! UTF-16/UTF-8 length calculations — this crate calls the same functions
//! through the `v8` crate's [`v8::simdutf`] module, which is the copy of simdutf
//! already linked into V8. That keeps validation and the strict WHATWG base64
//! rules exactly Node's instead of a second implementation drifting from them.
//! Everything else is byte arithmetic written out here; no new dependency is
//! needed and none was added.
//!
//! # Deliberate deviations
//!
//! * `arrayBufferAlignedOffset` computes the real padding from the backing store
//!   address rather than returning `0`. Node returns `0` only while building a
//!   snapshot, which rustnode does not do yet; the arithmetic is the same as the
//!   non-snapshot path in `node_buffer.cc`.
//! * `byteLengthUtf8Fast` returns the true length instead of Node's `-1`
//!   sentinel. `lib/buffer.js` treats `-1` as "call the slow function", so a real
//!   length is equally correct and saves the second call.
//! * `createUnsafeArrayBuffer` has no snapshot path, so it always returns an
//!   uninitialised backing store (zero-length buffers use a zeroed one).

pub mod args;
pub mod bytes;
pub mod encoding;
pub mod install;
pub mod misc;

pub use install::Buffer;

/// Registers the `buffer` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Buffer);
}

#[cfg(test)]
mod tests {
    use rn_core::BindingModule;

    use super::*;

    #[test]
    fn namespace_name_is_buffer() {
        assert_eq!(Buffer.namespace(), "buffer");
    }

    #[test]
    fn member_list_is_the_contract() {
        // `contracts/buffer.json` records 40 members; `Initialize()` in
        // `node_buffer.cc` installs the same 40. A test in
        // `tests/js_contract.rs` pins the set against the contract file, and
        // this one catches an accidental duplicate or a dropped name.
        assert_eq!(install::MEMBERS.len(), 40);
        let mut sorted = install::MEMBERS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 40, "duplicate member name in MEMBERS");
        assert_eq!(Buffer.members().len(), 40);
    }

    #[test]
    fn every_member_is_installed_and_none_deferred() {
        assert!(Buffer.deferred().is_empty());
        for member in Buffer.members() {
            assert!(!member.is_empty());
        }
    }
}

//! Node-API for rustnode: the symbol table, the loader, and the environment.
//!
//! # How an addon's `napi_*` calls reach this crate
//!
//! An addon written for Node is compiled against `node_api.h`, which declares the
//! ~200 `napi_*` functions `extern` and expects the *host binary* to provide them.
//! On Linux the addon's undefined `napi_*` symbols are resolved by the dynamic
//! loader against the global symbol scope of the process — which means the
//! rustnode executable itself must export them from its `.dynsym`.
//!
//! Three ways to achieve that were considered:
//!
//! | Approach | Why it was rejected |
//! | --- | --- |
//! | Register a symbols object at `process.dlopen` time | Node-API has no such registration step. An addon's relocations are resolved by the *loader*, before any of our code runs, so there is nothing to register against. |
//! | Ship an `RTLD_GLOBAL`-loaded shared library of shims | Works, but adds a second artifact that has to be located relative to the executable, and the two can skew: an addon could bind shims from one build and run against another. |
//! | **Export the shims from the binary itself** | **Chosen.** It is what Node does — `libnode` is linked in and its symbols exported — needs no extra file, and cannot desynchronise from the runtime because it *is* the runtime. |
//!
//! The mechanism is `-Wl,--export-dynamic-symbol=napi_*`, emitted by
//! `crates/rn-cli/build.rs`. That flag adds matching symbols to `.dynsym` without
//! `--export-dynamic`'s cost of publishing everything else.
//!
//! It lives there and not here because `cargo::rustc-link-arg` from a build script
//! applies to that script's own crate target, and cargo does not forward it from a
//! library dependency to the binary that links it. That was measured, not assumed:
//! with the flag in `rn-napi`'s build script the built executable's `.dynsym` held
//! zero `napi_*` entries, and moving the same two lines into `rn-cli/build.rs` put
//! all of them in. `tests/symbols.rs` then reads the built binary's own dynamic
//! symbol table and compares it against [`shims::EXPORTED`], so a shim that is
//! written but never exported fails the gate.
//!
//! `#[no_mangle]` alone is not sufficient. A symbol reaches `.dynsym` only if the
//! linker was asked for it, and nothing in Rust references these shims (that is
//! what they are for), so no other mechanism pulls them in. The shim definition and
//! the link flag are both required, and the test pins the pair.

pub mod abi;
pub mod async_work;
pub mod buffer;
pub mod callback;
pub mod env;
pub mod load;
pub mod scope;
pub mod shims;
pub mod symbols;
pub mod threadsafe;
pub mod values;
pub mod wrap;

#[cfg(unix)]
pub mod platform;
#[cfg(windows)]
pub mod platform;

#[cfg(not(any(unix, windows)))]
compile_error!(
    "rn-napi implements shared-library loading for Unix and Windows only; \
     a stub backend would silently report every addon as unavailable"
);

pub use abi::{NapiEnv, NapiStatus, NapiValue};
pub use env::Env;
pub use load::{LoadError, LoadResult, LoadedAddon};
pub use shims::{DEFERRED, EXPORTED};

/// `napi_register_module_v1`'s symbol name.
pub const REGISTER_MODULE_SYMBOL: &str = abi::REGISTER_MODULE_SYMBOL;

/// Replaces `module.exports` with the object an addon returned, if it returned a
/// different one.
///
/// Node's `napi_module_register_by_symbol` only reassigns when the returned
/// `napi_value` differs from the exports object it was given, so an addon that
/// mutates `exports` in place keeps the identity the CommonJS loader already
/// handed out.
///
/// # Safety
///
/// `returned` must be a handle from a scope that is still alive.
pub unsafe fn apply_returned_exports(
    scope: &mut v8::PinScope<'_, '_>,
    module: v8::Local<v8::Object>,
    original: v8::Local<v8::Value>,
    returned: *mut NapiValue,
) {
    // SAFETY: the caller guarantees the handle is live.
    let Some(returned) = (unsafe { values::from_napi(returned) }) else {
        return;
    };
    if returned.strict_equals(original) {
        return;
    }
    if let Some(key) = v8::String::new(scope, "exports") {
        let _ = module.set(scope, key.into(), returned);
    }
}

use rn_v8_sys::v8;

//! Finding the `uv_stream_t` behind a JavaScript stream handle.
//!
//! `src/process_wrap.cc`'s `ParseStdioOptions` has to hand libuv the actual
//! `uv_stream_t` a `'pipe'` or `'wrap'` stdio entry names, and neither case can be
//! expressed as a descriptor instead:
//!
//! * `UV_CREATE_PIPE` makes libuv create the child's end of *that* stream, so the
//!   stream must be unopened when `uv_spawn` runs and has no descriptor at all.
//! * `UV_INHERIT_STREAM` gives the child the parent's own handle, which is not
//!   interchangeable with a descriptor on Windows.
//!
//! In Node the mapping is free: `LibuvStreamWrap::From(env, handle)` unwraps the
//! `BaseObject` the handle object already points at. rustnode has one crate per
//! namespace, so `process_wrap` cannot read `tcp_wrap`'s or `pipe_wrap`'s private
//! allocation. This module is the shared answer: a binding [`attach`]es its stream
//! to the object under a per-isolate symbol, and anything that needs the stream
//! [`stream_of`]s it back.
//!
//! # Why a symbol property rather than a registry
//!
//! A side table would have to root the object to recognise it later, which pins
//! every socket for the process' life, and a raw pointer in a table would have to
//! be invalidated by hand from each binding's close path. An `External` under a
//! symbol key lives and dies with the object: V8 collects the handle exactly as
//! it would have otherwise, and the pairing cannot outlive it.
//!
//! The symbol is defined non-enumerable, so `Object.keys`, `for..in` and
//! `JSON.stringify` do not see it. It is a *registered* symbol rather than a
//! `v8::Private` because the `v8` crate cannot pass a `Private` to
//! `Object::set`, which wants a `Value`; [`rn_core::symbol`] documents that same
//! trade-off.
//!
//! # Invalidation
//!
//! `uv_close` is asynchronous and the stream stays usable until its callback
//! runs, so the pointer stays valid while the handle is only closing. A handle
//! that *has* been closed must not be handed to a spawn, so [`detach`] is called
//! from the close callback that frees the state.

use rn_v8_sys::v8;

use crate::handle::StreamState;
use crate::sys;

/// The per-isolate symbol a stream pointer is stored under.
///
/// Node reaches the same fact through `LibuvStreamWrap::From`; this is the name
/// that stands in for that unwrap across crates.
pub const STREAM_SYMBOL: &str = "node:rustnode:uv_stream";

/// The symbol, created as a *registered* symbol so identity is per isolate.
///
/// `Symbol::for_key` gives the same symbol for the same description inside one
/// isolate and a distinct one in another, which is exactly the lifetime a stream
/// pointer has. `rn_core::symbol` would also do, but it caches a `v8::Global` in a
/// thread-local, so a test process that creates a second isolate would hand out a
/// symbol owned by the first — which crashes when it is used.
fn stream_symbol<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Symbol> {
    // A description that cannot be allocated leaves an empty symbol, which no
    // attach/lookup pair will ever disagree about because both take this path.
    let description =
        v8::String::new(scope, STREAM_SYMBOL).unwrap_or_else(|| v8::String::empty(scope));
    v8::Symbol::for_key(scope, description)
}

/// Records `state`'s stream on `object`, so another binding can find it.
///
/// Called by a stream binding when it installs a handle. `state` must live for as
/// long as the object does; every binding already keeps it in the same allocation
/// as the handle itself.
///
/// # Safety
///
/// `state` must be a live [`StreamState`] whose `stream` field names a handle the
/// calling binding owns. Every caller passes the state pointer it just installed,
/// which satisfies this by construction.
pub unsafe fn attach(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    state: *mut StreamState,
) {
    if state.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `state` is a live `StreamState`, so its
    // `stream` field names the handle the binding initialised.
    let stream = unsafe { (*state).stream };
    if stream.is_null() {
        return;
    }
    let external = v8::External::new(scope, stream.cast());
    let symbol = stream_symbol(scope);
    object.set(scope, symbol.into(), external.into());
}

/// Drops the pairing, so a closed handle cannot be mistaken for a live one.
///
/// Called from a binding's close callback, before the state it named is freed.
pub fn detach(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) {
    let symbol = stream_symbol(scope);
    object.set(scope, symbol.into(), v8::undefined(scope).into());
}

/// The `uv_stream_t` attached to a JavaScript stream handle.
///
/// Returns `None` for an object no binding attached, which is what
/// `LibuvStreamWrap::From` reports for a handle of an unknown type.
///
/// # Safety
///
/// The returned pointer belongs to the binding that [`attach`]ed it. It stays
/// valid until that binding's close callback runs, so a caller must not keep it
/// across a loop turn in which the handle could close.
pub unsafe fn stream_of(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
) -> Option<*mut sys::uv_stream_t> {
    let symbol = stream_symbol(scope);
    let value = object.get(scope, symbol.into())?;
    let external = v8::Local::<v8::External>::try_from(value).ok()?;
    let pointer = external.value().cast::<sys::uv_stream_t>();
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

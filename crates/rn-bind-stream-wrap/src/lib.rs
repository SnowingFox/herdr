//! `internalBinding('stream_wrap')` for rustnode.
//!
//! `lib/internal/stream_base_commons.js` is unchanged Node code and this
//! namespace is what it stands on. It destructures five things at module scope:
//!
//! ```js
//! const {
//!   kReadBytesOrError,
//!   kArrayBufferOffset,
//!   kBytesWritten,
//!   kLastWriteErr,
//!   streamBaseState,
//! } = internalBinding('stream_wrap');
//! ```
//!
//! and `lib/net.js` additionally constructs `ShutdownWrap` per `socket.end()`.
//! `WriteWrap` is the sixth member, constructed lazily by the native write path
//! and by `lib/net.js`'s `_writeGeneric` when a request object is needed up
//! front.
//!
//! # `streamBaseState` is the interesting member
//!
//! It is an **`Int32Array(5)`**, not an `Array` and not a `Uint8Array`, and both
//! facts are load-bearing:
//!
//! * `src/env.h` declares the field as `AliasedInt32Array`, so an index means
//!   one `i32` on both sides. Exposing the bytes as a `Uint8Array` would make
//!   `streamBaseState[2]` mean byte 2 rather than word 2 and silently corrupt
//!   every value the two sides exchange.
//! * It is an *aliased* array: JavaScript writes it and native code reads the
//!   same memory, which is how `afterWriteDispatched` learns the byte count
//!   without a second call. A copied array would freeze at zero.
//!
//! The indices are `StreamBaseStateFields` in `src/stream_base.h`, in that
//! order: `kReadBytesOrError`, `kArrayBufferOffset`, `kBytesWritten`,
//! `kLastWriteWasAsync`, `kLastWriteErr`. [`rn_uv::handle`] owns the constants
//! because the read and write paths there are what fill them in.
//!
//! # What this crate cannot deliver on its own
//!
//! `ShutdownWrap` and `WriteWrap` are constructible, have the internal fields
//! Node pre-creates on them, and are what a `uv_write`/`uv_shutdown` completion
//! reports back to. They do not *initiate* anything: a write starts at
//! `handle.writev(...)`/`handle.writeBuffer(...)` on a `tcp_wrap` or `pipe_wrap`
//! handle, and those crates own the libuv request. What this crate supplies is
//! the object shape, the shared state buffer, and the completion plumbing those
//! writes call into.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub mod wrap;

pub use wrap::{ShutdownWrap, WriteWrap};

use rn_uv::handle::{
    K_ARRAY_BUFFER_OFFSET, K_BYTES_WRITTEN, K_LAST_WRITE_ERR, K_LAST_WRITE_WAS_ASYNC,
    K_READ_BYTES_OR_ERROR,
};

/// The five index constants, re-exported so the namespace and the read/write
/// paths cannot disagree about an index.
pub const K_READ: usize = K_READ_BYTES_OR_ERROR;
pub const K_OFFSET: usize = K_ARRAY_BUFFER_OFFSET;
pub const K_WRITTEN: usize = K_BYTES_WRITTEN;
pub const K_ASYNC: usize = K_LAST_WRITE_WAS_ASYNC;
pub const K_WRITE_ERR: usize = K_LAST_WRITE_ERR;

/// Members exposed on the namespace object, matching `contracts/stream_wrap.json`.
pub const MEMBERS: &[&str] = &[
    "ShutdownWrap",
    "WriteWrap",
    "kArrayBufferOffset",
    "kBytesWritten",
    "kLastWriteErr",
    "kLastWriteWasAsync",
    "kReadBytesOrError",
    "streamBaseState",
];

/// Members this namespace needs but cannot install yet, each with the reason.
///
/// Empty: every recorded member is installed. `lib/internal/stream_base_commons.js`
/// and `lib/net.js` both load and run against this namespace.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('stream_wrap')`.
pub struct StreamWrap;

/// Whether the state buffer has been created.
pub fn state_initialised() -> bool {
    rn_uv::stream::state_initialised()
}

/// Runs `body` with the shared `streamBaseState` buffer.
///
/// This is the escape hatch the read and write paths use, and the one a test uses
/// to prove the Rust side and the JavaScript side share one allocation: a value
/// written from either side has to read back from the other.
pub fn with_state_probe<R>(
    _scope: &mut v8::PinScope<'_, '_>,
    body: impl FnOnce(&rn_core::AliasedUint8Array) -> R,
) -> Option<R> {
    rn_uv::stream::with_state(body)
}

impl BindingModule for StreamWrap {
    fn namespace(&self) -> &'static str {
        "stream_wrap"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        // `src/stream_wrap.cc` registers the two constructors before the
        // constants, and `Object.keys()` exposes that order.
        let shutdown = wrap::constructor::<wrap::ShutdownWrap>(scope, wrap::shutdown_constructor)?;
        set(scope, object, "ShutdownWrap", shutdown)?;
        let write = wrap::constructor::<wrap::WriteWrap>(scope, wrap::write_constructor)?;
        set(scope, object, "WriteWrap", write)?;

        // `NODE_DEFINE_CONSTANT` produces `ReadOnly | DontDelete` (not
        // `DONT_ENUM`), so these appear in `Object.keys()` and cannot be
        // reassigned.
        for (name, value) in [
            ("kReadBytesOrError", K_READ),
            ("kArrayBufferOffset", K_OFFSET),
            ("kBytesWritten", K_WRITTEN),
            ("kLastWriteWasAsync", K_ASYNC),
            ("kLastWriteErr", K_WRITE_ERR),
        ] {
            let value = v8::Integer::new(scope, value as i32);
            define_constant(scope, object, name, value.into())?;
        }

        // The shared buffer, allocated here on first install and handed to JS
        // as-is: `src/stream_wrap.cc` publishes `env->stream_base_state()
        // .GetJSArray()` directly rather than a copy.
        // The shared buffer. `src/stream_wrap.cc` publishes
        // `env->stream_base_state().GetJSArray()` directly rather than a copy,
        // and `rn-uv`'s read and write paths write the same allocation, which is
        // the whole point of it being aliased.
        let array = rn_uv::stream::state_array(scope)
            .ok_or("cannot allocate the stream base state buffer")?;
        set(scope, object, "streamBaseState", array)?;

        Ok(object)
    }
}

/// Registers the `stream_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(StreamWrap);
}

fn define_constant(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .define_own_property(
            scope,
            key.into(),
            value,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or_else(|| format!("cannot define constant {name}"))?;
    Ok(())
}

fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

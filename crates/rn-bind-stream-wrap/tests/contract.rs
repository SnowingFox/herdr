//! The `stream_wrap` contract, checked through a real V8 isolate.
//!
//! `lib/internal/stream_base_commons.js` destructures `streamBaseState` and its
//! five index constants at module scope, then reads them on every read and write.
//! Two things about that array are load-bearing and both are easy to get wrong
//! silently:
//!
//! * **The element type is `Int32Array`.** `src/env.h` declares the field as
//!   `AliasedInt32Array`. Exposing the same bytes as a `Uint8Array` compiles,
//!   loads, and then makes `streamBaseState[2]` mean byte 2 rather than word 2 —
//!   every value exchanged between JS and native code would be wrong.
//! * **It is aliased, not copied.** JavaScript writes it and native code reads the
//!   same memory. A copy would look correct until the first write.
//!
//! So the tests below write from JavaScript and read back from Rust, and write
//! from Rust and read back from JavaScript. That is the only way to prove the two
//! sides share one allocation.
//!
//! The `ShutdownWrap` and `WriteWrap` shapes are pinned the same way: Node's
//! `Initialize` pre-creates specific fields on each so `lib/net.js` assigns them
//! through a monomorphic path, and a missing field is not an error — just a
//! permanently deoptimised object.

use rn_bind_stream_wrap::StreamWrap;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate, scope and context.
///
/// V8's platform and initialisation are process-global, so the tests serialise on
/// a mutex instead of each calling `V8::initialize`.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // The guard must outlive the isolate: dropping it would let a second test
    // enter `V8::initialize` concurrently.
    let _guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let mut scope = scope.init();
    let context = v8::Context::new(&scope, Default::default());
    let scope = std::pin::pin!(v8::ContextScope::new(&mut scope, context));
    let mut scope = scope;
    body(&mut scope)
}

fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace and binds it to `__stream` in the global object.
fn install<'s>(scope: &mut v8::PinScope<'s, '_>) {
    let object = StreamWrap
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("installing the stream_wrap namespace must not fail");
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__stream").expect("allocating __stream");
    global.set(scope, key.into(), object.into());
}

/// Evaluates `source` with `__stream` bound to the installed namespace.
fn eval(source: &str) -> String {
    with_context(|scope| {
        install(scope);
        let source = v8::String::new(scope, source).expect("allocating the probe");
        let script = v8::Script::compile(scope, source, None).expect("compiling the probe");
        let result = script.run(scope).expect("running the probe");
        result.to_rust_string_lossy(scope)
    })
}

/// The eight members `contracts/stream_wrap.json` records.
#[test]
fn the_namespace_publishes_exactly_the_recorded_members() {
    let members = eval(
        r#"
        Object.keys(__stream).sort().join(',')
        "#,
    );
    assert_eq!(
        members,
        "ShutdownWrap,WriteWrap,kArrayBufferOffset,kBytesWritten,kLastWriteErr,\
kLastWriteWasAsync,kReadBytesOrError,streamBaseState"
    );
}

/// The index constants are `StreamBaseStateFields`, in declaration order.
///
/// `lib/internal/stream_base_commons.js` and `lib/internal/webstreams/adapters.js`
/// both index the array with these, so a transposed pair would make every read
/// report a byte count where a write error belongs.
#[test]
fn the_index_constants_match_stream_base_state_fields() {
    let values = eval(
        r#"
        [
          __stream.kReadBytesOrError,
          __stream.kArrayBufferOffset,
          __stream.kBytesWritten,
          __stream.kLastWriteWasAsync,
          __stream.kLastWriteErr,
        ].join(',')
        "#,
    );
    assert_eq!(
        values, "0,1,2,3,4",
        "StreamBaseStateFields order is kReadBytesOrError, kArrayBufferOffset, \
kBytesWritten, kLastWriteWasAsync, kLastWriteErr"
    );
}

/// `streamBaseState` is an `Int32Array(5)`, which is `AliasedInt32Array` in
/// `src/env.h`.
///
/// The constructor name is checked rather than just the length because the width
/// is the part that silently breaks: five elements of the wrong type still has a
/// `.length` of 5.
#[test]
fn stream_base_state_is_an_int32_array_of_five_elements() {
    // One probe, because `streamBaseState` is a thread-local that outlives each
    // test's isolate: a second `with_context` here would return a handle into the
    // isolate the first one disposed.
    let report = eval(
        r#"
        const state = __stream.streamBaseState;
        [
          state.constructor.name,
          state.length,
          Object.prototype.toString.call(state),
          state.BYTES_PER_ELEMENT,
        ].join(',')
        "#,
    );
    assert_eq!(
        report, "Int32Array,5,[object Int32Array],4",
        "src/env.h declares the field as AliasedInt32Array: five 4-byte elements"
    );
}

/// A value written from JavaScript is visible to Rust in the same allocation.
///
/// This is the whole point of the buffer being aliased: `afterWriteDispatched`
/// reads `streamBaseState[kBytesWritten]` immediately after the native write
/// returns, with no intervening call.
#[test]
fn javascript_writes_are_visible_to_rust() {
    with_context(|scope| {
        install(scope);
        let source = v8::String::new(
            scope,
            r#"
            const s = __stream.streamBaseState;
            s[__stream.kReadBytesOrError] = 4242;
            s[__stream.kArrayBufferOffset] = 7;
            s[__stream.kBytesWritten] = -1;
            s[__stream.kLastWriteWasAsync] = 1;
            s[__stream.kLastWriteErr] = -32;
            "ok"
            "#,
        )
        .expect("allocating the probe");
        let script = v8::Script::compile(scope, source, None).expect("compiling the probe");
        script.run(scope).expect("running the probe");

        // Read the same allocation back through the binding's own handle.
        let values = rn_bind_stream_wrap::with_state_probe(scope, |state| {
            (
                state.get(0),
                state.get(1),
                state.get(2),
                state.get(3),
                state.get(4),
            )
        })
        .expect("the state buffer must exist after installing");

        assert_eq!(values.0, Some(4242), "kReadBytesOrError written from JS");
        assert_eq!(values.1, Some(7), "kArrayBufferOffset written from JS");
        // -1 and -32 are stored as their two's-complement bit patterns, which is
        // what `get` returns for a read of an `i32` slot.
        assert_eq!(values.2, Some(u32::MAX), "kBytesWritten = -1");
        assert_eq!(values.3, Some(1), "kLastWriteWasAsync");
        assert_eq!(values.4, Some((-32i32) as u32), "kLastWriteErr = -5");
    });
}

/// A value written from Rust is visible to JavaScript.
///
/// The other direction of the same proof: `SetWriteResult` writes `bytes`, `async`
/// and `err` before returning to JS, and `afterWriteDispatched` then reads them.
#[test]
fn rust_writes_are_visible_to_javascript() {
    with_context(|scope| {
        install(scope);
        rn_bind_stream_wrap::with_state_probe(scope, |state| {
            state.set(0, 99);
            state.set(1, 3);
            state.set(2, 1024);
            state.set(3, 1);
            state.set(4, (-32i32) as u32);
        })
        .expect("the state buffer must exist after installing");

        let source = v8::String::new(
            scope,
            r#"
            const s = __stream.streamBaseState;
            [s[0], s[1], s[2], s[3], s[4]].join(',')
            "#,
        )
        .expect("allocating the probe");
        let script = v8::Script::compile(scope, source, None).expect("compiling the probe");
        let result = script.run(scope).expect("running the probe");
        assert_eq!(
            result.to_rust_string_lossy(scope),
            "99,3,1024,1,-32",
            "the signed values must read back as signed from JavaScript"
        );
    });
}

/// The buffer is created once and reused, because Node allocates it per
/// `Environment` and every stream wrap writes into that one array.
#[test]
fn the_state_buffer_is_a_single_allocation() {
    with_context(|scope| {
        install(scope);
        let source = v8::String::new(
            scope,
            r#"
            // Writing through one reference and reading through the other is only
            // possible if both name the same object.
            globalThis.__a = __stream.streamBaseState;
            __a[2] = 1234;
            __stream.streamBaseState[2]
            "#,
        )
        .expect("allocating the probe");
        let script = v8::Script::compile(scope, source, None).expect("compiling the probe");
        let result = script.run(scope).expect("running the probe");
        assert_eq!(result.to_rust_string_lossy(scope), "1234");
    });
}

/// `ShutdownWrap` is constructible and pre-creates Node's three fields.
///
/// `lib/net.js`'s `_final` does `const req = new ShutdownWrap()` and then assigns
/// `oncomplete`, `handle` and `callback`. Node pre-creates all three so the object
/// keeps one shape; a missing field is invisible until something measures the
/// object's hidden class.
#[test]
fn shutdown_wrap_has_the_fields_lib_net_assigns() {
    let report = eval(
        r#"
        const req = new __stream.ShutdownWrap();
        [
          req.oncomplete === null,
          req.callback === null,
          req.handle === null,
          typeof __stream.ShutdownWrap,
          __stream.ShutdownWrap.name,
        ].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true,true,function,ShutdownWrap",
        "ShutdownWrap pre-creates oncomplete, callback and handle as null"
    );
}

/// `WriteWrap` additionally pre-creates `async`, `bytes`, `buffer` and
/// `writeStatus`, which is what `afterWriteDispatched` reads.
#[test]
fn write_wrap_has_the_fields_after_write_dispatched_reads() {
    let report = eval(
        r#"
        const req = new __stream.WriteWrap();
        [
          req.oncomplete === null,
          req.callback === null,
          req.handle === null,
          req.buffer === null,
          req.writeStatus === null,
          req.async === false,
          req.bytes === 0,
          __stream.WriteWrap.name,
        ].join(',')
        "#,
    );
    assert_eq!(
        report, "true,true,true,true,true,true,true,WriteWrap",
        "WriteWrap pre-creates the fields afterWriteDispatched reads"
    );
}

/// A `WriteWrap`'s `writeStatus` is what a synchronous completion is replayed
/// through, so it must start as `null` and accept a number.
#[test]
fn write_status_starts_null_and_takes_a_status() {
    let report = eval(
        r#"
        const req = new __stream.WriteWrap();
        const before = req.writeStatus === null;
        req.writeStatus = 0;
        [before, req.writeStatus].join(',')
        "#,
    );
    assert_eq!(report, "true,0");
}

/// The two request classes are `new`-only, as `IsConstructCallCallback` enforces
/// with a `CHECK`.
#[test]
fn the_request_classes_require_new() {
    let report = eval(
        r#"
        const results = [];
        for (const name of ['ShutdownWrap', 'WriteWrap']) {
          try {
            __stream[name]();
            results.push('called');
          } catch (error) {
            results.push(error.constructor.name);
          }
        }
        results.join(',')
        "#,
    );
    assert_eq!(report, "TypeError,TypeError");
}

/// The constructors are ordinary functions with no `prototype` methods, matching
/// `SetConstructorFunction`'s `NONE` flag.
#[test]
fn the_request_classes_expose_a_prototype_but_no_native_methods() {
    let report = eval(
        r#"
        [
          typeof __stream.ShutdownWrap.prototype,
          Object.getOwnPropertyNames(__stream.ShutdownWrap.prototype).filter(
            (name) => name !== 'constructor').length,
        ].join(',')
        "#,
    );
    assert_eq!(report, "object,0");
}

/// The constants are `ReadOnly | DontDelete`, as `NODE_DEFINE_CONSTANT` makes
/// them.
#[test]
fn the_index_constants_cannot_be_reassigned() {
    let report = eval(
        r#"
        'use strict';
        const before = __stream.kBytesWritten;
        try {
          __stream.kBytesWritten = 99;
        } catch (error) {
          // A strict-mode assignment to a read-only property throws.
        }
        [before, __stream.kBytesWritten].join(',')
        "#,
    );
    assert_eq!(report, "2,2", "kBytesWritten must not be writable");
}

/// Every installed member is declared, so the contract check has nothing to
/// complain about and `deferred()` stays empty.
#[test]
fn the_module_declares_exactly_what_it_installs() {
    assert_eq!(StreamWrap.namespace(), "stream_wrap");
    assert_eq!(StreamWrap.members(), rn_bind_stream_wrap::MEMBERS);
    assert!(
        StreamWrap.deferred().is_empty(),
        "every recorded member is installed, so nothing is deferred"
    );
    assert_eq!(
        rn_bind_stream_wrap::MEMBERS.len(),
        8,
        "contracts/stream_wrap.json records eight members"
    );
}

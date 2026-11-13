//! Calling back into JavaScript from a libuv completion.
//!
//! A libuv callback runs inside `uv_run`, on the isolate's own thread but with
//! no V8 scope of any kind: no handle scope is open and no context is entered.
//! Node's `MakeCallback` re-establishes both before it touches JavaScript, and
//! rustnode has to do the same or V8 aborts.
//!
//! # Why the context is a `Global`
//!
//! The isolate is created by the CLI *after* every binding is registered, so a
//! binding cannot be handed it up front. The install callback is the first point
//! where both the isolate and the context are reachable, which is when
//! [`remember_context`] records them. The context is stored as a
//! `v8::Global<v8::Context>` — a real root — so nothing has to reason about
//! whether it is still alive when a completion fires.
//!
//! The isolate is only reachable as a raw pointer because a `v8::Isolate` cannot
//! be rooted. That is sound here for one reason: a libuv completion can only run
//! from inside [`crate::uv_loop::run`], and the CLI only runs the loop while the
//! isolate it created is alive.
//!
//! # Why the isolate is re-entered with `from_raw_ptr`
//!
//! `v8::HandleScope::new` takes something that *owns* an isolate: an
//! `OwnedIsolate`, or an `&mut Isolate` that is itself pinned. The CLI has the
//! `OwnedIsolate`; a binding only has a pointer to it. Reconstructing a borrowed
//! `Isolate` view from that pointer and pinning it for the duration of the call
//! is exactly what the pointer is for, and the lifetimes below tie that view to
//! the closure so it cannot escape.

use std::cell::RefCell;

use rn_v8_sys::v8;

thread_local! {
    /// The isolate the bindings were installed into, as the raw V8 pointer.
    ///
    /// It is the *real* isolate pointer, not the address of the Rust `Isolate`
    /// wrapper: a wrapper reconstructed from its own address has no isolate annex,
    /// and taking a handle scope from one panics. `as_raw_isolate_ptr` is the
    /// supported way to keep an isolate reachable across a `uv_run` boundary.
    static ISOLATE: RefCell<Option<v8::UnsafeRawIsolatePtr>> = const { RefCell::new(None) };
    /// The context the bindings were installed in, rooted.
    static CONTEXT: RefCell<Option<v8::Global<v8::Context>>> = const { RefCell::new(None) };
}

/// Records the isolate and context a binding is being installed into.
///
/// Every binding's `install` calls this, so the value is available by the time
/// anything can call into JavaScript. Repeated calls are harmless and store the
/// same isolate and an equivalent context handle.
pub fn remember_context(scope: &mut v8::PinScope<'_, '_>) {
    let isolate: &v8::Isolate = scope.as_ref();
    // SAFETY: the isolate outlives every scope taken from it (it is owned by the
    // CLI's `main`), so keeping a pointer to it is sound for the process' life.
    let pointer = unsafe { isolate.as_raw_isolate_ptr() };
    ISOLATE.with(|slot| {
        *slot.borrow_mut() = Some(pointer);
    });
    let context = scope.get_current_context();
    CONTEXT.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(isolate, context));
    });
}

/// Whether a context has been recorded, i.e. whether a binding has installed.
pub fn has_context() -> bool {
    CONTEXT.with(|slot| slot.borrow().is_some())
}

/// Runs `body` inside a scope libuv callbacks can use to touch JavaScript.
///
/// Returns `None` when no binding has installed yet, or when the recorded
/// isolate or context has gone away. Either means there is nothing to call into,
/// so a completion delivered then is dropped — which is what libuv does with a
/// completion whose handle was already closed.
///
/// The body is handed the raw `ContextScope`, not a `PinScope`, so both of the
/// two things a caller needs work: `Local::new` wants the *handle* scope
/// underneath it, and method calls want the scope itself.
pub fn with_context<R>(
    body: impl FnOnce(&mut v8::PinScope<'_, '_, v8::Context>) -> R,
) -> Option<R> {
    let isolate_pointer = ISOLATE.with(|slot| *slot.borrow())?;
    let context = CONTEXT.with(|slot| slot.borrow().clone())?;

    // SAFETY: `isolate_pointer` came from `remember_context`, which stored the
    // real isolate pointer for the isolate the bindings were installed into. It is
    // still alive because the loop only runs from the CLI while the isolate
    // exists, and a libuv completion can only fire from inside `uv_run`.
    let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(isolate_pointer) };

    let storage = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let mut scope = storage.init();
    let local_context: v8::Local<v8::Context> = v8::Local::new(&scope, &context);
    let context_storage = std::pin::pin!(v8::ContextScope::new(&mut scope, local_context));
    let mut context_scope = context_storage;
    Some(body(&mut context_scope))
}

/// Calls `function`, with `receiver` as `this` and `arguments` as its arguments.
///
/// The call happens inside a [`with_context`] scope, which is what makes it
/// legal from a libuv callback.
///
/// **A throw from this call is not reported and does not affect the exit
/// status.** V8's default handler prints the exception because nothing above a
/// libuv completion installs one, but no exit code is set, so the process
/// reports success after a fatal error. Use [`call_reporting_uncaught`] for a
/// callback whose exception is genuinely uncaught; this entry point remains for
/// calls whose exceptions are handled by the caller or cannot escape.
pub fn call(
    function: &v8::Global<v8::Function>,
    receiver: Option<&v8::Global<v8::Object>>,
    arguments: &[v8::Global<v8::Value>],
) {
    with_context(|scope| {
        let function: v8::Local<v8::Function> = v8::Local::new(scope, function);
        let receiver: v8::Local<v8::Value> = match receiver {
            Some(object) => v8::Local::new(scope, object).into(),
            None => v8::undefined(&**scope).into(),
        };
        let arguments: Vec<v8::Local<v8::Value>> = arguments
            .iter()
            .map(|argument| v8::Local::new(scope, argument))
            .collect();
        let _ = function.call(&*scope, receiver, &arguments);
    });
}

/// Calls `function` and reports a thrown exception the way Node does.
///
/// This is the entry point for a completion that has no `TryCatch` above it and
/// no caller that could handle the throw: a threadpool job finishing, a write
/// completing, a DNS request resolving. Node's `MakeCallback` installs a
/// `TryCatch` around the callback and routes a caught exception through
/// `TriggerUncaughtException`, which calls `process._fatalException`, and only
/// prints and sets the exit code when that declines.
///
/// Dropping the `Option` returned by `Function::call` — as a bare
/// `let _ = function.call(..)` does — loses exactly that: V8's default handler
/// still prints the exception, but nothing sets the exit status, so the process
/// exits 0 after a fatal error. [`rn_errors::report_uncaught_exception`] is the
/// runtime's single implementation of that order, and this function exists so a
/// completion does not have to grow a fourth copy of it.
///
/// Returns whether the callback completed without throwing.
pub fn call_reporting_uncaught(
    function: &v8::Global<v8::Function>,
    receiver: Option<&v8::Global<v8::Object>>,
    arguments: &[v8::Global<v8::Value>],
) -> bool {
    with_context(|scope| {
        let function: v8::Local<v8::Function> = v8::Local::new(scope, function);
        let receiver: v8::Local<v8::Value> = match receiver {
            Some(object) => v8::Local::new(scope, object).into(),
            None => v8::undefined(&**scope).into(),
        };
        let arguments: Vec<v8::Local<v8::Value>> = arguments
            .iter()
            .map(|argument| v8::Local::new(scope, argument))
            .collect();
        // The exception is rooted and reported after the `TryCatch` closes,
        // because reporting runs JavaScript (`process._fatalException`) and the
        // pinned `TryCatch` scope is a different type from the context scope
        // that call needs. Rooting keeps the value alive across that boundary,
        // and the `TryCatch` still consumes the pending exception so it cannot
        // reach V8's default reporter.
        let caught = {
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let inner = &mut try_catch.init();
            let _ = function.call(inner, receiver, &arguments);
            inner
                .exception()
                .map(|exception| v8::Global::new(inner, exception))
        };
        match caught {
            Some(caught) => {
                let exception = v8::Local::new(scope, &caught);
                rn_errors::report_uncaught_exception(scope, exception);
                false
            }
            None => true,
        }
    })
    .unwrap_or(false)
}

/// Roots a string so it survives the scope that produced it.
pub fn global_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    text: &str,
) -> Option<v8::Global<v8::Value>> {
    let string = v8::String::new(scope, text)?;
    // A `Global<String>` and a `Global<Value>` are different types, and only the
    // latter can be stored as an argument.
    let value: v8::Local<v8::Value> = string.into();
    Some(v8::Global::new(scope.as_ref(), value))
}

/// Frees a read buffer the allocator handed libuv.
///
/// # Safety
///
/// `base` and `len` must be exactly what the allocator stored in the
/// `uv_buf_t` for this read.
pub unsafe fn free_read_buffer(base: *mut std::ffi::c_char, len: usize) {
    if base.is_null() || len == 0 {
        return;
    }
    // SAFETY: the caller guarantees this is the allocation the allocator made,
    // which used this exact layout.
    unsafe {
        std::alloc::dealloc(
            base.cast(),
            std::alloc::Layout::from_size_align_unchecked(len, 8),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an isolate whose global has a `process._fatalException` that only
    /// observes, so a report records the exception and sets the exit flag without
    /// the test having to stand up the whole runtime.
    fn with_isolate<R>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> R) -> Option<R> {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
        let mut isolate = v8::Isolate::new(Default::default());
        let storage = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut storage.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        let source = v8::String::new(
            scope,
            "globalThis.process = { _fatalException() { return false; } };",
        )?;
        let script = v8::Script::compile(scope, source, None)?;
        script.run(scope)?;
        Some(body(scope))
    }

    #[test]
    fn a_thrown_exception_requests_an_exit() {
        // The defect this guards: `let _ = function.call(..)` leaves the exit
        // code at 0, so a fatal error reads as success. Reported through the
        // shared path, the flag is what makes the process exit non-zero.
        rn_core::hook_slot::clear_exit_request();
        let caught = with_isolate(|scope| {
            let source =
                v8::String::new(scope, "(function(){ throw new Error('boom'); })").expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compile");
            let function = script.run(scope).expect("eval");
            let function = v8::Local::<v8::Function>::try_from(function).expect("function");
            let caught = {
                let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
                let inner = &mut try_catch.init();
                let _ = function.call(inner, v8::undefined(inner).into(), &[]);
                inner
                    .exception()
                    .map(|exception| v8::Global::new(inner, exception))
            };
            if let Some(caught) = caught {
                let exception = v8::Local::new(scope, &caught);
                rn_errors::report_uncaught_exception(scope, exception);
                true
            } else {
                false
            }
        })
        .expect("isolate");
        assert!(caught, "the call must have thrown");
        assert!(
            rn_core::hook_slot::flag(rn_core::hook_slot::EXIT_REQUESTED),
            "a reported uncaught exception must request a non-zero exit"
        );
    }
}

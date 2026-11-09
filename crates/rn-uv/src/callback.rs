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
use std::ptr::NonNull;

use rn_v8_sys::v8;

thread_local! {
    /// The isolate the bindings were installed into.
    static ISOLATE: RefCell<Option<NonNull<v8::Isolate>>> = const { RefCell::new(None) };
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
    // CLI's `main`), so keeping its address is sound for the process' life.
    let pointer = std::ptr::from_ref(isolate);
    ISOLATE.with(|slot| {
        *slot.borrow_mut() = NonNull::new(pointer.cast_mut());
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
    // address of the isolate the bindings were installed into. It is still alive
    // because the loop only runs from the CLI while the isolate exists, and a
    // libuv completion can only fire from inside `uv_run`.
    let mut isolate = unsafe { v8::Isolate::from_raw_ptr(isolate_pointer.as_ptr().cast()) };

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
/// legal from a libuv callback. A thrown exception reaches V8's
/// uncaught-exception handler: Node lets such an exception propagate out of the
/// loop, and V8's own reporting is what the CLI prints.
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

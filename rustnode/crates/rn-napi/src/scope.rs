//! The handle scope a Node-API call runs inside.
//!
//! Node's `napi_value` is a `v8::Local<v8::Value>`: a bare pointer to a V8
//! object that stays valid for as long as the handle scope which produced it.
//! That lifetime is what lets an addon hold a `napi_value` in a C local across
//! several Node-API calls — `napi_create_object` followed by
//! `napi_set_named_property`, say — without a reference.
//!
//! The C ABI cannot carry a Rust lifetime, so the scope has to be recovered from
//! somewhere at each entry point. Two things make that possible:
//!
//! * Every Node-API call happens while a scope from this runtime is alive: the
//!   `v8::FunctionCallback` that dispatches into a `napi_callback`, or the
//!   `process.dlopen` callback that invokes `napi_register_module_v1`.
//! * Those entry points already hold a `&mut v8::PinScope` on their own stack.
//!
//! [`enter`] publishes that scope's address for the duration of the call and
//! [`with_scope`] recovers it. The recovery is a lifetime erasure: the reference
//! handed to a shim is deliberately tied to the shim's own frame, never longer,
//! so a value created there cannot outlive the scope it was created in.

use std::cell::Cell;
use std::ffi::c_void;

use rn_v8_sys::v8;
thread_local! {
    /// Address of the `HandleScope` the current Node-API call runs inside.
    ///
    /// `Cell<*mut c_void>` rather than a typed pointer because the type carries
    /// lifetimes that cannot be written down here; [`enter`] is the only writer
    /// and it always stores the address of a live `PinScope`.
    static CURRENT: Cell<*mut c_void> = const { Cell::new(std::ptr::null_mut()) };
}

/// Restores [`CURRENT`] when it goes out of scope, including on unwind.
///
/// This matters because addon code can panic across the FFI boundary if the
/// panic was converted at a shim; a leaked non-null scope pointer would then
/// make every later Node-API call dereference a dead frame.
pub(crate) struct ScopeGuard {
    previous: *mut c_void,
}

impl ScopeGuard {
    /// Makes `scope` the scope Node-API shims resolve against.
    pub(crate) fn enter<'s, 'i>(scope: &mut v8::PinScope<'s, 'i>) -> Self {
        let previous = CURRENT
            .with(|slot| slot.replace((scope as *mut v8::PinScope<'s, 'i>).cast::<c_void>()));
        Self { previous }
    }

    /// The address of the scope a shim should use, if one is entered.
    fn current() -> Option<*mut c_void> {
        CURRENT.with(|slot| {
            let pointer = slot.get();
            (!pointer.is_null()).then_some(pointer)
        })
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        CURRENT.with(|slot| slot.set(self.previous));
    }
}

/// Runs `f` with the scope the current Node-API call was entered with.
///
/// Returns `None` when no scope is entered, which a shim reports as
/// `napi_handle_scope_mismatch` rather than dereferencing a null frame.
///
/// # The lifetime parameter
///
/// `'s` is chosen by the *caller* and is the lifetime of the handle scope the
/// entry point established. That is deliberate: a shim frequently has to return a
/// `v8::Local` created inside this closure (`napi_create_object` hands one back as
/// a `napi_value`), and a higher-ranked `for<'a>` closure could not express that.
///
/// The caller is responsible for picking a `'s` no longer than its own frame, which
/// is the same contract Node's C++ has: the handle is valid until the callback
/// scope that produced it unwinds.
///
/// # Safety
///
/// The `&mut PinScope` handed to `f` is a reborrow of a scope that is alive on an
/// outer stack frame, established by [`ScopeGuard::enter`]. No `Local` created
/// inside `f` may outlive that frame, so `'s` must not exceed it.
pub(crate) unsafe fn with_scope<'s, R>(
    f: impl FnOnce(&mut v8::PinScope<'s, '_>) -> R,
) -> Option<R> {
    let pointer = ScopeGuard::current()?;
    // SAFETY: the pointer came from `ScopeGuard::enter`, which is alive for as
    // long as this call: a shim runs synchronously inside the entry point that
    // owns the guard. `'s` is the caller's assertion about that frame.
    let scope: &mut v8::PinScope<'s, '_> = unsafe { &mut *(pointer as *mut v8::PinScope<'s, '_>) };
    Some(f(scope))
}

/// Enters the isolate and its context for code that libuv called back.
///
/// A libuv completion — an async work's `complete`, a thread-safe function's
/// queued value, a finalizer — runs on the isolate's thread but with no V8 scope
/// of any kind: `uv_run` is an ordinary Rust call, not a V8 callback. Touching
/// JavaScript there requires a handle scope and an entered context, and those have
/// to be recovered from the isolate the runtime recorded when it installed the
/// bindings, which is what `rn-uv`'s callback module owns.
///
/// Returning `None` means no isolate has been recorded, so there is nothing to
/// call into. A completion delivered then is dropped rather than faulting.
pub(crate) fn with_context<R>(
    body: impl FnOnce(&mut v8::PinScope<'_, '_, v8::Context>) -> R,
) -> Option<R> {
    rn_uv::callback::with_context(body)
}

/// Records the isolate and context so a callback with no Node-API scope can
/// re-enter V8.
///
/// `rn-uv`'s callback module owns the storage, but nothing guarantees a binding
/// that calls `remember_context` is installed before an addon finalizer runs.
/// `rn-napi` therefore records it at `process.dlopen` time, which is the first
/// moment an addon can have created anything that outlives a callback.
///
/// Idempotent; repeated calls store the same isolate and an equivalent context.
pub(crate) fn remember_context(scope: &mut v8::PinScope<'_, '_>) {
    rn_uv::callback::remember_context(scope);
}

/// Whether a context has been recorded, so a shim can report a real failure
/// instead of a misleading one.
#[cfg(test)]
pub(crate) fn has_context() -> bool {
    rn_uv::callback::has_context()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_scope_is_reported_rather_than_dereferenced() {
        // Outside any Node-API call there is no frame, and a shim must get a miss
        // instead of a null dereference. `with_scope` is unsafe only because a
        // *hit* dereferences the recorded scope; the miss path this exercises
        // touches nothing.
        // SAFETY: no scope is entered, so no pointer is dereferenced.
        assert!(unsafe { with_scope(|_: &mut v8::PinScope<'_, '_>| ()) }.is_none());
    }

    #[test]
    fn the_guard_restores_the_previous_scope() {
        // Nesting has to unwind exactly, because one addon callback can invoke
        // another addon's function.
        assert!(ScopeGuard::current().is_none());
        let outer = ScopeGuard {
            previous: std::ptr::null_mut(),
        };
        CURRENT.with(|slot| slot.set(std::ptr::dangling_mut::<c_void>()));
        assert!(ScopeGuard::current().is_some());
        drop(outer);
        assert!(ScopeGuard::current().is_none());
    }
}

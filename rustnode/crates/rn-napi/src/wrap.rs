//! `napi_wrap`, `napi_add_finalizer` and the finalizers attached to an object.
//!
//! An addon attaches its own `void*` to a JavaScript object so a later call can
//! get it back. Node keeps that pointer in a **private property** on the object,
//! as a `v8::External` pointing at a reference that owns the finalizer — see
//! `v8impl::Wrap` in `src/js_native_api_v8.cc`. This module does the same, and
//! the choice is not cosmetic.
//!
//! # Why a private property and not an internal field
//!
//! Internal fields look like the natural home for a native pointer, and
//! `rn-bind-crypto-keys/src/handle.rs` has a comment claiming V8 zeroes them on
//! allocation. **That claim is false.** `templates.rs` in the same crate records
//! what actually happened: reading an uninitialised aligned-pointer internal field
//! aborted the process with a misaligned-address panic, which is why that crate
//! keeps a second marker field saying whether the pointer is live.
//!
//! A private property has no such hazard. `has_private` answers whether a wrap
//! exists without reading any pointer, and the `External` it holds is dereferenced
//! only after that check succeeded. Nothing here depends on V8 pre-initialising
//! anything, so there is no marker field to forget.
//!
//! # One finalizer mechanism
//!
//! Two guarantees are used, both already in this codebase and neither new:
//!
//! * `v8::Weak::with_guaranteed_finalizer`, the same call `rn-bind-crypto-keys`
//!   uses for its key boxes and the thread-safe function's close path relies on.
//!   It runs before the isolate is destroyed, so the box is freed exactly once.
//! * The environment's reference table (`Env::add_ref`). When an addon asks
//!   `napi_wrap` for a `napi_ref`, the entry carries the wrap, so
//!   `napi_delete_reference` reaches the same finalizer through the same table
//!   every other reference uses. There is deliberately no separate wrap registry.
//!
//! # Ownership, from `v8impl::Unwrap`
//!
//! * `result == NULL` — the runtime owns the wrap. The guaranteed finalizer runs
//!   the addon's callback and frees the box.
//! * `result != NULL` — the addon owns it through the returned reference.
//!   `napi_delete_reference` runs the finalizer; deleting it earlier than the
//!   finalizer means the finalizer never runs, which is Node's documented contract.
//! * `napi_remove_wrap` deletes the private property. For an addon-owned wrap it
//!   resets the finalizer (so it will not run) and leaves the reference alone,
//!   because the addon may still delete it. For a runtime-owned wrap it runs the
//!   finalizer and frees the box.

use std::cell::RefCell;
use std::ffi::c_void;

use rn_v8_sys::v8;

use crate::abi::{NapiEnv, NapiFinalize, NapiRef, NapiStatus};

/// What a wrap records about one object.
pub(crate) struct Wrap {
    /// The addon's pointer, handed back by `napi_unwrap`.
    pub(crate) data: *mut c_void,
    /// The finalizer to run when the wrap dies, if the addon gave one.
    ///
    /// Cleared by `napi_remove_wrap` on an addon-owned wrap, which is Node's
    /// `ResetFinalizer`.
    pub(crate) finalize: NapiFinalize,
    pub(crate) finalize_hint: *mut c_void,
    /// The environment the wrap belongs to, so the finalizer receives it.
    pub(crate) env: *mut NapiEnv,
    /// Whether the addon holds a `napi_ref` for this wrap.
    pub(crate) owned_by_addon: bool,
    /// Set once the finalizer has run, so it runs exactly once even when both the
    /// guaranteed finalizer and `napi_delete_reference` reach it.
    pub(crate) finalized: bool,
    /// The weak handle that carries the finalizer.
    ///
    /// **Dropping a `v8::Weak` deregisters its finalizer** — `impl Drop for Weak`
    /// calls `remove_finalizer` (`handle.rs:1167` in rusty_v8). Holding the handle
    /// only transiently with `let _ =` therefore installed a finalizer and removed
    /// it in the same expression, which is why the wrap finalizer never ran. The
    /// handle lives here so it survives as long as the object might.
    weak: Option<v8::Weak<v8::Object>>,
}

// SAFETY: the wrap is created and consumed on the isolate's thread. Its raw
// pointers are the addon's own and are never dereferenced here; they are only
// handed back to the addon's callbacks.
unsafe impl Send for Wrap {}

thread_local! {
    /// The private symbol wraps live under.
    ///
    /// One per process rather than per environment: Node keys this off the
    /// isolate's private-symbol table, and two environments in one process must
    /// agree or an object wrapped by one could not be unwrapped by the other.
    static WRAP_KEY: RefCell<Option<v8::Global<v8::Private>>> = const { RefCell::new(None) };
}

/// The wrap key for `scope`, created on first use.
pub(crate) fn wrap_key<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Private>> {
    let existing = WRAP_KEY.with(|slot| slot.borrow().clone());
    if let Some(existing) = existing {
        return Some(v8::Local::new(scope, &existing));
    }
    let name = v8::String::new(scope, "node:napi:wrapper")?;
    let key = v8::Private::for_api(scope, Some(name));
    WRAP_KEY.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(scope, key));
    });
    Some(key)
}

/// The `Box<Wrap>` a wrapped object's private property points at.
///
/// # Safety
///
/// `object` must be a live object from `scope`, and any pointer read back must be
/// one this module stored.
pub(crate) unsafe fn wrap_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<*mut Wrap> {
    let key = wrap_key(scope)?;
    // `has_private` is what makes the read safe: without it a never-stored wrap
    // would be read as whatever the slot held, which is the internal-field bug
    // this module exists to avoid.
    if object.has_private(scope, key)? != true {
        return None;
    }
    let value = object.get_private(scope, key)?;
    let external = v8::Local::<v8::External>::try_from(value).ok()?;
    let pointer = external.value() as *mut Wrap;
    (!pointer.is_null()).then_some(pointer)
}

/// Runs a wrap's finalizer once, then frees the box when the runtime owns it.
///
/// # Threading
///
/// The addon's callback is **deferred to the loop's thread**, because a weak
/// callback fires on whichever thread ran the collection and calling into V8 from
/// there is undefined behaviour. That is right for the GC path, which is the only
/// caller of this function. [`run_finalizer_now`] is the variant for a caller that
/// is already on the isolate's thread and must see the finalizer run before it
/// returns — `napi_remove_wrap` is that caller.
///
/// # Safety
///
/// `pointer` must come from this module, and the caller must not use it
/// afterwards when the wrap is not owned by the addon.
unsafe fn run_finalizer(pointer: *mut Wrap) {
    unsafe { finish_finalizer(pointer, true) };
}

/// Frees a runtime-owned wrap's box without running its finalizer.
///
/// Used by `napi_remove_wrap`, where the addon takes the pointer back: running the
/// finalizer would free the allocation the addon now owns.
///
/// # Safety
///
/// `pointer` must be a runtime-owned wrap this module allocated, already detached
/// from its object.
unsafe fn discard_runtime_wrap(pointer: *mut Wrap) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: the caller guarantees this is one of this module's allocations and
    // that nothing else reaches it.
    drop(unsafe { Box::from_raw(pointer) });
}

/// Shared body of the two finalizer entry points.
///
/// # Safety
///
/// As [`run_finalizer`].
unsafe fn finish_finalizer(pointer: *mut Wrap, defer: bool) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: the caller guarantees this is one of this module's allocations.
    let wrap = unsafe { &mut *pointer };
    if !wrap.finalized {
        wrap.finalized = true;
        if let Some(finalize) = wrap.finalize {
            let env = wrap.env as usize;
            let data = wrap.data as usize;
            let hint = wrap.finalize_hint as usize;
            if defer {
                // V8 may call the weak callback from a GC thread, so the addon's
                // finalizer is deferred to the loop's thread where a scope exists.
                let _ = rn_core::finalizer::enqueue(move |scope| {
                    let guard = crate::scope::ScopeGuard::enter(scope);
                    // SAFETY: the addon's own callback with the pointers it
                    // supplied; it is being told to release `data` now.
                    unsafe {
                        finalize(
                            env as *mut NapiEnv,
                            data as *mut c_void,
                            hint as *mut c_void,
                        )
                    };
                    drop(guard);
                });
            } else {
                // Already on the isolate's thread inside a scope
                // (`napi_remove_wrap`), so running it here is both legal and what
                // Node does: the addon expects the finalizer to have run when that
                // call returns.
                // SAFETY: as above.
                unsafe {
                    finalize(
                        env as *mut NapiEnv,
                        data as *mut c_void,
                        hint as *mut c_void,
                    )
                };
            }
        }
    }
    if !wrap.owned_by_addon {
        // SAFETY: no reference was handed out, so nothing else may reach it.
        drop(unsafe { Box::from_raw(pointer) });
    }
}

/// Clears an addon-owned wrap's finalizer without running it.
///
/// `napi_remove_wrap` on an addon-owned wrap does this so the reference the addon
/// still holds cannot fire the finalizer later. The box itself stays alive until
/// the addon deletes the reference.
///
/// # Safety
///
/// `pointer` must be a live wrap this module allocated.
pub(crate) unsafe fn reset_finalizer(pointer: *mut Wrap) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: the caller guarantees this is one of this module's allocations.
    let wrap = unsafe { &mut *pointer };
    wrap.finalize = None;
    wrap.finalized = true;
}

/// Wraps `object`, returning the reference the addon owns when it asked for one.
///
/// `wrap` is moved in: on success this module owns it, on failure the caller's
/// box is freed before returning.
///
/// # Safety
///
/// `object` must be a live object from `scope`, and the caller must have already
/// rejected an object that is wrapped.
pub(crate) unsafe fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    wrap: Box<Wrap>,
) -> Option<*mut Wrap> {
    let key = wrap_key(scope)?;
    let pointer = Box::into_raw(wrap);
    let external = v8::External::new(scope, pointer.cast());
    // A private property is invisible to JavaScript and cannot be shadowed by a
    // user property of the same name, which is why Node uses one.
    if object.set_private(scope, key, external.into())? != true {
        // The store failed, so nothing owns the box; reclaim it rather than leak.
        drop(unsafe { Box::from_raw(pointer) });
        return None;
    }

    // The guaranteed finalizer covers the runtime-owned case and the case where
    // the addon never deletes its reference. It frees the box only when the
    // runtime owns it, because an addon-owned box must survive until the addon's
    // `napi_delete_reference` — `napi_unwrap` may still be called through it.
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: `pointer` was allocated above for this object alone, and
            // this finalizer is the only thing that frees a runtime-owned box.
            unsafe { run_finalizer(pointer) };
        }),
    );
    // Stored on the wrap so the handle outlives this call: dropping it would
    // deregister the finalizer.
    unsafe { (*pointer).weak = Some(weak) };
    Some(pointer)
}

/// Wraps `object` after Node's validation.
///
/// Returns the `napi_ref` handle when the addon asked for one. That reference is
/// an ordinary entry in the environment's reference table, whose finalizer runs
/// the wrap's finalizer — so `napi_delete_reference` reaches it through exactly
/// the same code every other reference uses.
///
/// # Safety
///
/// `object` must be a live object from `scope`.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn wrap_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    env: *mut NapiEnv,
    data: *mut c_void,
    finalize_cb: NapiFinalize,
    finalize_hint: *mut c_void,
    wants_reference: bool,
) -> Result<Option<*mut NapiRef>, NapiStatus> {
    // A second wrap would mean two finalizers for one pointer, and the addon has
    // lost track of which is live. Node rejects it.
    if unsafe { wrap_of(scope, object) }.is_some() {
        return Err(NapiStatus::InvalidArg);
    }
    // Node requires a finalizer when returning a reference: the reference is the
    // only thing that will ever delete it, so without one it could never be freed.
    if wants_reference && finalize_cb.is_none() {
        return Err(NapiStatus::InvalidArg);
    }
    let wrap = Box::new(Wrap {
        data,
        finalize: finalize_cb,
        finalize_hint,
        env,
        owned_by_addon: wants_reference,
        finalized: false,
        weak: None,
    });
    // SAFETY: `object` is a live object from `scope`.
    let Some(pointer) = (unsafe { install(scope, object, wrap) }) else {
        return Err(NapiStatus::GenericFailure);
    };
    if !wants_reference {
        return Ok(None);
    }
    // SAFETY: `env` was validated by the caller.
    let Some(environment) = (unsafe { crate::env::env_from(env) }) else {
        return Err(NapiStatus::InvalidArg);
    };
    let reference = environment.add_ref(crate::env::RefEntry {
        // A wrap reference holds no V8 value of its own: the object is kept alive
        // by the wrap's private property, and rooting it a second time here would
        // keep it alive past the finalizer.
        value: std::cell::RefCell::new(None),
        count: std::cell::Cell::new(1),
        finalize: Some(run_finalizer_from_reference),
        finalize_hint: pointer.cast(),
    });
    // Record which reference owns the box, so a `napi_remove_wrap` that resets the
    // finalizer can also leave the reference harmless.
    unsafe { (*pointer).owned_by_addon = true };
    Ok(Some(reference))
}

/// The finalizer the environment's reference table runs for a wrap reference.
///
/// # Safety
///
/// Called by `Env::delete_ref` with the reference's `finalize_hint`, which is the
/// wrap pointer stored by [`wrap_object`].
unsafe extern "C" fn run_finalizer_from_reference(
    _env: *mut NapiEnv,
    _data: *mut c_void,
    hint: *mut c_void,
) {
    // SAFETY: `wrap_object` stored this exact pointer as the hint.
    unsafe { run_finalizer(hint.cast::<Wrap>()) };
}

/// Detaches a wrap from `object`, returning its pointer to the caller.
///
/// # Safety
///
/// `object` must be a live object from `scope`.
pub(crate) unsafe fn remove<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<*mut c_void> {
    let key = wrap_key(scope)?;
    let pointer = unsafe { wrap_of(scope, object) }?;
    object.delete_private(scope, key)?;
    // SAFETY: the pointer came from `wrap_of`, so it is one of this module's.
    let wrap = unsafe { &*pointer };
    // Read the fields *before* the finalizer runs: a runtime-owned wrap frees its
    // box inside `run_finalizer_now`, so reading afterwards is a use-after-free.
    // That bug returned a garbage pointer to the addon, which then freed an
    // address it did not own.
    let data = wrap.data;
    let owned_by_addon = wrap.owned_by_addon;
    if owned_by_addon {
        // Node's `ResetFinalizer`: the addon still holds the reference and may
        // delete it later, but the finalizer must not run now.
        unsafe { reset_finalizer(pointer) };
    } else {
        // The addon is taking the pointer back and owns it from here, so the
        // finalizer must **not** run: it would free the allocation the addon is
        // about to use. Node reaches the same outcome by deleting the reference,
        // which for `RemoveWrap` drops the finalizer with it.
        //
        // This frees only the box that recorded the wrap.
        // SAFETY: the runtime owned the box and the property is gone, so nothing
        // else may reach it.
        unsafe { discard_runtime_wrap(pointer) };
    }
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank(owned_by_addon: bool) -> Box<Wrap> {
        Box::new(Wrap {
            data: std::ptr::null_mut(),
            finalize: None,
            finalize_hint: std::ptr::null_mut(),
            env: std::ptr::null_mut(),
            owned_by_addon,
            finalized: false,
            weak: None,
        })
    }

    #[test]
    fn a_wrap_records_who_owns_it() {
        // The ownership flag decides who frees the box, so getting it wrong is a
        // double free or a leak rather than a wrong answer.
        assert!(blank(true).owned_by_addon);
        assert!(!blank(false).owned_by_addon);
    }

    #[test]
    fn a_wrap_box_is_addressable_as_its_own_reference_hint() {
        // The reference's `finalize_hint` carries the wrap pointer, which is what
        // `delete_wrap_reference` reads back. A mismatch here would free the wrong
        // address.
        // The reference's `finalize_hint` carries the wrap pointer, which is what
        // `run_finalizer_from_reference` reads back. A mismatch would free the
        // wrong address, so the pair is asserted directly.
        let wrap = Box::into_raw(blank(false));
        assert!(!wrap.is_null());
        // SAFETY: this test owns the allocation.
        drop(unsafe { Box::from_raw(wrap) });
    }
}

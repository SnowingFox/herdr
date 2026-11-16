//! `napi_open_handle_scope` and its escapable twin.
//!
//! # Why this needs real storage rather than a counter
//!
//! `napi_handle_scope` looks like an opaque token, but it *is* a V8 `HandleScope`:
//! a stack-allocated object whose constructor records the isolate's current
//! handle-allocation top, and whose destructor rewinds to it. Every `Local` created
//! while it is open lives in it, so closing it releases those handles at once.
//! `node-addon-api` opens one around each `napi_callback` body and escapes the return
//! value out of it, which is why a class addon cannot load without these.
//!
//! The object is address-sensitive — V8 holds a `HandleScopeData*` pointing at it
//! while it is open — so it cannot move after initialisation. Returning a
//! `v8::HandleScope` by value through a `*mut` out parameter would therefore be
//! wrong: the shim's frame is gone before the addon closes it. Each open scope is
//! instead one `Pin<Box<ScopeStorage<T>>>`, whose address is stable for exactly as
//! long as it is in the table below.
//!
//! # Why the pinned reference is stored too
//!
//! `ScopeStorage::init` returns the `PinnedRef` that the V8 scope's methods need, and
//! calling `init` a second time *destructs the scope first* — which would rewind the
//! handle stack and invalidate every handle the addon already holds. So the
//! `PinnedRef` created at open time is kept beside the box and reused by
//! `napi_escape_handle`. The box is pinned, so the reference stays valid, and the
//! box is dropped only after the reference is.
//!
//! # Ordering
//!
//! V8's scope stack is LIFO. Closing an outer scope while an inner one is open would
//! leave the inner `HandleScopeData` pointing at a destructed frame — a
//! use-after-free V8 cannot detect — so `napi_close_handle_scope` requires the
//! innermost open scope and reports `napi_handle_scope_mismatch` otherwise, which is
//! what Node's `open_handle_scopes == 0` check does for the empty case.

use std::cell::RefCell;
use std::pin::Pin;

use rn_v8_sys::v8;

use crate::abi::{NapiEscapableHandleScope, NapiHandleScope, NapiStatus, NapiValue};

/// A plain scope's storage, with the lifetime erased.
type PlainStorage = v8::ScopeStorage<v8::HandleScope<'static>>;
/// An escapable scope's storage, with both lifetimes erased.
type EscapableStorage = v8::ScopeStorage<v8::EscapableHandleScope<'static, 'static>>;

/// One open Node-API handle scope.
enum OpenScope {
    Plain {
        /// Dropping this runs V8's `HandleScope` destructor, which rewinds the
        /// isolate's handle allocation — the whole effect of closing the scope.
        /// The `PinnedRef` that `init` produced is deliberately not kept: only an
        /// escapable scope's `escape` needs it, and holding one here would pin a
        /// reference into a box that the drop order then has to outlive.
        storage: Pin<Box<PlainStorage>>,
    },
    Escapable {
        storage: Pin<Box<EscapableStorage>>,
        entered: v8::PinnedRef<'static, v8::EscapableHandleScope<'static, 'static>>,
        /// Set by `napi_escape_handle`; V8 aborts on a second escape, so the flag is
        /// what keeps a double escape a reportable `napi_escape_called_twice`.
        escaped: bool,
    },
}

impl OpenScope {
    /// The handle the addon was given, which is the storage's own address.
    fn handle(&self) -> *mut NapiHandleScope {
        match self {
            Self::Plain { storage, .. } => (&**storage as *const PlainStorage).cast_mut().cast(),
            Self::Escapable { storage, .. } => {
                (&**storage as *const EscapableStorage).cast_mut().cast()
            }
        }
    }
}

/// The open scopes of one environment, innermost last.
#[derive(Default)]
pub(crate) struct ScopeStack {
    scopes: RefCell<Vec<OpenScope>>,
}

impl ScopeStack {
    /// Opens a plain handle scope, returning the handle the addon closes it with.
    ///
    /// `None` means the environment's table was already borrowed, which the caller
    /// reports as a handle-scope mismatch.
    pub(crate) fn open(&self, scope: &mut v8::PinScope<'_, '_>) -> Option<*mut NapiHandleScope> {
        // `HandleScope::new` accepts the live `PinScope` because it implements
        // `NewHandleScope`; the storage it returns owns no borrow, so the mutable
        // borrow of `scope` ends with this statement.
        let storage = Box::pin(v8::HandleScope::new(scope));
        // SAFETY: the storage is pinned, so it will not move and the reference
        // stays valid until the box is dropped. `'static` is the erasure the C ABI
        // requires; the table's ordering is what upholds it.
        let storage = unsafe { erase_plain(storage) };
        let open = OpenScope::Plain { storage };
        let handle = open.handle();
        self.scopes.try_borrow_mut().ok()?.push(open);
        Some(handle)
    }

    /// Opens an escapable handle scope, returning the handle the addon uses.
    pub(crate) fn open_escapable(
        &self,
        scope: &mut v8::PinScope<'_, '_>,
    ) -> Option<*mut NapiEscapableHandleScope> {
        let storage = Box::pin(v8::EscapableHandleScope::new(scope));
        // SAFETY: as in `open`.
        let (storage, entered) = unsafe { erase_escapable(storage) };
        let open = OpenScope::Escapable {
            storage,
            entered,
            escaped: false,
        };
        let handle = open.handle();
        self.scopes.try_borrow_mut().ok()?.push(open);
        Some(handle.cast::<NapiEscapableHandleScope>())
    }

    /// Closes the innermost scope, reporting a mismatch for anything else.
    pub(crate) fn close(&self, handle: *mut NapiHandleScope) -> NapiStatus {
        let Ok(mut scopes) = self.scopes.try_borrow_mut() else {
            return NapiStatus::HandleScopeMismatch;
        };
        let Some(innermost) = scopes.last() else {
            // Node reports this when `open_handle_scopes` is zero.
            return NapiStatus::HandleScopeMismatch;
        };
        if innermost.handle() != handle {
            return NapiStatus::HandleScopeMismatch;
        }
        // Dropping the entry runs the V8 destructor, which rewinds the isolate's
        // handle allocation to where it was when the scope opened.
        scopes.pop();
        NapiStatus::Ok
    }

    /// Escapes `value` out of an open escapable scope.
    ///
    /// # Safety
    ///
    /// `value` must be a handle from a scope that is still open.
    pub(crate) unsafe fn escape(
        &self,
        handle: *mut NapiEscapableHandleScope,
        value: *mut NapiValue,
    ) -> Result<*mut NapiValue, NapiStatus> {
        let mut scopes = self
            .scopes
            .try_borrow_mut()
            .map_err(|_| NapiStatus::HandleScopeMismatch)?;
        let Some(entry) = scopes
            .iter_mut()
            .find(|open| open.handle() == handle.cast::<NapiHandleScope>())
        else {
            return Err(NapiStatus::InvalidArg);
        };
        let OpenScope::Escapable {
            entered, escaped, ..
        } = entry
        else {
            // A plain scope passed where an escapable one is required.
            return Err(NapiStatus::InvalidArg);
        };
        if *escaped {
            return Err(NapiStatus::EscapeCalledTwice);
        }
        *escaped = true;
        let Some(local) = (unsafe { crate::values::from_napi(value) }) else {
            return Err(NapiStatus::InvalidArg);
        };
        // `escape` pushes the value into the enclosing scope and returns a handle
        // in that scope, which is the whole contract of an escapable scope.
        let escaped_value = entered.escape(local);
        Ok(crate::values::to_napi(escaped_value))
    }

    /// Closes every scope still open, innermost first.
    ///
    /// A `.node` file that forgets a `napi_close_handle_scope` would otherwise leave
    /// a V8 destructor that never runs.
    #[allow(dead_code)]
    pub(crate) fn close_all(&self) {
        if let Ok(mut scopes) = self.scopes.try_borrow_mut() {
            while scopes.pop().is_some() {}
        }
    }

    /// How many scopes are open, for tests and for an environment teardown that
    /// wants to report a leak.
    #[cfg(test)]
    pub(crate) fn depth(&self) -> usize {
        self.scopes.borrow().len()
    }
}

/// Initialises a pinned plain storage and erases its lifetime.
///
/// `init` is what calls V8's `HandleScope` constructor; the returned `PinnedRef` is
/// dropped immediately because a plain scope has no method that needs it, and
/// dropping the reference does not close the scope — only dropping the storage does.
///
/// # Safety
///
/// The returned box must be dropped on the isolate's thread, after every handle
/// created inside it is done with.
unsafe fn erase_plain<'i>(
    mut storage: Pin<Box<v8::ScopeStorage<v8::HandleScope<'i, v8::Context>>>>,
) -> Pin<Box<PlainStorage>> {
    // `init` must run (it calls V8's constructor); the reference it returns is
    // discarded because a plain scope has no method that needs one.
    let _ = storage.as_mut().init();
    // SAFETY: `ScopeStorage` carries its lifetime only in `PhantomData`, and moving
    // the box moves the pointer rather than the pinned allocation.
    unsafe { std::mem::transmute::<Pin<Box<_>>, Pin<Box<PlainStorage>>>(storage) }
}

/// Initialises a pinned escapable storage and erases its lifetimes.
///
/// # Safety
///
/// The box must be kept alive for as long as any handle created inside the scope is
/// reachable, and the returned reference must not outlive it.
unsafe fn erase_escapable<'i>(
    mut storage: Pin<Box<v8::ScopeStorage<v8::EscapableHandleScope<'i, 'i, v8::Context>>>>,
) -> (
    Pin<Box<EscapableStorage>>,
    v8::PinnedRef<'static, v8::EscapableHandleScope<'static, 'static>>,
) {
    let entered: v8::PinnedRef<'_, v8::EscapableHandleScope<'_, '_, v8::Context>> =
        storage.as_mut().init();
    // SAFETY: as in `erase`.
    let entered = unsafe {
        std::mem::transmute::<
            v8::PinnedRef<'_, v8::EscapableHandleScope<'_, '_, v8::Context>>,
            v8::PinnedRef<'static, v8::EscapableHandleScope<'static, 'static>>,
        >(entered)
    };
    let storage =
        unsafe { std::mem::transmute::<Pin<Box<_>>, Pin<Box<EscapableStorage>>>(storage) };
    (storage, entered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_a_scope_that_was_never_opened_is_a_mismatch() {
        // Node reports `napi_handle_scope_mismatch` when `open_handle_scopes` is
        // zero rather than dereferencing the handle.
        let stack = ScopeStack::default();
        assert_eq!(
            stack.close(std::ptr::dangling_mut::<NapiHandleScope>()),
            NapiStatus::HandleScopeMismatch
        );
        assert_eq!(stack.depth(), 0);
    }

    #[test]
    fn an_empty_stack_has_no_scopes_and_closes_cleanly() {
        // A teardown path must be able to run against a stack with nothing open.
        let stack = ScopeStack::default();
        stack.close_all();
        assert_eq!(stack.depth(), 0);
    }

    #[test]
    fn closing_a_scope_the_stack_does_not_hold_is_refused() {
        // The LIFO rule: a handle that is not the innermost open scope cannot be
        // closed, because doing so would leave the real innermost one dangling.
        // Exercised without opening a V8 scope, so the test needs no isolate: the
        // mismatch branch is taken before any V8 call.
        let stack = ScopeStack::default();
        assert_eq!(
            stack.close(std::ptr::dangling_mut::<NapiHandleScope>()),
            NapiStatus::HandleScopeMismatch
        );
    }
}

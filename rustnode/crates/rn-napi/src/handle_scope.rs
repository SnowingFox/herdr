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
/// The detached root's outer `HandleScope<'static, ()>` storage.
type DetachedHandleStorage = v8::ScopeStorage<v8::HandleScope<'static, ()>>;
/// The entered detached root handle scope (`HandleScope<'static, ()>`).
type DetachedEntered = v8::PinnedRef<'static, v8::HandleScope<'static, ()>>;
/// The entered detached context scope over that handle scope.
type DetachedContextScope = v8::ContextScope<'static, 'static, v8::HandleScope<'static>>;

/// One detached root used by bare-libuv Node-API calls.
///
/// `napi_open_handle_scope` may be called from a `uv_check`/`uv_queue_work`
/// callback with no entered Node-API scope. Node's shims still have `env->isolate`
/// there; this root recreates that by owning an entered isolate and context for as
/// long as the addon's handle scopes stay open.
///
/// # Drop order
///
/// Field order is deliberate:
/// - `guard` clears the detached-scope thread-local first.
/// - `context_scope` drops before `entered`, matching V8 nesting.
/// - `entered` drops before `handle_storage`, like every pinned ref in this file.
/// - `context` (the root) and finally `isolate` outlive both scopes.
struct DetachedRoot {
    guard: crate::scope::DetachedScopeGuard,
    context_scope: Pin<Box<DetachedContextScope>>,
    entered: Pin<Box<DetachedEntered>>,
    handle_storage: Pin<Box<DetachedHandleStorage>>,
    context: v8::Global<v8::Context>,
    isolate: v8::Isolate,
}

impl DetachedRoot {
    fn new() -> Option<Self> {
        let (isolate_pointer, context) = rn_uv::callback::isolate_and_context()?;
        // SAFETY: `remember_context` recorded the real isolate pointer; the loop
        // only runs while that isolate is alive.
        let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(isolate_pointer) };
        let handle_storage = Box::pin(v8::HandleScope::new(&mut isolate));
        // SAFETY: pinned storage with erased lifetime, as in `erase_plain`.
        let (handle_storage, entered) =
            unsafe { erase_detached_plain_with_entered(handle_storage) };
        let mut entered = Box::pin(entered);
        let local_context: v8::Local<v8::Context> = v8::Local::new(&entered, &context);
        // SAFETY: `entered` is pinned for the life of `DetachedRoot`, so extending
        // this borrow to match that ownership is sound.
        let entered_ref: &mut DetachedEntered = unsafe { entered.as_mut().get_unchecked_mut() };
        let context_scope = v8::ContextScope::new(entered_ref, local_context);
        // SAFETY: as above — `context_scope` borrows `entered`, which this root owns
        // and keeps pinned until drop.
        let context_scope = unsafe { erase_detached_context_scope(context_scope) };
        let mut context_scope = Box::pin(context_scope);
        let guard = crate::scope::DetachedScopeGuard::enter(&mut context_scope);
        Some(Self {
            guard,
            context_scope,
            entered,
            handle_storage,
            context,
            isolate,
        })
    }

    fn with_scope<R>(
        &mut self,
        body: impl FnOnce(&mut v8::PinScope<'_, '_, v8::Context>) -> R,
    ) -> R {
        // These fields are intentional lifetime anchors: they keep the detached
        // isolate/context/scope chain alive for the duration of every shim call.
        let _ = (
            &self.guard,
            &self.entered,
            &self.handle_storage,
            &self.context,
            &self.isolate,
        );
        let scope: &mut v8::PinScope<'static, 'static, v8::Context> = &mut self.context_scope;
        // SAFETY: `scope` is borrowed from `&mut self`, so shrinking `'static` to
        // that borrow's lifetime is sound and cannot outlive the root.
        let scope = unsafe {
            std::mem::transmute::<
                &mut v8::PinScope<'static, 'static, v8::Context>,
                &mut v8::PinScope<'_, '_, v8::Context>,
            >(scope)
        };
        body(scope)
    }
}

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
    detached: RefCell<Option<DetachedRoot>>,
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

    /// Opens a plain scope while running from a bare libuv callback.
    ///
    /// This first ensures there is one detached entered context alive, then opens
    /// the addon-visible handle scope inside it.
    pub(crate) fn open_detached(&self) -> Option<*mut NapiHandleScope> {
        let storage = self.with_detached_scope(|scope| {
            let storage = Box::pin(v8::HandleScope::new(scope));
            // SAFETY: same reasoning as `open`.
            let storage = unsafe { erase_plain(storage) };
            OpenScope::Plain { storage }
        })?;
        let handle = storage.handle();
        self.scopes.try_borrow_mut().ok()?.push(storage);
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

    /// Opens an escapable scope while running from a bare libuv callback.
    pub(crate) fn open_escapable_detached(&self) -> Option<*mut NapiEscapableHandleScope> {
        let open = self.with_detached_scope(|scope| {
            let storage = Box::pin(v8::EscapableHandleScope::new(scope));
            // SAFETY: same reasoning as `open_escapable`.
            let (storage, entered) = unsafe { erase_escapable(storage) };
            OpenScope::Escapable {
                storage,
                entered,
                escaped: false,
            }
        })?;
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
        let should_clear_detached = scopes.is_empty();
        drop(scopes);
        if should_clear_detached {
            // Clearing this also drops the detached-scope guard, which removes the
            // thread-local pointer before the backing V8 scopes are destroyed.
            if let Ok(mut detached) = self.detached.try_borrow_mut() {
                detached.take();
            }
        }
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
        if let Ok(mut detached) = self.detached.try_borrow_mut() {
            detached.take();
        }
    }

    fn with_detached_scope<R>(
        &self,
        f: impl FnOnce(&mut v8::PinScope<'_, '_, v8::Context>) -> R,
    ) -> Option<R> {
        let mut detached = self.detached.try_borrow_mut().ok()?;
        if detached.is_none() {
            *detached = DetachedRoot::new();
        }
        let root = detached.as_mut()?;
        Some(root.with_scope(f))
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

/// Initialises a pinned plain storage, returning the erased storage and entered ref.
///
/// # Safety
///
/// Same as [`erase_plain`], plus the returned reference must not outlive the box.
unsafe fn erase_detached_plain_with_entered<'i>(
    mut storage: Pin<Box<v8::ScopeStorage<v8::HandleScope<'i, ()>>>>,
) -> (Pin<Box<DetachedHandleStorage>>, DetachedEntered) {
    let entered: v8::PinnedRef<'_, v8::HandleScope<'_, ()>> = storage.as_mut().init();
    // SAFETY: as in `erase_plain`.
    let entered = unsafe {
        std::mem::transmute::<v8::PinnedRef<'_, v8::HandleScope<'_, ()>>, DetachedEntered>(entered)
    };
    let storage =
        unsafe { std::mem::transmute::<Pin<Box<_>>, Pin<Box<DetachedHandleStorage>>>(storage) };
    (storage, entered)
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

/// Erases the borrow lifetime on a detached context scope.
///
/// # Safety
///
/// The caller must guarantee the referenced handle scope is pinned and outlives
/// the returned value.
unsafe fn erase_detached_context_scope<'s>(
    scope: v8::ContextScope<'s, 'static, v8::HandleScope<'static>>,
) -> DetachedContextScope {
    unsafe { std::mem::transmute::<_, DetachedContextScope>(scope) }
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

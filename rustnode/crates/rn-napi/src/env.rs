//! The `napi_env` an addon receives.
//!
//! `napi_env` is opaque to the addon and only ever passed back to the runtime, so
//! its layout is ours. What it must hold is everything an addon expects to
//! persist between calls: the last error, the instance data, the module version
//! it declared, and the references it has created.
//!
//! # Why every field is interior-mutable
//!
//! A Node-API call can re-enter addon code. `napi_call_function` runs a
//! JavaScript callback, and that callback can be another function the same addon
//! created, which calls back into Node-API with the *same* environment. If a
//! shim held `&mut Env` across the V8 call it would alias the outer borrow, which
//! is undefined behaviour even though nothing is observably wrong in a build
//! without sanitizers.
//!
//! So the environment is only ever borrowed as `&Env`, and every mutable part is
//! a `Cell` or `RefCell`. That mirrors Node, whose `napi_env__` is likewise
//! shared and mutated from nested calls.

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use rn_v8_sys::v8;

use crate::abi::{
    NapiCleanupHook, NapiDeferred, NapiEnv, NapiExtendedErrorInfo, NapiFinalize, NapiNodeVersion,
    NapiRef, NapiStatus, NODE_MAJOR_VERSION, NODE_MINOR_VERSION, NODE_PATCH_VERSION,
};

/// The released-module information `napi_get_node_version` reports.
///
/// `release` is a `const char*` the addon does not free, so it points at a
/// `'static` string literal.
///
/// Wrapped in a `Sync` newtype because a raw pointer is not `Sync` by default and
/// the pointed-at `"node"` literal is immutable and immortal, so sharing the
/// struct across threads is sound.
struct NodeVersion(NapiNodeVersion);

// SAFETY: the only non-`Sync` field is `release`, which points at a `'static`
// byte string compiled into the binary. It is never written and never freed.
unsafe impl Sync for NodeVersion {}

static NODE_VERSION: NodeVersion = NodeVersion(NapiNodeVersion {
    major: NODE_MAJOR_VERSION,
    minor: NODE_MINOR_VERSION,
    patch: NODE_PATCH_VERSION,
    release: c"node".as_ptr(),
});

/// The version information `napi_get_node_version` hands out.
pub(crate) fn node_version() -> *const NapiNodeVersion {
    &NODE_VERSION.0
}

/// The last-error state `napi_get_last_error_info` hands out.
///
/// The `napi_extended_error_info` lives in a `Box` so its address is stable for the
/// life of the environment: the addon keeps the pointer and may read it after further
/// Node-API calls.
///
/// `error_message` points at a `'static` `CStr` from [`NapiStatus::message_cstr`],
/// never at memory this owns. Node's table is `static const char*[]` for the same
/// reason: an addon's `GET_AND_THROW_LAST_ERROR` saves the pointer, makes another
/// Node-API call (which clears the last error), and *then* reads the text. A heap
/// buffer freed by the clear would dangle there.
struct ErrorSlot {
    info: Box<NapiExtendedErrorInfo>,
}

impl ErrorSlot {
    fn new() -> Self {
        Self {
            info: Box::new(NapiExtendedErrorInfo {
                error_message: std::ptr::null(),
                engine_reserved: std::ptr::null_mut(),
                engine_error_code: 0,
                error_code: NapiStatus::Ok,
            }),
        }
    }
}

/// One `napi_add_async_cleanup_hook` registration.
///
/// Carries its environment so removal can unlink it: the shim takes no
/// `napi_env`, and once a teardown drains the list a freed handle left in it
/// would be dereferenced at exit.
pub(crate) struct AsyncCleanupHook {
    pub(crate) hook: crate::abi::NapiAsyncCleanupHook,
    pub(crate) arg: *mut std::ffi::c_void,
    /// The environment that owns this handle, so removal can reach its list.
    pub(crate) env: *const Env,
}

/// Removes an async cleanup hook by unlinking it from its environment's list.
///
/// # Safety
///
/// `handle` must be one `Env::add_async_cleanup_hook` produced and must not have
/// been removed already.
pub(crate) unsafe fn remove_async_cleanup_hook(
    handle: *mut crate::abi::NapiAsyncCleanupHookHandle,
) -> bool {
    if handle.is_null() {
        return false;
    }
    // SAFETY: the caller passes a handle from `Env::add_async_cleanup_hook`, which
    // allocated it with `Box::into_raw`.
    let boxed = unsafe { Box::from_raw(handle.cast::<AsyncCleanupHook>()) };
    // Unlink before freeing. `napi_remove_async_cleanup_hook` takes no `napi_env`,
    // which is why the handle remembers its own owner: without this the freed
    // pointer stays in the environment's list and a teardown dereferences it,
    // which is a use-after-free at exit rather than an error an addon can see.
    if !boxed.env.is_null() {
        // SAFETY: `env` was stored by `add_async_cleanup_hook` from a live `&self`
        // and the environment outlives every handle registered on it.
        let environment = unsafe { &*boxed.env };
        if let Ok(mut hooks) = environment.async_cleanup_hooks.try_borrow_mut() {
            hooks.retain(|other| *other != handle);
        }
    }
    drop(boxed);
    true
}
/// Reports `error` through Node's uncaught-exception path.
///
/// # Safety
///
/// `error` must be a live `napi_value` from the scope the caller has established,
/// which is the Node-API contract for every shim argument.
pub(crate) unsafe fn trigger_fatal_exception(env: *mut NapiEnv, error: *mut crate::abi::NapiValue) {
    let Some(environment) = (unsafe { env_from(env) }) else {
        return;
    };
    let owner = environment.owner_thread();
    let env_address = env as usize;
    let error_address = error as usize;
    // A fatal exception may be reported from a thread that does not own the
    // isolate (a thread-safe function's producer, for instance), so it is deferred
    // to the owner exactly as the other cross-thread paths are.
    let _ = rn_core::finalizer::enqueue_for(Some(owner), move || {
        crate::scope::with_owner_context(env_address as *mut NapiEnv, |scope| {
            // SAFETY: the value is a handle from the scope that reported it, and
            // the enqueue happened while that scope was alive.
            let Some(value) = (unsafe { crate::values::from_napi(error_address as *mut _) }) else {
                return;
            };
            rn_errors::report_uncaught_exception(scope, value);
        });
    });
}

/// One entry in the reference table.
///
/// The shims that would read these fields (`napi_create_reference` and friends) are
/// in `shims::DEFERRED`; the table and its accessors land now because they are the
/// part the environment owns, and a later slice only adds the shim wrappers.
#[allow(dead_code)]
pub(crate) struct RefEntry {
    /// The value, rooted so it survives garbage collection.
    ///
    /// `napi_create_reference` with a nonzero count is a *strong* reference: the
    /// value must not be collected even if JavaScript drops every other
    /// reference to it, and `v8::Global` is exactly that root.
    pub(crate) value: RefCell<Option<v8::Global<v8::Value>>>,
    /// Current reference count. Zero means weak: the value may be released.
    pub(crate) count: Cell<u32>,
    /// The finalizer Node runs when the reference is deleted.
    pub(crate) finalize: NapiFinalize,
    pub(crate) finalize_hint: *mut std::ffi::c_void,
}

/// `napi_is_exception_pending` / `napi_get_and_clear_last_exception` state.
///
/// V8 has no public "is an exception pending" query, so the runtime records the
/// exception at the moment it schedules one and hands it back when the addon
/// asks. That is the same contract Node implements in `napi_env__`.
#[derive(Default)]
pub(crate) struct ExceptionState {
    /// The scheduled exception, kept as a global so it survives the handle scope
    /// of the call that threw it.
    pending: Option<v8::Global<v8::Value>>,
    /// Set when an exception is pending in V8 but no value was captured for it.
    ///
    /// `napi_call_function` observes V8's own empty result and must report
    /// `napi_pending_exception`, but it cannot read the raised value from a
    /// `PinScope`. The flag keeps `napi_is_exception_pending` truthful in that
    /// case, and a later `napi_get_and_clear_last_exception` still asks V8 for the
    /// value, which is the same answer Node gives.
    pending_without_value: bool,
}

impl ExceptionState {
    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some() || self.pending_without_value
    }

    pub(crate) fn take(&mut self) -> Option<v8::Global<v8::Value>> {
        self.pending_without_value = false;
        self.pending.take()
    }

    pub(crate) fn set(&mut self, exception: v8::Global<v8::Value>) {
        self.pending = Some(exception);
        self.pending_without_value = false;
    }

    /// Records that V8 has an exception pending whose value was not captured.
    pub(crate) fn mark_pending(&mut self) {
        self.pending_without_value = true;
    }
}

/// One `napi_env`.
pub struct Env {
    /// The `napi_module_api_version` the addon declared, or the Node default.
    module_api_version: i32,
    /// `module.filename` as a URL: what `node_api_get_module_file_name` returns.
    module_filename: CString,
    last_error: RefCell<ErrorSlot>,
    /// `napi_set_instance_data` / `napi_get_instance_data`.
    ///
    /// The storage exists now so a later slice only adds the two one-line shims;
    /// both are in `shims::DEFERRED` with that reason.
    #[allow(dead_code)]
    instance_data: Cell<Option<(*mut std::ffi::c_void, NapiFinalize)>>,
    /// Handles created by `napi_create_reference`, indexed by `napi_ref`.
    #[allow(dead_code)]
    refs: RefCell<Vec<Option<RefEntry>>>,
    /// Resolvers created by `napi_create_promise`, indexed by `napi_deferred`.
    ///
    /// A separate table rather than the reference table because a
    /// `v8::Global<v8::PromiseResolver>` cannot be recovered from a
    /// `v8::Global<v8::Value>`: the `v8` crate allows the upcast but not the
    /// downcast, and a resolver is a `Data` rather than a `Value`. Keeping the
    /// typed global means settling a deferred needs no unchecked cast.
    deferreds: RefCell<Vec<Option<v8::Global<v8::PromiseResolver>>>>,
    /// The `napi_open_handle_scope` scopes this environment has open.
    ///
    /// On the environment rather than in a thread-local so a worker's scope can
    /// never be closed by the main realm, and so a teardown has one place to look
    /// for a scope an addon forgot to close.
    scopes: crate::handle_scope::ScopeStack,
    /// Handles from `napi_add_async_cleanup_hook`, so a teardown can run them.
    async_cleanup_hooks: RefCell<Vec<*mut crate::abi::NapiAsyncCleanupHookHandle>>,
    exceptions: RefCell<ExceptionState>,
    /// `napi_add_env_cleanup_hook` entries, in registration order.
    ///
    /// Order matters: Node runs cleanup hooks in reverse registration order, the
    /// same way a stack unwinds, so a hook registered last can still use what an
    /// earlier one set up.
    cleanup_hooks: RefCell<Vec<(NapiCleanupHook, *mut std::ffi::c_void)>>,
    /// How many `napi_open_callback_scope` calls have not been closed.
    ///
    /// Node's `napi_close_callback_scope` reports `napi_callback_scope_mismatch`
    /// when the count is zero (`src/node_api.cc:961`), so the counter has to exist
    /// even though the scopes themselves live on the addon's stack.
    open_callback_scopes: Cell<usize>,
    /// The thread whose isolate this environment belongs to.
    ///
    /// With `worker_threads` there is one isolate per worker thread, and a
    /// deferred finalizer must run against the isolate that owns the addon's
    /// pointers, not whichever realm's drain happens to reach it first. A
    /// finalizer that finds itself on the wrong thread reports it instead of
    /// calling into an isolate it does not own.
    owner_thread: std::thread::ThreadId,
}

impl Env {
    /// Creates an environment for one loaded addon.
    pub fn new(module_api_version: i32, module_filename: &str) -> Self {
        Self {
            module_api_version,
            module_filename: CString::new(module_filename)
                .unwrap_or_else(|_| CString::new("").unwrap_or_default()),
            last_error: RefCell::new(ErrorSlot::new()),
            instance_data: Cell::new(None),
            refs: RefCell::new(Vec::new()),
            deferreds: RefCell::new(Vec::new()),
            scopes: crate::handle_scope::ScopeStack::default(),
            async_cleanup_hooks: RefCell::new(Vec::new()),
            exceptions: RefCell::new(ExceptionState::default()),
            cleanup_hooks: RefCell::new(Vec::new()),
            open_callback_scopes: Cell::new(0),
            owner_thread: std::thread::current().id(),
        }
    }

    /// Whether the caller is on the thread that owns this environment's isolate.
    ///
    /// A deferred Node-API finalizer checks this before touching V8: the queue is
    /// process-wide, so a worker's finalizer could otherwise be drained by the main
    /// realm. Running it there would enter the wrong isolate.
    pub(crate) fn is_on_owner_thread(&self) -> bool {
        std::thread::current().id() == self.owner_thread
    }

    /// The thread whose isolate this environment belongs to.
    ///
    /// A deferred finalizer is filed under this id so only the owning realm drains
    /// it.
    pub(crate) fn owner_thread(&self) -> std::thread::ThreadId {
        self.owner_thread
    }

    /// Registers a cleanup hook, as `napi_add_env_cleanup_hook` does.
    ///
    /// Registering the same `(fun, arg)` pair twice is a no-op in Node, because the
    /// pair is the hook's identity and `napi_remove_env_cleanup_hook` removes by it.
    pub(crate) fn add_cleanup_hook(&self, fun: NapiCleanupHook, arg: *mut std::ffi::c_void) {
        if let Ok(mut hooks) = self.cleanup_hooks.try_borrow_mut() {
            if !hooks
                .iter()
                .any(|existing| hook_matches(existing, fun, arg))
            {
                hooks.push((fun, arg));
            }
        }
    }

    /// Removes a cleanup hook, reporting whether it was registered.
    pub(crate) fn remove_cleanup_hook(
        &self,
        fun: NapiCleanupHook,
        arg: *mut std::ffi::c_void,
    ) -> bool {
        let Ok(mut hooks) = self.cleanup_hooks.try_borrow_mut() else {
            return false;
        };
        let Some(index) = hooks
            .iter()
            .rposition(|existing| hook_matches(existing, fun, arg))
        else {
            return false;
        };
        hooks.remove(index);
        true
    }

    /// Runs every cleanup hook in reverse registration order.
    ///
    /// Node calls these when the environment is torn down, which is also when a
    /// thread-safe function's finalizer may fire. Nothing here calls into
    /// JavaScript: a hook runs after the environment has stopped allowing it.
    ///
    /// **This runtime has no environment teardown path**, so nothing calls this
    /// yet: `napi_add_env_cleanup_hook` registers and
    /// `napi_remove_env_cleanup_hook` unregisters, and the hooks run when a
    /// teardown path is added. Registering is still the correct behaviour for an
    /// addon that only wants its cleanup to happen at exit, and it is what makes
    /// `test_cleanup_hook` fail on the missing teardown rather than on the missing
    /// symbol. Reported rather than stubbed into a lie.
    #[allow(dead_code)]
    pub fn run_cleanup_hooks(&self) {
        let hooks = match self.cleanup_hooks.try_borrow_mut() {
            Ok(mut hooks) => std::mem::take(&mut *hooks),
            Err(_) => return,
        };
        for (fun, arg) in hooks.into_iter().rev() {
            if let Some(fun) = fun {
                // SAFETY: the addon's own hook, with the argument it registered.
                unsafe { fun(arg) };
            }
        }
    }

    /// Runs every async cleanup hook registered with
    /// `napi_add_async_cleanup_hook`.
    ///
    /// Node runs these at environment teardown, before the plain cleanup hooks,
    /// and a hook may either finish synchronously or keep its handle alive and
    /// call back later. This runtime has no teardown path yet (see
    /// [`Self::run_cleanup_hooks`]), so nothing calls this; it exists so the
    /// registration's payload is read rather than stored and forgotten.
    #[allow(dead_code)]
    pub fn run_async_cleanup_hooks(&self) {
        let handles = match self.async_cleanup_hooks.try_borrow_mut() {
            Ok(mut hooks) => std::mem::take(&mut *hooks),
            Err(_) => return,
        };
        for handle in handles {
            if handle.is_null() {
                continue;
            }
            // SAFETY: the handle came from `add_async_cleanup_hook`, which
            // allocated it with `Box::into_raw`, and it is freed exactly once.
            let entry = unsafe { Box::from_raw(handle.cast::<AsyncCleanupHook>()) };
            if let Some(hook) = entry.hook {
                // SAFETY: the addon's own callback with the argument it supplied,
                // and the handle it may retain to finish asynchronously.
                unsafe { hook(entry.arg, handle) };
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn cleanup_hook_count(&self) -> usize {
        self.cleanup_hooks.borrow().len()
    }

    pub fn module_api_version(&self) -> i32 {
        self.module_api_version
    }

    /// The module filename, for `node_api_get_module_file_name`.
    pub(crate) fn module_filename_ptr(&self) -> *const c_char {
        self.module_filename.as_ptr()
    }

    /// Records `status` as the last error and returns it, which is how every
    /// Node-API shim reports failure.
    pub(crate) fn set_last_error(&self, status: NapiStatus) -> NapiStatus {
        if let Ok(mut slot) = self.last_error.try_borrow_mut() {
            refresh(&mut slot, status);
        }
        status
    }

    /// The `napi_extended_error_info` pointer `napi_get_last_error_info`
    /// returns.
    ///
    /// Node refreshes `error_message` on each request so the pointer refers to
    /// the current status's text; doing the same means an addon that asks twice
    /// after different failures does not see stale text.
    pub(crate) fn last_error_info(&self) -> *const NapiExtendedErrorInfo {
        let Ok(mut slot) = self.last_error.try_borrow_mut() else {
            // A re-entrant request for the error info while it is being
            // rewritten: return what is there rather than panicking in FFI.
            return std::ptr::null();
        };
        let status = slot.info.error_code;
        refresh(&mut slot, status);
        &*slot.info as *const NapiExtendedErrorInfo
    }

    #[allow(dead_code)]
    pub(crate) fn set_instance_data(
        &self,
        data: *mut std::ffi::c_void,
        finalize: NapiFinalize,
        _hint: *mut std::ffi::c_void,
    ) {
        self.instance_data.set(Some((data, finalize)));
    }

    #[allow(dead_code)]
    pub(crate) fn instance_data(&self) -> Option<*mut std::ffi::c_void> {
        self.instance_data.get().map(|(data, _)| data)
    }

    /// Runs this environment's full teardown, in Node's order.
    ///
    /// Node's `Environment::RunCleanup` does these in this sequence, and each step
    /// is observable from an addon, so the order is part of the contract rather
    /// than an implementation detail:
    ///
    /// 1. **Async cleanup hooks first** — `CleanupHandles`, which runs the
    ///    `napi_add_async_cleanup_hook` payloads.
    /// 2. **Then the plain cleanup hooks, in reverse registration order** — a
    ///    hook registered last can still use what an earlier one set up.
    /// 3. **Then the instance-data finalizer** — `napi_set_instance_data`'s
    ///    callback, which is what `test_instance_data` asserts as `addon_free`.
    ///
    /// Taking the hooks before running them is deliberate and matches Node's
    /// `std::mem::take`-equivalent at the head of each drain, with one difference
    /// that matters: Node re-checks membership before each call so a hook removed
    /// by an already-running hook does not fire. `take()` cannot express that, so
    /// a removal during teardown is only honoured for hooks not yet taken. That
    /// gap is recorded here rather than hidden; `test_cleanup_hook` removes its
    /// hook *before* teardown begins, so it does not exercise it.
    ///
    /// Returns whether anything ran, so a caller can tell "no addons" from "an
    /// addon with no hooks".
    pub fn run_teardown(&self) -> bool {
        let had_async = !self.async_cleanup_hooks.borrow().is_empty();
        let had_plain = !self.cleanup_hooks.borrow().is_empty();
        let had_instance = self.instance_data.get().is_some();

        self.run_async_cleanup_hooks();
        self.run_cleanup_hooks();

        // The instance-data finalizer runs last, and only once: `take` clears the
        // slot so a second teardown cannot double-free an addon's payload.
        if let Some((data, Some(finalize))) = self.instance_data.take() {
            let env = self as *const Self as *mut NapiEnv;
            // SAFETY: the addon registered this callback with this pointer and has
            // not been told the environment is gone yet.
            unsafe { finalize(env, data, std::ptr::null_mut()) };
        }

        had_async || had_plain || had_instance
    }

    /// Adds a reference and returns its opaque handle.
    ///
    /// Node's `napi_ref` is a pointer to a heap `Reference`; here it is a
    /// one-based index into this environment's table. One-based so a valid handle
    /// is never mistaken for null, which every Node-API out parameter allows.
    #[allow(dead_code)]
    pub(crate) fn add_ref(&self, entry: RefEntry) -> *mut NapiRef {
        let mut refs = self.refs.borrow_mut();
        refs.push(Some(entry));
        refs.len() as *mut NapiRef
    }

    /// Resolves a `napi_ref` to its table index.
    #[allow(dead_code)]
    fn ref_index(reference: *mut NapiRef) -> Option<usize> {
        (reference as usize).checked_sub(1)
    }

    /// Runs `f` against the live entry behind a reference handle.
    #[allow(dead_code)]
    pub(crate) fn with_ref<R>(
        &self,
        reference: *mut NapiRef,
        f: impl FnOnce(&RefEntry) -> R,
    ) -> Option<R> {
        let index = Self::ref_index(reference)?;
        let refs = self.refs.try_borrow().ok()?;
        refs.get(index).and_then(Option::as_ref).map(f)
    }

    /// Deletes a reference, dropping its root and running its finalizer.
    #[allow(dead_code)]
    pub(crate) fn delete_ref(&self, reference: *mut NapiRef) -> bool {
        let Some(index) = Self::ref_index(reference) else {
            return false;
        };
        let entry = match self.refs.try_borrow_mut() {
            Ok(mut refs) => refs.get_mut(index).and_then(Option::take),
            Err(_) => return false,
        };
        let Some(entry) = entry else {
            return false;
        };
        // Dropping the `Global` releases the root. Doing it here rather than at
        // some later collection point is what makes `napi_delete_reference`
        // observable, and it is safe on this thread because every Node-API call
        // runs on the isolate's own thread.
        drop(entry.value.borrow_mut().take());
        if let Some(finalize) = entry.finalize {
            let env = self as *const Self as *mut NapiEnv;
            // SAFETY: the finalizer is the addon's own function pointer and this
            // environment is alive; `finalize_hint` is whatever the addon passed.
            unsafe { finalize(env, entry.finalize_hint, std::ptr::null_mut()) };
        }
        true
    }

    /// The environment's open Node-API handle scopes.
    pub(crate) fn scopes(&self) -> &crate::handle_scope::ScopeStack {
        &self.scopes
    }

    /// Registers an async cleanup hook and returns its handle.
    ///
    /// The handle *is* the registration: Node's `napi_async_cleanup_hook_handle__`
    /// owns a node cleanup-hook registration and unlinks it in its destructor, and
    /// `napi_remove_async_cleanup_hook` takes no environment so the handle has to
    /// carry everything removal needs. The same holds here.
    pub(crate) fn add_async_cleanup_hook(
        &self,
        hook: crate::abi::NapiAsyncCleanupHook,
        arg: *mut std::ffi::c_void,
    ) -> *mut crate::abi::NapiAsyncCleanupHookHandle {
        // The environment pointer is recorded here because
        // `napi_remove_async_cleanup_hook` takes no `napi_env`, and removal has to
        // unlink the handle from this list before freeing it.
        let entry = Box::new(AsyncCleanupHook {
            hook,
            arg,
            env: self as *const Self,
        });
        let handle = Box::into_raw(entry).cast::<crate::abi::NapiAsyncCleanupHookHandle>();
        if let Ok(mut hooks) = self.async_cleanup_hooks.try_borrow_mut() {
            hooks.push(handle);
        }
        handle
    }

    pub(crate) fn exceptions(&self) -> &RefCell<ExceptionState> {
        &self.exceptions
    }

    /// Adds a promise resolver and returns its opaque `napi_deferred` handle.
    ///
    /// One-based like `add_ref`, so a valid handle is never null — every Node-API
    /// out parameter treats null as "absent".
    pub(crate) fn add_deferred(
        &self,
        resolver: v8::Global<v8::PromiseResolver>,
    ) -> *mut NapiDeferred {
        let mut deferreds = self.deferreds.borrow_mut();
        deferreds.push(Some(resolver));
        deferreds.len() as *mut NapiDeferred
    }

    /// Takes a deferred's resolver out of the table, so settling it twice cannot
    /// succeed twice.
    ///
    /// Node's `ConcludeDeferred` deletes the persistent on every path, which
    /// makes a second settle unreachable; this is the same outcome expressed as a
    /// take.
    pub(crate) fn take_deferred(
        &self,
        deferred: *mut NapiDeferred,
    ) -> Option<v8::Global<v8::PromiseResolver>> {
        let index = (deferred as usize).checked_sub(1)?;
        let mut deferreds = self.deferreds.try_borrow_mut().ok()?;
        deferreds.get_mut(index).and_then(Option::take)
    }

    /// Drops any recorded pending exception.
    ///
    /// A thread-safe function takes a throw out of V8's pending state and hands it
    /// to the uncaught-exception path. Without this, a later `napi_*` call would
    /// still see the exception as pending and report `napi_pending_exception` for
    /// a throw that has already been delivered.
    pub(crate) fn clear_exceptions(&self) {
        if let Ok(mut state) = self.exceptions.try_borrow_mut() {
            state.take();
        }
    }

    /// Marks that an exception is pending without replacing the pending value.
    ///
    /// `napi_call_function` sees V8's own empty result and must report
    /// `napi_pending_exception`; the value V8 raised stays the one
    /// `napi_get_and_clear_last_exception` returns.
    pub(crate) fn mark_exception_pending(&self) {
        if let Ok(mut state) = self.exceptions.try_borrow_mut() {
            state.mark_pending();
        }
    }

    /// Whether an exception is pending, which a closing callback scope reads to
    /// decide between `after` and `failed_` (`src/api/callback.cc:154`).
    pub(crate) fn exception_is_pending(&self) -> bool {
        self.exceptions
            .try_borrow()
            .map(|state| state.is_pending())
            .unwrap_or(false)
    }

    /// Records one more open `napi_callback_scope`.
    pub(crate) fn note_callback_scope_opened(&self) {
        self.open_callback_scopes
            .set(self.open_callback_scopes.get() + 1);
    }

    /// Records one closed `napi_callback_scope`, or reports the imbalance.
    ///
    /// Node's check is `if (env->open_callback_scopes == 0) return
    /// napi_callback_scope_mismatch;` (`src/node_api.cc:961`), so closing with
    /// none open is a reported mismatch rather than an underflow.
    pub(crate) fn note_callback_scope_closed(&self) -> bool {
        match self.open_callback_scopes.get().checked_sub(1) {
            Some(remaining) => {
                self.open_callback_scopes.set(remaining);
                true
            }
            None => false,
        }
    }
}

/// One open `napi_callback_scope`.
///
/// The addon opens a scope, runs arbitrary JavaScript, and closes it in a later
/// call, so the state `rn_core::callback_scope::close_scope` needs cannot live on
/// a Rust stack frame. Node boxes the same thing (`HeapAllocatedCallbackScope` in
/// `src/node_api.cc:668`).
pub(crate) struct CallbackScopeState {
    pub(crate) open: rn_core::callback_scope::OpenScope,
}

/// Whether a registered hook is the one a `(fun, arg)` pair names.
///
/// Both halves have to match, and the argument is compared as an address because
/// that is what the addon passed. The function pointer is compared too, but see
/// the note below: identical functions can share an address, so the pair is the
/// identity rather than either half alone.
fn hook_matches(
    (existing_fun, existing_arg): &(NapiCleanupHook, *mut std::ffi::c_void),
    fun: NapiCleanupHook,
    arg: *mut std::ffi::c_void,
) -> bool {
    // `std::ptr::fn_addr_eq` is the documented comparison for function pointers;
    // a plain `==` is not, because the compiler may merge identical bodies and
    // may also duplicate one function, so equal addresses do not prove equal
    // pointers. Comparing the argument as well means a false positive needs two
    // hooks with both the same body address and the same argument, which is the
    // same program either way.
    let same_function = match (*existing_fun, fun) {
        (Some(left), Some(right)) => std::ptr::fn_addr_eq(left, right),
        // Both missing is not a hook the shim ever registers (`napi_add_...`
        // rejects a null callback), so it cannot match.
        _ => false,
    };
    same_function && *existing_arg == arg
}

/// Rewrites a slot's status and message in place.
///
/// A successful call clears the message, matching `napi_clear_last_error`. The text
/// for a failure is the header's own wording, pointed at its `'static` `CStr` so it
/// stays readable after a later call clears the slot.
fn refresh(slot: &mut ErrorSlot, status: NapiStatus) {
    slot.info.error_code = status;
    slot.info.engine_error_code = 0;
    slot.info.engine_reserved = std::ptr::null_mut();
    slot.info.error_message = if status == NapiStatus::Ok {
        std::ptr::null()
    } else {
        status.message_cstr().as_ptr()
    };
}

/// Resolves a raw `napi_env` to the environment it points at.
///
/// # Safety
///
/// `env` must be null or a pointer this crate produced from a boxed [`Env`].
pub(crate) unsafe fn env_from<'a>(env: *mut NapiEnv) -> Option<&'a Env> {
    if env.is_null() {
        return None;
    }
    // SAFETY: caller guarantees the pointer is one this crate created and that
    // it is still alive. Only `&Env` is produced, never `&mut`, so nested calls
    // may hold it at the same time.
    Some(unsafe { &*(env as *const Env) })
}

/// Runs one addon environment's teardown.
///
/// The raw-pointer entry point for a caller that owns the environment without
/// being this crate — `rn-bind-process-methods` keeps the loaded-addon list, but
/// it must not dereference an `Env` itself: the layout and the lifetime rule
/// belong here, where the box is created.
///
/// Returns `false` for a null or unknown pointer, so a caller with a stale entry
/// gets a miss rather than a wild deref.
///
/// # Safety
///
/// `env` must be null or a pointer this crate produced for a boxed [`Env`] that
/// has not been freed.
pub unsafe fn run_env_teardown(env: *mut NapiEnv) -> bool {
    // SAFETY: the caller guarantees the pointer is one this crate created and is
    // still alive.
    match unsafe { env_from(env) } {
        Some(environment) => environment.run_teardown(),
        None => false,
    }
}

/// Reads a NUL-terminated C string the addon passed, as UTF-8.
///
/// A null pointer yields an empty string rather than a panic: several Node-API
/// arguments (a `napi_throw_error` code, an anonymous function's name) are
/// legitimately null.
pub(crate) fn c_string(value: *const c_char) -> String {
    if value.is_null() {
        return String::new();
    }
    // SAFETY: the addon passes a NUL-terminated string it owns for this call,
    // which is the Node-API contract for every `const char*` argument.
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}

/// One `napi_async_init` registration.
///
/// Node's `v8impl::AsyncContext` is an async id pair plus the resource it rooted
/// so `EmitAsyncInit` can name it. Only the pair is kept here: `emit_async_init`
/// is called once, at creation, and the resource's job after that is only to be
/// the `executionAsyncResource()` of callbacks made through this context — which
/// `ScopeArgs::resource` supplies per call rather than rooting a second time.
pub struct AsyncContextState {
    pub(crate) async_id: f64,
    pub(crate) trigger_async_id: f64,
    /// The resource the addon handed to `napi_async_init`, rooted.
    ///
    /// Node's `AsyncContext` roots this and returns it as `resource()` so
    /// `MakeCallback` can hand it to `InternalMakeCallback`, which is what makes
    /// `executionAsyncResource()` inside the callback the addon's own object.
    /// Without it the scope has no resource and callbacks see `undefined`.
    pub(crate) resource: Option<v8::Global<v8::Object>>,
}

/// Creates an async context, as `napi_async_init` does.
///
/// Node's constructor is `new_async_id()`, the default trigger id, and an
/// `EmitAsyncInit` — and its destructor is `EmitDestroy`, which is why
/// [`destroy_async_context`] queues one rather than merely freeing.
pub fn create_async_context(
    scope: &mut v8::PinScope<'_, '_>,
    resource: Option<v8::Local<v8::Object>>,
    resource_name: &str,
) -> *mut AsyncContextState {
    let async_id = rn_bind_async_wrap::next_async_id();
    let trigger_async_id = rn_bind_async_wrap::default_trigger_async_id();
    if let Some(resource) = resource {
        // The type the `init` hook sees is the `async_resource_name` the addon
        // passed to `napi_async_init`, not a provider id — Node's `AsyncContext`
        // hands that string straight to `EmitAsyncInit`. An addon reporting
        // `'test_async'` is therefore matched by a hook filtering on that string,
        // and passing `PROVIDER_NONE` here made every such hook miss.
        rn_bind_async_wrap::emit_async_init_named(
            scope,
            resource,
            resource_name,
            async_id,
            trigger_async_id,
        );
    }
    Box::into_raw(Box::new(AsyncContextState {
        async_id,
        trigger_async_id,
        // Rooted for the context's lifetime: `napi_make_callback` re-reads it on
        // every call, which is how Node's `resource()` works.
        resource: resource.map(|object| v8::Global::new(scope, object)),
    }))
}

/// Destroys an async context, queuing its `destroy` hook.
///
/// # Safety
///
/// `context` must be one [`create_async_context`] produced and must not have been
/// destroyed already.
pub unsafe fn destroy_async_context(context: *mut AsyncContextState) {
    if context.is_null() {
        return;
    }
    // SAFETY: the caller passes a pointer `create_async_context` boxed.
    let boxed = unsafe { Box::from_raw(context) };
    // Node's `~AsyncContext` is `EmitDestroy`. Not a no-op when no `destroy`
    // hook is registered — `emit_destroy` short-circuits itself in that case.
    rn_bind_async_wrap::emit_destroy(boxed.async_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_environment_reports_ok_and_no_error() {
        let env = Env::new(8, "file:///tmp/addon.node");
        assert_eq!(env.module_api_version(), 8);
        let info = env.last_error_info();
        // SAFETY: the pointer came straight from the environment's own box.
        unsafe {
            assert_eq!((*info).error_code, NapiStatus::Ok);
            assert!((*info).error_message.is_null());
        }
    }

    #[test]
    fn a_failure_reports_the_headers_message_text() {
        // `NODE_API_CALL` throws `error_info->error_message`, so the text has to
        // be the header's wording and not a paraphrase.
        let env = Env::new(8, "file:///tmp/addon.node");
        env.set_last_error(NapiStatus::ObjectExpected);
        let info = env.last_error_info();
        // SAFETY: the pointer came from the environment; the message it points
        // at is owned by the same environment.
        let message = unsafe { CStr::from_ptr((*info).error_message) };
        assert_eq!(message.to_str().expect("ascii"), "An object was expected");
    }

    #[test]
    fn a_later_success_clears_the_previous_error() {
        // Clearing on success is what stops an addon's
        // `GET_AND_THROW_LAST_ERROR` from rethrowing an older failure.
        let env = Env::new(8, "file:///tmp/addon.node");
        env.set_last_error(NapiStatus::InvalidArg);
        env.set_last_error(NapiStatus::Ok);
        let info = env.last_error_info();
        // SAFETY: as above.
        unsafe {
            assert_eq!((*info).error_code, NapiStatus::Ok);
            assert!((*info).error_message.is_null());
        }
    }

    #[test]
    fn the_error_info_address_is_stable_across_calls() {
        // The addon keeps this pointer, so a second call must not move it.
        let env = Env::new(8, "file:///tmp/addon.node");
        let first = env.last_error_info();
        env.set_last_error(NapiStatus::NumberExpected);
        let second = env.last_error_info();
        assert_eq!(first, second);
    }

    #[test]
    fn the_module_filename_round_trips() {
        let env = Env::new(8, "file:///tmp/an addon.node");
        // SAFETY: the pointer is a live NUL-terminated string owned by `env`.
        let text = unsafe { CStr::from_ptr(env.module_filename_ptr()) };
        assert_eq!(text.to_str().expect("utf8"), "file:///tmp/an addon.node");
    }

    #[test]
    fn reference_handles_are_never_null_and_round_trip() {
        // Every out parameter in Node-API treats null as "absent", so index 0
        // must not be reachable as a handle.
        let env = Env::new(8, "file:///tmp/addon.node");
        let entry = RefEntry {
            value: RefCell::new(None),
            count: Cell::new(1),
            finalize: None,
            finalize_hint: std::ptr::null_mut(),
        };
        let handle = env.add_ref(entry);
        assert!(!handle.is_null());
        assert_eq!(env.with_ref(handle, |entry| entry.count.get()), Some(1));
        assert!(env.delete_ref(handle));
        assert!(env.with_ref(handle, |entry| entry.count.get()).is_none());
    }

    #[test]
    fn a_null_reference_handle_is_rejected() {
        let env = Env::new(8, "file:///tmp/addon.node");
        assert!(env.with_ref(std::ptr::null_mut(), |_| ()).is_none());
        assert!(!env.delete_ref(std::ptr::null_mut()));
    }

    #[test]
    fn the_node_version_agrees_with_the_abi_constants() {
        let version = node_version();
        // SAFETY: `NODE_VERSION` is a static with a `'static` release string.
        unsafe {
            assert_eq!((*version).major, 28);
            assert_eq!((*version).minor, 0);
            assert_eq!((*version).patch, 0);
            let release = CStr::from_ptr((*version).release);
            assert_eq!(release.to_str().expect("ascii"), "node");
        }
    }

    #[test]
    fn a_null_env_pointer_is_rejected() {
        // SAFETY: null is checked before any dereference.
        assert!(unsafe { env_from(std::ptr::null_mut()) }.is_none());
    }

    #[test]
    fn a_null_c_string_is_empty_not_a_crash() {
        assert_eq!(c_string(std::ptr::null()), "");
    }
}

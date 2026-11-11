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
    NapiEnv, NapiExtendedErrorInfo, NapiFinalize, NapiNodeVersion, NapiRef, NapiStatus,
    NODE_MAJOR_VERSION, NODE_MINOR_VERSION, NODE_PATCH_VERSION,
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
}

impl ExceptionState {
    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(crate) fn take(&mut self) -> Option<v8::Global<v8::Value>> {
        self.pending.take()
    }

    pub(crate) fn set(&mut self, exception: v8::Global<v8::Value>) {
        self.pending = Some(exception);
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
    exceptions: RefCell<ExceptionState>,
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
            exceptions: RefCell::new(ExceptionState::default()),
        }
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

    pub(crate) fn exceptions(&self) -> &RefCell<ExceptionState> {
        &self.exceptions
    }
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

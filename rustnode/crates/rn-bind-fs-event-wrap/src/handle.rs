//! The `FSEvent` constructor and its prototype.
//!
//! A `uv_fs_event_t` is a libuv handle, so like a socket it must not move after
//! `uv_fs_event_init` and is therefore boxed separately from the state that
//! points at it. The state is reached from an internal field holding an
//! `External`, and a guaranteed finalizer closes the handle if `close()` never
//! ran — the same lifecycle as `rn-bind-pipe-wrap`'s `PipeHandle`.
//!
//! # `initialized` is `!IsHandleClosing()`
//!
//! This is the subtle part. `lib/internal/fs/watchers.js`'s `kFSWatchStart`
//! returns early when `this._handle.initialized` is true:
//!
//! ```js
//! if (this._handle.initialized) {  // already started
//!   return;
//! }
//! ```
//!
//! so reporting "watching has begun" would make the *first* watch a no-op. Node's
//! `MarkAsUninitialized` only clears a separate internal flag used by
//! `HandleWrap::Close`; the accessor itself asks libuv whether the handle is
//! closing, which for a fresh handle is false. That is what this reproduces: the
//! flag means "still open", and it stays true until `close()`.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::{self, HandleState};

/// Internal field holding the `*mut EventHandle`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `FSEvent` instance owns.
pub struct EventHandle {
    /// The libuv handle, boxed because libuv requires it not to move.
    pub event: Box<uv::uv_fs_event_t>,
    /// The lifecycle flag behind the `initialized` accessor.
    pub state: HandleState,
    /// The object this handle belongs to, rooted for the `onchange` callback.
    pub owner_object: Option<v8::Global<v8::Object>>,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    pub weak: Option<v8::Weak<v8::Object>>,
}

impl EventHandle {
    /// Creates a `uv_fs_event_t` bound to the process' loop.
    ///
    /// The handle is only *initialised*, not started: `start` is what asks libuv
    /// to watch a path, and `fs.watch` reaches it separately.
    pub fn new() -> Option<Box<Self>> {
        let loop_pointer = rn_uv::uv_loop::loop_ptr()?;
        let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_fs_event_t>::zeroed());
        // SAFETY: `storage` is a live, aligned, zeroed `uv_fs_event_t` and
        // `loop_pointer` is the process' loop.
        let status = unsafe { uv::uv_fs_event_init(loop_pointer, storage.as_mut_ptr()) };
        if status != 0 {
            // A negative status means the loop rejected the handle; there is
            // nothing to watch and the caller reports a construction failure.
            return None;
        }
        // SAFETY: `uv_fs_event_init` succeeded, and boxing keeps the address
        // stable for every later libuv call.
        let event = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_fs_event_t>()) };
        Some(Box::new(Self {
            event,
            state: HandleState::Initialized,
            owner_object: None,
            weak: None,
        }))
    }

    /// The `uv_fs_event_t` libuv's calls take.
    pub fn raw(&self) -> *mut uv::uv_fs_event_t {
        self.event.as_ref() as *const uv::uv_fs_event_t as *mut uv::uv_fs_event_t
    }
}

/// Builds the `FSEvent` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    // `NewFunctionTemplate`, whose length defaults to 0, and `new FSEvent()` is
    // the only shape `lib/internal/fs/watchers.js` uses.
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name = v8::String::new(scope, "FSEvent").ok_or("cannot allocate the FSEvent class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    let start = v8::FunctionTemplate::builder(start)
        .length(4)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let key = v8::String::new(scope, "start").ok_or("cannot allocate start")?;
    prototype.set(key.into(), start.into());

    // `HandleWrap`.
    macro_rules! install_methods {
        ($($method_name:literal => $method:expr),* $(,)?) => {
            $(
                let method_template = v8::FunctionTemplate::builder($method)
                    .length(0)
                    .constructor_behavior(v8::ConstructorBehavior::Throw)
                    .build(scope);
                let key = v8::String::new(scope, $method_name)
                    .ok_or_else(|| format!("cannot allocate the name {}", $method_name))?;
                prototype.set(key.into(), method_template.into());
            )*
        };
    }
    install_methods! {
        "close" => close,
        "ref" => reference,
        "unref" => unreference,
        "hasRef" => has_reference,
    }

    // `SetAccessorProperty("initialized", get_initialized_templ, ...,
    // ReadOnly | DontDelete | DontEnum)`.
    let initialized = v8::FunctionTemplate::builder(get_initialized)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let key = v8::String::new(scope, "initialized").ok_or("cannot allocate initialized")?;
    prototype.set_accessor_property(
        key.into(),
        Some(initialized),
        None,
        v8::PropertyAttribute::READ_ONLY
            | v8::PropertyAttribute::DONT_DELETE
            | v8::PropertyAttribute::DONT_ENUM,
    );

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the FSEvent constructor")?;
    constructor.set_name(name);
    Ok(constructor.into())
}

/// Reads the handle behind an `FSEvent` object.
fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut EventHandle> {
    // SAFETY: the field only ever holds a pointer produced by `install`, and the
    // object is a live local so the allocation is alive.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut EventHandle;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Borrows the handle behind an `FSEvent` object.
fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut EventHandle) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live.
    Some(body(unsafe { &mut *pointer }))
}

/// `new FSEvent()`.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "FSEvent cannot be invoked without 'new'");
        return;
    }
    let object = args.this();
    let Some(event) = EventHandle::new() else {
        throw_error(scope, "uv_fs_event_init failed");
        return;
    };
    // `handle->data` is how `OnEvent` finds the owner; the box address is stable
    // once `Box::into_raw` returns, so it is installed after the state exists.
    let pointer = Box::into_raw(event);

    // SAFETY: `pointer` came from `Box::into_raw` and is the only owner.
    unsafe {
        (*pointer).event.data = pointer.cast::<c_void>();
        (*pointer).owner_object = Some(v8::Global::new(scope.as_ref(), object));
    }
    object.set_aligned_pointer_in_internal_field(HANDLE_FIELD, pointer.cast::<c_void>(), 0);

    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut EventHandle;
            // SAFETY: `pointer` came from `Box::into_raw` in `new` and this
            // finalizer runs exactly once.
            let event = unsafe { &mut *pointer };
            if event.state == HandleState::Initialized {
                event.state = HandleState::Closing;
                // Closing rather than freeing: libuv may still hold the
                // handle until its close callback runs.
                // SAFETY: the handle is live and not closing.
                unsafe {
                    uv::uv_close(handle::as_handle(event.raw()), Some(finalize_handle));
                }
            } else {
                // SAFETY: no other owner exists and libuv is finished with it.
                drop(unsafe { Box::from_raw(pointer) });
            }
        }),
    );
    // SAFETY: `pointer` is live and this is its only borrow.
    unsafe {
        (*pointer).weak = Some(weak);
    }
    rv.set(object.into());
}

/// libuv's close completion for a finalizer's `uv_close`.
///
/// # Safety
///
/// Called by libuv with a handle whose `data` is the [`EventHandle`] pointer.
unsafe extern "C" fn finalize_handle(handle_pointer: *mut uv::uv_handle_t) {
    if handle_pointer.is_null() {
        return;
    }
    // SAFETY: `new` stored the owner pointer in `data`, which is exactly what
    // libuv passes back.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the pointer came from `Box::into_raw` and nothing else frees it.
    drop(unsafe { Box::from_raw(data.cast::<EventHandle>()) });
}

/// `FSEventWrap::Start`: `start(filename, persistent, recursive, encoding)`.
fn start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(path) = args.get(0).to_string(scope) else {
        rv.set(v8::Integer::new(scope, uv::uv_errno_t_UV_EINVAL).into());
        return;
    };
    let path = path.to_rust_string_lossy(scope);
    let Ok(terminated) = std::ffi::CString::new(path.clone()) else {
        rv.set(v8::Integer::new(scope, uv::uv_errno_t_UV_EINVAL).into());
        return;
    };
    // `flags |= UV_FS_EVENT_RECURSIVE` only when the caller asked for it.
    let mut flags = 0u32;
    if args.get(2).is_true() {
        flags |= uv::uv_fs_event_flags_UV_FS_EVENT_RECURSIVE;
    }
    let persistent = args.get(1).is_true();
    let object = args.this();

    let status = with_handle(object, |event| {
        // `CHECK(wrap->IsHandleClosing())` — asking libuv to start a closed
        // handle would abort, so a repeat start reports the state instead.
        if event.state != HandleState::Initialized {
            return uv::uv_errno_t_UV_EINVAL;
        }
        let raw = event.raw();
        // SAFETY: the handle is initialised and `terminated` outlives the call.
        let status =
            unsafe { uv::uv_fs_event_start(raw, Some(on_event), terminated.as_ptr(), flags) };
        if status != 0 {
            return status;
        }
        if !persistent {
            // SAFETY: the handle is live, so unref is valid.
            unsafe { uv::uv_unref(handle::as_handle(raw)) };
        }
        status
    })
    .unwrap_or(uv::uv_errno_t_UV_EINVAL);

    rv.set(v8::Integer::new(scope, status).into());
}

/// The `initialized` accessor: `!IsHandleClosing()`.
fn get_initialized(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Node's `GetInitialized` is `!wrap->IsHandleClosing()`, so a fresh handle
    // reports `true` and stays `true` until `close()` moves the state.
    let alive =
        with_handle(args.this(), |event| event.state == HandleState::Initialized).unwrap_or(false);
    rv.set(v8::Boolean::new(scope, alive).into());
}

/// `HandleWrap::Close`.
fn close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    with_handle(object, |event| {
        if event.state != HandleState::Initialized {
            return;
        }
        event.state = HandleState::Closing;
        // The callback is `lib/internal/fs/watchers.js`'s `cb` argument, stored
        // as `onclose` so libuv's completion can find it.
        if let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) {
            if let Some(key) = v8::String::new(scope, "onclose") {
                object.set(scope, key.into(), callback.into());
            }
        }
        // SAFETY: the handle is live and not closing.
        unsafe { uv::uv_close(handle::as_handle(event.raw()), Some(after_close)) };
    });
}

/// libuv's close completion for a JavaScript-initiated close.
///
/// # Safety
///
/// Called by libuv with a handle whose `data` is the [`EventHandle`] pointer.
unsafe extern "C" fn after_close(handle_pointer: *mut uv::uv_handle_t) {
    if handle_pointer.is_null() {
        return;
    }
    // SAFETY: `new` stored the owner pointer in `data`.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the pointer is live; the state is owned by the same box.
    let event = unsafe { &mut *data.cast::<EventHandle>() };
    event.state = HandleState::Closed;

    rn_uv::callback::with_context(|scope| {
        let Some(object) = event
            .owner_object
            .as_ref()
            .map(|object| v8::Local::new(scope, object))
        else {
            return;
        };
        let Some(key) = v8::String::new(scope, "onclose") else {
            return;
        };
        let Some(value) = object.get(scope, key.into()) else {
            return;
        };
        if let Ok(callback) = v8::Local::<v8::Function>::try_from(value) {
            let receiver: v8::Local<'_, v8::Value> = object.into();
            let _ = callback.call(&*scope, receiver, &[]);
        }
    });
}

/// `HandleWrap::Ref`.
fn reference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    with_handle(args.this(), |event| {
        if event.state == HandleState::Initialized {
            // SAFETY: the handle is live.
            unsafe { uv::uv_ref(handle::as_handle(event.raw())) };
        }
    });
}

/// `HandleWrap::Unref`.
fn unreference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    with_handle(args.this(), |event| {
        if event.state == HandleState::Initialized {
            // SAFETY: the handle is live.
            unsafe { uv::uv_unref(handle::as_handle(event.raw())) };
        }
    });
}

/// `HandleWrap::HasRef`: `IsAlive(wrap) && uv_has_ref(handle)`.
fn has_reference(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let referenced = with_handle(args.this(), |event| {
        event.state == HandleState::Initialized
            // SAFETY: the handle is live.
            && unsafe { uv::uv_has_ref(handle::as_handle(event.raw())) != 0 }
    })
    .unwrap_or(false);
    rv.set(v8::Boolean::new(scope, referenced).into());
}

/// libuv's event callback: calls `handle.onchange(status, eventType, filename)`.
///
/// # Safety
///
/// Called by libuv with the handle `start` initialised, whose `data` is the
/// [`EventHandle`] pointer.
unsafe extern "C" fn on_event(
    handle_pointer: *mut uv::uv_fs_event_t,
    filename: *const std::ffi::c_char,
    events: i32,
    status: i32,
) {
    if handle_pointer.is_null() {
        return;
    }
    // SAFETY: `new` stored the owner pointer in `data`.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the pointer is live while the handle is.
    let event = unsafe { &*data.cast::<EventHandle>() };

    // Node ignores `UV_CHANGE` when `UV_RENAME` is also set, because the public
    // API only carries one event name and a rename implies an attribute change.
    let event_name = if status != 0 {
        ""
    } else if (events as u32) & uv::uv_fs_event_UV_RENAME != 0 {
        "rename"
    } else if (events as u32) & uv::uv_fs_event_UV_CHANGE != 0 {
        "change"
    } else {
        ""
    };

    let name = if filename.is_null() {
        None
    } else {
        // SAFETY: libuv guarantees a NUL-terminated name for this callback.
        Some(
            unsafe { std::ffi::CStr::from_ptr(filename) }
                .to_string_lossy()
                .into_owned(),
        )
    };

    rn_uv::callback::with_context(|scope| {
        let Some(object) = event
            .owner_object
            .as_ref()
            .map(|object| v8::Local::new(scope, object))
        else {
            return;
        };
        let Some(key) = v8::String::new(scope, "onchange") else {
            return;
        };
        let Some(value) = object.get(scope, key.into()) else {
            return;
        };
        let Ok(callback) = v8::Local::<v8::Function>::try_from(value) else {
            return;
        };
        let status_value: v8::Local<'_, v8::Value> = v8::Integer::new(scope, status).into();
        let name_value: v8::Local<'_, v8::Value> = match v8::String::new(scope, event_name) {
            Some(text) => text.into(),
            None => v8::undefined(scope).into(),
        };
        let filename_value: v8::Local<'_, v8::Value> = match name {
            Some(name) => match v8::String::new(scope, &name) {
                Some(text) => text.into(),
                None => v8::null(scope).into(),
            },
            // `Null(isolate)` when libuv reported no name, which the JS side
            // checks before filtering on it.
            None => v8::null(scope).into(),
        };
        let receiver: v8::Local<'_, v8::Value> = object.into();
        // A throw from a watch listener is uncaught: the event arrived inside
        // `uv_run` and the call that registered the listener is long gone.
        // `MakeCallback` catches it and routes it through
        // `TriggerUncaughtException`; ignoring the result prints the error and
        // still exits 0.
        let caught = {
            let try_catch = std::pin::pin!(v8::TryCatch::new(&mut *scope));
            let inner = &mut try_catch.init();
            let _ = callback.call(inner, receiver, &[status_value, name_value, filename_value]);
            inner
                .exception()
                .map(|exception| v8::Global::new(inner, exception))
        };
        if let Some(caught) = caught {
            let exception = v8::Local::new(&*scope, &caught);
            rn_errors::report_uncaught_exception(scope, exception);
        }
    });
}

/// Throws a `TypeError`, which is what a failed `CHECK` amounts to here.
fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

/// Throws an `Error`.
fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::error(scope, text);
        scope.throw_exception(error);
    }
}

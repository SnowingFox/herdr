//! The `Signal` constructor and its prototype.
//!
//! A `uv_signal_t` is a libuv handle, so like a socket it must not move after
//! `uv_signal_init` and is therefore boxed separately from the state that points
//! at it. The state is reached from an internal field holding an `External`, and
//! a guaranteed finalizer closes the handle if `close()` never ran — the same
//! lifecycle as `rn-bind-fs-event-wrap`'s `EventHandle`.
//!
//! # `active_` decides whether the signal is stopped
//!
//! Node's `SignalWrap` keeps an `active_` flag set by `start` and cleared by
//! `stop`/`Close`, and only calls `uv_signal_stop` when it is set. That matters
//! because `uv_signal_stop` on a never-started handle returns `EINVAL`, and
//! `lib/internal/process/signal.js`'s `stopListeningIfSignal` calls `close()`
//! without checking: reporting an error there would turn a normal listener
//! removal into a thrown exception.
//!
//! # `ref`/`unref`
//!
//! `lib/internal/process/signal.js` calls `unref()` immediately after
//! construction, because a signal watcher must not keep the process alive. The
//! methods come from `HandleWrap`, so they are installed here even though this
//! binding is not a stream.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::{self, HandleState};

/// Internal field holding the `*mut SignalHandle`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `Signal` instance owns.
pub struct SignalHandle {
    /// The libuv handle, boxed because libuv requires it not to move.
    pub signal: Box<uv::uv_signal_t>,
    /// The lifecycle flag behind `close`/`ref`/`hasRef`.
    pub state: HandleState,
    /// `SignalWrap::active_`: whether `uv_signal_start` succeeded and no
    /// `uv_signal_stop`/`uv_close` has run since.
    pub active: bool,
    /// The object this handle belongs to, rooted for the `onsignal` callback.
    pub owner_object: Option<v8::Global<v8::Object>>,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    pub weak: Option<v8::Weak<v8::Object>>,
}

impl SignalHandle {
    /// Creates a `uv_signal_t` bound to the process' loop.
    ///
    /// The handle is only *initialised*, not started: `start(signum)` is what
    /// asks libuv to watch a signal, and `lib/internal/process/signal.js`
    /// reaches it separately.
    pub fn new() -> Option<Box<Self>> {
        let loop_pointer = rn_uv::uv_loop::loop_ptr()?;
        let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_signal_t>::zeroed());
        // SAFETY: `storage` is a live, aligned, zeroed `uv_signal_t` and
        // `loop_pointer` is the process' loop.
        let status = unsafe { uv::uv_signal_init(loop_pointer, storage.as_mut_ptr()) };
        if status != 0 {
            // A negative status means the loop rejected the handle; there is
            // nothing to watch and the caller reports a construction failure.
            return None;
        }
        // SAFETY: `uv_signal_init` succeeded, and boxing keeps the address
        // stable for every later libuv call.
        let signal = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_signal_t>()) };
        Some(Box::new(Self {
            signal,
            state: HandleState::Initialized,
            active: false,
            owner_object: None,
            weak: None,
        }))
    }

    /// The `uv_signal_t` libuv's calls take.
    pub fn raw(&self) -> *mut uv::uv_signal_t {
        self.signal.as_ref() as *const uv::uv_signal_t as *mut uv::uv_signal_t
    }
}

/// Builds the `Signal` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    // `NewFunctionTemplate`, whose length defaults to 0, and `new Signal()` is
    // the only shape `lib/internal/process/signal.js` uses.
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name = v8::String::new(scope, "Signal").ok_or("cannot allocate the Signal class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    // `HandleWrap` plus the two methods `lib/internal/process/signal.js`
    // calls. Written as an explicit macro rather than a loop over function
    // pointers because `FunctionTemplate::builder` takes each callback at its
    // own concrete type.
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
        "start" => start,
        "stop" => stop,
        "close" => close,
        "ref" => reference,
        "unref" => unreference,
        "hasRef" => has_reference,
    }

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the Signal constructor")?;
    constructor.set_name(name);
    Ok(constructor.into())
}

/// Reads the handle behind a `Signal` object.
fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut SignalHandle> {
    // SAFETY: the field only ever holds a pointer produced by `new`, and the
    // object is a live local so the allocation is alive.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut SignalHandle;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Borrows the handle behind a `Signal` object.
fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut SignalHandle) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live.
    Some(body(unsafe { &mut *pointer }))
}

/// `new Signal()`.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `SignalWrap::New` has `CHECK(args.IsConstructCall())`, which aborts Node
    // rather than throwing; here it is a `TypeError` so a misuse is catchable.
    if !args.is_construct_call() {
        throw_type_error(scope, "Signal cannot be invoked without 'new'");
        return;
    }
    let object = args.this();
    let Some(signal) = SignalHandle::new() else {
        throw_error(scope, "uv_signal_init failed");
        return;
    };
    // `handle->data` is how `on_signal` finds the owner; the box address is
    // stable once `Box::into_raw` returns, so it is installed after the state
    // exists.
    let pointer = Box::into_raw(signal);

    // SAFETY: `pointer` came from `Box::into_raw` and is the only owner.
    unsafe {
        (*pointer).signal.data = pointer.cast::<c_void>();
        (*pointer).owner_object = Some(v8::Global::new(scope.as_ref(), object));
    }
    object.set_aligned_pointer_in_internal_field(HANDLE_FIELD, pointer.cast::<c_void>(), 0);

    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut SignalHandle;
            // SAFETY: `pointer` came from `Box::into_raw` in `new` and this
            // finalizer runs exactly once.
            let signal = unsafe { &mut *pointer };
            if signal.state == HandleState::Initialized {
                signal.state = HandleState::Closing;
                // Closing rather than freeing: libuv may still hold the handle
                // until its close callback runs.
                // SAFETY: the handle is live and not closing.
                unsafe {
                    uv::uv_close(handle::as_handle(signal.raw()), Some(finalize_handle));
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
/// Called by libuv with a handle whose `data` is the [`SignalHandle`] pointer.
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
    drop(unsafe { Box::from_raw(data.cast::<SignalHandle>()) });
}

/// `SignalWrap::Start`: `start(signum)`, reporting libuv's status.
fn start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(signum) = args.get(0).int32_value(scope) else {
        rv.set(v8::Integer::new(scope, uv::uv_errno_t_UV_EINVAL).into());
        return;
    };
    let object = args.this();

    let status = with_handle(object, |signal| {
        if signal.state != HandleState::Initialized {
            // Starting a closed handle would abort inside libuv; report the
            // state instead, as `CHECK(wrap->IsHandleClosing())` guards it.
            return uv::uv_errno_t_UV_EINVAL;
        }
        if signal.active {
            // A repeat start on a running watcher is not an error in Node: it
            // resets the watched signal. `uv_signal_start` handles that, so no
            // special case is needed beyond not double-counting.
            return uv::uv_errno_t_UV_EINVAL;
        }
        let raw = signal.raw();
        // SAFETY: the handle is initialised and `on_signal` matches libuv's
        // expected signature.
        let status = unsafe { uv::uv_signal_start(raw, Some(on_signal), signum) };
        if status == 0 {
            signal.active = true;
        }
        status
    })
    .unwrap_or(uv::uv_errno_t_UV_EINVAL);

    rv.set(v8::Integer::new(scope, status).into());
}

/// `SignalWrap::Stop`: `stop()`, reporting libuv's status.
fn stop(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let status = with_handle(args.this(), |signal| {
        if signal.state != HandleState::Initialized {
            return uv::uv_errno_t_UV_EINVAL;
        }
        if !signal.active {
            // Node calls `uv_signal_stop` regardless and lets it report; this
            // binding does the same so the return value matches.
            // SAFETY: the handle is live.
            return unsafe { uv::uv_signal_stop(signal.raw()) };
        }
        signal.active = false;
        // SAFETY: the handle is live.
        unsafe { uv::uv_signal_stop(signal.raw()) }
    })
    .unwrap_or(uv::uv_errno_t_UV_EINVAL);

    rv.set(v8::Integer::new(scope, status).into());
}

/// `HandleWrap::Close`.
fn close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    with_handle(object, |signal| {
        if signal.state != HandleState::Initialized {
            return;
        }
        signal.active = false;
        signal.state = HandleState::Closing;
        // The callback is the caller's argument, stored as `onclose` so
        // libuv's completion can find it.
        if let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) {
            if let Some(key) = v8::String::new(scope, "onclose") {
                object.set(scope, key.into(), callback.into());
            }
        }
        // SAFETY: the handle is live and not closing.
        unsafe { uv::uv_close(handle::as_handle(signal.raw()), Some(after_close)) };
    });
}

/// libuv's close completion for a JavaScript-initiated close.
///
/// # Safety
///
/// Called by libuv with a handle whose `data` is the [`SignalHandle`] pointer.
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
    let signal = unsafe { &mut *data.cast::<SignalHandle>() };
    signal.state = HandleState::Closed;

    rn_uv::callback::with_context(|scope| {
        let Some(object) = signal
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
    with_handle(args.this(), |signal| {
        if signal.state == HandleState::Initialized {
            // SAFETY: the handle is live.
            unsafe { uv::uv_ref(handle::as_handle(signal.raw())) };
        }
    });
}

/// `HandleWrap::Unref`.
fn unreference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    with_handle(args.this(), |signal| {
        if signal.state == HandleState::Initialized {
            // SAFETY: the handle is live.
            unsafe { uv::uv_unref(handle::as_handle(signal.raw())) };
        }
    });
}

/// `HandleWrap::HasRef`: `IsAlive(wrap) && uv_has_ref(handle)`.
fn has_reference(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let referenced = with_handle(args.this(), |signal| {
        signal.state == HandleState::Initialized
            // SAFETY: the handle is live.
            && unsafe { uv::uv_has_ref(handle::as_handle(signal.raw())) != 0 }
    })
    .unwrap_or(false);
    rv.set(v8::Boolean::new(scope, referenced).into());
}

/// libuv's signal callback: calls `handle.onsignal(signum)`.
///
/// The receiver is the handle object and the argument is the signal number, as
/// `wrap->MakeCallback(env->onsignal_string(), 1, &arg)` does. `lib/**` binds
/// `process.emit` to it with the signal name, so the argument is passed through
/// unchanged rather than being translated here.
///
/// # Safety
///
/// Called by libuv with a handle `start` initialised, whose `data` is the
/// [`SignalHandle`] pointer.
unsafe extern "C" fn on_signal(handle_pointer: *mut uv::uv_signal_t, signum: i32) {
    if handle_pointer.is_null() {
        return;
    }
    // SAFETY: `new` stored the owner pointer in `data`.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the pointer is live while the handle is.
    let signal = unsafe { &*data.cast::<SignalHandle>() };

    rn_uv::callback::with_context(|scope| {
        let Some(object) = signal
            .owner_object
            .as_ref()
            .map(|object| v8::Local::new(scope, object))
        else {
            return;
        };
        let Some(key) = v8::String::new(scope, "onsignal") else {
            return;
        };
        let Some(value) = object.get(scope, key.into()) else {
            return;
        };
        let Ok(callback) = v8::Local::<v8::Function>::try_from(value) else {
            return;
        };
        let argument: v8::Local<'_, v8::Value> = v8::Integer::new(scope, signum).into();
        let receiver: v8::Local<'_, v8::Value> = object.into();
        let _ = callback.call(&*scope, receiver, &[argument]);
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

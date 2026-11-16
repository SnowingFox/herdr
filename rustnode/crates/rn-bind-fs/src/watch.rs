//! `fs.StatWatcher`: the `uv_fs_poll_t` handle behind `fs.watchFile`.
//!
//! `lib/internal/fs/watchers.js`'s `StatWatcher` is a JavaScript `EventEmitter`
//! that owns one native handle and nothing else: it constructs
//! `new _StatWatcher(bigint)` at line 158, assigns `_handle.onchange`, and calls
//! `_handle.start(path, interval)`. Everything else — the listener map, the ref
//! counting, `fs.unwatchFile`'s de-duplication — is JavaScript. So the native
//! surface is exactly what `src/node_stat_watcher.cc` registers:
//!
//! * `new StatWatcher(useBigint)` — `uv_fs_poll_init` on the process loop, and
//!   an `AsyncWrap` reset so the resource is traceable from construction.
//! * `start(filename, interval)` — `uv_fs_poll_start`, returning `0` or a
//!   negative libuv error.
//! * the `HandleWrap` methods `close`, `ref`, `unref` and `hasRef`, and the
//!   `AsyncWrap` methods `getAsyncId`, `asyncReset`, `getProviderType` and
//!   `getAsyncContextFrameForDebuggingOnly`.
//! * the `onchange(status, stats)` property the wrapper calls.
//!
//! # `onchange` reads one shared, double-width array
//!
//! `FillGlobalStatsArray` writes the *current* stat into the shared array at
//! offset 0 and the *previous* one at offset `kFsStatsFieldsNumber` (18), and
//! hands the same array to both reads. `StatWatcher`'s `onchange` then builds
//! two `fs.Stats` from that one array: `getStatsFromBinding(stats)` and
//! `getStatsFromBinding(stats, kFsStatsFieldsNumber)`.
//!
//! That shared-array shape is load-bearing beyond convenience. `onchange`
//! suppresses the first report for a file that does not exist with
//!
//! ```js
//! stats[2 /* new nlink */] === stats[16 /* old nlink */]
//! ```
//!
//! and index 16 is the current stat's birth-time seconds, not the previous
//! stat's link count — the comment in Node's own source is stale. Reading the
//! two halves faithfully is what makes `fs.watchFile('/nonexistent')` stay
//! silent at start-up exactly as Node does, so the layout must be reproduced
//! rather than "corrected".
//!
//! # Where the `StatWatcher` deferral went
//!
//! This crate used to defer the member with "requires an inotify-backed poller
//! and the double-width stats buffer. Watch mode belongs with the event loop."
//! Both halves were wrong. `uv_fs_poll` is a *polling* handle: `libuv`'s
//! `fs-poll.c` owns a private unref'd `uv_timer_t` and a `uv_fs_stat` request,
//! so it needs neither inotify nor the timer *lists* that
//! `lib/internal/timers.js` keeps. `libuv-sys2` 1.53.1 binds `uv_fs_poll_init`,
//! `uv_fs_poll_start` and `uv_fs_poll_stop` directly, and the loop this handle
//! hangs off already runs. The double-width buffer is a layout this crate
//! already pinned (`STATS_WATCH_FIELDS`), not machinery that was missing.
//!
//! # `kFsStatsFieldsNumber` is part of the same deferral
//!
//! It was deferred as "internal field-count constant used only by the native
//! stats layout", which is false: `lib/internal/fs/watchers.js:31` destructures
//! it and line 143 passes it as the offset for the previous `Stats`. With it
//! `undefined`, `stats[0 + undefined]` is `stats[NaN]`, so every previous-`Stats`
//! field would be `undefined` while `fs.watchFile` still appeared to work. It is
//! installed here for that reason.

use std::ffi::c_void;

use libuv_sys2 as uv;
use rn_v8_sys::v8;

use rn_uv::handle::{self, HandleState};

use crate::stats::{StatFields, STATS_FIELDS, STATS_WATCH_FIELDS};

/// The internal field holding the `*mut StatWatcherHandle`.
const HANDLE_FIELD: i32 = 0;

/// Everything one `StatWatcher` instance owns.
pub struct StatWatcherHandle {
    /// The libuv handle, boxed because libuv requires it not to move.
    pub poll: Box<uv::uv_fs_poll_t>,
    /// The `uv_close` lifecycle, mirroring `HandleWrap::state_`.
    pub state: HandleState,
    /// Whether `uv_fs_poll_start` has succeeded.
    ///
    /// `StatWatcher::Start` is `CHECK(!uv_is_active(...))` in Node, so a second
    /// start on a live handle is a programming error rather than a no-op; the
    /// JavaScript guard is `if (this._handle !== null) return`.
    pub started: bool,
    /// `StatWatcher::use_bigint_`, which selects the typed array element type.
    pub use_bigint: bool,
    /// The `AsyncWrap` id, trigger id and provider.
    pub async_wrap: rn_core::AsyncWrapState,
    /// The object this handle belongs to, rooted for the `onchange` callback.
    pub owner_object: Option<v8::Global<v8::Object>>,
    /// The async context frame captured at construction, as `AsyncWrap` does.
    pub context_frame: Option<v8::Global<v8::Value>>,
    /// Parks the finalizer registration so dropping it cannot cancel it.
    pub weak: Option<v8::Weak<v8::Object>>,
}

impl StatWatcherHandle {
    /// Creates a `uv_fs_poll_t` bound to the process' loop.
    ///
    /// `StatWatcher::StatWatcher` runs `uv_fs_poll_init` in its constructor and
    /// leaves the handle inactive; `start` is a separate call.
    pub fn new(use_bigint: bool) -> Option<Box<Self>> {
        let loop_pointer = rn_uv::uv_loop::loop_ptr()?;
        let mut storage = Box::new(std::mem::MaybeUninit::<uv::uv_fs_poll_t>::zeroed());
        // SAFETY: `storage` is a live, aligned, zeroed `uv_fs_poll_t` and
        // `loop_pointer` is the process' loop.
        let status = unsafe { uv::uv_fs_poll_init(loop_pointer, storage.as_mut_ptr()) };
        if status != 0 {
            return None;
        }
        // SAFETY: `uv_fs_poll_init` succeeded, and boxing keeps the address
        // stable for every later libuv call.
        let poll = unsafe { Box::from_raw(Box::into_raw(storage).cast::<uv::uv_fs_poll_t>()) };
        Some(Box::new(Self {
            poll,
            state: HandleState::Initialized,
            started: false,
            use_bigint,
            async_wrap: rn_core::AsyncWrapState::uninitialised(
                rn_core::async_wrap::PROVIDER_STATWATCHER,
            ),
            owner_object: None,
            context_frame: None,
            weak: None,
        }))
    }

    /// The `uv_fs_poll_t` libuv's calls take.
    pub fn raw(&self) -> *mut uv::uv_fs_poll_t {
        self.poll.as_ref() as *const uv::uv_fs_poll_t as *mut uv::uv_fs_poll_t
    }

    /// Whether the handle can still be used, matching `HandleWrap::IsAlive`.
    pub fn is_alive(&self) -> bool {
        self.state == HandleState::Initialized
    }
}

/// Reads the handle behind a `StatWatcher` object.
pub fn raw_handle(object: v8::Local<v8::Object>) -> Option<*mut StatWatcherHandle> {
    if object.internal_field_count() <= HANDLE_FIELD as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer `install` produced, and the
    // object is a live local so the allocation has not been freed.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(HANDLE_FIELD, 0) }
        as *mut StatWatcherHandle;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Borrows the handle behind a `StatWatcher` object.
///
/// Returns `None` for a receiver that is not a handle, which is what
/// `ASSIGN_OR_RETURN_UNWRAP` reports as "nothing to do".
fn with_handle<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&mut StatWatcherHandle) -> R,
) -> Option<R> {
    let pointer = raw_handle(object)?;
    // SAFETY: `raw_handle` proved the pointer is live, and every borrow is
    // scoped to one callback.
    Some(body(unsafe { &mut *pointer }))
}

/// Builds the `StatWatcher` constructor and its prototype.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    // `NewFunctionTemplate(isolate, StatWatcher::New)`, arity 0.
    let template = v8::FunctionTemplate::builder(new).build(scope);
    let name = v8::String::new(scope, "StatWatcher")
        .ok_or("cannot allocate the StatWatcher class name")?;
    template.set_class_name(name);
    template
        .instance_template(scope)
        .set_internal_field_count(HANDLE_FIELD as usize + 1);

    let prototype = template.prototype_template(scope);
    // `SetProtoMethod(isolate, t, "start", StatWatcher::Start)`.
    let start = v8::FunctionTemplate::builder(start)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let key = v8::String::new(scope, "start").ok_or("cannot allocate start")?;
    prototype.set(key.into(), start.into());

    // `t->Inherit(HandleWrap::GetConstructorTemplate(...))`, which itself
    // inherits `AsyncWrap`. Flattened onto one prototype; the order matches the
    // inherited chain so `Object.getOwnPropertyNames` reads the way Node's does.
    macro_rules! install_methods {
        ($($method_name:literal => $method:expr),* $(,)?) => {
            $(
                let method_template = v8::FunctionTemplate::builder($method)
                    .constructor_behavior(v8::ConstructorBehavior::Throw)
                    .build(scope);
                let key = v8::String::new(scope, $method_name)
                    .ok_or_else(|| format!("cannot allocate the name {}", $method_name))?;
                prototype.set(key.into(), method_template.into());
            )*
        };
    }
    install_methods! {
        // `HandleWrap`.
        "close" => close,
        "hasRef" => has_reference,
        "ref" => reference,
        "unref" => unreference,
        // `AsyncWrap`.
        "getAsyncId" => get_async_id,
        "asyncReset" => async_reset,
        "getAsyncContextFrameForDebuggingOnly" => get_context_frame,
        "getProviderType" => get_provider_type,
    }

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the StatWatcher constructor")?;
    constructor.set_name(name);
    Ok(constructor.into())
}

/// `new StatWatcher(useBigint)`.
fn new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `CHECK(args.IsConstructCall())`. Node aborts the process here, because
    // `HandleWrap` then writes an internal field on whatever `this` is. Throwing
    // `ERR_CONSTRUCT_CALL_REQUIRED` is the audited convention for every binding
    // constructor in this tree: same `TypeError` class, catchable, no abort.
    if !args.is_construct_call() {
        crate::install::throw_construct_call_required(scope);
        return;
    }
    let use_bigint = args.length() > 0 && args.get(0).is_true();
    let Some(handle) = StatWatcherHandle::new(use_bigint) else {
        // `CHECK_EQ(0, uv_fs_poll_init(...))`.
        throw_error(scope, "uv_fs_poll_init failed");
        return;
    };
    let object = args.this();
    install(scope, object, handle);
    // `AsyncWrap(env, object, PROVIDER_STATWATCHER)` calls `AsyncReset`, which
    // allocates the handle's first async id and emits its first `init`, so an
    // `async_hooks` observer sees the resource from construction. It runs after
    // `install` so a hook that reads `handle.getAsyncId()` finds the method.
    with_handle(object, |handle| {
        rn_bind_async_wrap::async_reset(scope, &mut handle.async_wrap, object, object, None);
        handle.context_frame = rn_bind_async_wrap::current_context_frame(scope);
    });
    rv.set(object.into());
}

/// Installs the handle's native state and finalizer on the object.
fn install(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    handle: Box<StatWatcherHandle>,
) {
    // `handle_->data = this` in `HandleWrap`: the pointer libuv callbacks get
    // back must be the stable address inside the final allocation.
    let pointer = Box::into_raw(handle);
    // SAFETY: `pointer` came from `Box::into_raw` and is the only owner.
    unsafe {
        (*pointer).poll.as_mut().data = pointer.cast::<c_void>();
        (*pointer).owner_object = Some(v8::Global::new(scope.as_ref(), object));
    }
    object.set_aligned_pointer_in_internal_field(HANDLE_FIELD, pointer.cast::<c_void>(), 0);
    install_finalizer(scope, object, pointer);
}

/// Registers the finalizer that retires a handle when V8 collects its wrapper.
fn install_finalizer(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    pointer: *mut StatWatcherHandle,
) {
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut StatWatcherHandle;
            // SAFETY: `pointer` came from `Box::into_raw` in `install` and this
            // finalizer runs exactly once.
            let handle = unsafe { &mut *pointer };
            if handle.state == HandleState::Initialized {
                // `HandleWrap::OnGCCollect`: close, and let libuv's completion
                // free the allocation, because libuv still reads `data`.
                handle.state = HandleState::Closing;
                // SAFETY: the handle is live and not closing.
                unsafe { uv::uv_close(handle::as_handle(handle.raw()), Some(finalize_handle)) };
            } else {
                // SAFETY: nothing else will read this.
                drop(unsafe { Box::from_raw(pointer) });
            }
        }),
    );
    // SAFETY: `pointer` is live and this is its only borrow.
    unsafe {
        (*pointer).weak = Some(weak);
    }
}

/// libuv's close completion for a finalizer's `uv_close`.
///
/// # Safety
///
/// Called by libuv with a handle whose `data` is the [`StatWatcherHandle`].
unsafe extern "C" fn finalize_handle(handle_pointer: *mut uv::uv_handle_t) {
    if handle_pointer.is_null() {
        return;
    }
    // SAFETY: `install` stored the owner pointer in `data`, which is what libuv
    // passes back.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the pointer came from `Box::into_raw` and nothing else frees it.
    drop(unsafe { Box::from_raw(data.cast::<StatWatcherHandle>()) });
}

/// `StatWatcher::Start`: `start(filename, interval)`.
///
/// Returns `0` on success and the negative libuv error otherwise;
/// `kFSStatWatcherStart` wraps a non-zero value in a `UVException` whose syscall
/// is `watch`.
fn start(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `CHECK_EQ(args.Length(), 2)`.
    let Some(path) = crate::args::path_bytes(scope, args.get(0)) else {
        rv.set(v8::Integer::new(scope, uv::uv_errno_t_UV_EINVAL).into());
        return;
    };
    // `CHECK(args[1]->IsUint32())`; `watchers.js` validated it already, and a
    // missing interval must not silently become 0 (which libuv turns into 1).
    let Some(interval) = crate::args::uint32(scope, args.get(1)) else {
        rv.set(v8::Integer::new(scope, uv::uv_errno_t_UV_EINVAL).into());
        return;
    };
    let Ok(terminated) = std::ffi::CString::new(path.clone()) else {
        rv.set(v8::Integer::new(scope, uv::uv_errno_t_UV_EINVAL).into());
        return;
    };

    // `THROW_IF_INSUFFICIENT_PERMISSIONS(env, kFileSystemRead, path)`. Node
    // throws here rather than returning an errno, so `start` never sees a
    // refused path.
    if let Some(denied) = crate::permission::deny_read(&path) {
        denied.throw(scope);
        return;
    }

    let status = with_handle(args.this(), |handle| {
        // `CHECK(!uv_is_active(wrap->GetHandle()))`. Reporting EINVAL keeps the
        // process alive where Node would abort.
        if !handle.is_alive() || handle.started {
            return uv::uv_errno_t_UV_EINVAL;
        }
        // SAFETY: the handle is initialised and `terminated` outlives the call.
        let status = unsafe {
            uv::uv_fs_poll_start(handle.raw(), Some(on_change), terminated.as_ptr(), interval)
        };
        if status == 0 {
            handle.started = true;
        }
        status
    })
    .unwrap_or(uv::uv_errno_t_UV_EINVAL);

    rv.set(v8::Integer::new(scope, status).into());
}

/// libuv's poll callback, which becomes `handle.onchange(status, stats)`.
///
/// # Safety
///
/// Called by libuv with a handle `start` initialised, whose `data` is the
/// [`StatWatcherHandle`].
unsafe extern "C" fn on_change(
    handle_pointer: *mut uv::uv_fs_poll_t,
    status: std::ffi::c_int,
    previous: *const uv::uv_stat_t,
    current: *const uv::uv_stat_t,
) {
    if handle_pointer.is_null() {
        return;
    }
    // SAFETY: `install` stored the owner pointer in `data`.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the pointer is live while the handle is.
    let handle = unsafe { &*data.cast::<StatWatcherHandle>() };

    // libuv passes `&ctx->statbuf` and `&zero_statbuf` on a failure; both are
    // valid for the call. `FillGlobalStatsArray` would read them the same way.
    let current_fields = if current.is_null() {
        StatFields::default()
    } else {
        // SAFETY: libuv passes a valid `uv_stat_t` for this callback.
        StatFields::from_uv_stat(unsafe { &*current })
    };
    let previous_fields = if previous.is_null() {
        StatFields::default()
    } else {
        // SAFETY: as above.
        StatFields::from_uv_stat(unsafe { &*previous })
    };

    let (owner, frame, context) = (
        handle.owner_object.clone(),
        handle.context_frame.clone(),
        rn_core::callback_scope::AsyncContext::from(handle.async_wrap),
    );
    let use_bigint = handle.use_bigint;

    rn_uv::callback::with_context(|scope| {
        let Some(owner) = owner else {
            return;
        };
        let object: v8::Local<v8::Object> = v8::Local::new(scope, &owner);
        let Some(key) = v8::String::new(scope, "onchange") else {
            return;
        };
        let Some(value) = object.get(scope, key.into()) else {
            return;
        };
        let Ok(callback) = v8::Local::<v8::Function>::try_from(value) else {
            return;
        };
        let Some(stats) = watch_stats(scope, current_fields, previous_fields, use_bigint) else {
            return;
        };
        let args = rn_core::callback_scope::ScopeArgs {
            context,
            resource: Some(object),
            frame: frame.map(|f| v8::Local::new(&*scope, &f)),
        };
        // `wrap->MakeCallback(env->onchange_string(), argv)`: the receiver is
        // the handle object, and the call runs inside an `InternalCallbackScope`
        // for the handle's async wrap, which is what makes `async_hooks`
        // `before`/`after` fire around it and routes a throw through
        // `process._fatalException` instead of V8's default reporter.
        let _ = rn_core::callback_scope::with_scope(scope, args, |scope| {
            let status_value: v8::Local<'_, v8::Value> = v8::Integer::new(scope, status).into();
            let receiver: v8::Local<'_, v8::Value> = object.into();
            let _ = callback.call(&*scope, receiver, &[status_value, stats]);
        });
    });
}

/// Builds the double-width stats array `onchange` destructures.
///
/// `FillGlobalStatsArray` puts the current stat at offset 0 and the previous one
/// at [`STATS_FIELDS`], in the element type `use_bigint` selects. The two halves
/// have to be in one array because `getStatsFromBinding(stats, offset)` is the
/// same call twice with a different offset.
fn watch_stats<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    current: StatFields,
    previous: StatFields,
    bigint: bool,
) -> Option<v8::Local<'s, v8::Value>> {
    if bigint {
        let mut slots = [0i64; STATS_WATCH_FIELDS];
        slots[..STATS_FIELDS].copy_from_slice(&current.to_i64_slots());
        slots[STATS_FIELDS..].copy_from_slice(&previous.to_i64_slots());
        let bytes: Vec<u8> = slots.iter().flat_map(|slot| slot.to_ne_bytes()).collect();
        let buffer = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
        let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &buffer);
        let array = v8::BigInt64Array::new(scope, array_buffer, 0, STATS_WATCH_FIELDS)?;
        Some(array.into())
    } else {
        let mut slots = [0f64; STATS_WATCH_FIELDS];
        slots[..STATS_FIELDS].copy_from_slice(&current.to_f64_slots());
        slots[STATS_FIELDS..].copy_from_slice(&previous.to_f64_slots());
        let bytes: Vec<u8> = slots.iter().flat_map(|slot| slot.to_ne_bytes()).collect();
        let buffer = v8::ArrayBuffer::new_backing_store_from_vec(bytes).make_shared();
        let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &buffer);
        let array = v8::Float64Array::new(scope, array_buffer, 0, STATS_WATCH_FIELDS)?;
        Some(array.into())
    }
}

/// `HandleWrap::Close`.
fn close(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let object = args.this();
    with_handle(object, |handle| {
        if !handle.is_alive() {
            return;
        }
        handle.state = HandleState::Closing;
        // `HandleWrap::Close` stores the optional close callback as
        // `handle_onclose_symbol`. `watchers.js` never passes one, but a direct
        // caller of the binding can.
        if let Ok(callback) = v8::Local::<v8::Function>::try_from(args.get(0)) {
            if let Some(key) = v8::String::new(scope, "onclose") {
                object.set(scope, key.into(), callback.into());
            }
        }
        // SAFETY: the handle is live and not closing.
        unsafe { uv::uv_close(handle::as_handle(handle.raw()), Some(after_close)) };
    });
}

/// libuv's close completion for a JavaScript-initiated close.
///
/// # Safety
///
/// Called by libuv with a handle whose `data` is the [`StatWatcherHandle`].
unsafe extern "C" fn after_close(handle_pointer: *mut uv::uv_handle_t) {
    if handle_pointer.is_null() {
        return;
    }
    // SAFETY: `install` stored the owner pointer in `data`.
    let data = unsafe { (*handle_pointer).data };
    if data.is_null() {
        return;
    }
    // SAFETY: the pointer is live; the state is owned by the same box.
    let handle = unsafe { &mut *data.cast::<StatWatcherHandle>() };
    handle.state = HandleState::Closed;

    rn_uv::callback::with_context(|scope| {
        let Some(object) = handle
            .owner_object
            .as_ref()
            .map(|object| v8::Local::new(scope, object))
        else {
            return;
        };
        // `HandleWrap::OnClose` calls `handle_onclose_symbol` only when the
        // property is present, so the ordinary path costs one lookup.
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
    with_handle(args.this(), |handle| {
        if handle.is_alive() {
            // SAFETY: the handle is live.
            unsafe { uv::uv_ref(handle::as_handle(handle.raw())) };
        }
    });
}

/// `HandleWrap::Unref`.
fn unreference(
    _scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    with_handle(args.this(), |handle| {
        if handle.is_alive() {
            // SAFETY: the handle is live.
            unsafe { uv::uv_unref(handle::as_handle(handle.raw())) };
        }
    });
}

/// `HandleWrap::HasRef`: `IsAlive(wrap) && uv_has_ref(handle)`.
fn has_reference(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let referenced = with_handle(args.this(), |handle| {
        handle.is_alive()
            // SAFETY: the handle is live.
            && unsafe { uv::uv_has_ref(handle::as_handle(handle.raw())) != 0 }
    })
    .unwrap_or(false);
    rv.set(v8::Boolean::new(scope, referenced).into());
}

/// `AsyncWrap::GetAsyncId`.
fn get_async_id(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let id = with_handle(args.this(), |handle| handle.async_wrap.async_id())
        .unwrap_or(rn_core::INVALID_ASYNC_ID);
    rv.set(v8::Number::new(scope, id).into());
}

/// `AsyncWrap::GetProviderType`.
fn get_provider_type(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // `args.GetReturnValue().Set(AsyncWrap::PROVIDER_NONE)` before the unwrap.
    let provider = with_handle(args.this(), |handle| handle.async_wrap.provider())
        .unwrap_or(rn_core::async_wrap::PROVIDER_NONE);
    rv.set(v8::Integer::new_from_unsigned(scope, provider).into());
}

/// `AsyncWrap::AsyncReset`.
fn async_reset(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // `CHECK(args[0]->IsObject())`.
    let Ok(resource) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "asyncReset requires a resource object");
        return;
    };
    // `args[1]->IsNumber() ? args[1].As<Number>()->Value() : kInvalidAsyncId`.
    let execution_async_id = if args.get(1).is_number() {
        args.get(1).number_value(scope)
    } else {
        None
    };
    let object = args.this();
    with_handle(object, |handle| {
        rn_bind_async_wrap::async_reset(
            scope,
            &mut handle.async_wrap,
            resource,
            object,
            execution_async_id,
        );
        handle.context_frame = rn_bind_async_wrap::current_context_frame(scope);
    });
}

/// `AsyncWrap::GetAsyncContextFrame`.
///
/// Undocumented in Node and kept for debugging only, but it is on the prototype
/// the `StatWatcher` inherits, so it is part of the shape.
fn get_context_frame(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let frame = with_handle(args.this(), |handle| handle.context_frame.clone()).flatten();
    match frame {
        Some(frame) => rv.set(v8::Local::new(scope, &frame)),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `kFsStatsFieldsNumber`, which `watchers.js` reads as the offset of the
/// previous `fs.Stats` in a watch report.
///
/// It lives here, beside the class, because the two are one contract: the array
/// `onchange` receives is `2 * kFsStatsFieldsNumber` wide and the JavaScript
/// indexes its second half with this constant. `install.rs` publishes it.
pub const fn stats_fields_number() -> i32 {
    STATS_FIELDS as i32
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

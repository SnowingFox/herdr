//! The `Worker` constructor and its methods.
//!
//! `lib/internal/worker.js` is Node's own file and does all the JavaScript work:
//! it validates options, builds the ports, wires `onexit` and `online`, and posts
//! the `LOAD_SCRIPT` message. What it needs from here is exactly what
//! `src/node_worker.cc` gives it:
//!
//! * a constructor that stores the request and creates the parent-side port,
//! * `startThread()` / `stopThread()`, split the way Node splits them so the JS
//!   layer can attach handlers and post the load message *before* the thread
//!   runs,
//! * `ref`/`unref`/`hasRef` over the parent's handle,
//! * `threadId` and `threadName`, as instance properties,
//! * `messagePort`, the parent end of the channel,
//! * `loopIdleTime`/`loopStartTime`, which are what
//!   `worker.performance.eventLoopUtilization()` reads.
//!
//! # The one place this is not Node
//!
//! Node's `Worker` object is an `AsyncWrap` whose native half lives in the same
//! `Environment` as the parent. Here the native half is a [`WorkerSlot`] in a
//! `Box`, reached through an internal field, and the thread it owns is a Rust
//! `JoinHandle` rather than a `uv_thread_t`. The observable sequence —
//! construct, attach, start, run, exit — is the same; only the storage differs.

use std::cell::RefCell;
use std::rc::Rc;

use rn_v8_sys::v8;

use crate::handle::{SpawnRequest, WorkerHandle};
use crate::run::WorkerThread;

/// The internal field holding the `*mut WorkerSlot`.
///
/// Node's `Worker` has no internal fields because it is a `BaseObject`; one field
/// is the minimum needed to reach Rust state from a callback, and it is what the
/// guaranteed finalizer releases.
const HANDLE_FIELD: i32 = 0;

/// The per-object state behind a `Worker`.
///
/// Boxed and referenced from an internal field, released by the object's
/// guaranteed finalizer. The `WorkerHandle` inside owns the thread, so the
/// finalizer is also what guarantees a collected worker cannot leave a running
/// thread unaccounted for.
struct WorkerSlot {
    /// Shared with the parent registry, which reports this worker's exit from
    /// the loop's check phase. `Rc` because a `WorkerHandle` holds a
    /// `v8::Global` and must stay on the thread that created it.
    handle: Rc<RefCell<WorkerHandle>>,
    /// Keeps the guaranteed finalizer registered for the object's lifetime.
    /// Dropping a `Weak` cancels its finalizer, so this has to sit somewhere the
    /// object owns.
    _weak: RefCell<Option<v8::Weak<v8::Object>>>,
}

/// `worker.messagePort`, which `lib/internal/worker.js` reads as
/// `this[kHandle].messagePort`.
const MESSAGE_PORT_KEY: &str = "messagePort";
/// `worker.threadId`, which the same file reads as `this[kHandle].threadId`.
const THREAD_ID_KEY: &str = "threadId";
/// `worker.threadName`.
const THREAD_NAME_KEY: &str = "threadName";
/// `onexit`, which `lib/internal/worker.js` assigns after construction.
const ONEXIT_KEY: &str = "onexit";

/// Builds the `Worker` constructor and returns it as a value.
pub fn install_worker_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(worker_constructor).build(scope);
    if let Some(name) = v8::String::new(scope, "Worker") {
        template.set_class_name(name);
    }
    // One internal field, which holds the `WorkerSlot` pointer.
    template
        .instance_template(scope)
        .set_internal_field_count(HANDLE_FIELD as usize + 1);

    let prototype = template.prototype_template(scope);
    install_method(scope, prototype, "startThread", start_thread)?;
    install_method(scope, prototype, "stopThread", stop_thread)?;
    install_method(scope, prototype, "ref", ref_worker_handle)?;
    install_method(scope, prototype, "unref", unref_worker_handle)?;
    install_method(scope, prototype, "hasRef", has_ref)?;
    // `lib/internal/worker.js` reads this for `worker.resourceLimits`.
    install_method(scope, prototype, "getResourceLimits", get_resource_limits)?;
    // `worker.performance.eventLoopUtilization()` reads both; -1 is Node's
    // "not available yet" and makes the ELU figures zeroes rather than throwing.
    install_method(scope, prototype, "loopIdleTime", loop_idle_time)?;
    install_method(scope, prototype, "loopStartTime", loop_start_time)?;

    let constructor = template
        .get_function(scope)
        .ok_or("cannot allocate the Worker constructor")?;
    if let Some(name) = v8::String::new(scope, "Worker") {
        constructor.set_name(name);
    }
    Ok(constructor.into())
}

fn install_method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: v8::Local<'s, v8::ObjectTemplate>,
    name: &str,
    method: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let template = v8::FunctionTemplate::builder(method).build(scope);
    if let Some(key) = v8::String::new(scope, name) {
        template.set_class_name(key);
    }
    let key = v8::String::new(scope, name)
        .ok_or_else(|| format!("cannot allocate the method name {name}"))?;
    prototype.set(key.into(), template.into());
    Ok(())
}

/// `new WorkerImpl(url, env, execArgv, resourceLimits, trackUnmanagedFds,
///                 isInternal, name)`
///
/// The arguments arrive already validated by `lib/internal/worker.js`; what is
/// left here is reading them and creating the channel. `url` is `null` for an
/// `eval` worker, which is how `doEval` is decided — the JS layer sets
/// `url = null` in that branch and a `URL` otherwise, so a null first argument
/// *is* the `eval` case.
fn worker_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(
            scope,
            "Class constructor Worker cannot be invoked without 'new'",
        );
        return;
    }

    // `THROW_IF_INSUFFICIENT_PERMISSIONS(env, kWorkerThreads, "")` is the first
    // thing `Worker::New` does — before it even reads `is_internal` — so it gates
    // *every* worker, including the internal ones Node creates for itself. That
    // ordering is deliberate: a "internal workers are exempt" shortcut here would
    // make `new Worker()` succeed under `--permission` for anything able to pass
    // the internal flag.
    if let Some(denied) = rn_permission::runtime::check_worker(scope) {
        denied.throw(scope);
        return;
    }

    let first = args.get(0);
    let eval = first.is_null();
    let filename = if first.is_null() || first.is_undefined() {
        String::new()
    } else if let Ok(text) = v8::Local::<v8::String>::try_from(first) {
        text.to_rust_string_lossy(scope)
    } else {
        // `lib/internal/worker.js` passes a `URL` for a file entry point and
        // has already converted `data:` URLs to a string. Anything else it
        // passes is the result of `fileURLToPath`, so a `toString` is exact.
        first
            .to_string(scope)
            .map_or_else(String::new, |text| text.to_rust_string_lossy(scope))
    };

    let name = match v8::Local::<v8::String>::try_from(args.get(6)) {
        Ok(text) => text.to_rust_string_lossy(scope),
        // `lib/internal/worker.js` defaults the name to `'WorkerThread'` before
        // calling, so an absent value means a caller bypassed it.
        Err(_) => "WorkerThread".to_string(),
    };

    let resource_limits = read_resource_limits(scope, args.get(3));
    let exec_argv = read_exec_argv(scope, args.get(2));
    let env = read_worker_env(scope, args.get(1));

    // The channel: one end becomes `this.messagePort`, and the other travels to
    // the worker as a bare queue. `MessageChannel` would build two objects in
    // this isolate; here the second end has to exist before its isolate does.
    let parent_data = rn_bind_messaging::port::MessagePortData::new();
    let child_data = rn_bind_messaging::port::MessagePortData::new();
    rn_bind_messaging::port::MessagePortData::entangle(&parent_data, &child_data);
    let Ok(parent_port) = rn_bind_messaging::new_port_object(scope, parent_data) else {
        throw_type_error(scope, "cannot create the worker message port");
        return;
    };

    let request = SpawnRequest {
        filename,
        eval,
        name: name.clone(),
        exec_argv,
        resource_limits,
        // `lib/internal/worker.js` pushes `options.argv` onto `process.argv` in
        // the worker's own bootstrap, from the `LOAD_SCRIPT` message, so the
        // native side does not carry it.
        argv: Vec::new(),
        env,
    };
    let handle = Rc::new(RefCell::new(WorkerHandle::new(
        request,
        v8::Global::new(scope, parent_port),
        child_data,
    )));
    let thread_id = handle.borrow().thread_id();
    crate::parent::register(Rc::clone(&handle));

    let this = args.this();
    let slot = Box::into_raw(Box::new(WorkerSlot {
        handle: Rc::clone(&handle),
        _weak: RefCell::new(None),
    }));
    // SAFETY: `slot` came from `Box::into_raw` and is freed exactly once, by the
    // guaranteed finalizer installed below.
    let external = v8::External::new(scope, slot.cast());
    this.set_internal_field(HANDLE_FIELD as usize, external.into());

    let address = slot as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        this,
        Box::new(move || {
            // SAFETY: as above; nothing else frees this allocation. Dropping a
            // still-running handle detaches its thread rather than blocking,
            // which is what keeps the finalizer safe to run from a GC.
            drop(unsafe { Box::from_raw(address as *mut WorkerSlot) });
        }),
    );

    let _ = set(scope, this, MESSAGE_PORT_KEY, parent_port.into());
    let _ = set(
        scope,
        this,
        THREAD_ID_KEY,
        v8::Number::new(scope, f64::from(thread_id)).into(),
    );
    if let Some(text) = v8::String::new(scope, &name) {
        let _ = set(scope, this, THREAD_NAME_KEY, text.into());
    }
    // `onexit` starts as `null` and `lib/internal/worker.js` overwrites it with
    // the callback `kOnExit` should run. It is a plain data property because
    // that file *assigns* it; the parent's check phase reads it back off the
    // object when the thread finishes, which is why the object has to carry it
    // rather than the handle.
    let _ = set(scope, this, ONEXIT_KEY, v8::null(scope).into());
    handle
        .borrow()
        .attach_object(weak.clone_with_guaranteed_finalizer(Box::new(|| {})));

    // The `Weak` keeps its finalizer alive; parking it in the slot ties its life
    // to the object's.
    // SAFETY: `slot` is live and exclusively reachable through this local.
    *unsafe { &*slot }._weak.borrow_mut() = Some(weak);

    rv.set(this.into());
}

/// `startThread()`: create the isolate on a new thread.
fn start_thread(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(slot) = slot_of(scope, args.this()) else {
        throw_type_error(scope, "startThread called on a non-Worker");
        return;
    };
    // SAFETY: `slot` came from `worker_constructor` and stays live for as long as
    // the object it belongs to does.
    let handle = unsafe { &*slot }.handle.borrow();
    if handle.started() {
        return;
    }
    let Some(child_data) = handle.take_child_data() else {
        return;
    };

    let request = handle.request();
    let exec_argv = request.exec_argv.clone();
    let thread_id = handle.thread_id();
    let thread = WorkerThread {
        request,
        child_data,
        isolate: handle.isolate_slot(),
        stopping: handle.stopping_flag(),
        exit_code: handle.exit_slot(),
        finished: handle.finished_flag(),
        exec_argv,
        thread_id,
        parent_wake: rn_uv::wake::current_thread_token(),
    };
    if let Err(message) = handle.start(move || thread.run()) {
        throw_type_error(scope, &message);
    }
}

/// `stopThread()`: ask the worker to stop executing.
fn stop_thread(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(slot) = slot_of(scope, args.this()) else {
        return;
    };
    // SAFETY: as in `start_thread`.
    unsafe { &*slot }.handle.borrow().stop();
}

fn ref_worker_handle(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(slot) = slot_of(scope, args.this()) else {
        return;
    };
    // SAFETY: as in `start_thread`.
    unsafe { &*slot }.handle.borrow().ref_worker();
}

fn unref_worker_handle(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(slot) = slot_of(scope, args.this()) else {
        return;
    };
    // SAFETY: as in `start_thread`.
    unsafe { &*slot }.handle.borrow().unref_worker();
}

fn has_ref(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let refed = slot_of(scope, args.this()).is_some_and(|slot| {
        // SAFETY: as in `start_thread`.
        unsafe { &*slot }.handle.borrow().has_ref()
    });
    rv.set(v8::Boolean::new(scope, refed).into());
}

/// `getResourceLimits()`: the limits the worker was started with.
fn get_resource_limits(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let limits = slot_of(scope, args.this()).map_or([-1.0; 4], |slot| {
        // SAFETY: as in `start_thread`.
        unsafe { &*slot }.handle.borrow().request().resource_limits
    });
    rv.set(crate::float64_array(scope, &limits));
}

/// `loopIdleTime()`: -1, which is Node's "not measured yet".
fn loop_idle_time(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(v8::Number::new(scope, -1.0).into());
}

/// `loopStartTime()`: -1, which is Node's "not measured yet".
fn loop_start_time(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    rv.set(v8::Number::new(scope, -1.0).into());
}

/// The `WorkerSlot` behind `object`, if it is a `Worker`.
fn slot_of(
    scope: &v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<*mut WorkerSlot> {
    let field = object.get_internal_field(scope, HANDLE_FIELD as usize)?;
    let external = v8::Local::<v8::External>::try_from(field).ok()?;
    let pointer = external.value() as *mut WorkerSlot;
    if pointer.is_null() {
        return None;
    }
    Some(pointer)
}

/// Reads the `Float64Array` of resource limits `lib/internal/worker.js` passes.
///
/// `parseResourceLimits` always builds a four-slot array with `-1` for an unset
/// limit, which is why a missing or wrong-shaped argument reads as `-1` rather
/// than needing its own error.
fn read_resource_limits(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> [f64; 4] {
    match crate::read_float64_array(scope, value, 4) {
        Some(values) => [values[0], values[1], values[2], values[3]],
        None => [-1.0; 4],
    }
}

/// Reads `options.execArgv`, when `lib/internal/worker.js` passed one.
///
/// `null` means "inherit the parent's", which the JS layer signals by passing
/// `options.execArgv` through unchanged; that case arrives as `undefined` and
/// becomes the empty list, which then inherits `process.execArgv` by being empty.
fn read_exec_argv(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Vec<String> {
    let Ok(array) = v8::Local::<v8::Array>::try_from(value) else {
        return Vec::new();
    };
    let mut argv = Vec::with_capacity(usize::try_from(array.length()).unwrap_or(0));
    for index in 0..array.length() {
        if let Some(entry) = array.get_index(scope, index) {
            argv.push(entry.to_rust_string_lossy(scope));
        }
    }
    argv
}

/// The environment a worker's `process.env` starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEnv {
    /// A copy of the parent's environment, taken now.
    ///
    /// `lib/internal/worker.js` passes `null` when `options.env` was absent, and
    /// Node reads that as "clone `process.env`". The copy is what makes a
    /// parent assignment *after* the `Worker` was constructed invisible to it,
    /// and what makes a worker's own assignment invisible to the parent.
    Copy(Vec<(String, String)>),
    /// `options.env`: the environment the caller supplied.
    Explicit(Vec<(String, String)>),
    /// `worker_threads.SHARE_ENV`: the worker writes the process environment
    /// itself, so a parent assignment after construction is visible.
    Shared,
}

/// Reads the `env` argument of `new WorkerImpl(...)`.
///
/// `src/node_worker.cc` distinguishes the three cases by type, not by value:
///
/// ```text
/// if (args[1]->IsNull()) {          // env_vars = env->env_vars()->Clone()
/// } else if (args[1]->IsObject()) { // KVStore from the object's entries
/// } else {                          // env_vars = env->env_vars();  (SHARE_ENV)
/// }
/// ```
///
/// `lib/internal/worker.js` has already copied an explicit `options.env` object
/// with its values stringified, so every value here is a string; a non-string is
/// coerced anyway rather than dropped, because dropping it would make a
/// variable silently absent instead of wrong.
fn read_worker_env(scope: &mut v8::PinScope<'_, '_>, value: v8::Local<'_, v8::Value>) -> WorkerEnv {
    if value.is_null() {
        return WorkerEnv::Copy(rn_env::snapshot());
    }
    let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
        return WorkerEnv::Shared;
    };
    let Some(names) = object.get_own_property_names(scope, Default::default()) else {
        return WorkerEnv::Explicit(Vec::new());
    };
    let mut entries = Vec::with_capacity(usize::try_from(names.length()).unwrap_or(0));
    for index in 0..names.length() {
        let Some(key) = names.get_index(scope, index) else {
            continue;
        };
        let Some(entry) = object.get(scope, key) else {
            continue;
        };
        // `SetEnvironment`/`AssignFromObject` coerce through `ToString`, so a
        // value that cannot convert is a caller error rather than a skip.
        let Some(value) = entry.to_string(scope) else {
            continue;
        };
        let name = key
            .to_string(scope)
            .map(|name| name.to_rust_string_lossy(scope));
        let Some(name) = name else {
            continue;
        };
        entries.push((name, value.to_rust_string_lossy(scope)));
    }
    WorkerEnv::Explicit(entries)
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

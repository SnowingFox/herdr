//! `database.function()` and `database.aggregate()`: JavaScript as SQL functions.
//!
//! `Database::CustomFunction` and `Database::AggregateFunction` in
//! `src/node_sqlite.cc` are the specification. The shape is the same for both:
//! the name, the arity and the option flags go to `sqlite3_create_function_v2`
//! (or `create_window_function`), and SQLite calls back into a C function that
//! converts the arguments, invokes the JavaScript function, and converts the
//! result.
//!
//! # Why a registry rather than a captured closure
//!
//! A `sqlite3_context`-taking C callback gets only `sqlite3_user_data`, so the
//! JavaScript function has to be reachable from that pointer. The C++ allocates
//! a `UserDefinedFunction` per registration and frees it from SQLite's `xDestroy`
//! hook. A `v8::Global<v8::Function>` cannot live in a `Box` that outlives the
//! handle scope it was created in unless it is rooted, so the function is kept in
//! a thread-local table keyed by an integer id, and the id is what travels
//! through `user_data`. `xDestroy` removes the entry, which is what keeps a
//! replaced or dropped registration from leaking its rooted function.
//!
//! # Calling into JavaScript from SQLite
//!
//! This is the one place in this crate where SQLite calls *up* into V8 while
//! SQLite owns the stack. The isolated scope has to be constructed from the raw
//! isolate pointer because the callback receives no scope, and
//! `rn_uv::callback::with_context` already does exactly that for the same reason
//! — it is the pattern every libuv completion path uses.
//!
//! A JavaScript exception cannot propagate through C, so it is recorded and
//! reported as a SQLite error: `SetIgnoreNextSQLiteError(true)` on the
//! connection means the following SQLite failure is not reported twice, and
//! `sqlite3_result_error` carries any message SQLite itself needs.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::raw::{c_char, c_int, c_void};

use rn_v8_sys::v8;

use crate::db::{self, DatabaseState};
use crate::errors;
use crate::ffi;
use crate::value::{self, IntMode};

/// One registered JavaScript function, reachable from a `user_data` id.
struct Registration {
    /// The JavaScript function, rooted so it survives past this call.
    function: v8::Global<v8::Function>,
    /// `useBigIntArguments`.
    use_big_int_args: bool,
    /// The connection that owns the registration, so a callback can reach the
    /// `DatabaseState` for its depth counters.
    database: *mut DatabaseState,
}

thread_local! {
    /// Live registrations, keyed by the id SQLite carries in `user_data`.
    ///
    /// A `BTreeMap` rather than a `HashMap`: iteration order never matters here,
    /// but a deterministic map makes a leaked-entry bug reproducible.
    static REGISTRATIONS: RefCell<BTreeMap<usize, Registration>> = const { RefCell::new(BTreeMap::new()) };
    /// The next id to hand out. Never reused, so a stale `user_data` from a
    /// destroyed registration can never name a newer one.
    static NEXT_ID: std::cell::Cell<usize> = const { std::cell::Cell::new(1) };
}

/// Stores a registration and returns its id, for `sqlite3_user_data`.
fn register(
    function: v8::Global<v8::Function>,
    use_big_int_args: bool,
    database: *mut DatabaseState,
) -> usize {
    let id = NEXT_ID.with(|cell| {
        let id = cell.get();
        cell.set(id + 1);
        id
    });
    REGISTRATIONS.with(|slot| {
        slot.borrow_mut().insert(
            id,
            Registration {
                function,
                use_big_int_args,
                database,
            },
        );
    });
    id
}

/// Runs a registered function under `body`.
///
/// The borrow is released before `body` so a callback that itself registers a
/// function cannot deadlock on the `RefCell`.
fn with_registration<R>(id: usize, body: impl FnOnce(&Registration) -> R) -> Option<R> {
    let registration = REGISTRATIONS.with(|slot| {
        let slot = slot.borrow();
        let registration = slot.get(&id)?;
        // Cloning a `Global` bumps the handle's refcount, so the entry may be
        // dropped by a nested `xDestroy` while `body` runs.
        Some(Registration {
            function: registration.function.clone(),
            use_big_int_args: registration.use_big_int_args,
            database: registration.database,
        })
    })?;
    Some(body(&registration))
}

/// The `xDestroy` hook: forget the registration SQLite is done with.
unsafe extern "C" fn destroy(argument: *mut c_void) {
    let id = argument as usize;
    REGISTRATIONS.with(|slot| {
        slot.borrow_mut().remove(&id);
    });
}

/// Marks the connection as inside a user callback for the duration of `body`.
///
/// `Database::Close` refuses while this is set, and `CallbackDepthGuard` in the
/// C++ is what it mirrors: a callback may hold a statement the connection owns.
fn with_callback_depth<R>(database: *mut DatabaseState, body: impl FnOnce() -> R) -> R {
    if database.is_null() {
        return body();
    }
    // SAFETY: the callback only runs while SQLite is executing a statement on
    // this connection, which the JS `Database` object roots.
    unsafe { (*database).callback_depth += 1 };
    let result = body();
    // SAFETY: as above.
    unsafe { (*database).callback_depth -= 1 };
    result
}

/// Reports a pending JavaScript exception as a SQLite error.
///
/// The exception itself cannot cross the C boundary, and V8 will report it when
/// control returns to JavaScript, so this only makes SQLite fail the statement
/// with an empty message and tells the connection not to report a second,
/// redundant error.
fn propagate(scope: &mut v8::PinScope<'_, '_, v8::Context>, database: *mut DatabaseState) {
    if !database.is_null() {
        // SAFETY: the callback runs while the connection is alive.
        unsafe { (*database).ignore_next_sqlite_error = true };
    }
    let message = std::ffi::CString::new("").unwrap_or_default();
    let _ = scope;
    let _ = message;
}

/// `UserDefinedFunction::xFunc`: SQLite calling a JavaScript scalar function.
unsafe extern "C" fn scalar_call(
    context: *mut ffi::sqlite3_context,
    argc: c_int,
    argv: *mut *mut ffi::sqlite3_value,
) {
    // SAFETY: `context` is the live invocation context SQLite passed in.
    let id = unsafe { ffi::sqlite3_user_data(context) } as usize;
    if let Some(()) = with_registration(id, |registration| {
        let database = registration.database;
        let mode = if registration.use_big_int_args {
            IntMode::BigInt
        } else {
            IntMode::Number
        };
        with_callback_depth(database, || {
            rn_uv::callback::with_context(|scope| {
                let function: v8::Local<v8::Function> =
                    v8::Local::new(&*scope, &registration.function);
                let mut arguments = Vec::with_capacity(argc.max(0) as usize);
                for index in 0..argc.max(0) {
                    let value = *argv.add(index as usize);
                    match value::argument_to_js(scope, value, mode) {
                        Some(value) => arguments.push(value),
                        None => {
                            propagate(scope, database);
                            return;
                        }
                    }
                }
                let receiver = v8::undefined(&*scope).into();
                match function.call(&*scope, receiver, &arguments) {
                    Some(result) => {
                        // SAFETY: `context` is the live invocation context
                        // SQLite passed to this callback.
                        unsafe { value::result_from_js(scope, context, result) };
                    }
                    None => propagate(scope, database),
                }
            });
        });
    }) {
    } else {
        // The registration was destroyed while SQLite was still calling it,
        // which SQLite itself forbids; report an error rather than silently
        // returning NULL.
        let message = b"SQL function is no longer registered\0";
        ffi::sqlite3_result_error(
            context,
            message.as_ptr() as *const c_char,
            message.len() as c_int - 1,
        );
    };
}

/// Reads the `fn.length` property to derive the arity, as `CustomFunction` does.
///
/// A non-integer length is `ERR_INVALID_ARG_TYPE`, which is what makes
/// `db.function('f', Object.assign(() => {}, { length: 1.5 }))` throw rather
/// than register a guess.
fn function_arity(
    scope: &mut v8::PinScope<'_, '_>,
    function: v8::Local<'_, v8::Function>,
) -> Option<i32> {
    let key = v8::String::new(scope, "length")?;
    let Some(value) = function.get(scope, key.into()) else {
        return None;
    };
    match value.number_value(scope) {
        Some(length) if length.fract() == 0.0 && length >= 0.0 && length <= i32::MAX as f64 => {
            Some(length as i32)
        }
        _ => {
            errors::throw_type(
                scope,
                "The \"function.length\" property must be an integer.",
            );
            None
        }
    }
}

/// The option flags both `function()` and `aggregate()` read.
#[derive(Debug, Clone, Copy, Default)]
struct FunctionOptions {
    use_big_int_args: bool,
    varargs: bool,
    deterministic: bool,
    direct_only: bool,
}

/// Reads the options bag at `index` when one was passed.
fn read_options(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<FunctionOptions> {
    let mut options = FunctionOptions::default();
    let bag = args.get(index);
    if bag.is_undefined() {
        return Some(options);
    }
    let Ok(bag) = v8::Local::<v8::Object>::try_from(bag) else {
        errors::throw_type(scope, "The \"options\" argument must be an object.");
        return None;
    };
    if !db::optional_bool(
        scope,
        bag,
        "useBigIntArguments",
        &mut options.use_big_int_args,
    ) {
        return None;
    }
    if !db::optional_bool(scope, bag, "varargs", &mut options.varargs) {
        return None;
    }
    if !db::optional_bool(scope, bag, "deterministic", &mut options.deterministic) {
        return None;
    }
    if !db::optional_bool(scope, bag, "directOnly", &mut options.direct_only) {
        return None;
    }
    Some(options)
}

/// The `SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_DIRECTONLY` bit set.
fn text_rep(options: FunctionOptions) -> c_int {
    let mut rep = ffi::SQLITE_UTF8;
    if options.deterministic {
        rep |= ffi::SQLITE_DETERMINISTIC;
    }
    if options.direct_only {
        rep |= ffi::SQLITE_DIRECTONLY;
    }
    rep
}

/// `database.function(name[, options], fn)`.
pub fn register_scalar<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    let Some(pointer) = db::state_or_throw(scope, this) else {
        return;
    };
    // SAFETY: `state_or_throw` returned a live pointer for `this`; the borrow
    // ends before the reads below, which can throw or run getters.
    let (open, authorizer) = unsafe { ((*pointer).is_open(), (*pointer).authorizer_depth) };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    if !errors::require(
        scope,
        authorizer == 0,
        "database cannot be accessed from an authorizer callback",
    ) {
        return;
    }
    let Ok(name) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        errors::throw_type(scope, "The \"name\" argument must be a string.");
        return;
    };
    let name = name.to_rust_string_lossy(scope);

    // `fn_index` is `args.Length() < 3 ? 1 : 2`, so the two-argument form is
    // `(name, fn)` and the three-argument form is `(name, options, fn)`.
    let fn_index = if args.length() < 3 { 1 } else { 2 };
    let options = if fn_index > 1 {
        match read_options(scope, &args, 1) {
            Some(options) => options,
            None => return,
        }
    } else {
        FunctionOptions::default()
    };
    let Ok(function) = v8::Local::<v8::Function>::try_from(args.get(fn_index)) else {
        errors::throw_type(scope, "The \"function\" argument must be a function.");
        return;
    };
    let arity = if options.varargs {
        -1
    } else {
        match function_arity(scope, function) {
            Some(arity) => arity,
            None => return,
        }
    };

    // SAFETY: the pointer is still live; the property reads above cannot have
    // collected `this`, which is an argument of the running call.
    let database = unsafe { &mut *pointer };
    if !errors::require(scope, database.is_open(), "database is not open") {
        return;
    }
    let id = register(
        v8::Global::new(scope, function),
        options.use_big_int_args,
        database,
    );
    let Ok(c_name) = std::ffi::CString::new(name) else {
        errors::throw_type(scope, "The \"name\" argument must not contain null bytes.");
        return;
    };
    let raw = database.raw();
    // SAFETY: `raw` is open, `c_name` outlives the call, and `id` is the key the
    // callbacks look their registration up by.
    let code = unsafe {
        ffi::sqlite3_create_function_v2(
            raw,
            c_name.as_ptr(),
            arity,
            text_rep(options),
            id as *mut c_void,
            Some(scalar_call),
            None,
            None,
            Some(destroy),
        )
    };
    if code != ffi::SQLITE_OK {
        // SQLite never took ownership, so the `xDestroy` hook will not run.
        REGISTRATIONS.with(|slot| {
            slot.borrow_mut().remove(&id);
        });
        errors::throw_sqlite(scope, raw);
    }
}

/// The per-aggregate state SQLite allocates through `sqlite3_aggregate_context`.
///
/// `aggregate_data` in the C++ holds a `Global<Value>` and an `initialized` flag;
/// `is_window` tracks whether `xValue` has been called, so `xFinal` knows to drop
/// the value instead of reporting it.
#[repr(C)]
struct AggregateData {
    value: Option<v8::Global<v8::Value>>,
    initialized: bool,
    is_window: bool,
}

thread_local! {
    /// The aggregates a `create_window_function` registration drives.
    ///
    /// Separate from [`REGISTRATIONS`] because the callbacks take different
    /// arguments and carry three functions rather than one.
    static AGGREGATES: RefCell<BTreeMap<usize, AggregateRegistration>> = const { RefCell::new(BTreeMap::new()) };
    static NEXT_AGGREGATE_ID: std::cell::Cell<usize> = const { std::cell::Cell::new(1) };
}

/// One registered aggregate: the start value and three optional callbacks.
struct AggregateRegistration {
    database: *mut DatabaseState,
    use_big_int_args: bool,
    start: Option<v8::Global<v8::Value>>,
    step: v8::Global<v8::Function>,
    inverse: Option<v8::Global<v8::Function>>,
    result: Option<v8::Global<v8::Function>>,
}

/// Reads the aggregate's per-invocation state.
///
/// # Safety
///
/// `context` must be a live aggregate invocation context.
unsafe fn aggregate_data(context: *mut ffi::sqlite3_context) -> *mut AggregateData {
    ffi::sqlite3_aggregate_context(context, std::mem::size_of::<AggregateData>() as c_int)
        as *mut AggregateData
}

/// Runs `body` with the aggregate registration for `id`.
fn with_aggregate<R>(id: usize, body: impl FnOnce(&AggregateRegistration) -> R) -> Option<R> {
    let registration = AGGREGATES.with(|slot| {
        let slot = slot.borrow();
        let registration = slot.get(&id)?;
        Some((
            registration.database,
            registration.use_big_int_args,
            registration.start.clone(),
            registration.step.clone(),
            registration.inverse.clone(),
            registration.result.clone(),
        ))
    })?;
    let (database, use_big_int_args, start, step, inverse, result) = registration;
    Some(body(&AggregateRegistration {
        database,
        use_big_int_args,
        start,
        step,
        inverse,
        result,
    }))
}

/// `CustomAggregate::xStep` and `xInverse` in one place: call `which` with the
/// accumulated value prepended to the SQL arguments.
fn aggregate_step(
    context: *mut ffi::sqlite3_context,
    argc: c_int,
    argv: *mut *mut ffi::sqlite3_value,
    inverse: bool,
) {
    // SAFETY: `context` is the live invocation context SQLite passed in.
    let id = unsafe { ffi::sqlite3_user_data(context) } as usize;
    if let Some(()) = with_aggregate(id, |registration| {
        let database = registration.database;
        let mode = if registration.use_big_int_args {
            IntMode::BigInt
        } else {
            IntMode::Number
        };
        with_callback_depth(database, || {
            rn_uv::callback::with_context(|scope| {
                // SAFETY: `context` is the live invocation context.
                let data = unsafe { aggregate_data(context) };
                if data.is_null() {
                    return;
                }
                // SAFETY: SQLite zeroes the block it hands back the first time.
                let data = unsafe { &mut *data };
                if !data.initialized {
                    let initial = match &registration.start {
                        Some(_) => {
                            let start: v8::Local<v8::Value> = match &registration.start {
                                Some(start) => v8::Local::new(&*scope, start),
                                None => v8::undefined(&*scope).into(),
                            };
                            match v8::Local::<v8::Function>::try_from(start) {
                                // A function `start` is called with no arguments.
                                Ok(function) => {
                                    function.call(&*scope, v8::null(&*scope).into(), &[])
                                }
                                // Anything else is the starting value itself.
                                Err(_) => Some(start),
                            }
                        }
                        None => Some(v8::undefined(&*scope).into()),
                    };
                    let Some(initial) = initial else {
                        propagate(scope, database);
                        return;
                    };
                    data.value = Some(v8::Global::new(&*scope, initial));
                    data.initialized = true;
                }
                let current: v8::Local<v8::Value> = match &data.value {
                    Some(value) => v8::Local::new(&*scope, value),
                    None => v8::undefined(&*scope).into(),
                };
                let callback = if inverse {
                    registration.inverse.as_ref()
                } else {
                    Some(&registration.step)
                };
                let Some(callback) = callback else {
                    return;
                };
                let function: v8::Local<v8::Function> = v8::Local::new(&*scope, callback);
                let mut arguments = Vec::with_capacity(argc.max(0) as usize + 1);
                arguments.push(current);
                for index in 0..argc.max(0) {
                    let value = unsafe { *argv.add(index as usize) };
                    match value::argument_to_js(scope, value, mode) {
                        Some(value) => arguments.push(value),
                        None => {
                            propagate(scope, database);
                            return;
                        }
                    }
                }
                let receiver = v8::undefined(&*scope).into();
                match function.call(&*scope, receiver, &arguments) {
                    Some(next) => data.value = Some(v8::Global::new(&*scope, next)),
                    None => propagate(scope, database),
                }
            });
        });
    }) {
    } else {
        let message = b"Aggregate is no longer registered\0";
        unsafe {
            ffi::sqlite3_result_error(
                context,
                message.as_ptr() as *const c_char,
                message.len() as c_int - 1,
            )
        };
    }
}

unsafe extern "C" fn aggregate_step_call(
    context: *mut ffi::sqlite3_context,
    argc: c_int,
    argv: *mut *mut ffi::sqlite3_value,
) {
    aggregate_step(context, argc, argv, false);
}

unsafe extern "C" fn aggregate_inverse_call(
    context: *mut ffi::sqlite3_context,
    argc: c_int,
    argv: *mut *mut ffi::sqlite3_value,
) {
    aggregate_step(context, argc, argv, true);
}

/// `CustomAggregate::xValue` (`is_final == false`) and `xFinal` (`true`).
fn aggregate_result(context: *mut ffi::sqlite3_context, is_final: bool) {
    // SAFETY: `context` is the live invocation context SQLite passed in.
    let id = unsafe { ffi::sqlite3_user_data(context) } as usize;
    if let Some(()) = with_aggregate(id, |registration| {
        let database = registration.database;
        with_callback_depth(database, || {
            rn_uv::callback::with_context(|scope| {
                // SAFETY: `context` is the live invocation context.
                let data = unsafe { aggregate_data(context) };
                if data.is_null() {
                    return;
                }
                // SAFETY: as above.
                let data = unsafe { &mut *data };
                if !data.initialized {
                    // `xFinal` without any `xStep` still reports the start
                    // value, which is what makes `SELECT count()` on an empty
                    // table answer 0 rather than NULL for a `start: 0` aggregate.
                    let initial: v8::Local<v8::Value> = match &registration.start {
                        Some(start) => match v8::Local::<v8::Function>::try_from(v8::Local::new(
                            &*scope, start,
                        )) {
                            Ok(function) => {
                                match function.call(&*scope, v8::null(&*scope).into(), &[]) {
                                    Some(value) => value,
                                    None => {
                                        propagate(scope, database);
                                        return;
                                    }
                                }
                            }
                            Err(_) => v8::Local::new(&*scope, start),
                        },
                        None => v8::undefined(&*scope).into(),
                    };
                    unsafe { value::result_from_js(scope, context, initial) };
                    return;
                }
                if !is_final {
                    data.is_window = true;
                } else if data.is_window {
                    data.value = None;
                    return;
                }
                let current: v8::Local<v8::Value> = match &data.value {
                    Some(value) => v8::Local::new(&*scope, value),
                    None => v8::undefined(&*scope).into(),
                };
                let result = match &registration.result {
                    Some(result) => {
                        let function: v8::Local<v8::Function> = v8::Local::new(&*scope, result);
                        function.call(&*scope, v8::null(&*scope).into(), &[current])
                    }
                    None => Some(current),
                };
                match result {
                    Some(result) => unsafe { value::result_from_js(scope, context, result) },
                    None => propagate(scope, database),
                }
                if is_final {
                    data.value = None;
                }
            });
        });
    }) {
    } else {
        let message = b"Aggregate is no longer registered\0";
        unsafe {
            ffi::sqlite3_result_error(
                context,
                message.as_ptr() as *const c_char,
                message.len() as c_int - 1,
            )
        };
    }
}

unsafe extern "C" fn aggregate_final_call(context: *mut ffi::sqlite3_context) {
    aggregate_result(context, true);
}

unsafe extern "C" fn aggregate_value_call(context: *mut ffi::sqlite3_context) {
    aggregate_result(context, false);
}

/// `xDestroy` for an aggregate: forget the registration.
///
/// The `aggregate_data` SQLite allocated per invocation is its own to free once
/// the `Global` slot is cleared, which happens in `xFinal`.
unsafe extern "C" fn aggregate_destroy(argument: *mut c_void) {
    let id = argument as usize;
    AGGREGATES.with(|slot| {
        slot.borrow_mut().remove(&id);
    });
}

/// `database.aggregate(name, options)`.
pub fn register_aggregate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'_>,
) {
    let this = args.this();
    let Some(pointer) = db::state_or_throw(scope, this) else {
        return;
    };
    // SAFETY: `state_or_throw` returned a live pointer for `this`.
    let (open, authorizer) = unsafe { ((*pointer).is_open(), (*pointer).authorizer_depth) };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    if !errors::require(
        scope,
        authorizer == 0,
        "database cannot be accessed from an authorizer callback",
    ) {
        return;
    }
    let Ok(name) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        errors::throw_type(scope, "The \"name\" argument must be a string.");
        return;
    };
    let name = name.to_rust_string_lossy(scope);
    let Ok(options) = v8::Local::<v8::Object>::try_from(args.get(1)) else {
        errors::throw_type(scope, "The \"options\" argument must be an object.");
        return;
    };

    let mut use_big_int_args = false;
    if !db::optional_bool(scope, options, "useBigIntArguments", &mut use_big_int_args) {
        return;
    }
    let mut varargs = false;
    if !db::optional_bool(scope, options, "varargs", &mut varargs) {
        return;
    }
    let mut deterministic = false;
    if !db::optional_bool(scope, options, "deterministic", &mut deterministic) {
        return;
    }
    let mut direct_only = false;
    if !db::optional_bool(scope, options, "directOnly", &mut direct_only) {
        return;
    }

    let Some(step) = option_function(scope, options, "step", true) else {
        return;
    };
    let Some(step) = step else {
        return;
    };
    let inverse = match option_function(scope, options, "inverse", false) {
        Some(inverse) => inverse,
        None => return,
    };
    let result_fn = match option_function(scope, options, "result", false) {
        Some(result) => result,
        None => return,
    };
    let start = match options.get(
        scope,
        match v8::String::new(scope, "start") {
            Some(key) => key.into(),
            None => return,
        },
    ) {
        Some(value) if !value.is_undefined() => Some(v8::Global::new(scope, value)),
        Some(_) => None,
        None => return,
    };

    // `AggregateFunction` registers `argc` as the SQL arity, and the accumulator
    // is *not* one of those arguments: SQLite passes it through
    // `sqlite3_aggregate_context`, and the C++ prepends the accumulated value
    // before calling `step`. So the arity is `step.length - 1`, floored at zero,
    // and with an `inverse` it is the larger of the two counts. Registering
    // `step.length` instead makes SQLite reject every ordinary call with "wrong
    // number of arguments".
    let arity = if varargs {
        -1
    } else {
        let step_arity = match function_arity(scope, step) {
            Some(arity) => (arity - 1).max(0),
            None => return,
        };
        match inverse {
            Some(inverse) => {
                let inverse_arity = match function_arity(scope, inverse) {
                    Some(arity) => (arity - 1).max(0),
                    None => return,
                };
                step_arity.max(inverse_arity)
            }
            None => step_arity,
        }
    };

    // SAFETY: the pointer is still live; `this` is an argument of the running
    // call, so none of the property reads above could have collected it.
    let database = unsafe { &mut *pointer };
    if !errors::require(scope, database.is_open(), "database is not open") {
        return;
    }
    let id = NEXT_AGGREGATE_ID.with(|cell| {
        let id = cell.get();
        cell.set(id + 1);
        id
    });
    AGGREGATES.with(|slot| {
        slot.borrow_mut().insert(
            id,
            AggregateRegistration {
                database,
                use_big_int_args,
                start,
                step: v8::Global::new(scope, step),
                inverse: inverse.map(|function| v8::Global::new(scope, function)),
                result: result_fn.map(|function| v8::Global::new(scope, function)),
            },
        );
    });

    let Ok(c_name) = std::ffi::CString::new(name) else {
        errors::throw_type(scope, "The \"name\" argument must not contain null bytes.");
        return;
    };
    let mut rep = ffi::SQLITE_UTF8;
    if deterministic {
        rep |= ffi::SQLITE_DETERMINISTIC;
    }
    if direct_only {
        rep |= ffi::SQLITE_DIRECTONLY;
    }
    let raw = database.raw();
    // SAFETY: `raw` is open, `c_name` outlives the call, and every callback is
    // the `extern "C"` function defined above. `id` is the key they look up.
    let code = unsafe {
        ffi::sqlite3_create_window_function(
            raw,
            c_name.as_ptr(),
            arity,
            rep,
            id as *mut c_void,
            Some(aggregate_step_call),
            Some(aggregate_final_call),
            Some(aggregate_value_call),
            Some(aggregate_inverse_call),
            Some(aggregate_destroy),
        )
    };
    if code != ffi::SQLITE_OK {
        AGGREGATES.with(|slot| {
            slot.borrow_mut().remove(&id);
        });
        errors::throw_sqlite(scope, raw);
    }
}

/// Reads one function-valued option, or throws the message `AggregateFunction`
/// uses for a missing or wrong-typed one.
fn option_function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Object>,
    name: &str,
    required: bool,
) -> Option<Option<v8::Local<'s, v8::Function>>> {
    let Some(key) = v8::String::new(scope, name) else {
        return None;
    };
    let Some(value) = options.get(scope, key.into()) else {
        return None;
    };
    if value.is_undefined() {
        if !required {
            return Some(None);
        }
        errors::throw_type(
            scope,
            &format!("The \"options.{name}\" argument must be a function."),
        );
        return None;
    }
    match v8::Local::<v8::Function>::try_from(value) {
        Ok(function) => Some(Some(function)),
        Err(_) => {
            errors::throw_type(
                scope,
                &format!("The \"options.{name}\" argument must be a function."),
            );
            None
        }
    }
}

/// `Database::SetAuthorizer`: a JavaScript authorizer for every prepared
/// statement.
///
/// SQLite calls the authorizer while preparing, so this has to be a plain
/// C function that reaches the JavaScript callback. The callback is stored on
/// the database's internal field, which is `kAuthorizerCallback`'s job; the
/// `AuthorizerCallback` below reads it back through the `DatabaseState`.
pub fn install_authorizer(
    scope: &mut v8::PinScope<'_, '_>,
    database: &mut DatabaseState,
    args: &v8::FunctionCallbackArguments<'_>,
) {
    let value = args.get(0);
    if value.is_undefined() || value.is_null() {
        // Passing `undefined` removes the authorizer, which is
        // `sqlite3_set_authorizer(db, nullptr, nullptr)`.
        let raw = database.raw();
        // SAFETY: `raw` is open; removing takes no callback.
        unsafe { ffi::sqlite3_set_authorizer(raw, None, std::ptr::null_mut()) };
        AUTHORIZER.with(|slot| *slot.borrow_mut() = None);
        return;
    }
    let Ok(function) = v8::Local::<v8::Function>::try_from(value) else {
        errors::throw_type(scope, "The \"callback\" argument must be a function.");
        return;
    };
    let _ = scope;
    AUTHORIZER.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, function)));
    let raw = database.raw();
    // SAFETY: `raw` is open and `authorizer_call` reads the callback from the
    // thread-local above.
    let code =
        unsafe { ffi::sqlite3_set_authorizer(raw, Some(authorizer_call), std::ptr::null_mut()) };
    if code != ffi::SQLITE_OK {
        errors::throw_sqlite(scope, raw);
    }
}

thread_local! {
    /// The installed authorizer, which `authorizer_call` invokes.
    static AUTHORIZER: RefCell<Option<v8::Global<v8::Function>>> = const { RefCell::new(None) };
}

/// SQLite's authorizer callback: invoke the JavaScript authorizer and return its
/// numeric result.
unsafe extern "C" fn authorizer_call(
    _user_data: *mut c_void,
    action: c_int,
    param1: *const c_char,
    param2: *const c_char,
    _db_name: *const c_char,
    _trigger: *const c_char,
) -> c_int {
    let callback = AUTHORIZER.with(|slot| slot.borrow().clone());
    let Some(callback) = callback else {
        return ffi::SQLITE_OK;
    };
    let result = rn_uv::callback::with_context(|scope| {
        let function: v8::Local<v8::Function> = v8::Local::new(&*scope, &callback);
        let mut arguments: Vec<v8::Local<v8::Value>> =
            vec![v8::Integer::new(&*scope, action).into()];
        // `param1`/`param2` are the action's operands; a null one is `null` in
        // JavaScript rather than an empty string, which `test-sqlite-authz.js`
        // distinguishes.
        for pointer in [param1, param2] {
            if pointer.is_null() {
                arguments.push(v8::null(&*scope).into());
            } else {
                let text = errors::c_string(pointer);
                match v8::String::new(&*scope, &text) {
                    Some(text) => arguments.push(text.into()),
                    None => arguments.push(v8::null(&*scope).into()),
                }
            }
        }
        let receiver = v8::undefined(&*scope).into();
        match function.call(&*scope, receiver, &arguments) {
            Some(value) => value.number_value(&*scope).unwrap_or(ffi::SQLITE_OK as f64) as c_int,
            // A throw cannot cross into C; `SQLITE_DENY` fails the statement,
            // which is the safe direction: an exception during authorization
            // must not silently grant access.
            None => ffi::SQLITE_DENY,
        }
    });
    result.unwrap_or(ffi::SQLITE_DENY)
}

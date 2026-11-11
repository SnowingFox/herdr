//! The `Database` class: constructor, prototype methods and accessors.
//!
//! `Initialize` in `src/node_sqlite.cc` registers this surface, and
//! `test-sqlite-database.js` pins it member by member. What is here works; what
//! is not here is listed in [`crate::OMITTED_METHODS`] with the reason, because
//! a method that exists and silently does nothing is worse than one that is
//! absent.
//!
//! The `Symbol.for('sqlite-type')` own property and the `Symbol.dispose` method
//! are both load-bearing: the first is how a `Database` is told from a lookalike
//! (`test-sqlite-database.js` reads it back), the second is what `using db = new
//! Database(...)` calls at block exit.

use std::os::raw::c_int;

use rn_v8_sys::v8;

use crate::constants;
use crate::db::{self, DatabaseState, OpenConfiguration};
use crate::errors;
use crate::stmt;

/// Builds the `Database` constructor.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(construct)
        .length(1)
        .build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(db::INTERNAL_FIELDS);

    // `Symbol.for('sqlite-type')` is a *global* symbol, so every realm's
    // `Symbol.for` call finds this one. Setting it on the instance template
    // makes it own data on each instance, which is what the test reads back.
    if let Some(description) = v8::String::new(scope, "sqlite-type") {
        let symbol = v8::Symbol::for_key(scope, description);
        if let Some(value) = v8::String::new(scope, "node:sqlite") {
            template
                .instance_template(scope)
                .set(symbol.into(), value.into());
        }
    }

    let prototype = template.prototype_template(scope);
    // The full surface `Initialize` installs, in its order. `SetProtoMethod`
    // makes every one non-constructible, which `method` handles.
    let methods: [(&str, i32, v8::Local<'_, v8::FunctionTemplate>); 17] = [
        ("open", 0, method(scope, 0, open)),
        ("close", 0, method(scope, 0, close)),
        ("prepare", 1, method(scope, 1, prepare)),
        ("exec", 1, method(scope, 1, exec)),
        (
            "function",
            2,
            method(scope, 2, crate::sqlfn::register_scalar),
        ),
        (
            "aggregate",
            2,
            method(scope, 2, crate::sqlfn::register_aggregate),
        ),
        ("createTagStore", 0, method(scope, 0, create_tag_store)),
        ("location", 0, method(scope, 0, location)),
        ("createSession", 0, method(scope, 0, crate::session::create)),
        ("applyChangeset", 1, method(scope, 1, apply_changeset)),
        (
            "enableLoadExtension",
            1,
            method(scope, 1, enable_load_extension),
        ),
        ("enableDefensive", 1, method(scope, 1, enable_defensive)),
        ("loadExtension", 1, method(scope, 1, load_extension)),
        ("serialize", 0, method(scope, 0, serialize)),
        ("deserialize", 1, method(scope, 1, deserialize)),
        ("setAuthorizer", 1, method(scope, 1, set_authorizer)),
        ("createModule", 2, method(scope, 2, create_module)),
    ];
    for (name, _length, template) in methods {
        let key = v8::String::new(scope, name).ok_or("cannot allocate a method name")?;
        prototype.set(key.into(), template.into());
    }

    // `SetProtoDispose` installs `Symbol.dispose`, which is what makes
    // `using db = new Database(...)` close the connection at block exit.
    let dispose = v8::FunctionTemplate::builder(dispose)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    if let Some(name) = v8::String::new(scope, "dispose") {
        dispose.set_class_name(name);
    }
    let dispose_key: v8::Local<'_, v8::Name> =
        match v8::Local::<v8::Symbol>::try_from(well_known_dispose(scope)) {
            Ok(symbol) => symbol.into(),
            Err(_) => v8::String::new(scope, "@@dispose")
                .expect("literal allocates")
                .into(),
        };
    prototype.set(dispose_key, dispose.into());

    // `isOpen`, `isTransaction` and `limits` are accessors, which `Initialize`
    // installs with `SetSideEffectFreeGetter`.
    let accessors: [(&str, v8::Local<'_, v8::FunctionTemplate>); 3] = [
        ("isOpen", accessor_template!(scope, is_open)),
        ("isTransaction", accessor_template!(scope, is_transaction)),
        ("limits", accessor_template!(scope, limits)),
    ];
    for (name, getter) in accessors {
        let key = v8::String::new(scope, name).ok_or("cannot allocate an accessor name")?;
        prototype.set_accessor_property(
            key.into(),
            Some(getter),
            None,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        );
    }

    // `set_class_name` has to run before `get_function`: V8 marks the template
    // instantiated at that point, and renaming it afterwards aborts.
    if let Some(name) = v8::String::new(scope, "Database") {
        template.set_class_name(name);
    }
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate the Database constructor")?;
    if let Some(name) = v8::String::new(scope, "Database") {
        function.set_name(name);
    }
    Ok(function.into())
}

/// `Symbol.dispose`, which the V8 Rust bindings do not expose as a well-known.
///
/// `SetProtoDispose` uses `Symbol::GetDispose(isolate)`, and that symbol is
/// reachable from JavaScript as `Symbol.dispose`, so reading it off the global
/// `Symbol` is equivalent. A missing one would install the method under the key
/// `undefined` — the aliasing trap `AGENTS.md` records — so the fallback is a
/// unique symbol rather than `undefined`.
pub fn well_known_dispose<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Value> {
    let global = scope.get_current_context().global(scope);
    if let Some(key) = v8::String::new(scope, "Symbol") {
        if let Some(holder) = global.get(scope, key.into()) {
            if let Ok(holder) = v8::Local::<v8::Object>::try_from(holder) {
                if let Some(key) = v8::String::new(scope, "dispose") {
                    if let Some(dispose) = holder.get(scope, key.into()) {
                        if dispose.is_symbol() {
                            return dispose;
                        }
                    }
                }
            }
        }
    }
    if let Some(description) = v8::String::new(scope, "Symbol.dispose") {
        return v8::Symbol::new(scope, Some(description)).into();
    }
    v8::undefined(scope).into()
}

/// Builds the `FunctionTemplate` for one side-effect-free accessor getter.
///
/// `FunctionTemplate::builder` is generic over the callback through `MapFnTo`,
/// and a bare `fn` item does not satisfy that bound for an accessor callback,
/// so every accessor goes through this one helper with a concrete parameter
/// list. The `READ_ONLY | DONT_DELETE` attributes are what
/// `SetSideEffectFreeGetter` installs.
macro_rules! accessor_template {
    ($scope:expr, $getter:expr) => {
        $crate::database::method($scope, 0, $getter)
    };
}
pub(crate) use accessor_template;

/// One non-constructible method, matching `SetProtoMethod`.
pub fn method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::Local<'s, v8::FunctionTemplate> {
    v8::FunctionTemplate::builder(callback)
        .length(length)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope)
}

/// `new Database(path[, options])`.
fn construct<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    if !args.is_construct_call() {
        errors::throw_coded(
            scope,
            "ERR_CONSTRUCT_CALL_REQUIRED",
            "Class constructor Database cannot be invoked without 'new'",
        );
        return;
    }
    let Some(location) = db::path_argument(scope, args.get(0), "path") else {
        return;
    };
    let mut config = OpenConfiguration::new(location);
    let mut open = true;
    let mut allow_load_extension = false;

    let options = args.get(1);
    if !options.is_undefined() {
        let Ok(options) = v8::Local::<v8::Object>::try_from(options) else {
            errors::throw_type(scope, "The \"options\" argument must be an object.");
            return;
        };
        // The order is `Database::New`'s. Each read can run a getter that
        // observes the options already applied, so the sequence is observable.
        for (name, target) in [
            ("open", &mut open),
            ("readOnly", &mut config.read_only),
            (
                "enableForeignKeyConstraints",
                &mut config.enable_foreign_keys,
            ),
            ("enableDoubleQuotedStringLiterals", &mut config.enable_dqs),
            ("allowExtension", &mut allow_load_extension),
            ("readBigInts", &mut config.use_big_ints),
            ("returnArrays", &mut config.return_arrays),
            (
                "allowBareNamedParameters",
                &mut config.allow_bare_named_params,
            ),
            (
                "allowUnknownNamedParameters",
                &mut config.allow_unknown_named_params,
            ),
            ("defensive", &mut config.defensive),
        ] {
            if !db::optional_bool(scope, options, name, target) {
                return;
            }
        }
        if !read_timeout(scope, options, &mut config) {
            return;
        }
        if !read_limits(scope, options, &mut config) {
            return;
        }
    }

    let mut state = DatabaseState::new(config, allow_load_extension);
    if open {
        if let Err(error) = db::open(&mut state) {
            error.throw(scope);
            return;
        }
    }
    let object = args.this();
    db::install_state(scope, object, state);
    rv.set(object.into());
}

/// Reads `options.timeout`. `IsInt32` is false for a fractional number, so
/// `1.5` is a type error rather than a truncation.
fn read_timeout(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<'_, v8::Object>,
    config: &mut OpenConfiguration,
) -> bool {
    let Some(key) = v8::String::new(scope, "timeout") else {
        return false;
    };
    let Some(value) = options.get(scope, key.into()) else {
        return false;
    };
    if value.is_undefined() {
        return true;
    }
    let Some(number) = value.number_value(scope) else {
        errors::throw_type(
            scope,
            "The \"options.timeout\" argument must be an integer.",
        );
        return false;
    };
    if number.fract() != 0.0 || number < i32::MIN as f64 || number > i32::MAX as f64 {
        errors::throw_type(
            scope,
            "The \"options.timeout\" argument must be an integer.",
        );
        return false;
    }
    config.timeout = number as i32;
    true
}

/// Reads `options.limits`, validating every entry `kLimitMapping` knows.
fn read_limits(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<'_, v8::Object>,
    config: &mut OpenConfiguration,
) -> bool {
    let Some(key) = v8::String::new(scope, "limits") else {
        return false;
    };
    let Some(value) = options.get(scope, key.into()) else {
        return false;
    };
    if value.is_undefined() {
        return true;
    }
    let Ok(limits) = v8::Local::<v8::Object>::try_from(value) else {
        errors::throw_type(scope, "The \"options.limits\" argument must be an object.");
        return false;
    };
    for (index, name) in constants::LIMITS.iter().enumerate() {
        let Some(key) = v8::String::new(scope, name) else {
            return false;
        };
        let Some(entry) = limits.get(scope, key.into()) else {
            return false;
        };
        if entry.is_undefined() {
            continue;
        }
        let integer_message = format!("The \"options.limits.{name}\" argument must be an integer.");
        let Some(number) = entry.number_value(scope) else {
            errors::throw_type(scope, &integer_message);
            return false;
        };
        if number.fract() != 0.0 || number < i32::MIN as f64 || number > i32::MAX as f64 {
            errors::throw_type(scope, &integer_message);
            return false;
        }
        let number = number as i32;
        if number < 0 {
            errors::throw_range(
                scope,
                &format!("The \"options.limits.{name}\" argument must be non-negative."),
            );
            return false;
        }
        config.limits[index] = Some(number);
    }
    true
}

/// The `Database` state of `this`, or a thrown error.
fn this_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Option<*mut DatabaseState> {
    crate::db::state_or_throw(scope, args.this())
}

/// `database.open()`.
fn open<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(state) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`, and nothing below
    // re-enters JavaScript.
    if let Err(error) = db::open(unsafe { &mut *state }) {
        error.throw(scope);
    }
}

/// `database.close()`.
fn close<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(state) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: as above.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    if !errors::require(
        scope,
        state.callback_depth == 0,
        "database cannot be closed while in a callback",
    ) {
        return;
    }
    state.close();
}

/// `database[Symbol.dispose]()`.
///
/// `Dispose` calls `close()` and swallows the exception, so disposing an
/// already-closed database is a no-op rather than a throw: `using` runs it on the
/// way out of a block that may already have closed the connection.
fn dispose<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(state) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: as above.
    let state = unsafe { &mut *state };
    if !state.is_open() || state.callback_depth > 0 {
        return;
    }
    state.close();
}

/// The private property caching the `limits` object, which is `kLimitsObject`'s
/// job in the C++. A private key keeps it out of `Object.keys(db)` and out of
/// `Object.getOwnPropertyNames`.
const LIMITS_CACHE: &str = "rustnode.sqlite.limits";

/// `database.isOpen`.
fn is_open<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(state) = crate::db::state_or_throw(scope, args.this()) else {
        return;
    };
    // SAFETY: reading a flag cannot re-enter JavaScript.
    let open = unsafe { (*state).is_open() };
    rv.set(v8::Boolean::new(scope, open).into());
}

/// `database.isTransaction`.
fn is_transaction<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(state) = crate::db::state_or_throw(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer; nothing below re-enters
    // JavaScript.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    let in_transaction = state.is_transaction();
    rv.set(v8::Boolean::new(scope, in_transaction).into());
}

/// `database.limits`: the cached limits object.
///
/// `DatabaseLimits` is an object whose every property is an intercepted
/// getter/setter pair reading and writing `sqlite3_limit`, and the object is
/// cached in an internal field so `db.limits === db.limits`. This builds the
/// equivalent directly: one accessor pair per `kLimitMapping` entry, each
/// carrying the limit's index and reaching the connection through the object's
/// own stored state.
fn limits<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let this = args.this();
    if crate::db::state_or_throw(scope, this).is_none() {
        return;
    }
    // SAFETY: the field belongs to this object's template.
    let cache_key = v8::String::new(scope, LIMITS_CACHE).expect("literal allocates");
    let cache = v8::Private::for_api(scope, Some(cache_key));
    // A `Private` that was never set reads as `None`, but one set to
    // `undefined` reads as `Some(undefined)`. Checking the value rather than
    // only the presence is what keeps the first read from caching nothing and
    // every later read from returning it.
    if let Some(existing) = this.get_private(scope, cache) {
        if !existing.is_undefined() {
            rv.set(existing);
            return;
        }
    }
    let Some(object) = crate::limits::build(scope, this) else {
        // A `None` here means an allocation failed; report it rather than
        // leaving `db.limits` as `undefined`, which every caller then reads as
        // "no limits" and reports as a missing property much later.
        errors::throw_coded(
            scope,
            "ERR_INTERNAL_ASSERTION",
            "could not build the database limits object",
        );
        return;
    };
    this.set_private(scope, cache, object.into());
    rv.set(object.into());
}

/// `database.prepare(sql[, options])`.
fn prepare<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let this = args.this();
    let Some(state) = crate::db::state_or_throw(scope, this) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`. The borrow ends
    // before `sql_argument`, which can throw.
    let (open, authorizer, return_arrays, int_mode, allow_bare, allow_unknown) = unsafe {
        let state = &*state;
        (
            state.is_open(),
            state.authorizer_depth,
            state.config.return_arrays,
            state.config.int_mode(),
            state.config.allow_bare_named_params,
            state.config.allow_unknown_named_params,
        )
    };
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
    let Some(sql) = db::sql_argument(scope, args.get(0)) else {
        return;
    };
    let mut options = stmt::StatementOptions {
        return_arrays,
        int_mode,
        allow_bare_named_params: allow_bare,
        allow_unknown_named_params: allow_unknown,
        persistent: false,
    };
    if !stmt::read_options(scope, args.get(1), &mut options) {
        return;
    }
    // SAFETY: `state_of` returned a live pointer for `this`. Nothing between
    // here and `prepare` re-enters JavaScript.
    let state = unsafe { &mut *state };
    let Some(raw) = stmt::prepare(scope, state, &sql, options.persistent) else {
        return;
    };
    let Some(statement) = stmt::create(scope, raw, state, this, &options) else {
        // `create` failed after the handle was prepared, so the handle would
        // otherwise leak.
        // SAFETY: `raw` is a live statement nothing else owns.
        unsafe { crate::ffi::sqlite3_finalize(raw) };
        return;
    };
    rv.set(statement);
}

/// `database.exec(sql)`.
fn exec<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(state) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    if !errors::require(
        scope,
        state.authorizer_depth == 0,
        "database cannot be accessed from an authorizer callback",
    ) {
        return;
    }
    let Some(sql) = db::sql_argument(scope, args.get(0)) else {
        return;
    };
    db::exec_sql(scope, state, &sql);
}

/// `database.location([dbName])`.
fn location<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(state) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    let mut name = "main".to_string();
    let argument = args.get(0);
    if !argument.is_undefined() {
        let Ok(text) = v8::Local::<v8::String>::try_from(argument) else {
            errors::throw_type(scope, "The \"dbName\" argument must be a string.");
            return;
        };
        name = text.to_rust_string_lossy(scope);
    }
    let Ok(name) = std::ffi::CString::new(name) else {
        errors::throw_type(scope, "The \"dbName\" argument must be a string.");
        return;
    };
    let Some(raw) = crate::db::open_handle(scope, state) else {
        return;
    };
    // SAFETY: `raw` is open and `name` outlives the call. The result is a
    // borrowed string SQLite owns, or null for an in-memory database.
    let pointer = unsafe { crate::ffi::sqlite3_db_filename(raw, name.as_ptr()) };
    if pointer.is_null() {
        rv.set(v8::null(scope).into());
        return;
    }
    // SAFETY: SQLite owns a NUL-terminated path here.
    let path = unsafe { errors::c_string(pointer) };
    match v8::String::new(scope, &path) {
        Some(text) if !path.is_empty() => rv.set(text.into()),
        _ => rv.set(v8::null(scope).into()),
    }
}

/// `database.enableDefensive(active)`.
fn enable_defensive<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(state) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    let value = args.get(0);
    if !value.is_boolean() {
        errors::throw_type(scope, "The \"active\" argument must be a boolean.");
        return;
    }
    let active = value.boolean_value(scope);
    let Some(raw) = crate::db::open_handle(scope, state) else {
        return;
    };
    let mut enabled: c_int = 0;
    // SAFETY: `raw` is open; `db_config` writes the out-parameter.
    let code = unsafe {
        crate::ffi::sqlite3_db_config(
            raw,
            crate::ffi::SQLITE_DBCONFIG_DEFENSIVE,
            i32::from(active),
            &mut enabled,
        )
    };
    if code != crate::ffi::SQLITE_OK {
        errors::throw_sqlite(scope, raw);
        return;
    }
    state.config.defensive = active;
}

/// `database.enableLoadExtension(allow)`.
fn enable_load_extension<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(state) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    let value = args.get(0);
    if !value.is_boolean() {
        errors::throw_type(scope, "The \"allow\" argument must be a boolean.");
        return;
    }
    let allow = value.boolean_value(scope);
    if allow && crate::permission::enabled() {
        // Extension loading is arbitrary code execution, so the permission model
        // refuses it. Node checks `permission()->enabled()` in both `Open` and
        // `LoadExtension`.
        errors::throw_coded(
            scope,
            "ERR_LOAD_SQLITE_EXTENSION",
            "Cannot load SQLite extensions when the permission model is enabled.",
        );
        return;
    }
    let Some(raw) = crate::db::open_handle(scope, state) else {
        return;
    };
    // SAFETY: `raw` is open; enabling takes no out-parameter.
    let code = unsafe {
        crate::ffi::sqlite3_db_config(
            raw,
            crate::ffi::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
            i32::from(allow),
            std::ptr::null_mut::<c_int>(),
        )
    };
    if code != crate::ffi::SQLITE_OK {
        errors::throw_sqlite(scope, raw);
        return;
    }
    state.allow_load_extension = allow;
}

/// `database.createTagStore([maxSize])`.
fn create_tag_store<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`. The borrow ends at
    // this expression so the reads below can throw without aliasing it.
    let open = unsafe { (*pointer).is_open() };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    let mut capacity = 1000i32;
    let argument = args.get(0);
    if !argument.is_undefined() {
        let message = "The \"maxSize\" argument must be a positive integer.";
        if !argument.is_number() {
            // `CreateTagStore` uses `THROW_ERR_INVALID_ARG_TYPE` for a
            // non-number and `THROW_ERR_OUT_OF_RANGE` for a number it cannot
            // accept, and the test distinguishes the two codes.
            errors::throw_type(scope, message);
            return;
        }
        let number = argument.number_value(scope).unwrap_or(0.0);
        if number.fract() != 0.0 || number <= 0.0 || number > i32::MAX as f64 {
            // `THROW_ERR_OUT_OF_RANGE`, which carries `code` unlike the plain
            // `RangeError` that `throw_range` builds.
            errors::throw_coded(scope, "ERR_OUT_OF_RANGE", message);
            return;
        }
        capacity = number as i32;
    }
    // SAFETY: as above.
    let state = unsafe { &mut *pointer };
    match crate::tagstore::create(scope, state, args.this(), capacity) {
        Some(object) => rv.set(object.into()),
        None => errors::throw_sqlite_message(scope, "Failed to create SQLTagStore", "", 0),
    }
}

/// `database.loadExtension(path[, entryPoint])`.
///
/// Extension loading is deliberately absent and declared in `DEFERRED`: the
/// entry point signature can invoke arbitrary native code, and the acceptance
/// surface for this namespace does not include it. `enableLoadExtension` above
/// still toggles SQLite's own flag so the option plumbing is exercised.
fn load_extension<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    errors::throw_coded(
        scope,
        "ERR_METHOD_NOT_IMPLEMENTED",
        "database.loadExtension is not implemented in rustnode yet",
    );
}

/// `database.serialize([dbName])`.
///
/// `Database::Serialize` copies the database image with `sqlite3_serialize`,
/// which allocates the buffer this has to free once the bytes are in a
/// `Uint8Array`. An empty database serializes to a zero-length buffer rather
/// than failing, which `test-sqlite-serialize.js` asserts.
fn serialize<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(pointer) = this_state(scope, &args) else {
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
    let mut name = "main".to_string();
    let argument = args.get(0);
    if !argument.is_undefined() {
        let Ok(text) = v8::Local::<v8::String>::try_from(argument) else {
            errors::throw_type(scope, "The \"dbName\" argument must be a string.");
            return;
        };
        name = text.to_rust_string_lossy(scope);
    }
    let Ok(name) = std::ffi::CString::new(name) else {
        errors::throw_type(scope, "The \"dbName\" argument must be a string.");
        return;
    };
    // SAFETY: the pointer is still live; `this` is an argument of this call.
    let raw = unsafe { (*pointer).raw() };
    let mut size: i64 = 0;
    // SAFETY: `raw` is open and `name` outlives the call; the buffer returned is
    // owned by the caller and freed below with `sqlite3_free`.
    let data = unsafe { crate::ffi::sqlite3_serialize(raw, name.as_ptr(), &mut size, 0) };
    if data.is_null() {
        if size == 0 {
            // No allocation happened, so there is nothing to free and the image
            // is legitimately empty.
            if let Some(array) = crate::value::uint8_array(scope, &[]) {
                rv.set(array.into());
            }
            return;
        }
        errors::throw_sqlite(scope, raw);
        return;
    }
    let length = size.max(0) as usize;
    // SAFETY: SQLite allocated `length` bytes at `data`.
    let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, length) };
    let array = crate::value::uint8_array(scope, bytes);
    // SAFETY: `sqlite3_serialize` hands ownership of the buffer to the caller.
    unsafe { crate::ffi::sqlite3_free(data as *mut std::os::raw::c_void) };
    if let Some(array) = array {
        rv.set(array.into());
    }
}

/// `database.deserialize(buffer[, options])`.
///
/// `sqlite3_deserialize` takes ownership of the buffer it is given and may free
/// it, so the bytes cannot be borrowed from the `Uint8Array`'s backing store:
/// they are copied into a `sqlite3_malloc64` allocation first.
fn deserialize<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_or_throw` returned a live pointer for `this`.
    let (open, callback_depth, statements) = unsafe {
        (
            (*pointer).is_open(),
            (*pointer).callback_depth,
            (*pointer).statements.len(),
        )
    };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    if !errors::require(
        scope,
        callback_depth == 0,
        "database cannot be deserialized while in a callback",
    ) {
        return;
    }
    if !errors::require(scope, statements == 0, "database has open statements") {
        return;
    }
    // The bytes are captured *after* the options bag is read, not before.
    // `dbName` is a property getter, and a getter can call `buffer.resize(...)`
    // or `structuredClone(buffer, { transfer })` on the very view it was handed,
    // which detaches the backing store. A pointer taken before that point is
    // then dangling, and copying from it is the use-after-free
    // `test-sqlite-options-getter-reentry.js` calls "throws rather than handing
    // uninitialized memory to SQLite".
    let mut name = "main".to_string();
    let options = args.get(1);
    if !options.is_undefined() {
        let Ok(options) = v8::Local::<v8::Object>::try_from(options) else {
            errors::throw_type(scope, "The \"options\" argument must be an object.");
            return;
        };
        // The view's identity is checked after the read, so a getter that
        // detached it is caught rather than dereferenced.
        if !crate::db::optional_string(scope, options, "dbName", &mut name) {
            return;
        }
    }
    let Some((bytes, length)) = crate::value::view_snapshot(scope, args.get(0)) else {
        return;
    };
    let Ok(name) = std::ffi::CString::new(name) else {
        errors::throw_type(scope, "The \"dbName\" option must not contain null bytes.");
        return;
    };
    // The copy happens here, after every getter has run, so `bytes` cannot have
    // been detached between being read and being copied.
    // SAFETY: `sqlite3_malloc64` may return null; the empty case needs no
    // allocation because `sqlite3_deserialize` accepts a zero-length image.
    let buffer = unsafe { crate::ffi::sqlite3_malloc64(length as u64) } as *mut u8;
    if length > 0 {
        if buffer.is_null() {
            errors::throw_coded(
                scope,
                "ERR_MEMORY_ALLOCATION_FAILED",
                "Failed to allocate memory for database deserialization",
            );
            return;
        }
        // SAFETY: `buffer` is an allocation of `length` bytes and `bytes` does
        // not overlap it.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, length) };
    }
    // SAFETY: the pointer is still live; `this` is an argument of this call.
    let Some(raw) = crate::db::open_handle(scope, unsafe { &*pointer }) else {
        // The options getter closed the database; free the allocation rather
        // than handing it to a connection that no longer exists.
        if !buffer.is_null() {
            unsafe { crate::ffi::sqlite3_free(buffer as *mut std::os::raw::c_void) };
        }
        return;
    };
    // SAFETY: `raw` is open. SQLite takes ownership of `buffer` on success and
    // frees it on failure, which is what `FREEONCLOSE` declares.
    let code = unsafe {
        crate::ffi::sqlite3_deserialize(
            raw,
            name.as_ptr(),
            buffer,
            length as i64,
            length as i64,
            crate::ffi::SQLITE_DESERIALIZE_FREEONCLOSE | crate::ffi::SQLITE_DESERIALIZE_RESIZEABLE,
        )
    };
    if code != crate::ffi::SQLITE_OK {
        errors::throw_sqlite(scope, raw);
    }
}

/// `database.setAuthorizer(callback)`.
fn set_authorizer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(pointer) = this_state(scope, &args) else {
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
    // SAFETY: as above; the borrow ends before the callback is installed.
    let database = unsafe { &mut *pointer };
    crate::sqlfn::install_authorizer(scope, database, &args);
}

/// `database.createModule(name, options)`: a virtual table backed by JavaScript.
///
/// Not implemented, and declared in the contract as such. A virtual table needs
/// `sqlite3_module`'s nine callbacks plus the hidden-column and `idxNum` protocol
/// from `src/node_sqlite.cc`, and every one of them re-enters V8 from inside
/// SQLite's own query planner. Shipping a partial module would produce answers
/// that disagree with Node's for exactly the queries a virtual table exists to
/// serve, so this throws instead.
fn create_module(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    errors::throw_coded(
        scope,
        "ERR_METHOD_NOT_IMPLEMENTED",
        "database.createModule is not implemented in rustnode yet",
    );
}

/// `database.applyChangeset(changeset[, options])`.
///
/// Not implemented, and declared in the contract as such. Applying a changeset
/// needs the conflict-resolution callback table and the filter callbacks from
/// `Database::ApplyChangeset`; without them a conflicting changeset would have to
/// either abort or silently overwrite, and both answer differently from Node.
fn apply_changeset(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    errors::throw_coded(
        scope,
        "ERR_METHOD_NOT_IMPLEMENTED",
        "database.applyChangeset is not implemented in rustnode yet",
    );
}

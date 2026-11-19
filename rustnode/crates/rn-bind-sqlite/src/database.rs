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
    // Node: `NewFunctionTemplate` + `SetConstructorFunction`, i.e. length 0.
    let template = rn_core::class(construct).build(scope);
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
    let methods: [(&str, v8::Local<'_, v8::FunctionTemplate>); 17] = [
        ("open", method(scope, open)),
        ("close", method(scope, close)),
        ("prepare", method(scope, prepare)),
        ("exec", method(scope, exec)),
        ("function", method(scope, crate::sqlfn::register_scalar)),
        ("createTagStore", method(scope, create_tag_store)),
        ("location", method(scope, location)),
        ("aggregate", method(scope, crate::sqlfn::register_aggregate)),
        ("createSession", method(scope, crate::session::create)),
        ("applyChangeset", method(scope, apply_changeset)),
        ("enableLoadExtension", method(scope, enable_load_extension)),
        ("enableDefensive", method(scope, enable_defensive)),
        ("loadExtension", method(scope, load_extension)),
        ("serialize", method(scope, serialize)),
        ("deserialize", method(scope, deserialize)),
        ("setAuthorizer", method(scope, set_authorizer)),
        ("createModule", method(scope, create_module)),
    ];
    for (name, template) in methods {
        let key = v8::String::new(scope, name).ok_or("cannot allocate a method name")?;
        prototype.set(key.into(), template.into());
    }

    // `SetProtoDispose` installs `Symbol.dispose`, which is what makes
    // `using db = new Database(...)` close the connection at block exit.
    let dispose = rn_core::class(dispose).build(scope);
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

    // `isOpen`, `isTransaction` and `limits` are instance-template accessors,
    // not prototype ones; `side_effect_free_getter` records why that distinction
    // is observable.
    side_effect_free_getter(scope, template, "isOpen", is_open)
        .ok_or("cannot install the isOpen accessor")?;
    side_effect_free_getter(scope, template, "isTransaction", is_transaction)
        .ok_or("cannot install the isTransaction accessor")?;
    side_effect_free_getter(scope, template, "limits", limits)
        .ok_or("cannot install the limits accessor")?;

    // `set_class_name` has to run before `get_function`: V8 marks the template
    // instantiated at that point, and renaming it afterwards aborts.
    if let Some(name) = v8::String::new(scope, "Database") {
        template.set_class_name(name);
    }
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate the Database constructor")?;
    // `SetConstructorFunction` leaves `prototype.constructor` pointing at the
    // class, which is what makes `db.constructor === Database` true. A template's
    // prototype object has no `constructor` until it is set.
    link_constructor(scope, &template, function, "Database");
    Ok(function.into())
}

/// Sets `prototype.constructor` back to the class function.
///
/// V8 materializes `prototype` as a plain object; `SetConstructorFunction` is
/// what Node's `Initialize` gets for free and what a bare `get_function` does
/// not do. Without it `Object.getOwnPropertyNames(Database.prototype)` has no
/// `constructor` entry and `db.constructor` reads `Object`.
pub(crate) fn link_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    template: &v8::Local<'_, v8::FunctionTemplate>,
    function: v8::Local<'_, v8::Function>,
    class_name: &str,
) {
    let Some(prototype) = template.prototype_template(scope).new_instance(scope) else {
        return;
    };
    let _ = link_constructor_on(scope, prototype, function, class_name);
}

/// [`link_constructor`] against a prototype object the caller already holds.
///
/// Needed where the instance's prototype is not the template's default one —
/// `StatementIterator` attaches the global `Iterator.prototype` to its own
/// intermediary, so that object is the one `constructor` belongs on.
pub(crate) fn link_constructor_on(
    scope: &mut v8::PinScope<'_, '_>,
    prototype: v8::Local<'_, v8::Object>,
    function: v8::Local<'_, v8::Function>,
    class_name: &str,
) -> Option<()> {
    let key = v8::String::new(scope, "constructor")?;
    prototype.set(scope, key.into(), function.into())?;
    if let Some(name) = v8::String::new(scope, class_name) {
        function.set_name(name);
    }
    Some(())
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

/// Installs one `SetSideEffectFreeGetter` accessor on a class.
///
/// `node_sqlite.cc` puts these on the *instance* template, not the prototype:
///
/// ```cpp
/// static inline void SetSideEffectFreeGetter(
///     Isolate* isolate, Local<FunctionTemplate> class_template, Local<String> name,
///     FunctionCallback fn) {
///   Local<FunctionTemplate> getter = FunctionTemplate::New(
///       isolate, fn, Local<Value>(), v8::Signature::New(isolate, class_template),
///       /* length */ 0, ConstructorBehavior::kThrow, SideEffectType::kHasNoSideEffect);
///   class_template->InstanceTemplate()->SetAccessorProperty(
///       name, getter, Local<FunctionTemplate>(), DontDelete);
/// }
/// ```
///
/// The difference from the prototype is observable and Node's own tests read it:
/// `Object.keys(db)` is `['isOpen', 'isTransaction', 'limits']` and
/// `Object.getOwnPropertyDescriptor(db, 'limits').get` is a function. On the
/// prototype all three of those are `[]`, and the property is reachable only
/// through the chain.
///
/// Three details are load-bearing:
///
/// * `DontDelete` only — no `DontEnum` and no `ReadOnly`. That produces
///   `enumerable: true, configurable: false` and a `get` with no `set`, which is
///   the descriptor Node reports.
/// * The `Signature` binds the getter to this class, so a borrowed receiver such
///   as `descriptor.get.call({})` throws `TypeError: Illegal invocation` instead
///   of running the body against the wrong object.
/// * `HasNoSideEffect`, which is what lets V8 run the getter in a context that
///   has forbidden side effects.
pub(crate) fn side_effect_free_getter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    class_template: v8::Local<'s, v8::FunctionTemplate>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Option<()> {
    let signature = v8::Signature::new(scope, class_template);
    // `rn_core::method` already passes `ConstructorBehavior::Throw`, which is
    // what `SetSideEffectFreeGetter` asks for; naming it here keeps the crate on
    // the one chokepoint #121 introduced instead of repeating the builder call.
    let getter = rn_core::method(callback)
        .signature(signature)
        .side_effect_type(v8::SideEffectType::HasNoSideEffect)
        .build(scope);
    let key = v8::String::new(scope, name)?;
    class_template
        .instance_template(scope)
        .set_accessor_property(
            key.into(),
            Some(getter),
            None,
            v8::PropertyAttribute::DONT_DELETE,
        );
    Some(())
}

/// One non-constructible method, matching `SetProtoMethod`.
///
/// No arity parameter: `SetProtoMethod` builds through `NewFunctionTemplate`,
/// so every method here reports `length` 0 on Node however many arguments the
/// JavaScript layer passes.
pub fn method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::Local<'s, v8::FunctionTemplate> {
    rn_core::method(callback).build(scope)
}

/// `new Database(path[, options])`.
fn construct<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    if !args.is_construct_call() {
        // `THROW_ERR_CONSTRUCT_CALL_REQUIRED`, which is a `TypeError` in
        // `internal/errors`. The message and code were already right; the class
        // was not.
        errors::throw_construct_call_required(scope);
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
    let (open, callback_depth) = unsafe { ((*pointer).is_open(), (*pointer).callback_depth) };
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
    // `Database::Deserialize` does not reject a connection that still has
    // statements open: it finalizes them, which is what
    // `test-sqlite-serialize.js` asserts by reading a statement after the
    // replacement and expecting "statement has been finalized". Refusing instead
    // would also make the operation impossible for any database prepared past
    // its first query.
    //
    // The view and its length are read *before* the options bag, exactly as the
    // C++ does, and the copy afterwards reports how many bytes it really moved.
    // That pair is the only way to notice a getter that resized or detached the
    // backing store: a length read after the getter would agree with the copy and
    // the mismatch would be invisible, which is the use-after-free
    // `test-sqlite-options-getter-reentry.js` calls "throws rather than handing
    // uninitialized memory to SQLite".
    let Ok(input) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(0)) else {
        errors::throw_type(scope, "The \"buffer\" argument must be a Uint8Array.");
        return;
    };
    let length = input.byte_length();
    if length == 0 {
        errors::throw_coded(
            scope,
            "ERR_INVALID_ARG_VALUE",
            "The \"buffer\" argument must not be empty.",
        );
        return;
    }
    let mut name = "main".to_string();
    let options = args.get(1);
    if !options.is_undefined() {
        let Ok(options) = v8::Local::<v8::Object>::try_from(options) else {
            errors::throw_type(scope, "The \"options\" argument must be an object.");
            return;
        };
        if !crate::db::optional_string(scope, options, "dbName", &mut name) {
            return;
        }
    }
    // Reading the options bag above can run user JavaScript through a property
    // getter, which may have closed the database since it was checked.
    // SAFETY: the pointer is still live; `this` is an argument of this call.
    let Some(raw) = crate::db::open_handle(scope, unsafe { &*pointer }) else {
        return;
    };
    let Ok(name) = std::ffi::CString::new(name) else {
        errors::throw_type(scope, "The \"dbName\" option must not contain null bytes.");
        return;
    };

    // SAFETY: `sqlite3_malloc64` may return null, which is reported below.
    let buffer = unsafe { crate::ffi::sqlite3_malloc64(length as u64) } as *mut u8;
    if buffer.is_null() {
        errors::throw_coded(
            scope,
            "ERR_MEMORY_ALLOCATION_FAILED",
            "Failed to allocate memory for database deserialization",
        );
        return;
    }
    // SAFETY: `buffer` is an allocation of `length` bytes, so the destination
    // slice is exactly the region V8 may write to.
    let destination = unsafe { std::slice::from_raw_parts_mut(buffer, length) };
    let copied = input.copy_contents(destination);
    if copied != length {
        // The getter shrank, grew or detached the store, so `buffer` would be
        // partly uninitialized. Handing that to SQLite would disclose it through
        // `serialize()`, so it is freed and reported instead.
        // SAFETY: `buffer` is the allocation just made above and nothing else
        // owns it yet.
        unsafe { crate::ffi::sqlite3_free(buffer as *mut std::os::raw::c_void) };
        errors::throw_coded(
            scope,
            "ERR_INVALID_STATE",
            "The \"buffer\" argument was resized while reading \"options\"",
        );
        return;
    }

    // `FinalizeStatements()` runs here, after every getter, so a statement the
    // getter created is cleaned up too and the read above is not stale.
    // SAFETY: the pointer is live; the registry holds statements that root this
    // database object, so none has been dropped.
    unsafe {
        let state = &mut *pointer;
        for statement in std::mem::take(&mut state.statements) {
            crate::stmt::finalize_from_database(statement);
        }
    }
    // SAFETY: `raw` is open. SQLite takes ownership of `buffer` and frees it with
    // `sqlite3_free` when the connection closes, which is what `FREEONCLOSE`
    // declares.
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
///
/// The checks before the throw are `CreateModule`'s, in its order: a closed
/// connection and an authorizer context are reported before the arguments are
/// looked at, so a caller inside an options getter sees `ERR_INVALID_STATE`
/// rather than a missing-feature error from a call that could never have worked.
fn create_module<'s>(
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
    // `CreateModule` validates before it reads `options.columns`, and the column
    // loop reads one property per column. Those reads are load-bearing even
    // though the module is never installed: a getter there is how a caller
    // closes the database, and the second open check below is what reports it.
    if !args.get(0).is_string() {
        errors::throw_type(scope, "The \"name\" argument must be a string.");
        return;
    }
    let Ok(options) = v8::Local::<v8::Object>::try_from(args.get(1)) else {
        errors::throw_type(scope, "The \"options\" argument must be an object.");
        return;
    };
    if !read_create_module_options(scope, options) {
        return;
    }
    // SAFETY: the pointer is still live; `this` is an argument of this call.
    let open = unsafe { (*pointer).is_open() };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    errors::throw_coded(
        scope,
        "ERR_METHOD_NOT_IMPLEMENTED",
        "database.createModule is not implemented in rustnode yet",
    );
}

/// Reads the `createModule` options bag far enough to run every getter
/// `CreateModule` runs, and to report the same argument errors.
///
/// Returns `false` when a check failed and an exception is pending.
fn read_create_module_options(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<'_, v8::Object>,
) -> bool {
    let get = |name: &str| -> Option<v8::Local<'_, v8::Value>> {
        let key = v8::String::new(scope, name)?;
        options.get(scope, key.into())
    };
    let Some(columns) = get("columns") else {
        return false;
    };
    let Ok(columns) = v8::Local::<v8::Array>::try_from(columns) else {
        errors::throw_type(scope, "The \"options.columns\" argument must be an array.");
        return false;
    };
    let count = columns.length();
    if count == 0 {
        errors::throw_coded(
            scope,
            "ERR_INVALID_ARG_VALUE",
            "The \"options.columns\" array must not be empty.",
        );
        return false;
    }
    let Some(rows) = get("rows") else {
        return false;
    };
    if !rows.is_function() {
        errors::throw_type(scope, "The \"options.rows\" argument must be a function.");
        return false;
    }
    for name in ["directOnly", "useBigIntArguments"] {
        let mut enabled = false;
        if !db::optional_bool(scope, options, name, &mut enabled) {
            return false;
        }
    }
    for index in 0..count {
        let Some(column) = columns.get_index(scope, index) else {
            return false;
        };
        let Ok(column) = v8::Local::<v8::Object>::try_from(column) else {
            errors::throw_type(
                scope,
                "Each column in \"options.columns\" must be an object.",
            );
            return false;
        };
        let keyed = |name: &str| -> Option<v8::Local<'_, v8::Value>> {
            let key = v8::String::new(scope, name)?;
            column.get(scope, key.into())
        };
        let Some(name) = keyed("name") else {
            return false;
        };
        if !name.is_string() {
            errors::throw_type(scope, "The column \"name\" property must be a string.");
            return false;
        }
        let Some(kind) = keyed("type") else {
            return false;
        };
        if !kind.is_string() {
            errors::throw_type(scope, "The column \"type\" property must be a string.");
            return false;
        }
        let mut hidden = false;
        if !db::optional_bool(scope, column, "hidden", &mut hidden) {
            return false;
        }
        let kind = kind.to_rust_string_lossy(scope);
        if !matches!(kind.as_str(), "INTEGER" | "TEXT" | "REAL" | "BLOB" | "ANY") {
            errors::throw_coded(
                scope,
                "ERR_INVALID_ARG_VALUE",
                "The column \"type\" property must be one of 'INTEGER', 'TEXT', \
                 'REAL', 'BLOB', or 'ANY'.",
            );
            return false;
        }
    }
    true
}

/// `database.applyChangeset(changeset[, options])`.
///
/// Not implemented, and declared in the contract as such. Applying a changeset
/// needs the conflict-resolution callback table and the filter callbacks from
/// `Database::ApplyChangeset`; without them a conflicting changeset would have to
/// either abort or silently overwrite, and both answer differently from Node.
///
/// As with [`create_module`], the state checks run first so the reason reported
/// for a doomed call is the state rather than the missing feature.
fn apply_changeset<'s>(
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
    // `ApplyChangeset` reads the changeset and then the options bag's
    // `onConflict` and `filter` getters. Running them is what lets a getter close
    // the database, which the second open check reports.
    if !args.get(0).is_uint8_array() {
        errors::throw_type(scope, "The \"changeset\" argument must be a Uint8Array.");
        return;
    }
    let options = args.get(1);
    if args.length() > 1 && !options.is_undefined() {
        let Ok(options) = v8::Local::<v8::Object>::try_from(options) else {
            errors::throw_type(scope, "The \"options\" argument must be an object.");
            return;
        };
        let mut on_conflict = None;
        if !read_optional_callable(scope, options, "onConflict", &mut on_conflict) {
            return;
        }
        // `HasOwnProperty` first, so an inherited `filter` is not read at all.
        let Some(key) = v8::String::new(scope, "filter") else {
            return;
        };
        let Some(has_filter) = options.has_own_property(scope, key.into()) else {
            return;
        };
        if has_filter {
            let mut filter = None;
            if !read_optional_callable(scope, options, "filter", &mut filter) {
                return;
            }
        }
    }
    // SAFETY: the pointer is still live; `this` is an argument of this call.
    let open = unsafe { (*pointer).is_open() };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    errors::throw_coded(
        scope,
        "ERR_METHOD_NOT_IMPLEMENTED",
        "database.applyChangeset is not implemented in rustnode yet",
    );
}

/// Reads an optional option that must be a function when it is present.
///
/// Returns `false` when an exception is pending.
fn read_optional_callable<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    options: v8::Local<'s, v8::Object>,
    name: &str,
    target: &mut Option<v8::Local<'s, v8::Function>>,
) -> bool {
    let Some(key) = v8::String::new(scope, name) else {
        return false;
    };
    let Some(value) = options.get(scope, key.into()) else {
        return false;
    };
    if value.is_undefined() {
        return true;
    }
    match v8::Local::<v8::Function>::try_from(value) {
        Ok(function) => {
            *target = Some(function);
            true
        }
        Err(_) => {
            errors::throw_type(
                scope,
                &format!("The \"options.{name}\" argument must be a function."),
            );
            false
        }
    }
}

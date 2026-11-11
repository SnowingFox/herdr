//! The `SQLTagStore` a `createTagStore()` call returns.
//!
//! `SQLTagStore` in `src/node_sqlite.cc` is a small LRU of prepared statements
//! keyed by the SQL text a template literal produced. `sql.run\`INSERT ...\``
//! interpolates a `?` per substitution, prepares once, and caches the result, so
//! a loop that runs the same tagged statement reuses one prepared statement
//! instead of re-preparing per iteration. `clear()` empties the cache.
//!
//! # Why this reuses `StatementState`
//!
//! `PrepareStatement` builds a real `Statement` and hands it to the same
//! `ResetAndBindStatement` / `StatementExecutionHelper::Run` pair the public
//! methods use. The cache therefore holds live statements, which is why
//! `clear()` may free them safely and why a finalized entry is evicted rather
//! than reused: a statement closed by `db.close()` cannot be stepped.
//!
//! The statements here are *not* JS-visible objects. They are Rust
//! `StatementState` boxes owned by the store, freed by `clear()` or the store's
//! finalizer, so they never appear in `db.prepare`'s registry — a `db.close()`
//! would otherwise finalize them and leave the cache holding dead handles.

use std::collections::HashMap;
use std::os::raw::c_void;

use rn_v8_sys::v8;

use crate::db::DatabaseState;
use crate::errors;
use crate::ffi;
use crate::stmt::{self, StatementOptions, StatementState};

/// The internal field holding a tag store's boxed state.
pub const STATE_FIELD: i32 = 0;
/// How many internal fields a tag store instance has.
pub const INTERNAL_FIELDS: usize = 2;
/// The second field holds the rooted `Database` object, which is what keeps the
/// connection alive while the store exists — `kDatabaseObject`'s job.
pub const DATABASE_FIELD: i32 = 1;

/// One cached statement and the order it was last used in.
struct Entry {
    /// The prepared statement, owned by this store.
    statement: Box<StatementState>,
    /// The tick the entry was last used, for the LRU eviction.
    used: u64,
}

/// Everything one tag store owns.
pub struct TagStoreState {
    /// The connection, kept valid by the rooted database object.
    pub database: *mut DatabaseState,
    /// The rooted `Database` object.
    pub database_object: v8::Global<v8::Object>,
    /// Cached statements keyed by SQL text.
    entries: HashMap<String, Entry>,
    /// How many entries are kept, from `createTagStore(maxSize)`.
    capacity: usize,
    /// A monotonic use counter, so eviction does not need timestamps.
    tick: u64,
    /// The configuration the cached statements inherit.
    options: StatementOptions,
}

impl TagStoreState {
    /// Runs `body` with the database state.
    fn with_database<R>(&mut self, body: impl FnOnce(&mut DatabaseState) -> R) -> Option<R> {
        if self.database.is_null() {
            return None;
        }
        // SAFETY: `database_object` roots the `Database` object, whose boxed
        // state this pointer is, so the allocation outlives the store.
        Some(body(unsafe { &mut *self.database }))
    }

    /// Drops every cached statement.
    fn clear(&mut self) {
        for (_, entry) in self.entries.drain() {
            let mut statement = entry.statement;
            if !statement.raw.is_null() {
                // SAFETY: `raw` is a live statement this store owns.
                unsafe { ffi::sqlite3_finalize(statement.raw) };
                statement.raw = std::ptr::null_mut();
            }
        }
    }

    /// Prepares or reuses the statement for `sql`, returning a raw pointer.
    ///
    /// A raw pointer rather than a reference: the cache is a `HashMap`, and the
    /// caller only ever uses the statement inside one method call, so the
    /// borrow would otherwise have to be threaded through the whole chain for no
    /// benefit. The pointer stays valid until `clear()`, `close()` or this
    /// store's finalizer, none of which can run during the call that uses it.
    fn statement_for(&mut self, sql: &str) -> Option<*mut StatementState> {
        self.tick += 1;
        let tick = self.tick;
        let capacity = self.capacity;

        // A finalized entry cannot be stepped, so it is evicted rather than
        // reused; `PrepareStatement` does the same.
        if let Some(entry) = self.entries.get_mut(sql) {
            if entry.statement.is_live() {
                entry.used = tick;
                return Some(&mut *entry.statement as *mut StatementState);
            }
            self.entries.remove(sql);
        }

        let raw = self.prepare(sql)?;
        let database = self.database;
        let options = self.options;
        let statement = StatementState::new(
            raw,
            database,
            // `None`: this store's own `database_object` roots the connection,
            // so the cached statement must not root it a second time.
            None,
            options.return_arrays,
            options.int_mode,
            options.allow_bare_named_params,
            options.allow_unknown_named_params,
        );
        if self.entries.len() >= capacity {
            // Evict the least recently used entry.
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                if let Some(mut entry) = self.entries.remove(&oldest) {
                    if !entry.statement.raw.is_null() {
                        // SAFETY: `raw` is a live statement this store owns.
                        unsafe { ffi::sqlite3_finalize(entry.statement.raw) };
                        entry.statement.raw = std::ptr::null_mut();
                    }
                }
            }
        }
        let entry = self
            .entries
            .entry(sql.to_string())
            .or_insert_with(|| Entry {
                statement: Box::new(statement),
                used: tick,
            });
        entry.used = tick;
        Some(&mut *entry.statement as *mut StatementState)
    }

    /// Prepares `sql` on the store's connection.
    fn prepare(&mut self, sql: &str) -> Option<*mut ffi::sqlite3_stmt> {
        let text = std::ffi::CString::new(sql).ok()?;
        self.with_database(|database| crate::stmt::prepare_raw(database, &text, true))
            .flatten()
    }
}

/// The tag store state behind `object`, or a thrown `ERR_INVALID_THIS`.
fn state_of(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<*mut TagStoreState> {
    // SAFETY: the field is either absent, in which case V8 reports a null
    // pointer, or installed by `install` for this object's template.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut TagStoreState;
    if pointer.is_null() {
        errors::throw_type(
            scope,
            "This method can only be called on SQLTagStore instances.",
        );
        return None;
    }
    Some(pointer)
}

/// Allocates and installs a tag store on a fresh object.
pub fn create<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    database: &mut DatabaseState,
    database_object: v8::Local<'s, v8::Object>,
    capacity: i32,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = allocate(scope)?;
    let state = TagStoreState {
        database: database as *mut DatabaseState,
        database_object: v8::Global::new(scope, database_object),
        entries: HashMap::new(),
        capacity: capacity.max(1) as usize,
        tick: 0,
        options: StatementOptions {
            return_arrays: database.config.return_arrays,
            int_mode: database.config.int_mode(),
            allow_bare_named_params: database.config.allow_bare_named_params,
            allow_unknown_named_params: database.config.allow_unknown_named_params,
            persistent: true,
        },
    };
    let pointer = Box::into_raw(Box::new(state));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: the pointer came from `Box::into_raw` here, and this
            // finalizer runs exactly once, so it is the only owner.
            let mut state = unsafe { Box::from_raw(address as *mut TagStoreState) };
            state.clear();
            drop(state);
        }),
    );
    std::mem::forget(weak);
    Some(object)
}

thread_local! {
    /// The `SQLTagStore` prototype, built once per isolate.
    ///
    /// `SQLTagStore::GetConstructorTemplate` caches it in the environment, and
    /// `test-sqlite-template-tag.js` asserts two stores share a prototype and a
    /// constructor, so rebuilding it per store would be observable.
    static TAG_STORE_PROTOTYPE: std::cell::RefCell<Option<v8::Global<v8::Object>>> =
        const { std::cell::RefCell::new(None) };
}

/// Builds a `SQLTagStore` instance from its object template.
///
/// `SQLTagStore::GetConstructorTemplate` uses `IllegalConstructor` and `Create`
/// takes the instance template directly, so `new SQLTagStore()` throws while
/// `createTagStore()` works.
fn allocate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let cached = TAG_STORE_PROTOTYPE.with(|slot| slot.borrow().clone());
    if let Some(prototype) = cached {
        let template = v8::FunctionTemplate::builder(illegal_constructor)
            .length(0)
            .build(scope);
        let instance_template = template.instance_template(scope);
        instance_template.set_internal_field_count(INTERNAL_FIELDS);
        let instance = instance_template.new_instance(scope)?;
        instance.set_prototype(scope, v8::Local::new(scope, prototype).into())?;
        return Some(instance);
    }
    let template = v8::FunctionTemplate::builder(illegal_constructor)
        .length(0)
        .build(scope);
    let instance_template = template.instance_template(scope);
    instance_template.set_internal_field_count(INTERNAL_FIELDS);
    let instance = instance_template.new_instance(scope)?;
    let prototype = template.prototype_template(scope);
    for (name, method) in [
        ("run", crate::database::method(scope, 1, run)),
        ("get", crate::database::method(scope, 1, get)),
        ("all", crate::database::method(scope, 1, all)),
        ("iterate", crate::database::method(scope, 1, iterate)),
        ("clear", crate::database::method(scope, 0, clear)),
    ] {
        let key = v8::String::new(scope, name)?;
        prototype.set(key.into(), method.into());
    }
    for (name, getter) in [
        ("size", crate::database::accessor_template!(scope, size)),
        (
            "capacity",
            crate::database::accessor_template!(scope, capacity),
        ),
        ("db", crate::database::accessor_template!(scope, db)),
    ] {
        let key = v8::String::new(scope, name)?;
        prototype.set_accessor_property(
            key.into(),
            Some(getter),
            None,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        );
    }
    let prototype = prototype.new_instance(scope)?;
    TAG_STORE_PROTOTYPE.with(|slot| {
        *slot.borrow_mut() = Some(v8::Global::new(scope, prototype));
    });
    instance.set_prototype(scope, prototype.into())?;
    Some(instance)
}

fn illegal_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    errors::throw_coded(scope, "ERR_ILLEGAL_CONSTRUCTOR", "Illegal constructor");
}

/// The SQL text a tagged template produces, with a `?` per substitution.
///
/// `PrepareStatement` rejects anything but an array of strings as argument zero,
/// because that is the shape a tagged template call passes. The substitution
/// count is `strings.length - 1` and every part must be a string.
fn tagged_sql<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Option<String> {
    let strings = args.get(0);
    if !strings.is_array() {
        errors::throw_type(
            scope,
            "First argument must be an array of strings (template literal).",
        );
        return None;
    }
    let Ok(strings) = v8::Local::<v8::Array>::try_from(strings) else {
        return None;
    };
    let count = strings.length();
    let params = args.length().saturating_sub(1) as u32;
    let mut sql = String::new();
    for index in 0..count {
        let part = strings.get_index(scope, index)?;
        let Ok(part) = v8::Local::<v8::String>::try_from(part) else {
            errors::throw_type(scope, "Template literal parts must be strings.");
            return None;
        };
        sql.push_str(&part.to_rust_string_lossy(scope));
        if index < params {
            sql.push('?');
        }
    }
    Some(sql)
}

/// The state plus the SQL, shared by the four executing methods.
fn prepare_call<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Option<(*mut TagStoreState, String)> {
    let pointer = state_of(scope, args.this())?;
    // SAFETY: `state_of` returned a live pointer for `this`, and its rooted
    // database object keeps the state alive.
    // SAFETY: `state_of` returned a live pointer for `this`.
    let open = unsafe { (*pointer).is_open() };
    if !errors::require(scope, open, "database is not open") {
        return None;
    }
    // SAFETY: as above.
    let authorizer = unsafe { (*pointer).authorizer_depth() };
    if !errors::require(
        scope,
        authorizer == 0,
        "database cannot be accessed from an authorizer callback",
    ) {
        return None;
    }
    let sql = tagged_sql(scope, args)?;
    Some((pointer, sql))
}

/// Binds the substitution values and runs `body` on the cached statement.
///
/// `ResetAndBindStatement` refuses a parameter-count mismatch with a specific
/// message, because a tagged template always produces exactly one `?` per
/// substitution, so a mismatch means the SQL text already held a placeholder.
fn run_with_statement<'s, R>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    pointer: *mut TagStoreState,
    sql: &str,
    body: impl FnOnce(&mut v8::PinScope<'s, '_>, &mut StatementState) -> Option<R>,
) -> Option<R> {
    // SAFETY: `prepare_call` returned a live pointer for `this`.
    let store = unsafe { &mut *pointer };
    let params = args.length().saturating_sub(1);
    let statement = store.statement_for(sql)?;
    // SAFETY: `statement_for` returned a live cached statement, and nothing
    // between here and the body can clear the cache.
    let statement = unsafe { &mut *statement };
    let expected = statement.parameter_count();
    if expected != params {
        errors::throw_coded(
            scope,
            "ERR_INVALID_ARG_VALUE",
            "SQLite parameters must be bound using template literal placeholders.",
        );
        return None;
    }
    let code = statement.reset();
    if code != ffi::SQLITE_OK {
        let connection = statement.connection();
        errors::throw_sqlite(scope, connection);
        return None;
    }
    for index in 1..=params {
        let value = args.get(index);
        let value = match crate::value::from_js(scope, value) {
            Ok(value) => value,
            Err(rejection) => {
                crate::value::reject_binding(scope, index, rejection);
                return None;
            }
        };
        if !stmt::bind_value(scope, statement, &value, index) {
            return None;
        }
    }
    body(scope, statement)
}

/// `sqlTagStore.run\`...\``.
fn run<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((pointer, sql)) = prepare_call(scope, &args) else {
        return;
    };
    if let Some(value) = run_with_statement(scope, &args, pointer, &sql, stmt::run) {
        rv.set(value);
    }
}

/// `sqlTagStore.get\`...\``.
fn get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((pointer, sql)) = prepare_call(scope, &args) else {
        return;
    };
    if let Some(value) = run_with_statement(scope, &args, pointer, &sql, stmt::get) {
        rv.set(value);
    }
}

/// `sqlTagStore.all\`...\``.
fn all<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((pointer, sql)) = prepare_call(scope, &args) else {
        return;
    };
    if let Some(value) = run_with_statement(scope, &args, pointer, &sql, stmt::all) {
        rv.set(value);
    }
}

/// `sqlTagStore.iterate\`...\``.
fn iterate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some((pointer, sql)) = prepare_call(scope, &args) else {
        return;
    };
    // The iterator needs a JS `Statement` object to root, and a cached statement
    // has none; the tag store's own object is the equivalent receiver, since it
    // roots the same database.
    let this = args.this();
    if let Some(value) = run_with_statement(scope, &args, pointer, &sql, |scope, statement| {
        crate::iterator::create(scope, statement, this)
    }) {
        rv.set(value);
    }
}

/// `sqlTagStore.clear()`.
fn clear(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(pointer) = state_of(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    unsafe { (*pointer).clear() };
}

/// `sqlTagStore.size`: how many statements are cached.
fn size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(pointer) = state_of(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let size = unsafe { (*pointer).len() };
    rv.set(v8::Integer::new(scope, size as i32).into());
}

/// `sqlTagStore.capacity`.
fn capacity(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(pointer) = state_of(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let capacity = unsafe { (*pointer).capacity() };
    rv.set(v8::Integer::new(scope, capacity as i32).into());
}

/// `sqlTagStore.db`: the `Database` the store belongs to.
fn db(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(pointer) = state_of(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let object = unsafe { (*pointer).database_object() };
    if let Some(object) = object {
        rv.set(v8::Local::new(scope, object).into());
    }
}

impl TagStoreState {
    /// Whether the connection is still open.
    fn is_open(&mut self) -> bool {
        self.with_database(|database| database.is_open())
            .unwrap_or(false)
    }

    /// How deep inside an authorizer callback the connection is.
    fn authorizer_depth(&mut self) -> u32 {
        self.with_database(|database| database.authorizer_depth)
            .unwrap_or(0)
    }

    /// How many statements are cached, for `sqlTagStore.size`.
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// The configured `maxSize`, for `sqlTagStore.capacity`.
    fn capacity(&self) -> usize {
        self.capacity
    }

    /// The rooted `Database` object, for `sqlTagStore.db`.
    fn database_object(&self) -> Option<v8::Global<v8::Object>> {
        Some(self.database_object.clone())
    }
}

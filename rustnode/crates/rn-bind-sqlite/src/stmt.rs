//! The `Statement` state and the row and bind machinery.
//!
//! `src/node_sqlite.cc`'s `Statement` section is the specification, and several
//! behaviours there are not guessable from the API docs:
//!
//! * **`run()` accepts `SQLITE_ROW`.** A `RETURNING` statement produces rows,
//!   and `run()` steps once and discards them, so `INSERT ... RETURNING` still
//!   reports `changes` and `lastInsertRowid`.
//! * **Unbound parameters become NULL, they are not cleared.**
//!   `sqlite3_clear_bindings()` would expire statements whose query plan depends
//!   on a bound value, so every unbound index is bound to NULL instead.
//! * **Rows have a null prototype.** `RowToObject` builds them from a
//!   `DictionaryTemplate`, and `test-sqlite-statement.js` compares against
//!   `{ __proto__: null, ... }`. A column named `__proto__` is therefore an
//!   ordinary data property, which a plain `Object::new` would get wrong.
//! * **A deferred error replaces the row.** `get()` builds the row and *then*
//!   resets, because a deferred foreign-key check can fire during the reset of a
//!   `RETURNING` statement. An error there has to win over the row.
//!
//! # Why the statement roots its database object
//!
//! `BaseObjectPtr<Database>` in the C++ keeps the connection alive while any
//! statement exists. The Rust equivalent has to be a real V8 handle: a raw
//! `*mut DatabaseState` alone would dangle if the `Database` object were
//! collected first, and its finalizer would then `unregister` from freed memory.
//! [`StatementState::database_object`] is that handle, and dropping it — which
//! happens in the statement's own finalizer — is what finally makes the database
//! collectible.
//!
//! # Stepping
//!
//! A user-defined function or an aggregate's `xFinal` reaches JavaScript, and
//! that code may try to `close()` the statement SQLite is executing. Freeing it
//! would be a use-after-free, so the handle is recorded in
//! `DatabaseState::stepping` for the duration and `close()` refuses with
//! `ERR_INVALID_STATE`. This is `SteppingStatementGuard`.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_int, c_void};

use rn_v8_sys::v8;

use crate::constants;
use crate::db::{self, DatabaseState};
use crate::errors;
use crate::ffi;
use crate::value::{self, IntMode};

/// The internal field holding a `Statement`'s boxed state.
pub const STATE_FIELD: i32 = 0;
/// How many internal fields a `Statement` instance has.
pub const INTERNAL_FIELDS: usize = 1;

/// Everything one `Statement` instance owns.
pub struct StatementState {
    /// The live SQLite statement, or null once finalized.
    pub raw: *mut ffi::sqlite3_stmt,
    /// The `Database` state, kept valid by [`Self::database_object`].
    pub database: *mut DatabaseState,
    /// The rooted `Database` object: `BaseObjectPtr<Database>`'s job.
    ///
    /// `None` for a statement the tag store caches. That store roots its own
    /// `Database` object, so a second root here would be redundant; the
    /// pointer's validity is documented on whoever owns it instead.
    pub database_object: Option<v8::Global<v8::Object>>,
    /// The `returnArrays` flag, from the statement's options or the database's.
    pub return_arrays: bool,
    /// The `readBigInts` flag, from the statement's options or the database's.
    pub int_mode: IntMode,
    /// The `allowBareNamedParameters` flag.
    pub allow_bare_named_params: bool,
    /// The `allowUnknownNamedParameters` flag.
    pub allow_unknown_named_params: bool,
    /// Bare name → full name, computed once from the parameter list.
    ///
    /// `bare_named_params_` in the C++ is built lazily for the same reason: the
    /// parameter list cannot change, so rebuilding the map per bind would be
    /// wasted work on a hot path. The `Err` carries the conflict message so the
    /// throw does not depend on the map's contents.
    bare_names: Option<Result<HashMap<String, String>, String>>,
    /// Whether the statement has been finalized.
    pub finalized: bool,
    /// How many times this statement has been reset.
    ///
    /// `Statement::ResetStatement` bumps `reset_generation_` on every reset, and
    /// `StatementIterator` records the value it started at. A later `next()`
    /// compares them and refuses once they differ, which is what stops a
    /// `for...of` loop abandoned mid-scan from re-binding a *new* caller's
    /// parameters and replaying its statement — the case
    /// `test-sqlite-template-tag.js` calls "a stale iterator cannot replay a
    /// victim-bound write".
    pub reset_generation: u64,
}

impl StatementState {
    /// A statement that has not been installed on an object yet.
    pub fn new(
        raw: *mut ffi::sqlite3_stmt,
        database: *mut DatabaseState,
        database_object: Option<v8::Global<v8::Object>>,
        return_arrays: bool,
        int_mode: IntMode,
        allow_bare_named_params: bool,
        allow_unknown_named_params: bool,
    ) -> Self {
        Self {
            raw,
            database,
            database_object,
            return_arrays,
            int_mode,
            allow_bare_named_params,
            allow_unknown_named_params,
            bare_names: None,
            finalized: false,
            reset_generation: 0,
        }
    }

    /// Whether SQLite still owns a statement here.
    pub fn is_live(&self) -> bool {
        !self.finalized && !self.raw.is_null()
    }

    /// Runs `body` with the database state, or `None` when the pointer is unset.
    ///
    /// The borrow ends before `body` returns, so `body` may re-enter JavaScript
    /// as long as it does not use the reference after doing so and then touch the
    /// database again — every use below re-reads through this helper for exactly
    /// that reason.
    pub fn with_database<R>(&mut self, body: impl FnOnce(&mut DatabaseState) -> R) -> Option<R> {
        if self.database.is_null() {
            return None;
        }
        // SAFETY: `database_object` roots the `Database` object, whose boxed
        // state this pointer is, so the allocation outlives this statement.
        Some(body(unsafe { &mut *self.database }))
    }

    /// The connection handle, for the error constructors.
    pub fn connection(&mut self) -> *mut ffi::sqlite3 {
        self.with_database(|database| database.raw())
            .unwrap_or(std::ptr::null_mut())
    }

    /// `Statement::Close`: finalize the handle and mark the statement dead.
    ///
    /// Idempotent, because `Symbol.dispose` and `close()` can both run.
    pub fn finalize(&mut self) {
        if self.raw.is_null() {
            self.finalized = true;
            return;
        }
        // SAFETY: `raw` is a live statement this object owns; `sqlite3_finalize`
        // takes ownership, so the pointer is cleared immediately after.
        unsafe { ffi::sqlite3_finalize(self.raw) };
        self.raw = std::ptr::null_mut();
        self.finalized = true;
        let this = self as *mut Self;
        self.with_database(|database| database.unregister(this));
    }

    /// `sqlite3_reset`, bumping the generation every iterator watches.
    pub fn reset(&mut self) -> c_int {
        self.reset_generation = self.reset_generation.wrapping_add(1);
        if !self.is_live() {
            return ffi::SQLITE_OK;
        }
        // SAFETY: `raw` is live here.
        unsafe { ffi::sqlite3_reset(self.raw) }
    }

    /// `sqlite3_bind_parameter_count`.
    pub fn parameter_count(&self) -> i32 {
        if !self.is_live() {
            return 0;
        }
        // SAFETY: `raw` is live here.
        unsafe { ffi::sqlite3_bind_parameter_count(self.raw) }
    }

    /// `sqlite3_bind_parameter_name`, or `None` for an anonymous `?`.
    pub fn parameter_name(&self, index: i32) -> Option<String> {
        if !self.is_live() {
            return None;
        }
        // SAFETY: `raw` is live and `index` is within the parameter range.
        let pointer = unsafe { ffi::sqlite3_bind_parameter_name(self.raw, index) };
        if pointer.is_null() {
            None
        } else {
            // SAFETY: SQLite owns the name for the statement's lifetime.
            Some(unsafe { errors::c_string(pointer) })
        }
    }

    /// `sqlite3_bind_parameter_index`.
    pub fn parameter_index(&self, name: &str) -> i32 {
        if !self.is_live() {
            return 0;
        }
        let Ok(name) = CString::new(name) else {
            return 0;
        };
        // SAFETY: `raw` is live and `name` is a valid C string for the call.
        unsafe { ffi::sqlite3_bind_parameter_index(self.raw, name.as_ptr()) }
    }

    /// Drops the cached bare-name map, after the setting that built it changed.
    pub fn invalidate_bare_names(&mut self) {
        self.bare_names = None;
    }

    /// Looks a name up as `BindParams` does: the full form first, then the bare
    /// form when `allowBareNamedParameters` is on.
    pub fn resolve_name(&mut self, name: &str) -> Result<i32, String> {
        let index = self.parameter_index(name);
        if index != 0 || !self.allow_bare_named_params {
            return Ok(index);
        }
        let full = self.bare_names()?.get(name).cloned();
        Ok(match full {
            Some(full) => self.parameter_index(&full),
            None => 0,
        })
    }

    /// The bare-name → full-name map, built once from the parameter list.
    ///
    /// Two parameters whose names differ only in their sigil — `:k` and `$k` —
    /// would make `{ k: 1 }` ambiguous, which `BindParams` reports as
    /// `ERR_INVALID_STATE`.
    fn bare_names(&mut self) -> Result<&HashMap<String, String>, String> {
        if self.bare_names.is_none() {
            let mut map: HashMap<String, String> = HashMap::new();
            let mut conflict = None;
            let count = self.parameter_count();
            for index in 1..=count {
                let Some(full) = self.parameter_name(index) else {
                    continue;
                };
                // `std::string(name + 1)` in the C++ drops the sigil.
                let bare: String = full.chars().skip(1).collect();
                match map.get(&bare) {
                    Some(existing) if *existing != full => {
                        conflict = Some(format!(
                            "Cannot create bare named parameter '{bare}' because of conflicting \
                             names '{existing}' and '{full}'."
                        ));
                        break;
                    }
                    Some(_) => {}
                    None => {
                        map.insert(bare, full);
                    }
                }
            }
            self.bare_names = Some(match conflict {
                Some(message) => Err(message),
                None => Ok(map),
            });
        }
        match &self.bare_names {
            Some(Ok(map)) => Ok(map),
            Some(Err(message)) => Err(message.clone()),
            None => Err("Cannot read the parameter names.".to_string()),
        }
    }
}

/// The `StatementState` behind `object`, or a thrown `ERR_INVALID_THIS`.
///
/// The pointer is valid only while `object` is alive; callers do not hold a
/// borrow across a call into JavaScript that could run its finalizer.
pub fn pointer_of(object: v8::Local<'_, v8::Object>) -> Option<*mut StatementState> {
    // SAFETY: the field is either absent, in which case V8 reports a null
    // pointer, or installed by `install_state` for this object's own template.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut StatementState;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// Throws the `ERR_INVALID_THIS` a non-statement receiver produces.
pub fn throw_invalid_this(scope: &mut v8::PinScope<'_, '_>) {
    errors::throw_coded(
        scope,
        "ERR_INVALID_THIS",
        "Value of \"this\" must be of type Statement",
    );
}

/// The `StatementState` behind `object`, or a thrown `ERR_INVALID_THIS`.
pub fn state_or_throw(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<*mut StatementState> {
    match pointer_of(object) {
        Some(pointer) => Some(pointer),
        None => {
            throw_invalid_this(scope);
            None
        }
    }
}

/// Finalizes a statement on behalf of `Database::Close`.
///
/// # Safety
///
/// `pointer` must be a live statement's state, already removed from the
/// database registry so this is its only finalization.
pub unsafe fn finalize_from_database(pointer: *mut StatementState) {
    let state = &mut *pointer;
    if state.raw.is_null() {
        state.finalized = true;
        return;
    }
    ffi::sqlite3_finalize(state.raw);
    state.raw = std::ptr::null_mut();
    state.finalized = true;
}

/// Binds `value` at `index`, reporting a SQLite failure.
pub fn bind_value(
    scope: &mut v8::PinScope<'_, '_>,
    state: &mut StatementState,
    value: &value::Value,
    index: i32,
) -> bool {
    if !state.is_live() {
        return true;
    }
    let raw = state.raw;
    // SAFETY: `raw` is live and `index` is a valid parameter index. Every
    // destructor below is `SQLITE_TRANSIENT`, so SQLite copies the data and the
    // buffers need not outlive the call.
    let code = unsafe {
        match value {
            value::Value::Null => ffi::sqlite3_bind_null(raw, index),
            value::Value::Float(number) => ffi::sqlite3_bind_double(raw, index, *number),
            value::Value::Integer(number) => ffi::sqlite3_bind_int64(raw, index, *number),
            value::Value::Boolean(flag) => ffi::sqlite3_bind_int(raw, index, i32::from(*flag)),
            value::Value::Text(bytes) => ffi::sqlite3_bind_text64(
                raw,
                index,
                bytes.as_ptr() as *const std::os::raw::c_char,
                bytes.len() as u64,
                ffi::SQLITE_TRANSIENT,
                ffi::SQLITE_UTF8 as u8,
            ),
            value::Value::Blob(bytes) => ffi::sqlite3_bind_blob64(
                raw,
                index,
                bytes.as_ptr() as *const c_void,
                bytes.len() as u64,
                ffi::SQLITE_TRANSIENT,
            ),
        }
    };
    if code == ffi::SQLITE_OK {
        return true;
    }
    let connection = state.connection();
    errors::throw_sqlite(scope, connection);
    false
}

/// `Statement::BindParams`: positional arguments plus one optional named bag.
///
/// A plain object in position zero is the named bag; every other argument is a
/// value for the next anonymous `?`. A buffer in position zero is a value rather
/// than a bag, which is why the check excludes all three buffer kinds.
pub fn bind_params<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &mut StatementState,
    arguments: &v8::FunctionCallbackArguments<'s>,
) -> bool {
    let count = state.parameter_count();
    let mut bound = vec![false; (count.max(0) as usize) + 1];
    let argument_count = arguments.length();
    let mut anonymous_index = 1;
    let mut anonymous_start = 0;

    let first = arguments.get(0);
    let is_named_bag = argument_count > 0
        && first.is_object()
        && !first.is_array_buffer_view()
        && !first.is_array_buffer()
        && !first.is_shared_array_buffer();

    if is_named_bag {
        let Ok(object) = v8::Local::<v8::Object>::try_from(first) else {
            return false;
        };
        let Some(keys) = object.get_own_property_names(scope, v8::GetPropertyNamesArgs::default())
        else {
            return false;
        };
        let length = keys.length();
        // Collect the keys first so the borrow of `state` used to resolve a name
        // is not held while a property getter may run user JavaScript.
        let mut names = Vec::with_capacity(length as usize);
        for index in 0..length {
            let Some(key) = keys.get_index(scope, index) else {
                return false;
            };
            names.push((key, key.to_rust_string_lossy(scope)));
        }
        for (key, name) in names {
            let target = match state.resolve_name(&name) {
                Ok(index) => index,
                Err(message) => {
                    errors::throw_coded(scope, "ERR_INVALID_STATE", &message);
                    return false;
                }
            };
            if target == 0 {
                if state.allow_unknown_named_params {
                    continue;
                }
                errors::throw_coded(
                    scope,
                    "ERR_INVALID_STATE",
                    &format!("Unknown named parameter '{name}'"),
                );
                return false;
            }
            let Some(param) = object.get(scope, key) else {
                return false;
            };
            let param = match value::from_js(scope, param) {
                Ok(param) => param,
                Err(rejection) => {
                    value::reject_binding(scope, target, rejection);
                    return false;
                }
            };
            if !bind_value(scope, state, &param, target) {
                return false;
            }
            bound[target as usize] = true;
        }
        anonymous_start = 1;
    }

    for index in anonymous_start..argument_count {
        // Skip the named slots: a positional argument fills only `?`. A `None`
        // name is anonymous too, which is why the loop stops there.
        while anonymous_index <= count {
            match state.parameter_name(anonymous_index) {
                Some(name) if !name.starts_with('?') => anonymous_index += 1,
                _ => break,
            }
        }
        let argument = arguments.get(index);
        let param = match value::from_js(scope, argument) {
            Ok(param) => param,
            Err(rejection) => {
                value::reject_binding(scope, anonymous_index, rejection);
                return false;
            }
        };
        if !bind_value(scope, state, &param, anonymous_index) {
            return false;
        }
        if (anonymous_index as usize) < bound.len() {
            bound[anonymous_index as usize] = true;
        }
        anonymous_index += 1;
    }

    // Everything the caller did not bind becomes NULL, which is what makes
    // reusing a statement with fewer arguments deterministic.
    for index in 1..=count {
        if bound[index as usize] || !state.is_live() {
            continue;
        }
        // SAFETY: `raw` is live and `index` is in range.
        let code = unsafe { ffi::sqlite3_bind_null(state.raw, index) };
        if code != ffi::SQLITE_OK {
            let connection = state.connection();
            errors::throw_sqlite(scope, connection);
            return false;
        }
    }
    true
}

/// `sqlite3_step`'s outcome.
enum Step {
    /// A row is available.
    Row,
    /// The statement finished.
    Done,
    /// SQLite reported an error.
    Error,
}

fn step(state: &mut StatementState) -> Step {
    if !state.is_live() {
        return Step::Error;
    }
    // SAFETY: `raw` is live and stepped only here.
    match unsafe { ffi::sqlite3_step(state.raw) } {
        ffi::SQLITE_ROW => Step::Row,
        ffi::SQLITE_DONE => Step::Done,
        _ => Step::Error,
    }
}

/// Column count of the statement's current row.
pub fn column_total(state: &StatementState) -> i32 {
    if !state.is_live() {
        return 0;
    }
    // SAFETY: `raw` is live and prepared.
    unsafe { ffi::sqlite3_column_count(state.raw) }
}

/// Reads every column of the current row.
fn row_values<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &StatementState,
    columns: i32,
) -> Option<Vec<v8::Local<'s, v8::Value>>> {
    let mut values = Vec::with_capacity(columns as usize);
    for column in 0..columns {
        values.push(value::column_to_js(
            scope,
            state.raw,
            column,
            state.int_mode,
        )?);
    }
    Some(values)
}

/// Builds one row with a null prototype, as `RowToObject` does.
///
/// `DictionaryTemplate` is not reachable from the Rust V8 API, and it exists in
/// the C++ purely to avoid re-allocating the name list per row. Building the
/// object directly is observably identical: own enumerable data properties over a
/// null prototype, so `__proto__` and `constructor` are ordinary columns rather
/// than the prototype accessors a normal object literal would install.
fn row_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &StatementState,
    values: &[v8::Local<'s, v8::Value>],
) -> Option<v8::Local<'s, v8::Object>> {
    let mut names = Vec::with_capacity(values.len());
    for column in 0..values.len() as i32 {
        // SAFETY: `raw` is live and positioned on a row, so every in-range
        // column index has a name.
        let pointer = unsafe { ffi::sqlite3_column_name(state.raw, column) };
        if pointer.is_null() {
            errors::throw_coded(
                scope,
                "ERR_INVALID_STATE",
                &format!("Cannot get name of column {column}"),
            );
            return None;
        }
        // SAFETY: SQLite owns the name for the statement's lifetime.
        let name = unsafe { errors::c_string(pointer) };
        names.push(v8::String::new(scope, &name)?.into());
    }
    Some(v8::Object::with_prototype_and_properties(
        scope,
        v8::null(scope).into(),
        &names,
        values,
    ))
}

/// Builds one row in whichever shape the statement uses.
fn row<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &StatementState,
    values: &[v8::Local<'s, v8::Value>],
) -> Option<v8::Local<'s, v8::Value>> {
    if state.return_arrays {
        Some(v8::Array::new_with_elements(scope, values).into())
    } else {
        Some(row_object(scope, state, values)?.into())
    }
}

/// Resets the statement, throwing if SQLite reports a deferred failure.
fn reset_checked(scope: &mut v8::PinScope<'_, '_>, state: &mut StatementState) -> bool {
    let code = state.reset();
    if code == ffi::SQLITE_OK {
        return true;
    }
    let connection = state.connection();
    errors::throw_sqlite(scope, connection);
    false
}

fn throw_step_error(scope: &mut v8::PinScope<'_, '_>, state: &mut StatementState) {
    let connection = state.connection();
    errors::throw_sqlite(scope, connection);
}

/// `Statement::Get`: the first row, or `undefined`.
///
/// The reset happens after the row is built and its result is checked, because a
/// deferred constraint can fail there and that error must replace the row.
pub fn get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &mut StatementState,
) -> Option<v8::Local<'s, v8::Value>> {
    match step(state) {
        Step::Done => reset_checked(scope, state).then(|| v8::undefined(scope).into()),
        Step::Error => {
            throw_step_error(scope, state);
            None
        }
        Step::Row => {
            let columns = column_total(state);
            if columns == 0 {
                return reset_checked(scope, state).then(|| v8::undefined(scope).into());
            }
            let values = row_values(scope, state, columns)?;
            let built = row(scope, state, &values)?;
            reset_checked(scope, state).then_some(built)
        }
    }
}

/// `Statement::All`: every row, then a reset.
pub fn all<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &mut StatementState,
) -> Option<v8::Local<'s, v8::Value>> {
    let mut rows = Vec::new();
    let mut columns = 0;
    loop {
        match step(state) {
            Step::Row => {}
            Step::Done => break,
            Step::Error => {
                throw_step_error(scope, state);
                return None;
            }
        }
        if columns == 0 {
            columns = column_total(state);
        }
        let values = row_values(scope, state, columns)?;
        rows.push(row(scope, state, &values)?);
    }
    let array = v8::Array::new_with_elements(scope, &rows);
    reset_checked(scope, state).then(|| array.into())
}

/// `Statement::Run`: step once, discard any row, and report the counters.
pub fn run<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &mut StatementState,
) -> Option<v8::Local<'s, v8::Value>> {
    if !state.is_live() {
        errors::throw_coded(scope, "ERR_INVALID_STATE", "statement has been finalized");
        return None;
    }
    // SAFETY: `raw` is live and stepped only here.
    let result = unsafe { ffi::sqlite3_step(state.raw) };
    // `SQLITE_ROW` is accepted and discarded so a `RETURNING` statement can be
    // run with `run()`, which is what the C++ does.
    if result != ffi::SQLITE_DONE && result != ffi::SQLITE_ROW {
        throw_step_error(scope, state);
        return None;
    }
    if !reset_checked(scope, state) {
        return None;
    }
    let int_mode = state.int_mode;
    let connection = state.connection();
    // SAFETY: `connection` is the live handle the rooted database keeps open.
    let (rowid, changes) = unsafe {
        (
            ffi::sqlite3_last_insert_rowid(connection),
            ffi::sqlite3_changes64(connection),
        )
    };
    let changes_value = int_mode.to_value(scope, changes)?;
    let rowid_value = int_mode.to_value(scope, rowid)?;
    // `Run` builds this from a `DictionaryTemplate` whose keys are `changes`
    // then `lastInsertRowid`; property order is observable through
    // `deepStrictEqual`, so it is set in that order.
    let object = v8::Object::new(scope);
    let key = v8::String::new(scope, "changes")?;
    object.set(scope, key.into(), changes_value);
    let key = v8::String::new(scope, "lastInsertRowid")?;
    object.set(scope, key.into(), rowid_value);
    Some(object.into())
}

/// One entry of `statement.columns()`.
pub fn column_info<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &StatementState,
    index: i32,
) -> Option<v8::Local<'s, v8::Object>> {
    // SAFETY: `raw` is live and prepared, so the metadata accessors are defined
    // for every index in range. Each may return null, which becomes `null`.
    let (origin, database, table, decltype, name) = unsafe {
        (
            nullable_string(scope, ffi::sqlite3_column_origin_name(state.raw, index)),
            nullable_string(scope, ffi::sqlite3_column_database_name(state.raw, index)),
            nullable_string(scope, ffi::sqlite3_column_table_name(state.raw, index)),
            nullable_string(scope, ffi::sqlite3_column_decltype(state.raw, index)),
            nullable_string(scope, ffi::sqlite3_column_name(state.raw, index)),
        )
    };
    // `Columns` fills a `DictionaryTemplate` keyed `{column, database, name,
    // table, type}` and builds each row with `NewDictionaryInstanceNullProto`.
    // `test-sqlite-statement-columns.js` compares those objects, so both the key
    // order and the null prototype are load-bearing.
    let keys = ["column", "database", "name", "table", "type"];
    let values = [origin, database, name, table, decltype];
    let mut key_locals = Vec::with_capacity(keys.len());
    for key in keys {
        key_locals.push(v8::String::new(scope, key)?.into());
    }
    Some(v8::Object::with_prototype_and_properties(
        scope,
        v8::null(scope).into(),
        &key_locals,
        &values,
    ))
}

/// A `*const c_char` as a JS string, or `null`.
fn nullable_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    pointer: *const std::os::raw::c_char,
) -> v8::Local<'s, v8::Value> {
    if pointer.is_null() {
        return v8::null(scope).into();
    }
    // SAFETY: SQLite owns the string for the statement's lifetime.
    let text = unsafe { errors::c_string(pointer) };
    match v8::String::new(scope, &text) {
        Some(text) => text.into(),
        None => v8::null(scope).into(),
    }
}

/// The `statement.stat(name)` counter lookup, or `None` for an unknown name.
pub fn statement_stat(state: &StatementState, name: &str) -> Option<i32> {
    let (_, id) = constants::STATEMENT_STATUS
        .iter()
        .find(|(counter, _)| *counter == name)?;
    if !state.is_live() {
        return Some(0);
    }
    // SAFETY: `raw` is live and `id` is a valid `SQLITE_STMTSTATUS_*` value.
    Some(unsafe { ffi::sqlite3_stmt_status(state.raw, *id, 0) })
}

/// `statement.resetStats()`: clear every accumulated counter.
pub fn reset_stats(state: &StatementState) {
    if !state.is_live() {
        return;
    }
    for (_, id) in constants::STATEMENT_STATUS {
        // `memused` reports current usage rather than a counter, and SQLite
        // ignores the reset flag for it, so it is skipped.
        if *id == constants::STMTSTATUS_MEMUSED {
            continue;
        }
        // SAFETY: `raw` is live and `id` is valid.
        unsafe { ffi::sqlite3_stmt_status(state.raw, *id, 1) };
    }
}

/// Reads `statement.sourceSQL`.
pub fn source_sql<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &StatementState,
) -> Option<v8::Local<'s, v8::String>> {
    if !state.is_live() {
        return None;
    }
    // SAFETY: `raw` is live; `sqlite3_sql` returns a borrowed string SQLite owns
    // for the statement's lifetime.
    let pointer = unsafe { ffi::sqlite3_sql(state.raw) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: SQLite owns a NUL-terminated string here.
    let text = unsafe { errors::c_string(pointer) };
    v8::String::new(scope, &text)
}

/// Reads `statement.expandedSQL`, freeing SQLite's copy.
pub fn expanded_sql<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &StatementState,
) -> Option<v8::Local<'s, v8::String>> {
    if !state.is_live() {
        return None;
    }
    // SAFETY: `raw` is live; `expanded_sql` returns an owned buffer.
    let pointer = unsafe { ffi::sqlite3_expanded_sql(state.raw) };
    if pointer.is_null() {
        // `sqlite3_expanded_sql` can return null without an error code, which
        // the C++ turns into an `ERR_SQLITE_ERROR` naming the size limit.
        errors::throw_sqlite_message(
            scope,
            "Expanded SQL text would exceed configured limits",
            "Expanded SQL text would exceed configured limits",
            0,
        );
        return None;
    }
    // SAFETY: SQLite owns a NUL-terminated string here.
    let text = unsafe { errors::c_string(pointer) };
    // SAFETY: `expanded_sql` hands ownership of the buffer to the caller.
    unsafe { ffi::sqlite3_free(pointer as *mut c_void) };
    v8::String::new(scope, &text)
}

/// Prepares `sql` on `database`, returning the handle or throwing.
///
/// `sqlite3_prepare_v3` reports success without producing a statement when the
/// input holds no SQL, such as a comment alone. Such a statement can never be
/// stepped, so it is rejected rather than tracked: a null statement in the
/// registry would be a dangling entry.
pub fn prepare(
    scope: &mut v8::PinScope<'_, '_>,
    database: &mut DatabaseState,
    sql: &CString,
    persistent: bool,
) -> Option<*mut ffi::sqlite3_stmt> {
    let raw = database.raw();
    // `Database::Prepare` re-checks `IsOpen()` after reading the options bag
    // because a property getter can run arbitrary JavaScript, including
    // `db.close()`. The C++ then relies on `CHECK_ERROR_OR_THROW` seeing a null
    // connection; here a null handle would reach `sqlite3_prepare_v3` and be a
    // use-after-free, so the state is reported instead.
    if raw.is_null() {
        errors::throw_coded(scope, "ERR_INVALID_STATE", "database is not open");
        return None;
    }
    let mut statement: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
    let flags = if persistent {
        ffi::SQLITE_PREPARE_PERSISTENT
    } else {
        0
    };
    // SAFETY: `raw` is open, `sql` outlives the call, and `statement` is an
    // out-parameter SQLite writes.
    let code = unsafe {
        ffi::sqlite3_prepare_v3(
            raw,
            sql.as_ptr(),
            -1,
            flags,
            &mut statement,
            std::ptr::null_mut(),
        )
    };
    if code != ffi::SQLITE_OK {
        errors::throw_sqlite(scope, raw);
        return None;
    }
    if statement.is_null() {
        errors::throw_coded(
            scope,
            "ERR_INVALID_ARG_VALUE",
            "The SQL query contains no statements.",
        );
        return None;
    }
    Some(statement)
}

/// The inherited and per-statement behaviour flags `prepare` resolves.
#[derive(Debug, Clone, Copy)]
pub struct StatementOptions {
    /// `returnArrays`.
    pub return_arrays: bool,
    /// `readBigInts`.
    pub int_mode: IntMode,
    /// `allowBareNamedParameters`.
    pub allow_bare_named_params: bool,
    /// `allowUnknownNamedParameters`.
    pub allow_unknown_named_params: bool,
    /// `persistent`, which selects `SQLITE_PREPARE_PERSISTENT`.
    pub persistent: bool,
}

/// Reads the `prepare` options bag, which overrides the database's defaults.
///
/// Only the keys present in the bag change: `Database::Prepare` starts from
/// `std::optional` values so an absent key leaves the statement inheriting the
/// database's setting rather than resetting it to `false`.
pub fn read_options(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<'_, v8::Value>,
    target: &mut StatementOptions,
) -> bool {
    if options.is_undefined() {
        return true;
    }
    let Ok(options) = v8::Local::<v8::Object>::try_from(options) else {
        errors::throw_type(scope, "The \"options\" argument must be an object.");
        return false;
    };
    let mut arrays = target.return_arrays;
    let mut big_ints = target.int_mode == IntMode::BigInt;
    let mut bare = target.allow_bare_named_params;
    let mut unknown = target.allow_unknown_named_params;
    for (name, slot) in [
        ("returnArrays", &mut arrays),
        ("readBigInts", &mut big_ints),
        ("allowBareNamedParameters", &mut bare),
        ("allowUnknownNamedParameters", &mut unknown),
        ("persistent", &mut target.persistent),
    ] {
        if !db::optional_bool(scope, options, name, slot) {
            return false;
        }
    }
    target.return_arrays = arrays;
    target.int_mode = if big_ints {
        IntMode::BigInt
    } else {
        IntMode::Number
    };
    target.allow_bare_named_params = bare;
    target.allow_unknown_named_params = unknown;
    true
}

/// Builds the `Statement` constructor. Only `prepare` produces instances.
pub fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(illegal_constructor)
        .length(0)
        .build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(INTERNAL_FIELDS);

    populate_prototype(scope, &template);
    if let Some(name) = v8::String::new(scope, "Statement") {
        template.set_class_name(name);
    }
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate the Statement constructor")?;
    if let Some(name) = v8::String::new(scope, "Statement") {
        function.set_name(name);
    }
    Ok(function.into())
}

/// Installs every method, accessor and `Symbol.dispose` on a template's
/// prototype, so [`allocate`] can reuse the exact same surface.
fn populate_prototype(scope: &mut v8::PinScope<'_, '_>, template: &v8::FunctionTemplate) {
    let prototype = template.prototype_template(scope);
    let methods: [(&str, i32, v8::Local<'_, v8::FunctionTemplate>); 12] = [
        ("all", 0, crate::database::method(scope, 0, proto_all)),
        ("get", 0, crate::database::method(scope, 0, proto_get)),
        ("run", 0, crate::database::method(scope, 0, proto_run)),
        (
            "iterate",
            0,
            crate::database::method(scope, 0, proto_iterate),
        ),
        (
            "columns",
            0,
            crate::database::method(scope, 0, proto_columns),
        ),
        ("close", 0, crate::database::method(scope, 0, proto_close)),
        ("stat", 1, crate::database::method(scope, 1, proto_stat)),
        (
            "resetStats",
            0,
            crate::database::method(scope, 0, proto_reset_stats),
        ),
        (
            "setAllowBareNamedParameters",
            1,
            crate::database::method(scope, 1, proto_set_allow_bare),
        ),
        (
            "setAllowUnknownNamedParameters",
            1,
            crate::database::method(scope, 1, proto_set_allow_unknown),
        ),
        (
            "setReadBigInts",
            1,
            crate::database::method(scope, 1, proto_set_read_big_ints),
        ),
        (
            "setReturnArrays",
            1,
            crate::database::method(scope, 1, proto_set_return_arrays),
        ),
    ];
    for (name, _length, template) in methods {
        let key = match v8::String::new(scope, name) {
            Some(key) => key,
            None => return,
        };
        prototype.set(key.into(), template.into());
    }
    let dispose = crate::database::method(scope, 0, proto_dispose);
    let dispose_key: v8::Local<'_, v8::Name> =
        match v8::Local::<v8::Symbol>::try_from(crate::database::well_known_dispose(scope)) {
            Ok(symbol) => symbol.into(),
            Err(_) => v8::String::new(scope, "@@dispose")
                .expect("literal allocates")
                .into(),
        };
    prototype.set(dispose_key, dispose.into());

    // `sourceSQL` and `expandedSQL` are accessors, and both throw once the
    // statement is finalized, so they are not plain data properties.
    let accessors: [(&str, v8::Local<'_, v8::FunctionTemplate>); 2] = [
        (
            "sourceSQL",
            crate::database::accessor_template!(scope, proto_source_sql),
        ),
        (
            "expandedSQL",
            crate::database::accessor_template!(scope, proto_expanded_sql),
        ),
    ];
    for (name, getter) in accessors {
        let key = match v8::String::new(scope, name) {
            Some(key) => key,
            None => return,
        };
        prototype.set_accessor_property(
            key.into(),
            Some(getter),
            None,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        );
    }
}

/// The body of a class only the runtime may construct.
fn illegal_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    errors::throw_coded(scope, "ERR_ILLEGAL_CONSTRUCTOR", "Illegal constructor");
}

/// Creates and installs a JS `Statement` instance for `raw`.
///
/// The state box is what the object's finalizer frees, and the database's
/// registry holds a raw pointer to the same box so `close()` can finalize the
/// handle. Both are keyed to one allocation, which is why the box is made here
/// rather than in [`install_state`]: the registry needs its address.
pub fn create<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    raw: *mut ffi::sqlite3_stmt,
    database: &mut DatabaseState,
    database_object: v8::Local<'s, v8::Object>,
    options: &StatementOptions,
) -> Option<v8::Local<'s, v8::Value>> {
    let object = allocate(scope)?;
    let state = StatementState::new(
        raw,
        database as *mut DatabaseState,
        Some(v8::Global::new(scope, database_object)),
        options.return_arrays,
        options.int_mode,
        options.allow_bare_named_params,
        options.allow_unknown_named_params,
    );
    let pointer = Box::into_raw(Box::new(state));
    // SAFETY: the pointer is the allocation just made; nothing else owns it.
    track(database, pointer);
    install_state(scope, object, pointer);
    Some(object.into())
}

thread_local! {
    /// The `Statement` prototype, built once per isolate.
    ///
    /// `Statement::Create` in the C++ reuses `env->sqlite_statement_sync_constructor_template()`,
    /// and that caching is observable: `Object.getPrototypeOf(s1) ===
    /// Object.getPrototypeOf(s2)` holds, and `test-sqlite-template-tag.js`
    /// asserts it for tag stores too. Rebuilding the template per instance would
    /// give every statement its own prototype and break that identity.
    static STATEMENT_PROTOTYPE: std::cell::RefCell<Option<v8::Global<v8::Object>>> =
        const { std::cell::RefCell::new(None) };
}

/// Allocates a bare `Statement` instance from the cached object template.
///
/// `Statement::Create` in the C++ calls
/// `GetConstructorTemplate(env)->InstanceTemplate()->NewInstance(...)`, which
/// takes the *object* template and never runs the constructor body. Using
/// `Function::new_instance` here would invoke `IllegalConstructor` instead, so
/// this installs the cached prototype directly — the same escape the C++ uses,
/// and the reason `new Statement()` still throws.
fn allocate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let cache = STATEMENT_PROTOTYPE.with(|slot| slot.borrow().clone());
    let prototype = match cache {
        Some(prototype) => v8::Local::new(scope, prototype),
        None => {
            let template = v8::FunctionTemplate::builder(illegal_constructor)
                .length(0)
                .build(scope);
            populate_prototype(scope, &template);
            let prototype = template.prototype_template(scope).new_instance(scope)?;
            STATEMENT_PROTOTYPE.with(|slot| {
                *slot.borrow_mut() = Some(v8::Global::new(scope, prototype));
            });
            prototype
        }
    };
    let template = v8::FunctionTemplate::builder(illegal_constructor)
        .length(0)
        .build(scope);
    let instance_template = template.instance_template(scope);
    instance_template.set_internal_field_count(INTERNAL_FIELDS);
    let instance = instance_template.new_instance(scope)?;
    instance.set_prototype(scope, prototype.into())?;
    Some(instance)
}

/// Boxes an existing `StatementState` pointer onto `object`.
pub fn install_state(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    pointer: *mut StatementState,
) {
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
            let mut state = unsafe { Box::from_raw(address as *mut StatementState) };
            // `close()` finalizes explicitly; this is the path for a statement
            // that was never closed. The database may already be closed, in
            // which case `sqlite3_close_v2` zombied the connection and SQLite
            // finishes teardown when this statement is finalized.
            if !state.raw.is_null() {
                // SAFETY: `raw` is a live statement this object owns.
                unsafe { ffi::sqlite3_finalize(state.raw) };
                state.raw = std::ptr::null_mut();
            }
            let this: *mut StatementState = &mut *state;
            state.with_database(|database| database.unregister(this));
            // Dropping the box releases the rooted `Database` object last, which
            // is what finally lets the connection be collected.
            drop(state);
        }),
    );
    std::mem::forget(weak);
}

/// Registers a statement with its database so `close()` can finalize it.
pub fn track(database: &mut DatabaseState, statement: *mut StatementState) {
    database.statements.push(statement);
}

/// The state behind `this`, or a thrown `ERR_INVALID_THIS`.
fn this_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Option<*mut StatementState> {
    state_or_throw(scope, args.this())
}

/// The `ERR_INVALID_STATE` every method opens with once finalized.
pub fn require_live(scope: &mut v8::PinScope<'_, '_>, state: &StatementState) -> bool {
    errors::require(scope, state.is_live(), "statement has been finalized")
}

/// Opens a statement method: validates `this`, the finalized state, the
/// authorizer window, and the stepping guard.
///
/// The guard is pushed *before* the body runs and popped after, which is what
/// makes a callback's attempt to `close()` fail rather than free memory SQLite
/// is using.
fn begin_call<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Option<*mut StatementState> {
    let pointer = this_state(scope, args)?;
    // SAFETY: `state_or_throw` returned a live pointer for `this`, whose
    // receiver keeps the object alive for the duration of the call.
    let state = unsafe { &mut *pointer };
    if !require_live(scope, state) {
        return None;
    }
    let raw = state.raw;
    let (authorizer, stepping) = state
        .with_database(|database| (database.authorizer_depth, database.is_stepping(raw)))
        .unwrap_or((0, false));
    if !errors::require(
        scope,
        authorizer == 0,
        "database cannot be accessed from an authorizer callback",
    ) {
        return None;
    }
    if !errors::require(scope, !stepping, "statement is already being executed") {
        return None;
    }
    state.with_database(|database| database.stepping.push(raw));
    Some(pointer)
}

/// Closes a statement method opened with [`begin_call`].
fn end_call(pointer: *mut StatementState) {
    // SAFETY: `begin_call` returned a live pointer and the receiver keeps it
    // alive for the duration of the call.
    let state = unsafe { &mut *pointer };
    let raw = state.raw;
    state.with_database(|database| {
        if let Some(position) = database.stepping.iter().rposition(|entry| *entry == raw) {
            database.stepping.remove(position);
        }
    });
}

/// Resets and binds before running `execute`, then closes the guard.
///
/// The reset is `RESET_AND_CHECK`'s: a failure here means the previous run left
/// an error behind, and binding a fresh set of parameters onto a failed
/// statement would report the wrong cause.
fn execute_call<'s, R>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    pointer: *mut StatementState,
    execute: impl FnOnce(&mut v8::PinScope<'s, '_>, &mut StatementState) -> Option<R>,
) -> Option<R> {
    // SAFETY: `begin_call` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    let code = state.reset();
    if code != ffi::SQLITE_OK {
        let connection = state.connection();
        errors::throw_sqlite(scope, connection);
        end_call(pointer);
        return None;
    }
    if !bind_params(scope, state, &args) {
        end_call(pointer);
        return None;
    }
    let result = execute(scope, state);
    end_call(pointer);
    result
}

/// `statement.all([namedParameters][, ...anonymousParameters])`.
fn proto_all<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = begin_call(scope, &args) else {
        return;
    };
    if let Some(value) = execute_call(scope, args, pointer, all) {
        rv.set(value);
    }
}

/// `statement.get([namedParameters][, ...anonymousParameters])`.
fn proto_get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = begin_call(scope, &args) else {
        return;
    };
    if let Some(value) = execute_call(scope, args, pointer, get) {
        rv.set(value);
    }
}

/// `statement.run([namedParameters][, ...anonymousParameters])`.
fn proto_run<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = begin_call(scope, &args) else {
        return;
    };
    if let Some(value) = execute_call(scope, args, pointer, run) {
        rv.set(value);
    }
}

/// `statement.iterate([namedParameters][, ...anonymousParameters])`.
fn proto_iterate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = begin_call(scope, &args) else {
        return;
    };
    let this = args.this();
    if let Some(value) = execute_call(scope, args, pointer, |scope, state| {
        crate::iterator::create(scope, state, this)
    }) {
        rv.set(value);
    }
}

/// `statement.columns()`.
fn proto_columns<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !require_live(scope, state) {
        return;
    }
    let total = column_total(state);
    let mut columns = Vec::with_capacity(total as usize);
    for index in 0..total {
        let Some(column) = column_info(scope, state, index) else {
            return;
        };
        columns.push(column.into());
    }
    rv.set(v8::Array::new_with_elements(scope, &columns).into());
}

/// `statement.close()`.
fn proto_close<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !state.is_live() {
        // Disposal is idempotent, so an already-finalized statement is a no-op
        // even inside a callback.
        return;
    }
    let raw = state.raw;
    let (stepping, authorizer) = state
        .with_database(|database| (database.is_stepping(raw), database.authorizer_depth > 0))
        .unwrap_or((false, false));
    // `THROW_AND_RETURN_IF_STEPPING` uses "already being executed" for every
    // caller, and `close()` shares it. A different string here looks harmless
    // and is not: Node's test matches the message literally, so a mismatch makes
    // `assert.throws` fail, which leaves the statement unfinalized and lets a
    // later `db.close()` free it mid-step.
    if !errors::require(scope, !stepping, "statement is already being executed") {
        return;
    }
    if !errors::require(
        scope,
        !authorizer,
        "statement cannot be closed from an authorizer callback",
    ) {
        return;
    }
    state.finalize();
}

/// `statement[Symbol.dispose]()`.
///
/// `Dispose` re-checks only the finalized state, so disposing twice is a no-op.
fn proto_dispose<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !state.is_live() {
        return;
    }
    let raw = state.raw;
    let stepping = state
        .with_database(|database| database.is_stepping(raw))
        .unwrap_or(false);
    if stepping {
        return;
    }
    state.finalize();
}

/// `statement.stat(counter)`.
fn proto_stat<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &*pointer };
    if !require_live(scope, state) {
        return;
    }
    let Ok(counter) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        errors::throw_type(scope, "The \"counter\" argument must be a string.");
        return;
    };
    let name = counter.to_rust_string_lossy(scope);
    match statement_stat(state, &name) {
        Some(value) => rv.set(v8::Integer::new(scope, value).into()),
        None => errors::throw_coded(
            scope,
            "ERR_INVALID_ARG_VALUE",
            "The \"counter\" argument is not a valid statistic name.",
        ),
    }
}

/// `statement.resetStats()`.
fn proto_reset_stats<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &*pointer };
    if !require_live(scope, state) {
        return;
    }
    reset_stats(state);
}

/// Reads one boolean argument for the `set*` methods.
fn boolean_argument<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    message: &str,
) -> Option<bool> {
    let value = args.get(0);
    if !value.is_boolean() {
        errors::throw_type(scope, message);
        return None;
    }
    Some(value.boolean_value(scope))
}

/// `statement.setAllowBareNamedParameters(enabled)`.
fn proto_set_allow_bare<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !require_live(scope, state) {
        return;
    }
    let Some(enabled) = boolean_argument(
        scope,
        &args,
        "The \"allowBareNamedParameters\" argument must be a boolean.",
    ) else {
        return;
    };
    state.allow_bare_named_params = enabled;
    // The cached map was built under the previous setting, so it has to go.
    state.invalidate_bare_names();
}

/// `statement.setAllowUnknownNamedParameters(enabled)`.
fn proto_set_allow_unknown<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !require_live(scope, state) {
        return;
    }
    let Some(enabled) =
        boolean_argument(scope, &args, "The \"enabled\" argument must be a boolean.")
    else {
        return;
    };
    state.allow_unknown_named_params = enabled;
}

/// `statement.setReadBigInts(enabled)`.
fn proto_set_read_big_ints<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !require_live(scope, state) {
        return;
    }
    let Some(enabled) =
        boolean_argument(scope, &args, "The \"enabled\" argument must be a boolean.")
    else {
        return;
    };
    state.int_mode = if enabled {
        IntMode::BigInt
    } else {
        IntMode::Number
    };
}

/// `statement.setReturnArrays(enabled)`.
fn proto_set_return_arrays<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = this_state(scope, &args) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !require_live(scope, state) {
        return;
    }
    let Some(enabled) = boolean_argument(
        scope,
        &args,
        "The \"returnArrays\" argument must be a boolean.",
    ) else {
        return;
    };
    state.return_arrays = enabled;
}

/// `statement.sourceSQL`.
fn proto_source_sql<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = state_or_throw(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &*pointer };
    if !require_live(scope, state) {
        return;
    }
    if let Some(text) = source_sql(scope, state) {
        rv.set(text.into());
    }
}

/// `statement.expandedSQL`.
fn proto_expanded_sql<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = state_or_throw(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &*pointer };
    if !require_live(scope, state) {
        return;
    }
    if let Some(text) = expanded_sql(scope, state) {
        rv.set(text.into());
    }
}

/// Steps the statement once for `statement.iterate()`.
///
/// `Some(Some(row))` is a row, `Some(None)` means the statement finished, and
/// `None` means an error was thrown. The iterator owns the reset on completion,
/// so this does not reset.
pub fn step_for_iterator<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &mut StatementState,
) -> Option<Option<v8::Local<'s, v8::Value>>> {
    match step(state) {
        Step::Done => Some(None),
        Step::Error => {
            throw_step_error(scope, state);
            None
        }
        Step::Row => {
            let columns = column_total(state);
            let values = row_values(scope, state, columns)?;
            Some(Some(row(scope, state, &values)?))
        }
    }
}

/// `sqlite3_prepare_v3` without binding a scope, for callers that own the error
/// reporting themselves.
///
/// `SQLTagStore::PrepareStatement` reports the failure through
/// `THROW_ERR_SQLITE_ERROR(isolate, database)` in the caller, so this returns the
/// null pointer and leaves the connection's error state for the caller to read.
pub fn prepare_raw(
    database: &mut DatabaseState,
    sql: &CString,
    persistent: bool,
) -> Option<*mut ffi::sqlite3_stmt> {
    let raw = database.raw();
    if raw.is_null() {
        return None;
    }
    let mut statement: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
    let flags = if persistent {
        ffi::SQLITE_PREPARE_PERSISTENT
    } else {
        0
    };
    // SAFETY: `raw` is open, `sql` outlives the call, and `statement` is an
    // out-parameter SQLite writes.
    let code = unsafe {
        ffi::sqlite3_prepare_v3(
            raw,
            sql.as_ptr(),
            -1,
            flags,
            &mut statement,
            std::ptr::null_mut(),
        )
    };
    if code != ffi::SQLITE_OK || statement.is_null() {
        return None;
    }
    Some(statement)
}

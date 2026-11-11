//! The connection state behind one `Database` instance.
//!
//! `Database::New` in `src/node_sqlite.cc` is the specification: it validates the
//! path, reads the options bag, applies the open configuration, and only then
//! constructs the connection. The options are all observable and several have
//! defaults that differ from SQLite's, which is why they are enumerated here
//! rather than left to chance:
//!
//! | option | default | why it matters |
//! | --- | --- | --- |
//! | `open` | `true` | `{ open: false }` defers `sqlite3_open_v2` until `open()` |
//! | `readOnly` | `false` | selects `SQLITE_OPEN_READONLY` |
//! | `enableForeignKeyConstraints` | `true` | Node turns FKs on; SQLite does not |
//! | `enableDoubleQuotedStringLiterals` | `false` | Node turns DQS off |
//! | `timeout` | `0` | `sqlite3_busy_timeout` |
//! | `readBigInts` | `false` | integers as `BigInt` |
//! | `returnArrays` | `false` | rows as arrays rather than objects |
//! | `allowBareNamedParameters` | `true` | `{ k: 1 }` binds `:k` |
//! | `allowUnknownNamedParameters` | `false` | unknown names throw |
//! | `defensive` | `true` | Node turns defensive mode on; SQLite does not |
//! | `allowExtension` | `false` | needed by `loadExtension` |
//! | `limits` | none | per-connection SQLite limits |
//!
//! # Ownership
//!
//! The state lives in one box behind internal field zero, the arrangement
//! `rn-bind-block-list` uses. A `Statement` additionally roots its `Database`
//! *object*, which is `BaseObjectPtr<Database>`'s job in the C++: a statement
//! cannot outlive its connection. That is what makes the raw
//! `StatementState::database` pointer valid for as long as the statement exists,
//! and it makes finalizer ordering safe — the database box cannot be dropped
//! while a statement still roots its object.

use std::ffi::CString;
use std::os::raw::{c_int, c_void};

use rn_v8_sys::v8;

use crate::constants;
use crate::errors;
use crate::ffi;
use crate::value::IntMode;

/// The internal field holding a `Database`'s boxed state.
pub const STATE_FIELD: i32 = 0;
/// The internal field caching the `limits` object, as `kLimitsObject` does.
pub const LIMITS_FIELD: i32 = 1;
/// The internal field holding the `setAuthorizer` callback, as
/// `kAuthorizerCallback` does.
pub const AUTHORIZER_FIELD: i32 = 2;
/// How many internal fields a `Database` instance has.
pub const INTERNAL_FIELDS: usize = 3;

/// The `DatabaseOpenConfiguration` fields `Database::New` parses.
#[derive(Debug, Clone)]
pub struct OpenConfiguration {
    /// The value passed to `sqlite3_open_v2`, after URL and buffer handling.
    pub location: String,
    /// `readOnly`.
    pub read_only: bool,
    /// `enableForeignKeyConstraints`.
    pub enable_foreign_keys: bool,
    /// `enableDoubleQuotedStringLiterals`.
    pub enable_dqs: bool,
    /// `timeout`, in milliseconds.
    pub timeout: i32,
    /// `readBigInts`.
    pub use_big_ints: bool,
    /// `returnArrays`.
    pub return_arrays: bool,
    /// `allowBareNamedParameters`.
    pub allow_bare_named_params: bool,
    /// `allowUnknownNamedParameters`.
    pub allow_unknown_named_params: bool,
    /// `defensive`.
    pub defensive: bool,
    /// `limits`, indexed by SQLite's limit id.
    pub limits: [Option<i32>; 11],
}

impl OpenConfiguration {
    /// The defaults `DatabaseOpenConfiguration` is constructed with.
    ///
    /// These are deliberately *not* SQLite's defaults: Node enables foreign keys
    /// and defensive mode and disables double-quoted string literals, and
    /// `test-sqlite-config.js` asserts each reversal.
    pub fn new(location: String) -> Self {
        Self {
            location,
            read_only: false,
            enable_foreign_keys: true,
            enable_dqs: false,
            timeout: 0,
            use_big_ints: false,
            return_arrays: false,
            allow_bare_named_params: true,
            allow_unknown_named_params: false,
            defensive: true,
            limits: [None; 11],
        }
    }

    /// `use_big_ints`, in the form the value reader wants.
    pub fn int_mode(&self) -> IntMode {
        if self.use_big_ints {
            IntMode::BigInt
        } else {
            IntMode::Number
        }
    }
}

/// An open SQLite connection.
///
/// `Drop` calls `sqlite3_close_v2`, the *zombie* close: it succeeds with
/// unfinalized statements and defers real teardown until the last one is gone.
/// That is what makes finalizer order between a `Database` and its statements
/// irrelevant, so neither has to know when the other is collected.
pub struct Connection {
    raw: *mut ffi::sqlite3,
}

impl Connection {
    /// Borrows the raw handle.
    pub fn as_ptr(&self) -> *mut ffi::sqlite3 {
        self.raw
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: `raw` came from `sqlite3_open_v2` and is closed exactly
            // once, here; no other owner exists.
            unsafe { ffi::sqlite3_close_v2(self.raw) };
        }
    }
}

/// Everything one `Database` instance owns.
pub struct DatabaseState {
    /// The configuration the connection was opened with, and the settings the
    /// `limits` object reads back.
    pub config: OpenConfiguration,
    /// The connection, or `None` once `close()` has run.
    connection: Option<Connection>,
    /// Whether `loadExtension` may be called, from `allowExtension`.
    pub allow_load_extension: bool,
    /// Live prepared statements, so `close()` can finalize them.
    pub statements: Vec<*mut crate::stmt::StatementState>,
    /// Sessions this connection created, so `close()` can drop them.
    pub sessions: Vec<*mut crate::session::SessionState>,
    /// How deep inside a user callback the connection currently is.
    ///
    /// `close()` refuses while this is non-zero: a callback may be holding a
    /// statement this connection owns.
    pub callback_depth: u32,
    /// Set when a callback has already thrown, so the SQLite error that follows
    /// is a consequence rather than a cause.
    pub ignore_next_sqlite_error: bool,
    /// Whether an authorizer callback is running. SQLite forbids preparing or
    /// stepping from inside one.
    pub authorizer_depth: u32,
    /// The statements currently being stepped, innermost last.
    ///
    /// A user-defined function can reach JavaScript, and that code may try to
    /// `close()` the statement SQLite is executing. Recording it lets `close()`
    /// refuse rather than free memory underneath SQLite.
    pub stepping: Vec<*mut ffi::sqlite3_stmt>,
}

impl DatabaseState {
    /// Configuration defaults for `location`, with nothing open.
    pub fn new(config: OpenConfiguration, allow_load_extension: bool) -> Self {
        Self {
            config,
            connection: None,
            allow_load_extension,
            statements: Vec::new(),
            sessions: Vec::new(),
            callback_depth: 0,
            ignore_next_sqlite_error: false,
            authorizer_depth: 0,
            stepping: Vec::new(),
        }
    }

    /// Whether `sqlite3_open_v2` has succeeded and `close()` has not run.
    pub fn is_open(&self) -> bool {
        self.connection.is_some()
    }

    /// The raw connection, or null when closed.
    pub fn raw(&self) -> *mut ffi::sqlite3 {
        match &self.connection {
            Some(connection) => connection.as_ptr(),
            None => std::ptr::null_mut(),
        }
    }

    /// The integer mode from the configuration.
    pub fn int_mode(&self) -> IntMode {
        self.config.int_mode()
    }

    /// Whether the connection is inside a transaction.
    pub fn is_transaction(&self) -> bool {
        let raw = self.raw();
        if raw.is_null() {
            return false;
        }
        // SAFETY: `raw` is live; `get_autocommit` only reads connection state.
        unsafe { ffi::sqlite3_get_autocommit(raw) == 0 }
    }

    /// Whether `statement` is currently being stepped.
    pub fn is_stepping(&self, statement: *mut ffi::sqlite3_stmt) -> bool {
        self.stepping.contains(&statement)
    }

    /// `Database::Close`: finalize statements and sessions, then close.
    ///
    /// Finalizing statements first is what makes a later `stmt.get()` report
    /// "statement has been finalized" rather than reaching a zombie handle.
    pub fn close(&mut self) {
        for statement in std::mem::take(&mut self.statements) {
            // SAFETY: the registry only holds live statements, and the statement
            // objects root this database object, so none has been dropped.
            unsafe { crate::stmt::finalize_from_database(statement) };
        }
        for session in std::mem::take(&mut self.sessions) {
            // SAFETY: as above.
            unsafe { crate::session::delete_from_database(session) };
        }
        self.connection = None;
    }

    /// SQLite's current value for each limit, in `kLimitMapping` order.
    pub fn current_limits(&self) -> [i32; 11] {
        let raw = self.raw();
        let mut values = [0; 11];
        if raw.is_null() {
            return values;
        }
        for (index, slot) in values.iter_mut().enumerate() {
            // SAFETY: `index` is a valid limit id, and `-1` reads without
            // changing the limit.
            *slot = unsafe { ffi::sqlite3_limit(raw, index as c_int, -1) };
        }
        values
    }

    /// `Database::SetLimit`.
    pub fn set_limit(&mut self, id: usize, value: i32) {
        let raw = self.raw();
        if raw.is_null() {
            return;
        }
        // SAFETY: `id` comes from `kLimitMapping` and `raw` is live.
        unsafe { ffi::sqlite3_limit(raw, id as c_int, value) };
        if let Some(slot) = self.config.limits.get_mut(id) {
            *slot = Some(value);
        }
    }

    /// Removes a statement from the registry, if it is there.
    pub fn unregister(&mut self, statement: *mut crate::stmt::StatementState) {
        self.statements
            .retain(|registered| *registered != statement);
    }

    /// Removes a session from the registry, if it is there.
    pub fn unregister_session(&mut self, session: *mut crate::session::SessionState) {
        self.sessions.retain(|registered| *registered != session);
    }
}

/// The `DatabaseState` behind `object`, or `None` when it is not a database.
///
/// This does not take a scope, so the returned pointer does not inherit the
/// caller's handle-scope lifetime: an accessor's receiver belongs to the
/// property-callback lifetime rather than to the scope's, and tying the two
/// together makes every accessor fail to compile. Throwing is
/// [`state_or_throw`]'s job, which keeps the lookup usable from a `Drop`.
///
/// The pointer is valid only while `object` is alive. Callers copy out the
/// scalars they need instead of holding a borrow across a re-entry into
/// JavaScript, because such a re-entry could run the object's finalizer.
pub fn pointer_of(object: v8::Local<'_, v8::Object>) -> Option<*mut DatabaseState> {
    // SAFETY: the field is either absent, in which case V8 reports a null
    // pointer, or installed by `install_state` for this object's own template.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut DatabaseState;
    if pointer.is_null() {
        None
    } else {
        Some(pointer)
    }
}

/// The connection handle, re-checked after a possible re-entry into JavaScript.
///
/// `Database::Prepare` and friends all re-read `IsOpen()` after touching an
/// options bag, because a property getter can run `db.close()`. In C++ the
/// following call simply sees a null connection and `CHECK_ERROR_OR_THROW`
/// reports it; in Rust a null handle reaching `sqlite3_prepare_v3` is a
/// use-after-free, so every such site goes through this and gets the same
/// `ERR_INVALID_STATE` the C++ produces.
pub fn open_handle(
    scope: &mut v8::PinScope<'_, '_>,
    state: &DatabaseState,
) -> Option<*mut ffi::sqlite3> {
    let raw = state.raw();
    if raw.is_null() {
        errors::throw_coded(scope, "ERR_INVALID_STATE", "database is not open");
        return None;
    }
    Some(raw)
}

/// The `DatabaseState` behind `object`, or a thrown `ERR_INVALID_THIS`.
pub fn state_or_throw(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<*mut DatabaseState> {
    match pointer_of(object) {
        Some(pointer) => Some(pointer),
        None => {
            errors::throw_coded(
                scope,
                "ERR_INVALID_THIS",
                "Value of \"this\" must be of type Database",
            );
            None
        }
    }
}

/// Boxes `state` onto `object` and registers the finalizer that drops it.
pub fn install_state(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    state: DatabaseState,
) {
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
            drop(unsafe { Box::from_raw(address as *mut DatabaseState) });
        }),
    );
    // The registration has to outlive this scope; forgetting the `Weak` hands it
    // to V8 rather than cancelling it.
    std::mem::forget(weak);
}

/// Builds the `constants` object `lib/sqlite.js` re-exports.
pub fn constants_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    for (name, value) in constants::CONSTANTS {
        let key = v8::String::new(scope, name).ok_or("cannot allocate a constant name")?;
        object
            .define_own_property(
                scope,
                key.into(),
                v8::Integer::new(scope, *value).into(),
                v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
            )
            .ok_or_else(|| format!("cannot define constant {name}"))?;
    }
    Ok(object)
}

/// Opens the connection and applies every open configuration step.
///
/// The order is `Database::Open`'s: `sqlite3_open_v2`, then the two DQS flags,
/// then foreign keys, then defensive mode, then the busy timeout, then the
/// limits, then optional extension loading. Each step is checked, because a
/// setting SQLite silently ignored would make `test-sqlite-config.js` report the
/// wrong thing rather than fail.
pub fn open(state: &mut DatabaseState) -> Result<(), OpenError> {
    if state.is_open() {
        // A second `open()` on an open database is not something `lib/**` does;
        // closing first is the only behaviour that cannot leak the old handle.
        state.close();
    }
    let location = CString::new(state.config.location.as_str())
        .map_err(|_| OpenError::InvalidPath("path contains a null byte".to_string()))?;
    let mut flags = if state.config.read_only {
        ffi::SQLITE_OPEN_READONLY
    } else {
        ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE
    };
    flags |= ffi::SQLITE_OPEN_URI;

    let mut raw: *mut ffi::sqlite3 = std::ptr::null_mut();
    // SAFETY: `location` is a valid C string for the call and `raw` is an
    // out-parameter SQLite writes. On failure it still hands back a handle that
    // must be closed, which is why it is wrapped before the error is reported.
    let result =
        unsafe { ffi::sqlite3_open_v2(location.as_ptr(), &mut raw, flags, std::ptr::null()) };
    if raw.is_null() {
        return Err(OpenError::Sqlite(result, String::new(), 0));
    }
    state.connection = Some(Connection { raw });
    if result != ffi::SQLITE_OK {
        // `CHECK_ERROR_OR_THROW` leaves the connection in place on failure, so
        // `isOpen` stays true.
        return Err(error_for(state));
    }

    let dqs = i32::from(state.config.enable_dqs);
    for op in [ffi::SQLITE_DBCONFIG_DQS_DML, ffi::SQLITE_DBCONFIG_DQS_DDL] {
        // SAFETY: `raw` is the connection just opened; `db_config` takes the
        // value as an `int` and an optional `int*` out-parameter.
        let code = unsafe { ffi::sqlite3_db_config(raw, op, dqs, std::ptr::null_mut::<c_int>()) };
        if code != ffi::SQLITE_OK {
            return Err(error_for(state));
        }
    }

    let mut enabled: c_int = 0;
    // SAFETY: as above, with a live out-parameter.
    let code = unsafe {
        ffi::sqlite3_db_config(
            raw,
            ffi::SQLITE_DBCONFIG_ENABLE_FKEY,
            i32::from(state.config.enable_foreign_keys),
            &mut enabled,
        )
    };
    if code != ffi::SQLITE_OK {
        return Err(error_for(state));
    }
    if enabled != i32::from(state.config.enable_foreign_keys) {
        // The C++ has `CHECK_EQ` here. A silent mismatch is a compatibility bug,
        // so it becomes an error rather than a log line.
        return Err(OpenError::ConfigMismatch("enableForeignKeyConstraints"));
    }

    // SAFETY: as above.
    let code = unsafe {
        ffi::sqlite3_db_config(
            raw,
            ffi::SQLITE_DBCONFIG_DEFENSIVE,
            i32::from(state.config.defensive),
            &mut enabled,
        )
    };
    if code != ffi::SQLITE_OK {
        return Err(error_for(state));
    }
    if enabled != i32::from(state.config.defensive) {
        return Err(OpenError::ConfigMismatch("defensive"));
    }

    // SAFETY: `raw` is live; `busy_timeout` only sets connection state.
    unsafe { ffi::sqlite3_busy_timeout(raw, state.config.timeout) };

    for (index, limit) in state.config.limits.iter().enumerate() {
        if let Some(value) = limit {
            // SAFETY: `index` is a valid `SQLITE_LIMIT_*` id, being the array
            // position of `kLimitMapping`.
            unsafe { ffi::sqlite3_limit(raw, index as c_int, *value) };
        }
    }

    if state.allow_load_extension {
        // SAFETY: as above; enabling extension loading takes no out-parameter.
        let code = unsafe {
            ffi::sqlite3_db_config(
                raw,
                ffi::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
                1,
                std::ptr::null_mut::<c_int>(),
            )
        };
        if code != ffi::SQLITE_OK {
            return Err(error_for(state));
        }
    }

    Ok(())
}

/// What went wrong while opening or configuring a connection.
pub enum OpenError {
    /// A SQLite failure: the result code, message and extended code.
    Sqlite(i32, String, i32),
    /// A setting SQLite accepted but did not apply.
    ConfigMismatch(&'static str),
    /// The path could not be expressed as a C string.
    InvalidPath(String),
}

impl OpenError {
    /// Reports the failure as the exception `CHECK_ERROR_OR_THROW` would throw.
    pub fn throw(self, scope: &mut v8::PinScope<'_, '_>) {
        match self {
            OpenError::Sqlite(_, message, code) => {
                // SAFETY: `errstr` returns static text for the code.
                let errstr = unsafe { errors::c_string(ffi::sqlite3_errstr(code)) };
                errors::throw_sqlite_message(scope, &message, &errstr, code);
            }
            OpenError::ConfigMismatch(name) => errors::throw_sqlite_message(
                scope,
                &format!("failed to apply the \"{name}\" configuration"),
                "configuration was not applied",
                0,
            ),
            OpenError::InvalidPath(message) => errors::throw_type(scope, &message),
        }
    }
}

fn error_for(state: &DatabaseState) -> OpenError {
    let raw = state.raw();
    if raw.is_null() {
        return OpenError::Sqlite(ffi::SQLITE_ERROR, "database is not open".to_string(), 0);
    }
    // SAFETY: `raw` is live and these accessors only read connection state.
    unsafe {
        OpenError::Sqlite(
            ffi::SQLITE_ERROR,
            errors::c_string(ffi::sqlite3_errmsg(raw)),
            ffi::sqlite3_extended_errcode(raw),
        )
    }
}

/// Reads a `Database` path argument: a string, a `Uint8Array`, or a `file:` URL.
///
/// `ValidateDatabasePath` accepts exactly those three, and a `Uint8Array` path is
/// how a caller passes a path that is not valid UTF-8. A null byte is rejected
/// because SQLite would silently truncate the path there.
pub fn path_argument(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
    field: &str,
) -> Option<String> {
    let bytes = if value.is_string() {
        let text = v8::Local::<v8::String>::try_from(value).ok()?;
        crate::value::encode_utf8(scope, &text)
    } else if value.is_uint8_array() {
        crate::value::view_bytes(value)?
    } else if value.is_object() && !value.is_null_or_undefined() {
        return url_path_argument(scope, value, field);
    } else {
        return path_argument_error(scope, field);
    };
    if bytes.contains(&0) {
        return path_argument_error(scope, field);
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The `file:` URL form of a path argument.
fn url_path_argument(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
    field: &str,
) -> Option<String> {
    let object = v8::Local::<v8::Object>::try_from(value).ok()?;
    let key = v8::String::new(scope, "href")?;
    let href = object.get(scope, key.into())?;
    let Ok(text) = v8::Local::<v8::String>::try_from(href) else {
        return path_argument_error(scope, field);
    };
    let href = text.to_rust_string_lossy(scope);
    match crate::url::classify(&href) {
        Ok(path) => {
            if path.as_bytes().contains(&0) {
                return path_argument_error(scope, field);
            }
            Some(path)
        }
        Err(crate::url::UrlError::NotFile) => {
            errors::throw_coded(
                scope,
                "ERR_INVALID_URL_SCHEME",
                "The URL must be of scheme file",
            );
            None
        }
        Err(crate::url::UrlError::Invalid) => {
            errors::throw_coded(scope, "ERR_INVALID_URL", "Invalid URL");
            None
        }
    }
}

fn path_argument_error(scope: &mut v8::PinScope<'_, '_>, field: &str) -> Option<String> {
    errors::throw_type(
        scope,
        &format!(
            "The \"{field}\" argument must be a string, Uint8Array, or URL without null bytes."
        ),
    );
    None
}

/// Reads an optional boolean from an options bag, leaving `target` unchanged
/// when the property is absent.
pub fn optional_bool(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<'_, v8::Object>,
    name: &str,
    target: &mut bool,
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
    if !value.is_boolean() {
        errors::throw_type(
            scope,
            &format!("The \"options.{name}\" argument must be a boolean."),
        );
        return false;
    }
    *target = value.boolean_value(scope);
    true
}

/// Reads an optional string from an options bag.
pub fn optional_string(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<'_, v8::Object>,
    name: &str,
    target: &mut String,
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
    let Ok(text) = v8::Local::<v8::String>::try_from(value) else {
        errors::throw_type(
            scope,
            &format!("The \"options.{name}\" argument must be a string."),
        );
        return false;
    };
    *target = text.to_rust_string_lossy(scope);
    true
}

/// Reads an optional integer from an options bag.
///
/// `IsInt32()` is false for a fractional number, so `1.5` is a type error rather
/// than a truncation.
pub fn optional_int32(
    scope: &mut v8::PinScope<'_, '_>,
    options: v8::Local<'_, v8::Object>,
    name: &str,
    target: &mut i32,
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
    match value.number_value(scope) {
        Some(number)
            if number.fract() == 0.0 && number >= i32::MIN as f64 && number <= i32::MAX as f64 =>
        {
            *target = number as i32;
            true
        }
        _ => {
            errors::throw_type(
                scope,
                &format!("The \"{name}\" argument must be an integer."),
            );
            false
        }
    }
}

/// The `CString` for a statement's SQL text, or a thrown type error.
pub fn sql_argument(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<CString> {
    let Ok(text) = v8::Local::<v8::String>::try_from(value) else {
        errors::throw_type(scope, "The \"sql\" argument must be a string.");
        return None;
    };
    let bytes = crate::value::encode_utf8(scope, &text);
    match CString::new(bytes) {
        Ok(text) => Some(text),
        Err(_) => {
            // A NUL inside the SQL would silently truncate the statement, which
            // is exactly the kind of quiet wrong answer that has to be an error.
            errors::throw_coded(
                scope,
                "ERR_INVALID_ARG_VALUE",
                "The SQL string must not contain a null byte.",
            );
            None
        }
    }
}

/// `sqlite3_exec`, reporting a failure as an `ERR_SQLITE_ERROR`.
pub fn exec_sql(
    scope: &mut v8::PinScope<'_, '_>,
    state: &mut DatabaseState,
    sql: &CString,
) -> bool {
    let raw = state.raw();
    // SAFETY: `raw` is open, `sql` is a valid C string that outlives the call,
    // and no callback or error pointer is requested.
    let code = unsafe {
        ffi::sqlite3_exec(
            raw,
            sql.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if code == ffi::SQLITE_OK {
        return true;
    }
    errors::throw_sqlite(scope, raw);
    false
}

/// Reads a `db.limits.<name>` value, or throws the setter's errors.
///
/// `Infinity` means the compile-time maximum: SQLite's spelling of "unlimited"
/// is the largest `int`.
pub fn limit_value(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<'_, v8::Value>,
) -> Option<i32> {
    if !value.is_number() {
        errors::throw_type(
            scope,
            "Limit value must be a non-negative integer or Infinity.",
        );
        return None;
    }
    let number = value.number_value(scope)?;
    if number.is_infinite() && number > 0.0 {
        return Some(c_int::MAX);
    }
    if number.fract() != 0.0 || number < i32::MIN as f64 || number > i32::MAX as f64 {
        errors::throw_type(
            scope,
            "Limit value must be a non-negative integer or Infinity.",
        );
        return None;
    }
    let number = number as i32;
    if number < 0 {
        errors::throw_range(scope, "Limit value must be non-negative.");
        return None;
    }
    Some(number)
}

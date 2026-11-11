//! The SQLite C API, in the shape this crate needs.
//!
//! `vendor/sqlite/sqlite3.h` is the authority; this module mirrors only the
//! declarations the binding calls, because the amalgamation is compiled by
//! `build.rs` and its symbols are linked into this crate. Writing them out by
//! hand rather than generating bindings keeps the surface auditable: every
//! function here is one `node_sqlite.cc` also calls, with the same signature.
//!
//! # Why the type aliases
//!
//! SQLite's handles are opaque. Keeping them all as raw pointers with distinct
//! type aliases documents intent at each call site without pretending the
//! lifetimes are checked, which they are not: SQLite owns every one of these.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_double, c_int, c_uint, c_void};

/// `sqlite3` — one database connection.
pub type sqlite3 = c_void;
/// `sqlite3_stmt` — one prepared statement.
pub type sqlite3_stmt = c_void;
/// `sqlite3_context` — the state a SQL function is invoked with.
pub type sqlite3_context = c_void;
/// `sqlite3_value` — one argument to, or result of, a SQL function.
pub type sqlite3_value = c_void;
/// `sqlite3_session` — one changeset session.
pub type sqlite3_session = c_void;
/// `sqlite3_backup` — one incremental backup handle.
pub type sqlite3_backup = c_void;

/// `sqlite3_int64`.
pub type sqlite3_int64 = i64;
/// `sqlite3_uint64`.
pub type sqlite3_uint64 = u64;

/// `SQLITE_OK`.
pub const SQLITE_OK: c_int = 0;
/// `SQLITE_ERROR`, the generic failure code.
pub const SQLITE_ERROR: c_int = 1;
/// `SQLITE_BUSY`, a transient failure a backup retries from.
pub const SQLITE_BUSY: c_int = 5;
/// `SQLITE_LOCKED`, the other transient failure a backup retries from.
pub const SQLITE_LOCKED: c_int = 6;
/// `SQLITE_ROW`, the result code `sqlite3_step` returns for a row.
pub const SQLITE_ROW: c_int = 100;
/// `SQLITE_DONE`, the result code `sqlite3_step` returns when finished.
pub const SQLITE_DONE: c_int = 101;

/// `SQLITE_INTEGER`.
pub const SQLITE_INTEGER: c_int = 1;
/// `SQLITE_FLOAT`.
pub const SQLITE_FLOAT: c_int = 2;
/// `SQLITE_TEXT`.
pub const SQLITE_TEXT: c_int = 3;
/// `SQLITE_BLOB`.
pub const SQLITE_BLOB: c_int = 4;
/// `SQLITE_NULL`.
pub const SQLITE_NULL: c_int = 5;

/// `SQLITE_UTF8`.
pub const SQLITE_UTF8: c_int = 1;
/// `SQLITE_DETERMINISTIC`.
pub const SQLITE_DETERMINISTIC: c_int = 0x800;
/// `SQLITE_DIRECTONLY`.
pub const SQLITE_DIRECTONLY: c_int = 0x0008_0000;

/// `SQLITE_OPEN_READONLY`.
pub const SQLITE_OPEN_READONLY: c_int = 0x0000_0001;
/// `SQLITE_OPEN_READWRITE`.
pub const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
/// `SQLITE_OPEN_CREATE`.
pub const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;
/// `SQLITE_OPEN_URI`.
pub const SQLITE_OPEN_URI: c_int = 0x0000_0040;

/// `SQLITE_PREPARE_PERSISTENT`.
pub const SQLITE_PREPARE_PERSISTENT: c_uint = 0x01;

/// `SQLITE_DBCONFIG_ENABLE_FKEY`.
pub const SQLITE_DBCONFIG_ENABLE_FKEY: c_int = 1002;
/// `SQLITE_DBCONFIG_DEFENSIVE`.
pub const SQLITE_DBCONFIG_DEFENSIVE: c_int = 1010;
/// `SQLITE_DBCONFIG_DQS_DML`.
pub const SQLITE_DBCONFIG_DQS_DML: c_int = 1013;
/// `SQLITE_DBCONFIG_DQS_DDL`.
pub const SQLITE_DBCONFIG_DQS_DDL: c_int = 1014;
/// `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION`.
pub const SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION: c_int = 1005;

/// `SQLITE_DENY`, the authorizer result that fails the statement.
pub const SQLITE_DENY: c_int = 1;
/// `SQLITE_IGNORE`, the authorizer result that hides the column or row.
pub const SQLITE_IGNORE: c_int = 2;

/// `SQLITE_DESERIALIZE_FREEONCLOSE`.
pub const SQLITE_DESERIALIZE_FREEONCLOSE: c_uint = 1;
/// `SQLITE_DESERIALIZE_RESIZEABLE`.
pub const SQLITE_DESERIALIZE_RESIZEABLE: c_uint = 2;
/// `SQLITE_TRACE_PROFILE`.
pub const SQLITE_TRACE_PROFILE: c_uint = 0x02;

/// `SQLITE_DESTRUCTOR_TRANSIENT`, spelled `SQLITE_TRANSIENT` in C.
///
/// It is the sentinel `((sqlite3_destructor_type)-1)`, which tells SQLite to
/// copy the value instead of taking ownership. Expressed as `usize` here
/// because a Rust `fn` pointer cannot hold that value.
pub const SQLITE_TRANSIENT: usize = usize::MAX;

/// The scalar-function callback type.
pub type XFunc = Option<
    unsafe extern "C" fn(context: *mut sqlite3_context, argc: c_int, argv: *mut *mut sqlite3_value),
>;
/// The aggregate-function step callback type.
pub type XStep = Option<
    unsafe extern "C" fn(context: *mut sqlite3_context, argc: c_int, argv: *mut *mut sqlite3_value),
>;
/// The aggregate-function finalizer callback type.
pub type XFinal = Option<unsafe extern "C" fn(context: *mut sqlite3_context)>;
/// The destroy callback that SQLite runs when a registration is replaced.
pub type XDestroy = Option<unsafe extern "C" fn(argument: *mut c_void)>;

extern "C" {
    pub fn sqlite3_open_v2(
        filename: *const c_char,
        db: *mut *mut sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    pub fn sqlite3_close_v2(db: *mut sqlite3) -> c_int;
    pub fn sqlite3_errmsg(db: *mut sqlite3) -> *const c_char;
    pub fn sqlite3_errstr(code: c_int) -> *const c_char;
    pub fn sqlite3_extended_errcode(db: *mut sqlite3) -> c_int;
    pub fn sqlite3_db_config(db: *mut sqlite3, op: c_int, ...) -> c_int;
    pub fn sqlite3_busy_timeout(db: *mut sqlite3, milliseconds: c_int) -> c_int;
    pub fn sqlite3_limit(db: *mut sqlite3, id: c_int, new_value: c_int) -> c_int;
    pub fn sqlite3_db_filename(db: *mut sqlite3, name: *const c_char) -> *const c_char;
    pub fn sqlite3_get_autocommit(db: *mut sqlite3) -> c_int;
    pub fn sqlite3_last_insert_rowid(db: *mut sqlite3) -> sqlite3_int64;
    pub fn sqlite3_changes64(db: *mut sqlite3) -> sqlite3_int64;
    pub fn sqlite3_exec(
        db: *mut sqlite3,
        sql: *const c_char,
        callback: *const c_void,
        argument: *mut c_void,
        error_message: *mut *mut c_char,
    ) -> c_int;
    pub fn sqlite3_free(pointer: *mut c_void);
    pub fn sqlite3_serialize(
        db: *mut sqlite3,
        schema: *const c_char,
        size: *mut sqlite3_int64,
        flags: c_uint,
    ) -> *mut u8;
    pub fn sqlite3_deserialize(
        db: *mut sqlite3,
        schema: *const c_char,
        data: *mut u8,
        size: sqlite3_int64,
        buffer_size: sqlite3_int64,
        flags: c_uint,
    ) -> c_int;

    pub fn sqlite3_prepare_v3(
        db: *mut sqlite3,
        sql: *const c_char,
        length: c_int,
        prep_flags: c_uint,
        statement: *mut *mut sqlite3_stmt,
        tail: *mut *const c_char,
    ) -> c_int;
    pub fn sqlite3_finalize(statement: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_reset(statement: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_step(statement: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_sql(statement: *mut sqlite3_stmt) -> *const c_char;
    pub fn sqlite3_expanded_sql(statement: *mut sqlite3_stmt) -> *mut c_char;
    pub fn sqlite3_stmt_status(statement: *mut sqlite3_stmt, op: c_int, reset: c_int) -> c_int;

    pub fn sqlite3_bind_parameter_count(statement: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_bind_parameter_name(statement: *mut sqlite3_stmt, index: c_int)
        -> *const c_char;
    pub fn sqlite3_bind_parameter_index(statement: *mut sqlite3_stmt, name: *const c_char)
        -> c_int;
    pub fn sqlite3_bind_null(statement: *mut sqlite3_stmt, index: c_int) -> c_int;
    pub fn sqlite3_bind_int(statement: *mut sqlite3_stmt, index: c_int, value: c_int) -> c_int;
    pub fn sqlite3_bind_int64(
        statement: *mut sqlite3_stmt,
        index: c_int,
        value: sqlite3_int64,
    ) -> c_int;
    pub fn sqlite3_bind_double(
        statement: *mut sqlite3_stmt,
        index: c_int,
        value: c_double,
    ) -> c_int;
    pub fn sqlite3_bind_text64(
        statement: *mut sqlite3_stmt,
        index: c_int,
        value: *const c_char,
        length: sqlite3_uint64,
        destructor: usize,
        encoding: u8,
    ) -> c_int;
    pub fn sqlite3_bind_blob64(
        statement: *mut sqlite3_stmt,
        index: c_int,
        value: *const c_void,
        length: sqlite3_uint64,
        destructor: usize,
    ) -> c_int;

    pub fn sqlite3_column_count(statement: *mut sqlite3_stmt) -> c_int;
    pub fn sqlite3_column_name(statement: *mut sqlite3_stmt, column: c_int) -> *const c_char;
    pub fn sqlite3_column_origin_name(statement: *mut sqlite3_stmt, column: c_int)
        -> *const c_char;
    pub fn sqlite3_column_database_name(
        statement: *mut sqlite3_stmt,
        column: c_int,
    ) -> *const c_char;
    pub fn sqlite3_column_table_name(statement: *mut sqlite3_stmt, column: c_int) -> *const c_char;
    pub fn sqlite3_column_decltype(statement: *mut sqlite3_stmt, column: c_int) -> *const c_char;
    pub fn sqlite3_column_type(statement: *mut sqlite3_stmt, column: c_int) -> c_int;
    pub fn sqlite3_column_int64(statement: *mut sqlite3_stmt, column: c_int) -> sqlite3_int64;
    pub fn sqlite3_column_double(statement: *mut sqlite3_stmt, column: c_int) -> c_double;
    pub fn sqlite3_column_text(statement: *mut sqlite3_stmt, column: c_int) -> *const u8;
    pub fn sqlite3_column_blob(statement: *mut sqlite3_stmt, column: c_int) -> *const c_void;
    pub fn sqlite3_column_bytes(statement: *mut sqlite3_stmt, column: c_int) -> c_int;

    pub fn sqlite3_value_type(value: *mut sqlite3_value) -> c_int;
    pub fn sqlite3_value_int64(value: *mut sqlite3_value) -> sqlite3_int64;
    pub fn sqlite3_value_double(value: *mut sqlite3_value) -> c_double;
    pub fn sqlite3_value_text(value: *mut sqlite3_value) -> *const u8;
    pub fn sqlite3_value_blob(value: *mut sqlite3_value) -> *const c_void;
    pub fn sqlite3_value_bytes(value: *mut sqlite3_value) -> c_int;

    pub fn sqlite3_create_function_v2(
        db: *mut sqlite3,
        name: *const c_char,
        n_args: c_int,
        encoding: c_int,
        application: *mut c_void,
        scalar: XFunc,
        aggregate: XStep,
        finalizer: XFinal,
        destroy: XDestroy,
    ) -> c_int;
    pub fn sqlite3_create_window_function(
        db: *mut sqlite3,
        name: *const c_char,
        n_args: c_int,
        encoding: c_int,
        application: *mut c_void,
        step: XStep,
        finalizer: XFinal,
        value: XFinal,
        inverse: XStep,
        destroy: XDestroy,
    ) -> c_int;

    pub fn sqlite3_user_data(context: *mut sqlite3_context) -> *mut c_void;
    pub fn sqlite3_aggregate_context(context: *mut sqlite3_context, n_bytes: c_int) -> *mut c_void;
    pub fn sqlite3_result_null(context: *mut sqlite3_context);
    pub fn sqlite3_result_int64(context: *mut sqlite3_context, value: sqlite3_int64);
    pub fn sqlite3_result_double(context: *mut sqlite3_context, value: c_double);
    pub fn sqlite3_result_text64(
        context: *mut sqlite3_context,
        value: *const c_char,
        length: sqlite3_uint64,
        destructor: usize,
        encoding: u8,
    );
    pub fn sqlite3_result_blob64(
        context: *mut sqlite3_context,
        value: *const c_void,
        length: sqlite3_uint64,
        destructor: usize,
    );
    pub fn sqlite3_result_error(
        context: *mut sqlite3_context,
        message: *const c_char,
        length: c_int,
    );
    pub fn sqlite3_result_error_code(context: *mut sqlite3_context, code: c_int);

    pub fn sqlite3session_create(
        db: *mut sqlite3,
        db_name: *const c_char,
        session: *mut *mut sqlite3_session,
    ) -> c_int;
    pub fn sqlite3session_attach(session: *mut sqlite3_session, table: *const c_char) -> c_int;
    pub fn sqlite3session_changeset(
        session: *mut sqlite3_session,
        size: *mut c_int,
        buffer: *mut *mut c_void,
    ) -> c_int;
    pub fn sqlite3session_patchset(
        session: *mut sqlite3_session,
        size: *mut c_int,
        buffer: *mut *mut c_void,
    ) -> c_int;
    pub fn sqlite3session_delete(session: *mut sqlite3_session);

    pub fn sqlite3_backup_init(
        destination: *mut sqlite3,
        destination_name: *const c_char,
        source: *mut sqlite3,
        source_name: *const c_char,
    ) -> *mut sqlite3_backup;
    pub fn sqlite3_backup_step(backup: *mut sqlite3_backup, pages: c_int) -> c_int;
    pub fn sqlite3_backup_remaining(backup: *mut sqlite3_backup) -> c_int;
    pub fn sqlite3_backup_pagecount(backup: *mut sqlite3_backup) -> c_int;
    pub fn sqlite3_backup_finish(backup: *mut sqlite3_backup) -> c_int;

    pub fn sqlite3_set_authorizer(
        db: *mut sqlite3,
        callback: Option<
            unsafe extern "C" fn(
                user_data: *mut c_void,
                action: c_int,
                param1: *const c_char,
                param2: *const c_char,
                db_name: *const c_char,
                trigger: *const c_char,
            ) -> c_int,
        >,
        user_data: *mut c_void,
    ) -> c_int;

    pub fn sqlite3_load_extension(
        db: *mut sqlite3,
        file: *const c_char,
        entry: *const c_char,
        error_message: *mut *mut c_char,
    ) -> c_int;

    pub fn sqlite3_malloc64(size: sqlite3_uint64) -> *mut c_void;

    pub fn sqlite3_libversion() -> *const c_char;
}

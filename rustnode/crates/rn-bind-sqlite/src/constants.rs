//! `constants`, the value `lib/sqlite.js` re-exports as `sqlite.constants`.
//!
//! `DefineConstants` in `src/node_sqlite.cc` publishes 45 entries from
//! `sqlite3.h`: the changeset conflict policies, the authorizer result codes and
//! the authorizer action codes. They are the values SQL user code passes to
//! `applyChangeset` and receives in a `setAuthorizer` callback, so they have to
//! be SQLite's numbers rather than anything chosen here.
//!
//! `SQLITE_COPY` deserves a note: it is `0`, which is also `SQLITE_OK`. That is
//! not a mistake in this table, it is what `sqlite3.h` says, and Node publishes
//! it that way too.

/// Every constant `DefineConstants` defines, in the order it defines them.
pub const CONSTANTS: &[(&str, i32)] = &[
    // Changeset conflict resolution.
    ("SQLITE_CHANGESET_OMIT", 0),
    ("SQLITE_CHANGESET_REPLACE", 1),
    ("SQLITE_CHANGESET_ABORT", 2),
    ("SQLITE_CHANGESET_DATA", 1),
    ("SQLITE_CHANGESET_NOTFOUND", 2),
    ("SQLITE_CHANGESET_CONFLICT", 3),
    ("SQLITE_CHANGESET_CONSTRAINT", 4),
    ("SQLITE_CHANGESET_FOREIGN_KEY", 5),
    // Authorizer result codes.
    ("SQLITE_OK", 0),
    ("SQLITE_DENY", 1),
    ("SQLITE_IGNORE", 2),
    // Authorizer action codes.
    ("SQLITE_CREATE_INDEX", 1),
    ("SQLITE_CREATE_TABLE", 2),
    ("SQLITE_CREATE_TEMP_INDEX", 3),
    ("SQLITE_CREATE_TEMP_TABLE", 4),
    ("SQLITE_CREATE_TEMP_TRIGGER", 5),
    ("SQLITE_CREATE_TEMP_VIEW", 6),
    ("SQLITE_CREATE_TRIGGER", 7),
    ("SQLITE_CREATE_VIEW", 8),
    ("SQLITE_DELETE", 9),
    ("SQLITE_DROP_INDEX", 10),
    ("SQLITE_DROP_TABLE", 11),
    ("SQLITE_DROP_TEMP_INDEX", 12),
    ("SQLITE_DROP_TEMP_TABLE", 13),
    ("SQLITE_DROP_TEMP_TRIGGER", 14),
    ("SQLITE_DROP_TEMP_VIEW", 15),
    ("SQLITE_DROP_TRIGGER", 16),
    ("SQLITE_DROP_VIEW", 17),
    ("SQLITE_INSERT", 18),
    ("SQLITE_PRAGMA", 19),
    ("SQLITE_READ", 20),
    ("SQLITE_SELECT", 21),
    ("SQLITE_TRANSACTION", 22),
    ("SQLITE_UPDATE", 23),
    ("SQLITE_ATTACH", 24),
    ("SQLITE_DETACH", 25),
    ("SQLITE_ALTER_TABLE", 26),
    ("SQLITE_REINDEX", 27),
    ("SQLITE_ANALYZE", 28),
    ("SQLITE_CREATE_VTABLE", 29),
    ("SQLITE_DROP_VTABLE", 30),
    ("SQLITE_FUNCTION", 31),
    ("SQLITE_SAVEPOINT", 32),
    ("SQLITE_RECURSIVE", 33),
    ("SQLITE_COPY", 0),
];

/// `kLimitMapping` in `src/node_sqlite.h`, indexed by SQLite's limit id.
///
/// The header carries a `static_assert` that each entry's id equals its index,
/// and the JavaScript name is what `database.limits` exposes, so the order is
/// load-bearing: `SQLITE_LIMIT_LENGTH` is 0, `SQLITE_LIMIT_SQL_LENGTH` is 1, and
/// so on.
pub const LIMITS: &[&str] = &[
    "length",
    "sqlLength",
    "column",
    "exprDepth",
    "compoundSelect",
    "vdbeOp",
    "functionArg",
    "attach",
    "likePatternLength",
    "variableNumber",
    "triggerDepth",
];

/// `kStatusMapping` in `src/node_sqlite.h`: `statement.stat()` counter names.
///
/// `memused` maps to `SQLITE_STMTSTATUS_MEMUSED` (99), which reports current
/// memory usage rather than an accumulated count; `resetStats` skips it for
/// that reason.
pub const STATEMENT_STATUS: &[(&str, i32)] = &[
    ("fullscanStep", 1),
    ("sort", 2),
    ("autoindex", 3),
    ("vmStep", 4),
    ("reprepare", 5),
    ("run", 6),
    ("filterMiss", 7),
    ("filterHit", 8),
    ("memused", 99),
];

/// `SQLITE_STMTSTATUS_MEMUSED`, the one counter `resetStats` does not clear.
pub const STMTSTATUS_MEMUSED: i32 = 99;

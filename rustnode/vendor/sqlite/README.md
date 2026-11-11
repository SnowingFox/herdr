# vendored SQLite

`sqlite3.c`, `sqlite3.h` and `sqlite3ext.h` are the SQLite amalgamation copied
byte-identical from `deps/sqlite` in the Node revision `tools/node-pin.toml`
pins (`f344e7f552e`, SQLite 3.54.1). Node links SQLite as a static library from
this same tree, so building these files gives `node:sqlite` the SQLite Node
ships rather than whatever the host happens to have.

They are never patched. A local edit would change SQL semantics away from the
one Node produces, which is the only thing the binding exists to reproduce.
`SQLITE.sha256` records all three files and `tools/verify-sqlite.sh` checks them
in the gate.

## Why vendored instead of a system library

A system `libsqlite3` is a different version on every machine. Node 28 expects
3.54.1: `test-sqlite-limits.js` asserts limit defaults that moved between
releases, `SQLITE_STMTSTATUS_FILTER_HIT`/`FILTER_MISS` in `statement.stat()`
only exist from 3.38.0, and `sqlite3_stmt_explain`/`sqlite3_error_offset` used
by newer error paths are absent on older builds. Linux distributions ship
anything from 3.37 to 3.46, macOS ships its own, and Windows ships none. A
system link would therefore make results depend on the host, which is exactly
what the pinned vendor tree exists to prevent, and it would not build at all on
Windows. The amalgamation is one C translation unit with no dependencies, so
compiling it in the crate is both reproducible and portable.

## Build flags

The flags in `crates/rn-bind-sqlite/build.rs` mirror `deps/sqlite/sqlite.gyp`:
the same `SQLITE_ENABLE_*` set, so `FTS5`, `RTREE`, `GEOPOLY`, session
extension, `PREUPDATE_HOOK` (which `Session` needs) and `COLUMN_METADATA` (which
`statement.columns()` needs) are all present exactly as in Node's build.

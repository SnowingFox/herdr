//! Compiles the vendored SQLite amalgamation.
//!
//! `vendor/sqlite` holds `sqlite3.c`, `sqlite3.h` and `sqlite3ext.h` copied
//! byte-identical from `deps/sqlite` in the Node revision `tools/node-pin.toml`
//! pins. Node builds that same file as a static library, so this is not a
//! reimplementation of SQLite: it is SQLite 3.54.1 with the same compile-time
//! feature set, which is what makes `node:sqlite`'s SQL behaviour reproducible
//! across CI, macOS and Windows.
//!
//! # Why not the system library
//!
//! A host `libsqlite3` is a different version on every machine and absent on
//! Windows. `node:sqlite` exposes version-dependent behaviour directly:
//! `statement.stat()` offers `filterHit`/`filterMiss` only from SQLite 3.38,
//! `database.limits` reports defaults that moved between releases, and the
//! error text a test matches on comes from the library. Linking the host copy
//! would make results depend on the machine. The amalgamation is one C
//! translation unit with no dependencies, so compiling it is both reproducible
//! and portable.
//!
//! # The flags
//!
//! `deps/sqlite/sqlite.gyp` lists them, and they are copied exactly rather than
//! trimmed to what `lib/sqlite.js` appears to use. `SQLITE_ENABLE_SESSION` and
//! `SQLITE_ENABLE_PREUPDATE_HOOK` are required by `Session`, `COLUMN_METADATA`
//! by `statement.columns()`, and `FTS5`/`RTREE`/`GEOPOLY`/`MATH_FUNCTIONS` by
//! the SQL user code passes to `exec()`, which no static analysis here can see.

fn main() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sqlite = manifest.join("..").join("..").join("vendor").join("sqlite");
    println!("cargo:rerun-if-changed={}", sqlite.display());

    // `SQLITE_THREADSAFE=1` is SQLite's own default and is what Node builds.
    // `SQLITE_OMIT_LOAD_EXTENSION` is deliberately absent: `Database` decides
    // whether to enable extension loading per connection.
    cc::Build::new()
        .include(&sqlite)
        .file(sqlite.join("sqlite3.c"))
        .warnings(false)
        .flag_if_supported("-fvisibility=hidden")
        .define("SQLITE_DEFAULT_MEMSTATUS", "0")
        .define("SQLITE_ENABLE_COLUMN_METADATA", None)
        .define("SQLITE_ENABLE_DBSTAT_VTAB", None)
        .define("SQLITE_ENABLE_FTS3", None)
        .define("SQLITE_ENABLE_FTS3_PARENTHESIS", None)
        .define("SQLITE_ENABLE_FTS5", None)
        .define("SQLITE_ENABLE_GEOPOLY", None)
        .define("SQLITE_ENABLE_MATH_FUNCTIONS", None)
        .define("SQLITE_ENABLE_PERCENTILE", None)
        .define("SQLITE_ENABLE_PREUPDATE_HOOK", None)
        .define("SQLITE_ENABLE_RBU", None)
        .define("SQLITE_ENABLE_RTREE", None)
        .define("SQLITE_ENABLE_SESSION", None)
        .compile("sqlite3");
}

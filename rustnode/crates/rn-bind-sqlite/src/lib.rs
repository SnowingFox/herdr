//! `internalBinding('sqlite')` for rustnode.
//!
//! `vendor/libnode-js/lib/sqlite.js` is 18 lines of unchanged Node code and it
//! is the specification for this crate's shape:
//!
//! ```text
//! const { Database, Statement, Session, constants, backup } =
//!   internalBinding('sqlite');
//! ```
//!
//! Everything else in the namespace is reached through those members'
//! prototypes. That means the contract is small — five names — while the work is
//! almost entirely in the classes, which is the opposite of most namespaces here.
//!
//! Of those five, four are installed and `backup` is declared deferred: the
//! destructure in `lib/sqlite.js` binds `undefined` for it, which is what
//! `require('node:sqlite').backup` reports until [`DEFERRED`] is emptied.
//!
//! # SQLite linkage
//!
//! The amalgamation in `vendor/sqlite` is compiled into this crate by
//! `build.rs`, with the flags `deps/sqlite/sqlite.gyp` uses. It is not the system
//! `libsqlite3`: that is a different version on every host, absent on Windows,
//! and directly observable through `statement.stat()`'s `filterHit`/`filterMiss`
//! counters, `database.limits`' defaults and every error message a test matches
//! on. `vendor/sqlite/README.md` records the reasoning and
//! `tools/verify-sqlite.sh` holds the tree to the pinned revision.
//!
//! # What is implemented
//!
//! End to end: opening an in-memory or file-backed database, `exec`, `prepare`,
//! `run`/`get`/`all`/`iterate`, positional and named parameter binding in every
//! form Node accepts, the full five-type value round trip (including a blob as a
//! `Uint8Array`), transactions with rollback, `close`, `[Symbol.dispose]`,
//! `isOpen`, `isTransaction`, `limits`, `location`, `enableDefensive`,
//! `enableLoadExtension`, `columns`, `stat`, `resetStats`, the four `set*`
//! methods, `sourceSQL`, `expandedSQL`, `Session` with `changeset`/`patchset`, and
//! the `constants` table.
//!
//! # What is deferred, and why
//!
//! Each entry in [`DEFERRED`] names a member and the reason it is absent. The
//! important distinction is that these are *absent*, not silently inert: the
//! contract check reports a declared deferral as a pass, and
//! `tools/deferred-reach.py` proves `lib/**` does not call one while loading.
//! Nothing in `lib/sqlite.js` calls anything at module scope at all — it is a
//! destructure and an export — so the reach check has nothing to catch here, and
//! the deferrals are honestly just gaps.

pub mod accessor;
pub mod constants;
pub mod database;
pub mod db;
pub mod errors;
pub mod ffi;
pub mod iterator;
pub mod limits;
pub mod permission;
pub mod session;
pub mod sqlfn;
pub mod stmt;
pub mod tagstore;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod testsupport;
pub mod url;
pub mod value;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members this crate actually installs, matching `contracts/sqlite.json`.
///
/// `install()` puts exactly these keys on the namespace object. `backup` is
/// deliberately absent: it is declared in [`DEFERRED`] instead. Listing it here
/// as well is what made the contract check report `sqlite` complete while
/// `node:sqlite.backup` was `undefined` — `rn-compat` subtracts a member that
/// appears in `members()` from the gap before it ever consults `deferred()`, so
/// a member that is claimed *and* deferred is only ever checked once, as a
/// claim. `install()` never set it, and nothing compared the built object
/// against this list.
pub const MEMBERS: &[&str] = &["Database", "Session", "Statement", "constants"];

/// Members this namespace needs but does not install, each with the reason.
///
/// `backup` is the only one. It is a separate subsystem — an asynchronous
/// page-by-page copy driven through libuv's threadpool with a progress callback
/// and a promise — and `test-sqlite-backup.mjs` is 448 lines that only that
/// subsystem can satisfy. Shipping a synchronous approximation would answer
/// differently from Node's for every observable: the return type, the progress
/// callback's timing, and the retry behaviour on `SQLITE_BUSY`.
///
/// It is declared here rather than stubbed so the contract check reports it as a
/// known gap instead of a member that exists and lies. `lib/sqlite.js`
/// destructures it at module scope and re-exports it, so
/// `require('node:sqlite').backup` is `undefined` until this is implemented —
/// which is the honest state, and is why the deferral has to be visible to the
/// contract check rather than hidden behind a `MEMBERS` entry.
pub const DEFERRED: &[(&str, &str)] = &[
    (
        "backup",
        "page-wise asynchronous backup with a progress callback and a promise; needs threadpool integration (uv_queue_work plus a promise settled on the loop), and a synchronous stand-in would differ from Node in return type, progress-callback timing and SQLITE_BUSY retries",
    ),
];

/// `internalBinding('sqlite')`.
pub struct Sqlite;

impl BindingModule for Sqlite {
    fn namespace(&self) -> &'static str {
        "sqlite"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        // A namespace is installed once per isolate, so this is where the
        // per-isolate template caches are reset. It matters because those caches
        // are keyed by isolate address, and a new isolate can be allocated at the
        // address a disposed one had; the address check alone cannot tell the
        // two apart, but "install happened again" can.
        session::reset_template_cache();
        limits::reset_template_cache();
        iterator::reset_template_cache();
        stmt::reset_template_cache();
        tagstore::reset_template_cache();

        let object = v8::Object::new(scope);

        let database = database::constructor(scope)?;
        set(scope, object, "Database", database)?;

        let statement = stmt::constructor(scope)?;
        set(scope, object, "Statement", statement)?;

        let session =
            session::constructor(scope).ok_or("cannot allocate the Session constructor")?;
        set(scope, object, "Session", session.into())?;

        let constants = db::constants_object(scope)?;
        set(scope, object, "constants", constants.into())?;

        Ok(object)
    }
}

/// Registers the `sqlite` namespace with the runtime.
///
/// `tools/regen-bindings.sh` discovers this function, so nothing else has to be
/// edited for `internalBinding('sqlite')` to resolve. Note that the name is
/// `register`, not something like `register_classes`: the generator greps for the
/// literal substring `pub fn register` and would miss a longer name.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Sqlite);
}

fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    name: &str,
    value: v8::Local<'_, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    if object.set(scope, key.into(), value).is_none() {
        return Err(format!("cannot define {name}"));
    }
    Ok(())
}

/// The SQLite version this binary links, from `sqlite3_libversion`.
///
/// `process.versions.sqlite` is built from this, and `test/common/index.js`
/// derives `hasSQLite` from that value. Reporting a version the linked library
/// does not actually have would be worse than reporting none: it would enable
/// tests whose expectations belong to a different SQLite.
pub fn sqlite_version() -> Option<String> {
    // SAFETY: `sqlite3_libversion` returns static text for the life of the
    // process.
    let version = unsafe { errors::c_string(ffi::sqlite3_libversion()) };
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

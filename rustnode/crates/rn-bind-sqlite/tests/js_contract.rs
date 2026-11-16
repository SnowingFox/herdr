//! End-to-end tests that drive the installed `sqlite` namespace from JavaScript.
//!
//! `vendor/libnode-js/lib/sqlite.js` does nothing but destructure
//! `internalBinding('sqlite')` and re-export it, so a test that installs that
//! namespace and uses the classes the way `lib/sqlite.js` exposes them is
//! testing the real surface — the argument marshalling, the object templates and
//! the prototype identity the JavaScript layer depends on. Rust-only unit tests
//! cannot reach any of that.
//!
//! # What these pin, and why unit tests missed it
//!
//! `open()` on an already-open database used to close and reopen it, which
//! destroyed every table and row and reported success. The crate's own tests
//! were green because none of them called `open()` twice; only a test driven
//! through the public class can see that. The expected values here were measured
//! against the pinned oracle
//! (`node-v28.0.0-nightly20261111e8c1160d20-linux-x64`), not derived from this
//! implementation.

use std::sync::OnceLock;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_sqlite::Sqlite;

fn initialize_once() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace, runs `source`, and returns `String(__out)`.
fn run(source: &str) -> String {
    initialize_once();
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let mut context_scope = std::pin::pin!(v8::ContextScope::new(scope, context));
    let scope = &mut context_scope;

    let mut async_ids = rn_core::AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let namespace = Sqlite
        .install(scope, &mut ctx)
        .expect("install the sqlite namespace");

    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "sqliteBinding").expect("key");
    global
        .set(scope, key.into(), namespace.into())
        .expect("set");

    let source = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, source, None).expect("compiles");
    script.run(scope).expect("script runs");
    scope.as_mut().perform_microtask_checkpoint();

    let out_key = v8::String::new(scope, "__out").expect("key");
    let out = global.get(scope, out_key.into()).expect("__out");
    out.to_rust_string_lossy(scope)
}

#[test]
fn a_second_open_throws_and_preserves_the_data() {
    // The oracle, verbatim:
    //
    //   $ node -e '…'     → {"before":42,"code":"ERR_INVALID_STATE",
    //                        "message":"database is already open",
    //                        "after":42,"isOpen":true}
    //
    // Reopening instead of throwing answered `{"code":null,…,"after":"LOST:
    // no such table: important"}`: the throw was missing *and* the rows were
    // gone, and `isOpen` still read `true`, so nothing downstream could tell.
    let out = run(r#"
        const { Database } = sqliteBinding;
        const db = new Database(':memory:');
        db.exec('CREATE TABLE important(x)');
        db.exec('INSERT INTO important VALUES (42)');
        const before = db.prepare('SELECT x FROM important').get().x;

        let code = null;
        let message = null;
        try {
          db.open();
        } catch (error) {
          code = error.code;
          message = error.message;
        }

        let after = null;
        try {
          after = db.prepare('SELECT x FROM important').get().x;
        } catch (error) {
          after = 'LOST: ' + error.message;
        }

        let again = null;
        try {
          db.open();
        } catch (error) {
          again = error.code;
        }

        __out = JSON.stringify({
          before, code, message, after, isOpen: db.isOpen, again,
        });
        "#);
    assert_eq!(
        out,
        r#"{"before":42,"code":"ERR_INVALID_STATE","message":"database is already open","after":42,"isOpen":true,"again":"ERR_INVALID_STATE"}"#
    );
}

#[test]
fn a_failed_open_leaves_the_database_closed() {
    // `sqlite3_open_v2` hands back a handle even when it fails, and Node resets
    // it so `isOpen` is false afterwards — `test-sqlite-database.js`,
    // "does not leave the database open after a failed open". Keeping the sick
    // handle made `isOpen` true and turned the next `exec` into a different
    // error (`ERR_SQLITE_ERROR unable to open database file`) where Node reports
    // `ERR_INVALID_STATE database is not open`.
    let out = run(r#"
        const { Database } = sqliteBinding;
        const db = new Database('/nonexistent-rsnode-dir/sub/x.db', { open: false });
        const before = db.isOpen;

        let openCode = null;
        try {
          db.open();
        } catch (error) {
          openCode = error.code;
        }
        const afterFailed = db.isOpen;

        let execCode = null;
        try {
          db.exec('SELECT 1');
        } catch (error) {
          execCode = error.code;
        }

        __out = JSON.stringify({ before, openCode, afterFailed, execCode });
        "#);
    assert_eq!(
        out,
        r#"{"before":false,"openCode":"ERR_SQLITE_ERROR","afterFailed":false,"execCode":"ERR_INVALID_STATE"}"#
    );
}

#[test]
fn create_session_returns_a_working_session() {
    // `createSession()` allocated through `Function::new_instance`, which runs
    // the constructor callback — so the `ERR_ILLEGAL_CONSTRUCTOR` guard that
    // exists to stop `new Session()` fired on the one path meant to succeed, and
    // every call threw. Node allocates from
    // `GetConstructorTemplate(env)->InstanceTemplate()->NewInstance(...)`, which
    // never invokes the callback, and the resulting object *is* a `Session`.
    let out = run(r#"
        const { Database, Session } = sqliteBinding;
        const db = new Database(':memory:');
        db.exec('CREATE TABLE t(a)');
        const session = db.createSession();
        db.exec('INSERT INTO t VALUES (1)');

        const changeset = session.changeset();
        const patchset = session.patchset();

        let constructCode = null;
        try {
          new Session();
        } catch (error) {
          constructCode = error.code;
        }

        session.close();
        let closedCode = null;
        try {
          session.changeset();
        } catch (error) {
          closedCode = error.code;
        }

        __out = JSON.stringify({
          instanceOfSession: session instanceof Session,
          protoIsSessionPrototype: Object.getPrototypeOf(session) === Session.prototype,
          changesetIsUint8Array: changeset instanceof Uint8Array,
          patchsetIsUint8Array: patchset instanceof Uint8Array,
          constructCode,
          closedCode,
        });
        "#);
    // `changeset` is empty because the session was created before the insert on
    // the oracle too; the point is that it is a real `Uint8Array` rather than a
    // throw. The two length-zero results match the oracle exactly.
    assert_eq!(
        out,
        r#"{"instanceOfSession":true,"protoIsSessionPrototype":true,"changesetIsUint8Array":true,"patchsetIsUint8Array":true,"constructCode":"ERR_ILLEGAL_CONSTRUCTOR","closedCode":"ERR_INVALID_STATE"}"#
    );
}

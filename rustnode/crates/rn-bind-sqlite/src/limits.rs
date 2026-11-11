//! The `database.limits` object.
//!
//! `DatabaseLimits` in `src/node_sqlite.cc` is an `ObjectTemplate` with a named
//! property handler: every `Get`/`Set`/`Query` for a name in `kLimitMapping`
//! reads or writes `sqlite3_limit` on the owning connection, unknown names fall
//! through to ordinary property handling, and `LimitsEnumerator` lists the eleven
//! names. `test-sqlite-limits.js` exercises all of it, including that
//! `Infinity` resets a limit to the compile-time maximum.
//!
//! A Rust `ObjectTemplate` cannot carry a state pointer, so the equivalent is
//! built directly: one accessor pair per limit, each carrying its index, plus a
//! non-enumerable own reference to the database object so the accessor can find
//! the connection. That reference is a private symbol, not a string key, because
//! a string key would show up in `Object.keys(db.limits)` and the C++ enumerates
//! only the eleven limit names.

use rn_v8_sys::v8;

use crate::constants;
use crate::db::{self, DatabaseState};
use crate::errors;

/// The private property holding the owning `Database` object.
///
/// A `v8::Private` rather than a symbol or string: it is invisible to
/// `Object.getOwnPropertyNames`, `Object.keys` and `JSON.stringify`, which is
/// what keeps the enumeration equal to the eleven limit names.
const OWNER_PROPERTY: &str = "rustnode.sqlite.limits.owner";

/// Builds the limits object for the connection `state` belongs to.
pub fn build<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    owner: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    for name in constants::LIMITS {
        let key = v8::String::new(scope, name)?;
        // Closures rather than function items: the accessor callback takes its
        // `PropertyCallbackArguments` and `ReturnValue` with two *different*
        // lifetimes, which a `fn` item cannot be generic over.
        object.set_accessor_with_setter(scope, key.into(), limit_get, limit_set);
    }
    // The receiver of a later `db.limits.length` read is the limits object, so
    // it needs a way back to the connection. A `Private` keeps that invisible to
    // `Object.keys`, `getOwnPropertyNames` and `JSON.stringify`, which the C++
    // enumeration relies on: it lists exactly the eleven limit names.
    if let Some(key) = v8::String::new(scope, OWNER_PROPERTY) {
        let private = v8::Private::for_api(scope, Some(key));
        object.set_private(scope, private, owner.into());
    }
    Some(object)
}

/// The `Database` state behind a limits object, or a thrown error.
fn owner_state(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<'_, v8::Object>,
) -> Option<*mut DatabaseState> {
    let key = v8::String::new(scope, OWNER_PROPERTY)?;
    let private = v8::Private::for_api(scope, Some(key));
    let Some(owner) = this.get_private(scope, private) else {
        errors::throw_coded(
            scope,
            "ERR_INVALID_THIS",
            "Value of \"this\" must be a database limits object",
        );
        return None;
    };
    let Ok(owner) = v8::Local::<v8::Object>::try_from(owner) else {
        errors::throw_coded(
            scope,
            "ERR_INVALID_THIS",
            "Value of \"this\" must be a database limits object",
        );
        return None;
    };
    crate::db::state_or_throw(scope, owner)
}

/// The limit index a setter's `name` argument refers to.
///
/// The getter and setter are installed as ordinary method templates, so V8
/// passes no property name: the limit is identified by comparing the *value's*
/// position in `kLimitMapping`, which the caller supplies through the accessor's
/// installed name. `None` means the name is not a limit and the assignment falls
/// through to ordinary property handling.
fn limit_index(scope: &mut v8::PinScope<'_, '_>, name: v8::Local<'_, v8::Name>) -> Option<usize> {
    let name = name.to_rust_string_lossy(scope);
    constants::LIMITS.iter().position(|limit| *limit == name)
}

/// A limit getter: `sqlite3_limit(connection, id, -1)`.
fn limit_get(
    scope: &mut v8::PinScope<'_, '_>,
    name: v8::Local<'_, v8::Name>,
    info: v8::PropertyCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(index) = limit_index(scope, name) else {
        return;
    };
    let Some(state) = owner_state(scope, info.holder()) else {
        return;
    };
    // SAFETY: `owner_state` returned a live pointer for the database object the
    // limits object roots; nothing below re-enters JavaScript.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    let value = state.current_limits()[index];
    rv.set(v8::Integer::new(scope, value).into());
}

/// A limit setter, which also refuses inside an authorizer callback.
fn limit_set(
    scope: &mut v8::PinScope<'_, '_>,
    name: v8::Local<'_, v8::Name>,
    value: v8::Local<'_, v8::Value>,
    info: v8::PropertyCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_, ()>,
) {
    let Some(index) = limit_index(scope, name) else {
        return;
    };
    let Some(state) = owner_state(scope, info.holder()) else {
        return;
    };
    // SAFETY: `owner_state` returned a live pointer; the borrow ends before
    // `limit_value`, which can throw.
    let (open, authorizer) = unsafe {
        let state = &*state;
        (state.is_open(), state.authorizer_depth)
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
    let Some(limit) = db::limit_value(scope, value) else {
        return;
    };
    // SAFETY: as above.
    unsafe { (*state).set_limit(index, limit) };
}

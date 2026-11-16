//! The `database.limits` object.
//!
//! `DatabaseLimits` in `src/node_sqlite.cc` is an `ObjectTemplate` with a named
//! property handler: every `Get`/`Set`/`Query` for a name in `kLimitMapping`
//! reads or writes `sqlite3_limit` on the owning connection, unknown names fall
//! through to ordinary property handling, and `LimitsEnumerator` lists the eleven
//! names. `test-sqlite-limits.js` exercises all of it, including that
//! `Infinity` resets a limit to the compile-time maximum.
//!
//! # Why an interceptor, and not one accessor per limit
//!
//! The previous implementation installed eleven accessor pairs directly on a
//! plain `Object::new` with `set_accessor_with_setter`. Every limit *read* the
//! right number, which is why it looked correct, but the object it produced was
//! not Node's object and four things were observable:
//!
//! * A member's descriptor reported `configurable: true`. Node's `LimitsQuery`
//!   answers `DontDelete`, so `configurable` is `false`.
//! * `delete db.limits.length` removed the member for good, and the next read was
//!   `undefined`. In Node there is no own property to remove: the interceptor
//!   answers from `sqlite3_limit` every time, so the member is still there.
//! * `Object.defineProperty(db.limits, 'length', …)` replaced the limit with a
//!   dead data property. In Node there is no definer, so it throws.
//! * The instance's prototype was `Object.prototype`. A template's instance gets
//!   the template's own prototype object, which is what Node's
//!   `ObjectTemplate::New(isolate)` produces.
//!
//! All four are the same root cause: a snapshot of data properties standing in
//! for a live view of the connection. This is the `URLPattern` defect one layer
//! down — there, `set_accessor_with_setter` produced a lazy data property whose
//! value had been computed at install time; here it produces a data property that
//! a caller can delete or replace, detaching the object from `sqlite3_limit`
//! without any error.
//!
//! The template is cached per isolate, as `env->sqlite_limits_template()` caches
//! it, because that is observable: two databases from one realm hand back limits
//! objects that share a prototype and a constructor.

use rn_v8_sys::v8;

use crate::constants;
use crate::db::{self, DatabaseState};
use crate::errors;

/// The private property holding the owning `Database` object.
///
/// A `v8::Private` rather than a symbol or string: it is invisible to
/// `Object.getOwnPropertyNames`, `Object.keys` and `JSON.stringify`, which is
/// what keeps the enumeration equal to the eleven limit names. Private keys are
/// also never routed to a named interceptor, which is what lets the interceptor
/// below answer for string names only.
const OWNER_PROPERTY: &str = "rustnode.sqlite.limits.owner";

thread_local! {
    /// The one limits `ObjectTemplate` this isolate uses, and the isolate it
    /// belongs to.
    ///
    /// The address is stored beside it because a process runs more than one
    /// isolate on one thread, and a disposed isolate's address can be reused by
    /// the next one; handing a cached template across that boundary would read
    /// freed memory. It is only ever compared, never dereferenced — the same
    /// guard `session.rs` uses for its constructor template.
    static TEMPLATE: std::cell::RefCell<Option<CachedTemplate>> =
        const { std::cell::RefCell::new(None) };
}

/// A limits template belonging to one isolate, by address.
struct CachedTemplate {
    isolate: usize,
    template: v8::Global<v8::ObjectTemplate>,
}

/// Drops the cached template, called once per namespace install.
pub fn reset_template_cache() {
    TEMPLATE.with(|slot| *slot.borrow_mut() = None);
}

/// The `ObjectTemplate` every limits object in this isolate is built from.
fn template<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::ObjectTemplate>> {
    let address = crate::session::isolate_address(scope);
    let cached = TEMPLATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|cached| cached.isolate == address)
            .map(|cached| cached.template.clone())
    });
    if let Some(template) = cached {
        return Some(v8::Local::new(scope, template));
    }

    let template = v8::ObjectTemplate::new(scope);
    // `DatabaseLimits::GetTemplate` installs exactly these handlers and passes
    // `kHasNoSideEffect`. The flag is not decoration: without it V8 refuses to
    // run the getter from a context that has side effects disabled, which
    // `util.inspect` and a `--frozen-intrinsics` snapshot both do.
    template.set_named_property_handler(
        v8::NamedPropertyHandlerConfiguration::new()
            .getter(limit_get)
            .setter(limit_set)
            .query(limit_query)
            .enumerator(limit_enumerate)
            .flags(v8::PropertyHandlerFlags::HAS_NO_SIDE_EFFECT),
    );

    TEMPLATE.with(|slot| {
        *slot.borrow_mut() = Some(CachedTemplate {
            isolate: address,
            template: v8::Global::new(scope, template),
        });
    });
    Some(template)
}

/// Builds the limits object for the connection `state` belongs to.
pub fn build<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    owner: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = template(scope)?.new_instance(scope)?;
    // The receiver of a later `db.limits.length` read is the limits object, so
    // it needs a way back to the connection. A `Private` keeps that invisible to
    // `Object.keys`, `getOwnPropertyNames` and `JSON.stringify`, which the C++
    // enumeration relies on: it lists exactly the eleven limit names.
    let key = v8::String::new(scope, OWNER_PROPERTY)?;
    let private = v8::Private::for_api(scope, Some(key));
    object.set_private(scope, private, owner.into());
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

/// The limit index a property name refers to.
///
/// `LimitsGetter` and friends run `FindByJsName(kLimitMapping, …)` and report
/// `kNo` for anything else, which is what lets an unknown name behave like an
/// ordinary property on the object. `None` is that `kNo`.
fn limit_index(scope: &mut v8::PinScope<'_, '_>, name: v8::Local<'_, v8::Name>) -> Option<usize> {
    let value: v8::Local<'_, v8::Value> = name.into();
    // `LimitsGetter` starts with `if (!property->IsString()) return kNo;`, so a
    // symbol is never a limit name and must fall through rather than be coerced.
    if value.is_symbol() {
        return None;
    }
    let name = name.to_rust_string_lossy(scope);
    constants::LIMITS.iter().position(|limit| *limit == name)
}

/// `DatabaseLimits::LimitsGetter`: `sqlite3_limit(connection, id, -1)`.
fn limit_get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: v8::Local<'s, v8::Name>,
    info: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) -> v8::Intercepted {
    let Some(index) = limit_index(scope, name) else {
        return v8::Intercepted::kNo;
    };
    let Some(state) = owner_state(scope, info.holder()) else {
        return v8::Intercepted::kYes;
    };
    // SAFETY: `owner_state` returned a live pointer for the database object the
    // limits object roots; nothing below re-enters JavaScript.
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return v8::Intercepted::kYes;
    }
    let value = state.current_limits()[index];
    rv.set(v8::Integer::new(scope, value).into());
    v8::Intercepted::kYes
}

/// `DatabaseLimits::LimitsSetter`, which also refuses inside an authorizer
/// callback.
fn limit_set<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: v8::Local<'s, v8::Name>,
    value: v8::Local<'s, v8::Value>,
    info: v8::PropertyCallbackArguments<'s>,
    _rv: v8::ReturnValue<'_, v8::Boolean>,
) -> v8::Intercepted {
    let Some(index) = limit_index(scope, name) else {
        return v8::Intercepted::kNo;
    };
    let Some(state) = owner_state(scope, info.holder()) else {
        return v8::Intercepted::kYes;
    };
    // SAFETY: `owner_state` returned a live pointer; the borrow ends before
    // `limit_value`, which can throw.
    let (open, authorizer) = unsafe {
        let state = &*state;
        (state.is_open(), state.authorizer_depth)
    };
    if !errors::require(scope, open, "database is not open") {
        return v8::Intercepted::kYes;
    }
    if !errors::require(
        scope,
        authorizer == 0,
        "database cannot be accessed from an authorizer callback",
    ) {
        return v8::Intercepted::kYes;
    }
    let Some(limit) = db::limit_value(scope, value) else {
        return v8::Intercepted::kYes;
    };
    // SAFETY: as above.
    unsafe { (*state).set_limit(index, limit) };
    v8::Intercepted::kYes
}

/// `DatabaseLimits::LimitsQuery`.
///
/// Answering `DontDelete` for a known name is what makes the member's descriptor
/// `configurable: false` and, in turn, what makes `delete` a no-op and
/// `Object.defineProperty` throw. Reporting `kNo` for an unknown name is what
/// keeps this object an ordinary extensible object for everything else.
fn limit_query<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: v8::Local<'s, v8::Name>,
    _info: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Integer>,
) -> v8::Intercepted {
    let Some(_index) = limit_index(scope, name) else {
        return v8::Intercepted::kNo;
    };
    // `Integer::New(isolate, v8::PropertyAttribute::DontDelete)`: the query
    // answers with the attribute bits, not a boolean.
    rv.set(v8::Integer::new(
        scope,
        v8::PropertyAttribute::DONT_DELETE.as_u32() as i32,
    ));
    v8::Intercepted::kYes
}

/// `DatabaseLimits::LimitsEnumerator`: the eleven names, in `kLimitMapping`
/// order.
fn limit_enumerate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _info: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Array>,
) {
    let array = v8::Array::new(scope, constants::LIMITS.len() as i32);
    for (index, name) in constants::LIMITS.iter().enumerate() {
        let Some(value) = v8::String::new(scope, name) else {
            return;
        };
        array.set_index(scope, index as u32, value.into());
    }
    rv.set(array);
}

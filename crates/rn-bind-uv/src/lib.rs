//! `internalBinding('uv')` for rustnode.
//!
//! This namespace is what Node's error machinery stands on. `lib/internal/errors.js`
//! reads it on the first error it builds (`lazyUv`, `uvErrmapGet`) and every
//! module above `internal/util` transitively depends on that, so nothing in the
//! standard library loads until this exists.
//!
//! Three functions and ninety-three constants, exactly as `src/uv.cc`'s
//! `Initialize()` registers them:
//!
//! * `errname(errno)` — libuv's name for a negative error code, e.g. `ENOENT`.
//! * `getErrorMap()` — a `Map` from each code to `[name, message]`. This is the
//!   object `lib/internal/errors.js` reverse-indexes; its `uvErrmapGet` looks up
//!   `ctx.errno` in it to build `UVException` messages.
//! * `getErrorMessage(errno)` — libuv's human-readable text for a code.
//!
//! # Why the strings are a table and not a libuv call
//!
//! Node calls `uv_strerror_r` and `uv_err_name_r`. rustnode reproduces their
//! output from a table generated out of libuv's own headers
//! (`tools/generate.py`, `tools/uv-headers/`), which is the same source libuv
//! compiles its own switch statement from.
//!
//! Linking libuv instead would buy ~100 strings at the price of a C library
//! dependency in a workspace that otherwise has none: `rn-io` reaches libuv
//! through `libc` today, and nothing else here links it. Every platform would
//! need libuv built and shipped alongside `herdr`, and the strings would still
//! come from the same header this crate already vendors. The table is also
//! checkable in a way a linked call is not — `tests/constants.rs` re-derives
//! every value from the headers and from `libc` at test time, so a transcription
//! error fails the build rather than silently producing the wrong `errno`.
//!
//! # Deliberate deviation: `errname` does not abort
//!
//! `src/uv.cc` opens both functions with `CHECK_LT(err, 0)`, so a non-negative
//! argument kills the process. rustnode returns what libuv's own function would
//! have written for that argument (`Unknown system error 0`) instead. Nothing in
//! `lib/**` can reach `errname` — `util.getSystemErrorName` validates the range
//! in JavaScript and reads the map, not this function — so the difference is
//! only reachable from user code that was crashing under Node anyway.

mod generated;

pub use generated::{UvError, DIRENT, ERRORS, MEMBERS, UV_CC_REGISTRATIONS};

use std::borrow::Cow;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The prefix Node puts in front of each map entry to form the property name.
const PREFIX: &str = "UV_";

/// `uv_strerror`'s text for `errno`.
///
/// This is libuv's `uv_strerror_r`: a table lookup, falling back to
/// `Unknown system error <n>` for anything the map does not name. The fallback is
/// libuv's own wording and is what `util.getSystemErrorMessage` surfaces for
/// codes outside the table.
pub fn message(errno: i32) -> Cow<'static, str> {
    match by_value(errno) {
        Some(error) => Cow::Borrowed(error.message),
        None => Cow::Owned(unknown(errno)),
    }
}

/// `uv_err_name`'s text for `errno`, which is the map entry without its `UV_`
/// prefix.
///
/// Same fallback as [`message`], again matching libuv.
pub fn name(errno: i32) -> Cow<'static, str> {
    match by_value(errno) {
        Some(error) => Cow::Borrowed(error.name),
        None => Cow::Owned(unknown(errno)),
    }
}

/// The map entry for `errno`, or `None` when libuv has no such error.
pub fn by_value(errno: i32) -> Option<&'static UvError> {
    ERRORS.iter().find(|error| error.value == errno)
}

/// The map entry whose name is `name`, without the `UV_` prefix.
pub fn by_name(name: &str) -> Option<&'static UvError> {
    ERRORS.iter().find(|error| error.name == name)
}

/// libuv's placeholder text for an error code it does not know.
///
/// `uv__unknown_err_code` writes this with `snprintf` into a 32-byte buffer, so
/// a long enough number would truncate there; an `i32` cannot, which is why this
/// formats without a length limit.
fn unknown(errno: i32) -> String {
    format!("Unknown system error {errno}")
}

/// `internalBinding('uv')`.
pub struct Uv;

impl BindingModule for Uv {
    fn namespace(&self) -> &'static str {
        "uv"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        // `src/uv.cc` uses `SetConstructorFunction` for `errname` and `SetMethod`
        // for the other two, which is observable: only `errname` is constructible
        // and only `errname` has a `prototype`. `lib/**` never constructs it, but
        // user code reaching through `process.binding('uv')` can tell.
        let errname = constructor(scope, "errname", errname_callback)?;
        // `SetMethod` creates a zero-length internalized name and assigns it to
        // the function, so `fn.name` and `fn.length` are both observable.
        let get_error_map = method(scope, "getErrorMap", get_error_map_callback)?;
        let get_error_message = method(scope, "getErrorMessage", get_error_message_callback)?;

        // Node installs `errname` first, then the constants in map order, then
        // the two methods, and `Object.keys()` exposes that sequence.
        set(scope, object, "errname", errname)?;
        for error in ERRORS {
            let property = format!("{PREFIX}{}", error.name);
            let value = v8::Integer::new(scope, error.value);
            define_constant(scope, object, &property, value.into())?;
        }
        for (dirent_name, dirent_value) in DIRENT {
            let value = v8::Integer::new(scope, *dirent_value);
            define_constant(scope, object, dirent_name, value.into())?;
        }
        set(scope, object, "getErrorMap", get_error_map)?;
        set(scope, object, "getErrorMessage", get_error_message)?;

        Ok(object)
    }
}

/// Registers the `uv` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Uv);
}

fn errname_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(errno) = int32_arg(scope, &args) else {
        return;
    };
    let name = name(errno);
    set_string(scope, &mut rv, &name);
}

fn get_error_message_callback(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(errno) = int32_arg(scope, &args) else {
        return;
    };
    let message = message(errno);
    set_string(scope, &mut rv, &message);
}

/// Builds the `Map` of `errno -> [name, message]`.
///
/// Node creates a fresh `Map` on every call, and so must this: `errors.js`
/// caches the first result on the binding object as `uvBinding.errmap`, and any
/// later caller is entitled to its own copy.
fn get_error_map_callback(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let map = v8::Map::new(scope);
    for error in ERRORS {
        let key = v8::Integer::new(scope, error.value).into();
        let Some(name) = v8::String::new(scope, error.name) else {
            return;
        };
        let Some(message) = v8::String::new(scope, error.message) else {
            return;
        };
        // The entry is `[name, message]`, which `errors.js` destructures as
        // `const { 0: code, 1: uvmsg } = ...`.
        let entry = v8::Array::new_with_elements(scope, &[name.into(), message.into()]);
        if map.set(scope, key, entry.into()).is_none() {
            return;
        }
    }
    rv.set(map.into());
}

/// Reads argument 0 as an `i32`.
///
/// Node casts with `args[0].As<v8::Int32>()`, which reinterprets whatever was
/// passed; going through `int32_value` instead converts as JavaScript does. That
/// is why a missing argument reads as `0` and `errname(-2.5)` reads as `-2`
/// rather than as whatever bits were in the slot, and it is the same value
/// `util.getSystemErrorName`'s range check would have seen. A value that cannot
/// convert at all (`Symbol`, a throwing `valueOf`) leaves `rv` untouched, which
/// is the `undefined` Node's `As<Int32>` would produce.
fn int32_arg(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
) -> Option<i32> {
    args.get(0).int32_value(scope)
}

/// Defines one `UV_*` constant.
///
/// `src/uv.cc` defines these with `ReadOnly | DontDelete` — not `DONT_ENUM` — so
/// they appear in `Object.keys()` and cannot be reassigned or deleted.
fn define_constant(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .define_own_property(
            scope,
            key.into(),
            value,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
        )
        .ok_or_else(|| format!("cannot define constant {name}"))?;
    Ok(())
}

/// Creates a non-constructible function, matching `node::SetMethod`.
///
/// `ConstructorBehavior::Throw` is what makes `new binding.getErrorMap()` a
/// `TypeError` and leaves `binding.getErrorMap.prototype` undefined, both of
/// which real Node does.
fn method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate uv.{name}"))?;
    // `NODE_SET_METHOD` compatibility: the property name is also the function's
    // own `name`.
    if let Some(text) = v8::String::new(scope, name) {
        function.set_name(text);
    }
    Ok(function.into())
}

/// Creates a constructible function with a class name, matching
/// `node::SetConstructorFunction(..., SET_CLASS_NAME)`.
fn constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback)
        .length(0)
        .build(scope);
    let Some(text) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the name of uv.{name}"));
    };
    template.set_class_name(text);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate uv.{name}"))?;
    function.set_name(text);
    Ok(function.into())
}

fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn set_string(scope: &mut v8::PinScope<'_, '_>, rv: &mut v8::ReturnValue, value: &str) {
    if let Some(text) = v8::String::new(scope, value) {
        rv.set(text.into());
    }
}

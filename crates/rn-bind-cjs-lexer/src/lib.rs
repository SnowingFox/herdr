//! `internalBinding('cjs_lexer')` for rustnode.
//!
//! One member, from `contracts/cjs_lexer.json`:
//!
//! ```text
//! parse(source) -> [Set of export names, Array of reexport specifiers]
//! ```
//!
//! `lib/internal/modules/esm/translators.js` destructures `parse` at module
//! scope, so until this namespace existed `require('module')` threw outright.
//! The answer it produces also outlives that call: it is the export list an
//! ESM `import` of a CommonJS file observes, so a wrong answer is not an error
//! anywhere, it is just a different module.
//!
//! # The lexer is merve
//!
//! Node answers this with `deps/merve`, a C++ lexer, and the patterns it has to
//! get right are subtle in the way that invites a wrong reimplementation. The
//! ones below were recorded from a real Node binary, and several of them are
//! the opposite of what a plausible hand-written rule would do:
//!
//! * `exports.foo = ...` and `module.exports.foo = ...` are exports;
//!   `exports.foo.bar = ...` is not, because the assignment lands on `foo`.
//! * `module.exports = { a, b }` exports `a` and `b` — shorthand only.
//!   `module.exports = { a: 1 }` exports nothing, because a named property with
//!   a value cannot be reduced to an export statement.
//! * `Object.defineProperty(exports, 'name', ...)` exports `name` when it
//!   carries a `value`, but not when it carries a getter.
//! * `__esModule` *is* reported as an export. It is an ordinary property on
//!   `exports` as far as this analysis is concerned.
//! * `module.exports = require('./other')`, `{ ...require('./other') }` and
//!   `__export(require('./other'))` produce *reexport specifiers* rather than
//!   names, because the names live in the other module. The
//!   `Object.keys(require(...)).forEach` idiom does not.
//! * ESM syntax anywhere means the analysis fails, which Node reports as an
//!   empty result rather than as an error.
//!
//! Every one of those is a rule merve gets right and an approximation would get
//! wrong, which is why `vendor/merve` holds the lexer byte-identical from the
//! pinned Node revision and [`ffi`] is the only code that talks to it. What this
//! crate owns is the V8 glue: turning merve's two lists into the `[Set, Array]`
//! pair Node builds, with the same handling of missing, `null` and unparseable
//! input.
//!
//! # What is copied from `src/node_cjs_lexer.cc`
//!
//! * A missing argument, `null` and `undefined` all return a fresh empty `Set`
//!   and a fresh empty `Array` rather than throwing.
//! * A failed parse returns the same empty pair — `parse` never throws, because
//!   the callers load the module next and want their own error to be the one the
//!   user sees.
//! * Names are created as internalized strings. Node uses `kInternalized` so
//!   repeated loads of a module reuse the same strings, and it matters more here
//!   than it looks: these names are compared against property keys.
//! * A name that cannot be turned into a V8 string is dropped, not fatal. The
//!   only way that happens is allocation failure, and the alternative is
//!   discarding an entire analysis over one name.
//! * A non-string argument is a `CHECK` failure in Node, i.e. a crash. This
//!   implementation reports a `TypeError` instead: a crash is not a behaviour
//!   worth reproducing, and `lib/**` only ever passes a string.

pub mod ffi;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/cjs_lexer.json`.
pub const MEMBERS: &[&str] = &["parse"];

/// merve version `vendor/merve` is copied from.
///
/// `vendor/merve/include/merve.h` declares this and `tools/verify-merve.sh`
/// pins the sources; the test in [`tests`] asserts the linked library agrees, so
/// a stale build cache cannot silently analyse with a different lexer.
pub const MERVE_VERSION: &str = "1.2.2";

/// `internalBinding('cjs_lexer')`.
pub struct CjsLexer;

impl BindingModule for CjsLexer {
    fn namespace(&self) -> &'static str {
        "cjs_lexer"
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
        let parse = v8::Function::new(scope, parse).ok_or("cannot allocate cjs_lexer.parse")?;
        let key = v8::String::new(scope, "parse").ok_or("cannot allocate cjs_lexer.parse key")?;
        if object.set(scope, key.into(), parse.into()) != Some(true) {
            return Err("cannot install cjs_lexer.parse".to_string());
        }
        Ok(object)
    }
}

/// Registers the `cjs_lexer` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(CjsLexer);
}

/// `parse(source)`.
///
/// Returns `[Set, Array]`, matching `src/node_cjs_lexer.cc`.
fn parse<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `args.length()` is the count the caller actually passed, so a missing
    // argument is distinguishable from an explicit `undefined`. Node treats
    // both, and `null`, as "nothing to analyse", and so does this.
    let value = args.get(0);
    if args.length() < 1 || value.is_null_or_undefined() {
        rv.set(empty_result(scope).into());
        return;
    }

    if !value.is_string() {
        // Node `CHECK`s here and aborts the process. Throwing keeps the mistake
        // visible without turning a caller bug into a crash.
        throw_type_error(scope, "The \"source\" argument must be of type string");
        return;
    }

    let source = value
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope));
    let Some(source) = source else {
        // `ToString` on a string cannot really fail, but if it does the honest
        // answer is the same one a failed analysis gives.
        rv.set(empty_result(scope).into());
        return;
    };

    let Some(parsed) = ffi::parse_commonjs(&source) else {
        rv.set(empty_result(scope).into());
        return;
    };

    let exports = v8::Set::new(scope);
    for name in &parsed.exports {
        let Some(name) = internalized(scope, name) else {
            // Node drops a name it cannot allocate rather than failing the
            // whole analysis; see the module docs.
            continue;
        };
        // `Set::add` returns `None` only if the addition threw, which would
        // mean the isolate is in a state where the whole result is suspect.
        // Node answers `undefined` in that case; there is no useful partial
        // answer here either, but a `Set` missing one name is a more honest
        // failure than a `parse` that returns nothing at all.
        let _ = exports.add(scope, name.into());
    }

    let mut reexports = Vec::with_capacity(parsed.reexports.len());
    for specifier in &parsed.reexports {
        if let Some(specifier) = internalized(scope, specifier) {
            reexports.push(specifier.into());
        }
    }

    let values: [v8::Local<v8::Value>; 2] = [
        exports.into(),
        v8::Array::new_with_elements(scope, &reexports).into(),
    ];
    rv.set(v8::Array::new_with_elements(scope, &values).into());
}

/// `[new Set(), []]`, the shape every "nothing found" path returns.
fn empty_result<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Array> {
    let values: [v8::Local<v8::Value>; 2] =
        [v8::Set::new(scope).into(), v8::Array::new(scope, 0).into()];
    v8::Array::new_with_elements(scope, &values)
}

/// A V8 string from UTF-8 bytes, internalized.
///
/// Node uses `String::NewFromOneByte(..., kInternalized)` for ASCII names and
/// `NewFromUtf8(..., kInternalized)` otherwise. `NewFromUtf8` with
/// `kInternalized` produces the same string contents for ASCII input, so one
/// path covers both and the bytes merve produced are the bytes that are used.
fn internalized<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    text: &str,
) -> Option<v8::Local<'s, v8::String>> {
    v8::String::new_from_utf8(scope, text.as_bytes(), v8::NewStringType::Internalized)
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let error = v8::Exception::type_error(scope, message);
    scope.throw_exception(error);
}

#[cfg(test)]
mod tests;

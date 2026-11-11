//! The per-context objects Node's `internal/per_context/**` scripts run against.
//!
//! `InitializePrimordials` in `src/api/environment.cc` does three things before
//! it runs a single line of per-context JavaScript:
//!
//! 1. builds the `primordials` object with a null prototype,
//! 2. builds `privateSymbols` from `PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES`,
//! 3. builds `perIsolateSymbols` from `PER_ISOLATE_SYMBOL_PROPERTIES`,
//!
//! and then calls each file in `internal/per_context/` with
//! `(exports, primordials, privateSymbols, perIsolateSymbols)`. It publishes the
//! resulting `exports` object on the context under the private key
//! `node:per_context_binding_exports`, which is how `GetPerContextExports` — and
//! therefore every native path that needs `DOMException`, `QuotaExceededError`
//! or `emitMessage` — finds them again without a second implementation.
//!
//! # Why this module exists
//!
//! The two symbol objects are the part of that sequence that is easy to fake.
//! Anything can be passed in their place and the scripts still *run*: a missing
//! entry leaves the destructured binding `undefined`, and `object[undefined]`
//! writes the **string** key `"undefined"`. In `domexception.js` that is fatal
//! rather than cosmetic, because it defines two methods on one prototype
//! (`[messaging_clone_symbol]` and `[messaging_deserialize_symbol]`) and with
//! both symbols missing the second silently overwrites the first. The
//! `DOMException` that results looks plausible and clones nothing.
//!
//! So the two objects are built here, from the one table each, and every caller
//! that needs them asks for the same construction rather than making an empty
//! object that satisfies the argument count.

use rn_v8_sys::v8;

use crate::PRIVATE_SYMBOLS;

/// The private key Node stores the per-context exports under.
///
/// `Private::ForApi` with this name, not a symbol and not a string: it has to be
/// invisible to JavaScript and stable across the two callers that look it up.
pub const PER_CONTEXT_EXPORTS: &str = "node:per_context_binding_exports";

/// Sets an object's prototype to `null`, the way Node builds all three of these.
fn null_prototype(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) {
    // A failure here would mean the object is not extensible, which cannot happen
    // for one this module just created; the prototype is cosmetic anyway.
    let _ = object.set_prototype(scope, v8::null(scope).into());
}

/// Builds `privateSymbols`: every `PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES` entry.
///
/// Keys are Node's C++ member names, values are the shared identities from
/// [`crate::symbol`], so a script that writes `object[sym]` here and a binding
/// that reads it there are using the same key. `util.privateSymbols` publishes
/// the identical table, which is why both go through this function.
pub fn private_symbols_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    for (name, description) in PRIVATE_SYMBOLS {
        let symbol = crate::symbol(scope, description);
        let key = v8::String::new(scope, name)
            .ok_or_else(|| format!("cannot allocate the private symbol key {name}"))?;
        object.set(scope, key.into(), symbol.into());
    }
    null_prototype(scope, object);
    Ok(object)
}

/// Builds `perIsolateSymbols`: every `PER_ISOLATE_SYMBOL_PROPERTIES` entry,
/// keyed by its description.
///
/// `ObjectTemplate::Set(isolate, #PropertyName, isolate_data->PropertyName())`
/// in `environment.cc` uses the *member* name, but the same table feeds
/// `node_symbols.cc`, which keys `internalBinding('symbols')` by the
/// *description*. `domexception.js` destructures `messaging_clone_symbol` and
/// `messaging_deserialize_symbol` from this object, and both descriptions equal
/// their member names, so either spelling would work for it; the description is
/// the one that also matches what `internalBinding('symbols')` publishes, so
/// there is one spelling in the process instead of two.
pub fn per_isolate_symbols_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    for (_, description) in crate::PER_ISOLATE_SYMBOLS {
        let symbol = crate::symbol(scope, description);
        let key = v8::String::new(scope, description)
            .ok_or_else(|| format!("cannot allocate the per-isolate symbol key {description}"))?;
        object.set(scope, key.into(), symbol.into());
    }
    null_prototype(scope, object);
    Ok(object)
}

/// The stored per-context exports object, if the per-context scripts have run.
pub fn per_context_exports<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Object>> {
    let key = private_key(scope, PER_CONTEXT_EXPORTS)?;
    let global = scope.get_current_context().global(scope);
    let value = global.get_private(scope, key)?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

/// Stores the per-context exports object, the way `GetPerContextExports` does.
///
/// Returns the reason it could not be stored so a bootstrap that silently lost
/// them fails where it can name the cause, rather than leaving every later
/// `GetPerContextExports` to answer "not there yet".
pub fn set_per_context_exports(
    scope: &mut v8::PinScope<'_, '_>,
    exports: v8::Local<v8::Object>,
) -> Result<(), String> {
    let key =
        private_key(scope, PER_CONTEXT_EXPORTS).ok_or("cannot allocate the exports private key")?;
    let global = scope.get_current_context().global(scope);
    match global.set_private(scope, key, exports.into()) {
        Some(true) => Ok(()),
        _ => Err("cannot store the per-context exports on the context".to_string()),
    }
}

/// `v8::Private::ForApi` for `name`, the only key form that is invisible to JS.
pub fn private_key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::Private>> {
    let name = v8::String::new(scope, name)?;
    Some(v8::Private::for_api(scope, Some(name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exports_key_is_the_name_node_uses() {
        // `src/api/environment.cc` looks this string up verbatim; a rename here is
        // a silent "the per-context exports do not exist" in every native caller.
        assert_eq!(PER_CONTEXT_EXPORTS, "node:per_context_binding_exports");
    }
}

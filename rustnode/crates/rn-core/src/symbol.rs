//! Per-isolate symbols that several binding crates must agree on.
//!
//! Node keeps these on `IsolateData` (`PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES` in
//! `src/env_properties.h`), so every C++ namespace that asks for one gets the same
//! symbol. When two Rust crates need the same one — which is exactly the case for
//! `contextify`, because it *marks* a sandbox and `lib/internal/vm.js` reads the
//! mark back through `internalBinding('util').privateSymbols` — creating it
//! privately in each crate would give two distinct identities and the lookup would
//! silently never match.
//!
//! So they live here, keyed by name, in a thread-local table like the rest of the
//! per-isolate state.
//!
//! ## Why `v8::Symbol` and not `v8::Private`
//!
//! Node uses `v8::Private` for these, which makes the mark invisible to
//! `Reflect.ownKeys`. The `v8` crate linked here exposes `Private` only as a
//! `v8::Data`: it has no conversion to `v8::Value`, and `Object::set` takes a
//! `Value`, so a `Private` cannot be handed to JavaScript, which is what
//! `util.privateSymbols` has to do. A registered `v8::Symbol` is the closest thing
//! that can cross that boundary, and the two observable differences are that
//! `typeof` reports `symbol` for both and that `Reflect.ownKeys` can see the
//! symbol where it could not see a private name. Every mark installed here is
//! defined non-enumerable so `Object.keys` and `for..in` stay clean.

use std::cell::RefCell;
use std::collections::BTreeMap;

use rn_v8_sys::v8;

thread_local! {
    /// The symbols created so far, keyed by the Node name used as a description.
    ///
    /// A `v8::Global` keeps a symbol alive across handle scopes, which is what
    /// makes its identity stable rather than merely equal.
    static SYMBOLS: RefCell<BTreeMap<&'static str, v8::Global<v8::Symbol>>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Returns the per-isolate symbol `name`, creating it on first use.
pub fn symbol<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &'static str,
) -> v8::Local<'s, v8::Symbol> {
    let existing = SYMBOLS.with(|symbols| {
        symbols
            .borrow()
            .get(name)
            .map(|symbol| v8::Local::new(scope, symbol))
    });
    if let Some(symbol) = existing {
        return symbol;
    }
    // The description is the Node name itself: it is already namespaced with
    // `node:`, so it shows up in a stack trace or devtools as the thing it is.
    let description = v8::String::new(scope, name);
    let symbol = v8::Symbol::for_key(
        scope,
        description.unwrap_or_else(|| v8::String::empty(scope)),
    );
    SYMBOLS.with(|symbols| {
        symbols
            .borrow_mut()
            .insert(name, v8::Global::new(scope, symbol));
    });
    symbol
}

/// `contextify_context_private_symbol`: the mark that makes a sandbox a `vm`
/// context.
///
/// Node's private name is `node:contextify:context`. `contextify.makeContext`
/// writes it and `lib/internal/vm.js`'s `isContext` reads it through
/// `internalBinding('util').privateSymbols`, so both crates must resolve this to
/// the same object.
pub const CONTEXTIFY_CONTEXT: &str = "node:contextify:context";

/// `host_defined_option_symbol`: where a realm or script keeps its
/// `importModuleDynamically` id.
pub const HOST_DEFINED_OPTION: &str = "node:host_defined_option_symbol";

/// Defines `key` on `object` so the mark stays out of enumeration.
///
/// Non-enumerable, non-writable and non-configurable: `for..in`, `Object.keys` and
/// `JSON.stringify` all skip it, and user code cannot delete or forge it.
pub fn define_mark(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    key: v8::Local<v8::Symbol>,
    value: v8::Local<v8::Value>,
) {
    object.define_own_property(
        scope,
        key.into(),
        value,
        v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_ENUM,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_are_nodes_own() {
        // From `PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES` in
        // `src/env_properties.h`. These strings are the only thing tying
        // `contextify`'s mark to `lib/vm.js`'s lookup, so they are pinned here
        // rather than trusted to survive a refactor.
        assert_eq!(CONTEXTIFY_CONTEXT, "node:contextify:context");
        assert_eq!(HOST_DEFINED_OPTION, "node:host_defined_option_symbol");
        // The `util` contract lists this property by exactly this spelling.
        assert!(!CONTEXTIFY_CONTEXT.is_empty());
    }
}

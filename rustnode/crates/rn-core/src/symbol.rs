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

/// Every `PER_ISOLATE_PRIVATE_SYMBOL_PROPERTIES` entry, as
/// `(the name `util.privateSymbols` exposes, Node's description)`.
///
/// Copied from `src/env_properties.h` at the pinned revision. The exposed name
/// is the C++ member, and the description is the string Node passes to
/// `v8::Private::ForApi`, which is *not* always the member name: `napi_type_tag`
/// is described as `node:napi:type_tag`.
///
/// `lib/**` destructures these by exposed name and then uses the symbol as a
/// property key, so a missing entry is not an error it can report: the
/// destructured binding is `undefined`, `object[undefined]` collapses every
/// missing symbol onto the single string key `"undefined"`, and the read back
/// later returns whatever the last write happened to leave there. That is
/// exactly how `require()` lost its source text: `loader.js` writes
/// `module[kModuleSource]` and `loadSource()` reads it as a cache, so with
/// `kModuleSource` undefined a child module saw its *parent* object as its own
/// source and the compile step received a `Module` where a string belonged.
pub const PRIVATE_SYMBOLS: &[(&str, &str)] = &[
    ("arrow_message_private_symbol", "node:arrowMessage"),
    (
        "contextify_context_private_symbol",
        "node:contextify:context",
    ),
    ("decorated_private_symbol", "node:decorated"),
    (
        "empty_context_frame_sentinel_symbol",
        "node:empty_context_frame_sentinel",
    ),
    (
        "ffi_pointer_address_private_symbol",
        "node:ffi:pointer_address",
    ),
    ("transfer_mode_private_symbol", "node:transfer_mode"),
    (
        "host_defined_option_symbol",
        "node:host_defined_option_symbol",
    ),
    (
        "js_transferable_wrapper_private_symbol",
        "node:js_transferable_wrapper",
    ),
    (
        "entry_point_module_private_symbol",
        "node:entry_point_module",
    ),
    (
        "entry_point_promise_private_symbol",
        "node:entry_point_promise",
    ),
    ("module_source_private_symbol", "node:module_source"),
    (
        "module_export_names_private_symbol",
        "node:module_export_names",
    ),
    (
        "module_circular_visited_private_symbol",
        "node:module_circular_visited",
    ),
    ("module_export_private_symbol", "node:module_export"),
    (
        "module_first_parent_private_symbol",
        "node:module_first_parent",
    ),
    (
        "module_last_parent_private_symbol",
        "node:module_last_parent",
    ),
    ("napi_type_tag", "node:napi:type_tag"),
    ("napi_wrapper", "node:napi:wrapper"),
    (
        "untransferable_object_private_symbol",
        "node:untransferableObject",
    ),
    ("exit_info_private_symbol", "node:exit_info_private_symbol"),
    ("promise_trace_id", "node:promise_trace_id"),
    (
        "source_map_data_private_symbol",
        "node:source_map_data_private_symbol",
    ),
];

/// Every `PER_ISOLATE_SYMBOL_PROPERTIES` entry, as
/// `(the C++ member name, the description `internalBinding('symbols')` exposes)`.
///
/// Copied from `src/env_properties.h` at the pinned revision. Three descriptions
/// differ from the member name — `handle_onclose_symbol` is described
/// `handle_onclose` — because `node_symbols.cc` keys the namespace by the
/// *description*, so `internalBinding('symbols').handle_onclose` is the exposed
/// spelling while `env->handle_onclose_symbol()` is the C++ member.
///
/// These are identities, not names. `lib/internal/worker/js_transferable.js`
/// writes an object mark under `messaging_clone_symbol` and `node_messaging.cc`
/// reads it back, and `internal/per_context/domexception.js` defines one method
/// per symbol on a single prototype, so a table that handed out a fresh symbol
/// per call — or that omitted an entry — would make the write invisible to the
/// read. Both consumers resolve through [`symbol`], which is what keeps them
/// agreeing.
pub const PER_ISOLATE_SYMBOLS: &[(&str, &str)] = &[
    ("fs_use_promises_symbol", "fs_use_promises_symbol"),
    ("async_id_symbol", "async_id_symbol"),
    ("ffi_sb_shared_buffer_symbol", "ffi_sb_shared_buffer_symbol"),
    ("ffi_sb_invoke_slow_symbol", "ffi_sb_invoke_slow_symbol"),
    ("ffi_sb_arguments_symbol", "ffi_sb_arguments_symbol"),
    ("ffi_sb_return_symbol", "ffi_sb_return_symbol"),
    ("constructor_key_symbol", "constructor_key_symbol"),
    ("handle_onclose_symbol", "handle_onclose"),
    ("no_message_symbol", "no_message_symbol"),
    (
        "messaging_deserialize_symbol",
        "messaging_deserialize_symbol",
    ),
    ("imported_cjs_symbol", "imported_cjs_symbol"),
    ("messaging_transfer_symbol", "messaging_transfer_symbol"),
    ("messaging_clone_symbol", "messaging_clone_symbol"),
    (
        "messaging_transfer_list_symbol",
        "messaging_transfer_list_symbol",
    ),
    ("oninit_symbol", "oninit"),
    ("owner_symbol", "owner_symbol"),
    ("onpskexchange_symbol", "onpskexchange"),
    ("resource_symbol", "resource_symbol"),
    ("trigger_async_id_symbol", "trigger_async_id_symbol"),
    (
        "builtin_source_text_module_hdo",
        "builtin_source_text_module_hdo",
    ),
    ("embedder_module_hdo", "embedder_module_hdo"),
    (
        "source_text_module_default_hdo",
        "source_text_module_default_hdo",
    ),
    ("vm_context_no_contextify", "vm_context_no_contextify"),
    (
        "vm_dynamic_import_default_internal",
        "vm_dynamic_import_default_internal",
    ),
    (
        "vm_dynamic_import_main_context_default",
        "vm_dynamic_import_main_context_default",
    ),
    (
        "vm_dynamic_import_missing_flag",
        "vm_dynamic_import_missing_flag",
    ),
    (
        "vm_dynamic_import_no_callback",
        "vm_dynamic_import_no_callback",
    ),
];

/// Returns the per-isolate symbol described as `description`, creating it once.
///
/// The description is the identity, because that is what
/// `PER_ISOLATE_SYMBOL_PROPERTIES` passes to `v8::Symbol` in Node and what the
/// table above records for both symbol properties. Two names may share a
/// description in Node's table — they never do — so this is safe, and a caller
/// that has only the exposed name (rather than the description) should look it up
/// through [`per_isolate_symbol`].
pub fn symbol_by_description<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    description: &'static str,
) -> v8::Local<'s, v8::Symbol> {
    symbol(scope, description)
}

/// The description `internalBinding('symbols')` exposes as `name`, if any.
///
/// Node's `node_symbols.cc` sets each property of that namespace under
/// `env->PropertyName()->Description(...)`, **not** under the C++ member name, so
/// the exposed spelling is whatever `PER_ISOLATE_SYMBOL_PROPERTIES` passes as the
/// second tuple element. Three members rename themselves that way —
/// `handle_onclose_symbol` is exposed as `handle_onclose` — and `io.js`
/// destructures `handle_onclose`, so a table keyed by the member name installs
/// `handle_onclose_symbol` and leaves the destructured binding `undefined`.
///
/// That `undefined` then became the property key in
/// `ObjectDefineProperty(MessagePort.prototype, handleOnCloseSymbol, ...)`, which
/// is a `TypeError` at module scope: `undefined` has no descriptor to redefine.
pub fn per_isolate_symbol_description(name: &str) -> Option<&'static str> {
    PER_ISOLATE_SYMBOLS
        .iter()
        .find(|(_, description)| *description == name)
        .map(|(_, description)| *description)
}

/// The per-isolate symbol `internalBinding('symbols')` exposes as `name`.
///
/// Returns `None` for a name outside [`PER_ISOLATE_SYMBOLS`]: that is a
/// programming mistake rather than a runtime condition, and answering with a
/// fresh symbol would be the silent-identity bug the table exists to prevent.
pub fn per_isolate_symbol<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::Symbol>> {
    let description = per_isolate_symbol_description(name)?;
    Some(symbol(scope, description))
}

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

    #[test]
    fn every_contract_private_symbol_is_in_the_table() {
        // `contracts/util.json` is the recorded shape of
        // `internalBinding('util').privateSymbols`, recorded from the pinned Node
        // binary. A name in the contract but not in the table is the defect this
        // table exists to prevent: `lib/**` destructures it, gets `undefined`, and
        // then collapses every missing name onto the string key `"undefined"`.
        //
        // Read the contract here rather than hard-code the list, so a re-pin that
        // adds a private symbol fails this test instead of silently leaving the
        // new name uninstalled.
        let contract = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/util.json"),
        )
        .expect("contracts/util.json is readable");
        let contract: serde_json::Value =
            serde_json::from_str(&contract).expect("contracts/util.json is valid JSON");
        let recorded = contract["members"]["privateSymbols"]["properties"]
            .as_array()
            .expect("privateSymbols records a property list");

        let installed: Vec<&str> = PRIVATE_SYMBOLS.iter().map(|(name, _)| *name).collect();
        let mut missing: Vec<&str> = Vec::new();
        for name in recorded {
            let name = name.as_str().expect("a property name is a string");
            if !installed.contains(&name) {
                missing.push(name);
            }
        }
        assert!(
            missing.is_empty(),
            "private symbols recorded in the contract but not installed: {missing:?}"
        );
        assert_eq!(
            installed.len(),
            recorded.len(),
            "the table must not install names the contract does not record"
        );
    }

    #[test]
    fn the_exposed_names_are_unique() {
        // A duplicate would install one symbol under two names, so a write through
        // one would be visible through the other. Node's table has no duplicate
        // members; this catches a copy error in the table above.
        let mut names: Vec<&str> = PRIVATE_SYMBOLS.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "a private symbol name is duplicated");

        let mut descriptions: Vec<&str> = PRIVATE_SYMBOLS
            .iter()
            .map(|(_, description)| *description)
            .collect();
        descriptions.sort_unstable();
        let before = descriptions.len();
        descriptions.dedup();
        assert_eq!(
            before,
            descriptions.len(),
            "two private symbols share a description, so they would resolve to one identity"
        );
    }

    #[test]
    fn every_contract_per_isolate_symbol_is_in_the_table() {
        // `contracts/symbols.json` is the recorded shape of
        // `internalBinding('symbols')`. The same argument as the private table
        // applies, one step worse: `internal/per_context/domexception.js`
        // defines `[messaging_clone_symbol]` and `[messaging_deserialize_symbol]`
        // on one prototype, so two missing entries collapse onto the string key
        // `"undefined"` and the second method silently replaces the first.
        let contract = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/symbols.json"),
        )
        .expect("contracts/symbols.json is readable");
        let contract: serde_json::Value =
            serde_json::from_str(&contract).expect("contracts/symbols.json is valid JSON");
        let recorded = contract["members"]
            .as_object()
            .expect("the symbols contract has a members object");

        // The namespace is keyed by *description*, so that is the spelling the
        // contract records and the one to compare against.
        let installed: Vec<&str> = PER_ISOLATE_SYMBOLS
            .iter()
            .map(|(_, description)| *description)
            .collect();
        let mut missing: Vec<&str> = Vec::new();
        for name in recorded.keys() {
            if !installed.contains(&name.as_str()) {
                missing.push(name.as_str());
            }
        }
        assert!(
            missing.is_empty(),
            "per-isolate symbols recorded in the contract but not installed: {missing:?}"
        );
        assert_eq!(
            installed.len(),
            recorded.len(),
            "the table must not install names the contract does not record"
        );
    }

    #[test]
    fn the_per_isolate_table_has_no_collapsing_identities() {
        // Two entries with the same description would be one `v8::Symbol`, so a
        // write through `messaging_clone_symbol` would be readable as
        // `messaging_deserialize_symbol`. Node's table has no such pair.
        let mut descriptions: Vec<&str> = PER_ISOLATE_SYMBOLS
            .iter()
            .map(|(_, description)| *description)
            .collect();
        let total = descriptions.len();
        descriptions.sort_unstable();
        descriptions.dedup();
        assert_eq!(
            total,
            descriptions.len(),
            "two per-isolate symbols share a description, so they are one identity"
        );
        // And the descriptions are what Node passes to `v8::Symbol`, so they must
        // all be non-empty or two of them would collapse anyway.
        assert!(
            PER_ISOLATE_SYMBOLS
                .iter()
                .all(|(_, description)| !description.is_empty()),
            "an empty description makes every such symbol the same identity"
        );
    }

    #[test]
    fn the_per_isolate_lookup_reaches_every_recorded_name() {
        // `per_isolate_symbol` is what `internalBinding('symbols')` uses, and
        // `internal/per_context/domexception.js` destructures two of these names
        // from `perIsolateSymbols`. A description in the table that the lookup
        // cannot resolve would be a member the namespace claims and never
        // installs — or installs under a name `lib/**` never destructures.
        for (member, description) in PER_ISOLATE_SYMBOLS {
            assert_eq!(
                per_isolate_symbol_description(description),
                Some(*description),
                "the lookup does not reach the exposed name {description} \
                 (member {member})"
            );
        }
        assert_eq!(per_isolate_symbol_description("not_a_symbol"), None);
        // The three whose member name and exposed name differ, pinned so a copy
        // error cannot silently rename `internalBinding('symbols')`'s
        // `handle_onclose` into `handle_onclose_symbol`.
        assert_eq!(
            per_isolate_symbol_description("handle_onclose"),
            Some("handle_onclose")
        );
        assert_eq!(per_isolate_symbol_description("oninit"), Some("oninit"));
        assert_eq!(
            per_isolate_symbol_description("onpskexchange"),
            Some("onpskexchange")
        );
        // And the C++ spellings are genuinely not exposed: `io.js` destructures
        // `handle_onclose`, so resolving the member name would install a property
        // nothing asks for.
        assert_eq!(
            per_isolate_symbol_description("handle_onclose_symbol"),
            None
        );
    }
}

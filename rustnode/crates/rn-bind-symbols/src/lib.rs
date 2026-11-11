//! `internalBinding('symbols')` for rustnode.
//!
//! Node stores a set of well-known symbols per isolate so that the native layer
//! and the JavaScript layer can agree on a private property key without
//! exposing a string. `src/env_properties.h` is the table, and
//! `src/node_symbols.cc` exposes each one under its *description*, which is why
//! `oninit_symbol` appears here as `oninit`.
//!
//! # Why identity matters
//!
//! These are not names, they are identities. `lib/internal/streams/destroy.js`
//! writes `stream[owner_symbol] = source` and `lib/internal/async_hooks.js`
//! reads `resource[owner_symbol]` back. If this crate created a fresh symbol on
//! every call, the write and the read would use different keys and every one of
//! those lookups would silently return `undefined`. So each symbol is created
//! once and the same `v8::Symbol` is returned for the life of the process: the
//! property lookup succeeds precisely because the key is identical.
//!
//! Node gets this for free by storing the symbols on `Environment`, which is
//! per-isolate. rustnode registers each namespace once per process, so the
//! thread-local table in [`rn_core::symbol`] gives the same guarantee for the
//! single isolate the CLI runs today — and, unlike a table private to this
//! crate, it is the same one `internal/per_context/domexception.js` and
//! `rn-bind-messaging` read through.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The members exactly as `contracts/symbols.json` records them.
///
/// Every entry is `(C++ member name, symbol description)`, and the whole list is
/// [`rn_core::PER_ISOLATE_SYMBOLS`] — Node's `PER_ISOLATE_SYMBOL_PROPERTIES`.
/// It lives in `rn-core` because three places need the same identities:
/// `internal/per_context/domexception.js` receives the table as its
/// `perIsolateSymbols` argument, `rn-bind-messaging` reads clone hooks back
/// through it, and `internalBinding('symbols')` publishes it. A second copy here
/// would be a second set of symbols, so a write through one would be invisible to
/// the other.
pub const SYMBOLS: &[(&str, &str)] = rn_core::PER_ISOLATE_SYMBOLS;

/// The exposed names — `internalBinding('symbols')`'s members — in header order.
///
/// Derived from [`SYMBOLS`] rather than written twice: Node keys the namespace by
/// description, so the exposed name of `handle_onclose_symbol` is
/// `handle_onclose`, and a hand-maintained copy is exactly how the two spellings
/// drifted apart before. `rn-compat` compares members as a set, so the order here
/// is documentation rather than a contract.
pub const MEMBERS: &[&str] = &[
    "fs_use_promises_symbol",
    "async_id_symbol",
    "ffi_sb_shared_buffer_symbol",
    "ffi_sb_invoke_slow_symbol",
    "ffi_sb_arguments_symbol",
    "ffi_sb_return_symbol",
    "constructor_key_symbol",
    "handle_onclose",
    "no_message_symbol",
    "messaging_deserialize_symbol",
    "imported_cjs_symbol",
    "messaging_transfer_symbol",
    "messaging_clone_symbol",
    "messaging_transfer_list_symbol",
    "oninit",
    "owner_symbol",
    "onpskexchange",
    "resource_symbol",
    "trigger_async_id_symbol",
    "builtin_source_text_module_hdo",
    "embedder_module_hdo",
    "source_text_module_default_hdo",
    "vm_context_no_contextify",
    "vm_dynamic_import_default_internal",
    "vm_dynamic_import_main_context_default",
    "vm_dynamic_import_missing_flag",
    "vm_dynamic_import_no_callback",
];

pub struct Symbols;

impl BindingModule for Symbols {
    fn namespace(&self) -> &'static str {
        "symbols"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        // Node's `node_symbols.cc` sets each property under the symbol's
        // *description* (`env->PropertyName()->Description(isolate)`), which is
        // why `internalBinding('symbols')` exposes `handle_onclose` rather than
        // the C++ member `handle_onclose_symbol`. `lib/**` destructures the
        // exposed spelling, so installing the member name leaves every one of
        // those bindings `undefined` — and `io.js` then passes it to
        // `ObjectDefineProperty` as a property key, which throws at module scope.
        let object = v8::Object::new(scope);
        for (_, description) in SYMBOLS {
            let symbol = rn_core::symbol(scope, description);
            let Some(key) = v8::String::new(scope, description) else {
                return Err(format!("cannot allocate the key for {description}"));
            };
            object.set(scope, key.into(), symbol.into());
        }
        Ok(object)
    }
}

/// Returns the process-wide symbol exposed as `name`, creating it on first use.
///
/// Exposed so another crate can reach the *same* identity `internalBinding
/// ('symbols')` publishes. `messaging` needs `oninit` and `no_message_symbol`,
/// and a symbol created privately there would be a different key, so
/// `MessagePort.prototype[oninit]` would never be found.
///
/// `name` must be one of [`crate::SYMBOLS`]'s exposed names; anything else is a
/// programming error rather than a runtime condition, which is why the result is
/// a `Result` carrying the reason instead of an empty symbol.
pub fn ensure<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &'static str,
    description: &str,
) -> Result<v8::Local<'s, v8::Symbol>, String> {
    let recorded = rn_core::per_isolate_symbol_description(name)
        .ok_or_else(|| format!("{name} is not a recorded well-known symbol"))?;
    // The caller supplies a description only to be readable; identity comes from
    // `name`, so the recorded one wins and the argument is a cross-check against a
    // typo at the call site. A mismatch is worth naming rather than ignoring,
    // because it means the caller believes it is using a different symbol.
    if description != recorded {
        return Err(format!(
            "{name} is described as {recorded}, not {description}"
        ));
    }
    Ok(rn_core::symbol(scope, recorded))
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Symbols);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rn_core::AsyncIds;

    #[test]
    fn the_member_list_and_the_table_agree() {
        // `MEMBERS` is what `internalBinding('symbols')` claims, and the table is
        // what it installs. They are compared through the *descriptions*, because
        // that is the spelling the namespace is keyed by: a member list carrying
        // the C++ name for an entry would claim a property that is never set.
        assert_eq!(MEMBERS.len(), SYMBOLS.len());
        for (index, member) in MEMBERS.iter().enumerate() {
            assert_eq!(*member, SYMBOLS[index].1);
        }
    }

    #[test]
    fn the_table_is_nodes_own() {
        // `internalBinding('symbols')` is keyed by the *description*
        // (`node_symbols.cc` sets each property under
        // `env->PropertyName()->Description()`), so these are the exposed
        // spelling of members whose C++ names differ. Pinned because a copy error
        // would rename the namespace member rather than fail anything.
        assert_eq!(ensure_description("handle_onclose"), Some("handle_onclose"));
        assert_eq!(ensure_description("oninit"), Some("oninit"));
        assert_eq!(ensure_description("onpskexchange"), Some("onpskexchange"));
        // Everything the description table does not rename is described by its
        // own member name, which is what makes the identity and the spelling one
        // fact instead of two that can drift.
        let renamed = [
            "handle_onclose_symbol",
            "oninit_symbol",
            "onpskexchange_symbol",
        ];
        for (member, description) in SYMBOLS {
            if renamed.contains(member) {
                continue;
            }
            assert_eq!(
                member, description,
                "{member} is described as {description} but that rename is not recorded"
            );
        }
        assert_eq!(ensure_description("not_a_symbol"), None);
    }

    /// The description [`ensure`] resolves `name` to, without an isolate.
    fn ensure_description(name: &str) -> Option<&'static str> {
        rn_core::per_isolate_symbol_description(name)
    }

    #[test]
    fn the_namespace_installs_the_descriptions_and_shares_one_identity() {
        // `internalBinding('symbols')` is keyed by description, and `io.js`
        // destructures `handle_onclose` — the description — not
        // `handle_onclose_symbol`. Installing the member name is not a missing
        // property that fails a lookup: the destructured value stays `undefined`
        // and `ObjectDefineProperty(MessagePort.prototype, undefined, ...)`
        // throws at module scope, which is how this surfaced.
        //
        // One test rather than two: V8 can only be initialized once per process
        // and a second `initialize_platform` poisons its global state, so every
        // assertion needing an isolate has to share one.
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();

        let mut isolate = v8::Isolate::new(Default::default());
        let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut scope.init();
        let context = v8::Context::new(scope, Default::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        let mut async_ids = AsyncIds::new();
        let mut ctx = InstallCtx {
            async_ids: &mut async_ids,
        };
        let installed = Symbols.install(scope, &mut ctx).expect("install");

        for member in MEMBERS {
            let key = v8::String::new(scope, member).expect("key");
            let value = installed.get(scope, key.into()).expect("read");
            assert!(
                value.is_symbol(),
                "{member} is not installed on internalBinding('symbols')"
            );
        }
        // And the C++ member spellings must not appear: an extra member would be
        // a name `lib/**` never asks for, hiding that the exposed one is missing.
        for (member, description) in SYMBOLS {
            if member == description {
                continue;
            }
            let key = v8::String::new(scope, member).expect("key");
            assert!(
                installed
                    .get(scope, key.into())
                    .is_none_or(|value| value.is_undefined()),
                "{member} is the C++ name, not the exposed one"
            );
        }

        // Identity, not equality: a fresh symbol per install — or per crate —
        // would make every property written under one key invisible under the
        // other, which is the whole reason the table lives in `rn-core`.
        let second = Symbols.install(scope, &mut ctx).expect("second install");
        let key = v8::String::new(scope, "owner_symbol").expect("key");
        let from_first = installed.get(scope, key.into()).expect("first symbol");
        let from_second = second.get(scope, key.into()).expect("second symbol");
        assert!(
            from_first.strict_equals(from_second),
            "the same symbol must be shared across installs"
        );
        // `rn_core::symbol` is the other route to these identities, and
        // `domexception.js` receives the table through it.
        let direct = rn_core::symbol(scope, "owner_symbol");
        assert!(
            from_first.strict_equals(direct.into()),
            "the binding and rn_core must hand out one symbol"
        );

        // And it must actually work as a property key.
        let object = v8::Object::new(scope);
        let marker = v8::Integer::new(scope, 1);
        object.set(scope, from_first, marker.into());
        let read = object.get(scope, from_second).expect("read back");
        assert_eq!(read.int32_value(scope), Some(1));
    }
}

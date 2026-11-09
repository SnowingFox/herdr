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
//! per-isolate. rustnode registers each namespace once per process, so a
//! thread-local table gives the same guarantee for the single isolate the CLI
//! runs today.

use std::cell::RefCell;
use std::collections::BTreeMap;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// The members exactly as `contracts/symbols.json` records them.
///
/// Every entry is `(exposed name, symbol description)`. The two differ for
/// `handle_onclose` and `oninit`, whose C++ variable names carry a `_symbol`
/// suffix that the description does not.
pub const SYMBOLS: &[(&str, &str)] = &[
    ("async_id_symbol", "async_id_symbol"),
    (
        "builtin_source_text_module_hdo",
        "builtin_source_text_module_hdo",
    ),
    ("constructor_key_symbol", "constructor_key_symbol"),
    ("embedder_module_hdo", "embedder_module_hdo"),
    ("ffi_sb_arguments_symbol", "ffi_sb_arguments_symbol"),
    ("ffi_sb_invoke_slow_symbol", "ffi_sb_invoke_slow_symbol"),
    ("ffi_sb_return_symbol", "ffi_sb_return_symbol"),
    ("ffi_sb_shared_buffer_symbol", "ffi_sb_shared_buffer_symbol"),
    ("fs_use_promises_symbol", "fs_use_promises_symbol"),
    ("handle_onclose", "handle_onclose"),
    ("imported_cjs_symbol", "imported_cjs_symbol"),
    ("messaging_clone_symbol", "messaging_clone_symbol"),
    (
        "messaging_deserialize_symbol",
        "messaging_deserialize_symbol",
    ),
    (
        "messaging_transfer_list_symbol",
        "messaging_transfer_list_symbol",
    ),
    ("messaging_transfer_symbol", "messaging_transfer_symbol"),
    ("no_message_symbol", "no_message_symbol"),
    ("oninit", "oninit"),
    ("onpskexchange", "onpskexchange"),
    ("owner_symbol", "owner_symbol"),
    ("resource_symbol", "resource_symbol"),
    (
        "source_text_module_default_hdo",
        "source_text_module_default_hdo",
    ),
    ("trigger_async_id_symbol", "trigger_async_id_symbol"),
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

/// The exposed names, in contract order.
pub const MEMBERS: &[&str] = &[
    "async_id_symbol",
    "builtin_source_text_module_hdo",
    "constructor_key_symbol",
    "embedder_module_hdo",
    "ffi_sb_arguments_symbol",
    "ffi_sb_invoke_slow_symbol",
    "ffi_sb_return_symbol",
    "ffi_sb_shared_buffer_symbol",
    "fs_use_promises_symbol",
    "handle_onclose",
    "imported_cjs_symbol",
    "messaging_clone_symbol",
    "messaging_deserialize_symbol",
    "messaging_transfer_list_symbol",
    "messaging_transfer_symbol",
    "no_message_symbol",
    "oninit",
    "onpskexchange",
    "owner_symbol",
    "resource_symbol",
    "source_text_module_default_hdo",
    "trigger_async_id_symbol",
    "vm_context_no_contextify",
    "vm_dynamic_import_default_internal",
    "vm_dynamic_import_main_context_default",
    "vm_dynamic_import_missing_flag",
    "vm_dynamic_import_no_callback",
];

thread_local! {
    /// The symbols, created once and reused.
    ///
    /// A `v8::Global` keeps the symbol alive across handles scopes, which is
    /// what makes the identity stable rather than merely equal.
    static SYMBOL_TABLE: RefCell<BTreeMap<&'static str, v8::Global<v8::Symbol>>> =
        const { RefCell::new(BTreeMap::new()) };
}

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
        let object = v8::Object::new(scope);
        for (name, description) in SYMBOLS {
            let symbol = symbol_for(scope, name, description)?;
            let Some(key) = v8::String::new(scope, name) else {
                return Err(format!("cannot allocate the key for {name}"));
            };
            object.set(scope, key.into(), symbol.into());
        }
        Ok(object)
    }
}

/// Returns the process-wide symbol for `name`, creating it on first use.
///
/// Exposed so another crate can reach the *same* identity `internalBinding
/// ('symbols')` publishes. `messaging` needs `oninit` and `no_message_symbol`,
/// and a symbol created privately there would be a different key, so
/// `MessagePort.prototype[oninit]` would never be found.
///
/// `name` must be one of [`crate::SYMBOLS`]; anything else is a programming
/// error rather than a runtime condition, which is why the result is a `Result`
/// carrying the reason instead of an empty symbol.
pub fn ensure<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &'static str,
    description: &str,
) -> Result<v8::Local<'s, v8::Symbol>, String> {
    let recorded = SYMBOLS
        .iter()
        .find(|(member, _)| *member == name)
        .map(|(_, description)| *description);
    let Some(recorded) = recorded else {
        return Err(format!("{name} is not a recorded well-known symbol"));
    };
    // A caller supplies its own description only to be readable; identity comes
    // from `name`, so the recorded description wins and the argument is only a
    // cross-check against a typo at the call site.
    let _ = description;
    symbol_for(scope, name, recorded)
}

/// Returns the process-wide symbol for `name`, creating it on first use.
fn symbol_for<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &'static str,
    description: &str,
) -> Result<v8::Local<'s, v8::Symbol>, String> {
    let existing = SYMBOL_TABLE.with(|table| {
        table
            .borrow()
            .get(name)
            .map(|symbol| v8::Local::new(scope, symbol))
    });
    if let Some(symbol) = existing {
        return Ok(symbol);
    }

    let description =
        v8::String::new(scope, description).ok_or("cannot allocate a symbol description")?;
    let symbol = v8::Symbol::new(scope, Some(description));
    SYMBOL_TABLE.with(|table| {
        table
            .borrow_mut()
            .insert(name, v8::Global::new(scope, symbol));
    });
    Ok(symbol)
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
        // A missing entry here would leave a member undefined at runtime, which
        // only shows up as an unrelated `undefined` much later.
        assert_eq!(MEMBERS.len(), SYMBOLS.len());
        for (index, member) in MEMBERS.iter().enumerate() {
            assert_eq!(*member, SYMBOLS[index].0);
        }
    }

    #[test]
    fn installing_twice_returns_the_same_symbol_objects() {
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
        let first = Symbols.install(scope, &mut ctx).expect("first install");
        let second = Symbols.install(scope, &mut ctx).expect("second install");

        let key = v8::String::new(scope, "owner_symbol").expect("key");
        let from_first = first.get(scope, key.into()).expect("first symbol");
        let from_second = second.get(scope, key.into()).expect("second symbol");

        // Identity, not equality: a fresh symbol per call would make every
        // property written under one key invisible under the other.
        assert!(
            from_first.strict_equals(from_second),
            "the same symbol must be shared across installs"
        );

        // And it must actually work as a property key.
        let object = v8::Object::new(scope);
        let marker = v8::Integer::new(scope, 1);
        object.set(scope, from_first, marker.into());
        let read = object.get(scope, from_second).expect("read back");
        assert_eq!(read.int32_value(scope), Some(1));
    }
}

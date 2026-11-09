//! `internalBinding('serdes')` for rustnode.
//!
//! `lib/v8.js` is the only consumer, and it reads exactly two constructors from
//! here: `Serializer` and `Deserializer`. They wrap V8's own
//! `ValueSerializer`/`ValueDeserializer`, so `v8.serialize()` and
//! `v8.deserialize()` produce and consume Node's wire format rather than a
//! rustnode-local one. `lib/internal/error_serdes.js` then builds on that, and
//! `internalBinding('messaging')`'s `structuredClone` already round-trips through
//! the same machinery.
//!
//! # Why this is not a second serializer
//!
//! `crates/rn-bind-messaging` already drives `ValueSerializer`/`ValueDeserializer`
//! for `structuredClone` and for `MessagePort` payloads. What it does *not* do is
//! hand the object to JavaScript: its serializer is a stack object owned by one
//! native call. Here the serializer has to live as long as a JavaScript object,
//! because `lib/v8.js` interleaves native writes with JavaScript callbacks:
//!
//! ```js
//! const ser = new DefaultSerializer();
//! ser.writeHeader();
//! ser.writeValue(value);     // may call back into `_writeHostObject`
//! return ser.releaseBuffer();
//! ```
//!
//! So the shape is the one `src/node_serdes.cc` uses: a Rust object behind an
//! internal field, a `Global` keeping it alive, and a guaranteed finalizer that
//! drops it. The V8 calls it makes are the same ones the messaging crate makes.
//!
//! # The delegate is the JavaScript object
//!
//! Node's `SerializerContext` is itself the `ValueSerializer::Delegate`, and each
//! hook reads a method off the JavaScript object and calls it:
//!
//! | hook | JavaScript method |
//! | --- | --- |
//! | `ThrowDataCloneError` | `_getDataCloneError(message)`, called as a constructor |
//! | `WriteHostObject` | `_writeHostObject(object)` |
//! | `GetSharedArrayBufferId` | `_getSharedArrayBufferId(sab)`, when defined |
//! | `ReadHostObject` | `_readHostObject()` |
//!
//! That indirection is the whole point of the namespace: `DefaultSerializer`
//! subclasses `Serializer` and overrides `_writeHostObject` to serialize
//! `Buffer`s by value instead of by their pooled backing store. A Rust delegate
//! that decided for itself would break the subclass.
//!
//! # Deferred
//!
//! `Serializer._getDataCloneError` is assigned by `lib/v8.js` after the
//! constructors are installed, so it is a JavaScript property rather than a
//! namespace member; nothing is deferred here.

mod delegate;
mod deserializer;
mod ipc;
mod serializer;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub use delegate::ErrorKind;

/// Members exposed on the namespace object, matching `contracts/serdes.json`.
pub const MEMBERS: &[&str] = &["Deserializer", "Serializer"];

/// Members this build does not install yet.
///
/// Empty: both recorded members are installed.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('serdes')`.
pub struct Serdes;

impl BindingModule for Serdes {
    fn namespace(&self) -> &'static str {
        "serdes"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        // `src/node_serdes.cc` installs `Serializer` first and `Deserializer`
        // second, and `Object.keys()` on the namespace exposes that order.
        let serializer = serializer::install(scope)?;
        set(scope, object, "Serializer", serializer)?;
        let deserializer = deserializer::install(scope)?;
        set(scope, object, "Deserializer", deserializer)?;

        Ok(object)
    }
}

/// Registers the `serdes` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Serdes);
    // `ipc_serdes` is a second namespace rather than a member of `serdes`: Node
    // declares it separately in `src/node_ipc_serdes.cc`, `lib/**` binds it by
    // that name, and `rn-compat` checks each namespace against its own contract.
    registry.register_module(ipc::IpcSerdes);
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

#[cfg(test)]
mod tests {
    use rn_core::BindingModule;

    use super::*;

    #[test]
    fn the_member_list_is_the_contract() {
        assert_eq!(MEMBERS.len(), 2);
        assert_eq!(Serdes.members(), MEMBERS);
        assert!(Serdes.deferred().is_empty());
    }

    #[test]
    fn every_contract_member_is_installed() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/serdes.json"))
                .expect("the serdes contract parses");
        let recorded = contract["members"]
            .as_object()
            .expect("the contract has a members object");
        for member in recorded.keys() {
            assert!(
                MEMBERS.contains(&member.as_str()),
                "{member} is in the contract but not installed"
            );
        }
        assert_eq!(recorded.len(), MEMBERS.len());
    }
}

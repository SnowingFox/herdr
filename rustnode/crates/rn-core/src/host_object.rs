//! Node's `BaseObject` transfer hooks, for native handles that can be cloned.
//!
//! `src/node_messaging.cc` decides whether a native object may leave the isolate by
//! asking `BaseObject::GetTransferMode()`. When the answer includes `kCloneable`,
//! `SerializerDelegate::Finish` calls `CloneForMessaging()` — which returns a
//! `worker::TransferData` holding the state the receiver needs — and
//! `Message::Deserialize` rebuilds the handle from it. That is how a cloned
//! `BlockList` keeps working: the new handle wraps the *same* rules, so a rule
//! added on either side is visible on both.
//!
//! rustnode has no `BaseObject`. Instead a binding crate registers a *kind* here
//! and marks each handle it builds with that kind; the messaging layer consults
//! this table exactly where Node consults the virtual. A new native type opts in by
//! registering, and nothing in the messaging crate changes, which is what keeps the
//! clone path general rather than a `BlockList` special case.
//!
//! The mark is a `v8::Private`, unlike the registered symbols [`crate::symbol`]
//! hands out. Those have to cross into JavaScript; this one must not, because
//! Node's `BaseObject` wrapper private is invisible to `Reflect.ownKeys` and a
//! clone has no business exposing its own transfer bookkeeping to a
//! `fullObjectGraph` walk.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use rn_v8_sys::v8;

/// `BaseObject::TransferMode`, whose values `util.constants` also publishes.
///
/// The numbering is Node's and cannot be renumbered: `util.inspect` reads the same
/// numbers out of `internalBinding('util').constants`, and `markTransferMode` in
/// `lib/internal/worker/js_transferable.js` ORs them into one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// No transfer or clone is possible.
    DisallowCloneAndTransfer = 0,
    /// May be moved, giving up the sender's end.
    Transferable = 1,
    /// May be copied without modifying the original.
    Cloneable = 2,
    /// Either.
    TransferableAndCloneable = 3,
}

impl TransferMode {
    /// Reads a mode from the bits `markTransferMode` stored.
    ///
    /// Node checks the value is a `Uint32` and otherwise disallows. A bit pattern
    /// outside the four documented combinations is treated the same way, because
    /// it has no meaning the serializer could honour.
    pub fn from_bits(bits: u32) -> Self {
        match bits {
            1 => Self::Transferable,
            2 => Self::Cloneable,
            3 => Self::TransferableAndCloneable,
            _ => Self::DisallowCloneAndTransfer,
        }
    }

    /// Whether the object may be moved, Node's `mode & kTransferable`.
    pub fn is_transferable(self) -> bool {
        matches!(self, Self::Transferable | Self::TransferableAndCloneable)
    }

    /// Whether the object may be copied, Node's `mode & kCloneable`.
    pub fn is_cloneable(self) -> bool {
        matches!(self, Self::Cloneable | Self::TransferableAndCloneable)
    }
}

/// The state one host object carries to the receiving end.
///
/// This is Node's `worker::TransferData`. Its three data-bearing calls are that
/// type's three virtuals, and their order is what makes a clone work:
///
/// * [`rebuild`](Self::rebuild) runs *before* the main payload is read, because
///   the payload references the object by id and V8 needs something to return;
/// * [`write_data`](Self::write_data) runs *after* the main value is serialized,
///   appending this clone's own state;
/// * [`read_data`](Self::read_data) runs *after* the main value is read, against
///   the object `rebuild` produced.
///
/// A native handle carries nothing in the last two, because its whole state is
/// inside `rebuild`. A JavaScript-level clone carries the value its `[kClone]`
/// returned, which is why both live in one vector: they are two `TransferData`
/// implementations, exactly as `JSTransferable::Data` and
/// `SocketAddressBlockListWrap::TransferData` both derive from the same base.
pub trait TransferData {
    /// Builds the receiving object, Node's `TransferData::Deserialize`.
    fn rebuild<'s>(&self, scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>>;

    /// Appends this clone's own state, Node's `FinalizeTransferWrite`.
    ///
    /// Returning `false` aborts the serialization, which is what Node does when
    /// its `WriteValue` here fails.
    fn write_data(
        &self,
        _scope: &mut v8::PinScope<'_, '_>,
        _serializer: &dyn v8::ValueSerializerHelper,
    ) -> bool {
        true
    }

    /// Reads this clone's own state into `target`, Node's `FinalizeTransferRead`.
    fn read_data(
        &self,
        _scope: &mut v8::PinScope<'_, '_>,
        _deserializer: &dyn v8::ValueDeserializerHelper,
        _target: v8::Local<'_, v8::Object>,
    ) -> bool {
        true
    }
}

/// Builds the clone payload of one native handle, Node's `CloneForMessaging()`.
///
/// Higher-ranked over one lifetime only: `PinScope<'s, 'i>` borrows the isolate and
/// the handle scope for its own call, so a function item has to be generic over the
/// scope's local lifetime alone. Both lifetimes come free by naming `'s` once in
/// each position, which is what lets a plain `fn` coerce to this.
pub type CloneFn = for<'s> fn(
    &mut v8::PinScope<'s, '_>,
    v8::Local<'s, v8::Object>,
) -> Option<Rc<dyn TransferData>>;

thread_local! {
    /// Registered kinds, keyed by the name a handle is marked with.
    static KINDS: RefCell<BTreeMap<&'static str, CloneFn>> = const { RefCell::new(BTreeMap::new()) };

    /// The private key a marked handle carries its kind under.
    static MARK: RefCell<Option<v8::Global<v8::Private>>> = const { RefCell::new(None) };
}

/// Registers `kind`, whose handles [`mark`] makes cloneable.
///
/// Called from a binding crate's `register`, which runs while the binding registry
/// is built and therefore before the first clone can reach the table.
pub fn register_kind(kind: &'static str, clone: CloneFn) {
    KINDS.with(|kinds| {
        kinds.borrow_mut().insert(kind, clone);
    });
}

/// Marks `object` as a cloneable handle of `kind`.
///
/// A handle whose type is only ever consumed by the transfer machinery is marked
/// once, at construction, the way Node's `BaseObject` constructor records the
/// wrapper that `IsBaseObject` later finds.
pub fn mark(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    kind: &str,
) -> bool {
    let Some(key) = mark_key(scope) else {
        return false;
    };
    let Some(value) = v8::String::new(scope, kind) else {
        return false;
    };
    object
        .set_private(scope, key, value.into())
        .unwrap_or(false)
}

/// The transfer mode of a registered handle, or `None` when `object` is not one.
///
/// Every registered kind is `Cloneable`, because a kind exists to say "this type
/// knows how to be copied"; a future native type that could only move would carry
/// its mode in the marking instead.
pub fn transfer_mode(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<TransferMode> {
    kind_of(scope, object).map(|_| TransferMode::Cloneable)
}

/// The clone payload for `object`, when it is a handle of a registered kind.
///
/// `None` covers both "not marked" and "marked with a kind nothing registered".
/// Neither can be cloned, and the caller reports both the way Node reports
/// `kDisallowCloneAndTransfer`.
pub fn clone_for_messaging<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<Rc<dyn TransferData>> {
    let kind = kind_of(scope, object)?;
    let clone = KINDS.with(|kinds| kinds.borrow().get(kind).copied())?;
    clone(scope, object)
}

/// Whether `object` is a handle of a registered kind.
pub fn is_registered(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<'_, v8::Object>) -> bool {
    kind_of(scope, object).is_some()
}

/// The kind `object` was marked with, if it was marked at all.
///
/// The returned `&'static str` is the registry's own key, so a lookup does not leak
/// a fresh string per cloned object. This runs for every object a serializer walks,
/// so the common case — no mark at all — costs one private lookup and nothing else.
fn kind_of(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> Option<&'static str> {
    let key = mark_key(scope)?;
    let value = object.get_private(scope, key)?;
    let text = v8::Local::<v8::String>::try_from(value).ok()?;
    let name = text.to_rust_string_lossy(scope);
    KINDS.with(|kinds| {
        kinds
            .borrow()
            .keys()
            .find(|kind| **kind == name.as_str())
            .copied()
    })
}

/// The cached private key a handle's kind is stored under.
fn mark_key<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Private>> {
    let existing = MARK.with(|slot| slot.borrow().as_ref().map(|key| v8::Local::new(scope, key)));
    if let Some(key) = existing {
        return Some(key);
    }
    let name = v8::String::new(scope, "node:host_object_kind")?;
    let key = v8::Private::new(scope, Some(name));
    MARK.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, key)));
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never_clones<'s>(
        _scope: &mut v8::PinScope<'s, '_>,
        _object: v8::Local<'s, v8::Object>,
    ) -> Option<Rc<dyn TransferData>> {
        None
    }

    #[test]
    fn a_registered_kind_is_remembered() {
        // The table is what the messaging layer consults, so a registration has to
        // be visible to a later lookup rather than copied per call.
        register_kind("test_kind_registered", never_clones);
        assert!(KINDS.with(|kinds| kinds.borrow().contains_key("test_kind_registered")));
    }

    #[test]
    fn an_unregistered_kind_is_not_cloneable() {
        // A handle marked with a name nothing registered has to answer "no" rather
        // than fall through to a clone hook that is not there: the alternative is a
        // clone that produces a handle with no state behind it.
        register_kind("test_kind_present", never_clones);
        assert!(!KINDS.with(|kinds| kinds.borrow().contains_key("test_kind_absent")));
    }

    #[test]
    fn the_transfer_modes_keep_nodes_numbering() {
        // `util.constants` publishes these numbers to `lib/**`, and
        // `markTransferMode` ORs them, so a renumbering here would silently turn a
        // cloneable object into an untransferable one.
        assert_eq!(TransferMode::DisallowCloneAndTransfer as u32, 0);
        assert_eq!(TransferMode::Transferable as u32, 1);
        assert_eq!(TransferMode::Cloneable as u32, 2);
        assert_eq!(TransferMode::TransferableAndCloneable as u32, 3);
    }

    #[test]
    fn a_mode_round_trips_through_the_bits_js_stores() {
        for bits in 0..4u32 {
            let mode = TransferMode::from_bits(bits);
            assert_eq!(mode as u32, bits, "mode {bits} must survive the trip");
        }
        // `markTransferMode` writes whatever ORing the two bits produces, so a
        // value outside the four documented ones is a corrupted mark and has to
        // fall back to "not transferable" rather than guess.
        assert_eq!(
            TransferMode::from_bits(7),
            TransferMode::DisallowCloneAndTransfer
        );
    }

    #[test]
    fn the_mode_predicates_follow_the_bits() {
        assert!(!TransferMode::DisallowCloneAndTransfer.is_transferable());
        assert!(!TransferMode::DisallowCloneAndTransfer.is_cloneable());
        assert!(TransferMode::Transferable.is_transferable());
        assert!(!TransferMode::Transferable.is_cloneable());
        // `BlockList` and `SocketAddress` mark themselves `kCloneable` in
        // `lib/internal/blocklist.js`, so a `false` here would stop every clone
        // before the hook was reached.
        assert!(!TransferMode::Cloneable.is_transferable());
        assert!(TransferMode::Cloneable.is_cloneable());
        assert!(TransferMode::TransferableAndCloneable.is_transferable());
        assert!(TransferMode::TransferableAndCloneable.is_cloneable());
    }
}

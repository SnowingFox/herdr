//! Serializing a posted message, and honouring its transfer list.
//!
//! # Why this is not the `structuredClone` delegate
//!
//! `structuredClone` in the parent module never transfers anything: it round-trips
//! through `ValueSerializer`/`ValueDeserializer` with a delegate that reports "no
//! host objects" and refuses shared buffers and WASM modules. `postMessage` has to
//! do more:
//!
//! * An `ArrayBuffer` in the transfer list is detached in the sender's isolate and
//!   re-attached in the receiver's, which is what makes a transferred buffer
//!   unusable on one side and usable on the other.
//! * A host object is written as a `uint32` id and resolved by the receiving
//!   deserializer, which is how `postMessage(port, [port])` moves a port instead of
//!   copying it, and how a cloneable object is copied at all.
//!
//! # The id space
//!
//! `src/node_messaging.cc` keeps one `host_objects_` vector on the sender and one
//! `host_objects` vector on the receiver, and the `uint32` V8 carries is an index
//! into it. The vector is seeded from the transfer list, and
//! `SerializerDelegate::Finish` appends an entry for every *cloned* object after
//! the value has been written. `Message::Deserialize` rebuilds the receiving vector
//! from `Message::transferables_` before the payload is read, so both sides index
//! the same list in the same order.
//!
//! `first_cloned_object_index_` records where the transfer list's entries end and
//! the clones begin. It matters because the two are built by different calls:
//! below it, `TransferForMessaging()`; at or above it, `CloneForMessaging()`.
//!
//! # What was missing
//!
//! The clone half did not exist. A native handle was written as a host-object id —
//! so a `BlockList` *looked* like it would survive a clone — but nothing ever
//! called the clone hook, so no payload was recorded and the receiving delegate's
//! id lookup had nothing to return. `structuredClone` did not even get that far:
//! its delegate reported that nothing was a host object, so a `BlockList` was
//! copied as its enumerable properties and the handle inside it was dropped.
//!
//! the `Finish` loop in [`serialize`] is the missing step, and it is the only place
//! a clone hook is ever invoked.

use std::cell::RefCell;
use std::rc::Rc;

use rn_core::host_object::{self, TransferData};
use rn_v8_sys::v8;

use crate::port::Message;

/// The transfer list of one `postMessage`, resolved into concrete objects.
struct Transfers<'s> {
    /// `ArrayBuffer`s in list order. The index is the transfer id the serializer
    /// writes, and the order the receiver re-attaches them in.
    array_buffers: Vec<v8::Local<'s, v8::ArrayBuffer>>,
    /// Ports being handed over rather than copied.
    ports: Vec<v8::Local<'s, v8::Object>>,
}

/// Collects host objects while the message is serialized.
///
/// The serializer is a stack object that only lives for the call, so the
/// collection is borrowed from [`serialize`]'s own scope.
pub(crate) struct Delegate<'a> {
    /// One slot per host object written, indexed by the id the receiver reads.
    ///
    /// Node's `SerializerDelegate::host_objects_`: the transfer list seeds it and
    /// `WriteHostObject` appends to it, so the vector order and the id order are
    /// the same thing.
    pub host_objects: &'a RefCell<Vec<v8::Global<v8::Object>>>,
    /// How many of those slots arrived through the transfer list.
    ///
    /// Node's `first_cloned_object_index_`.
    pub transferred: usize,
}

impl v8::ValueSerializerImpl for Delegate<'_> {
    fn has_custom_host_object(&self, _isolate: &v8::Isolate) -> bool {
        // Node's `SerializerDelegate::HasCustomHostObject` is `true`, and it has to
        // be. With it `false`, V8 decides what a host object is by counting
        // embedder fields, which would route every internal-field handle through
        // `write_host_object` without consulting the transfer-mode marking — so a
        // socket or an fs handle would try to serialize as a clone.
        true
    }

    fn throw_data_clone_error<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        message: v8::Local<'s, v8::String>,
    ) {
        // V8 supplies the text (`"function ... could not be cloned"`). Node's
        // `SerializerDelegate::ThrowDataCloneError` raises
        // `ThrowDataCloneException`, which constructs
        // `internal/per_context/domexception`'s `DOMException` with the name
        // `DataCloneError` — so `error.name` is that string, `error.code` is 25,
        // and `error instanceof Error` holds. That class now exists, so this goes
        // through it instead of approximating with a `TypeError`.
        crate::throw_data_clone_exception(scope, message.into());
    }

    fn is_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
    ) -> Option<bool> {
        // Node asks two questions: is it a `BaseObject`, and is it a
        // `JSTransferable` — which is to say, does it carry a transfer mode.
        // rustnode asks the same two of its own machinery: a port is a handle it
        // knows, and anything else has to be a handle whose kind registered a
        // clone hook, or an object `markTransferMode` stamped.
        Some(
            crate::port_state_of(scope, object).is_some()
                || host_object::is_registered(scope, object)
                || crate::js_marked(scope, object),
        )
    }

    fn write_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
        serializer: &dyn v8::ValueSerializerHelper,
    ) -> Option<bool> {
        // A port is transferable and never cloneable: its payload in the message is
        // the id of its transfer-list slot, and the receiver rebuilds it from the
        // queue the sender gave up.
        if crate::port_state_of(scope, object).is_some() {
            return match self.transfer_index(scope, object) {
                Some(index) => {
                    serializer.write_uint32(index as u32);
                    Some(true)
                }
                None => {
                    // `postMessage(port)` without listing it. Node's
                    // `clone_transfer_needed_str()`: a port cannot be copied.
                    crate::throw_data_clone_exception_str(
                        scope,
                        "Object that needs transfer was found in message but not listed in \
                         transferList",
                    );
                    None
                }
            };
        }

        // A handle registered in `rn_core::host_object`, or an object that
        // `markTransferMode` stamped. Both end up in the same vector because Node
        // puts `BaseObject` and `JSTransferable` entries in one `host_objects_`.
        let mode = host_object::transfer_mode(scope, object)
            .or_else(|| crate::js_transfer_mode(scope, object));
        let Some(mode) = mode else {
            // Node's `clone_unsupported_type_str()`.
            crate::throw_data_clone_exception_str(
                scope,
                "Cannot clone object of unsupported type.",
            );
            return None;
        };
        if !mode.is_cloneable() {
            // A host object that can only move has to be in the transfer list. No
            // type in this build is in that state, but the answer must not quietly
            // become "copy it".
            crate::throw_data_clone_exception_str(
                scope,
                "Object that needs transfer was found in message but not listed in transferList",
            );
            return None;
        }

        let id = {
            let mut host_objects = self.host_objects.borrow_mut();
            host_objects.push(v8::Global::new(scope, object));
            host_objects.len() as u32 - 1
        };
        serializer.write_uint32(id);
        Some(true)
    }
}

impl Delegate<'_> {
    /// The transfer-list index of `object`, when it is in the list.
    ///
    /// Node's `WriteHostObject` searches `host_objects_`, which the transfer list
    /// already seeded, and writes that index. The search is by identity: the list
    /// refuses duplicates while it is read, so one entry per object is enough.
    fn transfer_index<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
    ) -> Option<usize> {
        let host_objects = self.host_objects.borrow();
        for (index, existing) in host_objects.iter().take(self.transferred).enumerate() {
            let existing: v8::Local<v8::Object> = v8::Local::new(scope, existing);
            if existing.strict_equals(object.into()) {
                return Some(index);
            }
        }
        None
    }
}

/// Serializes `value`, detaching everything in `transfer_list`.
///
/// On success returns the message and the ports the caller must hand over. On
/// failure returns the text to report as an exception, or `None` when V8 has
/// already scheduled one — throwing again would replace a precise message with a
/// generic one and leave two exceptions pending.
pub fn serialize<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
    transfer_list: v8::Local<'s, v8::Value>,
) -> Result<(Message, Vec<v8::Global<v8::Object>>), Option<String>> {
    let context = scope.get_current_context();
    let transfers = collect_transfers(scope, transfer_list)?;

    let host_objects = RefCell::new(Vec::new());
    let transferred = transfers.ports.len();
    let serializer = v8::ValueSerializer::new(
        scope,
        Box::new(Delegate {
            host_objects: &host_objects,
            transferred,
        }),
    );

    // Node seeds `host_objects_` with the transferable entries before writing the
    // value, so `WriteHostObject` finds them by index. Same order here, and in the
    // same place: the ids the payload references are these indices.
    {
        let mut slots = host_objects.borrow_mut();
        for port in &transfers.ports {
            slots.push(v8::Global::new(scope, *port));
        }
    }

    // Register each buffer under its list index before writing the value, so the
    // deserializer can re-attach it at the id the payload references.
    let mut backing_stores = Vec::with_capacity(transfers.array_buffers.len());
    for (id, buffer) in transfers.array_buffers.iter().enumerate() {
        v8::ValueSerializerHelper::transfer_array_buffer(&serializer, id as u32, *buffer);
        backing_stores.push(buffer.get_backing_store());
    }

    // `WriteHeader()` before `WriteValue`, exactly as Node does. It is load
    // bearing and not a formality: `ValueDeserializer::ReadValue` chooses
    // `ReadObjectUsingEntireBufferForLegacyFormat` when the wire-format version is
    // 0, and that reader consumes the *whole* buffer, so it cannot cope with the
    // clone data that follows the payload. Writing the header and calling
    // `ReadHeader` on the way back is what selects the streaming reader, and it is
    // why a clone whose `[kClone]` returns any `data` at all used to fail with
    // "Unable to deserialize cloned data".
    v8::ValueSerializerHelper::write_header(&serializer);
    match serializer.write_value(context, value) {
        Some(true) => {}
        // V8 threw; the exception is pending on the isolate already.
        _ => return Err(None),
    }

    // Detach only after a successful write: a message that could not be serialized
    // must not leave the caller's buffers unusable.
    for buffer in &transfers.array_buffers {
        if buffer.detach(None).is_none() {
            return Err(Some(
                "Could not detach an ArrayBuffer for transfer".to_string(),
            ));
        }
    }

    // `SerializerDelegate::Finish`, which interleaves `CloneForMessaging` and
    // `FinalizeTransferWrite` in one loop. Both halves have to be here rather than
    // in two passes because writing a clone's data can itself reach *more* host
    // objects: a `BlockList` wrapper's `[kClone]` returns `{ handle }`, and that
    // handle is a cloneable native object too. Node's loop re-reads
    // `host_objects_.size()` each iteration for exactly this reason, so a nested
    // object discovered while writing clone `i` is built at `i+1` and its own data
    // follows.
    //
    // Writing the clone data into the same serializer is also required: it has to
    // land after the main payload in one buffer, because the receiver reads it back
    // from the same stream in the same order.
    let mut clones: Vec<Rc<dyn TransferData>> = Vec::new();
    let mut index = transferred;
    loop {
        let count = host_objects.borrow().len();
        if index >= count {
            break;
        }
        let object = {
            let slots = host_objects.borrow();
            match slots.get(index) {
                Some(object) => v8::Local::new(scope, object),
                None => continue,
            }
        };
        let clone = rn_core::host_object::clone_for_messaging(scope, object)
            .or_else(|| crate::js_clone_for_messaging(scope, object));
        // A hook returning nothing is a failed clone, not a silent skip: Node
        // returns `Nothing<bool>()` from `Finish` and the serialization fails.
        let Some(clone) = clone else {
            return Err(None);
        };
        if !clone.write_data(scope, &serializer) {
            return Err(None);
        }
        clones.push(clone);
        index += 1;
    }

    let data = serializer.release();
    drop(serializer);
    // The message keeps the transfer-list objects so the receiver can rebuild them
    // by id, and the caller gets its own handles so it can detach them on the
    // sending side.
    let ports: Vec<v8::Global<v8::Object>> = host_objects
        .borrow()
        .iter()
        .take(transferred)
        .cloned()
        .collect();
    Ok((
        Message::new(data, backing_stores, ports, clones, transferred),
        host_objects.into_inner(),
    ))
}

/// Reads and validates the transfer list before anything is serialized.
///
/// Node reads it first, so a bad entry reports the transfer list even when the
/// message itself is also uncloneable.
fn collect_transfers<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    transfer_list: v8::Local<'s, v8::Value>,
) -> Result<Transfers<'s>, Option<String>> {
    let mut transfers = Transfers {
        array_buffers: Vec::new(),
        ports: Vec::new(),
    };
    if transfer_list.is_undefined() || transfer_list.is_null() {
        return Ok(transfers);
    }
    let Ok(array) = v8::Local::<v8::Array>::try_from(transfer_list) else {
        return Err(Some(
            "The transferList argument must be an array of transferable objects".to_string(),
        ));
    };

    for index in 0..array.length() {
        let Some(entry) = array.get_index(scope, index) else {
            return Err(None);
        };
        let Ok(object) = v8::Local::<v8::Object>::try_from(entry) else {
            // `Message::Serialize`'s `!entry_val->IsObject()` branch, whose text
            // is `env->clone_untransferable_str()`.
            return Err(Some("Found invalid value in transferList.".to_string()));
        };

        if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(entry) {
            if !buffer.is_detachable() {
                return Err(Some(
                    "Cannot transfer an ArrayBuffer that is not detachable".to_string(),
                ));
            }
            if buffer.was_detached() {
                return Err(Some(
                    "Cannot transfer an ArrayBuffer that was already detached".to_string(),
                ));
            }
            if transfers
                .array_buffers
                .iter()
                .any(|existing| existing.strict_equals(buffer.into()))
            {
                return Err(Some(
                    "Transfer list contains duplicate ArrayBuffer".to_string(),
                ));
            }
            transfers.array_buffers.push(buffer);
            continue;
        }

        if crate::port_state_of(scope, object).is_some() {
            // Node refuses a second entry for the same object: the receiver would
            // resolve two ids to one object and move the port twice.
            if transfers
                .ports
                .iter()
                .any(|existing| existing.strict_equals(object.into()))
            {
                return Err(Some(
                    "Transfer list contains duplicate MessagePort".to_string(),
                ));
            }
            transfers.ports.push(object);
            continue;
        }

        return Err(Some("Found invalid value in transferList.".to_string()));
    }

    Ok(transfers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_close_marker_is_distinguishable_from_an_empty_message() {
        // Both carry no bytes, so the flag is the only thing that tells them apart.
        // `ReceiveMessage` relies on it to dispatch `close` rather than trying to
        // deserialize an empty payload.
        assert!(Message::close_marker().close);
        assert!(!Message::new(Vec::new(), Vec::new(), Vec::new(), Vec::new(), 0).close);
    }

    #[test]
    fn a_message_remembers_where_the_clones_begin() {
        // The receiver subtracts this from every clone id, so a wrong value
        // resolves a clone against a transfer-list slot and produces a port where
        // a handle was expected.
        let message = Message::new(Vec::new(), Vec::new(), Vec::new(), Vec::new(), 2);
        assert_eq!(message.transferred_count, 2);
        assert_eq!(Message::close_marker().transferred_count, 0);
    }
}

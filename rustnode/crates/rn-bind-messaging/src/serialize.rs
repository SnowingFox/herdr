//! Serializing a posted message, and honouring its transfer list.
//!
//! # Why this is not the `structuredClone` delegate
//!
//! `structuredClone` in the parent module never transfers anything: it
//! round-trips through `ValueSerializer`/`ValueDeserializer` with a delegate that
//! reports "no host objects" and refuses shared buffers and WASM modules.
//! `postMessage` has to do more:
//!
//! * An `ArrayBuffer` in the transfer list is detached in the sender's isolate
//!   and re-attached in the receiver's, which is what makes a transferred buffer
//!   unusable on one side and usable on the other.
//! * A `MessagePort` in the transfer list is a *host object*. Its id is written
//!   as a `uint32` and resolved by the receiving deserializer, which is how
//!   `postMessage(port, [port])` moves a port instead of copying it.
//!
//! # What works, and what is refused
//!
//! `ArrayBuffer` and `MessagePort` entries both transfer. Shared `ArrayBuffer`s,
//! WASM modules and `JSTransferable` host objects are refused with a message
//! naming the type, which is what Node throws for an untransferable entry too —
//! the difference is only in which entries succeed.

use std::cell::RefCell;

use rn_v8_sys::v8;

use crate::port::Message;

/// The transfer list of one `postMessage`, resolved into concrete objects.
pub struct Transfers<'s> {
    /// `ArrayBuffer`s in list order. The index is the transfer id the serializer
    /// writes, and the order the receiver re-attaches them in.
    pub array_buffers: Vec<v8::Local<'s, v8::ArrayBuffer>>,
    /// Ports being handed over rather than copied.
    pub ports: Vec<v8::Local<'s, v8::Object>>,
}

/// Collects host objects while the message is serialized.
///
/// The serializer is a stack object that only lives for the call, so the
/// collections are borrowed from [`serialize`]'s own scope.
struct Delegate<'a, 's> {
    /// One slot per host object written, indexed by the id the receiver reads.
    host_objects: &'a RefCell<Vec<v8::Global<v8::Object>>>,
    /// A scope only exists so `throw_data_clone_error` can keep the marker.
    _scope: std::marker::PhantomData<&'s ()>,
}

impl v8::ValueSerializerImpl for Delegate<'_, '_> {
    fn throw_data_clone_error<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        message: v8::Local<'s, v8::String>,
    ) {
        // V8 supplies the text (`"function ... could not be cloned"`). Node
        // raises a `DataCloneError` `DOMException`; this build's `DOMException`
        // is the plain object installed by the parent module, so a `TypeError`
        // carrying the same message is the closest behaviour that keeps both the
        // type name and the text intact.
        let exception = v8::Exception::type_error(scope, message);
        scope.throw_exception(exception);
    }

    fn is_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
    ) -> Option<bool> {
        // A `MessagePort` is the only host object this build understands, and it
        // is recognized by the internal field every port carries.
        Some(crate::port_state_of(scope, object).is_some())
    }

    fn write_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
        serializer: &dyn v8::ValueSerializerHelper,
    ) -> Option<bool> {
        if crate::port_state_of(scope, object).is_none() {
            crate::throw_type_error(
                scope,
                "Cannot clone a host object that is not a MessagePort",
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
    let serializer = v8::ValueSerializer::new(
        scope,
        Box::new(Delegate {
            host_objects: &host_objects,
            _scope: std::marker::PhantomData,
        }),
    );

    // Register each buffer under its list index before writing the value, so the
    // deserializer can re-attach it at the id the payload references.
    let mut backing_stores = Vec::with_capacity(transfers.array_buffers.len());
    for (id, buffer) in transfers.array_buffers.iter().enumerate() {
        v8::ValueSerializerHelper::transfer_array_buffer(&serializer, id as u32, *buffer);
        backing_stores.push(buffer.get_backing_store());
    }

    match serializer.write_value(context, value) {
        Some(true) => {}
        // V8 threw; the exception is pending on the isolate already.
        _ => return Err(None),
    }
    let data = serializer.release();

    // Detach only after a successful write: a message that could not be
    // serialized must not leave the caller's buffers unusable.
    for buffer in &transfers.array_buffers {
        if buffer.detach(None).is_none() {
            return Err(Some(
                "Could not detach an ArrayBuffer for transfer".to_string(),
            ));
        }
    }

    // `serializer` borrows `host_objects`, so it has to go before the vector
    // moves out.
    drop(serializer);
    let ports = host_objects.into_inner();
    Ok((Message::new(data, backing_stores), ports))
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
            return Err(Some("Transfer list contents must be objects".to_string()));
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
                    "Transfer list contains a duplicate ArrayBuffer".to_string(),
                ));
            }
            transfers.array_buffers.push(buffer);
            continue;
        }

        if crate::port_state_of(scope, object).is_some() {
            transfers.ports.push(object);
            continue;
        }

        return Err(Some(
            "Transfer list contents must be ArrayBuffers or MessagePorts".to_string(),
        ));
    }

    Ok(transfers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_close_marker_is_distinguishable_from_an_empty_message() {
        // Both carry no bytes, so the flag is the only thing that tells them
        // apart. `ReceiveMessage` relies on it to dispatch `close` rather than
        // trying to deserialize an empty payload.
        assert!(Message::close_marker().close);
        assert!(!Message::new(Vec::new(), Vec::new()).close);
    }
}

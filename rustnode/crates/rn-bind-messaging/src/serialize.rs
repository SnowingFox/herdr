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
use std::sync::Arc;

use rn_core::host_object::{self, TransferData};
use rn_v8_sys::v8;

use crate::get_key;
use crate::port::{Message, PortTransferData};

/// How the caller's transfer-list value is to be interpreted.
///
/// The two shapes are genuinely different in Node and produce different errors,
/// which is why this is not one check:
///
/// * [`Argument`](TransferList::Argument) is `postMessage`'s second argument. Node
///   passes it through `GetTransferList`, which tries it as an iterable, then
///   falls back to `options.transfer`, and treats an object with neither as an
///   *empty* list — so `postMessage('x', {})` is legal.
/// * [`Sequence`](TransferList::Sequence) is `structuredClone`'s already-extracted
///   `options.transfer`, which `webidl` has already coerced to a sequence. It must
///   therefore be iterable: `structuredClone(v, {transfer: {}})` throws
///   `ERR_INVALID_ARG_TYPE` where `postMessage` accepts the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferList {
    /// `postMessage`'s transfer list argument.
    Argument,
    /// `structuredClone`'s `options.transfer`, already extracted.
    Sequence,
}

/// The transfer list of one `postMessage`, resolved into concrete objects.
///
/// Nothing has moved yet at this point. The transfer hooks — `[kTransfer]`,
/// `TransferForMessaging` — run later, in the `Finish` loop, because Node runs
/// them there too: a message that fails to serialize must not leave the caller's
/// socket closed or its `FileHandle` descriptor detached.
struct Transfers<'s> {
    /// `ArrayBuffer`s in list order. The index is the transfer id the serializer
    /// writes, and the order the receiver re-attaches them in.
    array_buffers: Vec<v8::Local<'s, v8::ArrayBuffer>>,
    /// Entries handed over rather than copied: ports, native handles that can
    /// only move, and `JSTransferable`s with `[kTransfer]`.
    ///
    /// Node keeps these in the same `host_objects_` vector it seeds before
    /// serializing, because the ids the payload writes are indices into it. Order
    /// is preserved as listed, and the nested entries each one registers are
    /// appended after all of them, which is what Node's `AddNestedHostObjects`
    /// does.
    transferables: Vec<v8::Local<'s, v8::Object>>,
}

/// Why a serialization could not produce a message.
///
/// The two failure classes are separate because Node raises two different
/// exceptions and JavaScript distinguishes them: every *entry* problem is a
/// `DataCloneError` (`Message::Serialize` calls `ThrowDataCloneException` on
/// every path through its transfer-list loop), while a transfer list that is not
/// an object at all is `THROW_ERR_INVALID_ARG_TYPE` from `GetTransferList`, which
/// is a `TypeError`. Routing both through one variant is what made every
/// transfer-list error a `TypeError` here.
#[derive(Debug)]
pub(crate) enum SerializeError {
    /// A transfer-list entry was rejected. Carries Node's message text.
    DataClone(String),
    /// `transferList` itself is not iterable, `GetTransferList`'s
    /// `ERR_INVALID_ARG_TYPE`.
    NotIterableTransferList,
    /// `options.transfer` exists but is not iterable.
    NotIterableOptionsTransfer,
    /// `structuredClone(..., { transfer })` got a non-sequence transfer value.
    NotIterableSequence,
    /// V8 scheduled the exception; rethrowing would replace it.
    Thrown,
}

/// One entry in the id space, while the message is still being built.
///
/// The vector of these *is* the id space: the transfer list seeds it and
/// `WriteHostObject` appends to it, so a slot's index is the id the payload
/// carries. Keeping the payload in the same slot as the handle is what makes
/// "which object does id `n` name" a single lookup on both sides of the post.
pub(crate) struct Slot {
    /// The sender's own object, for `transfer_index`.
    handle: v8::Global<v8::Object>,
    /// What the message carries for this id.
    ///
    /// A transfer-list port has one from the start, because handing the queue
    /// over is what transferring it means. A clone's payload only exists once the
    /// `Finish` loop has run its clone hook, which is why this starts empty.
    payload: Option<Arc<dyn TransferData>>,
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
    host_objects: &'a RefCell<Vec<Slot>>,
    /// How many of those slots arrived through the transfer list.
    ///
    /// Node's `first_cloned_object_index_`.
    transferred: usize,
    /// Shared buffers already written, in id order.
    ///
    /// Node's `seen_shared_array_buffers_`. A shared buffer is *not* a transfer
    /// list entry: it is shared memory, so it stays usable on the sending side
    /// and the id only tells the receiver which backing store to reattach. Ids
    /// are deduplicated by identity within one message, so a `Uint32Array` view
    /// and the `SharedArrayBuffer` behind it cost one entry, and both sides end
    /// up with the same buffer rather than two copies.
    shared_array_buffers: &'a RefCell<Vec<v8::Global<v8::SharedArrayBuffer>>>,
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
        //
        // `process.env` is a third case, and Node answers it in the same place:
        // `SerializationContext::WriteHostObject` tests
        // `env_proxy_ctor_template->HasInstance(object)` and serialises the
        // variables as a normal object. Without this the proxy is not a host
        // object at all, V8 copies its enumerable properties, and the copy works
        // by accident — but `structuredClone(process.env)` inside a worker, where
        // the proxy's own realm is not the one reading, is the case that has to
        // be explicit.
        Some(
            crate::port_state_of(scope, object).is_some()
                || host_object::is_registered(scope, object)
                || crate::js_marked(scope, object)
                || crate::js_transferable(scope, object)
                || rn_core::env_proxy::is_proxy(scope, object),
        )
    }

    fn write_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        object: v8::Local<'s, v8::Object>,
        serializer: &dyn v8::ValueSerializerHelper,
    ) -> Option<bool> {
        // `process.env` is not a handle and has no transfer mode; Node converts
        // it to a normal object and writes that. `kNormalObject` is the sentinel
        // `src/node_messaging.cc` defines ("Hack to have WriteHostObject inform
        // ReadHostObject that the value should be treated as a regular JS
        // object. Used to transfer process.env."), and the delegate on the other
        // side reads a value instead of looking up an id when it sees it.
        if rn_core::env_proxy::is_proxy(scope, object) {
            return match crate::env_pairs_object(scope) {
                Some(plain) => {
                    serializer.write_uint32(crate::K_NORMAL_OBJECT);
                    serializer.write_value(scope.get_current_context(), plain.into())
                }
                None => None,
            };
        }

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

        // Node searches `host_objects_` before it decides to clone, and that
        // order is load-bearing: a `FileHandle` is both a registered host handle
        // *and* a JS transferable whose `[kTransfer]` ran while the list was
        // read, so a transfer that took the clone path would report "needs
        // transfer" for an object it had already accepted. Searching first is
        // what makes `postMessage(fh, [fh])` find the seeded slot.
        if let Some(index) = self.transfer_index(scope, object) {
            serializer.write_uint32(index as u32);
            return Some(true);
        }

        // A host handle that can only move, or a JS transferable, that is not in
        // the transfer list. Node's `WriteHostObject` reaches the same refusal
        // from `GetTransferMode() & kTransferable` and finds nothing in
        // `host_objects_`.
        if rn_core::host_object::transfer_mode(scope, object)
            .map(|mode| mode.is_transferable())
            .unwrap_or(false)
            || crate::js_transferable(scope, object)
        {
            crate::throw_data_clone_exception_str(
                scope,
                "Object that needs transfer was found in message but not listed in transferList",
            );
            return None;
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
            host_objects.push(Slot {
                handle: v8::Global::new(scope, object),
                payload: None,
            });
            host_objects.len() as u32 - 1
        };
        serializer.write_uint32(id);
        Some(true)
    }

    fn get_shared_array_buffer_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        shared_array_buffer: v8::Local<'s, v8::SharedArrayBuffer>,
    ) -> Option<u32> {
        // Node's `SerializerDelegate::GetSharedArrayBufferId`. A shared buffer is
        // copied by reference, never transferred: it stays usable on the sending
        // side, so this is not a transfer-list entry and does not consult one.
        //
        // The id is deduplicated by identity within this message. That is the part
        // a naive implementation gets wrong: a `Uint32Array` view writes its buffer
        // as well, and if each got its own id the receiver would build two distinct
        // shared buffers from one allocation and the counter would stop being
        // shared between them.
        let wanted: v8::Local<'s, v8::Object> = shared_array_buffer.into();
        {
            let seen = self.shared_array_buffers.borrow();
            for (index, existing) in seen.iter().enumerate() {
                let existing: v8::Local<v8::SharedArrayBuffer> = v8::Local::new(scope, existing);
                let existing: v8::Local<v8::Object> = existing.into();
                if existing.strict_equals(wanted.into()) {
                    return Some(index as u32);
                }
            }
        }

        let mut seen = self.shared_array_buffers.borrow_mut();
        seen.push(v8::Global::new(scope, shared_array_buffer));
        Some(seen.len() as u32 - 1)
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
        for (index, slot) in host_objects.iter().take(self.transferred).enumerate() {
            let existing: v8::Local<v8::Object> = v8::Local::new(scope, &slot.handle);
            if existing.strict_equals(object.into()) {
                return Some(index);
            }
        }
        None
    }
}

/// The payload for one transfer-list entry, Node's `TransferForMessaging`.
///
/// Three kinds reach here, and the order matters: a `MessagePort` has to be
/// recognised first because it is neither a registered handle nor a
/// `JSTransferable`; a native handle registered as transferable moves its own
/// state; and everything else runs `[kTransfer]`.
fn transfer_payload<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Result<Arc<dyn TransferData>, SerializeError> {
    if let Some(state) = crate::port_state_of(scope, object) {
        // `MessagePort::TransferForMessaging` is `Close(); return Detach();`.
        // The detach happens here rather than while the list was read because
        // this is the point of no return: everything that could reject the
        // message has already run.
        let payload = PortTransferData::for_port(Arc::clone(&state.data));
        state.detach_for_transfer();
        return Ok(payload);
    }
    if let Some(payload) = rn_core::host_object::transfer_for_messaging(scope, object) {
        return Ok(payload);
    }
    // A throwing hook propagates: Node's `TransferOrClone` returns an empty
    // pointer and lets the exception out of `postMessage`, so the caller sees the
    // hook's own error. `Thrown` is how the caller learns not to replace it.
    crate::js_transfer_for_messaging(scope, object).ok_or(SerializeError::Thrown)
}

/// Serializes `value`, detaching everything in `transfer_list`.
///
/// `source_port` is Node's `Message::Serialize(..., Local<Object> source_port)`:
/// the port a `postMessage` is being called on, so a transfer list naming it can
/// be refused with `Transfer list contains source port`. `structuredClone` has no
/// source port and passes `None`, which is Node's empty `Local<Object>`.
///
/// On success returns the message. On failure returns the reason to report as an
/// exception, or [`SerializeError::Thrown`] when V8 has already scheduled one —
/// throwing again would replace a precise message with a generic one and leave
/// two exceptions pending.
pub fn serialize<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
    transfer_list: v8::Local<'s, v8::Value>,
    source_port: Option<v8::Local<'s, v8::Object>>,
    shape: TransferList,
) -> Result<Message, SerializeError> {
    let context = scope.get_current_context();
    let transfers = collect_transfers(scope, transfer_list, source_port, shape)?;

    let host_objects = RefCell::new(Vec::new());
    let shared_array_buffers = RefCell::new(Vec::new());
    let transferred = transfers.transferables.len();
    let serializer = v8::ValueSerializer::new(
        scope,
        Box::new(Delegate {
            host_objects: &host_objects,
            transferred,
            shared_array_buffers: &shared_array_buffers,
        }),
    );

    // Node seeds `host_objects_` with the transferable entries before writing the
    // value, so `WriteHostObject` finds them by index. Same order here, and in the
    // same place: the ids the payload references are these indices.
    //
    // Their payloads are empty on purpose. Node runs `TransferForMessaging` in
    // `Finish`, after `WriteValue`, and the position is observable: a transfer
    // hook that throws, or a value V8 refuses to serialize, must not have closed
    // the caller's socket or given up its `FileHandle`. `Finish` below fills these
    // slots in.
    {
        let mut slots = host_objects.borrow_mut();
        for object in &transfers.transferables {
            slots.push(Slot {
                handle: v8::Global::new(scope, *object),
                payload: None,
            });
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
        _ => return Err(SerializeError::Thrown),
    }

    // Detach only after a successful write: a message that could not be serialized
    // must not leave the caller's buffers unusable.
    for buffer in &transfers.array_buffers {
        if buffer.detach(None).is_none() {
            // `collect_transfers` already rejected a non-detachable buffer, so
            // reaching this means V8 refused a detach it advertised. V8 threw, so
            // its own exception is the one to report.
            return Err(SerializeError::Thrown);
        }
    }

    // `SerializerDelegate::Finish`, Node's one loop over `host_objects_` that
    // runs `TransferForMessaging` below `first_cloned_object_index_` and
    // `CloneForMessaging` at or above it, writing each payload in turn.
    //
    // One loop rather than two passes because writing a payload can itself reach
    // *more* host objects: a `BlockList` wrapper's `[kClone]` returns `{ handle }`,
    // and that handle is a cloneable native object too. Node re-reads
    // `host_objects_.size()` each iteration for exactly this reason, so a nested
    // object discovered while writing entry `i` is built at `i+1`.
    //
    // Writing into the same serializer is also required: the payload has to land
    // after the main value in one buffer, because the receiver reads it back from
    // the same stream in the same order.
    //
    // It runs after `WriteValue` and after the buffers are detached, which is the
    // position that makes a failed post safe: the sender has not yet given up a
    // socket, a descriptor or a port queue.
    let mut index = 0;
    loop {
        let count = host_objects.borrow().len();
        if index >= count {
            break;
        }
        let object = {
            let slots = host_objects.borrow();
            match slots.get(index) {
                Some(slot) => v8::Local::new(scope, &slot.handle),
                None => continue,
            }
        };
        let payload = if index < transferred {
            // A transfer-list entry. A port gives up its queue; a native handle
            // and a JS transferable run their own move hook, which is where the
            // sender's handle is actually released.
            transfer_payload(scope, object)?
        } else {
            // A clone. A hook returning nothing is a failed clone, not a silent
            // skip: Node returns `Nothing<bool>()` from `Finish`.
            rn_core::host_object::clone_for_messaging(scope, object)
                .or_else(|| crate::js_clone_for_messaging(scope, object))
                .ok_or(SerializeError::Thrown)?
        };
        if !payload.write_data(scope, &serializer) {
            return Err(SerializeError::Thrown);
        }
        // The payload lands in the slot its id already names, so the receiver's
        // vector needs no second walk to line up.
        let mut slots = host_objects.borrow_mut();
        match slots.get_mut(index) {
            Some(slot) => slot.payload = Some(payload),
            None => return Err(SerializeError::Thrown),
        }
        index += 1;
    }

    // The queues this message hands over, so `dispatch` can tell a destination it
    // is about to deliver to that the transfer list just moved it. Node compares
    // `MessagePortData*` pointers for this; the addresses are the same identity.
    // Read after the detach above, which is when `data` stops being reachable
    // from the sending side.
    let transferred_ports: Vec<usize> = transfers
        .transferables
        .iter()
        .filter_map(|object| crate::port_state_of(scope, *object))
        .map(|state| PortTransferData::address(&state.data))
        .collect();

    let data = serializer.release();
    drop(serializer);

    // One vector is the whole message: the transfer-list entries carrying their
    // payloads, then the clones, in the id order the payload references.
    let slots = host_objects.into_inner();
    let mut payloads: Vec<Arc<dyn TransferData>> = Vec::with_capacity(slots.len());
    for slot in slots {
        let Some(payload) = slot.payload else {
            return Err(SerializeError::Thrown);
        };
        payloads.push(payload);
    }

    // The shared buffers the payload referenced, in id order, so the receiver
    // reattaches the same allocation instead of an empty one. Taken after the
    // clone loop because writing a clone's data can reach more shared buffers.
    let shared_array_buffers: Vec<v8::SharedRef<v8::BackingStore>> = shared_array_buffers
        .into_inner()
        .iter()
        .map(|buffer| {
            let buffer: v8::Local<v8::SharedArrayBuffer> = v8::Local::new(scope, buffer);
            buffer.get_backing_store()
        })
        .collect();

    Ok(Message::new(
        data,
        backing_stores,
        shared_array_buffers,
        payloads,
        transferred,
        transferred_ports,
    ))
}

/// Reads and validates the transfer list before anything is serialized.
///
/// Node reads it first, so a bad entry reports the transfer list even when the
/// message itself is also uncloneable.
///
/// This mirrors `GetTransferList` + the head of `Message::Serialize`
/// (`src/node_messaging.cc`), and the order of the checks is Node's order rather
/// than a convenient one, because the order decides *which* error a script sees
/// when a value is wrong in more than one way.
fn collect_transfers<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    transfer_list: v8::Local<'s, v8::Value>,
    source: Option<v8::Local<'s, v8::Object>>,
    shape: TransferList,
) -> Result<Transfers<'s>, SerializeError> {
    let mut transfers = Transfers {
        array_buffers: Vec::new(),
        transferables: Vec::new(),
    };
    if transfer_list.is_undefined() || transfer_list.is_null() {
        return Ok(transfers);
    }
    // `GetTransferList`: a non-object is `THROW_ERR_INVALID_ARG_TYPE`, which is a
    // `TypeError`, not a `DataCloneError`. An object that is not iterable falls
    // back to `options.transfer`, and only a non-iterable *there* is the same
    // `TypeError`; an object with neither is an empty transfer list.
    let Ok(holder) = v8::Local::<v8::Object>::try_from(transfer_list) else {
        return Err(match shape {
            TransferList::Argument => SerializeError::NotIterableTransferList,
            TransferList::Sequence => SerializeError::NotIterableSequence,
        });
    };
    let mut entries: Vec<v8::Local<'s, v8::Value>> = Vec::new();
    match read_iterable(scope, holder)? {
        Some(found) => entries = found,
        None if shape == TransferList::Sequence => return Err(SerializeError::NotIterableSequence),
        None => {
            // `ReadIterable` was not an iterable, so `options.transfer` decides.
            let transfer = get_key(scope, holder, "transfer");
            let transfer = transfer.unwrap_or_else(|| v8::undefined(scope).into());
            if !transfer.is_undefined() {
                let Ok(options) = v8::Local::<v8::Object>::try_from(transfer) else {
                    return Err(SerializeError::NotIterableOptionsTransfer);
                };
                entries = read_iterable(scope, options)?
                    .ok_or(SerializeError::NotIterableOptionsTransfer)?;
            }
        }
    }

    for entry in entries {
        let Ok(object) = v8::Local::<v8::Object>::try_from(entry) else {
            // `Message::Serialize`'s `!entry_val->IsObject()` branch, whose text
            // is `env->clone_untransferable_str()`.
            return Err(SerializeError::DataClone(
                "Found invalid value in transferList.".to_string(),
            ));
        };
        // `markAsUntransferable()` stamps `node:transfer_mode` and Node consults
        // that stamp before any type-specific transfer path.
        let marked_untransferable = is_untransferable_mark(scope, object);

        if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(entry) {
            if marked_untransferable {
                return Err(SerializeError::DataClone(
                    "Cannot transfer object of unsupported type.".to_string(),
                ));
            }
            // Node folds "cannot be detached" and "already detached" into one
            // test and one message: `if (!ab->IsDetachable() || ab->WasDetached())`
            // with `transfer_unsupported_type_str()`. The two are one mechanism,
            // not two, and the message says so.
            if !buffer.is_detachable() || buffer.was_detached() {
                return Err(SerializeError::DataClone(
                    "Cannot transfer object of unsupported type.".to_string(),
                ));
            }
            if transfers
                .array_buffers
                .iter()
                .any(|existing| existing.strict_equals(buffer.into()))
            {
                return Err(SerializeError::DataClone(
                    "Transfer list contains duplicate ArrayBuffer".to_string(),
                ));
            }
            transfers.array_buffers.push(buffer);
            continue;
        }

        // A `SharedArrayBuffer` is not transferable — it is shared by reference
        // and needs no transfer list entry — so it never reaches the port branch
        // below and reports the same "invalid value" a plain object does.
        if entry.is_shared_array_buffer() {
            return Err(SerializeError::DataClone(
                "Found invalid value in transferList.".to_string(),
            ));
        }

        // Node tests the source port before anything else, because a script that
        // names the port it is posting on gets that message whether or not the
        // port is also detached. Passing `None` for the source port
        // (`structuredClone`) skips the branch entirely, which is Node's
        // `!source_port.IsEmpty()`.
        if let Some(source) = source {
            if source.strict_equals(object.into()) {
                return Err(SerializeError::DataClone(
                    "Transfer list contains source port".to_string(),
                ));
            }
        }

        // A duplicate is refused before the mode is consulted, and the message
        // names the constructor: Node's
        // `String::Concat("Transfer list contains duplicate ", entry->GetConstructorName())`.
        // Checking it here rather than per branch is what keeps a duplicate
        // `MessagePort` reporting the port message and a duplicate
        // `FileHandle` reporting *its* name, instead of one message for both.
        if transfers
            .transferables
            .iter()
            .any(|existing| existing.strict_equals(object.into()))
        {
            let name = object.get_constructor_name().to_rust_string_lossy(scope);
            return Err(SerializeError::DataClone(format!(
                "Transfer list contains duplicate {name}"
            )));
        }

        // Ports move by giving up the queue; they are never cloned, which is why
        // this branch is before the general `is_transferable` test.
        if let Some(state) = crate::port_state_of(scope, object) {
            if marked_untransferable {
                return Err(SerializeError::DataClone(
                    "Cannot transfer object of unsupported type.".to_string(),
                ));
            }
            // `MessagePort in transfer list is already detached`. Node's
            // `IsDetached()` is `data_ == nullptr || IsHandleClosing()`: a port
            // is detached once `close()` ran *or* once it was handed over.
            if state.closing.get() {
                return Err(SerializeError::DataClone(
                    "MessagePort in transfer list is already detached".to_string(),
                ));
            }
            transfers.transferables.push(object);
            continue;
        }

        // A host handle that can only move: a `net.Socket`'s `TCP`, a
        // `FileHandle`'s native handle. Node's `GetTransferMode() ==
        // kTransferable` test, which is exact rather than "has the bit": a
        // native handle that is `kTransferableAndCloneable` still may not be
        // listed, because a transfer list name means "move this".
        if rn_core::host_object::transfer_mode(scope, object)
            == Some(rn_core::host_object::TransferMode::Transferable)
        {
            if marked_untransferable {
                return Err(SerializeError::DataClone(
                    "Cannot transfer object of unsupported type.".to_string(),
                ));
            }
            transfers.transferables.push(object);
            continue;
        }

        // A JS transferable: `[kTransfer]` is a function, which is Node's whole
        // test. The mode is deliberately *not* consulted — a `FileHandle` is
        // `markTransferMode(this, false, true)`, so mode 1, but so is a web
        // stream, and requiring `kTransferable` on a value rustnode had marked
        // itself refused all of them with "Found invalid value in transferList.".
        if crate::js_transferable(scope, object) && !marked_untransferable {
            transfers.transferables.push(object);
            continue;
        }

        // A handle rustnode registered as cloneable, or a `JSTransferable` whose
        // mode has no `kTransferable` bit. Both are host objects a transfer list
        // cannot move, which Node reports as an invalid value rather than as
        // unsupported: the value is fine, the list is what is wrong.
        return Err(SerializeError::DataClone(
            "Found invalid value in transferList.".to_string(),
        ));
    }

    // Some objects in the transfer list register sub-objects that can be
    // transferred. This could e.g. be a public JS wrapper object, such as a
    // FileHandle, that is registering its C++ handle for transfer.
    add_nested_transferables(scope, &mut transfers)?;

    Ok(transfers)
}

/// Node's `SerializerDelegate::AddNestedHostObjects`.
///
/// A wrapper's `[kTransfer]` returns `{ data: { handle }, ... }`, and that
/// `handle` is itself a moved native object the payload will reference by id. It
/// is not in the user's transfer list, so the only way the receiver can resolve
/// it is for the sender to seed the id space with it — which is what this does,
/// before the value is written, exactly where Node does it.
///
/// The loop re-reads the collection's length each iteration because a nested
/// entry can itself have nested transferables: a `TransformStream`'s list holds
/// the two streams it is made of, and each of those registers a `MessagePort`.
/// Node's `host_objects_` grows inside its loop for the same reason.
fn add_nested_transferables<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    transfers: &mut Transfers<'s>,
) -> Result<(), SerializeError> {
    // Only the entries that can register nested ones are asked. A port has no
    // `[kTransferList]`, and a native handle's nested entries come from its own
    // kind, not from JavaScript.
    let mut index = 0;
    while index < transfers.transferables.len() {
        let host = transfers.transferables[index];
        let nested = crate::js_nested_transferables(scope, host).map_err(|()| {
            // The hook threw; the exception is pending and the caller rethrows it.
            SerializeError::Thrown
        })?;
        for entry in nested {
            // The *same* object twice would make the receiver resolve two ids to
            // one object, and moving a port twice loses the first message. Node
            // says "The transfer list is invalid." for this.
            if transfers
                .transferables
                .iter()
                .any(|existing| existing.strict_equals(entry.into()))
            {
                return Err(SerializeError::DataClone(
                    "The transfer list is invalid.".to_string(),
                ));
            }

            // A port is the common case — every web stream registers one — and
            // it has no `[kTransfer]`; it moves by giving up its queue.
            if crate::port_state_of(scope, entry).is_some()
                || rn_core::host_object::transfer_mode(scope, entry)
                    == Some(rn_core::host_object::TransferMode::Transferable)
                || crate::js_transferable(scope, entry)
            {
                transfers.transferables.push(entry);
                continue;
            }
            // `if (BaseObject::IsBaseObject) ... else if (!IsJSTransferable) continue;`
            // — a value that is neither is skipped, not an error, because the
            // hook is not user-facing.
        }
        index += 1;
    }
    Ok(())
}

/// `ReadIterable`: the entries of `object`, or `None` when it is not iterable.
///
/// Node special-cases an array (index reads, no iterator protocol), then falls
/// back to `Symbol.iterator`/`next()`/`done`, returning `Just(false)` — not an
/// error — when any piece is missing. `Some(vec![])` therefore means "iterable
/// and empty", which is a different answer from `None`.
fn read_iterable<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Result<Option<Vec<v8::Local<'s, v8::Value>>>, SerializeError> {
    if let Ok(array) = v8::Local::<v8::Array>::try_from(object) {
        let mut entries = Vec::with_capacity(array.length() as usize);
        for index in 0..array.length() {
            let Some(entry) = array.get_index(scope, index) else {
                return Err(SerializeError::Thrown);
            };
            entries.push(entry);
        }
        return Ok(Some(entries));
    }

    let Some(iterator_method) = well_known_symbol(scope, "iterator") else {
        return Ok(None);
    };
    let Some(method) = object.get(scope, iterator_method) else {
        return Err(SerializeError::Thrown);
    };
    let Ok(method) = v8::Local::<v8::Function>::try_from(method) else {
        return Ok(None);
    };
    let Some(iterator) = method.call(scope, object.into(), &[]) else {
        return Err(SerializeError::Thrown);
    };
    let Ok(iterator) = v8::Local::<v8::Object>::try_from(iterator) else {
        return Ok(None);
    };
    let Some(next) = get_key(scope, iterator, "next") else {
        return Ok(None);
    };
    let Ok(next) = v8::Local::<v8::Function>::try_from(next) else {
        return Ok(None);
    };

    let mut entries = Vec::new();
    loop {
        let Some(result) = next.call(scope, iterator.into(), &[]) else {
            return Err(SerializeError::Thrown);
        };
        let Ok(result) = v8::Local::<v8::Object>::try_from(result) else {
            return Ok(None);
        };
        let Some(done) = get_key(scope, result, "done") else {
            return Err(SerializeError::Thrown);
        };
        if done.boolean_value(scope) {
            return Ok(Some(entries));
        }
        let Some(value) = get_key(scope, result, "value") else {
            return Err(SerializeError::Thrown);
        };
        entries.push(value);
    }
}

/// `Symbol.<name>`, read off the global `Symbol` because the V8 crate exposes no
/// accessor for it.
fn well_known_symbol<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Symbol")?;
    let holder = global.get(scope, key.into())?;
    let holder = v8::Local::<v8::Object>::try_from(holder).ok()?;
    let key = v8::String::new(scope, name)?;
    let symbol = holder.get(scope, key.into())?;
    symbol.is_symbol().then_some(symbol)
}

/// Whether `markAsUntransferable(obj)` stamped `obj`.
///
/// `internal/buffer` marks this under `untransferable_object_private_symbol`
/// (`node:untransferableObject` here). Node treats that as "cannot be moved",
/// so attempting to transfer such a value must fail before any detach attempt.
fn is_untransferable_mark(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
) -> bool {
    let key = rn_core::symbol(scope, "node:untransferableObject");
    object.has(scope, key.into()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload that carries nothing, so a test can compare entries by identity.
    struct Named;

    impl TransferData for Named {
        fn rebuild<'s>(
            &self,
            scope: &mut v8::PinScope<'s, '_>,
            _target: v8::Local<'s, v8::Context>,
        ) -> Option<v8::Local<'s, v8::Object>> {
            Some(v8::Object::new(scope))
        }
    }

    #[test]
    fn a_close_marker_is_distinguishable_from_an_empty_message() {
        // Both carry no bytes, so the flag is the only thing that tells them apart.
        // `ReceiveMessage` relies on it to dispatch `close` rather than trying to
        // deserialize an empty payload.
        assert!(Message::close_marker().close);
        assert!(
            !Message::new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0,
                Vec::new()
            )
            .close
        );
    }

    #[test]
    fn one_vector_puts_every_transfer_before_every_clone() {
        // The ids the payload writes are indices into `host_objects`, so an id
        // below `transferred_count` has to name a transfer-list entry and one at
        // or above it a clone. Two vectors meant the deserializer had to guess
        // which one an id named, and a clone could resolve to a port — a wrong
        // object with the right shape rather than a clean failure.
        //
        // The names are what makes this checkable: asserting only the length
        // would pass for any ordering, including the broken one.
        let port_a: Arc<dyn TransferData> = Arc::new(Named);
        let port_b: Arc<dyn TransferData> = Arc::new(Named);
        let clone_a: Arc<dyn TransferData> = Arc::new(Named);
        let message = Message::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![port_a.clone(), port_b.clone(), clone_a.clone()],
            2,
            Vec::new(),
        );

        assert_eq!(message.transferred_count, 2, "two transfer-list entries");
        assert_eq!(
            message.host_objects.len(),
            3,
            "every id is in this one vector"
        );

        // Identity, not a downcast: the vector must hold *these* payloads at
        // *these* indices. A length check alone passes for any ordering.
        let entry = |index: usize| Arc::as_ptr(&message.host_objects[index]);
        assert_eq!(
            entry(0),
            Arc::as_ptr(&port_a),
            "id 0 must be the first transferred port"
        );
        assert_eq!(
            entry(1),
            Arc::as_ptr(&port_b),
            "id 1 must be the second transferred port"
        );
        assert_eq!(
            entry(message.transferred_count),
            Arc::as_ptr(&clone_a),
            "the id at `transferred_count` must be the first clone"
        );
    }
}

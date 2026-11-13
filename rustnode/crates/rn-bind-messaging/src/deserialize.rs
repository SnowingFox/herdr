//! Reading a posted message back, and re-attaching what it transferred.
//!
//! The counterpart of [`crate::serialize`]. Three things have to be rebuilt rather
//! than copied:
//!
//! * a transferred `ArrayBuffer`, from the backing store the sender detached, so
//!   the bytes are the same allocation and not a copy;
//! * a transferred `MessagePort`, as a *new* object around the queue the sender
//!   handed over — which is why the port is detached on the sender first;
//! * a cloned host object, from the `TransferData` the sender's clone hook
//!   produced.
//!
//! # The three phases, and why they are ordered this way
//!
//! `Message::Deserialize` in `src/node_messaging.cc` is worth following exactly,
//! because the order is not stylistic:
//!
//! 1. **Rebuild every transferred object**, before the `ValueDeserializer` exists:
//!    `host_objects[i] = data->Deserialize(env, context, ...)`. For a
//!    `JSTransferable` that calls the `setDeserializerCreateObjectFunction` hook,
//!    which is JavaScript; for a `MessagePort` it runs `oninit`, also JavaScript.
//! 2. **Read the payload**, resolving each host-object id against that vector. V8
//!    runs the `ReadHostObject` callback inside a
//!    `DisallowJavascriptExecutionScope`, so nothing here may call into JS: a
//!    rebuild attempted from inside the callback aborts the process with
//!    `Invoke in DisallowJavascriptExecutionScope` rather than reporting an error.
//! 3. **Finalize each one**: `FinalizeTransferRead`, which reads the clone's own
//!    state and calls `this[kDeserialize]`.
//!
//! Both rebuilding lazily inside the callback and calling `[kDeserialize]` from
//! inside it abort, which is how the ordering above was found.

use rn_v8_sys::v8;

/// The objects one message rebuilt, in the id order the payload references.
///
/// Transfer-list entries first, then clones — Node's receiving `host_objects`
/// vector. One vector, because the serializer wrote one id space: an id is an
/// index into this, with no boundary to get wrong.
struct Rebuilt {
    /// Every rebuilt object, by the id the payload used for it.
    objects: Vec<v8::Global<v8::Object>>,
}

/// The delegate V8 asks for a host object by id.
///
/// Holds the already-rebuilt objects rather than building them, because
/// `read_host_object` runs with JavaScript disabled.
struct Lookup<'a> {
    rebuilt: &'a Rebuilt,
    /// One `SharedArrayBuffer` per backing store the message carries, in id order.
    ///
    /// Node builds this vector before reading the payload
    /// (`Message::Deserialize`'s `shared_array_buffers`), so each id resolves to
    /// exactly one object. Building it here rather than on demand is what keeps
    /// two references to one shared buffer pointing at one buffer.
    shared_array_buffers: &'a [v8::Global<v8::SharedArrayBuffer>],
}

impl v8::ValueDeserializerImpl for Lookup<'_> {
    fn read_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        deserializer: &dyn v8::ValueDeserializerHelper,
    ) -> Option<v8::Local<'s, v8::Object>> {
        let mut id = 0u32;
        if !deserializer.read_uint32(&mut id) {
            // Throwing is allowed here even though calling JS is not: V8's scope
            // forbids *executing* JavaScript, not raising an exception.
            crate::throw_type_error(scope, "Could not read a transferred object's id");
            return None;
        }
        // One id space, so one lookup: the id the payload carries is an index into
        // the vector `rebuild` produced, in the same order the serializer numbered.
        //
        // `kNormalObject` is the exception, and it is not an index: the sender
        // used it to say "the value that follows is a plain object", which is how
        // `structuredClone(process.env)` and `postMessage(process.env)` carry the
        // variables rather than a live proxy. Node's `ReadHostObject` reads a
        // value in that case and returns it.
        if id == crate::K_NORMAL_OBJECT {
            return match deserializer.read_value(scope.get_current_context()) {
                Some(value) => v8::Local::<v8::Object>::try_from(value).ok(),
                None => None,
            };
        }
        let object = self.rebuilt.objects.get(id as usize);
        let Some(object) = object else {
            crate::throw_type_error(scope, "The message referenced an object that was not sent");
            return None;
        };
        Some(v8::Local::new(scope, object))
    }

    fn get_shared_array_buffer_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        transfer_id: u32,
    ) -> Option<v8::Local<'s, v8::SharedArrayBuffer>> {
        // Node's `Message::Deserialize` resolves this id against
        // `shared_array_buffers`, the vector built from the message's own list.
        // There is nothing to transfer here: the buffer was never detached, so
        // the sender and the receiver hold the same allocation.
        let Some(buffer) = self.shared_array_buffers.get(transfer_id as usize) else {
            crate::throw_type_error(
                scope,
                "The message referenced a shared buffer that was not sent",
            );
            return None;
        };
        Some(v8::Local::new(scope, buffer))
    }

    fn get_wasm_module_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _clone_id: u32,
    ) -> Option<v8::Local<'s, v8::WasmModuleObject>> {
        crate::throw_type_error(scope, "Cannot transfer a WebAssembly.Module");
        None
    }
}

/// Reads one message's payload, re-attaching everything it transferred.
pub fn deserialize<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    message: &crate::port::Message,
) -> Result<Deserialized<'s>, ()> {
    // Phase 1: every transferred object, before V8 is involved. Both kinds reach
    // JavaScript — a `PortTransferData::rebuild` builds a port object and runs its
    // `oninit`, and a clone's `rebuild` calls the create-object hook — which is
    // exactly why they cannot happen inside `read_host_object`.
    let mut objects = Vec::with_capacity(message.host_objects.len());
    for payload in message.host_objects.iter() {
        // `rebuild` is where a transfer is inverted: `TransferForMessaging` ran on
        // the sender, and this builds the receiving object from the moved state.
        let rebuilt = payload.rebuild(scope).ok_or(())?;
        objects.push(v8::Global::new(scope, rebuilt));
    }
    let rebuilt = Rebuilt { objects };

    // Phase 1b: one `SharedArrayBuffer` per backing store the message carried.
    // Built before the payload is read so an id resolves to exactly one object,
    // which is what makes two references to one shared buffer stay one buffer.
    // `with_backing_store` attaches the same allocation rather than copying it.
    let shared_array_buffers: Vec<v8::Global<v8::SharedArrayBuffer>> = message
        .shared_array_buffers
        .iter()
        .map(|store| {
            let buffer = v8::SharedArrayBuffer::with_backing_store(scope, store);
            v8::Global::new(scope, buffer)
        })
        .collect();

    // Phase 2: the payload. No JavaScript from here until `read_value` returns.
    let deserializer = v8::ValueDeserializer::new(
        scope,
        Box::new(Lookup {
            rebuilt: &rebuilt,
            shared_array_buffers: &shared_array_buffers,
        }),
        &message.data,
    );
    for (id, store) in message.array_buffers.iter().enumerate() {
        let buffer = v8::ArrayBuffer::with_backing_store(scope, store);
        v8::ValueDeserializerHelper::transfer_array_buffer(&deserializer, id as u32, buffer);
    }
    let context = scope.get_current_context();
    // `ReadHeader`, the counterpart of the `WriteHeader` in
    // `crate::serialize::serialize`. It selects V8's streaming reader; without it
    // `ReadValue` uses `ReadObjectUsingEntireBufferForLegacyFormat`, which consumes
    // the whole buffer and therefore rejects the clone data appended after the
    // payload.
    if v8::ValueDeserializerHelper::read_header(&deserializer, context) != Some(true) {
        return Err(());
    }
    let value = deserializer.read_value(context).ok_or(())?;

    // Phase 3: each clone's own state, then `this[kDeserialize]`. The sender
    // appended one value per clone in vector order after the payload, so reading
    // them back in the same order is the contract between the two halves. A
    // transferred port has no trailing state, so its `read_data` is the default
    // no-op.
    for (payload, target) in message.host_objects.iter().zip(&rebuilt.objects) {
        let target: v8::Local<v8::Object> = v8::Local::new(scope, target);
        if !payload.read_data(scope, &deserializer, target) {
            return Err(());
        }
    }
    drop(deserializer);

    // `emitMessage(data, ports, type)` wants the transferred ports alone, and a
    // rebuilt port is the only object here that answers `port_state_of`. Filtering
    // the one vector this way keeps the ports array in id order without a second
    // list to keep in step.
    let ports = rebuilt
        .objects
        .iter()
        .filter(|object| {
            let object: v8::Local<v8::Object> = v8::Local::new(scope, *object);
            crate::port_state_of(scope, object).is_some()
        })
        .cloned()
        .collect();

    Ok(Deserialized { value, ports })
}

/// What one message deserialized into.
pub struct Deserialized<'s> {
    /// The message payload.
    pub value: v8::Local<'s, v8::Value>,
    /// The ports it carried, as the objects the receiver now owns.
    pub ports: Vec<v8::Global<v8::Object>>,
}

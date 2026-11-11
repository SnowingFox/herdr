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
/// Transfer-list slots first, then clones — Node's receiving `host_objects` vector,
/// and the reason [`crate::port::Message::transferred_count`] exists.
struct Rebuilt {
    /// The ports, as the objects the receiver now owns.
    ports: Vec<v8::Global<v8::Object>>,
    /// The cloned host objects.
    hosts: Vec<v8::Global<v8::Object>>,
}

/// The delegate V8 asks for a host object by id.
///
/// Holds the already-rebuilt objects rather than building them, because
/// `read_host_object` runs with JavaScript disabled.
struct Lookup<'a> {
    rebuilt: &'a Rebuilt,
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
        // One id space: below the boundary is a transfer-list slot, at or above it
        // is a clone. Getting this wrong resolves a clone against a port and
        // produces an object of the wrong type rather than a clean failure.
        let ports = self.rebuilt.ports.len();
        let object = if (id as usize) < ports {
            self.rebuilt.ports.get(id as usize)
        } else {
            self.rebuilt.hosts.get(id as usize - ports)
        };
        let Some(object) = object else {
            crate::throw_type_error(scope, "The message referenced an object that was not sent");
            return None;
        };
        Some(v8::Local::new(scope, object))
    }

    fn get_shared_array_buffer_from_id<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _transfer_id: u32,
    ) -> Option<v8::Local<'s, v8::SharedArrayBuffer>> {
        // A shared buffer cannot be transferred, only shared, and sharing one
        // between two threads is the case this build does not have a Worker for.
        crate::throw_type_error(
            scope,
            "Cannot transfer a SharedArrayBuffer without a second thread",
        );
        None
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
    // Phase 1: every transferred object, before V8 is involved. Both of these reach
    // JavaScript — `clone_port_into` runs the port's `oninit`, and a clone's
    // `rebuild` calls the create-object hook — which is exactly why they cannot
    // happen inside `read_host_object`.
    let mut ports = Vec::with_capacity(message.ports.len());
    for source in &message.ports {
        let source: v8::Local<v8::Object> = v8::Local::new(scope, source);
        let rebuilt = crate::clone_port_into(scope, source).ok_or(())?;
        ports.push(v8::Global::new(scope, rebuilt));
    }
    let mut hosts = Vec::with_capacity(message.host_objects.len());
    for clone in message.host_objects.iter() {
        // `rebuild` is where a clone hook is inverted: `[kClone]` ran on the
        // sender, and this builds the object `[kDeserialize]` will fill in.
        let rebuilt = clone.rebuild(scope).ok_or(())?;
        hosts.push(v8::Global::new(scope, rebuilt));
    }
    let rebuilt = Rebuilt { ports, hosts };

    // Phase 2: the payload. No JavaScript from here until `read_value` returns.
    let deserializer =
        v8::ValueDeserializer::new(scope, Box::new(Lookup { rebuilt: &rebuilt }), &message.data);
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
    // them back in the same order is the contract between the two halves.
    for (clone, target) in message.host_objects.iter().zip(&rebuilt.hosts) {
        let target: v8::Local<v8::Object> = v8::Local::new(scope, target);
        if !clone.read_data(scope, &deserializer, target) {
            return Err(());
        }
    }
    drop(deserializer);

    Ok(Deserialized {
        value,
        ports: rebuilt.ports,
    })
}

/// What one message deserialized into.
pub struct Deserialized<'s> {
    /// The message payload.
    pub value: v8::Local<'s, v8::Value>,
    /// The ports it carried, as the objects the receiver now owns.
    pub ports: Vec<v8::Global<v8::Object>>,
}

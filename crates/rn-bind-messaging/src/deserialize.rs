//! Reading a posted message back, and re-attaching what it transferred.
//!
//! The counterpart of [`crate::serialize`]. Two things have to be rebuilt rather
//! than copied:
//!
//! * a transferred `ArrayBuffer`, from the backing store the sender detached, so
//!   the bytes are the same allocation and not a copy;
//! * a transferred `MessagePort`, as a *new* object around the queue the sender
//!   handed over — which is why the port is detached on the sender first.
//!
//! `ValueDeserializerImpl` asks for both through callbacks keyed by id, and the
//! id is the index the serializer wrote.

use rn_v8_sys::v8;

/// Rebuilds the objects one message carried.
///
/// Borrows the sender-side state rather than owning it so the deserializer, which
/// is a stack object, can hand it values one at a time.
pub struct Rebuild<'a, 's> {
    /// The ports handed over, still owned by the message until claimed.
    ///
    /// `RefCell` because `read_host_object` runs with only a shared borrow of the
    /// delegate and each port can be claimed once.
    pub ports: &'a std::cell::RefCell<Vec<v8::Global<v8::Object>>>,
    /// The ports rebuilt for this message, in id order.
    pub rebuilt: &'a std::cell::RefCell<Vec<v8::Global<v8::Object>>>,
    /// A scope marker so the lifetimes line up with the trait's.
    pub _scope: std::marker::PhantomData<&'s ()>,
}

impl v8::ValueDeserializerImpl for Rebuild<'_, '_> {
    fn read_host_object<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        deserializer: &dyn v8::ValueDeserializerHelper,
    ) -> Option<v8::Local<'s, v8::Object>> {
        let mut id = 0u32;
        if !deserializer.read_uint32(&mut id) {
            crate::throw_type_error(scope, "Could not read the transferred port's id");
            return None;
        }
        let source = {
            let ports = self.ports.borrow();
            ports.get(id as usize).cloned()
        };
        let Some(source) = source else {
            crate::throw_type_error(scope, "The message referenced a port that was not sent");
            return None;
        };

        // Take the queue out of the sender's object and build a fresh port around
        // it. The sender's object was already detached by `serialize`, so it can
        // no longer post or receive; the new object is the live end.
        let source: v8::Local<v8::Object> = v8::Local::new(scope, &source);
        let rebuilt = crate::clone_port_into(scope, source)?;
        self.rebuilt
            .borrow_mut()
            .push(v8::Global::new(scope, rebuilt));
        Some(rebuilt)
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
///
/// `array_buffers` is attached before `read_value` because the deserializer
/// resolves a buffer's transfer id during the read and finds nothing if the slot
/// is still empty.
pub fn deserialize<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    data: &[u8],
    array_buffers: &[v8::SharedRef<v8::BackingStore>],
) -> Result<Deserialized<'s>, ()> {
    let ports = std::cell::RefCell::new(Vec::new());
    let rebuilt = std::cell::RefCell::new(Vec::new());

    let deserializer = v8::ValueDeserializer::new(
        scope,
        Box::new(Rebuild {
            ports: &ports,
            rebuilt: &rebuilt,
            _scope: std::marker::PhantomData,
        }),
        data,
    );

    for (id, store) in array_buffers.iter().enumerate() {
        let buffer = v8::ArrayBuffer::with_backing_store(scope, store);
        v8::ValueDeserializerHelper::transfer_array_buffer(&deserializer, id as u32, buffer);
    }

    let context = scope.get_current_context();
    let value = deserializer.read_value(context).ok_or(())?;
    // `deserializer` borrows `rebuilt`, so drop it before moving the vector out.
    drop(deserializer);
    Ok(Deserialized {
        value,
        ports: rebuilt.into_inner(),
    })
}

/// What one message deserialized into.
pub struct Deserialized<'s> {
    /// The message payload.
    pub value: v8::Local<'s, v8::Value>,
    /// The ports it carried, as the objects the receiver now owns.
    pub ports: Vec<v8::Global<v8::Object>>,
}

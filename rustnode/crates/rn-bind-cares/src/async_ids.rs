//! The `AsyncWrap` identity of the `cares_wrap` resources.
//!
//! Four classes in `src/cares_wrap.cc` derive from `AsyncWrap`: `ChannelWrap`
//! (`:958`), `GetAddrInfoReqWrap`, `GetNameInfoReqWrap` and `QueryReqWrap`
//! (`MakeLazilyInitializedJSTemplate` subclasses created at `:1` of their
//! `New`). Each one emits an `init` with its own provider, and each one's
//! completion is a `MakeCallback`, so a hook pair is observable around it.
//!
//! # Why the ids live behind an internal field
//!
//! `ChannelWrap` already stores its channel key in field 0, and the request
//! wraps store nothing. Node keeps the ids in C++ state that outlives the
//! constructor; here the completion needs them after the constructor's scope is
//! gone, so each object gets one additional field holding a boxed
//! [`rn_core::AsyncWrapState`].
//!
//! A request wrap is created and discarded per request, so its state is freed by
//! the same guaranteed finalizer that frees the object. `ChannelWrap` lives as
//! long as the `Resolver` that owns it.

use rn_v8_sys::v8;

/// The internal field `ChannelWrap` keeps its async identity in.
///
/// Field 0 is the channel key (`install.rs`'s `install_channel_key`), so this is
/// the next free slot.
pub const CHANNEL_ASYNC_FIELD: i32 = 1;

/// The internal field every request wrap keeps its async identity in.
///
/// The request wraps have no other state, so this is their only field.
pub const REQUEST_ASYNC_FIELD: i32 = 0;

/// `new ChannelWrap(...)` / `new GetAddrInfoReqWrap()`: emit `init` and record
/// the ids on `object`.
pub fn begin(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    provider: u32,
) -> Option<rn_core::AsyncWrapState> {
    begin_in(scope, object, provider, field_for(provider)?)
}

/// Reads back the state [`begin`] stored, if the object carries one.
pub fn state_of(
    object: v8::Local<v8::Object>,
    provider: u32,
) -> Option<rn_core::AsyncWrapState> {
    read(object, field_for(provider)?)
}

/// Which internal field a provider's state lives in.
///
/// Only `ChannelWrap` has another field to stay clear of; every request wrap is
/// empty otherwise.
pub fn field_for(provider: u32) -> Option<i32> {
    if provider == rn_core::async_wrap::PROVIDER_DNSCHANNEL {
        Some(CHANNEL_ASYNC_FIELD)
    } else if matches!(
        provider,
        rn_core::async_wrap::PROVIDER_GETADDRINFOREQWRAP
            | rn_core::async_wrap::PROVIDER_GETNAMEINFOREQWRAP
            | rn_core::async_wrap::PROVIDER_QUERYWRAP
    ) {
        Some(REQUEST_ASYNC_FIELD)
    } else {
        None
    }
}

fn begin_in(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    provider: u32,
    field: i32,
) -> Option<rn_core::AsyncWrapState> {
    let (async_id, trigger_async_id) =
        rn_bind_async_wrap::emit_init_for_new_resource(scope, object, provider)?;
    let state = Box::new(rn_core::AsyncWrapState {
        async_id,
        trigger_async_id,
        provider,
    });
    object.set_aligned_pointer_in_internal_field(
        field,
        Box::into_raw(state).cast_const().cast(),
        0,
    );
    // SAFETY: the pointer was just written to this object's own field.
    let address = unsafe { object.get_aligned_pointer_from_internal_field(field, 0) } as usize;
    v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut rn_core::AsyncWrapState;
            // SAFETY: allocated just above for this object alone, freed once by
            // the finalizer V8 guarantees to run.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
    Some(rn_core::AsyncWrapState {
        async_id,
        trigger_async_id,
        provider,
    })
}

fn read(object: v8::Local<v8::Object>, field: i32) -> Option<rn_core::AsyncWrapState> {
    if object.internal_field_count() <= field as usize {
        return None;
    }
    // SAFETY: the field only ever holds a pointer produced by `begin_in`, and the
    // object is live for the duration of this call.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(field, 0) }
        as *const rn_core::AsyncWrapState;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above; the allocation is owned by this object.
    Some(unsafe { *pointer })
}

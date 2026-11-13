//! `refreshDefaultSettings` and `packSettings`.
//!
//! Both work on `settingsBuffer`, the shared `Uint32Array(29)` in
//! [`crate::state`]. The layout is seven setting values, then `IDX_SETTINGS_COUNT`
//! (a bitset naming which of the seven are present), then the number of custom
//! settings, then `[id, value]` pairs:
//!
//! ```text
//!  0  1  2  3  4  5  6 | 7 | 8 | 9  10 | 11 12 | ...
//!  HT EP IW MF MC HL CP | F | N | id val| id val| ...
//! ```
//!
//! # `refreshDefaultSettings`
//!
//! `Http2Settings::RefreshDefaults` writes every default and sets every flag bit.
//! `lib/internal/http2/util.js:getDefaultSettings` clears the flags and count
//! first, calls this, then reads only the settings whose bit is set. So this must
//! set all seven bits — writing values without the bits would produce an empty
//! settings object, which is the failure mode the JS comment at that call site
//! ("`binding.refreshDefaultSettings()`") exists to prevent.
//!
//! The defaults are `node_http2.h`'s `DEFAULT_SETTINGS_*` constants, not
//! nghttp2's. `DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE` is **4194304**, not the
//! protocol's 65535, and `DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS` is
//! `0xffffffff`. Those two are the ones a reader is most likely to "correct" to
//! the RFC values; `test-http2-binding.js` asserts both.
//!
//! # `packSettings`
//!
//! `Http2Settings::Pack` builds the `nghttp2_settings_entry` array from the
//! buffer, calls `nghttp2_pack_settings_payload`, and wraps the result in a
//! `Buffer`. The buffer is six bytes per entry, big-endian: two bytes of id, four
//! of value. nghttp2 does the serialization, so the byte order is its business.
//!
//! Two failures have to be distinguishable here. `getPackedSettings` validates the
//! settings object in JavaScript before calling this, so an invalid value never
//! reaches the buffer through that path; but `nghttp2_pack_settings_payload`
//! returns a negative value for an over-long entry array, and `Pack` returns
//! `undefined` in that case rather than a truncated buffer.

use rn_v8_sys::v8;

use crate::ffi;
use crate::state::{
    self, IDX_SETTINGS_COUNT, IDX_SETTINGS_ENABLE_CONNECT_PROTOCOL, IDX_SETTINGS_ENABLE_PUSH,
    IDX_SETTINGS_HEADER_TABLE_SIZE, IDX_SETTINGS_INITIAL_WINDOW_SIZE,
    IDX_SETTINGS_MAX_CONCURRENT_STREAMS, IDX_SETTINGS_MAX_FRAME_SIZE,
    IDX_SETTINGS_MAX_HEADER_LIST_SIZE, MAX_ADDITIONAL_SETTINGS,
};

/// `DEFAULT_SETTINGS_HEADER_TABLE_SIZE` from `node_http2.h`.
pub const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;
/// `DEFAULT_SETTINGS_ENABLE_PUSH`.
pub const DEFAULT_ENABLE_PUSH: u32 = 1;
/// `DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS`, which is `0xffffffff`.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 0xffff_ffff;
/// `DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE`, which is 4 MiB rather than the RFC's
/// 65535. Node raises it deliberately for throughput; see the comment at
/// `Http2Session`'s constructor in `lib/internal/http2/core.js`.
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 4_194_304;
/// `DEFAULT_SETTINGS_MAX_FRAME_SIZE`.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
/// `DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE`.
pub const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 65_535;
/// `DEFAULT_SETTINGS_ENABLE_CONNECT_PROTOCOL`.
pub const DEFAULT_ENABLE_CONNECT_PROTOCOL: u32 = 0;

/// `Http2Settings::RefreshDefaults`: write every default and set every flag bit.
pub fn refresh_defaults(state: &state::Http2State) {
    let defaults = [
        (IDX_SETTINGS_HEADER_TABLE_SIZE, DEFAULT_HEADER_TABLE_SIZE),
        (IDX_SETTINGS_ENABLE_PUSH, DEFAULT_ENABLE_PUSH),
        (
            IDX_SETTINGS_INITIAL_WINDOW_SIZE,
            DEFAULT_INITIAL_WINDOW_SIZE,
        ),
        (IDX_SETTINGS_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE),
        (
            IDX_SETTINGS_MAX_CONCURRENT_STREAMS,
            DEFAULT_MAX_CONCURRENT_STREAMS,
        ),
        (
            IDX_SETTINGS_MAX_HEADER_LIST_SIZE,
            DEFAULT_MAX_HEADER_LIST_SIZE,
        ),
        (
            IDX_SETTINGS_ENABLE_CONNECT_PROTOCOL,
            DEFAULT_ENABLE_CONNECT_PROTOCOL,
        ),
    ];
    let mut flags = 0u32;
    for (index, value) in defaults {
        state.set_setting(index, value);
        flags |= 1 << index;
    }
    state.set_setting(IDX_SETTINGS_COUNT, flags);
    // No additional settings.
    state.set_setting(IDX_SETTINGS_COUNT + 1, 0);
}

/// `Http2Settings::Init`: the entries the buffer currently describes.
///
/// The seven known settings come first, in the order `HTTP2_SETTINGS` lists them,
/// and then any custom ones. The order matters because `nghttp2_pack_settings_payload`
/// writes the array out as given, and `test-http2-getpackedsettings.js` compares the
/// whole buffer to a literal byte string.
pub fn entries(state: &state::Http2State) -> Vec<ffi::nghttp2_settings_entry> {
    let flags = state.setting(IDX_SETTINGS_COUNT);
    let mut entries = Vec::with_capacity(IDX_SETTINGS_COUNT + MAX_ADDITIONAL_SETTINGS);
    let mut push = |set: usize, id: i32| {
        if flags & (1 << set) != 0 {
            entries.push(ffi::nghttp2_settings_entry {
                settings_id: id,
                value: state.setting(set),
            });
        }
    };
    push(
        IDX_SETTINGS_HEADER_TABLE_SIZE,
        ffi::NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
    );
    push(IDX_SETTINGS_ENABLE_PUSH, ffi::NGHTTP2_SETTINGS_ENABLE_PUSH);
    push(
        IDX_SETTINGS_MAX_CONCURRENT_STREAMS,
        ffi::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    );
    push(
        IDX_SETTINGS_INITIAL_WINDOW_SIZE,
        ffi::NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    );
    push(
        IDX_SETTINGS_MAX_FRAME_SIZE,
        ffi::NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
    );
    push(
        IDX_SETTINGS_MAX_HEADER_LIST_SIZE,
        ffi::NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
    );
    push(
        IDX_SETTINGS_ENABLE_CONNECT_PROTOCOL,
        ffi::NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    );

    let custom = state.setting(IDX_SETTINGS_COUNT + 1) as usize;
    let base = IDX_SETTINGS_COUNT + 1 + 1;
    for index in 0..custom.min(MAX_ADDITIONAL_SETTINGS) {
        let id = state.setting(base + index * 2);
        let value = state.setting(base + index * 2 + 1);
        // A custom setting is a 16-bit id from the wire, so a value that does not
        // fit is not one nghttp2 can frame.
        if let Ok(id) = i32::try_from(id) {
            entries.push(ffi::nghttp2_settings_entry {
                settings_id: id,
                value,
            });
        }
    }
    entries
}

/// `Http2Settings::Pack`: the serialized SETTINGS payload as a `Buffer`.
///
/// `None` when nghttp2 rejects the payload, which is what `Pack` reports as
/// `undefined`.
pub fn pack<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &state::Http2State,
) -> Option<v8::Local<'s, v8::Value>> {
    let entries = entries(state);
    // Six bytes per entry: `nghttp2_pack_settings_payload` writes exactly that.
    let mut payload = vec![0u8; entries.len() * 6];
    // SAFETY: `payload` is writable for its whole length and `entries` is a live
    // slice of the right element type.
    let written = unsafe {
        ffi::nghttp2_pack_settings_payload(
            payload.as_mut_ptr(),
            payload.len(),
            entries.as_ptr(),
            entries.len(),
        )
    };
    if written < 0 {
        return None;
    }
    payload.truncate(usize::try_from(written).ok()?);
    // `Pack` returns a `Buffer`, not a `Uint8Array`:
    // `test-http2-getpackedsettings.js` compares the result to `Buffer.from(...)`
    // with `deepStrictEqual`, which distinguishes the two by constructor.
    buffer_from(scope, &payload)
}

/// Builds a real `Buffer` over `bytes`.
///
/// `Buffer.from(arrayBuffer, 0, length)` off the global `Buffer` rather than a
/// bare `Uint8Array`: the callers compare against `Buffer` instances and use
/// `.toString('base64')`.
fn buffer_from<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice())
            .make_shared();
    let array_buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let buffer = buffer_constructor(scope)?;
    let from_key = v8::String::new(scope, "from")?;
    let from = buffer.get(scope, from_key.into())?;
    let from = v8::Local::<v8::Function>::try_from(from).ok()?;
    let start = v8::Integer::new(scope, 0);
    let length = v8::Integer::new(scope, i32::try_from(bytes.len()).ok()?);
    let called = from.call(
        scope,
        buffer.into(),
        &[array_buffer.into(), start.into(), length.into()],
    )?;
    called.is_object().then_some(called)
}

/// The global `Buffer` constructor object.
fn buffer_constructor<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let value = global.get(scope, key.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::NUMBERS;

    fn published(name: &str) -> f64 {
        NUMBERS
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| *value)
            .expect("the constant is published")
    }

    #[test]
    fn the_defaults_are_the_published_constants() {
        // `refreshDefaultSettings`'s output is compared against
        // `constants.DEFAULT_SETTINGS_*` by `test-http2-binding.js`, so both have
        // to come from the same numbers. The interesting pair is the initial
        // window: 4194304 here, 65535 in the RFC.
        assert_eq!(
            published("DEFAULT_SETTINGS_HEADER_TABLE_SIZE"),
            f64::from(DEFAULT_HEADER_TABLE_SIZE)
        );
        assert_eq!(
            published("DEFAULT_SETTINGS_ENABLE_PUSH"),
            f64::from(DEFAULT_ENABLE_PUSH)
        );
        assert_eq!(
            published("DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS"),
            f64::from(DEFAULT_MAX_CONCURRENT_STREAMS)
        );
        assert_eq!(
            published("DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE"),
            f64::from(DEFAULT_INITIAL_WINDOW_SIZE)
        );
        assert_eq!(
            published("DEFAULT_SETTINGS_MAX_FRAME_SIZE"),
            f64::from(DEFAULT_MAX_FRAME_SIZE)
        );
        assert_eq!(
            published("DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE"),
            f64::from(DEFAULT_MAX_HEADER_LIST_SIZE)
        );
        assert_eq!(
            published("DEFAULT_SETTINGS_ENABLE_CONNECT_PROTOCOL"),
            f64::from(DEFAULT_ENABLE_CONNECT_PROTOCOL)
        );
    }

    #[test]
    fn the_initial_window_default_is_not_the_rfc_one() {
        // The trap: this looks wrong and is right. Node raises the initial stream
        // window from the protocol's 65535 to 4 MiB for throughput
        // (nodejs/node#38426), and `Http2Session` relies on the raised value
        // being what `settings()` sends when the caller did not say otherwise.
        assert_eq!(DEFAULT_INITIAL_WINDOW_SIZE, 4 * 1024 * 1024);
        assert_ne!(DEFAULT_INITIAL_WINDOW_SIZE, 65_535);
    }

    #[test]
    fn all_seven_flag_bits_are_set() {
        // `getDefaultSettings` reads only the settings whose bit is set, so
        // writing values without flags yields `{}` — a plausible-looking empty
        // object rather than an error.
        let mut flags = 0u32;
        for index in 0..IDX_SETTINGS_COUNT {
            flags |= 1 << index;
        }
        assert_eq!(flags, 0b0111_1111);
    }
}

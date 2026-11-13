//! The shared typed arrays `lib/internal/http2/*.js` reads and writes.
//!
//! Node's `Http2State` (`src/node_http2_state.h`) allocates one
//! `http2_state_internal` struct and exposes five views into it as
//! `AliasedBuffer`s, so the JavaScript and C++ sides index one allocation. The
//! views are:
//!
//! | member | element | length | who writes |
//! | --- | --- | --- | --- |
//! | `sessionState` | `Float64Array` | 9 | native, before `refreshState` returns |
//! | `streamState` | `Float64Array` | 6 | native, before `refreshState` returns |
//! | `settingsBuffer` | `Uint32Array` | 29 | both |
//! | `optionsBuffer` | `Uint32Array` | 14 | JavaScript, read natively at session construction |
//! | `streamStats`, `sessionStats` | `Float64Array` | 6 and 9 | native |
//!
//! # Why one allocation
//!
//! `http2_state_internal` places the `double` arrays first so they are
//! `sizeof(double)`-aligned, then the two `uint32_t` arrays. The views are taken
//! with `offsetof`, not with separate allocations. Nothing in `lib/**` reads a
//! view through another's `.buffer`, so a split allocation would not be
//! *observable* today — but the shared buffer is what makes `optionsBuffer`'s
//! writes in `updateOptionsBuffer` and this crate's reads at construction one
//! piece of memory, and reproducing it costs nothing.
//!
//! `settingsBuffer`'s length is the interesting one: seven settings values, then
//! `IDX_SETTINGS_COUNT` (the flag bitset), then the count of custom settings,
//! then `2 * MAX_ADDITIONAL_SETTINGS`. `MAX_ADDITIONAL_SETTINGS` is 10, so the
//! length is `7 + 1 + 1 + 20 = 29`, which is also what `settingsBuffer.length` is
//! in a real Node.
//!
//! # Why the crate holds them
//!
//! `internalBinding('http2')` returns the same object to every caller, and the
//! arrays are per-realm in Node (`Realm::AddBindingData`). rustnode's registry
//! caches the installed namespace object per isolate, so a `thread_local` holding
//! the buffers has the same lifetime and the same sharing. It also means the
//! `refreshDefaultSettings` function can write into them without taking a scope
//! from the caller beyond the one it already has.

use std::cell::RefCell;

use rn_core::{AliasedUint8Array, Element};
use rn_v8_sys::v8;

/// `IDX_SESSION_STATE_COUNT`: how many `double`s `sessionState` holds.
pub const SESSION_STATE_COUNT: usize = 9;
/// `IDX_STREAM_STATE_COUNT`.
pub const STREAM_STATE_COUNT: usize = 6;
/// `IDX_SETTINGS_COUNT + 1 + 1 + 2 * MAX_ADDITIONAL_SETTINGS`.
pub const SETTINGS_BUFFER_LENGTH: usize = 29;
/// `IDX_OPTIONS_FLAGS + 1`, which is `optionsBuffer.length`.
pub const OPTIONS_BUFFER_LENGTH: usize = 15;
/// `IDX_STREAM_STATS_COUNT`.
pub const STREAM_STATS_COUNT: usize = 6;
/// `IDX_SESSION_STATS_COUNT`.
pub const SESSION_STATS_COUNT: usize = 9;

/// `MAX_ADDITIONAL_SETTINGS` from `node_http2_state.h`.
pub const MAX_ADDITIONAL_SETTINGS: usize = 10;

// `Http2SettingsIndex`.
/// `IDX_SETTINGS_HEADER_TABLE_SIZE`.
pub const IDX_SETTINGS_HEADER_TABLE_SIZE: usize = 0;
/// `IDX_SETTINGS_ENABLE_PUSH`.
pub const IDX_SETTINGS_ENABLE_PUSH: usize = 1;
/// `IDX_SETTINGS_INITIAL_WINDOW_SIZE`.
pub const IDX_SETTINGS_INITIAL_WINDOW_SIZE: usize = 2;
/// `IDX_SETTINGS_MAX_FRAME_SIZE`.
pub const IDX_SETTINGS_MAX_FRAME_SIZE: usize = 3;
/// `IDX_SETTINGS_MAX_CONCURRENT_STREAMS`.
pub const IDX_SETTINGS_MAX_CONCURRENT_STREAMS: usize = 4;
/// `IDX_SETTINGS_MAX_HEADER_LIST_SIZE`.
pub const IDX_SETTINGS_MAX_HEADER_LIST_SIZE: usize = 5;
/// `IDX_SETTINGS_ENABLE_CONNECT_PROTOCOL`.
pub const IDX_SETTINGS_ENABLE_CONNECT_PROTOCOL: usize = 6;
/// `IDX_SETTINGS_COUNT`: the flag bitset, one bit per setting above.
pub const IDX_SETTINGS_COUNT: usize = 7;

// `Http2OptionsIndex`.
/// The fifteen `IDX_OPTIONS_*` positions `updateOptionsBuffer` writes.
pub mod options {
    /// `IDX_OPTIONS_MAX_DEFLATE_DYNAMIC_TABLE_SIZE`.
    pub const MAX_DEFLATE_DYNAMIC_TABLE_SIZE: usize = 0;
    /// `IDX_OPTIONS_MAX_RESERVED_REMOTE_STREAMS`.
    pub const MAX_RESERVED_REMOTE_STREAMS: usize = 1;
    /// `IDX_OPTIONS_MAX_SEND_HEADER_BLOCK_LENGTH`.
    pub const MAX_SEND_HEADER_BLOCK_LENGTH: usize = 2;
    /// `IDX_OPTIONS_PEER_MAX_CONCURRENT_STREAMS`.
    pub const PEER_MAX_CONCURRENT_STREAMS: usize = 3;
    /// `IDX_OPTIONS_PADDING_STRATEGY`.
    pub const PADDING_STRATEGY: usize = 4;
    /// `IDX_OPTIONS_MAX_HEADER_LIST_PAIRS`.
    pub const MAX_HEADER_LIST_PAIRS: usize = 5;
    /// `IDX_OPTIONS_MAX_OUTSTANDING_PINGS`.
    pub const MAX_OUTSTANDING_PINGS: usize = 6;
    /// `IDX_OPTIONS_MAX_OUTSTANDING_SETTINGS`.
    pub const MAX_OUTSTANDING_SETTINGS: usize = 7;
    /// `IDX_OPTIONS_MAX_SESSION_MEMORY`.
    pub const MAX_SESSION_MEMORY: usize = 8;
    /// `IDX_OPTIONS_MAX_SETTINGS`.
    pub const MAX_SETTINGS: usize = 9;
    /// `IDX_OPTIONS_STREAM_RESET_RATE`.
    pub const STREAM_RESET_RATE: usize = 10;
    /// `IDX_OPTIONS_STREAM_RESET_BURST`.
    pub const STREAM_RESET_BURST: usize = 11;
    /// `IDX_OPTIONS_STRICT_HTTP_FIELD_WHITESPACE_VALIDATION`.
    pub const STRICT_HTTP_FIELD_WHITESPACE_VALIDATION: usize = 12;
    /// `IDX_OPTIONS_CONNECTION_WINDOW_SIZE`.
    pub const CONNECTION_WINDOW_SIZE: usize = 13;
    /// `IDX_OPTIONS_FLAGS`: the bitset naming which of the above JavaScript set.
    pub const FLAGS: usize = 14;
}

// `Http2SessionStateIndex`, as positions in `sessionState`.
/// `IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE`.
pub const IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE: usize = 0;
/// `IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH`.
pub const IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH: usize = 1;
/// `IDX_SESSION_STATE_NEXT_STREAM_ID`.
pub const IDX_SESSION_STATE_NEXT_STREAM_ID: usize = 2;
/// `IDX_SESSION_STATE_LOCAL_WINDOW_SIZE`.
pub const IDX_SESSION_STATE_LOCAL_WINDOW_SIZE: usize = 3;
/// `IDX_SESSION_STATE_LAST_PROC_STREAM_ID`.
pub const IDX_SESSION_STATE_LAST_PROC_STREAM_ID: usize = 4;
/// `IDX_SESSION_STATE_REMOTE_WINDOW_SIZE`.
pub const IDX_SESSION_STATE_REMOTE_WINDOW_SIZE: usize = 5;
/// `IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE`.
pub const IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE: usize = 6;
/// `IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE`.
pub const IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE: usize = 7;
/// `IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE`.
pub const IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE: usize = 8;

// `Http2StreamStateIndex`, as positions in `streamState`.
/// `IDX_STREAM_STATE`.
pub const IDX_STREAM_STATE: usize = 0;
/// `IDX_STREAM_STATE_WEIGHT`.
pub const IDX_STREAM_STATE_WEIGHT: usize = 1;
/// `IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT`.
pub const IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT: usize = 2;
/// `IDX_STREAM_STATE_LOCAL_CLOSE`.
pub const IDX_STREAM_STATE_LOCAL_CLOSE: usize = 3;
/// `IDX_STREAM_STATE_REMOTE_CLOSE`.
pub const IDX_STREAM_STATE_REMOTE_CLOSE: usize = 4;
/// `IDX_STREAM_STATE_LOCAL_WINDOW_SIZE`.
pub const IDX_STREAM_STATE_LOCAL_WINDOW_SIZE: usize = 5;

/// The six buffers, created once per process.
pub struct Http2State {
    /// `sessionState`.
    pub session_state: AliasedUint8Array,
    /// `streamState`.
    pub stream_state: AliasedUint8Array,
    /// `settingsBuffer`.
    pub settings_buffer: AliasedUint8Array,
    /// `optionsBuffer`.
    pub options_buffer: AliasedUint8Array,
    /// `streamStats`.
    pub stream_stats: AliasedUint8Array,
    /// `sessionStats`.
    pub session_stats: AliasedUint8Array,
}

thread_local! {
    /// The process's buffers, created on first install.
    ///
    /// The registry caches the installed namespace object, so `install` runs
    /// once and every later `internalBinding('http2')` returns the same object
    /// holding these same arrays — which is what `lib/internal/http2/util.js`
    /// relies on when it destructures `settingsBuffer` at module scope and writes
    /// to it later.
    static STATE: RefCell<Option<Http2State>> = const { RefCell::new(None) };
}

impl Http2State {
    /// Allocates the six buffers.
    fn new(scope: &mut v8::PinScope<'_, '_>) -> Result<Self, String> {
        Ok(Self {
            session_state: AliasedUint8Array::new(scope, SESSION_STATE_COUNT, Element::Double)?,
            stream_state: AliasedUint8Array::new(scope, STREAM_STATE_COUNT, Element::Double)?,
            settings_buffer: AliasedUint8Array::new(scope, SETTINGS_BUFFER_LENGTH, Element::Word)?,
            options_buffer: AliasedUint8Array::new(scope, OPTIONS_BUFFER_LENGTH, Element::Word)?,
            stream_stats: AliasedUint8Array::new(scope, STREAM_STATS_COUNT, Element::Double)?,
            session_stats: AliasedUint8Array::new(scope, SESSION_STATS_COUNT, Element::Double)?,
        })
    }

    /// Creates the buffers if they do not exist yet.
    ///
    /// Separate from [`with`](Self::with) rather than folded into it because the
    /// two need different borrows: creating needs `&mut PinScope`, using needs
    /// only `&Self`. A combined `with(scope, |state| ...)` forced every closure
    /// that also touched the scope to borrow it twice, which the compiler rejects
    /// and which would be unsound to work around.
    pub fn ensure(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
        STATE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(Self::new(scope)?);
            }
            Ok(())
        })
    }

    /// Runs `body` on the buffers, which must have been created by
    /// [`ensure`](Self::ensure).
    ///
    /// The borrow is scoped to this call so a binding function that re-enters
    /// from a callback cannot find it held.
    pub fn with<R>(body: impl FnOnce(&Self) -> R) -> Result<R, String> {
        STATE.with(|slot| {
            let slot = slot.borrow();
            let state = slot
                .as_ref()
                .ok_or("the http2 state was used before it was created")?;
            Ok(body(state))
        })
    }

    /// Reads the `optionsBuffer` flag bitset.
    pub fn option_flags(&self) -> u32 {
        self.options_buffer.get(options::FLAGS).unwrap_or(0)
    }

    /// Reads one `optionsBuffer` value.
    pub fn option(&self, index: usize) -> u32 {
        self.options_buffer.get(index).unwrap_or(0)
    }

    /// Reads one `settingsBuffer` value.
    pub fn setting(&self, index: usize) -> u32 {
        self.settings_buffer.get(index).unwrap_or(0)
    }

    /// Writes one `settingsBuffer` value.
    pub fn set_setting(&self, index: usize, value: u32) {
        self.settings_buffer.set(index, value);
    }

    /// Writes one `sessionState` value.
    pub fn set_session_state(&self, index: usize, value: f64) {
        self.session_state.set_float(index, value);
    }

    /// Writes one `streamState` value.
    pub fn set_stream_state(&self, index: usize, value: f64) {
        self.stream_state.set_float(index, value);
    }

    /// The five buffers as JavaScript values, in `Initialize`'s order.
    pub fn arrays<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
    ) -> [(&'static str, v8::Local<'s, v8::Value>); 6] {
        [
            ("sessionState", self.session_state.array(scope)),
            ("streamState", self.stream_state.array(scope)),
            ("settingsBuffer", self.settings_buffer.array(scope)),
            ("optionsBuffer", self.options_buffer.array(scope)),
            ("streamStats", self.stream_stats.array(scope)),
            ("sessionStats", self.session_stats.array(scope)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::NUMBERS;

    fn published(name: &str) -> usize {
        NUMBERS
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| *value as usize)
            .expect("the constant is published")
    }

    #[test]
    fn the_buffer_lengths_are_the_ones_node_exposes() {
        // These lengths are what `internalBinding('http2').settingsBuffer.length`
        // reports in a real Node, and `lib/internal/http2/util.js` indexes up to
        // `IDX_SETTINGS_FLAGS + 1 + 2 * MAX_ADDITIONAL_SETTINGS` inside them. A
        // short buffer would silently drop writes to a custom setting.
        assert_eq!(SESSION_STATE_COUNT, 9);
        assert_eq!(STREAM_STATE_COUNT, 6);
        assert_eq!(
            SETTINGS_BUFFER_LENGTH,
            7 + 1 + 1 + 2 * MAX_ADDITIONAL_SETTINGS
        );
        assert_eq!(OPTIONS_BUFFER_LENGTH, options::FLAGS + 1);
        assert_eq!(STREAM_STATS_COUNT, 6);
        assert_eq!(SESSION_STATS_COUNT, 9);
    }

    #[test]
    fn the_option_indices_match_the_published_setting_ids() {
        // `updateOptionsBuffer` writes these positions and
        // `Http2Options` reads them back, so a shifted index would apply one
        // option's value to another option. The two that are published
        // constants are pinned against the table above; the rest are pinned by
        // the ordering test below.
        assert_eq!(options::FLAGS, 14);
        assert_eq!(options::CONNECTION_WINDOW_SIZE, 13);
    }

    #[test]
    fn the_settings_ids_are_nghttp2s_own_numbers() {
        // `Http2Settings::Init` builds `nghttp2_settings_entry` values from these
        // and `GRABSETTING` indexes the buffer with the *index*, so a transposed
        // pair would send one setting's id with another's value.
        //
        // The two orders differ, which is the trap. `Http2SettingsIndex` lists
        // INITIAL_WINDOW_SIZE before MAX_CONCURRENT_STREAMS; nghttp2 numbers them
        // the other way round (3 and 4). So the mapping is explicitly *not*
        // `index + 1`, and this table is the only place that says so.
        let expected = [
            (IDX_SETTINGS_HEADER_TABLE_SIZE, 0x01),
            (IDX_SETTINGS_ENABLE_PUSH, 0x02),
            (IDX_SETTINGS_INITIAL_WINDOW_SIZE, 0x04),
            (IDX_SETTINGS_MAX_FRAME_SIZE, 0x05),
            (IDX_SETTINGS_MAX_CONCURRENT_STREAMS, 0x03),
            (IDX_SETTINGS_MAX_HEADER_LIST_SIZE, 0x06),
            (IDX_SETTINGS_ENABLE_CONNECT_PROTOCOL, 0x08),
        ];
        let names = [
            "NGHTTP2_SETTINGS_HEADER_TABLE_SIZE",
            "NGHTTP2_SETTINGS_ENABLE_PUSH",
            "NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE",
            "NGHTTP2_SETTINGS_MAX_FRAME_SIZE",
            "NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS",
            "NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE",
            "NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL",
        ];
        // `expected` is in `Http2SettingsIndex` order, `names` in the same order,
        // so a reordering of either is a failure rather than a coincidence.
        for ((index, id), name) in expected.into_iter().zip(names) {
            assert_eq!(published(name), id, "{name} is {id:#04x} at index {index}");
        }
        // Every index appears exactly once, which is what makes the buffer layout
        // unambiguous.
        let mut indices: Vec<usize> = expected.iter().map(|(index, _)| *index).collect();
        indices.sort_unstable();
        assert_eq!(indices, (0..IDX_SETTINGS_COUNT).collect::<Vec<_>>());
    }
}

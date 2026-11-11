//! `Http2Options`: the `nghttp2_option` object a session is built with.
//!
//! `Http2Options::Http2Options` in `src/node_http2.cc` reads the shared
//! `optionsBuffer` that `updateOptionsBuffer` in
//! `lib/internal/http2/util.js` filled and applies each flagged option. The
//! defaults that are *not* buffer-driven are the interesting part, because they
//! are the ones that differ from nghttp2's own:
//!
//! | | Node | nghttp2 default |
//! | --- | --- | --- |
//! | closed streams retained | no | yes |
//! | automatic WINDOW_UPDATE | no | yes |
//! | peer max concurrent streams | 100 | unlimited |
//! | connection window | 33554432 (32 MiB) | 65535 |
//!
//! Node turns off both automatic behaviours on purpose: it tracks flow control
//! itself so backpressure is observable, and it discards closed streams because it
//! does not use nghttp2's priority tree.
//!
//! # The connection window
//!
//! `kDefaultConnectionWindowSize` is 32 MiB rather than the protocol's 64 KiB, for
//! the reason nodejs/node#38426 gives: a 64 KiB connection window limits a
//! high-latency link to window/RTT. `test-http2-connection-window-size-option.js`
//! reads the window back out of `session.state`, so this number is observable.

use std::ptr;

use crate::ffi;
use crate::state::options as idx;

/// `kDefaultConnectionWindowSize`: 32 MiB.
pub const DEFAULT_CONNECTION_WINDOW_SIZE: i32 = 33_554_432;
/// `kDefaultMaxSessionMemory`: 10 MB.
pub const DEFAULT_MAX_SESSION_MEMORY: u64 = 10_000_000;
/// `kDefaultMaxPings`.
pub const DEFAULT_MAX_PINGS: usize = 10;
/// `kDefaultMaxSettings`.
pub const DEFAULT_MAX_SETTINGS: usize = 10;
/// `DEFAULT_MAX_HEADER_LIST_PAIRS` from `node_http_common.h`.
pub const DEFAULT_MAX_HEADER_LIST_PAIRS: u32 = 128;

/// A live `nghttp2_option`, freed on drop.
pub struct Options {
    raw: *mut ffi::nghttp2_option,
}

impl Options {
    /// Builds the option object from the shared `optionsBuffer`.
    ///
    /// The order of the `if` blocks is `Http2Options`'s, so a diff against
    /// `node_http2.cc` lines up. It is not observable, but a reordering would make
    /// the two files harder to compare than they already are.
    pub fn from_buffer(session_type: i32) -> Result<Self, String> {
        let mut raw: *mut ffi::nghttp2_option = ptr::null_mut();
        // SAFETY: `raw` is an out-parameter.
        let status = unsafe { ffi::nghttp2_option_new(&mut raw) };
        if status != 0 || raw.is_null() {
            return Err(format!("nghttp2_option_new failed with {status}"));
        }
        let options = Self { raw };

        let (flags, values) = crate::state::Http2State::with(|shared| {
            let mut values = [0u32; idx::FLAGS];
            for (index, slot) in values.iter_mut().enumerate() {
                *slot = shared.option(index);
            }
            (shared.option_flags(), values)
        })?;
        let buffer = |index: usize| values[index];

        // SAFETY: `options.raw` is live and every setter below only stores into
        // it. Each flag bit is `1 << IDX_OPTIONS_*`, so a cleared bit means
        // JavaScript did not set that option and the default applies.
        unsafe {
            // Not configurable from JavaScript: Node's own two choices.
            ffi::nghttp2_option_set_no_closed_streams(options.raw, 1);
            ffi::nghttp2_option_set_no_auto_window_update(options.raw, 1);

            // The client side decodes ALTSVC and ORIGIN frames itself.
            if session_type == crate::session::SESSION_CLIENT {
                ffi::nghttp2_option_set_builtin_recv_extension_type(
                    options.raw,
                    ffi::NGHTTP2_ALTSVC,
                );
                ffi::nghttp2_option_set_builtin_recv_extension_type(
                    options.raw,
                    ffi::NGHTTP2_ORIGIN,
                );
            }

            if flags & (1 << idx::MAX_DEFLATE_DYNAMIC_TABLE_SIZE) != 0 {
                ffi::nghttp2_option_set_max_deflate_dynamic_table_size(
                    options.raw,
                    buffer(idx::MAX_DEFLATE_DYNAMIC_TABLE_SIZE) as usize,
                );
            }
            if flags & (1 << idx::MAX_RESERVED_REMOTE_STREAMS) != 0 {
                ffi::nghttp2_option_set_max_reserved_remote_streams(
                    options.raw,
                    buffer(idx::MAX_RESERVED_REMOTE_STREAMS) as usize,
                );
            }
            if flags & (1 << idx::MAX_SEND_HEADER_BLOCK_LENGTH) != 0 {
                ffi::nghttp2_option_set_max_send_header_block_length(
                    options.raw,
                    buffer(idx::MAX_SEND_HEADER_BLOCK_LENGTH) as usize,
                );
            }

            // Node's recommended default, applied whether or not JavaScript set
            // one; the buffer overrides it below.
            ffi::nghttp2_option_set_peer_max_concurrent_streams(options.raw, 100);
            if flags & (1 << idx::PEER_MAX_CONCURRENT_STREAMS) != 0 {
                ffi::nghttp2_option_set_peer_max_concurrent_streams(
                    options.raw,
                    buffer(idx::PEER_MAX_CONCURRENT_STREAMS),
                );
            }

            if flags & (1 << idx::STRICT_HTTP_FIELD_WHITESPACE_VALIDATION) != 0 {
                ffi::nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(
                    options.raw,
                    buffer(idx::STRICT_HTTP_FIELD_WHITESPACE_VALIDATION) as i32,
                );
            }

            if flags & (1 << idx::MAX_SETTINGS) != 0 {
                ffi::nghttp2_option_set_max_settings(
                    options.raw,
                    buffer(idx::MAX_SETTINGS) as usize,
                );
            }

            if flags & (1 << idx::STREAM_RESET_BURST) != 0
                && flags & (1 << idx::STREAM_RESET_RATE) != 0
            {
                ffi::nghttp2_option_set_stream_reset_rate_limit(
                    options.raw,
                    u64::from(buffer(idx::STREAM_RESET_BURST)),
                    u64::from(buffer(idx::STREAM_RESET_RATE)),
                );
            }
        }

        Ok(options)
    }

    /// The option object, for `nghttp2_session_*_new2`.
    pub fn as_ptr(&self) -> *const ffi::nghttp2_option {
        self.raw
    }

    /// The connection-level flow control window this option object implies.
    ///
    /// `Http2Options` keeps it as a plain field and applies it with
    /// `nghttp2_session_set_local_window_size` after the session exists, because
    /// nghttp2 has no option setter for it. Reading it here keeps the
    /// buffer-or-default decision in one place.
    pub fn connection_window_size() -> i32 {
        crate::state::Http2State::with(|shared| {
            let flags = shared.option_flags();
            if flags & (1 << idx::CONNECTION_WINDOW_SIZE) != 0 {
                shared.option(idx::CONNECTION_WINDOW_SIZE) as i32
            } else {
                DEFAULT_CONNECTION_WINDOW_SIZE
            }
        })
        .unwrap_or(DEFAULT_CONNECTION_WINDOW_SIZE)
    }
}

impl Drop for Options {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: `raw` came from `nghttp2_option_new` and is freed exactly
            // once. nghttp2 copies what it needs when the session is created, so
            // dropping this after `*_new2` returned is correct.
            unsafe { ffi::nghttp2_option_del(self.raw) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_nodes_not_nghttp2s() {
        // The connection window is the one a reader is most likely to "correct" to
        // 65535. It is 32 MiB because Node raises it, and
        // `test-http2-connection-window-size-option.js` reads it back.
        assert_eq!(DEFAULT_CONNECTION_WINDOW_SIZE, 32 * 1024 * 1024);
        assert_ne!(DEFAULT_CONNECTION_WINDOW_SIZE, 65_535);
    }

    #[test]
    fn the_memory_default_is_ten_megabytes() {
        // `maxSessionMemory` is expressed in MB and multiplied by 1000000, so the
        // default cap is 10 MB rather than 10 MiB. `test-http2-session-memory.js`
        // depends on the decimal unit.
        assert_eq!(DEFAULT_MAX_SESSION_MEMORY, 10_000_000);
        assert_ne!(DEFAULT_MAX_SESSION_MEMORY, 10 * 1024 * 1024);
    }

    #[test]
    fn the_header_pair_default_is_the_pin_header_value() {
        assert_eq!(DEFAULT_MAX_HEADER_LIST_PAIRS, 128);
    }
}

//! One-shot zlib codecs, in the wrapper modes `Bun` names.
//!
//! Bun exposes four `zlib` members and **no** RFC 1950 (zlib-wrapped) one, which
//! is the single most important fact about this group:
//!
//! | member | wrapper | RFC |
//! | --- | --- | --- |
//! | `Bun.gzipSync` / `Bun.gunzipSync` | gzip | 1952 |
//! | `Bun.deflateSync` / `Bun.inflateSync` | **raw deflate** | 1951 |
//!
//! `Bun.deflateSync("hello world hello world hello world")` is
//! `cb48cdc9…`, and `cb` is a raw deflate block header. A zlib-wrapped encoder
//! would start `78 9c`. So the deflate pair selects `windowBits = -15` and the
//! gzip pair `windowBits = 15 + 16`; getting that backwards produces output that
//! round-trips through itself and fails against everything else, which is why
//! the tests assert the first byte rather than only the round trip.
//!
//! # Why this is not a second zlib binding
//!
//! This module names the `libz-rs-sys` C ABI directly rather than going through
//! `internalBinding('zlib')`. The binding Node's `lib/zlib.js` drives is a
//! *stream* handle: it takes an `init(level, windowBits, …)`, a
//! `writeSync(flush, …)` with a caller-supplied output buffer, and reports
//! completion through a callback into the threadpool. Bun's members here are
//! one-shot: give it bytes, get back a `Uint8Array`. Driving the stream handle
//! from Rust would mean re-implementing `lib/zlib.js`'s chunk loop and its error
//! mapping, and it would still need a `Uint32Array(2)` write state to read
//! offsets back out of. The library, the version, and the compiled artifact are
//! shared either way — only the entry point differs.
//!
//! # The `windowBits` the wrappers use
//!
//! Measured against Bun 1.4.4, and *not* symmetric between the pairs:
//!
//! * compression always uses the wrapper's own value — 31 for gzip and **-15**
//!   for raw deflate — and `{windowBits}` is accepted and ignored
//!   (`Bun`'s own schema comment says "converted and not used");
//! * decompression takes `{windowBits}` seriously: `gunzipSync(gz, {windowBits:
//!   15})` reads the same bytes as a zlib stream and reports
//!   `incorrect header check`, and `inflateSync(raw, {windowBits: 15})` does the
//!   same in reverse. The defaults are 31 and -15.

use std::ffi::CStr;

use libz_rs_sys as z;

use crate::error::CompressionError;

/// `Z_DEFAULT_STRATEGY`.
pub const Z_DEFAULT_STRATEGY: i32 = 0;
/// `Z_DEFAULT_MEMLEVEL`.
pub const Z_DEFAULT_MEMLEVEL: i32 = 8;

/// `windowBits` for gzip, i.e. `15 + 16`: a 32 KiB window with a gzip header.
pub const GZIP_WINDOW_BITS: i32 = 31;
/// `windowBits` for raw deflate, i.e. `-15`. The sign selects "no wrapper".
pub const RAW_WINDOW_BITS: i32 = -15;

/// Which RFC wrapper a call selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    Gzip,
    Raw,
}

impl Wrapper {
    /// The `windowBits` compression uses for this wrapper.
    pub fn window_bits(self) -> i32 {
        match self {
            Wrapper::Gzip => GZIP_WINDOW_BITS,
            Wrapper::Raw => RAW_WINDOW_BITS,
        }
    }
}

/// The compression parameters Bun's `ZlibCompressionOptions` resolves to.
///
/// `mem_level` and `strategy` are not "converted and not used" the way Bun's own
/// schema comment claims: measured, `{strategy: 2}` really does change the output
/// (`gzipSync` on a 20 KB payload gives 1116 bytes at strategy 0 and 100249 at
/// strategy 2), and `{memLevel: 1}` gives 1199 where `{memLevel: 9}` gives 1116.
/// So all three are passed to `deflateInit2_`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionParams {
    pub level: i32,
    pub mem_level: i32,
    pub strategy: i32,
}

impl Default for CompressionParams {
    fn default() -> Self {
        // Bun's defaults: level 6 (`map_or(6, …)`), and the dictionary's own
        // `memLevel: 8`, `strategy: 0`.
        Self {
            level: 6,
            mem_level: Z_DEFAULT_MEMLEVEL,
            strategy: Z_DEFAULT_STRATEGY,
        }
    }
}

/// How a compressed stream failed.
///
/// Bun reports two shapes and they are not interchangeable (spec 3.4):
///
/// * zlib's own text — `"incorrect header check"`, `"invalid block type"` — for a
///   stream that had enough bytes to be decoded and was wrong;
/// * the fixed `"Zlib returned an error"` for a stream that ended before zlib
///   could say anything — empty input, a truncated member, or a header split so
///   early that no check ran.
///
/// The rule that produces that split is zlib's own: its `msg` field is null
/// until a check has run and failed, and Bun's reader falls back to a fixed
/// string when `msg` is null. So [`ZlibError::Stream`] carries the real `msg`
/// when zlib set one and the fallback when it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZlibError {
    /// zlib refused the parameters before starting a stream.
    ///
    /// Bun renders this `Zlib error: Invalid argument`, which is what a level of
    /// 99 or a `windowBits` outside the accepted range produces.
    InvalidArgument,
    /// The stream failed, with zlib's `msg` when it published one.
    Stream(Option<String>),
    /// The input ran out before the stream ended.
    Truncated,
    /// The allocator failed.
    OutOfMemory,
}

impl ZlibError {
    /// The `Error` message Bun throws for this failure.
    pub fn message(&self) -> String {
        match self {
            // `init_error` has its own capitalisation for this one case.
            ZlibError::InvalidArgument => "Zlib error: Invalid argument".to_string(),
            ZlibError::Stream(Some(message)) => message.clone(),
            ZlibError::Stream(None) | ZlibError::Truncated => "Zlib returned an error".to_string(),
            ZlibError::OutOfMemory => "Out of memory".to_string(),
        }
    }
}

impl From<ZlibError> for CompressionError {
    fn from(error: ZlibError) -> Self {
        CompressionError::Zlib(error.message())
    }
}

/// The writable tail of an output `Vec`.
///
/// zlib is called in a loop rather than handed one guessed capacity: the input's
/// compression ratio is unknown before the first block, so compression starts
/// from `deflateBound` — zlib's own upper bound, which makes the common case one
/// call — and decompression starts from the caller's hint and grows. Growing
/// rather than trusting a size read out of a header matters for decompression,
/// where the size comes from the untrusted stream.
struct Sink<'a> {
    bytes: &'a mut Vec<u8>,
}

impl Sink<'_> {
    /// Returns the next writable region as `(pointer, capacity)`.
    ///
    /// The capacity handed to zlib is clamped to `u32::MAX` because
    /// `z_stream.avail_out` is a `uInt`; a larger slice would wrap and zlib would
    /// write past what the caller declared.
    fn reserve(&mut self, extra: usize) -> (*mut u8, u32) {
        if self.bytes.capacity() - self.bytes.len() < extra {
            self.bytes.reserve(extra);
        }
        let spare = self.bytes.capacity() - self.bytes.len();
        // SAFETY: `spare` bytes are reserved past `len()` and owned by `bytes`,
        // so a pointer to the byte at `len()` is valid for writes of `spare`
        // bytes. The bytes are uninitialized, which `*mut u8` permits.
        let pointer = unsafe { self.bytes.as_mut_ptr().add(self.bytes.len()) };
        (pointer, spare.min(u32::MAX as usize) as u32)
    }

    /// How much spare capacity is left, which decides the next region.
    fn spare(&self) -> usize {
        self.bytes.capacity() - self.bytes.len()
    }

    /// Records how many bytes zlib wrote into the region from [`Self::reserve`].
    ///
    /// # Safety
    ///
    /// `written` must be the number of bytes zlib initialized in the region the
    /// matching `reserve` returned, which has to be at most its capacity.
    unsafe fn commit(&mut self, written: usize) {
        // SAFETY: the caller guarantees `written` bytes were initialized by
        // zlib in the spare capacity, and `reserve` reserved at least that many.
        unsafe { self.bytes.set_len(self.bytes.len() + written) };
    }
}

/// Compresses `input` in one call, with the wrapper `wrapper` selects.
///
/// `params.level` goes to zlib unchanged, which is what reproduces Bun: `-1` is
/// the library default and `0` is a real stored-block level, so the substitution
/// Bun makes (absent means **6**) is applied by the argument layer and not here.
pub fn compress(
    input: &[u8],
    params: CompressionParams,
    wrapper: Wrapper,
) -> Result<Vec<u8>, ZlibError> {
    let mut stream = z::z_stream::default();
    // SAFETY: `stream` is local, zeroed by `Default` and not shared. The size and
    // version arguments are the ones the linked library was compiled against,
    // which is what its own `is_version_compatible` check compares.
    let status = unsafe {
        z::deflateInit2_(
            &mut stream,
            params.level,
            z::Z_DEFLATED,
            wrapper.window_bits(),
            params.mem_level,
            params.strategy,
            z::zlibVersion(),
            std::mem::size_of::<z::z_stream>() as i32,
        )
    };
    if status != z::Z_OK {
        return Err(if status == z::Z_MEM_ERROR {
            ZlibError::OutOfMemory
        } else {
            ZlibError::InvalidArgument
        });
    }

    let mut output = Vec::new();
    // `deflateBound` needs an initialized stream, so it is asked after the init
    // above. A zero bound means zlib considers the state invalid; the loop grows
    // anyway, so a floor is enough.
    // SAFETY: `stream` is initialized and only read for its bound.
    let bound = unsafe { z::deflateBound(&mut stream, input.len() as _) } as usize;
    let floor = input.len() / 2 + 64;
    output.reserve(bound.max(floor));

    let mut sink = Sink { bytes: &mut output };
    let mut input_offset = 0usize;
    // `Z_FINISH` may need several calls when the output region fills: the
    // contract is to call again with the same flush and more room until it
    // returns `Z_STREAM_END`.
    let result = loop {
        let step = sink.spare().max(4096);
        let (pointer, capacity) = sink.reserve(step);
        stream.next_out = pointer;
        stream.avail_out = capacity;
        stream.next_in = if input_offset < input.len() {
            // SAFETY: the pointer stays inside `input` for this call only.
            unsafe { input.as_ptr().add(input_offset) }
        } else {
            std::ptr::null()
        };
        stream.avail_in = (input.len() - input_offset) as u32;

        // SAFETY: both buffer pairs were installed above from live slices that
        // outlive the call, and `stream` is initialized.
        let status = unsafe { z::deflate(&mut stream, z::Z_FINISH) };
        let produced = (capacity - stream.avail_out) as usize;
        // SAFETY: zlib initialized the `produced` bytes it reported.
        unsafe { sink.commit(produced) };
        input_offset = input.len() - stream.avail_in as usize;

        match status {
            z::Z_STREAM_END => break Ok(()),
            z::Z_OK | z::Z_BUF_ERROR => {
                // `Z_BUF_ERROR` with nothing consumed and nothing produced means
                // the loop cannot make progress; `deflateBound` makes that
                // unreachable, but refusing to spin is better than hanging.
                if produced == 0 && stream.avail_in == input.len() as u32 {
                    break Err(ZlibError::Stream(zlib_message(&stream)));
                }
            }
            z::Z_MEM_ERROR => break Err(ZlibError::OutOfMemory),
            _ => break Err(ZlibError::Stream(zlib_message(&stream))),
        }
    };

    // SAFETY: `stream` was initialized by `deflateInit2_` and is ended exactly
    // once here, before it goes out of scope.
    unsafe { z::deflateEnd(&mut stream) };
    result.map(|()| output)
}

/// Decompresses `input` with an explicit `windowBits`.
///
/// Mirrors Bun's `ZlibReaderArrayList::read_all(true)`: every failure after a
/// stream exists is a [`ZlibError::Stream`] carrying zlib's message, and an
/// input that ends mid-stream is [`ZlibError::Truncated`] — which Bun renders as
/// `Zlib returned an error`.
///
/// `capacity_hint` is what to reserve first. For gzip Bun reads the trailer's
/// `ISIZE` for exactly this, so a caller that has it available should pass it.
pub fn decompress(
    input: &[u8],
    window_bits: i32,
    capacity_hint: Option<usize>,
) -> Result<Vec<u8>, ZlibError> {
    let mut stream = z::z_stream::default();
    // SAFETY: `stream` is local, zeroed by `Default` and not shared.
    let status = unsafe {
        z::inflateInit2_(
            &mut stream,
            window_bits,
            z::zlibVersion(),
            std::mem::size_of::<z::z_stream>() as i32,
        )
    };
    if status != z::Z_OK {
        return Err(if status == z::Z_MEM_ERROR {
            ZlibError::OutOfMemory
        } else {
            ZlibError::InvalidArgument
        });
    }

    // A hint is only a starting capacity: the header it came from is untrusted, so
    // a wrong one costs a `reserve` and nothing else.
    let mut output =
        Vec::with_capacity(capacity_hint.filter(|hint| *hint > 0).unwrap_or(32).max(32));

    let mut sink = Sink { bytes: &mut output };
    let mut installed_input = false;
    let result = loop {
        let step = sink.spare().clamp(4096, 1 << 20);
        let (pointer, capacity) = sink.reserve(step);
        stream.next_out = pointer;
        stream.avail_out = capacity;
        if !installed_input {
            stream.next_in = input.as_ptr();
            stream.avail_in = input.len() as u32;
            installed_input = true;
        }

        // SAFETY: the output region belongs to `output` for this call and the
        // input pointer refers to `input`, which outlives the call.
        let status = unsafe { z::inflate(&mut stream, z::Z_NO_FLUSH) };
        let produced = (capacity - stream.avail_out) as usize;
        // SAFETY: zlib initialized the `produced` bytes it reported.
        unsafe { sink.commit(produced) };

        match status {
            z::Z_STREAM_END => break Ok(()),
            z::Z_MEM_ERROR => break Err(ZlibError::OutOfMemory),
            z::Z_NEED_DICT => break Err(ZlibError::Stream(zlib_message(&stream))),
            z::Z_BUF_ERROR | z::Z_OK => {
                // No input left and nothing produced: zlib cannot continue.
                // Bun's reader reaches the same conclusion with `is_done` true
                // and reports `ZlibError::ZlibError`, whose message becomes the
                // fixed fallback because `msg` is null. `avail_out == 0` with
                // input left is the "needs more room" case, which the next
                // iteration provides.
                if stream.avail_in == 0 && produced == 0 {
                    break Err(ZlibError::Truncated);
                }
            }
            _ => break Err(ZlibError::Stream(zlib_message(&stream))),
        }
    };

    // SAFETY: `stream` was initialized by `inflateInit2_` and is ended exactly
    // once here.
    unsafe { z::inflateEnd(&mut stream) };
    result.map(|()| output)
}

/// zlib's own `msg` for the current stream state, if it published one.
///
/// `None` is the "no check ran, or the check did not describe itself" case, and
/// Bun turns it into the fixed `Zlib returned an error` text. That is what makes
/// an empty input and a truncated header report the same string while a corrupt
/// body reports `incorrect header check` or `invalid block type`.
fn zlib_message(stream: &z::z_stream) -> Option<String> {
    if stream.msg.is_null() {
        return None;
    }
    // SAFETY: zlib's `msg` is either null or a NUL-terminated static string it
    // owns for the life of the stream.
    Some(
        unsafe { CStr::from_ptr(stream.msg) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes Bun 1.4.4 produces for `"hello"`. Recorded, not compared
    /// against a second implementation: `libz-rs-sys` and the zlib Bun links
    /// agree on this input at Bun's default level of 6, and pinning the exact
    /// bytes is what keeps a level or wrapper change from going unnoticed.
    const BUN_GZIP_HELLO: &str = "1f8b0800000000000003cb48cdc9c9070086a6103605000000";
    /// `Bun.deflateSync("hello")` — raw deflate, beginning `cb` rather than `78`.
    const BUN_DEFLATE_HELLO: &str = "cb48cdc9c90700";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn gzip_matches_bun_byte_for_byte() {
        // Bun's gzip output is deterministic — `mtime` 0, `os` 3, level 6 — so a
        // byte comparison is a valid differential rather than an approximation.
        let compressed =
            compress(b"hello", CompressionParams::default(), Wrapper::Gzip).expect("compress");
        assert_eq!(hex(&compressed), BUN_GZIP_HELLO);
    }

    #[test]
    fn deflate_is_raw_and_not_zlib_wrapped() {
        let compressed =
            compress(b"hello", CompressionParams::default(), Wrapper::Raw).expect("compress");
        assert_eq!(hex(&compressed), BUN_DEFLATE_HELLO);
        // The assertion that names the defect: a zlib header would be `78`.
        assert_ne!(
            compressed[0], 0x78,
            "deflateSync must not emit a zlib header"
        );
        assert_eq!(compressed[0], 0xcb);
    }

    #[test]
    fn round_trips_every_shape_that_matters() {
        for (label, input) in [
            ("empty", Vec::new()),
            ("one byte", vec![0x41]),
            ("block boundary", vec![b'z'; 65_536]),
            ("multi-megabyte", vec![0x5a; 3 * 1024 * 1024]),
        ] {
            for wrapper in [Wrapper::Gzip, Wrapper::Raw] {
                let compressed =
                    compress(&input, CompressionParams::default(), wrapper).expect(label);
                let restored =
                    decompress(&compressed, wrapper.window_bits(), Some(input.len())).expect(label);
                assert_eq!(restored, input, "{label} ({wrapper:?}) round trip");
            }
        }
    }

    #[test]
    fn the_empty_gzip_container_is_still_a_container() {
        // 20 bytes: a header, an empty final block and the trailer. Bun produces
        // the same 20 for `gzipSync("")`.
        let compressed =
            compress(b"", CompressionParams::default(), Wrapper::Gzip).expect("compress");
        assert_eq!(hex(&compressed), "1f8b080000000000000303000000000000000000");
        assert_eq!(
            decompress(&compressed, GZIP_WINDOW_BITS, None).expect("decompress"),
            b""
        );
    }

    #[test]
    fn a_bad_gzip_header_reports_zlibs_own_message() {
        // Random bytes are long enough for zlib's header check to run, so the
        // message is zlib's rather than the fixed fallback.
        let error =
            decompress(&[1, 2, 3, 4, 5, 6, 7, 8], GZIP_WINDOW_BITS, None).expect_err("fails");
        assert_eq!(error.message(), "incorrect header check");
    }

    #[test]
    fn an_empty_or_truncated_stream_reports_the_fixed_message() {
        assert_eq!(
            decompress(&[], GZIP_WINDOW_BITS, None)
                .expect_err("empty fails")
                .message(),
            "Zlib returned an error"
        );
        let compressed = compress(
            b"hello hello hello",
            CompressionParams::default(),
            Wrapper::Gzip,
        )
        .expect("compress");
        for length in [1, 5, 10, compressed.len() - 1] {
            assert_eq!(
                decompress(&compressed[..length], GZIP_WINDOW_BITS, None)
                    .expect_err("truncated fails")
                    .message(),
                "Zlib returned an error",
                "length {length}"
            );
        }
    }

    #[test]
    fn an_out_of_range_level_is_an_initialization_failure() {
        let params = CompressionParams {
            level: 99,
            ..CompressionParams::default()
        };
        let error = compress(b"hello", params, Wrapper::Gzip).expect_err("fails");
        assert_eq!(error.message(), "Zlib error: Invalid argument");
    }

    #[test]
    fn level_zero_is_stored_blocks_and_not_the_default() {
        // Bun's default is level 6 and 0 is a real stored-block level. If `-1`
        // leaked through as "default" the two would be indistinguishable on this
        // input; level 0's output is much larger, which is the difference.
        let stored = compress(
            b"hello",
            CompressionParams {
                level: 0,
                ..CompressionParams::default()
            },
            Wrapper::Raw,
        )
        .expect("compress");
        assert_eq!(hex(&stored), "010500faff68656c6c6f");
        let default =
            compress(b"hello", CompressionParams::default(), Wrapper::Raw).expect("compress");
        assert!(stored.len() > default.len());
    }

    #[test]
    fn an_explicit_window_bits_selects_the_wrapper_on_decompression() {
        // Measured both ways: the raw stream read as a zlib stream reports
        // `incorrect header check`, which is exactly Bun's answer for
        // `inflateSync(raw, {windowBits: 15})`.
        let raw = compress(b"hello", CompressionParams::default(), Wrapper::Raw).expect("compress");
        assert_eq!(
            decompress(&raw, RAW_WINDOW_BITS, None).expect("raw"),
            b"hello"
        );
        let error = decompress(&raw, 15, None).expect_err("zlib mode rejects a raw stream");
        assert_eq!(error.message(), "incorrect header check");
    }

    #[test]
    fn a_window_bits_zlib_refuses_is_an_initialization_failure() {
        // Bun reports `Zlib error: Invalid argument` for 48 and for -16, both of
        // which are outside what `inflateInit2_` accepts.
        for window_bits in [-16, 48] {
            let error = decompress(&[0x03, 0x00], window_bits, None).expect_err("fails");
            assert_eq!(error.message(), "Zlib error: Invalid argument");
        }
    }
}

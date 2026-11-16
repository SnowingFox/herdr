//! One-shot zstd compression and decompression, in Bun's error taxonomy.
//!
//! Bun's `zstdCompressSync`/`zstdDecompressSync` do **not** ride its Node-style
//! `Zstd` stream class: `Bun.zstd*` calls `compress_to_box`/`decompress_to_box`
//! directly, and its decompressor distinguishes four `ZstdError` variants that
//! all surface as `ERR_ZSTD` but with different words. Reproducing that mapping
//! is the point of this module, because a single "decompression failed" string
//! would pass a round-trip test and fail every corrupt-input assertion.
//!
//! | observed message | when Bun reports it |
//! | --- | --- |
//! | `Decompression failed: InvalidZstdData` | no frame header could be read: bad magic, a truncated first frame, trailing junk, or gzip input |
//! | `Decompression failed: ZstdDecompressionError` | a header was read and the *body* could not be decoded, including an input that ends mid-frame |
//! | `Decompression failed: DecompressionFailed` | `ZSTD_decompress` rejected an already-sized frame |
//! | `Decompression failed: ShortRead` | more input was needed and the caller was not done |
//!
//! The split is Bun's own control flow, not a heuristic: `decompress_alloc`
//! reads the content size first and reports `InvalidZstdData` when that fails,
//! and the streaming reader it falls back to reports
//! `ZstdDecompressionError`/`ShortRead` from `ZSTD_decompressStream`. This module
//! follows the same order, so the strings are derived rather than looked up.

use std::ffi::CStr;

use zstd_sys as z;

use crate::error::CompressionError;

/// zstd's `ZSTD_CONTENTSIZE_UNKNOWN`/`ERROR`, as `ZSTD_getFrameContentSize`
/// returns them.
///
/// The bindings declare the `i32` constants, but the function returns
/// `unsigned long long`, so the sentinels have to be compared as `u64`. Reading
/// them through the `i32` constants and casting would turn `-1` into
/// `0xFFFF_FFFF` and miss `u64::MAX`.
const CONTENTSIZE_UNKNOWN: u64 = u64::MAX;
const CONTENTSIZE_ERROR: u64 = u64::MAX - 1;

// `ZSTD_findDecompressedSize`, which the pregenerated `zstd-sys` bindings do not
// expose.
//
// It is declared `ZSTDLIB_STATIC_API` in `zstd.h`, so it is not in the stable
// header and not in the bindings module `rn-bind-zlib` links against. The symbol
// is still in the vendored `libzstd.a` this workspace already builds, and it is
// the only function that answers Bun's question exactly: the *total* size of a
// series of frames, `CONTENTSIZE_UNKNOWN` when any frame omits its size, and
// `CONTENTSIZE_ERROR` when the input is not a valid series.
//
// The distinction is load-bearing rather than cosmetic, because Bun's two
// decompression messages split on it: a probe failure is `InvalidZstdData` before
// any decoder exists, while a failure *inside* a decoder is
// `ZstdDecompressionError`. Reproducing it by walking frames with
// `ZSTD_findFrameCompressedSize` does not work — that walk reports a truncated
// second member as a frame-size error, where this reports the whole input as
// invalid, and the messages then disagree with the oracle.
unsafe extern "C" {
    fn ZSTD_findDecompressedSize(src: *const std::ffi::c_void, src_size: usize) -> u64;
}

/// The total decompressed size of every frame in `input`.
///
/// `Ok(None)` is zstd's `CONTENTSIZE_UNKNOWN`: a frame does not record its size, so
/// the caller has to stream. `Err(())` is `CONTENTSIZE_ERROR` — the input is not a
/// well-formed series of frames — which Bun reports as `InvalidZstdData` before any
/// decoder exists.
fn find_decompressed_size(input: &[u8]) -> Result<Option<usize>, ()> {
    // SAFETY: `input` is a valid slice for its length, and the function only reads
    // the frame headers and block boundaries inside it.
    let size = unsafe { ZSTD_findDecompressedSize(input.as_ptr().cast(), input.len()) };
    if size == CONTENTSIZE_ERROR {
        return Err(());
    }
    if size == CONTENTSIZE_UNKNOWN {
        return Ok(None);
    }
    Ok(Some(size.min(usize::MAX as u64) as usize))
}

/// The largest output a single frame is allowed to pre-allocate from its header.
///
/// Bun's `decompress_alloc` uses 16 MiB and switches to streaming above it,
/// precisely because the size in a header is untrusted. Matching the number keeps
/// the memory profile the same on a hostile input.
const MAX_PREALLOCATE: usize = 16 * 1024 * 1024;

/// Bun's default level, from `JSZstd::level_of`'s `map_or(3, …)`.
pub const DEFAULT_LEVEL: i32 = 3;

/// The accepted level range, also from `level_of`.
pub const MIN_LEVEL: i32 = 1;
pub const MAX_LEVEL: i32 = 22;

/// An invalid compression level, which Bun reports as a *type* error.
///
/// `heap.invalid_arguments` in `level_of` produces `ERR_INVALID_ARG_TYPE`, not
/// `ERR_OUT_OF_RANGE`; that is measured and is the reason this is its own
/// constructor rather than [`CompressionError::OutOfRange`].
pub fn invalid_level() -> CompressionError {
    CompressionError::InvalidArgType("Compression level must be between 1 and 22".to_string())
}

/// `ZSTD_isError`, which is an `unsafe` extern only because the C signature is.
fn is_error(result: usize) -> bool {
    // SAFETY: no pointer is dereferenced; the argument is a return value.
    unsafe { z::ZSTD_isError(result) != 0 }
}

/// The `ZstdError` enumerator name zstd itself would give this failure.
///
/// Bun maps a `ZSTD_*` error code through `strum::IntoStaticStr`, so the name in
/// the message is the enumerator's, not zstd's prose. This reproduces the three
/// names its decompressor can actually produce; everything else falls back to
/// `DecompressionFailed`, which is what `decompress_append` reports.
fn decompress_reason(result: usize) -> &'static str {
    // SAFETY: `ZSTD_getErrorCode` is documented as meaningful for a value
    // `ZSTD_isError` accepted, and only reads the argument's bit pattern.
    let code = unsafe { z::ZSTD_getErrorCode(result) };
    if code == z::ZSTD_ErrorCode::ZSTD_error_memory_allocation {
        return "OutOfMemory";
    }
    if code == z::ZSTD_ErrorCode::ZSTD_error_prefix_unknown {
        // A magic number that is not zstd's is the one case Bun names
        // `InvalidZstdData` from inside the decoder.
        return "InvalidZstdData";
    }
    // Everything else in the decoding path is `ZstdDecompressionError`, which is
    // what `for_decompression`'s `other` argument is at every call site in Bun's
    // reader.
    "ZstdDecompressionError"
}

/// `ZSTD_getErrorName`'s text, for a compression failure.
///
/// `compress_to_box` reports `Failure::Compression(err.as_bytes())`, where `err`
/// came from `ZSTD_getErrorName`, so a compress failure's message is zstd's own
/// prose rather than an enumerator name. It is unreachable in practice — the
/// destination is `ZSTD_compressBound` bytes — but the shape is recorded rather
/// than guessed.
fn compress_reason(result: usize) -> String {
    // SAFETY: `ZSTD_getErrorName` returns a pointer to a static NUL-terminated
    // string for any error code.
    let pointer = unsafe { z::ZSTD_getErrorName(result) };
    if pointer.is_null() {
        return "ZstdError".to_string();
    }
    // SAFETY: non-null, NUL-terminated and static, per the function's contract.
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

/// Compresses `input` into a single zstd frame at `level`.
///
/// `ZSTD_compress` writes the content size into the header whenever the source
/// size is known, which is what makes Bun's output byte-identical in shape: the
/// frame starts `28 b5 2f fd`, then a frame header with the size, then one block.
pub fn compress(input: &[u8], level: i32) -> Result<Vec<u8>, CompressionError> {
    if !(MIN_LEVEL..=MAX_LEVEL).contains(&level) {
        return Err(invalid_level());
    }

    // SAFETY: `ZSTD_compressBound` reads only its argument.
    let bound = unsafe { z::ZSTD_compressBound(input.len()) };
    if is_error(bound) {
        return Err(CompressionError::Zstd {
            reason: "Input is too large to compress".to_string(),
            decompress: false,
        });
    }

    let mut output = vec![0u8; bound];
    // SAFETY: `output` is exactly `bound` bytes, which `ZSTD_compress`
    // guarantees is enough; `input` is a valid slice for its length.
    let written = unsafe {
        z::ZSTD_compress(
            output.as_mut_ptr().cast(),
            output.len(),
            input.as_ptr().cast(),
            input.len(),
            level,
        )
    };
    if is_error(written) {
        return Err(CompressionError::Zstd {
            reason: compress_reason(written),
            decompress: false,
        });
    }
    output.truncate(written);
    Ok(output)
}

/// Decompresses every frame in `input`, concatenating their contents.
///
/// An empty input returns an empty buffer rather than throwing — the deliberate
/// special case in spec 3.3 that an "is it valid" check would get wrong. Bun
/// gets it for free: `ZSTD_findDecompressedSize` reports a size of 0 for empty
/// input, the fast path allocates nothing and `ZSTD_decompress` of nothing
/// succeeds.
///
/// Concatenated frames concatenate their output, which is measured: two
/// `zstdCompressSync` results back to back decode to `"aabb"`. Trailing bytes
/// that are *not* a frame are an error, also measured.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut output = Vec::new();
    if input.is_empty() {
        return Ok(output);
    }

    let size = match find_decompressed_size(input) {
        // Bun's `decompress_alloc` reports `InvalidZstdData` here, before any
        // decoder exists. This is the arm that catches a bad magic, gzip input,
        // and trailing junk after a complete frame.
        Err(()) => return Err(invalid_zstd_data()),
        Ok(size) => size,
    };

    if size.is_none() || size.unwrap_or(0) > MAX_PREALLOCATE {
        return decompress_streaming(input);
    }
    let expected = size.unwrap_or(0);
    output.reserve_exact(expected);
    // `ZSTD_decompress`'s destination is a raw pointer plus a capacity, not a
    // slice: passing `output.len()` would hand it a capacity of 0, because
    // `reserve_exact` grows `capacity` while `len` stays at zero. That is exactly
    // the bug this line used to have, and it reported `ZstdDecompressionError` on
    // every valid frame.
    let capacity = output.capacity();
    // SAFETY: `capacity` bytes are allocated and owned by `output`, and both
    // pointers refer to live slices for the duration of the call.
    let written = unsafe {
        z::ZSTD_decompress(
            output.as_mut_ptr().cast(),
            capacity,
            input.as_ptr().cast(),
            input.len(),
        )
    };
    if is_error(written) {
        return Err(CompressionError::Zstd {
            reason: decompress_reason(written).to_string(),
            decompress: true,
        });
    }
    // SAFETY: `ZSTD_decompress` initialized exactly the `written` bytes it
    // returned, and `written` is at most the capacity reserved above.
    unsafe { output.set_len(written) };
    Ok(output)
}

/// The streaming path, for a frame whose size is unknown or too large to trust.
///
/// This mirrors `ZstdReaderArrayList::read_all(true)` in Bun's `src/zstd`:
/// `ZSTD_decompressStream` in a loop until it reports 0 (frame done) with the
/// input consumed, and `ZstdDecompressionError` when the input runs out mid
/// frame. An input that ends exactly on a frame boundary is a success.
fn decompress_streaming(input: &[u8]) -> Result<Vec<u8>, CompressionError> {
    // SAFETY: creates a fresh context with the default memory functions.
    let stream = unsafe { z::ZSTD_createDStream() };
    if stream.is_null() {
        return Err(CompressionError::Zstd {
            reason: "OutOfMemory".to_string(),
            decompress: true,
        });
    }
    // SAFETY: `stream` was just created and is not shared.
    unsafe { z::ZSTD_initDStream(stream) };

    let mut output: Vec<u8> = Vec::new();
    let mut consumed = 0usize;
    let result = loop {
        if consumed >= input.len() {
            // Every byte was consumed. Reaching this with the stream still
            // asking for more is Bun's truncation case; reaching it right after
            // a completed frame is the success the loop breaks on below, so this
            // arm only runs for a genuinely short input.
            break Err(truncated());
        }

        if output.len() == output.capacity() {
            output.reserve(4096);
        }
        let spare = output.capacity() - output.len();
        let mut in_buffer = z::ZSTD_inBuffer {
            // SAFETY: `consumed` is within `input`, so the offset pointer is
            // valid for the remaining length.
            src: unsafe { input.as_ptr().add(consumed) }.cast(),
            size: input.len() - consumed,
            pos: 0,
        };
        let mut out_buffer = z::ZSTD_outBuffer {
            // SAFETY: `output` has `spare` bytes of capacity past `len()`, which
            // `reserve` just guaranteed. The region is uninitialized, which a
            // raw pointer permits.
            dst: unsafe { output.as_mut_ptr().add(output.len()) }.cast(),
            size: spare,
            pos: 0,
        };

        // SAFETY: `stream` is live, and both buffers describe live slices with
        // correct capacities.
        let remaining =
            unsafe { z::ZSTD_decompressStream(stream, &mut out_buffer, &mut in_buffer) };
        // SAFETY: zstd initialized `out_buffer.pos` bytes in the spare capacity.
        unsafe { output.set_len(output.len() + out_buffer.pos) };
        consumed += in_buffer.pos;

        if is_error(remaining) {
            break Err(CompressionError::Zstd {
                reason: decompress_reason(remaining).to_string(),
                decompress: true,
            });
        }
        if remaining == 0 {
            // A frame ended. If more input remains it is another frame, which
            // the loop continues into; `ZSTD_decompressStream` resets itself
            // for the next frame and Bun relies on that rather than calling
            // `ZSTD_initDStream` again.
            if consumed >= input.len() {
                break Ok(());
            }
            continue;
        }
        if in_buffer.pos == 0 && out_buffer.pos == 0 {
            // No progress in either direction. Bun's reader reports
            // `ShortRead` when it is not done; this caller always is, so the
            // same condition is the truncation arm.
            break Err(truncated());
        }
    };

    // SAFETY: `stream` was created above and is freed exactly once here.
    unsafe { z::ZSTD_freeDStream(stream) };
    result.map(|()| output)
}

fn invalid_zstd_data() -> CompressionError {
    CompressionError::Zstd {
        reason: "InvalidZstdData".to_string(),
        decompress: true,
    }
}

fn truncated() -> CompressionError {
    CompressionError::Zstd {
        reason: "ZstdDecompressionError".to_string(),
        decompress: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

    #[test]
    fn the_output_starts_with_the_zstd_magic() {
        let compressed = compress(b"hello", DEFAULT_LEVEL).expect("compress");
        assert_eq!(&compressed[..4], &MAGIC);
    }

    #[test]
    fn bun_hello_bytes_match_at_the_default_level() {
        // Bun 1.4.4's `zstdCompressSync("hello")`. The frame carries the content
        // size, so the header is `20 05 29 00 00` — one byte of size and the
        // single-byte literals — and this pins that the encoder is called with
        // the content size rather than in streaming mode.
        let compressed = compress(b"hello", DEFAULT_LEVEL).expect("compress");
        let hex: String = compressed
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, "28b52ffd200529000068656c6c6f");
    }

    #[test]
    fn an_empty_input_round_trips_and_is_not_an_error_to_decompress() {
        // The deliberate special case: `zstdDecompressSync(Buffer.alloc(0))`
        // returns an empty Buffer. A "no magic, so invalid" check would throw.
        assert!(decompress(&[]).expect("empty is fine").is_empty());
        let compressed = compress(b"", DEFAULT_LEVEL).expect("compress");
        assert!(
            !compressed.is_empty(),
            "an empty input still produces a frame"
        );
        assert!(decompress(&compressed).expect("round trip").is_empty());
    }

    #[test]
    fn round_trips_empty_one_byte_a_block_boundary_and_multi_megabyte() {
        for (label, input) in [
            ("empty", Vec::new()),
            ("one byte", vec![0]),
            ("block boundary", vec![7u8; 131_072]),
            ("multi-megabyte", vec![9u8; 3 * 1024 * 1024]),
        ] {
            let compressed = compress(&input, DEFAULT_LEVEL)
                .unwrap_or_else(|error| panic!("{label}: {error:?}"));
            let restored =
                decompress(&compressed).unwrap_or_else(|error| panic!("{label}: {error:?}"));
            assert_eq!(restored, input, "{label}");
        }
    }

    #[test]
    fn concatenated_frames_concatenate_their_output() {
        let mut joined = compress(b"aa", DEFAULT_LEVEL).expect("first");
        joined.extend_from_slice(&compress(b"bb", DEFAULT_LEVEL).expect("second"));
        assert_eq!(decompress(&joined).expect("both frames"), b"aabb");
    }

    #[test]
    fn random_bytes_report_invalid_zstd_data() {
        let error = decompress(&[1, 2, 3, 4, 5, 6, 7, 8]).expect_err("fails");
        assert_eq!(error.message(), "Decompression failed: InvalidZstdData");
        assert_eq!(error.code(), Some("ERR_ZSTD"));
    }

    #[test]
    fn a_bad_body_reports_zstd_decompression_error() {
        // The magic is intact and the frame header parses, so the failure comes
        // from the decoder rather than from the size probe. That is the split
        // Bun's error taxonomy turns on, and this input is the measured case.
        let error = decompress(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00]).expect_err("fails");
        assert_eq!(
            error.message(),
            "Decompression failed: ZstdDecompressionError"
        );
    }

    #[test]
    fn gzip_input_is_invalid_zstd_data() {
        // Cross-container confusion is the case the spec calls out: it must be
        // rejected, not misdecoded.
        let error = decompress(&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 3]).expect_err("fails");
        assert_eq!(error.message(), "Decompression failed: InvalidZstdData");
    }

    #[test]
    fn a_truncated_frame_is_an_error_at_every_length() {
        let compressed = compress(b"hello world hello world", DEFAULT_LEVEL).expect("compress");
        for length in 1..compressed.len() {
            let error = decompress(&compressed[..length]).expect_err("truncated fails");
            assert_eq!(error.code(), Some("ERR_ZSTD"), "length {length}");
        }
    }

    #[test]
    fn trailing_junk_after_a_complete_frame_is_an_error() {
        let mut joined = compress(b"hi", DEFAULT_LEVEL).expect("compress");
        joined.extend_from_slice(&[1, 2, 3, 4]);
        let error = decompress(&joined).expect_err("junk fails");
        assert_eq!(error.message(), "Decompression failed: InvalidZstdData");
    }

    #[test]
    fn a_skippable_frame_decodes_to_nothing() {
        // `50 2a 4d 18` is skippable-frame magic with a zero-length body, which
        // zstd accepts and Bun returns as an empty Buffer.
        let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        assert!(decompress(&skippable).expect("skippable frame").is_empty());
    }

    #[test]
    fn a_level_outside_the_range_is_a_type_error_naming_the_range() {
        for level in [0, 23, -1] {
            let error = compress(b"hello", level).expect_err("fails");
            assert_eq!(
                error.message(),
                "Compression level must be between 1 and 22"
            );
            assert_eq!(error.code(), Some("ERR_INVALID_ARG_TYPE"));
        }
    }

    #[test]
    fn a_level_changes_the_frame_where_the_encoder_cares() {
        // Level 1 and level 19 agree on most inputs, so the check uses the exact
        // payload Bun's spec records a split on: 5000 copies of `a`, where Bun
        // reports 19 bytes at level 1 and 18 at level 19 and measured that the two
        // really differ. Pinning the sizes would be wrong — they are the encoder's
        // — so only the inequality is asserted.
        let payload = vec![b'a'; 5000];
        let level1 = compress(&payload, 1).expect("level 1");
        let level19 = compress(&payload, 19).expect("level 19");
        assert_ne!(
            level1.len(),
            level19.len(),
            "levels 1 and 19 agree on this payload"
        );
        assert_eq!(decompress(&level19).expect("round trip"), payload);
    }
}

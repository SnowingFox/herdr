//! The eight callbacks `Bun` publishes, and the two container formats they serve.
//!
//! The sync members are thin: read the bytes, read the options, call the codec,
//! wrap the result. Everything that is actually interesting — which wrapper, which
//! message, which `code` — lives in [`crate::zlib_codec`], [`crate::zstd_codec`]
//! and [`crate::args`], because it is testable there without an isolate.
//!
//! The two async members are not thin: they queue on libuv's threadpool and settle
//! a promise from the completion, so that `Bun.zstdCompress` really is
//! asynchronous. Measured on Bun 1.4.4: the promise is unresolved when
//! `zstdCompress` returns, a `.then` on it runs in the completion's microtask
//! checkpoint, and a 40 MiB compression leaves a 1 ms interval timer ticking while
//! it runs. A member that computed inline and returned `Promise.resolve(value)`
//! would satisfy every round-trip test and be observably wrong.

use rn_v8_sys::v8;

use crate::args;
use crate::error::CompressionError;
use crate::job;
use crate::zlib_codec::{self, Wrapper};
use crate::zstd_codec;

/// The gzip trailer's `ISIZE` field, which Bun reads as an output-size hint.
const GZIP_TRAILER: usize = 8;
/// Bun's ceiling on a trailer size it will trust enough to reserve.
const MAX_TRUSTED_HINT: usize = 256 * 1024 * 1024;

/// `Bun.gzipSync(data, options?)`.
pub fn gzip_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue,
) {
    compress_into_uint8_array(scope, &args, rv, Wrapper::Gzip);
}

/// `Bun.deflateSync(data, options?)` — **raw** deflate, RFC 1951.
pub fn deflate_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue,
) {
    compress_into_uint8_array(scope, &args, rv, Wrapper::Raw);
}

fn compress_into_uint8_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
    wrapper: Wrapper,
) {
    let Some(input) = input(scope, args) else {
        return;
    };
    let params = match args::zlib_compression(scope, args.get(1)) {
        Ok(params) => params,
        Err(error) => return throw(scope, error),
    };
    match zlib_codec::compress(&input, params, wrapper) {
        Ok(bytes) => {
            let value = args::uint8_array(scope, bytes);
            set(scope, &mut rv, value);
        }
        Err(error) => throw(scope, error.into()),
    }
}

/// `Bun.gunzipSync(data, options?)`.
///
/// Returns the **first** gzip member only. Measured: concatenating two members and
/// decompressing yields the first member's payload, and trailing zero padding and
/// trailing non-zero junk after it are both ignored. That is what a single
/// `windowBits = 31` inflate does, so this deliberately does not loop over members
/// the way Node's `gunzip` does.
pub fn gunzip_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue,
) {
    decompress_into_uint8_array(scope, &args, rv, zlib_codec::GZIP_WINDOW_BITS, true);
}

/// `Bun.inflateSync(data, options?)` — accepts **raw** deflate, RFC 1951.
pub fn inflate_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    rv: v8::ReturnValue,
) {
    // No trailer to read a hint from: a raw stream carries no size anywhere.
    decompress_into_uint8_array(scope, &args, rv, zlib_codec::RAW_WINDOW_BITS, false);
}

fn decompress_into_uint8_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
    default_window_bits: i32,
    gzip_hint: bool,
) {
    let Some(input) = input(scope, args) else {
        return;
    };
    // The two members differ in the `windowBits` they default to — 31 for the gzip
    // pair and -15 for the raw pair — and an explicit `{windowBits}` overrides it.
    // Measured: `gunzipSync(gz, {windowBits: 15})` reports `incorrect header
    // check`, and `inflateSync(raw, {windowBits: 15})` does the same in reverse.
    let window_bits = match args::zlib_decompression(scope, args.get(1), default_window_bits) {
        Ok(settings) => settings.window_bits,
        Err(error) => return throw(scope, error),
    };
    let hint = if gzip_hint && window_bits == zlib_codec::GZIP_WINDOW_BITS {
        gzip_capacity_hint(&input)
    } else {
        None
    };
    match zlib_codec::decompress(&input, window_bits, hint) {
        Ok(bytes) => {
            let value = args::uint8_array(scope, bytes);
            set(scope, &mut rv, value);
        }
        Err(error) => throw(scope, error.into()),
    }
}

/// The output size a gzip trailer claims, when the stream really is gzip.
///
/// Bun reserves this much up front, which is why a 3 MB member decompresses without
/// a doubling ladder. The value is `len % 2^32` by RFC 1952 and is untrusted, so it
/// is only a hint: the codec grows past it when it is wrong.
fn gzip_capacity_hint(input: &[u8]) -> Option<usize> {
    if input.len() <= GZIP_TRAILER {
        return None;
    }
    let trailer = &input[input.len() - 4..];
    let claimed = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]) as usize;
    (claimed > 0 && claimed < MAX_TRUSTED_HINT).then_some(claimed)
}

/// `Bun.zstdCompressSync(data, options?)` — returns a `Buffer`.
pub fn zstd_compress_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(input) = input(scope, &args) else {
        return;
    };
    let level = match args::zstd_level(scope, args.get(1)) {
        Ok(level) => level,
        Err(Some(error)) => return throw(scope, error),
        // `None` means V8 already holds a pending exception from coercing a
        // symbol; returning without setting a value leaves it in place, which is
        // what Bun does (`Cannot convert a symbol to a number`).
        Err(None) => return,
    };
    match zstd_codec::compress(&input, level) {
        Ok(bytes) => {
            let value = args::buffer(scope, bytes);
            set(scope, &mut rv, value);
        }
        Err(error) => throw(scope, error),
    }
}

/// `Bun.zstdDecompressSync(data)` — returns a `Buffer`, and takes no options.
///
/// Bun's own schema for this member is `{ data: stringOrBuffer }`: a second
/// argument is accepted and ignored, even a non-object one, which is why
/// `zstdDecompressSync(z, 9)` does not throw the way `gunzipSync(gz, 9)` does.
pub fn zstd_decompress_sync<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(input) = input(scope, &args) else {
        return;
    };
    match zstd_codec::decompress(&input) {
        Ok(bytes) => {
            let value = args::buffer(scope, bytes);
            set(scope, &mut rv, value);
        }
        Err(error) => throw(scope, error),
    }
}

/// `Bun.zstdCompress(data, options?)` → `Promise<Buffer>`.
pub fn zstd_compress<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    // The level is validated **before** the promise exists, because Bun throws it
    // synchronously: `zstdCompress("hello", {level: 99})` is a `TypeError` out of
    // the call, not a rejection. Measured.
    let level = match args::zstd_level(scope, args.get(1)) {
        Ok(level) => level,
        Err(Some(error)) => return throw(scope, error),
        Err(None) => return,
    };
    let Some(input) = input(scope, &args) else {
        return;
    };
    match job::schedule(scope, job::Work::compress(input, level)) {
        Ok(promise) => set(scope, &mut rv, Some(promise)),
        Err(error) => throw(scope, error),
    }
}

/// `Bun.zstdDecompress(data)` → `Promise<Buffer>`.
///
/// The data type is checked synchronously (`zstdDecompress(123)` throws), but a
/// *corrupt body* rejects: measured, `zstdDecompress(garbage)` returns a promise
/// that rejects with the `ERR_ZSTD` error. Decompression failures therefore cross
/// the threadpool boundary as a rejection rather than a throw.
pub fn zstd_decompress<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(input) = input(scope, &args) else {
        return;
    };
    match job::schedule(scope, job::Work::decompress(input)) {
        Ok(promise) => set(scope, &mut rv, Some(promise)),
        Err(error) => throw(scope, error),
    }
}

/// Reads argument 0, throwing the shared `data must be …` `TypeError` if it is not
/// one of the three accepted shapes.
fn input<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Option<Vec<u8>> {
    match args::data_bytes(scope, args.get(0)) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            throw(scope, error);
            None
        }
    }
}

/// Sets the return value, or leaves `undefined` when the allocation failed and V8
/// already holds the exception.
fn set(
    scope: &mut v8::PinScope<'_, '_>,
    rv: &mut v8::ReturnValue,
    value: Option<v8::Local<'_, v8::Value>>,
) {
    match value {
        Some(value) => rv.set(value),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// Throws a `CompressionError`.
///
/// The `ReturnValue` is left unset, which reads back as `undefined` — the value a
/// throwing member yields on both runtimes when its exception is caught.
fn throw(scope: &mut v8::PinScope<'_, '_>, error: CompressionError) {
    let exception = error.exception(scope);
    scope.throw_exception(exception);
}

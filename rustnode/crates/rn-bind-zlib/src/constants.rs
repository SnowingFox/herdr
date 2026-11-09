//! zlib/Brotli constants that `lib/internal/constants.js` would own.
//!
//! `lib/zlib.js` reads them from `internalBinding('constants').zlib`, not from
//! this namespace, but the same numbers have to exist somewhere and every one
//! of them is referenced by name there. Keeping them here makes the values
//! testable without a V8 isolate and documents the exact set the JS uses.

/// Flush levels (`Z_*` from `zlib.h`).
pub const Z_NO_FLUSH: i32 = 0;
pub const Z_PARTIAL_FLUSH: i32 = 1;
pub const Z_SYNC_FLUSH: i32 = 2;
pub const Z_FULL_FLUSH: i32 = 3;
pub const Z_FINISH: i32 = 4;
pub const Z_BLOCK: i32 = 5;

/// Return codes.
pub const Z_OK: i32 = 0;
pub const Z_STREAM_END: i32 = 1;
pub const Z_NEED_DICT: i32 = 2;
pub const Z_ERRNO: i32 = -1;
pub const Z_STREAM_ERROR: i32 = -2;
pub const Z_DATA_ERROR: i32 = -3;
pub const Z_MEM_ERROR: i32 = -4;
pub const Z_BUF_ERROR: i32 = -5;
pub const Z_VERSION_ERROR: i32 = -6;

/// Compression levels and strategies.
pub const Z_NO_COMPRESSION: i32 = 0;
pub const Z_BEST_SPEED: i32 = 1;
pub const Z_BEST_COMPRESSION: i32 = 9;
pub const Z_DEFAULT_COMPRESSION: i32 = -1;
pub const Z_FILTERED: i32 = 1;
pub const Z_HUFFMAN_ONLY: i32 = 2;
pub const Z_RLE: i32 = 3;
pub const Z_FIXED: i32 = 4;
pub const Z_DEFAULT_STRATEGY: i32 = 0;

/// The only compression method zlib implements.
pub const Z_DEFLATED: i32 = 8;

/// Window and buffer bounds, from `src/node_zlib.cc`.
pub const Z_MIN_WINDOWBITS: i32 = 8;
pub const Z_MAX_WINDOWBITS: i32 = 15;
pub const Z_DEFAULT_WINDOWBITS: i32 = 15;
pub const Z_MIN_CHUNK: i32 = 64;
pub const Z_DEFAULT_CHUNK: i32 = 16 * 1024;
pub const Z_MIN_MEMLEVEL: i32 = 1;
pub const Z_MAX_MEMLEVEL: i32 = 9;
pub const Z_DEFAULT_MEMLEVEL: i32 = 8;
pub const Z_MIN_LEVEL: i32 = -1;
pub const Z_MAX_LEVEL: i32 = 9;

/// `node_zlib_mode`, in declaration order. The numbers are load-bearing:
/// `lib/zlib.js` builds them from the `constants` binding and asserts
/// `DEFLATE <= mode <= ZSTD_DECOMPRESS`.
pub const NONE: i32 = 0;
pub const DEFLATE: i32 = 1;
pub const INFLATE: i32 = 2;
pub const GZIP: i32 = 3;
pub const GUNZIP: i32 = 4;
pub const DEFLATERAW: i32 = 5;
pub const INFLATERAW: i32 = 6;
pub const UNZIP: i32 = 7;
pub const BROTLI_DECODE: i32 = 8;
pub const BROTLI_ENCODE: i32 = 9;
pub const ZSTD_COMPRESS: i32 = 10;
pub const ZSTD_DECOMPRESS: i32 = 11;

/// Brotli operations, which stand in for flush levels.
pub const BROTLI_OPERATION_PROCESS: i32 = 0;
pub const BROTLI_OPERATION_FLUSH: i32 = 1;
pub const BROTLI_OPERATION_FINISH: i32 = 2;
pub const BROTLI_OPERATION_EMIT_METADATA: i32 = 3;

/// Gzip framing bytes, used by auto-detecting UNZIP.
pub const GZIP_HEADER_ID1: u8 = 0x1f;
pub const GZIP_HEADER_ID2: u8 = 0x8b;

/// Name for a zlib return code, matching `ZlibStrerror()` in `node_zlib.cc`.
///
/// This string is what `lib/zlib.js` puts on the `code` property of the error
/// object it builds from `onerror(message, errno, code)`.
pub fn zlib_strerror(err: i32) -> &'static str {
    match err {
        Z_OK => "Z_OK",
        Z_STREAM_END => "Z_STREAM_END",
        Z_NEED_DICT => "Z_NEED_DICT",
        Z_ERRNO => "Z_ERRNO",
        Z_STREAM_ERROR => "Z_STREAM_ERROR",
        Z_DATA_ERROR => "Z_DATA_ERROR",
        Z_MEM_ERROR => "Z_MEM_ERROR",
        Z_BUF_ERROR => "Z_BUF_ERROR",
        Z_VERSION_ERROR => "Z_VERSION_ERROR",
        _ => "Z_UNKNOWN_ERROR",
    }
}

/// `ZLIB_VERSION` as the binding reports it.
pub const ZLIB_VERSION: &str = "1.3.1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_are_ordered_like_node_zlib_mode() {
        // lib/zlib.js asserts `mode >= DEFLATE && mode <= ZSTD_DECOMPRESS`, and
        // its switch statements compare against these exact numbers.
        assert_eq!(NONE, 0);
        assert_eq!(DEFLATE, 1);
        assert_eq!(INFLATE, 2);
        assert_eq!(GZIP, 3);
        assert_eq!(GUNZIP, 4);
        assert_eq!(DEFLATERAW, 5);
        assert_eq!(INFLATERAW, 6);
        assert_eq!(UNZIP, 7);
        assert_eq!(BROTLI_DECODE, 8);
        assert_eq!(BROTLI_ENCODE, 9);
        assert_eq!(ZSTD_COMPRESS, 10);
        assert_eq!(ZSTD_DECOMPRESS, 11);
        const { assert!(DEFLATE <= ZSTD_DECOMPRESS) };
    }

    #[test]
    fn flush_levels_match_zlib_h() {
        assert_eq!(Z_NO_FLUSH, 0);
        assert_eq!(Z_PARTIAL_FLUSH, 1);
        assert_eq!(Z_SYNC_FLUSH, 2);
        assert_eq!(Z_FULL_FLUSH, 3);
        assert_eq!(Z_FINISH, 4);
        assert_eq!(Z_BLOCK, 5);
        // `flushiness[]` in lib/zlib.js maps each flag to its index in this
        // exact list, so the values only have to be distinct and in the order
        // of increasing flush strength.
        let flushiness = [
            Z_NO_FLUSH,
            Z_BLOCK,
            Z_PARTIAL_FLUSH,
            Z_SYNC_FLUSH,
            Z_FULL_FLUSH,
            Z_FINISH,
        ];
        let mut seen = flushiness.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), flushiness.len(), "flush flags must be distinct");
    }

    #[test]
    fn return_codes_match_zlib_h() {
        assert_eq!(Z_OK, 0);
        assert_eq!(Z_STREAM_END, 1);
        assert_eq!(Z_NEED_DICT, 2);
        assert_eq!(Z_ERRNO, -1);
        assert_eq!(Z_STREAM_ERROR, -2);
        assert_eq!(Z_DATA_ERROR, -3);
        assert_eq!(Z_MEM_ERROR, -4);
        assert_eq!(Z_BUF_ERROR, -5);
        assert_eq!(Z_VERSION_ERROR, -6);
    }

    #[test]
    fn strerror_names_round_trip_through_zlib_js_codes_table() {
        // lib/zlib.js builds `codes` by mapping each numeric code to its name and
        // then parses the name back out of `zlibError(message, errno, code)`.
        for (code, name) in [
            (Z_OK, "Z_OK"),
            (Z_STREAM_END, "Z_STREAM_END"),
            (Z_NEED_DICT, "Z_NEED_DICT"),
            (Z_STREAM_ERROR, "Z_STREAM_ERROR"),
            (Z_DATA_ERROR, "Z_DATA_ERROR"),
            (Z_BUF_ERROR, "Z_BUF_ERROR"),
        ] {
            assert_eq!(zlib_strerror(code), name);
        }
        assert_eq!(zlib_strerror(1234), "Z_UNKNOWN_ERROR");
    }

    #[test]
    fn brotli_operations_match_the_c_enum() {
        assert_eq!(BROTLI_OPERATION_PROCESS, 0);
        assert_eq!(BROTLI_OPERATION_FLUSH, 1);
        assert_eq!(BROTLI_OPERATION_FINISH, 2);
        assert_eq!(BROTLI_OPERATION_EMIT_METADATA, 3);
    }
}

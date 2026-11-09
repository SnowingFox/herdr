//! The zlib-backed half of the `Zlib` handle: `src/node_zlib.cc`'s
//! `ZlibContext`, minus libuv.
//!
//! Everything here is synchronous and allocation-only; the V8 wrapper in
//! `handle.rs` decides when to call it. Buffer pointers are `&mut [u8]` slices
//! taken from the JS-supplied `Buffer`s for the duration of one call, exactly
//! like `SetBuffers()` does.

use std::ffi::CStr;

use libz_rs_sys as z;

use crate::constants::*;
use crate::AfterWrite;

/// Which compression stream this handle runs: `node_zlib_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZlibMode {
    Deflate,
    Inflate,
    Gzip,
    Gunzip,
    DeflateRaw,
    InflateRaw,
    Unzip,
}

impl ZlibMode {
    /// Maps the `node_zlib_mode` integer `lib/zlib.js` passes to
    /// `new binding.Zlib(mode)`.
    pub fn from_i32(mode: i32) -> Option<Self> {
        Some(match mode {
            DEFLATE => Self::Deflate,
            INFLATE => Self::Inflate,
            GZIP => Self::Gzip,
            GUNZIP => Self::Gunzip,
            DEFLATERAW => Self::DeflateRaw,
            INFLATERAW => Self::InflateRaw,
            UNZIP => Self::Unzip,
            _ => return None,
        })
    }

    /// `true` for the three modes that run `deflate()`.
    pub fn is_deflate(self) -> bool {
        matches!(self, Self::Deflate | Self::Gzip | Self::DeflateRaw)
    }

    /// `true` for the four modes that run `inflate()`.
    pub fn is_inflate(self) -> bool {
        !self.is_deflate()
    }

    /// The `node_zlib_mode` integer for this mode.
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Deflate => DEFLATE,
            Self::Inflate => INFLATE,
            Self::Gzip => GZIP,
            Self::Gunzip => GUNZIP,
            Self::DeflateRaw => DEFLATERAW,
            Self::InflateRaw => INFLATERAW,
            Self::Unzip => UNZIP,
        }
    }
}

/// A zlib error in the shape `CompressionError` has: a message for
/// `onerror(message, errno, code)`, a symbolic `code`, and the numeric `errno`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZlibError {
    pub message: String,
    pub code: &'static str,
    pub err: i32,
}

impl ZlibError {
    fn new(message: impl Into<String>, err: i32) -> Self {
        Self {
            message: message.into(),
            code: zlib_strerror(err),
            err,
        }
    }
}

/// `ZlibContext` from `src/node_zlib.cc`.
pub struct ZlibStream {
    mode: ZlibMode,
    /// Set once the stream finished (or failed) and had to be re-initialized on
    /// the next write, mirroring `zlib_init_done_`.
    initialized: bool,
    closed: bool,
    err: i32,
    flush: i32,
    level: i32,
    mem_level: i32,
    strategy: i32,
    /// `window_bits_` after Node's gzip/raw/unzip fixups.
    window_bits: i32,
    /// Where the last `write` left the output cursor, as `(pointer, capacity)`.
    ///
    /// `deflateParams` may need to emit the tail of the current block, and
    /// Node's `SetParams()` runs with whatever `next_out`/`avail_out` the
    /// previous write left behind. `lib/zlib.js` always reaches `params()`
    /// through `paramsAfterFlushCallback`, which is invoked from the write
    /// callback while `engine._outBuffer` is still the buffer that write used,
    /// so restoring this pair reproduces Node's state exactly.
    ///
    /// # Safety contract
    ///
    /// Only read it in `set_params`, and only while the JS is inside the write
    /// callback for the write that set it. `reset` and `write` both clear it.
    out_cursor: Option<(*mut u8, usize)>,
    dictionary: Vec<u8>,
    reject_garbage_after_end: bool,
    /// `gzip_id_bytes_read_`, only meaningful while auto-detecting in UNZIP.
    gzip_id_bytes_read: u32,
    /// The live `z_stream`. Its `zalloc`/`zfree`/`opaque` are configured once in
    /// the constructor and reused by every re-initialization.
    stream: Box<z::z_stream>,
}

// The `z_stream` only ever points at memory owned by its own allocator, and the
// buffer pointers are installed and cleared entirely inside one call, so a
// `ZlibStream` is safe to move between threads the way Node's zlib handle is.
unsafe impl Send for ZlibStream {}

impl ZlibStream {
    /// Creates the un-initialized context for `mode`, matching
    /// `CompressionStream`'s constructor. zlib itself is initialized lazily on
    /// the first write, as Node does.
    pub fn new(mode: ZlibMode) -> Self {
        Self {
            mode,
            initialized: false,
            closed: false,
            err: Z_OK,
            flush: Z_NO_FLUSH,
            level: Z_DEFAULT_COMPRESSION,
            mem_level: Z_DEFAULT_MEMLEVEL,
            strategy: Z_DEFAULT_STRATEGY,
            window_bits: Z_DEFAULT_WINDOWBITS,
            dictionary: Vec::new(),
            reject_garbage_after_end: false,
            gzip_id_bytes_read: 0,
            out_cursor: None,
            stream: Box::new(z::z_stream::default()),
        }
    }

    /// The mode this handle runs.
    pub fn mode(&self) -> ZlibMode {
        self.mode
    }

    /// `ZlibStream::Init()`: stores the options and applies Node's windowBits
    /// fixups. No allocation happens here; zlib is initialized on first write.
    pub fn init(
        &mut self,
        level: i32,
        window_bits: i32,
        mem_level: i32,
        strategy: i32,
        dictionary: &[u8],
        reject_garbage_after_end: bool,
    ) -> Result<(), ZlibError> {
        let in_range = (Z_MIN_WINDOWBITS..=Z_MAX_WINDOWBITS).contains(&window_bits);
        let auto_window = window_bits == 0 && self.mode.is_inflate();
        if !in_range && !auto_window {
            return Err(ZlibError::new("invalid windowBits", Z_STREAM_ERROR));
        }
        if !(Z_MIN_LEVEL..=Z_MAX_LEVEL).contains(&level) {
            return Err(ZlibError::new("invalid compression level", Z_STREAM_ERROR));
        }
        if !(Z_MIN_MEMLEVEL..=Z_MAX_MEMLEVEL).contains(&mem_level) {
            return Err(ZlibError::new("invalid memlevel", Z_STREAM_ERROR));
        }
        if !matches!(
            strategy,
            Z_DEFAULT_STRATEGY | Z_FILTERED | Z_HUFFMAN_ONLY | Z_RLE | Z_FIXED
        ) {
            return Err(ZlibError::new("invalid strategy", Z_STREAM_ERROR));
        }

        self.level = level;
        self.window_bits = window_bits;
        self.mem_level = mem_level;
        self.strategy = strategy;
        self.reject_garbage_after_end = reject_garbage_after_end;
        self.flush = Z_NO_FLUSH;
        self.err = Z_OK;
        self.closed = false;

        // Node shifts windowBits into the gzip/auto-detect/raw ranges here so
        // the value handed to zlib already selects the wrapper.
        match self.mode {
            ZlibMode::Gzip | ZlibMode::Gunzip => self.window_bits += 16,
            ZlibMode::Unzip => self.window_bits += 32,
            ZlibMode::DeflateRaw | ZlibMode::InflateRaw => self.window_bits *= -1,
            ZlibMode::Deflate | ZlibMode::Inflate => {}
        }

        self.dictionary = dictionary.to_vec();
        Ok(())
    }

    /// Runs one compression/decompression step over `input`, writing into
    /// `output`, and reports what was left over.
    pub fn write(&mut self, flush: i32, input: &[u8], output: &mut [u8]) -> AfterWrite {
        if !self.initialized {
            if let Err(error) = self.init_zlib() {
                self.err = error.err;
                return AfterWrite {
                    avail_in: input.len() as u32,
                    avail_out: output.len() as u32,
                };
            }
        }

        self.set_buffers(input, output);
        self.flush = flush;

        match self.mode {
            ZlibMode::Deflate | ZlibMode::Gzip | ZlibMode::DeflateRaw => {
                // SAFETY: `set_buffers` installed live pointers into `input` and
                // `output`. They stay valid for this call and are cleared by
                // `take_after_write_offsets`, which runs right after this
                // method's caller is done with them.
                self.err = unsafe { z::deflate(self.stream.as_mut(), flush) };
            }
            ZlibMode::Unzip => {
                self.inflate_auto_detect(flush);
            }
            ZlibMode::Inflate | ZlibMode::Gunzip | ZlibMode::InflateRaw => {
                self.inflate(flush);
            }
        }

        let after = self.after_write_offsets();
        // `GetErrorInfo` reads `avail_out`, and the JS reads both offsets out of
        // `writeState`, so they stay in the stream. The output cursor is
        // remembered for a `params()` call made from this write's callback, and
        // the input pointer is dropped because nothing follows it.
        self.out_cursor = Some((self.stream.next_out, self.stream.avail_out as usize));
        self.stream.next_in = std::ptr::null();
        after
    }

    /// What the last `write` left over, which the JS reads back out of
    /// `writeState`.
    pub fn after_write_offsets(&self) -> AfterWrite {
        AfterWrite {
            avail_in: self.stream.avail_in,
            avail_out: self.stream.avail_out,
        }
    }

    /// `ZlibContext::GetErrorInfo()`: `Some` when the JS layer must be told
    /// about a failure via `onerror`.
    pub fn error_info(&self) -> Option<ZlibError> {
        match self.err {
            Z_OK | Z_BUF_ERROR => {
                if self.stream.avail_out != 0 && self.flush == Z_FINISH {
                    // Decompression ran out of input before finding the end of
                    // the stream: "unexpected end of file".
                    return Some(self.error_for_message("unexpected end of file"));
                }
                None
            }
            Z_STREAM_END => None,
            Z_NEED_DICT => {
                if self.dictionary.is_empty() {
                    Some(self.error_for_message("Missing dictionary"))
                } else {
                    Some(self.error_for_message("Bad dictionary"))
                }
            }
            _ => Some(self.error_for_message("Zlib error")),
        }
    }

    /// `ZlibContext::SetParams()`: changes level and strategy mid-stream.
    /// `deflateParams` may need output room to flush the pending block, and
    /// reports `Z_BUF_ERROR` when it could not finish; Node treats that as
    /// success and retries on the next write.
    pub fn set_params(&mut self, level: i32, strategy: i32) -> Option<ZlibError> {
        if !self.initialized {
            if let Err(error) = self.init_zlib() {
                return Some(error);
            }
        }
        self.err = Z_OK;
        if matches!(self.mode, ZlibMode::Deflate | ZlibMode::DeflateRaw) {
            // `deflateParams` needs room to finish the block it is in the middle
            // of. `lib/zlib.js` calls `params()` from the callback of a
            // `Z_SYNC_FLUSH` write, so the input is already consumed and the
            // output cursor is exactly where that write left it.
            if let Some((next_out, avail_out)) = self.out_cursor {
                self.stream.next_out = next_out;
                self.stream.avail_out = avail_out as u32;
            }
            self.stream.next_in = std::ptr::null();
            self.stream.avail_in = 0;
            // SAFETY: the stream is initialized and owns its own state. The
            // output pointer is the JS buffer that the write callback is still
            // running under, which is the same guarantee Node relies on.
            self.err = unsafe { z::deflateParams(self.stream.as_mut(), level, strategy) };
            // `deflateParams` may have written into that buffer, so the cursor
            // moves on for the next write's bookkeeping.
            self.out_cursor = Some((self.stream.next_out, self.stream.avail_out as usize));
        }
        self.level = level;
        self.strategy = strategy;
        if self.err != Z_OK && self.err != Z_BUF_ERROR {
            return Some(self.error_for_message("Failed to set parameters"));
        }
        None
    }

    /// `ZlibContext::ResetStream()`: restarts the stream so it can decompress
    /// or compress another independent member.
    pub fn reset(&mut self) -> Option<ZlibError> {
        if self.closed {
            return Some(ZlibError::new("zlib binding closed", Z_STREAM_ERROR));
        }
        if self.mode == ZlibMode::Unzip {
            self.gzip_id_bytes_read = 0;
        }
        if !self.initialized {
            if let Err(error) = self.init_zlib() {
                return Some(error);
            }
        }
        self.err = Z_OK;
        // SAFETY: the stream is initialized for this mode.
        self.err = unsafe {
            match self.mode {
                ZlibMode::Deflate | ZlibMode::Gzip | ZlibMode::DeflateRaw => {
                    z::deflateReset(self.stream.as_mut())
                }
                ZlibMode::Inflate | ZlibMode::Gunzip | ZlibMode::InflateRaw | ZlibMode::Unzip => {
                    z::inflateReset(self.stream.as_mut())
                }
            }
        };
        if self.err != Z_OK {
            return Some(self.error_for_message("Failed to reset stream"));
        }
        self.set_dictionary()
    }

    /// Releases the zlib state. Idempotent, like `ZlibContext::Close()`.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if self.initialized {
            // SAFETY: `initialized` means zlib allocated this stream.
            unsafe {
                if self.mode.is_deflate() {
                    z::deflateEnd(self.stream.as_mut());
                } else {
                    z::inflateEnd(self.stream.as_mut());
                }
            }
            self.initialized = false;
        }
        self.dictionary.clear();
    }

    fn init_zlib(&mut self) -> Result<(), ZlibError> {
        self.stream.msg = std::ptr::null_mut();
        match self.mode {
            ZlibMode::Deflate | ZlibMode::Gzip | ZlibMode::DeflateRaw => {
                // SAFETY: `self.stream` is a valid, uniquely borrowed z_stream
                // with a configured allocator; `zlibVersion()` is static.
                self.err = unsafe {
                    z::deflateInit2_(
                        self.stream.as_mut(),
                        self.level,
                        Z_DEFLATED,
                        self.window_bits,
                        self.mem_level,
                        self.strategy,
                        zlib_version_ptr(),
                        std::mem::size_of::<z::z_stream>() as i32,
                    )
                };
            }
            ZlibMode::Inflate | ZlibMode::Gunzip | ZlibMode::InflateRaw | ZlibMode::Unzip => {
                // SAFETY: as above.
                self.err = unsafe {
                    z::inflateInit2_(
                        self.stream.as_mut(),
                        self.window_bits,
                        zlib_version_ptr(),
                        std::mem::size_of::<z::z_stream>() as i32,
                    )
                };
            }
        }

        if self.err != Z_OK {
            self.dictionary.clear();
            return Err(self.error_for_message("Failed to initialize stream"));
        }

        self.initialized = true;
        match self.set_dictionary() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn set_dictionary(&mut self) -> Option<ZlibError> {
        if self.dictionary.is_empty() {
            return None;
        }
        self.err = Z_OK;
        // SAFETY: the stream is initialized and the dictionary slice is owned by
        // `self`, so it outlives the call.
        unsafe {
            match self.mode {
                ZlibMode::Deflate | ZlibMode::DeflateRaw => {
                    self.err = z::deflateSetDictionary(
                        self.stream.as_mut(),
                        self.dictionary.as_ptr(),
                        self.dictionary.len() as u32,
                    );
                }
                ZlibMode::InflateRaw => {
                    self.err = z::inflateSetDictionary(
                        self.stream.as_mut(),
                        self.dictionary.as_ptr(),
                        self.dictionary.len() as u32,
                    );
                }
                _ => {}
            }
        }
        if self.err != Z_OK {
            return Some(self.error_for_message("Failed to set dictionary"));
        }
        None
    }

    fn set_buffers(&mut self, input: &[u8], output: &mut [u8]) {
        self.stream.next_in = input.as_ptr();
        self.stream.avail_in = input.len() as u32;
        self.stream.next_out = output.as_mut_ptr();
        self.stream.avail_out = output.len() as u32;
    }

    /// `UNZIP` has no separate zlib mode: Node initializes `inflateInit2()` with
    /// `window_bits + 32`, which makes zlib itself detect a gzip or zlib header.
    /// Node additionally peeks at the first two bytes to remember which one it
    /// saw, which is kept here for parity but does not change the call.
    fn inflate_auto_detect(&mut self, flush: i32) {
        if self.stream.avail_in > 0 && self.gzip_id_bytes_read < 2 {
            // SAFETY: `avail_in` bytes are valid at `next_in` for this call.
            let header = unsafe {
                std::slice::from_raw_parts(self.stream.next_in, self.stream.avail_in as usize)
            };
            if self.gzip_id_bytes_read == 0 && header[0] == GZIP_HEADER_ID1 {
                self.gzip_id_bytes_read = 1;
            }
            if self.gzip_id_bytes_read == 1 && header.len() > 1 && header[1] == GZIP_HEADER_ID2 {
                self.gzip_id_bytes_read = 2;
            }
        }

        self.inflate(flush);
    }

    fn inflate(&mut self, flush: i32) {
        // SAFETY: buffers were installed for this call.
        self.err = unsafe { z::inflate(self.stream.as_mut(), flush) };

        if self.mode != ZlibMode::InflateRaw
            && self.err == Z_NEED_DICT
            && !self.dictionary.is_empty()
        {
            // SAFETY: the dictionary outlives the call and the stream is live.
            self.err = unsafe {
                z::inflateSetDictionary(
                    self.stream.as_mut(),
                    self.dictionary.as_ptr(),
                    self.dictionary.len() as u32,
                )
            };
            if self.err == Z_OK {
                self.err = unsafe { z::inflate(self.stream.as_mut(), flush) };
            } else if self.err == Z_DATA_ERROR {
                self.err = Z_NEED_DICT;
            }
        }

        // Node concatenates multiple gzip members, and ignores trailing zero
        // padding, unless the caller opted into strict trailing-junk errors.
        while self.stream.avail_in > 0 && self.err == Z_STREAM_END && !self.reject_garbage_after_end
        {
            // SAFETY: `avail_in > 0` guarantees `next_in` points at one byte.
            let next = unsafe { *self.stream.next_in };
            if next == 0 {
                break;
            }
            // SAFETY: the stream is initialized.
            self.err = unsafe { z::inflateReset(self.stream.as_mut()) };
            if self.err != Z_OK {
                return;
            }
            self.err = unsafe { z::inflate(self.stream.as_mut(), flush) };
        }
    }

    fn error_for_message(&self, fallback: &str) -> ZlibError {
        let message = if self.stream.msg.is_null() {
            fallback.to_string()
        } else {
            // SAFETY: `msg` is a NUL-terminated string owned by zlib.
            unsafe { CStr::from_ptr(self.stream.msg) }
                .to_string_lossy()
                .into_owned()
        };
        ZlibError::new(message, self.err)
    }
}

fn zlib_version_ptr() -> *const std::ffi::c_char {
    z::zlibVersion()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deflate_all(mode: ZlibMode, level: i32, data: &[u8]) -> Vec<u8> {
        let mut stream = ZlibStream::new(mode);
        stream
            .init(
                level,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect("init");
        let mut out = vec![0u8; data.len() * 4 + 1024];
        let after = stream.write(Z_FINISH, data, &mut out);
        assert_eq!(after.avail_in, 0, "all input consumed");
        assert!(stream.error_info().is_none(), "no error");
        let written = out.len() - after.avail_out as usize;
        out.truncate(written);
        stream.close();
        out
    }

    /// Decompresses with `Z_FINISH`, retrying until the output buffer is not
    /// the limiting factor. This is the loop `processChunkSync` runs.
    fn inflate_all(mode: ZlibMode, data: &[u8]) -> Vec<u8> {
        let mut stream = ZlibStream::new(mode);
        stream
            .init(
                Z_DEFAULT_COMPRESSION,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect("init");

        let mut plain = Vec::new();
        let mut offset = 0usize;
        loop {
            let mut out = vec![0u8; 1 << 16];
            let after = stream.write(Z_FINISH, &data[offset..], &mut out);
            let produced = out.len() - after.avail_out as usize;
            plain.extend_from_slice(&out[..produced]);
            offset = data.len() - after.avail_in as usize;
            assert!(stream.error_info().is_none(), "no error");
            // Output space left over means the stream had nothing more to give.
            if after.avail_out != 0 {
                break;
            }
        }
        stream.close();
        plain
    }

    #[test]
    fn deflate_round_trips() {
        let data = b"hello world, this is a round trip".repeat(20);
        let compressed = deflate_all(ZlibMode::Deflate, 6, &data);
        assert!(compressed.len() < data.len());
        assert_eq!(inflate_all(ZlibMode::Inflate, &compressed), data);
    }

    #[test]
    fn gzip_has_the_gzip_header_and_round_trips() {
        let data = b"gzip payload".repeat(30);
        let compressed = deflate_all(ZlibMode::Gzip, 6, &data);
        assert_eq!(&compressed[..2], &[GZIP_HEADER_ID1, GZIP_HEADER_ID2]);
        assert_eq!(inflate_all(ZlibMode::Gunzip, &compressed), data);
    }

    #[test]
    fn raw_deflate_round_trips_through_raw_inflate() {
        let data = b"raw payload".repeat(30);
        let compressed = deflate_all(ZlibMode::DeflateRaw, 6, &data);
        // Raw deflate has no wrapper, so it must not carry the zlib header.
        assert_ne!(compressed[0] & 0x0f, 0x08, "no zlib CMF header");
        assert_eq!(inflate_all(ZlibMode::InflateRaw, &compressed), data);
    }

    #[test]
    fn unzip_accepts_both_gzip_and_zlib_wrapped_data() {
        let data = b"autodetect payload".repeat(30);
        let gzipped = deflate_all(ZlibMode::Gzip, 6, &data);
        let deflated = deflate_all(ZlibMode::Deflate, 6, &data);
        assert_eq!(inflate_all(ZlibMode::Unzip, &gzipped), data);
        assert_eq!(inflate_all(ZlibMode::Unzip, &deflated), data);
    }

    #[test]
    fn unzip_detects_a_header_split_across_two_writes() {
        let data = b"split header".repeat(40);
        let gzipped = deflate_all(ZlibMode::Gzip, 6, &data);

        let mut stream = ZlibStream::new(ZlibMode::Unzip);
        stream
            .init(
                Z_DEFAULT_COMPRESSION,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect("init");

        // First write: exactly the 0x1f byte of the magic number.
        let mut out = vec![0u8; 1 << 16];
        let after = stream.write(Z_NO_FLUSH, &gzipped[..1], &mut out);
        assert_eq!(after.avail_in, 0);
        assert!(stream.error_info().is_none());
        out.clear();
        out.resize(1 << 16, 0);

        // Second write: the rest, including the second magic byte.
        let after = stream.write(Z_FINISH, &gzipped[1..], &mut out);
        assert_eq!(after.avail_in, 0);
        assert!(stream.error_info().is_none());
        let written = out.len() - stream.after_write_offsets().avail_out as usize;
        assert_eq!(&out[..written], &data[..]);
        stream.close();
    }

    #[test]
    fn params_change_mid_stream_still_round_trips() {
        let data = b"params change payload".repeat(60);

        let mut stream = ZlibStream::new(ZlibMode::Deflate);
        stream
            .init(
                1,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect("init");

        let mut compressed = Vec::new();
        let half = data.len() / 2;
        let mut out = vec![0u8; 1 << 16];

        let after = stream.write(Z_NO_FLUSH, &data[..half], &mut out);
        let produced = out.len() - after.avail_out as usize;
        compressed.extend_from_slice(&out[..produced]);
        assert!(stream.error_info().is_none());

        // Switching level after a SYNC_FLUSH is the path lib/zlib.js takes in
        // `paramsAfterFlushCallback`.
        let mut flush_out = vec![0u8; 1 << 16];
        let flush_after = stream.write(Z_SYNC_FLUSH, &[], &mut flush_out);
        let flushed = flush_out.len() - flush_after.avail_out as usize;
        compressed.extend_from_slice(&flush_out[..flushed]);
        assert!(stream.error_info().is_none());

        assert!(stream.set_params(9, Z_DEFAULT_STRATEGY).is_none());

        let mut tail_out = vec![0u8; 1 << 16];
        let tail_after = stream.write(Z_FINISH, &data[half..], &mut tail_out);
        assert_eq!(after.avail_in, 0);
        assert!(stream.error_info().is_none());
        let produced = tail_out.len() - tail_after.avail_out as usize;
        compressed.extend_from_slice(&tail_out[..produced]);
        stream.close();

        assert_eq!(inflate_all(ZlibMode::Inflate, &compressed), data);
    }

    #[test]
    fn reset_restarts_the_stream_for_a_second_member() {
        let first = b"first member".repeat(20);
        let second = b"second member".repeat(20);

        let mut stream = ZlibStream::new(ZlibMode::Deflate);
        stream
            .init(
                6,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect("init");

        let mut out = vec![0u8; 1 << 16];
        let after = stream.write(Z_FINISH, &first, &mut out);
        let produced = out.len() - after.avail_out as usize;
        let mut compressed = out[..produced].to_vec();

        assert!(stream.reset().is_none());
        let mut out2 = vec![0u8; 1 << 16];
        let after2 = stream.write(Z_FINISH, &second, &mut out2);
        assert_eq!(after2.avail_in, 0);
        assert!(stream.error_info().is_none());
        let produced = out2.len() - after2.avail_out as usize;
        compressed.extend_from_slice(&out2[..produced]);
        stream.close();

        // Both members decode with a fresh sequential inflate stream.
        assert_eq!(
            inflate_all(ZlibMode::Inflate, &compressed),
            [first, second].concat()
        );
    }

    #[test]
    fn truncated_stream_reports_unexpected_end_of_file() {
        let data = b"truncation payload".repeat(40);
        let compressed = deflate_all(ZlibMode::Deflate, 6, &data);
        let truncated = &compressed[..compressed.len() - 4];

        let mut stream = ZlibStream::new(ZlibMode::Inflate);
        stream
            .init(
                Z_DEFAULT_COMPRESSION,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect("init");
        let mut out = vec![0u8; 1 << 20];
        stream.write(Z_FINISH, truncated, &mut out);
        let error = stream.error_info().expect("truncated input must fail");
        assert_eq!(error.code, "Z_BUF_ERROR");
        assert_eq!(error.message, "unexpected end of file");
        stream.close();
    }

    #[test]
    fn dictionary_compress_and_decompress_round_trip() {
        let dictionary = b"common prefix words that repeat a lot";
        let data = b"common prefix words that repeat a lot in this payload".repeat(10);

        let mut compressor = ZlibStream::new(ZlibMode::Deflate);
        compressor
            .init(
                6,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                dictionary,
                false,
            )
            .expect("init");
        let mut out = vec![0u8; 1 << 16];
        let after = compressor.write(Z_FINISH, &data, &mut out);
        assert!(compressor.error_info().is_none());
        let produced = out.len() - after.avail_out as usize;
        let compressed = out[..produced].to_vec();
        compressor.close();

        let mut decompressor = ZlibStream::new(ZlibMode::Inflate);
        decompressor
            .init(
                Z_DEFAULT_COMPRESSION,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                dictionary,
                false,
            )
            .expect("init");
        let mut plain = vec![0u8; 1 << 16];
        let plain_after = decompressor.write(Z_FINISH, &compressed, &mut plain);
        assert!(decompressor.error_info().is_none());
        let produced = plain.len() - plain_after.avail_out as usize;
        assert_eq!(&plain[..produced], &data[..]);
        decompressor.close();
    }

    #[test]
    fn missing_dictionary_is_reported_as_such() {
        let dictionary = b"a dictionary the decoder will not have";
        let data = b"payload that needs the dictionary".repeat(10);

        let mut compressor = ZlibStream::new(ZlibMode::Deflate);
        compressor
            .init(
                6,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                dictionary,
                false,
            )
            .expect("init");
        let mut out = vec![0u8; 1 << 16];
        let after = compressor.write(Z_FINISH, &data, &mut out);
        let produced = out.len() - after.avail_out as usize;
        let compressed = out[..produced].to_vec();
        compressor.close();

        let mut decompressor = ZlibStream::new(ZlibMode::Inflate);
        decompressor
            .init(
                Z_DEFAULT_COMPRESSION,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect("init");
        let mut plain = vec![0u8; 1 << 16];
        decompressor.write(Z_FINISH, &compressed, &mut plain);
        let error = decompressor.error_info().expect("dictionary required");
        assert_eq!(error.message, "Missing dictionary");
        decompressor.close();
    }

    #[test]
    fn corrupt_input_is_a_data_error() {
        let mut stream = ZlibStream::new(ZlibMode::Inflate);
        stream
            .init(
                Z_DEFAULT_COMPRESSION,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect("init");
        let garbage = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
        let mut out = vec![0u8; 1024];
        stream.write(Z_FINISH, &garbage, &mut out);
        let error = stream.error_info().expect("garbage must fail");
        assert_eq!(error.code, "Z_DATA_ERROR");
        stream.close();
    }

    #[test]
    fn window_bits_are_validated_like_node() {
        let mut stream = ZlibStream::new(ZlibMode::Deflate);
        let error = stream
            .init(6, 7, Z_DEFAULT_MEMLEVEL, Z_DEFAULT_STRATEGY, &[], false)
            .expect_err("7 is below the minimum windowBits");
        assert_eq!(error.message, "invalid windowBits");

        let error = stream
            .init(
                10,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                false,
            )
            .expect_err("10 is above the maximum level");
        assert_eq!(error.message, "invalid compression level");

        let error = stream
            .init(6, Z_DEFAULT_WINDOWBITS, 10, Z_DEFAULT_STRATEGY, &[], false)
            .expect_err("10 is above the maximum memLevel");
        assert_eq!(error.message, "invalid memlevel");
    }

    #[test]
    fn gzip_member_concatenation_matches_node() {
        let first = b"member one".repeat(20);
        let second = b"member two".repeat(20);
        let mut compressed = deflate_all(ZlibMode::Gzip, 6, &first);
        compressed.extend_from_slice(&deflate_all(ZlibMode::Gzip, 6, &second));
        assert_eq!(
            inflate_all(ZlibMode::Gunzip, &compressed),
            [first, second].concat()
        );
    }

    #[test]
    fn gzip_trailing_zero_padding_is_accepted() {
        let data = b"padded".repeat(10);
        let mut compressed = deflate_all(ZlibMode::Gzip, 6, &data);
        compressed.extend_from_slice(&[0u8; 8]);
        assert_eq!(inflate_all(ZlibMode::Gunzip, &compressed), data);
    }

    #[test]
    fn strict_trailing_junk_is_reported_when_requested() {
        let data = b"strict".repeat(10);
        let mut compressed = deflate_all(ZlibMode::Gzip, 6, &data);
        compressed.extend_from_slice(b"junk");

        let mut stream = ZlibStream::new(ZlibMode::Gunzip);
        stream
            .init(
                Z_DEFAULT_COMPRESSION,
                Z_DEFAULT_WINDOWBITS,
                Z_DEFAULT_MEMLEVEL,
                Z_DEFAULT_STRATEGY,
                &[],
                true,
            )
            .expect("init");
        let mut out = vec![0u8; 1 << 16];
        let after = stream.write(Z_FINISH, &compressed, &mut out);
        // `reject_garbage_after_end` leaves the junk unread so `processChunkSync`
        // can raise ERR_TRAILING_JUNK_AFTER_STREAM_END itself.
        assert!(after.avail_in > 0, "trailing junk must stay unconsumed");
        stream.close();
    }
}

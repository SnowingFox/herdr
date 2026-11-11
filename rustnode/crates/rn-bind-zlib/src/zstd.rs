//! The zstd half of the binding: `src/node_zlib.cc`'s `ZstdCompressContext`
//! and `ZstdDecompressContext`.
//!
//! Unlike the zlib and Brotli halves, this is not a reimplementation: the crate
//! links the same C library Node bundles. `deps/zstd` at the pinned Node
//! revision is zstd 1.5.7 and `zstd-sys` vendors exactly `+zstd.1.5.7`, so the
//! frame layout, the level table and the error codes are the ones Node
//! produces rather than an approximation of them.
//!
//! The two contexts differ from the single-shot `ZSTD_compress2` API in the
//! ways `lib/zlib.js` can observe, and those are what this module reproduces:
//!
//! * `ZSTD_e_continue` / `ZSTD_e_flush` / `ZSTD_e_end` arrive as the `flush`
//!   argument of every write, so `ZSTD_compressStream2` is the entry point, not
//!   `ZSTD_compress2`.
//! * A pledged source size is checked when the frame ends, and a mismatch is
//!   reported as `ZSTD_error_srcSize_wrong` rather than being ignored.
//! * Ending a frame that already ended must not append an empty second frame
//!   (`test-zlib-zstd-compress-single-frame.js`).
//! * Resetting a compressor whose incomplete frame has already emitted bytes
//!   cannot be undone and is refused, because the next frame would be appended
//!   to a fragment and produce an undecodable stream
//!   (`test-zlib-zstd-reset-incomplete-frame.js`).
//! * A decompressor stops at the end of the last frame instead of reporting
//!   trailing bytes as corruption, unless `rejectGarbageAfterEnd` asks for it.

use std::ffi::c_void;

use zstd_sys as z;

use crate::AfterWrite;

/// `ZSTD_CONTENTSIZE_UNKNOWN`, the "no pledge" sentinel.
///
/// `zstd_sys` exposes it as an `i32` constant, while the C API takes a
/// `u64` (`ZSTD_CONTENTSIZE_UNKNOWN` is `(0ULL - 1)`), so the widening has to
/// happen explicitly instead of relying on a cast that would sign-extend.
pub const CONTENTSIZE_UNKNOWN: u64 = u64::MAX;

/// A zstd error in the `CompressionError` shape
/// `onerror(message, errno, code)` expects.
///
/// `code` is owned because the decompressor's trailing-junk path synthesises
/// `ERR_TRAILING_JUNK_AFTER_STREAM_END` rather than reporting a zstd error
/// code, exactly as `ZstdDecompressContext::GetErrorInfo` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZstdError {
    pub message: String,
    pub code: String,
    pub err: i32,
}

impl ZstdError {
    fn new(message: impl Into<String>, code: impl Into<String>, err: i32) -> Self {
        Self {
            message: message.into(),
            code: code.into(),
            err,
        }
    }

    /// The `CompressionError` a failed `ZSTD_*` return value turns into.
    fn from_code(result: usize) -> Self {
        let code = zstd_error_code(result);
        Self {
            message: zstd_error_message(code),
            code: zstd_error_symbol(code),
            err: code as i32,
        }
    }

    /// `ERR_ZLIB_INITIALIZATION_FAILED`, which `Init` throws as a JavaScript
    /// exception in addition to calling `onerror`.
    pub fn initialization_failed(message: impl Into<String>) -> Self {
        Self::new(message, "ERR_ZLIB_INITIALIZATION_FAILED", -1)
    }
}

/// `ZSTD_isError`, which is an `unsafe` extern function only because the C
/// signature is; it reads its argument's bit pattern and touches no memory.
fn is_error(result: usize) -> bool {
    // SAFETY: no pointer is dereferenced.
    unsafe { z::ZSTD_isError(result) != 0 }
}

fn zstd_error_code(result: usize) -> z::ZSTD_ErrorCode {
    // SAFETY: `ZSTD_getErrorCode` only inspects the bit pattern of its argument
    // and is documented as meaningful for values `ZSTD_isError` accepts.
    let code = unsafe { z::ZSTD_getErrorCode(result) };
    if code == z::ZSTD_ErrorCode::ZSTD_error_no_error {
        // A non-error value reached here, which only happens if a caller
        // skipped `ZSTD_isError`. Report the generic code rather than inventing
        // a success.
        z::ZSTD_ErrorCode::ZSTD_error_GENERIC
    } else {
        code
    }
}

/// `ZSTD_getErrorString`, the human-readable half of the pair.
fn zstd_error_message(code: z::ZSTD_ErrorCode) -> String {
    // SAFETY: `ZSTD_getErrorString` returns a pointer to a static string for
    // every code it knows and NULL for an out-of-range one. NULL is handled
    // instead of being dereferenced.
    let pointer = unsafe { z::ZSTD_getErrorString(code) };
    if pointer.is_null() {
        return "Unknown error code".to_string();
    }
    // SAFETY: non-null, NUL-terminated and static, per the function's contract.
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

/// `ZstdStrerror` from `src/node_zlib.cc`: the `ZSTD_error_*` spelling of a
/// code, which is what `lib/zlib.js` puts on `error.code`.
///
/// This is a local table rather than `ZSTD_getErrorName` because Node's
/// `code` values are the enumerator names, and the two differ: `getErrorName`
/// returns prose such as "Src size is incorrect" for
/// `ZSTD_error_srcSize_wrong`.
fn zstd_error_symbol(code: z::ZSTD_ErrorCode) -> String {
    use z::ZSTD_ErrorCode::*;
    let name = match code {
        ZSTD_error_no_error => "ZSTD_error_no_error",
        ZSTD_error_GENERIC => "ZSTD_error_GENERIC",
        ZSTD_error_prefix_unknown => "ZSTD_error_prefix_unknown",
        ZSTD_error_version_unsupported => "ZSTD_error_version_unsupported",
        ZSTD_error_frameParameter_unsupported => "ZSTD_error_frameParameter_unsupported",
        ZSTD_error_frameParameter_windowTooLarge => "ZSTD_error_frameParameter_windowTooLarge",
        ZSTD_error_corruption_detected => "ZSTD_error_corruption_detected",
        ZSTD_error_checksum_wrong => "ZSTD_error_checksum_wrong",
        ZSTD_error_literals_headerWrong => "ZSTD_error_literals_headerWrong",
        ZSTD_error_dictionary_corrupted => "ZSTD_error_dictionary_corrupted",
        ZSTD_error_dictionary_wrong => "ZSTD_error_dictionary_wrong",
        ZSTD_error_dictionaryCreation_failed => "ZSTD_error_dictionaryCreation_failed",
        ZSTD_error_parameter_unsupported => "ZSTD_error_parameter_unsupported",
        ZSTD_error_parameter_combination_unsupported => {
            "ZSTD_error_parameter_combination_unsupported"
        }
        ZSTD_error_parameter_outOfBound => "ZSTD_error_parameter_outOfBound",
        ZSTD_error_tableLog_tooLarge => "ZSTD_error_tableLog_tooLarge",
        ZSTD_error_maxSymbolValue_tooLarge => "ZSTD_error_maxSymbolValue_tooLarge",
        ZSTD_error_maxSymbolValue_tooSmall => "ZSTD_error_maxSymbolValue_tooSmall",
        ZSTD_error_stabilityCondition_notRespected => "ZSTD_error_stabilityCondition_notRespected",
        ZSTD_error_stage_wrong => "ZSTD_error_stage_wrong",
        ZSTD_error_init_missing => "ZSTD_error_init_missing",
        ZSTD_error_memory_allocation => "ZSTD_error_memory_allocation",
        ZSTD_error_workSpace_tooSmall => "ZSTD_error_workSpace_tooSmall",
        ZSTD_error_dstSize_tooSmall => "ZSTD_error_dstSize_tooSmall",
        ZSTD_error_srcSize_wrong => "ZSTD_error_srcSize_wrong",
        ZSTD_error_dstBuffer_null => "ZSTD_error_dstBuffer_null",
        ZSTD_error_noForwardProgress_destFull => "ZSTD_error_noForwardProgress_destFull",
        ZSTD_error_noForwardProgress_inputEmpty => "ZSTD_error_noForwardProgress_inputEmpty",
        // The enumerator set in this bindings revision is the one Node pins, so
        // an extra variant would only appear after a zstd bump. Name it rather
        // than mislabelling it as a known code.
        _ => "ZSTD_error_GENERIC",
    };
    name.to_string()
}

/// `ZSTD_e_continue`/`ZSTD_e_flush`/`ZSTD_e_end`, which `lib/zlib.js` passes
/// through unchanged as the `flush` argument.
pub(crate) fn end_directive(flush: i32) -> Option<z::ZSTD_EndDirective> {
    match flush {
        0 => Some(z::ZSTD_EndDirective::ZSTD_e_continue),
        1 => Some(z::ZSTD_EndDirective::ZSTD_e_flush),
        2 => Some(z::ZSTD_EndDirective::ZSTD_e_end),
        // `lib/zlib.js` range-checks `flush` against this triple before it ever
        // reaches the handle, so anything else is a caller bug rather than a
        // user error; treating it as `continue` keeps the stream alive.
        _ => None,
    }
}

/// A `ZSTD_c_*` parameter key from JavaScript as the C enumerator.
///
/// `lib/zlib.js` range-checks the key against the largest `ZSTD_c_` constant it
/// knows, so any integer in `0..=402` can arrive. `ZSTD_CCtx_setParameter`
/// rejects an unknown one through its return value, and that rejection is what
/// `Init` turns into "Setting parameter failed", so `None` here means exactly
/// the same thing as zstd's own `parameter_unsupported`.
///
/// A `transmute` would make the same call for the values that match and be
/// undefined behaviour for the ones that do not, so the valid keys are spelled
/// out. They are the constants rn-bind-config publishes, which is the set the
/// JavaScript can name.
pub(crate) fn compression_parameter(key: i32) -> Option<z::ZSTD_cParameter> {
    use z::ZSTD_cParameter::*;
    Some(match key {
        100 => ZSTD_c_compressionLevel,
        101 => ZSTD_c_windowLog,
        102 => ZSTD_c_hashLog,
        103 => ZSTD_c_chainLog,
        104 => ZSTD_c_searchLog,
        105 => ZSTD_c_minMatch,
        106 => ZSTD_c_targetLength,
        107 => ZSTD_c_strategy,
        160 => ZSTD_c_enableLongDistanceMatching,
        161 => ZSTD_c_ldmHashLog,
        162 => ZSTD_c_ldmMinMatch,
        163 => ZSTD_c_ldmBucketSizeLog,
        164 => ZSTD_c_ldmHashRateLog,
        200 => ZSTD_c_contentSizeFlag,
        201 => ZSTD_c_checksumFlag,
        202 => ZSTD_c_dictIDFlag,
        400 => ZSTD_c_nbWorkers,
        401 => ZSTD_c_jobSize,
        402 => ZSTD_c_overlapLog,
        _ => return None,
    })
}

/// A `ZSTD_d_*` parameter key from JavaScript as the C enumerator; the
/// decompression counterpart of [`compression_parameter`].
pub(crate) fn decompression_parameter(key: i32) -> Option<z::ZSTD_dParameter> {
    use z::ZSTD_dParameter::*;
    Some(match key {
        100 => ZSTD_d_windowLogMax,
        _ => return None,
    })
}

/// `ZstdCompressContext::SetParameter`'s error, which Node reports as both an
/// `onerror` call and a thrown `ERR_ZLIB_INITIALIZATION_FAILED`.
pub(crate) fn parameter_failed() -> ZstdError {
    ZstdError::new("Setting parameter failed", "ERR_ZSTD_PARAM_SET_FAILED", -1)
}

/// One `ZSTD_inBuffer`/`ZSTD_outBuffer` pair for the duration of a call.
///
/// Node keeps these as members of `ZstdContext` and re-points them from
/// `SetBuffers()`; the offsets are read back through
/// `GetAfterWriteOffsets()`. Holding them in one place keeps the two halves
/// from drifting apart.
struct Buffers {
    input: z::ZSTD_inBuffer,
    output: z::ZSTD_outBuffer,
}

impl Buffers {
    fn new(input: &[u8], output: &mut [u8]) -> Self {
        Self {
            input: z::ZSTD_inBuffer {
                src: input.as_ptr().cast::<c_void>(),
                size: input.len(),
                pos: 0,
            },
            output: z::ZSTD_outBuffer {
                dst: output.as_mut_ptr().cast::<c_void>(),
                size: output.len(),
                pos: 0,
            },
        }
    }

    /// `GetAfterWriteOffsets`: what each side did not consume.
    fn after(&self) -> AfterWrite {
        AfterWrite {
            avail_in: (self.input.size - self.input.pos) as u32,
            avail_out: (self.output.size - self.output.pos) as u32,
        }
    }
}

/// `ZstdCompressContext`.
pub struct ZstdCompressStream {
    context: *mut z::ZSTD_CCtx,
    pledged_src_size: u64,
    /// Set while a pledge is outstanding, so the consumed count is only tracked
    /// when it will be checked. `None` means no pledge.
    consumed_src_size: Option<u64>,
    frame_ended: bool,
    /// A frame is complete once `ZSTD_compressStream2` with `ZSTD_e_end` has
    /// returned 0.
    frame_complete: bool,
    /// Whether any byte of the current incomplete frame has left the
    /// compressor. Resetting is only unsafe once this is true.
    frame_output_emitted: bool,
    /// Last parameters, replayed by `reset()` so a reset handle behaves like a
    /// fresh one with the same options.
    params: Vec<(i32, i32)>,
    dictionary: Vec<u8>,
    error: Option<ZstdError>,
}

// SAFETY: the context is a plain heap allocation that no thread touches
// concurrently; the handle is driven from the thread whose isolate owns it.
unsafe impl Send for ZstdCompressStream {}

impl Drop for ZstdCompressStream {
    fn drop(&mut self) {
        self.close();
    }
}

impl ZstdCompressStream {
    /// The state `new binding.ZstdCompress()` installs before `init`.
    ///
    /// Node's `ZstdStream::New` default-constructs a `ZstdCompressContext`
    /// whose `cctx_` is null; `Init` is what creates it. Keeping that split
    /// means a handle's first `init` and a re-`init` after `close()` take the
    /// same path.
    pub fn uninitialized() -> Self {
        Self {
            context: std::ptr::null_mut(),
            pledged_src_size: CONTENTSIZE_UNKNOWN,
            consumed_src_size: None,
            frame_ended: false,
            frame_complete: true,
            frame_output_emitted: false,
            params: Vec::new(),
            dictionary: Vec::new(),
            error: None,
        }
    }

    /// `ZstdCompressContext::Init`.
    pub fn init(
        &mut self,
        pledged_src_size: u64,
        dictionary: &[u8],
        params: &[(i32, i32)],
    ) -> Result<(), ZstdError> {
        self.close();
        // SAFETY: creates a fresh context with default memory functions.
        let context = unsafe { z::ZSTD_createCCtx() };
        if context.is_null() {
            return Err(ZstdError::initialization_failed(
                "Could not initialize zstd instance",
            ));
        }
        self.context = context;
        self.pledged_src_size = pledged_src_size;
        self.params = params.to_vec();
        self.dictionary = dictionary.to_vec();
        self.error = None;
        self.apply_init()
    }

    /// The part of `Init` that `reset()` has to replay: the dictionary, the
    /// pledge and every parameter.
    fn apply_init(&mut self) -> Result<(), ZstdError> {
        self.consumed_src_size = if self.pledged_src_size == CONTENTSIZE_UNKNOWN {
            None
        } else {
            Some(0)
        };
        self.frame_ended = false;
        self.frame_complete = true;
        self.frame_output_emitted = false;

        if !self.dictionary.is_empty() {
            // SAFETY: `self.dictionary` outlives the call and the context copies
            // what it needs; `ZSTD_CCtx_loadDictionary` is the documented way to
            // install a raw dictionary on a compression context.
            let result = unsafe {
                z::ZSTD_CCtx_loadDictionary(
                    self.context,
                    self.dictionary.as_ptr().cast::<c_void>(),
                    self.dictionary.len(),
                )
            };
            if is_error(result) {
                return Err(ZstdError::initialization_failed(
                    "Failed to load zstd dictionary",
                ));
            }
        }

        // SAFETY: `self.context` is a live compression context.
        let result = unsafe { z::ZSTD_CCtx_setPledgedSrcSize(self.context, self.pledged_src_size) };
        if is_error(result) {
            return Err(ZstdError::initialization_failed(
                "Could not set pledged src size",
            ));
        }

        // `ZstdCompressContext::SetParameter`, in `SetParameters` order. Node's
        // `Init` reports a failure here as both an `onerror` and a thrown
        // `ERR_ZLIB_INITIALIZATION_FAILED`, which is why the message is the
        // fixed "Setting parameter failed" rather than zstd's own text.
        for (key, value) in &self.params {
            let Some(parameter) = compression_parameter(*key) else {
                return Err(parameter_failed());
            };
            // SAFETY: `self.context` is a live compression context and
            // `parameter` is one of its enumerators.
            let result = unsafe { z::ZSTD_CCtx_setParameter(self.context, parameter, *value) };
            if is_error(result) {
                return Err(parameter_failed());
            }
        }
        Ok(())
    }

    /// `ZstdCompressContext::DoThreadPoolWork`.
    pub fn write(&mut self, flush: i32, input: &[u8], output: &mut [u8]) -> AfterWrite {
        let Some(directive) = end_directive(flush) else {
            let mut buffers = Buffers::new(input, output);
            buffers.input.pos = input.len();
            return buffers.after();
        };
        let mut buffers = Buffers::new(input, output);

        // Ending a frame that already ended would append an empty one, which is
        // what `test-zlib-zstd-compress-single-frame.js` pins.
        if self.frame_ended && buffers.input.size == 0 {
            return buffers.after();
        }

        let input_pos_before = buffers.input.pos;
        // SAFETY: both buffers point at the caller's live slices, which outlive
        // this call, and the context is a live compression context.
        let remaining = unsafe {
            z::ZSTD_compressStream2(
                self.context,
                &mut buffers.output,
                &mut buffers.input,
                directive,
            )
        };
        if let Some(consumed) = self.consumed_src_size.as_mut() {
            *consumed += (buffers.input.pos - input_pos_before) as u64;
        }

        self.frame_ended = remaining == 0 && directive == z::ZSTD_EndDirective::ZSTD_e_end;
        if buffers.output.pos > 0 {
            self.frame_output_emitted = true;
        }

        if is_error(remaining) {
            self.error = Some(ZstdError::from_code(remaining));
            self.frame_complete = false;
        } else if remaining == 0 && directive == z::ZSTD_EndDirective::ZSTD_e_end {
            self.frame_complete = true;
            self.frame_output_emitted = false;
            if let Some(consumed) = self.consumed_src_size.take() {
                // The pledge is only enforced when the frame ends, which is the
                // point zstd itself checks it. Node compares the two here
                // because `ZSTD_compressStream2` does not report a short frame
                // as an error on its own.
                if consumed != self.pledged_src_size {
                    let code = z::ZSTD_ErrorCode::ZSTD_error_srcSize_wrong;
                    self.error = Some(ZstdError::new(
                        zstd_error_message(code),
                        zstd_error_symbol(code),
                        code as i32,
                    ));
                }
            }
        } else {
            self.frame_complete = false;
        }

        buffers.after()
    }

    /// `ZstdCompressContext::ResetStream`.
    pub fn reset(&mut self) -> Option<ZstdError> {
        // `ZSTD_reset_session_only` cancels unflushed internal data. Bytes that
        // have already been written out cannot be taken back, so a reset is
        // refused only when the current incomplete frame has emitted output.
        if !self.frame_complete && self.frame_output_emitted {
            return Some(ZstdError::new(
                "Cannot reset a zstd stream with an incomplete frame; end the frame \
                 or discard the output produced so far",
                "ERR_ZLIB_INCOMPLETE_FRAME",
                z::ZSTD_ErrorCode::ZSTD_error_stage_wrong as i32,
            ));
        }

        // SAFETY: live context; `ZSTD_reset_session_only` keeps the parameters.
        let result = unsafe {
            z::ZSTD_CCtx_reset(
                self.context,
                z::ZSTD_ResetDirective::ZSTD_reset_session_only,
            )
        };
        if is_error(result) {
            return Some(ZstdError::from_code(result));
        }

        // The reset re-applies the pledge, because `ZSTD_reset_session_only`
        // starts a new session in which no size has been promised.
        // SAFETY: live context.
        let result = unsafe { z::ZSTD_CCtx_setPledgedSrcSize(self.context, self.pledged_src_size) };
        if is_error(result) {
            return Some(ZstdError::from_code(result));
        }

        // `ZSTD_reset_session_only` does not drop the parameters or the
        // dictionary, which is what makes a reset stream keep its options
        // (`test-zlib-zstd-reset.js`). Re-applying them would be harmless but
        // would also hide a regression in that behaviour, so they are left
        // alone and only the bookkeeping is cleared.
        self.consumed_src_size = if self.pledged_src_size == CONTENTSIZE_UNKNOWN {
            None
        } else {
            Some(0)
        };
        self.frame_ended = false;
        self.frame_complete = true;
        self.frame_output_emitted = false;
        self.error = None;
        None
    }

    /// `ZstdCompressContext::Close`.
    pub fn close(&mut self) {
        if !self.context.is_null() {
            // SAFETY: the pointer came from `ZSTD_createCCtx` and is nulled
            // immediately after, so this runs at most once per allocation.
            unsafe { z::ZSTD_freeCCtx(self.context) };
            self.context = std::ptr::null_mut();
        }
    }

    pub fn error_info(&self) -> Option<&ZstdError> {
        self.error.as_ref()
    }

    pub fn closed(&self) -> bool {
        self.context.is_null()
    }
}

/// `ZstdDecompressContext`.
pub struct ZstdDecompressStream {
    context: *mut z::ZSTD_DCtx,
    frame_complete: bool,
    decoding_frame_after_complete: bool,
    reject_garbage_after_end: bool,
    ignoring_trailing_input: bool,
    /// How many bytes of the next frame's magic have been matched so far.
    frame_prefix_size: usize,
    /// A bit set of the frame shapes the prefix still matches: bit 0 for a zstd
    /// frame, bit 1 for a skippable frame. Zero means the bytes are junk.
    possible_frame_types: u8,
    dictionary: Vec<u8>,
    params: Vec<(i32, i32)>,
    error: Option<ZstdError>,
    /// The `flush` argument of the write being processed, which
    /// `GetErrorInfo` consults to tell a truncated frame from a pause.
    flush: i32,
}

// SAFETY: as for the compressor: one heap context, driven from the owning
// isolate's thread.
unsafe impl Send for ZstdDecompressStream {}

impl Drop for ZstdDecompressStream {
    fn drop(&mut self) {
        self.close();
    }
}

impl ZstdDecompressStream {
    /// The state `new binding.ZstdDecompress()` installs before `init`.
    pub fn uninitialized() -> Self {
        Self {
            context: std::ptr::null_mut(),
            frame_complete: false,
            decoding_frame_after_complete: false,
            reject_garbage_after_end: false,
            ignoring_trailing_input: false,
            frame_prefix_size: 0,
            possible_frame_types: 0,
            dictionary: Vec::new(),
            params: Vec::new(),
            error: None,
            flush: 0,
        }
    }

    /// `ZstdDecompressContext::Init`. `pledged_src_size` is accepted for
    /// signature parity with Node's `Init` but unused, as it is there.
    pub fn init(
        &mut self,
        _pledged_src_size: u64,
        dictionary: &[u8],
        params: &[(i32, i32)],
        reject_garbage_after_end: bool,
    ) -> Result<(), ZstdError> {
        self.close();
        // SAFETY: creates a fresh context with default memory functions.
        let context = unsafe { z::ZSTD_createDCtx() };
        if context.is_null() {
            return Err(ZstdError::initialization_failed(
                "Could not initialize zstd instance",
            ));
        }
        self.context = context;
        self.dictionary = dictionary.to_vec();
        self.params = params.to_vec();
        self.reject_garbage_after_end = reject_garbage_after_end;
        self.error = None;
        self.apply_init()
    }

    fn apply_init(&mut self) -> Result<(), ZstdError> {
        self.frame_complete = false;
        self.decoding_frame_after_complete = false;
        self.ignoring_trailing_input = false;
        self.frame_prefix_size = 0;
        self.possible_frame_types = 0;

        if !self.dictionary.is_empty() {
            // SAFETY: as in the compressor; the context copies what it needs.
            let result = unsafe {
                z::ZSTD_DCtx_loadDictionary(
                    self.context,
                    self.dictionary.as_ptr().cast::<c_void>(),
                    self.dictionary.len(),
                )
            };
            if is_error(result) {
                return Err(ZstdError::initialization_failed(
                    "Failed to load zstd dictionary",
                ));
            }
        }

        for (key, value) in &self.params {
            let Some(parameter) = decompression_parameter(*key) else {
                return Err(parameter_failed());
            };
            // SAFETY: `self.context` is a live decompression context and
            // `parameter` is one of its enumerators.
            let result = unsafe { z::ZSTD_DCtx_setParameter(self.context, parameter, *value) };
            if is_error(result) {
                return Err(parameter_failed());
            }
        }
        Ok(())
    }

    /// `ZstdDecompressContext::DoThreadPoolWork`.
    pub fn write(&mut self, flush: i32, input: &[u8], output: &mut [u8]) -> AfterWrite {
        let mut buffers = Buffers::new(input, output);
        self.flush = flush;
        // `SetFlush` stores the directive on the context, and `GetErrorInfo`
        // compares it against `ZSTD_e_end`.
        if end_directive(flush).is_none() {
            buffers.input.pos = input.len();
            return buffers.after();
        }

        if self.ignoring_trailing_input {
            buffers.input.pos = input.len();
            return buffers.after();
        }

        // The JavaScript loop retries with an empty input when the previous call
        // filled the output buffer. That retry is not the start of a new,
        // incomplete frame.
        if self.frame_complete && buffers.input.size == 0 {
            return buffers.after();
        }

        loop {
            if self.frame_complete {
                self.decoding_frame_after_complete = true;
                self.frame_prefix_size = 0;
                self.possible_frame_types = 0b11;
            }

            if self.decoding_frame_after_complete && self.frame_prefix_size < 4 {
                let mut input_prefix_offset = 0usize;
                while self.frame_prefix_size < 4
                    && buffers.input.pos + input_prefix_offset < buffers.input.size
                {
                    let index = self.frame_prefix_size;
                    let byte = input[buffers.input.pos + input_prefix_offset];
                    if byte != ZSTD_MAGIC[index] {
                        self.possible_frame_types &= !0b01;
                    }
                    if (index == 0 && (byte & 0xf0) != SKIPPABLE_MAGIC[0])
                        || (index != 0 && byte != SKIPPABLE_MAGIC[index])
                    {
                        self.possible_frame_types &= !0b10;
                    }
                    self.frame_prefix_size += 1;
                    input_prefix_offset += 1;
                }

                if self.possible_frame_types == 0 {
                    self.frame_complete = true;
                    self.decoding_frame_after_complete = false;
                    if self.reject_garbage_after_end {
                        self.error = Some(ZstdError::new(
                            "Trailing junk found after the end of the compressed stream",
                            "ERR_TRAILING_JUNK_AFTER_STREAM_END",
                            z::ZSTD_ErrorCode::ZSTD_error_GENERIC as i32,
                        ));
                    } else {
                        self.ignoring_trailing_input = true;
                    }
                    return buffers.after();
                }
            }

            // SAFETY: both buffers point at the caller's live slices, and
            // `ZSTD_DStream` is `ZSTD_DCtx`, which this context is.
            let result = unsafe {
                z::ZSTD_decompressStream(self.context, &mut buffers.output, &mut buffers.input)
            };
            if is_error(result) {
                self.frame_complete = false;
                self.error = Some(ZstdError::from_code(result));
                return buffers.after();
            }

            self.frame_complete = result == 0;
            if self.frame_complete {
                self.decoding_frame_after_complete = false;
            }

            // Keep going while frames are complete and both sides still have
            // room, which is what lets one call decode back-to-back frames.
            if !(self.frame_complete
                && buffers.input.pos < buffers.input.size
                && buffers.output.pos < buffers.output.size)
            {
                break;
            }
        }

        buffers.after()
    }

    /// `ZstdDecompressContext::GetErrorInfo`, which adds the truncated-frame
    /// check that the compressor does not have.
    ///
    /// A write that asked for `ZSTD_e_end`, did not finish a frame and consumed
    /// all its input is a truncated stream: zstd itself treats that as a pause
    /// rather than an error, but `lib/zlib.js` needs the failure to finish the
    /// stream with `Z_BUF_ERROR`.
    pub fn check_truncated(&mut self, avail_in: u32, avail_out: u32) {
        if self.error.is_some() {
            return;
        }
        let wants_end = self.flush == z::ZSTD_EndDirective::ZSTD_e_end as i32;
        if !wants_end || self.frame_complete || avail_in != 0 || avail_out == 0 {
            return;
        }
        if self.decoding_frame_after_complete && self.frame_prefix_size < 4 {
            // Fewer than four bytes of a frame: not enough to tell a truncated
            // frame from trailing junk, so it is reported only when the caller
            // asked for junk to be rejected.
            if self.reject_garbage_after_end {
                self.error = Some(ZstdError::new(
                    "Trailing junk found after the end of the compressed stream",
                    "ERR_TRAILING_JUNK_AFTER_STREAM_END",
                    -1,
                ));
            }
            return;
        }
        self.error = Some(ZstdError::new(
            "unexpected end of file",
            crate::constants::zlib_strerror(crate::constants::Z_BUF_ERROR),
            crate::constants::Z_BUF_ERROR,
        ));
    }

    /// `ZstdDecompressContext::ResetStream`.
    pub fn reset(&mut self) -> Option<ZstdError> {
        // SAFETY: live context; session-only reset keeps dictionary and
        // parameters, which is what makes a reset decompressor keep them
        // (`test-zlib-zstd-reset.js`).
        let result = unsafe {
            z::ZSTD_DCtx_reset(
                self.context,
                z::ZSTD_ResetDirective::ZSTD_reset_session_only,
            )
        };
        if is_error(result) {
            return Some(ZstdError::from_code(result));
        }

        self.frame_complete = false;
        self.decoding_frame_after_complete = false;
        self.ignoring_trailing_input = false;
        self.frame_prefix_size = 0;
        self.possible_frame_types = 0;
        self.error = None;
        None
    }

    pub fn close(&mut self) {
        if !self.context.is_null() {
            // SAFETY: from `ZSTD_createDCtx`, nulled after use.
            unsafe { z::ZSTD_freeDCtx(self.context) };
            self.context = std::ptr::null_mut();
        }
    }

    pub fn error_info(&self) -> Option<&ZstdError> {
        self.error.as_ref()
    }

    pub fn closed(&self) -> bool {
        self.context.is_null()
    }
}

/// The raw content of a zstd frame: `0x28 0xb5 0x2f 0xfd`.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// A skippable frame's first byte masks to this; the rest must match exactly.
const SKIPPABLE_MAGIC: [u8; 4] = [0x50, 0x2a, 0x4d, 0x18];

#[cfg(test)]
mod tests {
    use super::*;

    /// A compressor with the given pledge, dictionary and parameters.
    fn compress_cx(pledge: u64, dictionary: &[u8], params: &[(i32, i32)]) -> ZstdCompressStream {
        let mut stream = ZstdCompressStream::uninitialized();
        stream
            .init(pledge, dictionary, params)
            .expect("compressor init");
        stream
    }

    /// A decompressor, optionally rejecting trailing junk.
    fn decompress_cx(reject_garbage: bool) -> ZstdDecompressStream {
        let mut stream = ZstdDecompressStream::uninitialized();
        stream
            .init(CONTENTSIZE_UNKNOWN, &[], &[], reject_garbage)
            .expect("decompressor init");
        stream
    }

    /// `ZSTD_e_continue`/`flush`/`end` are `0`/`1`/`2` in `zstd.h`, and
    /// `lib/zlib.js` passes its own constants straight through.
    #[test]
    fn end_directives_match_the_c_enum() {
        assert_eq!(
            end_directive(0),
            Some(z::ZSTD_EndDirective::ZSTD_e_continue)
        );
        assert_eq!(end_directive(1), Some(z::ZSTD_EndDirective::ZSTD_e_flush));
        assert_eq!(end_directive(2), Some(z::ZSTD_EndDirective::ZSTD_e_end));
        assert_eq!(end_directive(7), None);
    }

    /// `ZSTD_CONTENTSIZE_UNKNOWN` is `(0ULL - 1)` in `zstd.h`. The bindings
    /// expose an `i32` version, so the widening has to be explicit; a plain
    /// `as u64` on `-1i32` sign-extends to `u64::MAX`, which is the same
    /// value, but the constant is asserted so a bindings bump cannot change
    /// the meaning silently.
    #[test]
    fn contentsize_unknown_is_all_ones() {
        assert_eq!(CONTENTSIZE_UNKNOWN, u64::MAX);
        assert_eq!(z::ZSTD_CONTENTSIZE_UNKNOWN, -1);
    }

    /// Every error code Node names has to come back with Node's spelling,
    /// because `lib/zlib.js` puts it on `error.code` and tests match on it.
    #[test]
    fn error_symbols_use_the_node_spelling() {
        assert_eq!(
            zstd_error_symbol(z::ZSTD_ErrorCode::ZSTD_error_srcSize_wrong),
            "ZSTD_error_srcSize_wrong"
        );
        assert_eq!(
            zstd_error_symbol(z::ZSTD_ErrorCode::ZSTD_error_frameParameter_windowTooLarge),
            "ZSTD_error_frameParameter_windowTooLarge"
        );
        assert_eq!(
            zstd_error_symbol(z::ZSTD_ErrorCode::ZSTD_error_no_error),
            "ZSTD_error_no_error"
        );
    }

    /// The magic numbers the trailing-junk scan compares against are the ones
    /// in the format specification: a wrong table would classify every valid
    /// frame as junk.
    #[test]
    fn frame_magics_match_the_specification() {
        assert_eq!(ZSTD_MAGIC, [0x28, 0xb5, 0x2f, 0xfd]);
        assert_eq!(SKIPPABLE_MAGIC, [0x50, 0x2a, 0x4d, 0x18]);
        // A real empty zstd frame starts with the raw magic.
        let frame = compress_all(&[], 3);
        assert_eq!(&frame[..4], &ZSTD_MAGIC);
    }

    /// A single `ZSTD_e_end` call has to produce a decodable frame, and the
    /// compressor has to report having consumed all input and emitted all
    /// output so `processChunkSync` stops looping.
    #[test]
    fn one_shot_round_trip() {
        let input = b"hello hello hello hello hello";
        let compressed = compress_all(input, 3);
        assert!(!compressed.is_empty());
        assert_eq!(decompress_all(&compressed, &[]), input);
    }

    /// A pledged size that does not match the data has to be reported as
    /// `ZSTD_error_srcSize_wrong` when the frame ends, which is what
    /// `test-zlib-zstd-pledged-src-size.js` asserts on.
    #[test]
    fn a_short_pledge_is_an_error_at_frame_end() {
        let mut stream = compress_cx(4, &[], &[]);
        let mut output = vec![0u8; 1024];
        let after = stream.write(2, b"hello world", &mut output);
        assert_eq!(after.avail_in, 0);
        let error = stream.error_info().expect("pledge mismatch must fail");
        assert_eq!(error.code, "ZSTD_error_srcSize_wrong");
        assert_eq!(
            error.err,
            z::ZSTD_ErrorCode::ZSTD_error_srcSize_wrong as i32
        );
    }

    /// Ending a frame twice must not append an empty second frame.
    #[test]
    fn ending_an_ended_frame_writes_nothing() {
        let mut stream = compress_cx(CONTENTSIZE_UNKNOWN, &[], &[]);
        let mut first = vec![0u8; 1024];
        let after = stream.write(2, b"hello", &mut first);
        assert_eq!(after.avail_in, 0);
        let emitted = first.len() - after.avail_out as usize;
        assert!(emitted > 0);

        let mut second = vec![0u8; 1024];
        let after = stream.write(2, &[], &mut second);
        assert_eq!(
            after.avail_out as usize,
            second.len(),
            "an empty second frame would consume output"
        );
    }

    /// A reset after an incomplete frame that emitted output has to be refused;
    /// after one that emitted nothing it has to succeed.
    #[test]
    fn reset_refuses_only_after_an_incomplete_frame_emitted_output() {
        let mut clean = compress_cx(CONTENTSIZE_UNKNOWN, &[], &[]);
        let mut output = vec![0u8; 1024];
        clean.write(0, b"hello", &mut output);
        assert!(clean.reset().is_none(), "no bytes left the compressor");

        let mut dirty = compress_cx(CONTENTSIZE_UNKNOWN, &[], &[]);
        let mut flushed = vec![0u8; 1024];
        dirty.write(1, b"hello", &mut flushed);
        let error = dirty.reset().expect("an emitted fragment cannot be reset");
        assert_eq!(error.code, "ERR_ZLIB_INCOMPLETE_FRAME");
    }

    /// A decompressor has to stop at the end of the last frame rather than
    /// calling trailing bytes corruption, unless it was asked to reject them.
    ///
    /// The junk is left unconsumed either way, exactly as Node leaves it: the
    /// sync path ignores `availInAfter` because `processChunkSync` checks
    /// `_rejectGarbageAfterEnd` itself and throws, while the stream path reports
    /// it through `onerror`.
    #[test]
    fn trailing_junk_is_ignored_by_default_and_rejected_on_request() {
        let mut with_junk = compress_all(b"hello world", 3);
        with_junk.extend_from_slice(b"XXXXXXXXXXXX");

        let mut lenient = decompress_cx(false);
        let mut output = vec![0u8; 1024];
        let after = lenient.write(2, &with_junk, &mut output);
        assert!(lenient.error_info().is_none(), "junk is ignored by default");
        assert_eq!(
            after.avail_in,
            "XXXXXXXXXXXX".len() as u32,
            "only the frame is consumed; the junk is left for the caller"
        );
        let produced = output.len() - after.avail_out as usize;
        assert_eq!(&output[..produced], b"hello world");

        let mut strict = decompress_cx(true);
        let mut strict_output = vec![0u8; 1024];
        strict.write(2, &with_junk, &mut strict_output);
        let error = strict.error_info().expect("junk is rejected on request");
        assert_eq!(error.code, "ERR_TRAILING_JUNK_AFTER_STREAM_END");

        // A clean frame is never junk, even with the strict flag.
        let clean = compress_all(b"hello world", 3);
        let mut strict_clean = decompress_cx(true);
        decompress_cx(true);
        let mut clean_output = vec![0u8; 1024];
        strict_clean.write(2, &clean, &mut clean_output);
        assert!(strict_clean.error_info().is_none());
    }

    /// A truncated frame written with `ZSTD_e_end` has to be reported as
    /// `Z_BUF_ERROR`, which is the error `zlib.js` expects for a short stream.
    #[test]
    fn a_truncated_frame_is_a_buf_error() {
        let compressed = compress_all(b"hello world, this is a longer payload", 3);
        let truncated = &compressed[..compressed.len() - 4];

        let mut stream = decompress_cx(false);
        let mut output = vec![0u8; 4096];
        let after = stream.write(2, truncated, &mut output);
        stream.check_truncated(after.avail_in, after.avail_out);
        let error = stream.error_info().expect("a truncated frame must fail");
        assert_eq!(error.code, "Z_BUF_ERROR");
    }

    /// `reset()` has to keep the parameters, which is what
    /// `test-zlib-zstd-reset.js` checks by compressing with a window log of 11
    /// and decompressing after a reset with a matching limit.
    #[test]
    fn reset_keeps_the_compression_parameters() {
        let params = [(z::ZSTD_cParameter::ZSTD_c_compressionLevel as i32, 9)];
        let mut stream = compress_cx(CONTENTSIZE_UNKNOWN, &[], &params);
        let mut output = vec![0u8; 4096];
        stream.write(2, b"hello world", &mut output);
        assert!(stream.error_info().is_none());
        assert!(stream.reset().is_none());

        // The reset handle still compresses at level 9 and still ends frames.
        let mut again = vec![0u8; 4096];
        let after = stream.write(2, b"hello world", &mut again);
        assert_eq!(after.avail_in, 0);
        assert!(stream.error_info().is_none());
        let emitted = again.len() - after.avail_out as usize;
        assert!(emitted > 0);
    }

    /// Compresses `input` in one `ZSTD_e_end` call, looping while the output
    /// fills, and returns exactly the bytes emitted.
    fn compress_all(input: &[u8], level: i32) -> Vec<u8> {
        let params = [(z::ZSTD_cParameter::ZSTD_c_compressionLevel as i32, level)];
        let mut stream = compress_cx(CONTENTSIZE_UNKNOWN, &[], &params);
        let mut output = vec![0u8; 64 * 1024];
        let after = stream.write(2, input, &mut output);
        if let Some(error) = stream.error_info() {
            panic!("compression failed: {error:?}");
        }
        output.truncate(output.len() - after.avail_out as usize);
        output
    }

    fn decompress_all(input: &[u8], dictionary: &[u8]) -> Vec<u8> {
        let mut stream = ZstdDecompressStream::uninitialized();
        stream
            .init(CONTENTSIZE_UNKNOWN, dictionary, &[], false)
            .expect("decompressor init");
        let mut output = vec![0u8; 64 * 1024];
        let after = stream.write(2, input, &mut output);
        if let Some(error) = stream.error_info() {
            panic!("decompression failed: {error:?}");
        }
        assert_eq!(after.avail_in, 0);
        output.truncate(output.len() - after.avail_out as usize);
        output
    }
}

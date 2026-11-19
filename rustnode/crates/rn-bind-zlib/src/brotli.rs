//! The Brotli half of the binding: `BrotliEncoder`/`BrotliDecoder` handles.
//!
//! `src/node_zlib.cc` runs C Brotli through `BrotliEncoderCompressStream` /
//! `BrotliDecoderDecompressStream`. The `brotli` crate exposes the same
//! streaming state machine as `BrotliEncoderStateStruct::compress_stream` and
//! `BrotliDecompressStream`, so the flush semantics line up one-to-one:
//! `BROTLI_OPERATION_PROCESS`/`FLUSH`/`FINISH` are the `flush` argument the JS
//! passes through unchanged.

use brotli::enc::backward_references::BrotliEncoderParams;
use brotli::enc::encode::{
    BrotliEncoderOperation, BrotliEncoderParameter, BrotliEncoderStateStruct,
};
use brotli::enc::interface::{PredictionModeContextMap, StaticCommand};
use brotli::enc::StandardAlloc;
use brotli::{InputPair, InputReferenceMut};
use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState};

use crate::constants::*;
use crate::AfterWrite;

type Encoder = BrotliEncoderStateStruct<StandardAlloc>;

/// One Brotli stream, either an encoder or a decoder.
pub enum BrotliStream {
    /// `BrotliEncoderContext`.
    Encode(Box<BrotliEncoder>),
    /// `BrotliDecoderContext`.
    Decode(Box<BrotliDecoder>),
}

impl BrotliStream {
    /// `true` for the encoder direction.
    ///
    /// Node instantiates one `BrotliCompressionStream` template per direction, so
    /// the two are distinct classes with distinct `SelfSize()` values; the
    /// snapshot needs to know which one a handle is.
    pub fn is_encoder(&self) -> bool {
        matches!(self, Self::Encode(_))
    }

    /// The encoder for `BROTLI_ENCODE`.
    pub fn encoder(dictionary: &[u8]) -> Self {
        Self::Encode(Box::new(BrotliEncoder::new(dictionary)))
    }

    /// The decoder for `BROTLI_DECODE`.
    pub fn decoder(dictionary: &[u8]) -> Self {
        Self::Decode(Box::new(BrotliDecoder::new(dictionary)))
    }

    /// Runs one step and reports what was left over.
    pub fn write(&mut self, flush: i32, input: &[u8], output: &mut [u8]) -> AfterWrite {
        match self {
            Self::Encode(encoder) => encoder.write(flush, input, output),
            Self::Decode(decoder) => decoder.write(flush, input, output),
        }
    }

    /// The `CompressionError` shape `onerror(message, errno, code)` expects.
    pub fn error_info(&self) -> Option<BrotliError> {
        match self {
            Self::Encode(encoder) => encoder.error_info(),
            Self::Decode(decoder) => decoder.error_info(),
        }
    }

    /// Restarts the stream. Encoder parameters and the dictionary are replayed.
    pub fn reset(&mut self) -> Option<BrotliError> {
        match self {
            Self::Encode(encoder) => encoder.reset(),
            Self::Decode(decoder) => decoder.reset(),
        }
    }

    /// Releases the stream state. Idempotent.
    pub fn close(&mut self) {
        match self {
            Self::Encode(encoder) => encoder.closed = true,
            Self::Decode(decoder) => decoder.closed = true,
        }
    }
}

/// A Brotli error in `CompressionError` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrotliError {
    pub message: String,
    pub code: String,
    pub err: i32,
}

/// `BrotliEncoderContext`.
pub struct BrotliEncoder {
    state: Encoder,
    dictionary: Vec<u8>,
    params: Vec<(i32, u32)>,
    /// `last_result_`: `false` means the last `compress_stream` call failed.
    last_result: bool,
    closed: bool,
}

impl BrotliEncoder {
    fn new(dictionary: &[u8]) -> Self {
        let mut encoder = Self {
            state: BrotliEncoderStateStruct::new(StandardAlloc::default()),
            dictionary: dictionary.to_vec(),
            params: Vec::new(),
            last_result: true,
            closed: false,
        };
        if !encoder.dictionary.is_empty() {
            let dictionary = std::mem::take(&mut encoder.dictionary);
            encoder
                .state
                .set_custom_dictionary(dictionary.len(), &dictionary);
            encoder.dictionary = dictionary;
        }
        encoder
    }
    /// Replaces the custom dictionary before the first write.
    pub fn set_dictionary(&mut self, dictionary: &[u8]) {
        self.dictionary = dictionary.to_vec();
        if self.dictionary.is_empty() {
            return;
        }
        let owned = std::mem::take(&mut self.dictionary);
        self.state.set_custom_dictionary(owned.len(), &owned);
        self.dictionary = owned;
    }

    /// `BrotliEncoderContext::SetParams()`, called for every non-`-1` entry of
    /// the `options.params` array.
    pub fn set_params(&mut self, key: i32, value: u32) -> Option<BrotliError> {
        let Some(parameter) = brotli_encoder_parameter(key) else {
            return Some(param_set_failed());
        };
        if !self.state.set_parameter(parameter, value) {
            return Some(param_set_failed());
        }
        record_param(&mut self.params, key, value);
        None
    }

    fn write(&mut self, flush: i32, input: &[u8], output: &mut [u8]) -> AfterWrite {
        let op = match flush {
            BROTLI_OPERATION_FLUSH => BrotliEncoderOperation::BROTLI_OPERATION_FLUSH,
            BROTLI_OPERATION_FINISH => BrotliEncoderOperation::BROTLI_OPERATION_FINISH,
            BROTLI_OPERATION_EMIT_METADATA => {
                BrotliEncoderOperation::BROTLI_OPERATION_EMIT_METADATA
            }
            _ => BrotliEncoderOperation::BROTLI_OPERATION_PROCESS,
        };

        let mut available_in = input.len();
        let mut input_offset = 0usize;
        let mut available_out = output.len();
        let mut output_offset = 0usize;
        let mut total_out = Some(0usize);
        let mut callback = |_: &mut PredictionModeContextMap<InputReferenceMut<'_>>,
                            _: &mut [StaticCommand],
                            _: InputPair<'_>,
                            _: &mut StandardAlloc| {};

        self.last_result = self.state.compress_stream(
            op,
            &mut available_in,
            input,
            &mut input_offset,
            &mut available_out,
            output,
            &mut output_offset,
            &mut total_out,
            &mut callback,
        );

        AfterWrite {
            avail_in: available_in as u32,
            avail_out: available_out as u32,
        }
    }

    fn error_info(&self) -> Option<BrotliError> {
        if self.last_result {
            None
        } else {
            Some(BrotliError {
                message: "Compression failed".to_string(),
                code: "ERR_BROTLI_COMPRESSION_FAILED".to_string(),
                err: -1,
            })
        }
    }

    fn reset(&mut self) -> Option<BrotliError> {
        let params = self.params.clone();
        let dictionary = std::mem::take(&mut self.dictionary);
        *self = Self::new(&dictionary);
        for (key, value) in params {
            if let Some(error) = self.set_params(key, value) {
                return Some(error);
            }
        }
        None
    }
}

/// `BrotliDecoderContext`.
pub struct BrotliDecoder {
    state: Box<BrotliState<StandardAlloc, StandardAlloc, StandardAlloc>>,
    dictionary: Vec<u8>,
    params: Vec<(i32, u32)>,
    result: BrotliResult,
    /// The decoder's error, as `(BrotliDecoderErrorString, errno)`.
    ///
    /// Both halves are captured when the failure happens, because they are what
    /// `CompressionError` reports and `zlibOnError` puts on the JS `Error`.
    /// `BrotliDecoderErrorCode` is not part of the crate's public API, so the
    /// name is looked up from the numeric code in
    /// [`brotli_decoder_error_code`].
    error: Option<(&'static str, i32)>,
    flush: i32,
    closed: bool,
}

impl BrotliDecoder {
    fn new(dictionary: &[u8]) -> Self {
        let mut decoder = Self {
            state: Box::new(BrotliState::new(
                StandardAlloc::default(),
                StandardAlloc::default(),
                StandardAlloc::default(),
            )),
            dictionary: Vec::new(),
            params: Vec::new(),
            result: BrotliResult::NeedsMoreInput,
            error: None,
            flush: BROTLI_OPERATION_PROCESS,
            closed: false,
        };
        if !dictionary.is_empty() {
            decoder.dictionary = dictionary.to_vec();
            let mut allocator = StandardAlloc::default();
            let memory = brotli::Allocator::alloc_cell(&mut allocator, dictionary.len());
            decoder.state.custom_dict = memory;
            // `custom_dict_size` is what the decoder uses to bound backward
            // distances, so it has to match the dictionary that was attached.
            decoder.state.custom_dict_size = dictionary.len() as isize;
        }
        decoder
    }

    fn write(&mut self, flush: i32, input: &[u8], output: &mut [u8]) -> AfterWrite {
        self.flush = flush;
        let mut available_in = input.len();
        let mut input_offset = 0usize;
        let mut available_out = output.len();
        let mut output_offset = 0usize;
        let mut total_out = 0usize;

        self.result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            input,
            &mut available_out,
            &mut output_offset,
            output,
            &mut total_out,
            &mut self.state,
        );

        if matches!(self.result, BrotliResult::ResultFailure) && self.error.is_none() {
            // `node_zlib.cc` records both the numeric code and the string here,
            // in `DoThreadPoolWork`, because `BrotliDecoderErrorString` is a C
            // API the Rust crate does not export. `BrotliDecoderErrorCode` is
            // `#[repr(C)]` and the field is public, so the numeric value is
            // readable and the name follows from it.
            self.error = Some(brotli_decoder_error_code(self.state.error_code as i32));
        }

        AfterWrite {
            avail_in: available_in as u32,
            avail_out: available_out as u32,
        }
    }

    fn error_info(&self) -> Option<BrotliError> {
        if let Some((code, err)) = &self.error {
            return Some(BrotliError {
                message: "Decompression failed".to_string(),
                // `BrotliDecoderContext::DoThreadPoolWork` builds this as
                // `std::string("ERR_") + BrotliDecoderErrorString(code)`, and
                // `BrotliDecoderErrorString` returns `#PREFIX #NAME`. For the
                // format errors the prefix is `_ERROR_FORMAT_`, so the code
                // really is `ERR__ERROR_FORMAT_PADDING_2` — the doubled
                // underscore is upstream's, not a typo.
                code: format!("ERR_{code}"),
                err: *err,
            });
        }
        // Brotli has no "unexpected end of file" code; Node maps a FINISH that
        // still wants more input onto zlib's Z_BUF_ERROR.
        if self.flush == BROTLI_OPERATION_FINISH
            && matches!(self.result, BrotliResult::NeedsMoreInput)
        {
            return Some(BrotliError {
                message: "unexpected end of file".to_string(),
                code: "Z_BUF_ERROR".to_string(),
                err: Z_BUF_ERROR,
            });
        }
        None
    }

    fn reset(&mut self) -> Option<BrotliError> {
        let params = self.params.clone();
        let dictionary = std::mem::take(&mut self.dictionary);
        *self = Self::new(&dictionary);
        self.params = params;
        None
    }
}

/// `BrotliDecoderErrorString(code)` from `deps/brotli/c/dec/decode.c`, which
/// renders each entry of `BROTLI_DECODER_ERROR_CODES_LIST` as `#PREFIX #NAME`.
///
/// The table is transcribed from the vendored `decode.h` rather than derived
/// from the Rust enum because two things differ between them: the crate has no
/// `BLOCK_SWITCH` or `COMPOUND_DICTIONARY`, and its `BrotliDecoderErrorStr`
/// misspells `CL_SPACE` as `FL_SPACE`. Node's `Error.code` is built from the C
/// string, so the C spelling is what has to be reproduced.
///
/// A code outside the table yields Node's `default` branch, `"INVALID"`.
fn brotli_decoder_error_name(code: i32) -> &'static str {
    match code {
        0 => "_NO_ERROR",
        1 => "_SUCCESS",
        2 => "_NEEDS_MORE_INPUT",
        3 => "_NEEDS_MORE_OUTPUT",
        -1 => "_ERROR_FORMAT_EXUBERANT_NIBBLE",
        -2 => "_ERROR_FORMAT_RESERVED",
        -3 => "_ERROR_FORMAT_EXUBERANT_META_NIBBLE",
        -4 => "_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET",
        -5 => "_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME",
        -6 => "_ERROR_FORMAT_CL_SPACE",
        -7 => "_ERROR_FORMAT_HUFFMAN_SPACE",
        -8 => "_ERROR_FORMAT_CONTEXT_MAP_REPEAT",
        -9 => "_ERROR_FORMAT_BLOCK_LENGTH_1",
        -10 => "_ERROR_FORMAT_BLOCK_LENGTH_2",
        -11 => "_ERROR_FORMAT_TRANSFORM",
        -12 => "_ERROR_FORMAT_DICTIONARY",
        -13 => "_ERROR_FORMAT_WINDOW_BITS",
        -14 => "_ERROR_FORMAT_PADDING_1",
        -15 => "_ERROR_FORMAT_PADDING_2",
        -16 => "_ERROR_FORMAT_DISTANCE",
        -17 => "_ERROR_FORMAT_BLOCK_SWITCH",
        -18 => "_ERROR_COMPOUND_DICTIONARY",
        -19 => "_ERROR_DICTIONARY_NOT_SET",
        -20 => "_ERROR_INVALID_ARGUMENTS",
        -21 => "_ERROR_ALLOC_CONTEXT_MODES",
        -22 => "_ERROR_ALLOC_TREE_GROUPS",
        -25 => "_ERROR_ALLOC_CONTEXT_MAP",
        -26 => "_ERROR_ALLOC_RING_BUFFER_1",
        -27 => "_ERROR_ALLOC_RING_BUFFER_2",
        -30 => "_ERROR_ALLOC_BLOCK_TYPE_TREES",
        -31 => "_ERROR_UNREACHABLE",
        _ => "INVALID",
    }
}

/// The pair `BrotliDecoderContext` records for a failure.
fn brotli_decoder_error_code(code: i32) -> (&'static str, i32) {
    (brotli_decoder_error_name(code), code)
}

fn param_set_failed() -> BrotliError {
    BrotliError {
        message: "Setting parameter failed".to_string(),
        code: "ERR_BROTLI_PARAM_SET_FAILED".to_string(),
        err: -1,
    }
}

fn record_param(params: &mut Vec<(i32, u32)>, key: i32, value: u32) {
    if let Some(entry) = params.iter_mut().find(|entry| entry.0 == key) {
        entry.1 = value;
        return;
    }
    params.push((key, value));
}

fn brotli_encoder_parameter(key: i32) -> Option<BrotliEncoderParameter> {
    Some(match key {
        0 => BrotliEncoderParameter::BROTLI_PARAM_MODE,
        1 => BrotliEncoderParameter::BROTLI_PARAM_QUALITY,
        2 => BrotliEncoderParameter::BROTLI_PARAM_LGWIN,
        3 => BrotliEncoderParameter::BROTLI_PARAM_LGBLOCK,
        4 => BrotliEncoderParameter::BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING,
        5 => BrotliEncoderParameter::BROTLI_PARAM_SIZE_HINT,
        6 => BrotliEncoderParameter::BROTLI_PARAM_LARGE_WINDOW,
        _ => return None,
    })
}

/// Default encoder parameters, matching Node's Brotli defaults.
pub fn default_encoder_params() -> BrotliEncoderParams {
    BrotliEncoderParams::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compress(data: &[u8], quality: u32) -> Vec<u8> {
        let mut stream = BrotliStream::encoder(&[]);
        let BrotliStream::Encode(encoder) = &mut stream else {
            unreachable!("encoder() builds an encoder");
        };
        assert!(encoder.set_params(1, quality).is_none());
        let mut out = vec![0u8; data.len() * 2 + 4096];
        let after = stream.write(BROTLI_OPERATION_FINISH, data, &mut out);
        assert_eq!(after.avail_in, 0, "all input consumed");
        assert!(stream.error_info().is_none(), "no encoder error");
        out.truncate(out.len() - after.avail_out as usize);
        stream.close();
        out
    }

    fn decompress(data: &[u8]) -> Vec<u8> {
        let mut stream = BrotliStream::decoder(&[]);
        let mut out = vec![0u8; 1 << 20];
        let after = stream.write(BROTLI_OPERATION_FINISH, data, &mut out);
        assert_eq!(after.avail_in, 0, "all input consumed");
        assert!(stream.error_info().is_none(), "no decoder error");
        out.truncate(out.len() - after.avail_out as usize);
        stream.close();
        out
    }

    #[test]
    fn brotli_round_trips() {
        let data = b"brotli payload that repeats a lot".repeat(40);
        let compressed = compress(&data, 5);
        assert!(!compressed.is_empty());
        assert_eq!(decompress(&compressed), data);
    }

    #[test]
    fn brotli_compresses_repetitive_input() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(50);
        let compressed = compress(&data, 9);
        assert!(
            compressed.len() < data.len(),
            "{} compressed vs {} raw",
            compressed.len(),
            data.len()
        );
    }

    #[test]
    fn brotli_empty_input_round_trips() {
        let compressed = compress(b"", 5);
        assert_eq!(decompress(&compressed), b"");
    }

    #[test]
    fn brotli_truncated_input_reports_unexpected_end_of_file() {
        let data = b"truncation".repeat(60);
        let compressed = compress(&data, 5);
        let truncated = &compressed[..compressed.len() - 1];

        let mut stream = BrotliStream::decoder(&[]);
        let mut out = vec![0u8; 1 << 16];
        stream.write(BROTLI_OPERATION_FINISH, truncated, &mut out);
        let error = stream.error_info().expect("truncated brotli must fail");
        assert_eq!(error.code, "Z_BUF_ERROR");
        assert_eq!(error.message, "unexpected end of file");
    }

    /// `node -e 'try{zlib.brotliDecompressSync(Buffer.from("notbrotli"))}catch(e){...}'`
    /// on the pinned oracle prints
    /// `ERR__ERROR_FORMAT_PADDING_2 -15 Decompression failed`. The doubled
    /// underscore is Node's: it prefixes `ERR_` to a string that already starts
    /// with `_ERROR_FORMAT_`.
    #[test]
    fn brotli_invalid_input_reports_node_error_code_and_errno() {
        let mut stream = BrotliStream::decoder(&[]);
        let mut out = vec![0u8; 1024];
        stream.write(BROTLI_OPERATION_FINISH, b"notbrotli", &mut out);
        let error = stream.error_info().expect("garbage must fail");
        assert_eq!(error.message, "Decompression failed");
        assert_eq!(error.code, "ERR__ERROR_FORMAT_PADDING_2");
        assert_eq!(error.err, -15);
    }

    /// Every name in the table, checked against the C list in
    /// `deps/brotli/c/include/brotli/decode.h`. The Rust crate's own
    /// `BrotliDecoderErrorStr` cannot be used for this: it misspells
    /// `CL_SPACE` as `FL_SPACE` and is missing the two entries below.
    #[test]
    fn decoder_error_names_match_the_c_list() {
        assert_eq!(brotli_decoder_error_name(0), "_NO_ERROR");
        assert_eq!(brotli_decoder_error_name(2), "_NEEDS_MORE_INPUT");
        assert_eq!(
            brotli_decoder_error_name(-1),
            "_ERROR_FORMAT_EXUBERANT_NIBBLE"
        );
        // The crate's own string table says ERROR_FORMAT_FL_SPACE.
        assert_eq!(brotli_decoder_error_name(-6), "_ERROR_FORMAT_CL_SPACE");
        assert_eq!(brotli_decoder_error_name(-15), "_ERROR_FORMAT_PADDING_2");
        // Present in the C list, absent from the Rust enum.
        assert_eq!(brotli_decoder_error_name(-17), "_ERROR_FORMAT_BLOCK_SWITCH");
        assert_eq!(brotli_decoder_error_name(-18), "_ERROR_COMPOUND_DICTIONARY");
        assert_eq!(brotli_decoder_error_name(-31), "_ERROR_UNREACHABLE");
        // Node's `default` branch.
        assert_eq!(brotli_decoder_error_name(-99), "INVALID");
    }

    #[test]
    fn brotli_unknown_parameter_is_rejected() {
        let mut stream = BrotliStream::encoder(&[]);
        let BrotliStream::Encode(encoder) = &mut stream else {
            unreachable!("encoder() builds an encoder");
        };
        let error = encoder.set_params(99, 1).expect("unknown keys must fail");
        assert_eq!(error.code, "ERR_BROTLI_PARAM_SET_FAILED");
    }

    #[test]
    fn brotli_params_are_replayed_by_reset() {
        let mut stream = BrotliStream::encoder(&[]);
        let BrotliStream::Encode(encoder) = &mut stream else {
            unreachable!("encoder() builds an encoder");
        };
        assert!(encoder.set_params(1, 2).is_none());
        assert!(stream.reset().is_none());
        let BrotliStream::Encode(encoder) = &stream else {
            unreachable!("encoder() builds an encoder");
        };
        assert!(encoder.params.contains(&(1, 2)), "quality must be replayed");
    }

    #[test]
    fn brotli_streaming_in_one_byte_chunks_round_trips() {
        let data = b"brotli one byte at a time".repeat(20);
        let mut encoder = BrotliStream::encoder(&[]);
        let mut compressed = Vec::new();
        for (index, byte) in data.iter().enumerate() {
            let flush = if index + 1 == data.len() {
                BROTLI_OPERATION_FINISH
            } else {
                BROTLI_OPERATION_PROCESS
            };
            let mut out = [0u8; 4096];
            let after = encoder.write(flush, &[*byte], &mut out);
            assert_eq!(after.avail_in, 0, "byte {index} not consumed");
            assert!(encoder.error_info().is_none());
            let produced = 4096 - after.avail_out as usize;
            compressed.extend_from_slice(&out[..produced]);
        }

        let mut decoder = BrotliStream::decoder(&[]);
        let mut plain = Vec::new();
        for (index, byte) in compressed.iter().enumerate() {
            let flush = if index + 1 == compressed.len() {
                BROTLI_OPERATION_FINISH
            } else {
                BROTLI_OPERATION_PROCESS
            };
            let mut out = [0u8; 4096];
            let after = decoder.write(flush, &[*byte], &mut out);
            assert_eq!(after.avail_in, 0, "compressed byte {index} not consumed");
            assert!(decoder.error_info().is_none());
            let produced = 4096 - after.avail_out as usize;
            plain.extend_from_slice(&out[..produced]);
        }
        assert_eq!(plain, data);
    }
}

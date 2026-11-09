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
    /// The decoder's error code, rendered on arrival because
    /// `BrotliDecoderErrorCode` is not part of the crate's public API.
    error: Option<String>,
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
            self.error = Some(format!("{:?}", self.state.error_code));
        }

        AfterWrite {
            avail_in: available_in as u32,
            avail_out: available_out as u32,
        }
    }

    fn error_info(&self) -> Option<BrotliError> {
        if let Some(code) = &self.error {
            return Some(BrotliError {
                message: "Decompression failed".to_string(),
                // Node formats this as `"ERR_" + BrotliDecoderErrorString(code)`.
                code: format!("ERR_{code}"),
                err: 0,
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

    #[test]
    fn brotli_invalid_input_reports_decompression_failed() {
        let mut stream = BrotliStream::decoder(&[]);
        let mut out = vec![0u8; 1024];
        stream.write(BROTLI_OPERATION_FINISH, &[0xff; 32], &mut out);
        let error = stream.error_info().expect("garbage must fail");
        assert_eq!(error.message, "Decompression failed");
        assert!(error.code.starts_with("ERR_BROTLI"), "{}", error.code);
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

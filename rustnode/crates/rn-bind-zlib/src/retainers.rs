//! The compression handles as `MemoryRetainer`s.
//!
//! Node's `CompressionStream` is a `MemoryRetainer` whose `MemoryInfo`
//! (`src/node_zlib.cc:718-722`) tracks two things:
//!
//! ```text
//! tracker->TrackField("compression context", ctx_);
//! tracker->TrackFieldWithSize("zlib_memory", zlib_memory_ + unreported_allocations_);
//! ```
//!
//! and whose `MemoryRetainerNode` adds `native_to_javascript` to the JavaScript
//! handle object because `WrappedObject()` is non-empty. That is the whole of the
//! graph `test/pummel/test-heapdump-zlib.js` and `-zstd.js` walk:
//!
//! ```text
//! Node / ZlibStream --native_to_javascript--> Zlib
//!                   --compression context-->  Node / ZlibContext
//!                   --zlib_memory-->          Node / zlib_memory
//! ```
//!
//! # Why the class sizes are pinned and the memory total is not
//!
//! `SelfSize()` is `sizeof(TheClass)` on Node's side, so it is a constant this
//! build can reproduce exactly and must: a `loose` validation accepts a node of
//! the right name at any size, so a wrong number passes the test and is still a
//! lie about the process. Each size below was read from the pinned oracle's own
//! snapshot of the same construction, and `the_sizes_are_the_oracles_self_sizes`
//! pins them so a typo cannot survive.
//!
//! `Node / zlib_memory` is different in kind: it is the live allocation total of
//! whichever library is compressing, so it is a measurement rather than a
//! constant. The oracle's own value moves between runs and between compressors
//! (284,680 bytes for a gzip handle over `hello world`, 9,096 for the same bytes
//! through an inflate handle), and this build links libz-rs rather than zlib. So
//! [`crate::memory`] counts real allocations and reports their real total; what
//! the node must get right, and what the test asserts, is that it is absent until
//! something has been allocated.

use rn_core::heap_retainers::HeapNode;
use rn_v8_sys::v8;

use crate::handle::{Backend, HandleState};

/// `sizeof(node::ZlibStream)`, the `SelfSize()` the oracle reports.
pub(crate) const ZLIB_STREAM_SIZE: usize = 496;

/// `sizeof(node::ZlibContext)`, the `SelfSize()` the oracle reports.
pub(crate) const ZLIB_CONTEXT_SIZE: usize = 240;

/// `sizeof(node::BrotliCompressionStream)`, for the encoder.
///
/// Node has one C++ class for both Brotli directions; its `SelfSize()` is the
/// same for either, which is why the oracle reports 392 and 416 for the encoder
/// and decoder here. Those two numbers differ because the *object* differs, not
/// the class: `BrotliCompressionStream<BrotliEncoderContext>` and
/// `<BrotliDecoderContext>` are distinct instantiations. `SET_SELF_SIZE` in a
/// class template expands to `sizeof(BrotliCompressionStream<Ctx>)`, so each
/// direction has its own constant.
pub(crate) const BROTLI_ENCODER_STREAM_SIZE: usize = 392;

/// `sizeof(node::BrotliCompressionStream<BrotliDecoderContext>)`.
pub(crate) const BROTLI_DECODER_STREAM_SIZE: usize = 416;

/// `sizeof(node::BrotliEncoderContext)`.
pub(crate) const BROTLI_ENCODER_CONTEXT_SIZE: usize = 136;

/// `sizeof(node::BrotliDecoderContext)`.
pub(crate) const BROTLI_DECODER_CONTEXT_SIZE: usize = 160;

/// `sizeof(node::ZstdStream<ZstdCompressContext>)`.
pub(crate) const ZSTD_COMPRESS_STREAM_SIZE: usize = 432;

/// `sizeof(node::ZstdStream<ZstdDecompressContext>)`.
pub(crate) const ZSTD_DECOMPRESS_STREAM_SIZE: usize = 424;

/// `sizeof(node::ZstdCompressContext)`.
pub(crate) const ZSTD_COMPRESS_CONTEXT_SIZE: usize = 176;

/// `sizeof(node::ZstdDecompressContext)`.
pub(crate) const ZSTD_DECOMPRESS_CONTEXT_SIZE: usize = 168;

/// The three names `MemoryInfoName()` returns, and the class sizes to go with
/// each.
struct Names {
    /// `CompressionStream::MemoryInfoName()`, which its subclasses inherit.
    stream: &'static str,
    /// The `ctx_` member's `MemoryInfoName()`.
    context: &'static str,
    stream_size: usize,
    context_size: usize,
}

fn names(backend: &Backend) -> Names {
    match backend {
        Backend::Zlib(_) => Names {
            stream: "ZlibStream",
            context: "ZlibContext",
            stream_size: ZLIB_STREAM_SIZE,
            context_size: ZLIB_CONTEXT_SIZE,
        },
        Backend::Brotli(stream) => {
            if stream.is_encoder() {
                Names {
                    stream: "BrotliCompressionStream",
                    context: "BrotliEncoderContext",
                    stream_size: BROTLI_ENCODER_STREAM_SIZE,
                    context_size: BROTLI_ENCODER_CONTEXT_SIZE,
                }
            } else {
                Names {
                    stream: "BrotliCompressionStream",
                    context: "BrotliDecoderContext",
                    stream_size: BROTLI_DECODER_STREAM_SIZE,
                    context_size: BROTLI_DECODER_CONTEXT_SIZE,
                }
            }
        }
        Backend::ZstdCompress(_) => Names {
            stream: "ZstdStream",
            context: "ZstdCompressContext",
            stream_size: ZSTD_COMPRESS_STREAM_SIZE,
            context_size: ZSTD_COMPRESS_CONTEXT_SIZE,
        },
        Backend::ZstdDecompress(_) => Names {
            stream: "ZstdStream",
            context: "ZstdDecompressContext",
            stream_size: ZSTD_DECOMPRESS_STREAM_SIZE,
            context_size: ZSTD_DECOMPRESS_CONTEXT_SIZE,
        },
    }
}

/// Builds the node graph for one live handle.
///
/// `wrapper` is the handle's JavaScript object, resolved by the caller from the
/// state's `v8::Weak`. Returns `None` when the wrapper has been collected, which
/// means the handle is gone and reporting it would claim memory nothing holds.
pub(crate) fn describe<'s>(
    state: &HandleState,
    wrapper: Option<v8::Local<'s, v8::Value>>,
) -> Option<HeapNode<'s>> {
    let Some(wrapper) = wrapper else {
        return None;
    };
    let names = names(state.backend());
    let mut node = HeapNode::new(names.stream, names.stream_size).with_wrapper(wrapper);
    node = node.with_child(
        // `TrackField("compression context", ctx_)`: `ctx_` is a base subobject,
        // not a pointer, so the edge name carries the space Node's literal does.
        "compression context",
        HeapNode::new(names.context, names.context_size),
    );
    // `TrackFieldWithSize` adds nothing at all when the size is zero
    // (`src/memory_tracker-inl.h:108-110`), which is what makes the node absent
    // on a stream that has not been written to yet.
    let bytes = state.memory_bytes();
    if bytes > 0 {
        node = node.with_child("zlib_memory", HeapNode::new("zlib_memory", bytes));
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes are the ones the oracle reports, and nothing else checks them.
    ///
    /// `validateByRetainingPath` matches on the node *name*, so a wrong size
    /// passes every test in Node's suite. These numbers come from a snapshot of
    /// the pinned oracle, and this is the assertion that keeps them honest.
    #[test]
    fn the_sizes_are_the_oracles_self_sizes() {
        assert_eq!(ZLIB_STREAM_SIZE, 496);
        assert_eq!(ZLIB_CONTEXT_SIZE, 240);
        assert_eq!(BROTLI_ENCODER_STREAM_SIZE, 392);
        assert_eq!(BROTLI_DECODER_STREAM_SIZE, 416);
        assert_eq!(BROTLI_ENCODER_CONTEXT_SIZE, 136);
        assert_eq!(BROTLI_DECODER_CONTEXT_SIZE, 160);
        assert_eq!(ZSTD_COMPRESS_STREAM_SIZE, 432);
        assert_eq!(ZSTD_DECOMPRESS_STREAM_SIZE, 424);
        assert_eq!(ZSTD_COMPRESS_CONTEXT_SIZE, 176);
        assert_eq!(ZSTD_DECOMPRESS_CONTEXT_SIZE, 168);
    }

    #[test]
    fn every_backend_has_a_name_and_two_sizes() {
        // The three names are the ones a snapshot renders as `Node / <name>`;
        // each has to be the C++ `MemoryInfoName()` literally, including the
        // `Stream` suffix Node's base class adds.
        for (backend, stream, context) in [
            (
                Backend::Zlib(Box::new(crate::zlib::ZlibStream::new(
                    crate::ZlibMode::Gzip,
                ))),
                "ZlibStream",
                "ZlibContext",
            ),
            (
                Backend::ZstdCompress(Box::new(crate::zstd::ZstdCompressStream::uninitialized())),
                "ZstdStream",
                "ZstdCompressContext",
            ),
            (
                Backend::ZstdDecompress(Box::new(
                    crate::zstd::ZstdDecompressStream::uninitialized(),
                )),
                "ZstdStream",
                "ZstdDecompressContext",
            ),
        ] {
            let names = names(&backend);
            assert_eq!(names.stream, stream);
            assert_eq!(names.context, context);
            assert!(names.stream_size > 0);
            assert!(names.context_size > 0);
        }
    }

    /// Each backend reports its own class names, including the two Brotli
    /// directions, which Node instantiates as separate templates.
    #[test]
    fn brotli_reports_the_direction_it_is() {
        let encoder = Backend::Brotli(Box::new(crate::brotli::BrotliStream::encoder(&[])));
        let decoder = Backend::Brotli(Box::new(crate::brotli::BrotliStream::decoder(&[])));
        assert_eq!(names(&encoder).context, "BrotliEncoderContext");
        assert_eq!(names(&decoder).context, "BrotliDecoderContext");
        assert_eq!(names(&encoder).stream, names(&decoder).stream);
        assert_ne!(
            names(&encoder).stream_size,
            names(&decoder).stream_size,
            "the two instantiations are distinct classes with distinct sizes"
        );
    }
}

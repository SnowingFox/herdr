# nghttp2, as vendored by Node

`lib/**` and `nghttp2.gyp` are copied byte-identical from `deps/nghttp2` in the
Node revision pinned in `tools/node-pin.toml` (`f344e7f552e`, which reports
itself as 28.0.0). nghttp2 is version 1.70.0 there, and `lib/includes/nghttp2/nghttp2ver.h`
carries that number.

    deps/nghttp2/COPYING
    deps/nghttp2/nghttp2.gyp
    deps/nghttp2/lib/**            (26 .c files, 26 internal .h files)
    deps/nghttp2/lib/includes/**   (config.h and the two public headers)

MIT licensed; see `COPYING`.

## Why the C rather than a Rust HTTP/2 implementation

HTTP/2 is a wire protocol with a HPACK Huffman table, a frame state machine, a
priority tree and a flow-control accounting model that remote peers can drive
into edge states. Node's `src/node_http2.cc` is not a protocol implementation at
all: it is a binding *over* nghttp2, and `deps/nghttp2` is the implementation.
`lib/internal/http2/core.js` depends on nghttp2's exact behaviour in ways that are
observable in test assertions — the error strings `nghttp2ErrorString` returns,
the stream-state numbering `refreshState` publishes, the `NGHTTP2_ERR_*` values
`nghttp2ErrorString` is called with, and the settings defaults
`refreshDefaultSettings` writes.

rustnode's thesis is that only the *native glue* is rewritten, so the protocol
stays C and this project owns only `crates/rn-bind-http2`.

## What is not vendored

`deps/nghttp2/lib/includes/Makefile.in`, `CMakeLists.txt`, `version.rc.in`,
`libnghttp2.pc.in`, `Makefile.am`, `Makefile.msvc` and `nghttp2ver.h.in` are the
autotools/CMake/MSVC build scaffolding. They are not compiled and not read by
anything here, so they are left out rather than carried as dead files. The gyp
file is kept because it is the *source* of the compile set and the define list
`crates/rn-bind-http2/build.rs` mirrors.

`deps/nghttp2/lib/sfparse.c` is compiled as part of the same library by
`nghttp2.gyp`'s second target, and it is included here for that reason.

## Updating

Replace every file from a newer Node checkout, regenerate `NGHTTP2.sha256`, and
update the commit above. `tools/verify-nghttp2.sh` checks that the vendored tree
still matches, and also that the file set is exactly the gyp's source list plus
the headers, so a vendored tree assembled by hand fails the gate instead of
quietly compiling a different library.

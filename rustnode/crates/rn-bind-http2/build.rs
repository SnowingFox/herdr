//! Compiles the vendored nghttp2.
//!
//! `vendor/nghttp2` holds nghttp2 1.70.0, copied byte-identical from
//! `deps/nghttp2` in the Node revision `tools/node-pin.toml` pins. Node builds
//! that same tree as a static library, so this is not a reimplementation of
//! HTTP/2: it is the protocol implementation Node ships, and `src/node_http2.cc`
//! is a thin binding over it.
//!
//! # Why not the system library
//!
//! A host `libnghttp2` is a different version on every machine and absent on
//! Windows. `node:http2` exposes version-dependent behaviour directly:
//! `nghttp2ErrorString` returns nghttp2's own `nghttp2_strerror` text, which
//! `test-http2-binding.js` asserts verbatim for `-517`, the `NGHTTP2_ERR_*`,
//! `NGHTTP2_STREAM_STATE_*` and `NGHTTP2_FLAG_*` values published through
//! `constants` are the header's numbers, and `refreshDefaultSettings` writes
//! nghttp2's settings defaults. Debian ships 1.52, macOS does not ship it at all,
//! and Windows ships none, so a system link would make results depend on the
//! host. The tree is self-contained C with no dependencies, which makes
//! compiling it in the crate both reproducible and portable.
//!
//! # The flags
//!
//! `vendor/nghttp2/nghttp2.gyp` lists them, and they are copied exactly rather
//! than trimmed to what `lib/internal/http2/core.js` appears to use:
//!
//! * `_U_` silences the "unused parameter" annotations nghttp2 writes as
//!   `UNUSED` arguments; the gyp sets it in `target_defaults` so it applies to
//!   every translation unit.
//! * `BUILDING_NGHTTP2` selects the visibility attribute in `NGHTTP2_EXTERN`.
//! * `NGHTTP2_STATICLIB` makes `NGHTTP2_EXTERN` empty, which is what a static
//!   link needs; the gyp puts it in `direct_dependent_settings` so the *consumer*
//!   also sees it, and this crate is that consumer.
//! * `HAVE_CONFIG_H` makes every `.c` include `lib/includes/config.h`, which is
//!   nghttp2's own configured header rather than a generated one. It is vendored
//!   byte-identical and is what makes `nghttp2_ssize` and the Windows `ssize_t`
//!   shim resolve.
//!
//! `deps/nghttp2/nghttp2.gyp` also defines `WIN32` and `_WINDOWS` when
//! `OS=="win"`, and `DEBUGBUILD=1` under `debug_nghttp2 == 1`. `cc-rs` defines
//! the platform macros itself for a Windows target, and Node's own build does not
//! enable `debug_nghttp2` by default, so neither is repeated here.

use std::path::Path;

/// The 26 translation units `nghttp2.gyp` compiles.
///
/// Written out rather than globbed so a stray `.c` file in the vendored tree
/// cannot join the build, and so the list is reviewable against the gyp.
/// `tools/verify-nghttp2.sh` checks the tree contains exactly these.
const SOURCES: &[&str] = &[
    "lib/nghttp2_alpn.c",
    "lib/nghttp2_buf.c",
    "lib/nghttp2_callbacks.c",
    "lib/nghttp2_debug.c",
    "lib/nghttp2_extpri.c",
    "lib/nghttp2_frame.c",
    "lib/nghttp2_hd.c",
    "lib/nghttp2_hd_huffman.c",
    "lib/nghttp2_hd_huffman_data.c",
    "lib/nghttp2_helper.c",
    "lib/nghttp2_http.c",
    "lib/nghttp2_map.c",
    "lib/nghttp2_mem.c",
    "lib/nghttp2_option.c",
    "lib/nghttp2_outbound_item.c",
    "lib/nghttp2_pq.c",
    "lib/nghttp2_priority_spec.c",
    "lib/nghttp2_queue.c",
    "lib/nghttp2_ratelim.c",
    "lib/nghttp2_rcbuf.c",
    "lib/nghttp2_session.c",
    "lib/nghttp2_stream.c",
    "lib/nghttp2_submit.c",
    "lib/nghttp2_time.c",
    "lib/nghttp2_version.c",
    // `nghttp2.gyp`'s second target. Structured Field Values parsing, which
    // nghttp2's own EXT_PRIORITY support needs.
    "lib/sfparse.c",
];

fn main() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let nghttp2 = manifest
        .join("..")
        .join("..")
        .join("vendor")
        .join("nghttp2");
    let includes = nghttp2.join("lib").join("includes");
    println!("cargo:rerun-if-changed={}", nghttp2.display());

    let mut build = cc::Build::new();
    build
        .include(&includes)
        .warnings(false)
        .flag_if_supported("-fvisibility=hidden")
        .define("_U_", "")
        .define("BUILDING_NGHTTP2", None)
        .define("NGHTTP2_STATICLIB", None)
        .define("HAVE_CONFIG_H", None);
    for source in SOURCES {
        let path = nghttp2.join(source);
        assert!(
            Path::new(&path).is_file(),
            "{} is missing from vendor/nghttp2",
            path.display()
        );
        build.file(path);
    }
    build.compile("nghttp2");
}

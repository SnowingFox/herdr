//! Builds the C QUIC dependencies from the pinned Node vendored trees.
//!
//! This is a feasibility probe, not a shippable crate. It compiles exactly the
//! source sets `deps/ngtcp2/ngtcp2.gyp` lists and links them against the same
//! vendored OpenSSL the rest of the workspace already builds, so the question
//! "can the C dependencies be built and bound here at all" gets a real answer
//! instead of an estimate.
//!
//! # Where the sources come from
//!
//! Node vendors both libraries inside `deps/ngtcp2`:
//!
//! * `deps/ngtcp2/ngtcp2/` — ngtcp2
//! * `deps/ngtcp2/nghttp3/` — nghttp3
//! * `deps/ngtcp2/crypto/` — the TLS glue, of which the `ossl/` backend is the
//!   one matching Node's OpenSSL build
//!
//! `RN_QUIC_NODE_DEPS` points at a checkout's `deps` directory. The probe does
//! not vendor copies: the point is to test the real tree at the pin, and a
//! vendored copy would answer a different question.
//!
//! # feature flags
//!
//! The defines below are transcribed from `ngtcp2.gyp`'s `defines` blocks for
//! its `ngtcp2` and `nghttp3` targets, minus `HAVE_CONFIG_H`. That one is
//! intentionally absent: `HAVE_CONFIG_H` makes the sources `#include "config.h"`,
//! and the `config.h` the vendored tree ships is a hand-edited stand-in for
//! `src/node.h` that *undefines* `HAVE_UNISTD_H` and `HAVE_ARPA_INET_H` (see the
//! comment at its top). Defining both a config header and the same macros on the
//! command line is how a build ends up with the header silently winning, so this
//! takes the other road: no `HAVE_CONFIG_H`, and every `HAVE_*` the sources
//! actually test is defined explicitly here.

use std::path::{Path, PathBuf};

/// The defines `ngtcp2.gyp` applies to the `ngtcp2` target.
const NGTCP2_DEFINES: &[&str] = &[
    "BUILDING_NGTCP2",
    "NGTCP2_STATICLIB",
    // Linux branch of the gyp `conditions` blocks.
    "HAVE_UNISTD_H",
    "HAVE_ARPA_INET_H",
    "HAVE_NETINET_IN_H",
    // ngtcp2 checks these to pick its memset_s/endian helpers. They are
    // configure-time detections that the vendored `config.h` never sets, and
    // the library falls back to portable code without them; being explicit
    // keeps the probe from depending on libc symbol availability.
    "HAVE_DECL_BSWAP_64=0",
    "HAVE_DECL_BE64TOH=0",
];

/// The defines `ngtcp2.gyp` applies to the `nghttp3` target.
const NGHTTP3_DEFINES: &[&str] = &[
    "BUILDING_NGHTTP3",
    "NGHTTP3_STATICLIB",
    "HAVE_UNISTD_H",
    "HAVE_ARPA_INET_H",
    "HAVE_NETINET_IN_H",
    "HAVE_DECL_BSWAP_64=0",
    "HAVE_DECL_BE64TOH=0",
];

/// The `ngtcp2_sources` list from `ngtcp2.gyp`, verbatim.
const NGTCP2_SOURCES: &[&str] = &[
    "ngtcp2/lib/ngtcp2_acktr.c",
    "ngtcp2/lib/ngtcp2_addr.c",
    "ngtcp2/lib/ngtcp2_balloc.c",
    "ngtcp2/lib/ngtcp2_bbr.c",
    "ngtcp2/lib/ngtcp2_buf.c",
    "ngtcp2/lib/ngtcp2_callbacks.c",
    "ngtcp2/lib/ngtcp2_cc.c",
    "ngtcp2/lib/ngtcp2_cid.c",
    "ngtcp2/lib/ngtcp2_conn.c",
    "ngtcp2/lib/ngtcp2_conn_info.c",
    "ngtcp2/lib/ngtcp2_conv.c",
    "ngtcp2/lib/ngtcp2_crypto.c",
    "ngtcp2/lib/ngtcp2_dcidtr.c",
    "ngtcp2/lib/ngtcp2_err.c",
    "ngtcp2/lib/ngtcp2_fmt.c",
    "ngtcp2/lib/ngtcp2_frame_chain.c",
    "ngtcp2/lib/ngtcp2_gaptr.c",
    "ngtcp2/lib/ngtcp2_idtr.c",
    "ngtcp2/lib/ngtcp2_ksl.c",
    "ngtcp2/lib/ngtcp2_log.c",
    "ngtcp2/lib/ngtcp2_map.c",
    "ngtcp2/lib/ngtcp2_mem.c",
    "ngtcp2/lib/ngtcp2_objalloc.c",
    "ngtcp2/lib/ngtcp2_opl.c",
    "ngtcp2/lib/ngtcp2_path.c",
    "ngtcp2/lib/ngtcp2_pcg.c",
    "ngtcp2/lib/ngtcp2_pkt.c",
    "ngtcp2/lib/ngtcp2_pmtud.c",
    "ngtcp2/lib/ngtcp2_ppe.c",
    "ngtcp2/lib/ngtcp2_pq.c",
    "ngtcp2/lib/ngtcp2_pv.c",
    "ngtcp2/lib/ngtcp2_qlog.c",
    "ngtcp2/lib/ngtcp2_range.c",
    "ngtcp2/lib/ngtcp2_ratelim.c",
    "ngtcp2/lib/ngtcp2_ringbuf.c",
    "ngtcp2/lib/ngtcp2_rob.c",
    "ngtcp2/lib/ngtcp2_rst.c",
    "ngtcp2/lib/ngtcp2_rtb.c",
    "ngtcp2/lib/ngtcp2_settings.c",
    "ngtcp2/lib/ngtcp2_str.c",
    "ngtcp2/lib/ngtcp2_strm.c",
    "ngtcp2/lib/ngtcp2_transport_params.c",
    "ngtcp2/lib/ngtcp2_unreachable.c",
    "ngtcp2/lib/ngtcp2_vec.c",
    "ngtcp2/lib/ngtcp2_version.c",
    "ngtcp2/lib/ngtcp2_wf.c",
    // The allocator/callback glue shared by every crypto backend.
    "ngtcp2/crypto/shared.c",
    // The OpenSSL 3.5 backend. `ngtcp2.gyp` selects this one when
    // `openssl_version >= 0x3050001f`; the BoringSSL and quictls backends are
    // not built by Node.
    "ngtcp2/crypto/ossl/ossl.c",
];

/// The `nghttp3_sources` list from `ngtcp2.gyp`, verbatim.
const NGHTTP3_SOURCES: &[&str] = &[
    "nghttp3/lib/nghttp3_balloc.c",
    "nghttp3/lib/nghttp3_buf.c",
    "nghttp3/lib/nghttp3_callbacks.c",
    "nghttp3/lib/nghttp3_conn.c",
    "nghttp3/lib/nghttp3_conv.c",
    "nghttp3/lib/nghttp3_debug.c",
    "nghttp3/lib/nghttp3_err.c",
    "nghttp3/lib/nghttp3_frame.c",
    "nghttp3/lib/nghttp3_gaptr.c",
    "nghttp3/lib/nghttp3_http.c",
    "nghttp3/lib/nghttp3_idtr.c",
    "nghttp3/lib/nghttp3_ksl.c",
    "nghttp3/lib/nghttp3_map.c",
    "nghttp3/lib/nghttp3_mem.c",
    "nghttp3/lib/nghttp3_objalloc.c",
    "nghttp3/lib/nghttp3_opl.c",
    "nghttp3/lib/nghttp3_pq.c",
    "nghttp3/lib/nghttp3_qpack.c",
    "nghttp3/lib/nghttp3_qpack_huffman.c",
    "nghttp3/lib/nghttp3_qpack_huffman_data.c",
    "nghttp3/lib/nghttp3_range.c",
    "nghttp3/lib/nghttp3_ratelim.c",
    "nghttp3/lib/nghttp3_rcbuf.c",
    "nghttp3/lib/nghttp3_ringbuf.c",
    "nghttp3/lib/nghttp3_settings.c",
    "nghttp3/lib/nghttp3_str.c",
    "nghttp3/lib/nghttp3_stream.c",
    "nghttp3/lib/nghttp3_tnode.c",
    "nghttp3/lib/nghttp3_unreachable.c",
    "nghttp3/lib/nghttp3_vec.c",
    "nghttp3/lib/nghttp3_version.c",
];

fn main() {
    println!("cargo:rerun-if-changed={}", shim_dir().display());
    println!("cargo:rerun-if-env-changed=RN_QUIC_NODE_DEPS");
    // `unexpected_cfgs` is warn-by-default; declaring the probe's flag here is
    // what keeps a clean `cargo clippy --workspace` quiet on machines that have
    // no Node checkout.
    println!("cargo:rustc-check-cfg=cfg(quic_probe_enabled)");

    let Some(deps) = node_deps_dir() else {
        // No checkpoint configured. This is the normal case in CI and for any
        // contributor who is not looking at QUIC, so it must not fail the
        // build: the crate compiles to an empty library and its tests are
        // compiled out. Failing here would take the whole workspace gate
        // hostage to an optional checkout that only the probe needs.
        println!(
            "cargo:warning=RN_QUIC_NODE_DEPS is unset; rn-quic-vendor-probe builds \
             an empty library. Set it to a Node checkout's deps directory to run \
             the probe."
        );
        return;
    };
    println!("cargo:rustc-cfg=quic_probe_enabled");

    let shim = shim_dir();

    let openssl = openssl_src::Build::new().build();
    openssl.print_cargo_metadata();
    // `include_dir()` is the directory containing `openssl/`, so it is already
    // the path `<openssl/ssl.h>` needs. ngtcp2's ossl adapter and the shim both
    // include the header with the `openssl/` prefix.
    let openssl_include = openssl.include_dir().to_path_buf();

    // ngtcp2 first: nghttp3's build in gyp depends on it, and the crypto glue
    // needs the OpenSSL headers ngtcp2 itself was compiled against.
    build_ngtcp2(&deps, &openssl_include);
    build_nghttp3(&deps);
    build_shim(&shim, &deps, &openssl_include);
}

fn shim_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("shim")
}

/// The `deps` directory of a Node checkout at the pin, or `None` when the
/// operator has not pointed the probe at one.
fn node_deps_dir() -> Option<PathBuf> {
    std::env::var_os("RN_QUIC_NODE_DEPS").map(PathBuf::from)
}

fn build_ngtcp2(deps: &Path, openssl_include: &Path) {
    let root = deps.join("ngtcp2");
    let mut build = cc::Build::new();
    build
        .include(&root)
        .include(root.join("ngtcp2").join("lib").join("includes"))
        .include(root.join("ngtcp2").join("crypto").join("includes"))
        .include(root.join("ngtcp2").join("lib"))
        .include(root.join("ngtcp2").join("crypto"))
        .include(openssl_include)
        .warnings(false);

    for define in NGTCP2_DEFINES {
        define_flag(&mut build, define);
    }

    for source in NGTCP2_SOURCES {
        build.file(root.join(source));
    }

    build.compile("ngtcp2");
}

/// Applies one `NAME` or `NAME=VALUE` define to a `cc::Build`.
///
/// `cc::Build::define` takes the name and value separately, so a define list
/// written the way a `-D` flag reads has to be split here. Passing
/// `HAVE_DECL_BSWAP_64=0` as the *name* would emit `-DHAVE_DECL_BSWAP_64=0=1`,
/// which the preprocessor rejects.
fn define_flag(build: &mut cc::Build, define: &str) {
    match define.split_once('=') {
        Some((name, value)) => build.define(name, Some(value)),
        None => build.define(define, None::<&str>),
    };
}

fn build_nghttp3(deps: &Path) {
    let root = deps.join("ngtcp2");
    let mut build = cc::Build::new();
    build
        .include(root.join("nghttp3").join("lib").join("includes"))
        .include(root.join("nghttp3").join("lib"))
        .warnings(false);

    for define in NGHTTP3_DEFINES {
        define_flag(&mut build, define);
    }

    for source in NGHTTP3_SOURCES {
        build.file(root.join(source));
    }

    build.compile("nghttp3");
}

fn build_shim(shim: &Path, deps: &Path, openssl_include: &Path) {
    let root = deps.join("ngtcp2");
    cc::Build::new()
        .include(shim)
        .include(&root)
        .include(root.join("ngtcp2").join("lib").join("includes"))
        .include(root.join("nghttp3").join("lib").join("includes"))
        .include(openssl_include)
        .warnings(false)
        .file(shim.join("rn_quic_probe.c"))
        .compile("rn_quic_probe");
}

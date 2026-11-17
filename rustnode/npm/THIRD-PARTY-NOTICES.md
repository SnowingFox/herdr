# Third-party notices

The published `rsnode` packages contain a compiled binary, not source. That
binary statically links or embeds the components below, so their licenses and
notices have to travel with the download even though the npm tarball itself is
MIT (see `LICENSE`).

Every version below was read out of the binary that was packed, through
`process.versions`, and cross-checked against the tree that built it. That is
deliberate: a notices file generated from a manifest describes what the build
intended to link, while this one describes what the shipped bytes actually
report. Where the two disagree the binary wins, and nothing here is listed that
the binary does not say it runs.

## Components

| Component | Version | License | Source in this repository |
| --- | --- | --- | --- |
| Node.js JavaScript layer (`lib/**`, `deps/undici`) | Node 28.0.0 pin | MIT | `rustnode/vendor/libnode-js/` (`LICENSE` alongside) |
| V8 | 15.2.124.1 | BSD-3-Clause | `v8` crate 152.2.0 (prebuilt `librusty_v8.a`) |
| OpenSSL | 3.6.3 | Apache-2.0 | `openssl-src` 300.6.1+3.6.3, statically linked |
| libuv | 1.53.0 | MIT | `libuv-sys2` 1.53.1, built from its vendored source |
| nghttp2 | 1.70.0 | MIT | `rustnode/vendor/nghttp2/` (`COPYING`) |
| llhttp | 9.4.3 | MIT | `rustnode/vendor/llhttp/` (`LICENSE`) |
| merve | 1.2.2 | MIT | `rustnode/vendor/merve/` (`LICENSE-MIT`) |
| SQLite | 3.54.1 | Public domain | `rustnode/vendor/sqlite/` |
| zlib-rs | 0.6.8 (`zlib` 1.3.0-compatible) | Zlib | `libz-rs-sys` 0.6.8 |
| zstd | 1.5.7 | BSD-3-Clause | `zstd-sys` 2.0.17+zstd.1.5.7 |
| Brotli | 8.0.4 | BSD-3-Clause AND MIT | `brotli` 8.0.4 |
| ICU | 78.2 | Unicode-3.0 | V8's bundled copy |
| acorn | 8.19.0 | MIT | `rustnode/vendor/libnode-js/deps/acorn/` |
| undici | 8.12.4 | MIT | `rustnode/vendor/libnode-js/deps/undici/` |

## What each of those means for redistribution

**Node.js** — The vendored `lib/**` builtin JavaScript is copied byte-identical
from Node and hash-frozen (`vendor/libnode-js/LIBJS.sha256`). Its license text is
`vendor/libnode-js/LICENSE`, which carries the Node contributors' MIT grant plus
the notices Node itself accumulates. It is the largest single notice obligation
here and its text is reproduced in full in that file.

**V8** — BSD-3-Clause requires the copyright notice, the conditions, and the
disclaimer to accompany a binary distribution. The `v8` crate ships the license
text in its own package; it is not duplicated in this repository because the
crate, not this repository, is where the prebuilt archive comes from.

**OpenSSL 3.x** — Apache-2.0. Redistribution of a binary that statically links
OpenSSL requires the Apache-2.0 license text and preservation of its notices,
including the `NOTICE` file if one is present in the source distribution.

**libuv, nghttp2, llhttp, merve, acorn, undici** — MIT. The grant and copyright
line must accompany the binary. nghttp2's `COPYING` and llhttp's `LICENSE` are
committed under `rustnode/vendor/`; merve's is `LICENSE-MIT` in the same place.

**SQLite** — Public domain. No notice is required; it is listed so the inventory
is complete.

**zlib-rs, zstd, Brotli** — Permissive (Zlib / BSD-3-Clause / BSD-3-Clause AND
MIT). Each requires its notice and, for the BSD forms, the disclaimer.

**ICU** — Unicode-3.0, from the copy V8 bundles. V8's own notices cover it.

**Root certificates** — The binary embeds a Mozilla CA root store generated from
`rustnode/vendor/certdata/certdata.txt`, which is Mozilla Public License 2.0
material. The certificates themselves are data, not code; the MPL notice is on
that file.

## OpenSSL linking and the system libraries

The binary is dynamically linked against `libstdc++`, `libm`, `libgcc_s` and
`libc` only (`ldd` on a released build shows exactly those). Everything else in
the table above is inside it, which is why this file exists at all rather than
deferring to the host's package database.

## If you are packaging this for a distribution

Compile from source instead of repackaging the npm binary, and use
`cargo metadata` plus `cargo deny` in the rustnode tree to regenerate this list
for your toolchain. The versions above are the ones this repository's
`Cargo.lock` and vendored trees pinned at the time of packing.

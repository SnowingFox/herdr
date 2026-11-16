//! `Bun`'s compression members: the four `zlib` ones and the four `zstd` ones.
//!
//! ```text
//! gzipSync  gunzipSync  deflateSync  inflateSync
//! zstdCompress  zstdCompressSync  zstdDecompress  zstdDecompressSync
//! ```
//!
//! # The one fact that decides this whole group
//!
//! **`Bun.deflateSync` is raw deflate (RFC 1951), not zlib-wrapped (RFC 1950).**
//! Measured on Bun 1.4.4: `deflateSync("hello")` is `cb48cdc9c90700`, and `cb` is
//! a raw deflate block header where a zlib stream would start `78 9c`. There is
//! **no** zlib-wrapped member in `Bun` at all. Code written against Node's
//! `zlib.deflateSync` gets this wrong by default, which is why every layer of this
//! crate names the wrapper explicitly and why the tests assert the first byte
//! rather than only the round trip.
//!
//! # What has to match, and what does not
//!
//! Compression output does **not** have to be byte-identical to Bun's: the exact
//! bytes are Bun's zlib level and strategy choice. What has to match is
//!
//! * the **container**, which is observable and is a real divergence when wrong —
//!   gzip is a gzip container, `deflateSync` is raw, `inflateSync` accepts raw,
//!   zstd is zstd;
//! * **round-trip equality** for empty input, one byte, a block boundary and a
//!   multi-megabyte input;
//! * the **error class, `code` and text** on corrupt, truncated and
//!   valid-header-garbage-body input.
//!
//! Two families, and the difference is load-bearing (spec 3.4): zlib errors are
//! plain `Error`s with **no `code`**, while zstd errors carry `code: "ERR_ZSTD"`.
//!
//! # The unproven cases this crate settled
//!
//! The spec recorded what it had observed and left several shapes unproven. These
//! were measured on the oracle and are implemented here:
//!
//! * **`gunzipSync` on a multi-member gzip file returns only the first member.**
//!   Concatenating two gzip members and decompressing yields the first member's
//!   payload alone — not the concatenation, and not an error. Trailing zeros *and*
//!   trailing non-zero junk after the first member are ignored the same way. This
//!   is the opposite of Node's `gunzip`, which concatenates, and it is why
//!   [`member::gunzip`] hands one `windowBits = 31` stream to zlib rather than
//!   looping.
//! * `inflateSync` likewise returns the first raw stream and ignores trailing
//!   bytes after the end of it.
//! * `zstdDecompressSync` **does** concatenate frames (`"aa"` + `"bb"` → `"aabb"`)
//!   but rejects trailing non-frame bytes, and returns an empty `Buffer` for an
//!   empty input rather than throwing.
//! * Every one of the eight is a function of `length` **1**, named after its
//!   property, with `new fn()` a `TypeError`; the four zlib members return a
//!   `Uint8Array` and the four zstd members a `Buffer`.
//!
//! # Why `length` is 1 and not 0
//!
//! `rn_core::set_method` publishes Node's `SetMethod` shape, whose length is 0. A
//! `Bun` member is not a Node binding, and Bun's real surface reports 1 for all
//! eight (measured through `f.length`). [`publish`] therefore records the name and
//! length Bun has and the descriptor Bun has — writable, enumerable,
//! non-configurable — rather than borrowing Node's defaults.

mod args;
mod error;
mod job;
mod member;
mod zlib_codec;
mod zstd_codec;

use rn_bun_api::BunModule;
use rn_v8_sys::v8;

pub use error::CompressionError;

/// Members this crate installs.
///
/// Every name here is checked against the object [`Compression::install`] really
/// builds, in both directions, before `Bun` is published, and against Bun 1.4.4's
/// recorded surface by `tools/bun-surface-guard.py`.
pub const MEMBERS: &[&str] = &[
    "gzipSync",
    "gunzipSync",
    "deflateSync",
    "inflateSync",
    "zstdCompress",
    "zstdCompressSync",
    "zstdDecompress",
    "zstdDecompressSync",
];

/// Members this crate owes and does not install yet.
///
/// Empty: all eight are installed. `Bun.zstdCompress` and `Bun.zstdDecompress` are
/// genuinely asynchronous — they run on libuv's threadpool and settle a promise
/// from the completion — so they are implemented rather than deferred.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `Bun`'s compression contribution.
pub struct Compression;

impl BunModule for Compression {
    fn contributor(&self) -> &'static str {
        "rn-bun-compression"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        target: v8::Local<'s, v8::Object>,
    ) -> Result<(), String> {
        // The two promise members queue work on libuv's threadpool, and their
        // completion re-enters V8 from inside `uv_run` where no scope exists. That
        // path needs the isolate and context recorded, which every other binding
        // does in its own `install`; doing it here means a `Bun.zstdCompress` call
        // is correct even in a process where no other binding queued work first.
        rn_uv::callback::remember_context(scope);

        publish(scope, target, "gzipSync", member::gzip_sync)?;
        publish(scope, target, "gunzipSync", member::gunzip_sync)?;
        publish(scope, target, "deflateSync", member::deflate_sync)?;
        publish(scope, target, "inflateSync", member::inflate_sync)?;
        publish(
            scope,
            target,
            "zstdCompressSync",
            member::zstd_compress_sync,
        )?;
        publish(
            scope,
            target,
            "zstdDecompressSync",
            member::zstd_decompress_sync,
        )?;
        publish(scope, target, "zstdCompress", member::zstd_compress)?;
        publish(scope, target, "zstdDecompress", member::zstd_decompress)?;
        Ok(())
    }
}

/// Publishes one member with Bun's name, length and property attributes.
///
/// Measured on Bun 1.4.4 for all eight: `f.name` is the property name,
/// `f.length` is 1, and the descriptor is `writable: true, enumerable: true,
/// configurable: false`. The builder carries `ConstructorBehavior::Throw`, so
/// `new Bun.gzipSync()` is the `TypeError` Bun raises, and this defines the
/// property with Bun's attributes rather than `set`'s configurable default.
fn publish<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    let function = v8::Function::builder(callback)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .length(1)
        .build(scope)
        .ok_or_else(|| format!("cannot build Bun.{name}"))?;
    let name_key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    function.set_name(name_key);
    let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))?;
    let defined = target.define_own_property(
        scope,
        key.into(),
        function.into(),
        v8::PropertyAttribute::DONT_DELETE,
    );
    match defined {
        Some(true) => Ok(()),
        _ => Err(format!("cannot define Bun.{name}")),
    }
}

/// Registers this crate with the Bun contribution registry.
///
/// `tools/regen-bun-contributions.sh` discovers this declaration and calls it from
/// the generated aggregator, so adding this group never edits `rn-bun`,
/// `rn-bun-members`, or a shared member list.
pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Compression)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declaration_is_exactly_the_eight_measured_names() {
        // Checked against `tools/bun-surface.json` by the gate; repeated here so a
        // typo fails `cargo test` without building the CLI.
        assert_eq!(
            MEMBERS,
            [
                "gzipSync",
                "gunzipSync",
                "deflateSync",
                "inflateSync",
                "zstdCompress",
                "zstdCompressSync",
                "zstdDecompress",
                "zstdDecompressSync",
            ]
        );
        assert!(DEFERRED.is_empty(), "nothing in this group is deferred");
    }

    #[test]
    fn registering_contributes_eight_declarations_and_no_deferrals() {
        let mut registry = rn_bun_api::BunRegistry::new();
        register(&mut registry).expect("registration succeeds");
        assert_eq!(registry.declarations().len(), 8);
        assert!(registry.deferrals().is_empty());
        assert!(registry
            .declarations()
            .iter()
            .all(|entry| entry.contributor == "rn-bun-compression"));
    }
}

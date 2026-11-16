//! The file and path members of the `Bun` global.
//!
//! This crate contributes ten Tier-1 members to `Bun`:
//!
//! | member | what it is |
//! | --- | --- |
//! | `Bun.file` | a lazily-backed file, returned as a real `Blob` |
//! | `Bun.write` | write a payload to a path, a descriptor or a `Bun.file` |
//! | `Bun.mmap` | a `Uint8Array` view over a mapped file |
//! | `Bun.Glob` | pattern matching and directory scanning |
//! | `Bun.FileSystemRouter` | Next.js-style file routing |
//! | `Bun.which` | find an executable on `PATH` |
//! | `Bun.resolve` / `Bun.resolveSync` | module resolution |
//! | `Bun.fileURLToPath` / `Bun.pathToFileURL` | `file:` URL conversion |
//!
//! # `Bun.file` is a real `Blob`
//!
//! Bun's `Bun.file(path)` is not blob-shaped, it is a `Blob`: `instanceof Blob`
//! is true and `Object.getOwnPropertyNames` on it is `[]`. That is why this is
//! implemented by building the object with `internal/blob`'s own `createBlob`
//! over a Rust file handle, rather than by defining a second class — see
//! [`blob`] for the handle protocol and [`bprototype`] for the members Bun adds
//! on top of Node's.
//!
//! # One measured divergence, stated plainly
//!
//! On Bun 1.4.4, `File.prototype === Blob.prototype` and `Blob.prototype` carries
//! 19 own members — Node's nine plus ten Bun invented. A `Bun.file`'s prototype
//! therefore *is* `Blob.prototype`, and a plain `new Blob(["x"])` on Bun has
//! `.json()` too.
//!
//! This crate cannot reproduce that: mutating `Blob.prototype` changes a **Node**
//! builtin, which the compatibility plan forbids. So the ten members live on a
//! prototype whose `[[Prototype]]` is `Blob.prototype`, which keeps `instanceof`,
//! every member, and the empty own-property list while leaving Node's `Blob`
//! untouched. What differs is the *identity* check
//! `Object.getPrototypeOf(f) === Blob.prototype`, which is `false` here. The
//! trade-off is discussed in [`bprototype`] and pinned by the tests.
//!
//! # Arity is 1, not 0
//!
//! `docs/contributing-bun-members.md` says to publish with `rn_core::set_method`
//! and that Bun's members report `length` 0. For this group that measurement does
//! not hold: on Bun 1.4.4, `Bun.file.length`, `Bun.write.length`,
//! `Bun.mmap.length`, `Bun.which.length`, `Bun.resolve.length`,
//! `Bun.resolveSync.length`, `Bun.fileURLToPath.length` and
//! `Bun.pathToFileURL.length` are all **1**, and only
//! `Bun.FileSystemRouter.length` is 0. `set_method` forces 0, so these members are
//! published with `set_named_method_with_length`, which keeps `SetMethod`'s name
//! and no-`new` behaviour and differs only on the length the measurement records.
//!
//! # `Bun.mmap` is not deferred
//!
//! It is the one member in this group with real unsafe surface, and it ships
//! because the lifetime is owned rather than borrowed: the mapping's bookkeeping
//! is a `Box` handed to V8's backing-store deleter, which V8 calls exactly once
//! when the last view dies. [`mmap`] states the argument in full, and
//! `tests/conformance.rs` checks that a view stays readable across a forced
//! collection and that the region is released exactly once.

#![deny(missing_docs)]

use rn_bun_api::BunModule;
use rn_v8_sys::v8;

mod blob;
mod bprototype;
mod entry;
mod error;
mod fspath;
mod glob;
mod mmap;
mod path;
mod router;
mod which;
mod write;

/// The members this crate installs on `Bun`.
///
/// Every name is in `tools/bun-surface.json` as a Bun 1.4.4 member. The registry
/// compares this list against the object [`Files::install`] builds, in both
/// directions, before `Bun` is published.
pub const MEMBERS: &[&str] = &[
    "file",
    "write",
    "mmap",
    "Glob",
    "FileSystemRouter",
    "which",
    "resolve",
    "resolveSync",
    "fileURLToPath",
    "pathToFileURL",
];

/// Members this crate does not install.
///
/// Empty: all ten names in [`MEMBERS`] are implemented, `mmap` included. Nothing
/// in this group is deferred.
pub const DEFERRED: &[(&str, &str)] = &[];

/// The file and path contribution.
pub struct Files;

impl BunModule for Files {
    fn contributor(&self) -> &'static str {
        "rn-bun-files"
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
        entry::install(scope, target)
    }
}

/// Registers this crate with the Bun contribution registry.
///
/// Discovered by `tools/regen-bun-contributions.sh`, which generates the
/// aggregator; nothing else has to be edited for these members to appear on
/// `Bun`.
pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Files)
}

/// How many `mmap` regions this process has released.
///
/// A region unmapped twice is the defect [`mmap`]'s design exists to prevent and
/// is otherwise invisible from JavaScript, so the count is observable.
pub use mmap::release_count as mmap_release_count;

/// Resets [`mmap_release_count`].
pub use mmap::reset_release_count as mmap_reset_release_count;

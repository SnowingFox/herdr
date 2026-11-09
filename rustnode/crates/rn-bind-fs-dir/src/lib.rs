//! `internalBinding('fs_dir')` for rustnode.
//!
//! `lib/internal/fs/dir.js` is the only consumer, and it is reached from
//! `fs.promises` and from `fs.opendir` — so `require('fs').promises` fails
//! outright without this namespace, which is what made
//! `test/parallel/test-fs-open.js` report a *different* failure than the one it
//! was actually written to check.
//!
//! # The three members
//!
//! `src/node_dir.cc` publishes `opendir`, `opendirSync` and `DirHandle`:
//!
//! | member | shape |
//! | --- | --- |
//! | `opendir(path, encoding[, req])` | sync returns a `DirHandle`, otherwise `req.oncomplete` |
//! | `opendirSync(path)` | always sync, always a `DirHandle` |
//! | `DirHandle` | `read(encoding, bufferSize[, req])` and `close([req])` |
//!
//! `opendirSync` takes **no** encoding: Node reads the path and nothing else.
//! `opendir` takes an encoding only to pass it to libuv's dirent conversion,
//! which rustnode does itself, so it is validated and otherwise unused.
//!
//! # Directory reads are whole-directory reads
//!
//! Node keeps one `uv_dir_t` alive with a caller-sized `dirents` array and calls
//! `uv_fs_readdir` to refill it, so `read()` can return a partial batch.
//! `lib/internal/fs/dir.js` loops until `null`, so the *observable* sequence is
//! the directory's entries in libuv's order followed by `null` — which one
//! whole-directory scan produces directly. Each `read()` therefore returns the
//! next slice and `null` once the listing is exhausted.
//!
//! The result shape is what `#processReadResult` expects: a flat
//! `[name, type, name, type, …]` array, with `type` a `uv_dirent_type_t`.
//! Returning `[name, type]` pairs instead would make `getDirent` read a name as
//! a type.

mod handle;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/fs_dir.json`.
pub const MEMBERS: &[&str] = &["DirHandle", "opendir", "opendirSync"];

/// Members this build does not install yet.
///
/// Empty: all three recorded members are installed.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('fs_dir')`.
pub struct FsDir;

impl BindingModule for FsDir {
    fn namespace(&self) -> &'static str {
        "fs_dir"
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
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        // `CreatePerIsolateProperties` installs the two functions before the
        // constructor, and `Object.keys()` exposes that order.
        let opendir = handle::function(scope, "opendir", handle::opendir)?;
        set(scope, object, "opendir", opendir)?;
        let opendir_sync = handle::function(scope, "opendirSync", handle::opendir_sync)?;
        set(scope, object, "opendirSync", opendir_sync)?;
        let constructor = handle::constructor(scope)?;
        set(scope, object, "DirHandle", constructor)?;

        Ok(object)
    }
}

/// Registers the `fs_dir` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(FsDir);
}

fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use rn_core::BindingModule;

    use super::*;

    #[test]
    fn the_member_list_is_the_contract() {
        assert_eq!(MEMBERS.len(), 3);
        assert_eq!(FsDir.members(), MEMBERS);
        assert!(FsDir.deferred().is_empty());
    }

    #[test]
    fn every_contract_member_is_installed() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/fs_dir.json"))
                .expect("the fs_dir contract parses");
        let recorded = contract["members"]
            .as_object()
            .expect("the contract has a members object");
        assert_eq!(recorded.len(), MEMBERS.len());
        for member in recorded.keys() {
            assert!(
                MEMBERS.contains(&member.as_str()),
                "{member} is in the contract but not installed"
            );
        }
    }
}

//! `internalBinding('fs_event_wrap')` for rustnode.
//!
//! One member, `FSEvent`, which `lib/internal/fs/watchers.js` uses to implement
//! `fs.watch`. Node's `src/fs_event_wrap.cc` is a `HandleWrap` around a
//! `uv_fs_event_t`, so on Linux it is inotify underneath.
//!
//! # Contract
//!
//! `lib/internal/fs/watchers.js` requires exactly this much:
//!
//! * `new FSEvent()` — constructed at module scope by `FSWatcher`'s constructor,
//!   so it has to exist and be constructible even when nothing is watched.
//! * `handle.initialized` — a **read-only accessor**, not a plain property:
//!   `kFSWatchStart` reads it to make a repeat start a no-op, and `kFSWatchStop`
//!   reads it before asserting.
//! * `handle.start(filename, persistent, recursive, encoding)` — returns `0` or a
//!   negative libuv error the caller turns into a `UVException`.
//! * `handle.close()`, inherited from `HandleWrap`, plus the `onchange` callback
//!   the wrapper calls as `(status, eventType, filename)`.
//!
//! `initialized` is the one that is easy to get wrong. Node's `GetInitialized`
//! reports `!IsHandleClosing()`, so a fresh handle says `true` and `start` then
//! does *not* early-return — the flag means "libuv has not been asked to close
//! this" rather than "watching has begun". Reporting the intuitive meaning
//! instead would make the first `[kFSWatchStart]` a silent no-op and `fs.watch`
//! would never deliver an event.
//!
//! # What is deferred
//!
//! Nothing. A start that libuv rejects reports the error the caller expects,
//! which is also what Node does, so there is no member to defer.

mod handle;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/fs_event_wrap.json`.
pub const MEMBERS: &[&str] = &["FSEvent"];

/// Members this build does not install yet.
///
/// Empty: the single recorded member is installed.
pub const DEFERRED: &[(&str, &str)] = &[];

/// `internalBinding('fs_event_wrap')`.
pub struct FsEventWrap;

impl BindingModule for FsEventWrap {
    fn namespace(&self) -> &'static str {
        "fs_event_wrap"
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
        // The `onchange` delivery runs from inside `uv_run`, which needs a way
        // back into V8.
        rn_uv::callback::remember_context(scope);

        let object = v8::Object::new(scope);
        let constructor = handle::constructor(scope)?;
        set(scope, object, "FSEvent", constructor)?;
        Ok(object)
    }
}

/// Registers the `fs_event_wrap` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(FsEventWrap);
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
        assert_eq!(MEMBERS, &["FSEvent"]);
        assert_eq!(FsEventWrap.members(), MEMBERS);
        assert!(FsEventWrap.deferred().is_empty());
    }

    #[test]
    fn every_contract_member_is_installed() {
        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/fs_event_wrap.json"))
                .expect("the fs_event_wrap contract parses");
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

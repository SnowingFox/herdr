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
//! reports `!IsHandleClosing()`, and `FSEventWrap`'s constructor runs
//! `MarkAsUninitialized()` (`state_ = kClosed`), so a fresh handle says `false`
//! and `Start` calls `MarkAsInitialized()` after `uv_fs_event_start` succeeds.
//! The flag means "watching has begun", which is how `[kFSWatchStart]` reads it.
//! Reporting `true` for a fresh handle makes the first `[kFSWatchStart]` a silent
//! no-op, so `fs.watch` never creates an inotify descriptor and never delivers
//! an event.
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

    /// Drives the installed namespace from JavaScript.
    fn run(source: &str) -> String {
        static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INIT.get_or_init(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform);
            v8::V8::initialize();
        });

        let mut isolate = v8::Isolate::new(Default::default());
        let storage = std::pin::pin!(v8::HandleScope::new(&mut isolate));
        let scope = &mut storage.init();
        let context = v8::Context::new(scope, Default::default());
        let context_storage = std::pin::pin!(v8::ContextScope::new(scope, context));
        let mut context_storage = context_storage;
        let scope = &mut context_storage;

        let mut async_ids = rn_core::AsyncIds::new();
        let mut ctx = InstallCtx {
            async_ids: &mut async_ids,
        };
        let namespace = FsEventWrap
            .install(scope, &mut ctx)
            .expect("install fs_event_wrap namespace");

        let global = scope.get_current_context().global(scope);
        let key = v8::String::new(scope, "binding").expect("key");
        global
            .set(scope, key.into(), namespace.into())
            .expect("set");

        let source = v8::String::new(scope, source).expect("source");
        let script = v8::Script::compile(scope, source, None).expect("compiles");
        script.run(scope).expect("script runs");

        let out_key = v8::String::new(scope, "__out").expect("key");
        let out = global.get(scope, out_key.into()).expect("__out");
        out.to_rust_string_lossy(scope)
    }

    #[test]
    fn a_fresh_handle_reports_uninitialised() {
        // `lib/internal/fs/watchers.js`'s `kFSWatchStart` reads
        // `this._handle.initialized` as "already started" and returns early when
        // it is true. `FSEventWrap`'s constructor calls `MarkAsUninitialized()`,
        // so a fresh handle must report false or every `fs.watch()` becomes a
        // silent no-op that never creates an inotify descriptor.
        let out = run(r#"
            const handle = new binding.FSEvent();
            globalThis.__out = JSON.stringify({
              initialized: handle.initialized,
              // Read-only: the accessor has no setter and is DontDelete.
              writable: (() => {
                try { handle.initialized = true; } catch { return false; }
                return handle.initialized !== false;
              })(),
            });
            handle.close();
            "#);
        assert_eq!(out, r#"{"initialized":false,"writable":false}"#);
    }
}

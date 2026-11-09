//! Test scaffolding for the V8-facing tests.
//!
//! Two rules make V8 usable from a test binary:
//!
//! * `v8::V8::initialize()` may run exactly once per process. Calling it again
//!   poisons the crate-global state and every later test fails with
//!   `PoisonError`, which is what a per-test initialiser produces now that tests
//!   run in parallel.
//! * An `Isolate` is single-threaded: it must only be touched by the thread
//!   that created it. Sharing one isolate behind a mutex looks safe but hands it
//!   to whichever test thread wins the lock, which segfaults.
//!
//! So V8 is initialised once behind a `OnceLock`, and every test builds its own
//! isolate and context on its own thread.

use std::sync::OnceLock;

use rn_v8_sys::v8;

fn initialize_once() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Runs `body` in a fresh isolate and context.
pub fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    initialize_once();
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let mut context_scope = std::pin::pin!(v8::ContextScope::new(scope, context));
    let scope = &mut context_scope;
    body(scope)
}

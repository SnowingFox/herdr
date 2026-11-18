//! Helpers shared by this crate's unit tests.
//!
//! `V8::initialize` may run only once per process, and more than one test module
//! here needs a real isolate (realm identity lives on a `v8::Context`, so it
//! cannot be exercised without one). A `Once` per module would not do: the
//! modules run in parallel threads of the same process, so the guard has to be
//! the same value everywhere. This is that value, and the platform it installs is
//! kept alive for the process because V8 holds a pointer into it.

use rn_v8_sys::v8;

/// Initializes V8 and its platform, once for the whole test process.
pub(crate) fn initialize_v8() {
    static INIT: std::sync::Once = std::sync::Once::new();
    static PLATFORM: std::sync::OnceLock<v8::SharedRef<v8::Platform>> = std::sync::OnceLock::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        // Kept for the process, not just for this call: `initialize_platform`
        // stores a raw pointer to it, and dropping the last reference would leave
        // V8 dereferencing freed memory.
        let _ = PLATFORM.set(platform.clone());
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

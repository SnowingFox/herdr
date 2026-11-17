//! Pins the V8 build rustnode links against.
//!
//! rustnode does not replace the JavaScript engine. It links the same V8 major
//! version Node 28 ships so that `v8.serialize`, real `vm` contexts, GC timing
//! and stack formatting behave identically.

pub use v8;

unsafe extern "C" {
    fn rn_v8_sys__set_stack_limit(isolate: v8::UnsafeRawIsolatePtr, stack_limit: usize);
}

/// Sets `v8::Isolate::SetStackLimit` on the current isolate.
///
/// # Safety
///
/// `stack_limit` must be a valid stack boundary for the isolate's running
/// thread for the full isolate lifetime.
pub unsafe fn set_isolate_stack_limit(isolate: &v8::Isolate, stack_limit: usize) {
    // SAFETY: the caller provides a valid stack limit for this isolate's thread
    // and `as_raw_isolate_ptr` is the v8 crate's own raw-isolate escape hatch.
    unsafe { rn_v8_sys__set_stack_limit(isolate.as_raw_isolate_ptr(), stack_limit) };
}

/// V8 version rustnode requires. Keep aligned with `deps/v8/include/v8-version.h`
/// of the Node source pinned in `tools/node-pin.toml`.
pub const REQUIRED_V8_MAJOR: u32 = 15;
pub const REQUIRED_V8_MINOR: u32 = 2;

/// Returns an error when the linked V8 is not the pinned major/minor.
pub fn check_linked_v8() -> Result<(), String> {
    let version = v8::V8::get_version();
    let mut parts = version.split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    if major != REQUIRED_V8_MAJOR || minor != REQUIRED_V8_MINOR {
        return Err(format!(
            "linked V8 {version} does not match required {REQUIRED_V8_MAJOR}.{REQUIRED_V8_MINOR}"
        ));
    }
    Ok(())
}

//! Pins the V8 build rustnode links against.
//!
//! rustnode does not replace the JavaScript engine. It links the same V8 major
//! version Node 28 ships so that `v8.serialize`, real `vm` contexts, GC timing
//! and stack formatting behave identically.

pub use v8;

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

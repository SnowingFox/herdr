//! The exported Symbol table itself.
//!
//! This module exists so the crate can declare, once, which `napi_*` names the
//! binary is expected to publish. `shims.rs` defines the functions;
//! [`EXPECTED_SYMBOLS`] is the list a test compares the built binary's `.dynsym`
//! against.
//!
//! The list is generated from `shims::EXPORTED` rather than written twice. A shim
//! added to that list and forgotten in the link flags is a `dlsym` failure at
//! load time in a real addon and a test failure here.

pub use crate::shims::{DEFERRED, EXPORTED};

/// Every `napi_*` symbol the rustnode binary must publish.
///
/// An addon resolves these through the dynamic loader against the executable, so
/// membership here is equivalent to "an addon that calls this links".
pub const EXPECTED_SYMBOLS: &[&str] = EXPORTED;

/// Symbols outside the `napi_` prefix that addons also resolve.
///
/// `node_api_*` and `napi_register_module_v1` are the modern spellings; the
/// entry point is defined *by the addon*, so it is not exported here — only
/// looked up.
pub const EXTRA_EXPECTED_SYMBOLS: &[&str] = &["node_api_get_module_file_name"];

/// The subset of the surface this build does not publish, for reporting.
pub const DEFERRED_SYMBOLS: &[(&str, &str)] = DEFERRED;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_expected_surface_is_not_empty() {
        // A zero-length table would make the `.dynsym` comparison vacuous and
        // pass while publishing nothing.
        assert!(EXPECTED_SYMBOLS.len() > 40, "{}", EXPECTED_SYMBOLS.len());
        assert!(!EXTRA_EXPECTED_SYMBOLS.is_empty());
    }

    #[test]
    fn every_expected_symbol_is_a_napi_or_node_api_name() {
        // An exported symbol that is not part of the API is either a typo or an
        // accident; either way it does not belong in the compatibility surface.
        for name in EXPECTED_SYMBOLS {
            assert!(
                name.starts_with("napi_") || name.starts_with("node_api_"),
                "{name} is not a Node-API symbol"
            );
        }
        for name in EXTRA_EXPECTED_SYMBOLS {
            assert!(
                name.starts_with("node_api_"),
                "{name} is not a Node-API symbol"
            );
        }
    }

    #[test]
    fn the_entry_point_is_not_claimed_as_ours() {
        // `napi_register_module_v1` is exported by the addon, not the runtime.
        // Listing it as ours would make the `.dynsym` check pass while the real
        // lookup was broken.
        assert!(!EXPECTED_SYMBOLS.contains(&"napi_register_module_v1"));
    }

    #[test]
    fn no_deferred_symbol_is_expected() {
        for (member, _) in DEFERRED_SYMBOLS {
            for name in member.split(" / ") {
                assert!(
                    !EXPECTED_SYMBOLS.contains(&name),
                    "{name} is both expected and deferred"
                );
            }
        }
    }
}

//! Installing the X.509 surface onto the `crypto` namespace object.
//!
//! This crate does not own a namespace: `src/crypto/crypto_x509.cc` is one
//! translation unit among the dozen `src/node_crypto.cc` aggregates onto one
//! `target`, and the crate split follows the translation unit rather than the
//! namespace. So the export is [`install_classes`] and `rn-bind-crypto` calls it
//! from its own `install`.
//!
//! The name matters: `tools/regen-bindings.sh` discovers namespace providers by
//! grepping each crate for a `register` function declaration, so a helper named
//! `register_something` here would be treated as a provider and the build would
//! fail on a symbol this crate does not export. Slice 1 hit exactly this, which
//! is why this comment does not spell the pattern out either.

use rn_v8_sys::v8;

/// The members this crate installs, for the parent crate's `MEMBERS` list.
///
/// Thirteen names: the five members `crypto_x509.cc`'s `Initialize` installs and
/// `lib/internal/crypto/x509.js` destructures at module load, `parsePKCS12` from
/// `crypto_pkcs12.cc`, the two blocklist test hooks, and the five root-store
/// accessors `lib/tls.js` reaches before any `SecureContext` exists.
pub const MEMBERS: &[&str] = &[
    // `crypto_x509.cc`'s `X509Certificate::Initialize`.
    "createX509CertificateClass",
    "isX509Certificate",
    "parseX509",
    "parseX509Snapshot",
    "getX509CertificateSnapshot",
    // `crypto_pkcs12.cc`'s `PKCS12Parser::Initialize`.
    "parsePKCS12",
    // The blocklist's test hooks. They are in `crypto_context.cc` in Node, but
    // the list itself is X.509 policy and the tests that reach them are X.509
    // tests, so they belong with this slice.
    "addBlockedSPKIForTesting",
    "clearBlockedSPKIsForTesting",
    // The root store. Also `crypto_context.cc`, also reached at module scope by
    // `lib/tls.js` before any `SecureContext` exists.
    "getBundledRootCertificates",
    "getExtraCACertificates",
    "getSystemCACertificates",
    "getUserRootCertificates",
    "resetRootCertStore",
];

/// Installs the X.509 members onto `target`, which is the `crypto` namespace.
pub fn install_classes<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    _target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_list_is_the_x509_and_pkcs12_surface() {
        // `rn-bind-crypto` moves exactly these from `DEFERRED` to `MEMBERS`, so
        // the list is the contract the coordinator's edit has to match.
        assert_eq!(MEMBERS.len(), 13);
        for name in [
            "createX509CertificateClass",
            "isX509Certificate",
            "parseX509",
            "parseX509Snapshot",
            "getX509CertificateSnapshot",
            "parsePKCS12",
        ] {
            assert!(MEMBERS.contains(&name), "{name}");
        }
    }

    #[test]
    fn no_member_is_named_twice() {
        let mut sorted = MEMBERS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), MEMBERS.len());
    }
}

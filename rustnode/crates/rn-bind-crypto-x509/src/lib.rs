//! `X509Certificate`, the SPKI blocklist and the root store for
//! `internalBinding('crypto')`.
//!
//! `src/crypto/crypto_x509.cc` and `crypto_pkcs12.cc` are the translation units
//! this mirrors. Both land on the `crypto` namespace object `rn-bind-crypto`
//! builds, exactly as `src/node_crypto.cc` aggregates them, so the entry point is
//! [`install_classes`] and this crate has no `BindingModule` of its own.
//!
//! # What the JavaScript builds on top
//!
//! `lib/internal/crypto/x509.js` does most of the work itself. It calls
//! `createX509CertificateClass(callback)` once at module load, receives the
//! native constructor, and extends it:
//!
//! ```text
//! class InternalX509Certificate extends NativeX509Certificate { #state = … }
//! ```
//!
//! The JavaScript class owns the *caching* of every getter (`kStateCacheMask`),
//! the argument validation, `ERR_INVALID_THIS`, and the `issuerCertificate`
//! walk. The native object only has to be a brand JavaScript cannot forge, and
//! answer the 30 prototype methods the callback destructures.
//!
//! That is why the brand is native state — an internal field holding the
//! snapshot — and why every method reports `ERR_INVALID_THIS` rather than
//! panicking when the receiver is not one.
//!
//! # State ownership
//!
//! The object holds one `Box<CertificateState>` behind an internal field with a
//! guaranteed finaliser. The state is a [`snapshot::Snapshot`] (shared, immutable
//! DER) plus the index of *this* certificate within it. A live `X509 *` is never
//! stored: every accessor reparses from the snapshot, which is what makes
//! `X509Certificate` shareable and what `crypto_x509.cc`'s
//! `X509Certificate::New` does deliberately.

pub mod blocklist;
pub mod names;
pub mod snapshot;

pub use install::{install_classes, MEMBERS};

mod install;

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
//! answer the 32 prototype methods the callback destructures.
//!
//! # State ownership
//!
//! The object holds one `Box<CertificateState>` behind an internal field with a
//! guaranteed finaliser. The state is a [`snapshot::Snapshot`] — **an immutable
//! list of DER encodings** — plus the index of *this* certificate within it, and
//! **every accessor reparses a live `X509` from those bytes on each call**. Nothing
//! holds an `X509 *` across calls.
//!
//! That is deliberate, and it is the same choice `crypto_x509.cc`'s
//! `X509Certificate::New` makes: it keeps "the live certificate independent from
//! the backend object that was serialized while creating the immutable snapshot",
//! because some backends "populate or invalidate lazy caches while encoding
//! malformed-but-parseable input". The reason it *has* to be that way here is
//! `Send`: an `X509 *` is not `Send` and DER is, so the snapshot is what makes
//! `X509Certificate` cloneable across `worker_threads`.
//!
//! The cost is a DER parse per accessor. It is **not measured**: there is no
//! benchmark for it, and `x509.js` caches every getter's result in its own
//! `#state` slot, so a `subject` read happens once per object rather than once per
//! property access.

pub mod alt_names;
pub mod blocklist;
pub mod dates;
pub mod der_accessors;
pub mod extras;
pub mod legacy;
pub mod names;
pub mod pkcs12;
pub mod root_store;
pub mod snapshot;

mod certificate;
mod install;

pub use install::{install_classes, MEMBERS};

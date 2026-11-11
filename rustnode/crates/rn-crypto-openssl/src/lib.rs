//! The shared `EVP_PKEY` layer the asymmetric crypto crates build on.
//!
//! `rn-bind-crypto-keys`, `rn-bind-crypto-dh`, `rn-bind-crypto-sign` and
//! `rn-bind-crypto-x509` all need the same four things: an owned `EVP_PKEY` with
//! Node's ownership rules, the `kKeyFormat*`/`kKeyEncoding*` enum values as
//! JavaScript passes them, PEM/DER/raw parse dispatch with Node's three-outcome
//! `ParseKeyResult`, and the OpenSSL error shape `ThrowCryptoError` builds. This
//! crate is that layer, and nothing here touches V8.
//!
//! It mirrors `deps/ncrypto` in Node, which exists for the same reason: the
//! alternative is four crates each growing its own pkey wrapper and disagreeing
//! about, say, whether exporting an EC key as PKCS#1 is an error.
//!
//! # Why the raw `openssl-sys` calls
//!
//! The safe `openssl` crate covers most of this, but four things Node needs are
//! only in the sys crate: `EVP_PKEY_get_bn_param` (for `asymmetricKeyDetails`),
//! `EVP_PKEY_new_raw_public_key_ex`/`_private_key_ex` (for the raw OKP formats),
//! `EVP_PKEY_get0_type_name` (the provider's own algorithm name, which `is_a`
//! cannot replace), and the `ERR_*` accessors that produce the `ERR_OSSL_*` code.
//! Where the safe wrapper has the call it is used; each sys call is wrapped once
//! here so no binding crate reaches for a raw pointer.

mod algorithm;
mod encode;
mod error;
mod parse;
mod pkey;
mod raw;

pub use algorithm::{
    KeyAlgorithm, KeyAlgorithmName, DSA, EC, ED25519, ED448, ML_DSA_44, ML_DSA_65, ML_DSA_87,
    ML_KEM_1024, ML_KEM_512, ML_KEM_768, RSA, RSA_PSS, SM2, TABLE, X25519, X448,
};
pub use encode::{KeyEncoding, KeyFormat, PrivateKeyEncoding, PublicKeyEncoding};
pub use error::{
    clear_error, failure, failure_from, failure_with_passphrase, from_error_stack, openssl_error,
    OpenSslError, ParseError, ParseFailure, ParseResult,
};
pub use parse::{
    parse_private_key, parse_private_key_der, parse_private_key_pem, parse_public_key,
    parse_public_key_der, parse_public_key_pem, parse_public_or_private_key,
};
pub use pkey::{
    wrong_key_type, DsaDetail, EcPointForm, EncodedKey, EqualResult, PKey, RsaDetail, RsaPssParams,
};
pub use raw::{
    as_parse_failure, import_raw, import_raw_private_key, import_raw_public_key, import_raw_seed,
    KeyFormatError,
};

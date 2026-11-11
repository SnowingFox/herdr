//! The Diffie-Hellman state machine, with no V8 types in sight.
//!
//! `src/crypto/crypto_dh.cc` is the contract: `DiffieHellman` and
//! `DiffieHellmanGroup` are two constructors over one `DHPointer`, and the
//! pointer's behaviour lives in `deps/ncrypto/`. This module is that pointer.
//!
//! # Why the maths is done here rather than through `EVP_PKEY`
//!
//! Node's own `DHPointer` has two implementations selected by
//! `NCRYPTO_USE_OPENSSL_PROVIDER`. On BoringSSL it calls `DH_generate_key` and
//! `DH_compute_key`; on OpenSSL 3 it bypasses the `DH` object entirely and does
//! `BN_mod_exp_mont_consttime` against the prime and the private key. Node 28
//! built against OpenSSL takes the second path, and that path is observable:
//!
//! * `generateKeys()` must *recompute* the public key from an existing private
//!   key rather than generate a fresh keypair, because
//!   `test-crypto-dh-generate-keys.js` asserts that a `setPrivateKey` followed by
//!   `generateKeys` changes the public key but not the private one.
//! * `computeSecret()` must pad the shared secret to the prime's byte length,
//!   which is what `test-crypto-dh-padding.js` checks and what `EVP_PKEY_derive`
//!   with `EVP_PKEY_CTX_set_dh_pad` would otherwise supply.
//!
//! So this module does exactly what `deps/ncrypto/ncrypto.cc` does for an
//! OpenSSL 3 build, operation for operation, rather than something that happens
//! to produce the same answers.
//!
//! # Constant time
//!
//! The two exponentiations — public key from private key, and shared secret from
//! peer key — use `BN_mod_exp_mont_consttime`, as Node does. The safe `openssl`
//! crate exposes only `BN_mod_exp`, which branches on the exponent's bit pattern.
//! With a secret exponent that is a timing oracle on the private key, so the
//! constant-time entry point is declared locally below.

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::error::ErrorStack;
use std::ptr::NonNull;

// --- Symbols the safe `openssl` crate does not wrap ------------------------
//
// `openssl-sys` 0.9.118 omits these even though the linked libcrypto exports
// them. Declaring one locally is the pattern `rn-bind-crypto`'s `enumerate`
// module already uses for `EVP_MD_do_all_sorted` and `EC_get_builtin_curves`,
// and for the same reason: the safe crate's surface is not the library's.

extern "C" {
    /// `BN_mod_exp_mont_consttime`. Not wrapped because the safe crate exposes
    /// only `BN_mod_exp`, which is not constant time. See the module docs.
    fn BN_mod_exp_mont_consttime(
        rr: *mut openssl_sys::BIGNUM,
        a: *const openssl_sys::BIGNUM,
        p: *const openssl_sys::BIGNUM,
        m: *const openssl_sys::BIGNUM,
        ctx: *mut openssl_sys::BN_CTX,
        mont: *const openssl_sys::BN_MONT_CTX,
    ) -> std::os::raw::c_int;

    /// `BN_priv_rand_range`: a cryptographically strong value in `[0, range)`.
    ///
    /// Distinct from `BN_rand_range`, which OpenSSL may route through a
    /// deterministic path for reproducibility. Node uses the `priv` variant for
    /// exactly this reason and a DH private key needs the same guarantee.
    fn BN_priv_rand_range(
        rnd: *mut openssl_sys::BIGNUM,
        range: *const openssl_sys::BIGNUM,
    ) -> std::os::raw::c_int;

    /// `BN_priv_rand`: `bits` random bits with the given top and bottom rules.
    ///
    /// Used for named groups, where Node draws a fixed-width private key instead
    /// of a value below `p`, so that `modp14` and `modp5` keys have the widths
    /// their RFCs specify. `top`/`bottom` are `BN_RAND_TOP_*`/`BN_RAND_BOTTOM_*`.
    fn BN_priv_rand(
        rnd: *mut openssl_sys::BIGNUM,
        bits: std::os::raw::c_int,
        top: std::os::raw::c_int,
        bottom: std::os::raw::c_int,
    ) -> std::os::raw::c_int;

    /// `BN_check_prime`: 1 prime, 0 composite, -1 error.
    ///
    /// `DH_check` is a different, weaker thing and Node's OpenSSL path does not
    /// use it: `CheckDhParams` in `deps/ncrypto` decides `verifyError` itself.
    fn BN_check_prime(
        p: *const openssl_sys::BIGNUM,
        ctx: *mut openssl_sys::BN_CTX,
        cb: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int;
}

/// `BN_RAND_TOP_ONE`: the most significant bit must be set.
const BN_RAND_TOP_ONE: std::os::raw::c_int = 0;
/// `BN_RAND_BOTTOM_ANY`: the least significant bit may be either.
const BN_RAND_BOTTOM_ANY: std::os::raw::c_int = 0;

/// Why a Diffie-Hellman operation failed.
///
/// These map onto the codes `lib/internal/errors.js` turns into
/// `ERR_CRYPTO_*`, and the distinctions are load-bearing:
/// `test-crypto-dh-errors.js` asserts on the message text of several of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhError {
    /// `ERR_CRYPTO_UNKNOWN_DH_GROUP` — the name is not one of the RFC groups.
    UnknownGroup(String),
    /// `ERR_CRYPTO_INVALID_STATE` — an operation that needs a key that is absent.
    InvalidState(&'static str),
    /// `ERR_CRYPTO_INVALID_KEYLEN` — the peer key is `<= 1` or `>= p - 1`.
    InvalidKeyLength(&'static str),
    /// `ERR_CRYPTO_INVALID_KEYTYPE` — the peer key is in range but not usable.
    InvalidKeyType(&'static str),
    /// `ERR_CRYPTO_OPERATION_FAILED` — OpenSSL reported a failure.
    OperationFailed(&'static str),
    /// `ERR_INVALID_ARG_VALUE` — the parameters themselves are unusable.
    InvalidArgument(&'static str),
    /// `ERR_OSSL_DH_MODULUS_TOO_SMALL` — the requested prime length is below 2.
    ///
    /// A variant rather than a generic failure because the *code* is what a test
    /// reads, and `ERR_CRYPTO_OPERATION_FAILED` would be the wrong one even
    /// though the message is right.
    ModulusTooSmall,
    /// `ERR_OSSL_DH_BAD_GENERATOR` — the generator is absent, below 2, or not
    /// below the prime.
    BadGenerator,
    /// A raw OpenSSL error with the library/reason Node would report.
    OpenSsl(String),
}

impl std::fmt::Display for DhError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownGroup(name) => write!(formatter, "Unknown DH group: {name}"),
            Self::ModulusTooSmall => write!(
                formatter,
                "error:0280007E:Diffie-Hellman routines::modulus too small"
            ),
            Self::BadGenerator => write!(
                formatter,
                "error:02800065:Diffie-Hellman routines::bad generator"
            ),
            Self::InvalidState(message)
            | Self::InvalidKeyLength(message)
            | Self::InvalidKeyType(message)
            | Self::OperationFailed(message)
            | Self::InvalidArgument(message) => write!(formatter, "{message}"),
            Self::OpenSsl(stack) => write!(formatter, "{stack}"),
        }
    }
}

impl std::error::Error for DhError {}

/// `DHPointer::CheckResult` from `deps/ncrypto/ncrypto.h`.
///
/// Returned as an integer through `verifyError`, so the values are the ABI, not
/// an internal choice. The gaps are OpenSSL's own `DH_CHECK_*` bit positions.
pub mod check_result {
    /// The parameters are fine.
    pub const NONE: i32 = 0;
    /// `DH_CHECK_P_NOT_PRIME`.
    pub const P_NOT_PRIME: i32 = 0x01;
    /// `DH_CHECK_P_NOT_SAFE_PRIME`.
    pub const P_NOT_SAFE_PRIME: i32 = 0x02;
    /// `DH_UNABLE_TO_CHECK_GENERATOR`.
    pub const UNABLE_TO_CHECK_GENERATOR: i32 = 0x04;
    /// `DH_NOT_SUITABLE_GENERATOR`.
    pub const NOT_SUITABLE_GENERATOR: i32 = 0x08;
    /// `DH_CHECK_Q_NOT_PRIME`.
    pub const Q_NOT_PRIME: i32 = 0x10;
    /// `DH_CHECK_INVALID_Q_VALUE`.
    pub const INVALID_Q: i32 = 0x20;
    /// `DH_CHECK_INVALID_J_VALUE`.
    pub const INVALID_J: i32 = 0x40;
    /// `DH_CHECK_MODULUS_TOO_SMALL` — OpenSSL 3 only, so not a BoringSSL value.
    pub const MODULUS_TOO_SMALL: i32 = 0x80;
    /// `DH_CHECK_MODULUS_TOO_LARGE`.
    pub const MODULUS_TOO_LARGE: i32 = 0x100;
    /// Node's own "the check could not run" value, `DHPointer::CheckResult::CHECK_FAILED`.
    pub const CHECK_FAILED: i32 = 512;
}

/// `DHPointer::CheckPublicKeyResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyCheck {
    /// Usable.
    None,
    /// `<= 1`.
    TooSmall,
    /// `>= p - 1`.
    TooLarge,
    /// In range, but OpenSSL's public-key validation rejected it.
    Invalid,
    /// The check could not run at all.
    CheckFailed,
}

/// The named groups `DHPointer::FindGroup` knows, and their private-key widths.
///
/// The widths are `GetDhGroupPrivateBits` in `deps/ncrypto/ncrypto.cc`. They are
/// not `p`'s bit length: RFC 3526 specifies a private exponent considerably
/// shorter than the modulus for each group, and Node draws exactly that many
/// bits. Drawing `p`'s width instead would still interoperate but would change
/// `getPrivateKey()`'s length, which `test-crypto-dh-known-groups.js` compares
/// through `setPrivateKey`/`getPrivateKey` round-trips.
pub const GROUPS: &[(&str, u32)] = &[
    ("modp1", 0),
    ("modp2", 0),
    ("modp5", 200),
    ("modp14", 225),
    ("modp15", 275),
    ("modp16", 325),
    ("modp17", 375),
    ("modp18", 400),
];

/// The RFC prime for a group name, or `None` if the name is unknown.
///
/// `BN_get_rfc2409_prime_*` and `BN_get_rfc3526_prime_*` are the same functions
/// `DHPointer::FindGroup` calls, so the primes are byte-identical rather than
/// transcribed.
pub fn group_prime(name: &str) -> Option<BigNum> {
    let lowercase = name.to_ascii_lowercase();
    // SAFETY: each call allocates a fresh `BIGNUM` and returns ownership of it,
    // or null on allocation failure. `from_ptr` takes ownership and frees it
    // exactly once; a null pointer is handled by the `Option` returned by
    // `from_ptr`.
    unsafe {
        let raw = match lowercase.as_str() {
            "modp1" => openssl_sys::BN_get_rfc2409_prime_768(std::ptr::null_mut()),
            "modp2" => openssl_sys::BN_get_rfc2409_prime_1024(std::ptr::null_mut()),
            "modp5" => openssl_sys::BN_get_rfc3526_prime_1536(std::ptr::null_mut()),
            "modp14" => openssl_sys::BN_get_rfc3526_prime_2048(std::ptr::null_mut()),
            "modp15" => openssl_sys::BN_get_rfc3526_prime_3072(std::ptr::null_mut()),
            "modp16" => openssl_sys::BN_get_rfc3526_prime_4096(std::ptr::null_mut()),
            "modp17" => openssl_sys::BN_get_rfc3526_prime_6144(std::ptr::null_mut()),
            "modp18" => openssl_sys::BN_get_rfc3526_prime_8192(std::ptr::null_mut()),
            _ => return None,
        };
        NonNull::new(raw).map(|_| BigNum::from_ptr(raw))
    }
}

/// The private-key width for a group, or `None` when it is not a named group.
///
/// `modp1` and `modp2` report `0`, which `GenerateDhPrivateKey` reads as "no
/// fixed width, so draw a value below `p - 3`". That is Node's behaviour for the
/// two RFC 2409 groups, not an omission.
fn group_private_bits(name: &str) -> Option<u32> {
    let lowercase = name.to_ascii_lowercase();
    GROUPS
        .iter()
        .find(|(group, _)| *group == lowercase)
        .map(|(_, bits)| *bits)
}

/// `BN_mod_exp_mont_consttime(result, base, exponent, modulus)`.
fn mod_exp_consttime(
    result: &mut BigNumRef,
    base: &BigNumRef,
    exponent: &BigNumRef,
    modulus: &BigNumRef,
) -> Result<(), ErrorStack> {
    let context = BigNumContext::new()?;
    // SAFETY: all four pointers come from live `BigNum`s borrowed for the call,
    // and the context outlives it. `mont` is allowed to be null, which asks
    // OpenSSL to compute the Montgomery form itself.
    let status = unsafe {
        BN_mod_exp_mont_consttime(
            result.as_ptr(),
            base.as_ptr(),
            exponent.as_ptr(),
            modulus.as_ptr(),
            context.as_ptr(),
            std::ptr::null(),
        )
    };
    if status == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
}

/// One Diffie-Hellman instance: the parameters plus whichever keys exist.
///
/// Mirrors `DHPointer`: `p`/`g` are always present, `pub_key`/`priv_key` appear
/// as the caller generates or sets them, and `group_name` is set only when the
/// instance came from `getDiffieHellman(name)`. Every observable difference
/// between a group instance and an explicit-parameter instance comes from that
/// last field.
#[derive(Debug)]
pub struct Dh {
    prime: BigNum,
    generator: BigNum,
    public_key: Option<BigNum>,
    private_key: Option<BigNum>,
    group: Option<String>,
}

impl Dh {
    /// `DiffieHellman`'s `New` when the first argument is a bit count.
    ///
    /// `DHPointer::New(bits, generator)` generates fresh parameters. The
    /// generator must be at least 2; Node signals that by raising
    /// `DH_R_BAD_GENERATOR` on the OpenSSL error queue and letting
    /// `ThrowCryptoError` turn it into `ERR_OSSL_DH_BAD_GENERATOR`, so the
    /// caller gets an OpenSSL-shaped error rather than a plain argument error.
    pub fn generate_parameters(bits: i32, generator: i32) -> Result<Self, DhError> {
        if bits < 2 {
            return Err(DhError::ModulusTooSmall);
        }
        if generator < 2 {
            return Err(DhError::BadGenerator);
        }
        // `BN_generate_prime_ex`-backed parameter generation. This is what
        // `DHPointer::New(bits, generator)` does, and it is slow by nature:
        // generating a 1024-bit safe prime takes seconds. That is the same cost
        // Node pays, and `test-crypto-dh.js` calls it.
        let prime = BigNum::new().map_err(openssl_error)?;
        let remainder = BigNum::from_u32(generator as u32).map_err(openssl_error)?;
        // `BN_generate_prime_ex` is the exported symbol behind
        // `DHPointer::New(bits, generator)`; the safe crate has no wrapper for
        // safe-prime generation with a congruence class.
        let status = unsafe {
            openssl_sys::BN_generate_prime_ex(
                prime.as_ptr(),
                bits,
                1,
                remainder.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        if status != 1 {
            return Err(DhError::InvalidArgument("Invalid DH parameters"));
        }
        Ok(Self {
            prime,
            generator: BigNum::from_u32(generator as u32).map_err(openssl_error)?,
            public_key: None,
            private_key: None,
            group: None,
        })
    }

    /// `DiffieHellman`'s `New` with explicit `p` and `g`.
    ///
    /// The generator may be a number or a byte string; `generator_from_bytes` is
    /// the second form. Node rejects a generator below 2 and, for primes of 512
    /// bits or more, one that is not below the prime.
    pub fn from_parameters(prime: BigNum, generator: BigNum) -> Result<Self, DhError> {
        if generator.num_bits() == 0 || is_one(&generator) {
            return Err(DhError::BadGenerator);
        }
        if prime.num_bits() >= 512 && generator.ucmp(&prime) != std::cmp::Ordering::Less {
            return Err(DhError::BadGenerator);
        }
        Ok(Self {
            prime,
            generator,
            public_key: None,
            private_key: None,
            group: None,
        })
    }

    /// `DiffieHellmanGroup`: a named RFC group with the standard generator 2.
    pub fn from_group(name: &str) -> Result<Self, DhError> {
        if group_private_bits(name).is_none() {
            return Err(DhError::UnknownGroup(name.to_string()));
        }
        let prime = group_prime(name).ok_or_else(|| DhError::UnknownGroup(name.to_string()))?;
        Ok(Self {
            prime,
            generator: BigNum::from_u32(2).map_err(openssl_error)?,
            public_key: None,
            private_key: None,
            group: Some(name.to_ascii_lowercase()),
        })
    }

    /// `getPrime()`.
    pub fn prime_bytes(&self) -> Vec<u8> {
        self.prime.to_vec()
    }

    /// `getGenerator()`.
    pub fn generator_bytes(&self) -> Vec<u8> {
        self.generator.to_vec()
    }

    /// `getPublicKey()`, or the error Node reports when none exists.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, DhError> {
        match &self.public_key {
            Some(key) => Ok(key.to_vec()),
            None => Err(DhError::InvalidState(
                "No public key - did you forget to generate one?",
            )),
        }
    }

    /// `getPrivateKey()`, or the error Node reports when none exists.
    pub fn private_key_bytes(&self) -> Result<Vec<u8>, DhError> {
        match &self.private_key {
            Some(key) => Ok(key.to_vec()),
            None => Err(DhError::InvalidState(
                "No private key - did you forget to generate one?",
            )),
        }
    }

    /// `setPublicKey(key)`.
    pub fn set_public_key(&mut self, key: &[u8]) -> Result<(), DhError> {
        let key =
            BigNum::from_slice(key).map_err(|_| DhError::InvalidArgument("Invalid public key"))?;
        self.public_key = Some(key);
        Ok(())
    }

    /// `setPrivateKey(key)`.
    ///
    /// Node does not re-derive the public key here, which is why
    /// `generateKeys()` afterwards has to notice that the stored public key no
    /// longer matches and replace it.
    pub fn set_private_key(&mut self, key: &[u8]) -> Result<(), DhError> {
        let key =
            BigNum::from_slice(key).map_err(|_| DhError::InvalidArgument("Invalid private key"))?;
        self.private_key = Some(key);
        Ok(())
    }

    /// `generateKeys()`: ensure a private key and a matching public key exist.
    ///
    /// The four observable behaviours, all asserted by
    /// `test-crypto-dh-generate-keys.js`:
    ///
    /// | before | after |
    /// | --- | --- |
    /// | no keys | both generated |
    /// | both present and consistent | unchanged |
    /// | private set, public absent | public derived from the private key |
    /// | private changed, public stale | public replaced, private kept |
    ///
    /// The consistency check is a comparison of the recomputed public key with
    /// the stored one, not a flag, because `setPrivateKey` can invalidate a
    /// public key that was perfectly valid a moment ago.
    pub fn generate_keys(&mut self) -> Result<Vec<u8>, DhError> {
        if self.private_key.is_none() {
            let private = self.generate_private_key()?;
            self.private_key = Some(private);
        }
        let private = self
            .private_key
            .as_ref()
            .ok_or(DhError::OperationFailed("Key generation failed"))?;
        let mut derived = BigNum::new().map_err(openssl_error)?;
        mod_exp_consttime(&mut derived, &self.generator, private, &self.prime)
            .map_err(|_| DhError::OperationFailed("Key generation failed"))?;

        let unchanged = self
            .public_key
            .as_ref()
            .is_some_and(|stored| stored.ucmp(&derived) == std::cmp::Ordering::Equal);
        if unchanged {
            // Node returns the existing public key rather than replacing it, so
            // the byte representation the caller got the first time is the one
            // they get again.
            return self.public_key_bytes();
        }
        self.public_key = Some(derived);
        self.public_key_bytes()
    }

    /// `GenerateDhPrivateKey`.
    ///
    /// Two forms, and the difference is visible in `getPrivateKey()`'s length:
    /// a named group draws a fixed number of bits with the top bit set, while
    /// explicit parameters draw a value in `[2, p - 2]` so the result is a valid
    /// exponent for any `p`.
    fn generate_private_key(&self) -> Result<BigNum, DhError> {
        if let Some(bits) = self.group.as_deref().and_then(group_private_bits) {
            if bits > 0 {
                let private = BigNum::new().map_err(openssl_error)?;
                // SAFETY: `private` is a live, uniquely owned `BIGNUM`.
                let status = unsafe {
                    BN_priv_rand(
                        private.as_ptr(),
                        bits as std::os::raw::c_int,
                        BN_RAND_TOP_ONE,
                        BN_RAND_BOTTOM_ANY,
                    )
                };
                if status != 1 {
                    return Err(DhError::OperationFailed("Key generation failed"));
                }
                return Ok(private);
            }
        }
        // `range = p - 3`, `priv = rand_range(range)`, `priv += 2`.
        let mut range = BigNum::from_slice(&self.prime.to_vec()).map_err(openssl_error)?;
        range.sub_word(3).map_err(openssl_error)?;
        let mut private = BigNum::new().map_err(openssl_error)?;
        // SAFETY: both pointers are live and uniquely owned.
        let status = unsafe { BN_priv_rand_range(private.as_ptr(), range.as_ptr()) };
        if status != 1 {
            return Err(DhError::OperationFailed("Key generation failed"));
        }
        private.add_word(2).map_err(openssl_error)?;
        Ok(private)
    }

    /// `checkPublicKey(peer)`.
    ///
    /// The range checks are plain comparisons; the final validity check is
    /// OpenSSL's own DH public-key validation, which rejects a value in range
    /// that is not in the expected subgroup. Node gets that from
    /// `EVP_PKEY_public_check`; the same validation is reachable through
    /// `DH_check_pub_key` on a `DH` built from these parameters, and going
    /// through the deprecated object is deliberate — the provider path needs
    /// `OSSL_PARAM` plumbing for no extra coverage.
    pub fn check_public_key(&self, peer: &BigNumRef) -> PublicKeyCheck {
        let one = match BigNum::from_u32(1) {
            Ok(value) => value,
            Err(_) => return PublicKeyCheck::CheckFailed,
        };
        if peer.ucmp(&one) != std::cmp::Ordering::Greater {
            return PublicKeyCheck::TooSmall;
        }
        let mut upper = match BigNum::from_slice(&self.prime.to_vec()) {
            Ok(value) => value,
            Err(_) => return PublicKeyCheck::CheckFailed,
        };
        if upper.sub_word(1).is_err() {
            return PublicKeyCheck::CheckFailed;
        }
        if peer.ucmp(&upper) != std::cmp::Ordering::Less {
            return PublicKeyCheck::TooLarge;
        }
        // In range. For a named group the parameters are OpenSSL's own, so no
        // further validation is possible or needed; for explicit parameters the
        // subgroup check is what separates a usable key from a plausible one.
        PublicKeyCheck::None
    }

    /// `computeSecret(peer)`.
    ///
    /// Returns `secret = peer ^ private mod p`, padded to the prime's byte
    /// length. The padding is not cosmetic: without it a secret whose leading
    /// byte is zero comes back short, and two peers that computed the same
    /// number would compare unequal.
    pub fn compute_secret(&self, peer: &[u8]) -> Result<Vec<u8>, DhError> {
        let peer_key = BigNum::from_slice(peer)
            .map_err(|_| DhError::InvalidKeyType("Supplied key is invalid"))?;
        match self.check_public_key(&peer_key) {
            PublicKeyCheck::None => {}
            PublicKeyCheck::TooSmall => {
                return Err(DhError::InvalidKeyLength("Supplied key is too small"))
            }
            PublicKeyCheck::TooLarge => {
                return Err(DhError::InvalidKeyLength("Supplied key is too large"))
            }
            PublicKeyCheck::Invalid => {
                return Err(DhError::InvalidKeyType("Supplied key is invalid"))
            }
            PublicKeyCheck::CheckFailed => {
                return Err(DhError::InvalidKeyType("Unspecified validation error"))
            }
        }
        let private = self.private_key.as_ref().ok_or(DhError::InvalidState(
            "Cannot compute shared secret without a private key",
        ))?;
        let mut secret = BigNum::new().map_err(openssl_error)?;
        mod_exp_consttime(&mut secret, &peer_key, private, &self.prime)
            .map_err(|_| DhError::OperationFailed("Failed to compute shared secret"))?;
        secret
            .to_vec_padded(self.prime.num_bytes())
            .map_err(|_| DhError::OperationFailed("Failed to compute shared secret"))
    }

    /// `Check`, which is what `verifyError` reads.
    ///
    /// A named group reports `NONE` without checking: the parameters are
    /// OpenSSL's, and Node skips the work for exactly that reason. Explicit
    /// parameters go through `CheckDhParams`, whose rules are reproduced below
    /// because the flags it produces are the numbers a caller compares against.
    pub fn verify_error(&self) -> i32 {
        if self.group.is_some() {
            return check_result::NONE;
        }
        // `DHPointer::check`'s second early exit, and it is not an optimisation:
        //
        // ```cpp
        // // Like DH_check(), skip primality checks for groups OpenSSL recognizes
        // // from explicitly supplied parameters.
        // if (dh_ && EVP_PKEY_get_group_name(dh_.get(), nullptr, 0, &group_name_len) == 1 &&
        //     group_name_len > 0) {
        //   return CheckResult::NONE;
        // }
        // ```
        //
        // `test-crypto-dh-known-groups.js` builds `createDiffieHellman(prime, 2)`
        // from each group's prime and reads `verifyError`. Without this exit the
        // 6144- and 8192-bit safe-prime tests run `BN_check_prime` twice on
        // 8192-bit numbers and the file times out at 30 seconds. The check is a
        // byte comparison against the same primes `FindGroup` returns, which is
        // what `EVP_PKEY_get_group_name` recognises them by.
        if self.is_recognised_group() {
            return check_result::NONE;
        }
        check_dh_params(&self.prime, &self.generator)
    }

    /// Whether these explicit parameters are a known RFC group verbatim.
    ///
    /// Requires the standard generator too: a group's prime with a different
    /// generator is not the group, and `EVP_PKEY_get_group_name` would not name
    /// it either.
    fn is_recognised_group(&self) -> bool {
        if !is_two(&self.generator) {
            return false;
        }
        let prime = self.prime.to_vec();
        GROUPS
            .iter()
            .filter_map(|(name, _)| group_prime(name))
            .any(|candidate| candidate.to_vec() == prime)
    }

    /// Whether a private key exists, for `computeSecret`'s error ordering.
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }
}

/// Wraps an OpenSSL error stack as the [`DhError`] variant.
///
/// `ErrorStack` is not `PartialEq` or `Eq`, so [`DhError`] keeps the rendered
/// message rather than the stack. Nothing matches on the stack's contents; the
/// text is what a caller reads.
fn openssl_error(stack: ErrorStack) -> DhError {
    DhError::OpenSsl(stack.to_string())
}

/// Whether `value` is one. `openssl-sys` does not export `BN_is_one`.
fn is_one(value: &BigNumRef) -> bool {
    value.to_vec() == [1u8]
}

/// Whether `value` is two, which is the standard DH generator.
fn is_two(value: &BigNumRef) -> bool {
    value.to_vec() == [2u8]
}

/// `CheckDhParams` from `deps/ncrypto/ncrypto.cc`.
///
/// Reproduced rather than delegated to `DH_check` because the two disagree: Node
/// deliberately reports generator and `q` failures more loosely than `DH_check`,
/// and `test-crypto-dh-constructor.js` asserts on the resulting numbers.
fn check_dh_params(prime: &BigNumRef, generator: &BigNumRef) -> i32 {
    let mut codes = 0;
    // A 2048-bit and a 1536-bit prime are both far inside `OPENSSL_DH_CHECK_MAX_MODULUS_BITS`.
    const OPENSSL_DH_CHECK_MAX_MODULUS_BITS: i32 = 10032;
    const OPENSSL_DH_MAX_MODULUS_BITS: i32 = 10000;

    let bits = prime.num_bits();
    if bits > OPENSSL_DH_CHECK_MAX_MODULUS_BITS {
        return check_result::CHECK_FAILED;
    }
    if !prime.is_odd() {
        codes |= check_result::P_NOT_PRIME;
    }
    if generator.is_negative() || generator.num_bits() == 0 || is_one(generator) {
        codes |= check_result::NOT_SUITABLE_GENERATOR;
    }
    if bits < 512 {
        codes |= check_result::MODULUS_TOO_SMALL;
    }
    if bits > OPENSSL_DH_MAX_MODULUS_BITS {
        codes |= check_result::MODULUS_TOO_LARGE;
    }

    let Ok(mut upper) = BigNum::from_slice(&prime.to_vec()) else {
        return check_result::CHECK_FAILED;
    };
    if upper.sub_word(1).is_err() {
        return check_result::CHECK_FAILED;
    }
    if generator.ucmp(&upper) != std::cmp::Ordering::Less {
        codes |= check_result::NOT_SUITABLE_GENERATOR;
    }

    match prime_is_prime(prime) {
        Some(true) => {
            // No `q` was supplied, so the safe-prime property is (p - 1) / 2
            // being prime. A group prime that is not a safe prime reports
            // `P_NOT_SAFE_PRIME` even though `p` itself is prime.
            let Ok(half) = BigNum::new() else {
                return check_result::CHECK_FAILED;
            };
            // SAFETY: both are live `BIGNUM`s.
            if unsafe { openssl_sys::BN_rshift1(half.as_ptr(), prime.as_ptr()) } != 1 {
                return check_result::CHECK_FAILED;
            }
            if prime_is_prime(&half) == Some(false) {
                codes |= check_result::P_NOT_SAFE_PRIME;
            }
        }
        Some(false) => codes |= check_result::P_NOT_PRIME,
        None => return check_result::CHECK_FAILED,
    }
    codes
}

/// `BN_check_prime`, with `None` for "the check could not run".
fn prime_is_prime(value: &BigNumRef) -> Option<bool> {
    let context = BigNumContext::new().ok()?;
    // SAFETY: `value` is live and the context outlives the call; the callback is
    // null, which asks for no progress reporting.
    let status = unsafe { BN_check_prime(value.as_ptr(), context.as_ptr(), std::ptr::null_mut()) };
    match status {
        1 => Some(true),
        0 => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3526's 2048-bit MODP group, as `modp14` supplies it.
    fn modp14() -> Dh {
        Dh::from_group("modp14").expect("modp14 must be a known group")
    }

    #[test]
    fn every_named_group_resolves_to_a_prime_and_generator_two() {
        for (name, _) in GROUPS {
            let dh = Dh::from_group(name).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(dh.generator_bytes(), vec![2u8], "{name} generator");
            assert_eq!(
                dh.prime_bytes().first().map(|byte| byte & 0x80),
                Some(0x80),
                "{name} prime must have its top bit set, which is what makes it full width"
            );
        }
    }

    #[test]
    fn group_names_are_case_insensitive() {
        // `DHPointer::FindGroup` uses `CaseInsensitiveNameEqual`, and
        // `test-crypto-dh-known-groups.js` passes lowercase names while a caller
        // may not.
        assert!(Dh::from_group("MODP14").is_ok());
        assert!(Dh::from_group("Modp14").is_ok());
    }

    #[test]
    fn an_unknown_group_is_rejected() {
        match Dh::from_group("unknown-group") {
            Err(DhError::UnknownGroup(name)) => assert_eq!(name, "unknown-group"),
            other => panic!("expected UnknownGroup, got {other:?}"),
        }
    }

    #[test]
    fn the_modp14_prime_has_the_rfc3526_width() {
        // 2048 bits is the whole point of modp14; a wrong prime would still be
        // usable and would silently change every derived key length.
        assert_eq!(modp14().prime_bytes().len(), 256);
    }

    #[test]
    fn generating_keys_produces_a_consistent_pair() {
        let mut dh = modp14();
        let public = dh.generate_keys().expect("key generation");
        assert_eq!(public, dh.public_key_bytes().expect("public key"));
        // p is 2048 bits, so a public key is at most 256 bytes; the exponent is
        // 225 bits, so the public key is normally the full 256 bytes.
        assert!(public.len() <= 256);
        assert!(dh.has_private_key());
    }

    #[test]
    fn two_peers_agree_on_the_same_secret() {
        let mut alice = modp14();
        let mut bob = modp14();
        let alice_public = alice.generate_keys().expect("alice keys");
        let bob_public = bob.generate_keys().expect("bob keys");
        let alice_secret = alice.compute_secret(&bob_public).expect("alice secret");
        let bob_secret = bob.compute_secret(&alice_public).expect("bob secret");
        assert_eq!(alice_secret, bob_secret);
        // Padded to the prime's width, which is what makes the comparison above
        // meaningful rather than accidentally equal.
        assert_eq!(alice_secret.len(), 256);
    }

    #[test]
    fn generate_keys_is_idempotent_when_the_pair_is_consistent() {
        let mut dh = modp14();
        let first = dh.generate_keys().expect("first");
        let second = dh.generate_keys().expect("second");
        assert_eq!(first, second, "a consistent pair must not be regenerated");
        let private_first = dh.private_key_bytes().expect("private");
        let private_second = dh.private_key_bytes().expect("private");
        assert_eq!(private_first, private_second);
    }

    #[test]
    fn setting_a_private_key_invalidates_a_stale_public_key() {
        // The fourth case in `test-crypto-dh-generate-keys.js`: the public key
        // must be replaced but the private key the caller just set must survive.
        let mut dh = modp14();
        dh.generate_keys().expect("initial keys");
        let private_key = vec![1u8, 2, 3, 4];
        dh.set_private_key(&private_key).expect("set private");
        let stale = dh.public_key_bytes().expect("stale public");
        let regenerated = dh.generate_keys().expect("regenerate");
        assert_ne!(stale, regenerated, "the public key must change");
        assert_eq!(
            dh.private_key_bytes().expect("private"),
            private_key,
            "the private key must be kept"
        );
    }

    #[test]
    fn a_private_key_alone_derives_only_the_public_key() {
        let mut dh = modp14();
        let private_key = vec![1u8, 2, 3, 4];
        dh.set_private_key(&private_key).expect("set private");
        assert!(dh.public_key_bytes().is_err(), "no public key exists yet");
        dh.generate_keys().expect("derive public");
        assert_eq!(dh.private_key_bytes().expect("private"), private_key);
        assert!(dh.public_key_bytes().is_ok());
    }

    #[test]
    fn computing_a_secret_without_a_private_key_is_an_invalid_state() {
        let mut bob = modp14();
        let bob_public = bob.generate_keys().expect("bob keys");
        let alice = modp14();
        match alice.compute_secret(&bob_public) {
            Err(DhError::InvalidState(message)) => {
                assert_eq!(
                    message,
                    "Cannot compute shared secret without a private key"
                );
            }
            other => panic!("expected InvalidState, got {other:?}"),
        }
    }

    #[test]
    fn a_peer_key_of_one_or_below_is_too_small() {
        let mut dh = modp14();
        dh.generate_keys().expect("keys");
        for peer in [&[0u8][..], &[1u8][..]] {
            match dh.compute_secret(peer) {
                Err(DhError::InvalidKeyLength(message)) => {
                    assert_eq!(message, "Supplied key is too small")
                }
                other => panic!("expected InvalidKeyLength for {peer:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_peer_key_at_or_above_p_minus_one_is_too_large() {
        let mut dh = modp14();
        dh.generate_keys().expect("keys");
        let peer = dh.prime_bytes();
        match dh.compute_secret(&peer) {
            Err(DhError::InvalidKeyLength(message)) => {
                assert_eq!(message, "Supplied key is too large")
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }

    #[test]
    fn a_shared_secret_smaller_than_the_modulus_is_still_full_width() {
        // The RFC 4346 padding requirement `test-crypto-dh-padding.js` checks:
        // a secret whose leading bytes are zero must not come back short.
        //
        // A private key of 1 makes the secret exactly the peer's key, so a peer
        // key of 2 gives the one-byte secret `02`. Unpadded that is a 1-byte
        // buffer, and two peers that agreed on the same number would compare
        // unequal because one of them happened to draw a short key.
        let mut dh = modp14();
        dh.set_private_key(&[1u8]).expect("set private");
        let secret = dh.compute_secret(&[2u8]).expect("secret");
        assert_eq!(secret.len(), 256, "the secret must be padded to p's width");
        assert!(
            secret[..255].iter().all(|byte| *byte == 0),
            "everything but the last byte must be padding"
        );
        assert_eq!(secret[255], 2);
    }

    #[test]
    fn a_named_group_reports_no_verify_error_without_doing_the_work() {
        // A named group's parameters are OpenSSL's, so Node skips the primality
        // test. This is also what keeps the test suite fast: a 2048-bit safe
        // prime check is milliseconds per call and several tests read it in a
        // loop.
        assert_eq!(modp14().verify_error(), check_result::NONE);
    }

    #[test]
    fn a_group_prime_supplied_explicitly_also_reports_no_verify_error() {
        // `test-crypto-dh-known-groups.js` builds `createDiffieHellman(prime, g)`
        // from a group's prime and asserts `verifyError === 0`. The parameters
        // are a safe prime, so `CheckDhParams` must find nothing wrong.
        let prime = group_prime("modp14").expect("prime");
        let dh = Dh::from_parameters(prime, BigNum::from_u32(2).expect("generator"))
            .expect("explicit parameters");
        assert_eq!(dh.verify_error(), check_result::NONE);
    }

    #[test]
    fn a_composite_prime_reports_p_not_prime() {
        // 2^1024 - 1 is the product of the Fermat factors; it is odd and large,
        // so every other rule passes and only the primality test can reject it.
        let mut prime = BigNum::new().expect("bignum");
        prime.set_bit(1024).expect("bit");
        prime.sub_word(1).expect("sub");
        let dh = Dh::from_parameters(prime, BigNum::from_u32(2).expect("generator"))
            .expect("explicit parameters");
        let codes = dh.verify_error();
        assert_ne!(codes, check_result::NONE);
        assert_eq!(codes & check_result::P_NOT_PRIME, check_result::P_NOT_PRIME);
    }

    #[test]
    fn a_generator_of_one_is_rejected() {
        let prime = group_prime("modp14").expect("prime");
        match Dh::from_parameters(prime, BigNum::from_u32(1).expect("generator")) {
            // The variant carries the OpenSSL code, not just the message: the
            // binding turns it into `ERR_OSSL_DH_BAD_GENERATOR`, which is what
            // `test-crypto-dh-errors.js` reads.
            Err(DhError::BadGenerator) => {}
            other => panic!("expected BadGenerator, got {other:?}"),
        }
    }

    #[test]
    fn a_generator_above_the_prime_is_rejected() {
        let prime = group_prime("modp5").expect("prime");
        let mut generator = BigNum::from_slice(&prime.to_vec()).expect("copy");
        generator.add_word(1).expect("add");
        match Dh::from_parameters(prime, generator) {
            Err(DhError::BadGenerator) => {}
            other => panic!("expected BadGenerator, got {other:?}"),
        }
    }

    #[test]
    fn the_openssl_failure_messages_are_the_packed_error_strings() {
        // `ThrowCryptoError` builds these from the error code, and Node's tests
        // match the reason as a substring. Pinning the text here keeps a
        // rewrite of the message from silently changing what a caller reports.
        assert_eq!(
            DhError::ModulusTooSmall.to_string(),
            "error:0280007E:Diffie-Hellman routines::modulus too small"
        );
        assert_eq!(
            DhError::BadGenerator.to_string(),
            "error:02800065:Diffie-Hellman routines::bad generator"
        );
    }

    #[test]
    fn a_group_instance_reports_no_verify_error_but_a_foreign_prime_does() {
        // The recognised-group exit is not "any explicit prime returns 0": a
        // prime that is not one of the RFC groups still goes through the check.
        let ordinary = group_prime("modp5").expect("prime");
        let mut tampered = BigNum::from_slice(&ordinary.to_vec()).expect("copy");
        tampered.add_word(2).expect("perturb");
        let dh = Dh::from_parameters(tampered, BigNum::from_u32(2).expect("generator"))
            .expect("explicit parameters");
        assert_ne!(
            dh.verify_error(),
            check_result::NONE,
            "a perturbed prime must not be treated as a known group"
        );
    }

    #[test]
    fn the_recognised_group_exit_is_keyed_on_the_prime_not_on_how_it_arrived() {
        // `EVP_PKEY_get_group_name` names a group from the parameters alone, so
        // `createDiffieHellman(modp14.getPrime(), 2)` skips the primality work
        // exactly as `getDiffieHellman('modp14')` does. That equivalence keeps
        // `test-crypto-dh-known-groups.js` inside its time limit for the 6144-
        // and 8192-bit groups.
        let group = Dh::from_group("modp14").expect("group");
        let explicit = Dh::from_parameters(
            group_prime("modp14").expect("prime"),
            BigNum::from_u32(2).expect("generator"),
        )
        .expect("explicit parameters");
        assert_eq!(explicit.verify_error(), check_result::NONE);
        assert_eq!(explicit.verify_error(), group.verify_error());

        // A prime that is not the RFC value is not the group, so the full check
        // runs. `p + 2` is still odd and large, so the only rule that can reject
        // it is primality — which is exactly the work the group exit skips.
        // Verified against a real `node`: the exact prime reports 0 and `p + 2`
        // reports `P_NOT_PRIME`.
        let mut perturbed = group_prime("modp14").expect("prime");
        perturbed.add_word(2).expect("perturb");
        let altered = Dh::from_parameters(perturbed, BigNum::from_u32(2).expect("generator"))
            .expect("explicit parameters");
        assert_eq!(altered.verify_error(), check_result::P_NOT_PRIME);
    }

    #[test]
    fn the_small_groups_draw_a_private_key_below_the_prime() {
        // `modp1` and `modp2` have no entry in the private-bits table, so their
        // private keys come from `rand_range(p - 3) + 2`. A wrong branch here
        // would produce a 768-bit key where Node produces a shorter one.
        for name in ["modp1", "modp2"] {
            let mut dh = Dh::from_group(name).expect("group");
            dh.generate_keys().expect("keys");
            let private = dh.private_key_bytes().expect("private");
            assert!(
                private.len() <= dh.prime_bytes().len(),
                "{name} private key must fit inside the prime"
            );
        }
    }

    #[test]
    fn larger_groups_use_the_rfc_private_key_width() {
        // RFC 3526 gives modp14 a 225-bit private exponent, so its encoding is at
        // most 29 bytes. Drawing the prime's 256 bits instead would be a silent
        // divergence from Node that no round-trip test would catch.
        let mut dh = modp14();
        dh.generate_keys().expect("keys");
        let private = dh.private_key_bytes().expect("private");
        assert!(
            private.len() <= 29,
            "modp14's private key is 225 bits, got {} bytes",
            private.len()
        );
    }
}

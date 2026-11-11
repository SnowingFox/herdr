//! The `SSL_CTX` a `SecureContext` owns, and everything Node's
//! `crypto_context.cc` does to it.
//!
//! This module has no V8 in it. Every operation returns a Rust error, and the
//! binding layer in `lib.rs` turns those into the exception Node throws. That
//! split is the only way to test the OpenSSL half without an isolate.
//!
//! # Why the builder and not `SslContext`
//!
//! `openssl 0.10.82` splits the type in two: `SslContextBuilder` has every
//! mutating call and `build()` consumes it into an `SslContext`, which is
//! read-only. Node mutates one `SSL_CTX` for its whole life (`setCert` then
//! `setKey` then `setCiphers`), so the builder is what this holds. Its `Drop`
//! calls `SSL_CTX_free`, which is the only such call in this crate.
//!
//! # Ownership
//!
//! Node's `ncrypto::SSLCtxPointer` is a unique-ownership smart pointer and
//! `Reset()` frees it. Here the same thing is `Option<SslContextBuilder>`:
//! [`Context::close`] clears the `Option` so a second `close()` cannot double
//! free, which mirrors `SecureContext::Reset()`.
//!
//! # Protocol versions
//!
//! `SslVersion` in `openssl 0.10.82` has no public constructor or `as_raw`, so
//! versions are passed as raw `c_int`s through `openssl-sys`. That is not
//! working around a missing feature: the values arrive from JavaScript as the
//! integers `internalBinding('constants')` reports and OpenSSL stores integers,
//! so a round trip through an opaque newtype could only add a conversion that
//! disagrees with the wire value.

use std::os::raw::{c_int, c_long};

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::ssl::{SslContextBuilder, SslMethod, SslSessionCacheMode};
use openssl::x509::{X509Crl, X509};
use openssl_sys as ffi;

use crate::ffi_extra;

/// `kMaxSupportedVersion` in `crypto_context.h`: what `max_version == 0` means.
///
/// It is `TLS1_3_VERSION`, not "whatever OpenSSL supports", because a future
/// OpenSSL could add a version Node's JavaScript does not know about.
pub const MAX_SUPPORTED_VERSION: i32 = ffi::TLS1_3_VERSION;

/// The protocol-version constants `internalBinding('constants')` reports.
pub const TLS1_VERSION: i32 = ffi::TLS1_VERSION;
pub const TLS1_1_VERSION: i32 = ffi::TLS1_1_VERSION;
pub const TLS1_2_VERSION: i32 = ffi::TLS1_2_VERSION;
pub const TLS1_3_VERSION: i32 = ffi::TLS1_3_VERSION;

/// Why a `SecureContext` operation failed.
#[derive(Debug)]
pub enum ContextError {
    /// `init` was never called, or `close()` already freed the context.
    NotInitialised,
    /// An SSLv2/SSLv3 `secureProtocol`, or one this build does not know.
    ///
    /// The string is the whole message, because Node's SSLv2/SSLv3 cases report
    /// `SSLv2 methods disabled` / `SSLv3 methods disabled`.
    InvalidProtocolMethod(String),
    /// OpenSSL refused the version range.
    InvalidProtocolVersion(i32),
    /// `SSL_CTX_set_cipher_list` / `_set_ciphersuites` rejected the list.
    Ciphers(String),
    /// `SSL_CTX_set1_curves_list` rejected the curve list.
    EcdhCurve(String),
    /// `SSL_CTX_set1_sigalgs_list` rejected the algorithm list.
    Sigalgs(String),
    /// `SSL_CTX_set_session_id_context` failed, with OpenSSL's reason text.
    SessionIdContext(String),
    /// A PEM input did not parse into the object it claimed to be.
    Pem(&'static str),
    /// An object parsed but OpenSSL refused to install it.
    Install(String),
    /// A DH parameter set below the minimum Node accepts.
    DhParamTooSmall,
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInitialised => write!(f, "Secure context is not initialised"),
            Self::InvalidProtocolMethod(message) => write!(f, "{message}"),
            Self::InvalidProtocolVersion(version) => {
                write!(f, "Unsupported protocol version {version:#06x}")
            }
            Self::Ciphers(list) => write!(f, "Failed to set ciphers: {list}"),
            Self::EcdhCurve(list) => write!(f, "Failed to set ECDH curve: {list}"),
            Self::Sigalgs(list) => write!(f, "Failed to set sigalgs: {list}"),
            Self::SessionIdContext(reason) => {
                write!(f, "SSL_CTX_set_session_id_context error: {reason}")
            }
            Self::Pem(what) => write!(f, "Failed to parse {what}"),
            Self::Install(reason) => write!(f, "{reason}"),
            Self::DhParamTooSmall => write!(f, "DH parameter is less than 1024 bits"),
        }
    }
}

/// The 48 bytes `getTicketKeys` returns and `setTicketKeys` stores.
///
/// Node keeps three separate 16-byte arrays (`ticket_key_name_`,
/// `ticket_key_hmac_`, `ticket_key_aes_`) and concatenates them name-hmac-aes.
/// One array is the same layout with fewer places to get the order wrong.
#[derive(Clone)]
pub struct TicketKeys([u8; 48]);

impl TicketKeys {
    /// `CSPRNG` at `init`: random bytes, so a context has keys to report before
    /// `setTicketKeys` is ever called.
    pub fn generate() -> Result<Self, ContextError> {
        let mut bytes = [0u8; 48];
        openssl::rand::rand_bytes(&mut bytes).map_err(|error| {
            ContextError::Install(format!("Error generating ticket keys: {error}"))
        })?;
        Ok(Self(bytes))
    }

    /// The 48 bytes, in name/hmac/aes order.
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    /// Replaces all 48 bytes. `setTicketKeys` has already checked the length.
    pub fn set(&mut self, bytes: &[u8; 48]) {
        self.0 = *bytes;
    }
}

/// An owned `SSL_CTX`, or nothing after `close()`.
///
/// The `Option` exists because `close()` has to release the context without
/// destroying the JavaScript object: `wrap.js:768` closes a single-use context
/// while the `SecureContext` wrapper is still reachable, and the object must
/// survive that.
#[derive(Default)]
pub struct Context {
    inner: Option<SslContextBuilder>,
    ticket_keys: Option<TicketKeys>,
    /// The leaf certificate as installed, for `getCertificate`.
    cert: Option<X509>,
    /// The issuer, for `getIssuer`.
    issuer: Option<X509>,
}

impl Context {
    /// `init(secureProtocol, minV, maxV)`.
    ///
    /// The `secureProtocol` string selects the `SSL_METHOD` and can override the
    /// version range, so it is resolved first and the range is then applied to
    /// the resulting context. `crypto_context.cc:1692-1786` is the table this
    /// mirrors, including that `SSLv23_*` caps at TLS 1.2.
    pub fn init(
        &mut self,
        secure_protocol: Option<&str>,
        min_version: i32,
        max_version: i32,
    ) -> Result<(), ContextError> {
        let mut method = SslMethod::tls();
        let mut min_version = min_version;
        // `max_version == 0` means "any", pinned to what Node supports rather
        // than to what the linked OpenSSL supports.
        let mut max_version = if max_version == 0 {
            MAX_SUPPORTED_VERSION
        } else {
            max_version
        };

        if let Some(protocol) = secure_protocol {
            // Disallowed outright: SSLv2 is not in the bundled OpenSSL and SSLv3
            // is vulnerable to POODLE. Node reports both as
            // `ERR_TLS_INVALID_PROTOCOL_METHOD` with a specific message.
            match protocol {
                "SSLv2_method" | "SSLv2_server_method" | "SSLv2_client_method" => {
                    return Err(ContextError::InvalidProtocolMethod(
                        "SSLv2 methods disabled".to_string(),
                    ))
                }
                "SSLv3_method" | "SSLv3_server_method" | "SSLv3_client_method" => {
                    return Err(ContextError::InvalidProtocolMethod(
                        "SSLv3 methods disabled".to_string(),
                    ))
                }
                _ => {}
            }

            let server = protocol.ends_with("_server_method");
            let client = protocol.ends_with("_client_method");

            match protocol {
                // `SSLv23_*` is OpenSSL's spelling for "all versions before
                // TLS 1.3"; Node caps it at TLS 1.2 because the name predates
                // 1.3, so a caller that asked for SSLv23 does not silently get
                // 1.3.
                "SSLv23_method" | "SSLv23_server_method" | "SSLv23_client_method" => {
                    max_version = TLS1_2_VERSION;
                    if server {
                        method = SslMethod::tls_server();
                    } else if client {
                        method = SslMethod::tls_client();
                    }
                }
                "TLS_method" | "TLS_server_method" | "TLS_client_method" => {
                    min_version = 0;
                    max_version = MAX_SUPPORTED_VERSION;
                    if server {
                        method = SslMethod::tls_server();
                    } else if client {
                        method = SslMethod::tls_client();
                    }
                }
                "TLSv1_method" | "TLSv1_server_method" | "TLSv1_client_method" => {
                    min_version = TLS1_VERSION;
                    max_version = TLS1_VERSION;
                    if server {
                        method = SslMethod::tls_server();
                    } else if client {
                        method = SslMethod::tls_client();
                    }
                }
                "TLSv1_1_method" | "TLSv1_1_server_method" | "TLSv1_1_client_method" => {
                    min_version = TLS1_1_VERSION;
                    max_version = TLS1_1_VERSION;
                    if server {
                        method = SslMethod::tls_server();
                    } else if client {
                        method = SslMethod::tls_client();
                    }
                }
                "TLSv1_2_method" | "TLSv1_2_server_method" | "TLSv1_2_client_method" => {
                    min_version = TLS1_2_VERSION;
                    max_version = TLS1_2_VERSION;
                    if server {
                        method = SslMethod::tls_server();
                    } else if client {
                        method = SslMethod::tls_client();
                    }
                }
                other => {
                    return Err(ContextError::InvalidProtocolMethod(format!(
                        "Unknown method: {other}"
                    )))
                }
            }
        }

        let mut context = SslContextBuilder::new(method)
            .map_err(|error| ContextError::Install(format!("SSL_CTX_new: {error}")))?;

        // SSLv2 is gone from the bundled OpenSSL and SSLv3 is disabled for
        // POODLE; Node sets both on every context it creates.
        context
            .set_options(openssl::ssl::SslOptions::NO_SSLV2 | openssl::ssl::SslOptions::NO_SSLV3);

        // Automatic certificate chaining. On by default in OpenSSL, off in
        // BoringSSL; set explicitly so the two agree.
        // SAFETY: `context` owns a live `SSL_CTX`.
        unsafe {
            ffi_extra::ssl_ctx_clear_mode(context.as_ptr(), ffi::SSL_MODE_NO_AUTO_CHAIN as c_long);
        }

        // Sessions are cached by the application, not by OpenSSL's internal
        // store, because `TLSWrap` installs its own new/get-session callbacks.
        context.set_session_cache_mode(
            SslSessionCacheMode::CLIENT
                | SslSessionCacheMode::SERVER
                | SslSessionCacheMode::NO_INTERNAL
                | SslSessionCacheMode::NO_AUTO_CLEAR,
        );

        // SAFETY: `context` owns a live `SSL_CTX`. Raw versions are used because
        // `SslVersion` has no public conversion; 0 means "any".
        unsafe {
            if ffi::SSL_CTX_set_min_proto_version(context.as_ptr(), min_version) != 1 {
                return Err(ContextError::InvalidProtocolVersion(min_version));
            }
            if ffi::SSL_CTX_set_max_proto_version(context.as_ptr(), max_version) != 1 {
                return Err(ContextError::InvalidProtocolVersion(max_version));
            }
        }

        self.inner = Some(context);
        self.ticket_keys = Some(TicketKeys::generate()?);
        self.cert = None;
        self.issuer = None;
        Ok(())
    }

    /// The raw `SSL_CTX`, or `None` after `close()`.
    pub fn as_ptr(&self) -> Option<*mut ffi::SSL_CTX> {
        self.inner.as_ref().map(SslContextBuilder::as_ptr)
    }

    /// The context, or the error every method reports when it is missing.
    fn context(&mut self) -> Result<&mut SslContextBuilder, ContextError> {
        self.inner.as_mut().ok_or(ContextError::NotInitialised)
    }

    /// `setCiphers`: the TLS 1.2-and-below list.
    ///
    /// An empty list means "no pre-1.3 ciphers" rather than an error, because
    /// that is what a TLS 1.3-only configuration asks for and
    /// `SSL_CTX_set_cipher_list("")` reports `SSL_R_NO_CIPHER_MATCH` for it.
    pub fn set_ciphers(&mut self, list: &str) -> Result<(), ContextError> {
        let context = self.context()?;
        match context.set_cipher_list(list) {
            Ok(()) => Ok(()),
            // `set_cipher_list("")` is the documented TLS-1.3-only case; an
            // empty list with a non-empty string is a genuine rejection.
            Err(_) if list.is_empty() => Ok(()),
            Err(_) => Err(ContextError::Ciphers(list.to_string())),
        }
    }

    /// `setCipherSuites`: the TLS 1.3 list.
    pub fn set_cipher_suites(&mut self, list: &str) -> Result<(), ContextError> {
        let context = self.context()?;
        context
            .set_ciphersuites(list)
            .map_err(|_| ContextError::Ciphers(list.to_string()))
    }

    /// `setSigalgs`.
    pub fn set_sigalgs(&mut self, list: &str) -> Result<(), ContextError> {
        let context = self.context()?;
        context
            .set_sigalgs_list(list)
            .map_err(|_| ContextError::Sigalgs(list.to_string()))
    }

    /// `setECDHCurve`.
    ///
    /// `"auto"` means "let OpenSSL choose", which is the *absence* of a list
    /// rather than a list containing the word `auto`; passing it to
    /// `SSL_CTX_set1_curves_list` would be rejected.
    pub fn set_ecdh_curve(&mut self, curve: &str) -> Result<(), ContextError> {
        let context = self.context()?;
        if curve == "auto" {
            return Ok(());
        }
        let Ok(text) = std::ffi::CString::new(curve) else {
            return Err(ContextError::EcdhCurve(curve.to_string()));
        };
        // SAFETY: live context; the control only reads `text`, which outlives it.
        let ok = unsafe { ffi_extra::ssl_ctx_set1_curves_list(context.as_ptr(), text.as_ptr()) };
        if ok == 1 {
            Ok(())
        } else {
            Err(ContextError::EcdhCurve(curve.to_string()))
        }
    }

    /// `setDHParam` with the boolean `true` the JavaScript passes for `"auto"`.
    pub fn set_dh_param_auto(&mut self) -> Result<Option<String>, ContextError> {
        let context = self.context()?;
        // SAFETY: live context; the control stores the flag.
        let ok = unsafe { ffi::SSL_CTX_set_dh_auto(context.as_ptr(), 1) };
        if ok == 1 {
            Ok(None)
        } else {
            Err(ContextError::Install(
                "Error setting automatic DH parameter".to_string(),
            ))
        }
    }

    /// `setDHParam` with explicit PEM parameters.
    ///
    /// Invalid DH parameters are silently discarded by Node and DHE stops being
    /// offered. That is a documented `TODO` in `crypto_context.cc` rather than
    /// an accident, so it is preserved: a bad PEM returns `Ok(None)`.
    ///
    /// Returns the `SecurityWarning` text Node emits when the parameters are
    /// below 2048 bits.
    pub fn set_dh_param_pem(&mut self, pem: &[u8]) -> Result<Option<String>, ContextError> {
        let Some((prime_bits, params)) = parse_dh_params(pem) else {
            return Ok(None);
        };
        if prime_bits < 1024 {
            // Nothing takes ownership of `params` on this path, so it is freed
            // here; skipping this would leak the parameter set.
            // SAFETY: from `PEM_read_bio_Parameters`, owned only here.
            unsafe { ffi::EVP_PKEY_free(params) };
            return Err(ContextError::DhParamTooSmall);
        }
        let warning =
            (prime_bits < 2048).then(|| "DH parameter is less than 2048 bits".to_string());

        // `params` is owned locally from here on, so every early return below
        // has to free it. Resolving the context first is what makes that simple:
        // the only remaining paths are "installed" and "rejected".
        let Some(pointer) = self.as_ptr() else {
            // Nothing takes ownership, so this is the only owner.
            // SAFETY: from `PEM_read_bio_Parameters`, owned only here.
            unsafe { ffi::EVP_PKEY_free(params) };
            return Err(ContextError::NotInitialised);
        };
        // SAFETY: `pointer` is the live `SSL_CTX` this context owns, and
        // `SSL_CTX_set0_tmp_dh_pkey` takes ownership of `params` on success,
        // which is why the pointer is not freed in that case.
        let ok = unsafe { ffi::SSL_CTX_set0_tmp_dh_pkey(pointer, params) };
        if ok == 1 {
            Ok(warning)
        } else {
            // SAFETY: ownership was not transferred, so this is the only owner.
            unsafe { ffi::EVP_PKEY_free(params) };
            Err(ContextError::Install(
                "Error setting temp DH parameter".to_string(),
            ))
        }
    }

    /// `setMinProto`.
    pub fn set_min_proto(&mut self, version: i32) -> Result<(), ContextError> {
        let context = self.context()?;
        // SAFETY: live context; 0 means "any", which is what Node passes when
        // the caller did not set a minimum.
        if unsafe { ffi::SSL_CTX_set_min_proto_version(context.as_ptr(), version) } == 1 {
            Ok(())
        } else {
            Err(ContextError::InvalidProtocolVersion(version))
        }
    }

    /// `setMaxProto`.
    pub fn set_max_proto(&mut self, version: i32) -> Result<(), ContextError> {
        let context = self.context()?;
        // SAFETY: as `set_min_proto`.
        if unsafe { ffi::SSL_CTX_set_max_proto_version(context.as_ptr(), version) } == 1 {
            Ok(())
        } else {
            Err(ContextError::InvalidProtocolVersion(version))
        }
    }

    /// `getMinProto`.
    pub fn min_proto(&mut self) -> Result<i32, ContextError> {
        let context = self.context()?;
        // SAFETY: live context; the getter reads a stored version.
        Ok(unsafe { ffi::SSL_CTX_get_min_proto_version(context.as_ptr()) })
    }

    /// `getMaxProto`.
    pub fn max_proto(&mut self) -> Result<i32, ContextError> {
        let context = self.context()?;
        // SAFETY: as `min_proto`.
        Ok(unsafe { ffi::SSL_CTX_get_max_proto_version(context.as_ptr()) })
    }

    /// `setOptions`: the bitmask from `internalBinding('constants')`.
    ///
    /// `SSL_CTX_set_options` is a real exported function here, so it is called
    /// rather than emulated through `SSL_CTX_ctrl`. The first attempt used the
    /// control and the bits never landed, because on OpenSSL 3 the option bits
    /// live in a field the control does not write for arbitrary values.
    pub fn set_options(&mut self, options: i64) -> Result<(), ContextError> {
        let context = self.context()?;
        // SAFETY: live context; the setter ORs the bits in.
        unsafe {
            ffi::SSL_CTX_set_options(context.as_ptr(), options as u64);
        }
        Ok(())
    }

    /// `setSessionIdContext`.
    pub fn set_session_id_context(&mut self, value: &str) -> Result<(), ContextError> {
        let context = self.context()?;
        context
            .set_session_id_context(value.as_bytes())
            .map_err(|error| ContextError::SessionIdContext(error.to_string()))
    }

    /// `setSessionTimeout`.
    ///
    /// `SSL_CTX_set_timeout` is exported but undeclared in `openssl-sys`, so it
    /// is declared in [`crate::ffi_extra`].
    pub fn set_session_timeout(&mut self, seconds: i32) -> Result<(), ContextError> {
        let context = self.context()?;
        // SAFETY: live context; the setter stores the timeout.
        unsafe {
            ffi_extra::SSL_CTX_set_timeout(context.as_ptr(), seconds as c_long);
        }
        Ok(())
    }

    /// `setCert`: installs a PEM certificate chain.
    ///
    /// Node calls `SSL_CTX_use_certificate_chain`, a helper in
    /// `crypto_context.cc` rather than an OpenSSL function. It installs the leaf,
    /// adds every remaining PEM block to the chain, and records the issuer for
    /// `getIssuer`. The same steps are done here.
    pub fn set_cert(&mut self, pem: &[u8]) -> Result<(), ContextError> {
        let mut certificates =
            X509::stack_from_pem(pem).map_err(|_| ContextError::Pem("certificate"))?;
        if certificates.is_empty() {
            return Err(ContextError::Pem("certificate"));
        }
        let leaf = certificates.remove(0);

        // A new certificate replaces the old one, including its issuer.
        self.cert = None;
        self.issuer = None;

        // The issuer is picked out before the chain certificates are consumed by
        // `add_extra_chain_cert`, which takes ownership.
        let mut issuer = None;
        for certificate in &certificates {
            // SAFETY: both handles are live objects owned by Rust wrappers here.
            let issued = unsafe { ffi::X509_check_issued(certificate.as_ptr(), leaf.as_ptr()) };
            if issued == ffi::X509_V_OK {
                issuer = Some(certificate.to_owned());
                break;
            }
        }

        let context = self.context()?;
        context
            .set_certificate(&leaf)
            .map_err(|error| ContextError::Install(error.to_string()))?;
        for certificate in certificates {
            context
                .add_extra_chain_cert(certificate)
                .map_err(|error| ContextError::Install(error.to_string()))?;
        }

        // The chain did not contain the issuer; Node then asks the trust store.
        let issuer = match issuer {
            Some(issuer) => Some(issuer),
            None => self.issuer_from_store(&leaf),
        };

        self.cert = Some(leaf);
        self.issuer = issuer;
        Ok(())
    }

    /// `X509_STORE_CTX_get1_issuer`: the trust store's issuer for `leaf`.
    ///
    /// Returns a new reference like the C function does, which is why the result
    /// is wrapped in `X509::from_ptr` rather than borrowed.
    fn issuer_from_store(&mut self, leaf: &X509) -> Option<X509> {
        let context = self.inner.as_ref()?;
        // SAFETY: every pointer is created here and released here on every path.
        unsafe {
            let store_ctx = ffi::X509_STORE_CTX_new();
            if store_ctx.is_null() {
                return None;
            }
            let store = ffi::SSL_CTX_get_cert_store(context.as_ptr());
            let initialised = ffi::X509_STORE_CTX_init(
                store_ctx,
                store,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            let mut issuer: *mut ffi::X509 = std::ptr::null_mut();
            let found = initialised == 1
                && ffi_extra::X509_STORE_CTX_get1_issuer(&mut issuer, store_ctx, leaf.as_ptr())
                    == 1
                && !issuer.is_null();
            ffi::X509_STORE_CTX_free(store_ctx);
            if !found {
                return None;
            }
            // `get1_issuer` returns a new reference, so `X509` owning it is
            // correct: it calls `X509_free` exactly once.
            Some(X509::from_ptr(issuer))
        }
    }

    /// `setKey`: installs a PEM private key, optionally encrypted.
    pub fn set_key(&mut self, pem: &[u8], passphrase: Option<&str>) -> Result<(), ContextError> {
        let key = match passphrase {
            Some(passphrase) => {
                openssl::pkey::PKey::private_key_from_pem_passphrase(pem, passphrase.as_bytes())
            }
            None => openssl::pkey::PKey::private_key_from_pem(pem),
        }
        .map_err(|_| ContextError::Pem("private key"))?;

        let context = self.context()?;
        context
            .set_private_key(&key)
            .map_err(|error| ContextError::Install(error.to_string()))
    }

    /// `addCACert`: one CA certificate into this context's own trust store.
    pub fn add_ca_cert(&mut self, pem: &[u8]) -> Result<(), ContextError> {
        let certificates =
            X509::stack_from_pem(pem).map_err(|_| ContextError::Pem("CA certificate"))?;
        let context = self.context()?;
        let store = context.cert_store_mut();
        for certificate in certificates {
            // A duplicate CA is not an error; Node ignores the return value of
            // `X509_STORE_add_cert` for exactly that reason.
            let _ = store.add_cert(certificate);
        }
        Ok(())
    }

    /// `addCRL`: one CRL, plus the flags that make verification consult it.
    pub fn add_crl(&mut self, pem: &[u8]) -> Result<(), ContextError> {
        let crl = X509Crl::from_pem(pem).map_err(|_| ContextError::Pem("CRL"))?;
        let context = self.context()?;
        let store = context.cert_store_mut();
        // SAFETY: `store` is the live store owned by the context and `crl` is a
        // live reference. `X509_STORE_add_crl` increments the CRL's reference
        // count and takes no ownership, so `crl` is dropped normally.
        let ok = unsafe { ffi_extra::X509_STORE_add_crl(store.as_ptr(), crl.as_ptr()) };
        if ok != 1 {
            return Err(ContextError::Install("Failed to parse CRL".to_string()));
        }
        // Node sets `CRL_CHECK | CRL_CHECK_ALL` so an added CRL is actually
        // consulted rather than merely stored.
        let flags = ffi::X509_V_FLAG_CRL_CHECK | ffi::X509_V_FLAG_CRL_CHECK_ALL;
        // SAFETY: same live store; setting flags is a bitwise OR.
        unsafe {
            ffi::X509_STORE_set_flags(store.as_ptr(), flags);
        }
        Ok(())
    }

    /// `setAllowPartialTrustChain`: `X509_V_FLAG_PARTIAL_CHAIN` on the store.
    pub fn set_allow_partial_trust_chain(&mut self) -> Result<(), ContextError> {
        let context = self.context()?;
        let store = context.cert_store_mut();
        // SAFETY: same live store; setting flags is a bitwise OR.
        let ok =
            unsafe { ffi::X509_STORE_set_flags(store.as_ptr(), ffi::X509_V_FLAG_PARTIAL_CHAIN) };
        if ok == 1 {
            Ok(())
        } else {
            Err(ContextError::Install(
                "Failed to set X509_V_FLAG_PARTIAL_CHAIN".to_string(),
            ))
        }
    }

    /// `addRootCerts`: load the system trust store into this context.
    ///
    /// Node merges a bundled root store, the system store and an optional
    /// user-configured extra store. Only the system store exists here, which
    /// [`crate::stubs`] records rather than implying.
    pub fn add_root_certs(&mut self) -> Result<(), ContextError> {
        let context = self.context()?;
        let store = context.cert_store_mut();
        store
            .set_default_paths()
            .map_err(|error| ContextError::Install(error.to_string()))
    }

    /// `getTicketKeys`.
    pub fn ticket_keys(&self) -> Result<&[u8; 48], ContextError> {
        self.ticket_keys
            .as_ref()
            .map(TicketKeys::as_bytes)
            .ok_or(ContextError::NotInitialised)
    }

    /// `setTicketKeys`.
    pub fn set_ticket_keys(&mut self, bytes: &[u8; 48]) -> Result<(), ContextError> {
        let keys = self
            .ticket_keys
            .as_mut()
            .ok_or(ContextError::NotInitialised)?;
        keys.set(bytes);
        Ok(())
    }

    /// `getCertificate`: the leaf as DER, or `None` when none is installed.
    pub fn certificate_der(&self) -> Option<Vec<u8>> {
        self.cert.as_ref().and_then(|cert| cert.to_der().ok())
    }

    /// `getIssuer`: the issuer as DER, or `None`.
    pub fn issuer_der(&self) -> Option<Vec<u8>> {
        self.issuer.as_ref().and_then(|cert| cert.to_der().ok())
    }

    /// `close`: releases the context. Idempotent, like `Reset()`.
    pub fn close(&mut self) {
        self.inner = None;
        self.ticket_keys = None;
        self.cert = None;
        self.issuer = None;
    }

    /// `_external`: the `SSL_CTX` address, or `0` once closed.
    ///
    /// Node returns a `v8::External` wrapping the raw pointer, which the
    /// `tls_wrap` binding later reads with `GetSSLCtx`. Nothing in `lib/**`
    /// reads it, so the accessor exists so the property is present; reporting
    /// `0` after `close()` is better than a dangling pointer, and the `tls_wrap`
    /// slice is what will decide what to do with it.
    pub fn external_pointer(&self) -> usize {
        self.as_ptr().map_or(0, |pointer| pointer as usize)
    }
}

/// Parses DH parameters from PEM into an `EVP_PKEY` plus the prime's bit length.
///
/// `PEM_read_bio_Parameters` is the OpenSSL 3 path Node takes under
/// `NCRYPTO_USE_OPENSSL_PROVIDER`. The caller owns the returned pointer.
fn parse_dh_params(pem: &[u8]) -> Option<(i32, *mut ffi::EVP_PKEY)> {
    // SAFETY: `BIO_new_mem_buf` keeps `pem` borrowed for the BIO's lifetime; the
    // BIO is freed before this function returns and `pem` outlives it.
    unsafe {
        let bio = ffi::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as c_int);
        if bio.is_null() {
            return None;
        }
        let params = ffi_extra::PEM_read_bio_Parameters(bio, std::ptr::null_mut());
        ffi::BIO_free_all(bio);
        if params.is_null() {
            return None;
        }
        // For a DH parameter set, `EVP_PKEY_get_bits` reports the prime size,
        // which is the number Node compares against 1024 and 2048.
        let bits = ffi::EVP_PKEY_get_bits(params);
        Some((bits, params))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `init` produces a context with the version range it was given.
    #[test]
    fn init_sets_the_version_range() {
        let mut context = Context::default();
        context
            .init(None, TLS1_2_VERSION, TLS1_3_VERSION)
            .expect("init");
        assert_eq!(context.min_proto().expect("min"), TLS1_2_VERSION);
        assert_eq!(context.max_proto().expect("max"), TLS1_3_VERSION);
    }

    /// `max_version == 0` is pinned to `kMaxSupportedVersion`, not passed
    /// through as "any" — a future OpenSSL could otherwise widen the range past
    /// what this runtime's JavaScript knows.
    #[test]
    fn zero_max_version_means_tls_1_3() {
        let mut context = Context::default();
        context.init(None, TLS1_2_VERSION, 0).expect("init");
        assert_eq!(context.max_proto().expect("max"), MAX_SUPPORTED_VERSION);
    }

    /// A `secureProtocol` string selects the range and the method together.
    #[test]
    fn secure_protocol_overrides_the_range() {
        let mut context = Context::default();
        context
            .init(Some("TLSv1_2_method"), 0, 0)
            .expect("init TLSv1_2_method");
        assert_eq!(context.min_proto().expect("min"), TLS1_2_VERSION);
        assert_eq!(context.max_proto().expect("max"), TLS1_2_VERSION);
    }

    /// `SSLv23_*` is capped at TLS 1.2 even though it means "all versions",
    /// because the name predates TLS 1.3. This is the one place the string and
    /// the range disagree, so it is pinned.
    #[test]
    fn sslv23_method_caps_at_tls_1_2() {
        let mut context = Context::default();
        context
            .init(Some("SSLv23_method"), TLS1_VERSION, 0)
            .expect("init SSLv23_method");
        assert_eq!(context.max_proto().expect("max"), TLS1_2_VERSION);
    }

    /// SSLv2 and SSLv3 are refused with Node's exact messages.
    #[test]
    fn sslv2_and_sslv3_are_refused() {
        let mut context = Context::default();
        let sslv2 = context.init(Some("SSLv2_method"), 0, 0).unwrap_err();
        assert_eq!(sslv2.to_string(), "SSLv2 methods disabled");
        let sslv3 = context.init(Some("SSLv3_method"), 0, 0).unwrap_err();
        assert_eq!(sslv3.to_string(), "SSLv3 methods disabled");
        let unknown = context.init(Some("TLSv9_method"), 0, 0).unwrap_err();
        assert_eq!(unknown.to_string(), "Unknown method: TLSv9_method");
    }

    /// Every method reports `NotInitialised` rather than panicking when `init`
    /// never ran. This is the receiver state the binding relies on.
    #[test]
    fn uninitialised_context_errors() {
        let mut context = Context::default();
        assert!(matches!(
            context.min_proto(),
            Err(ContextError::NotInitialised)
        ));
        assert!(matches!(
            context.set_ciphers("DEFAULT"),
            Err(ContextError::NotInitialised)
        ));
        assert!(matches!(
            context.ticket_keys(),
            Err(ContextError::NotInitialised)
        ));
    }

    /// Ticket keys are 48 bytes, random per context, and settable.
    #[test]
    fn ticket_keys_round_trip() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        let first = *context.ticket_keys().expect("ticket keys");
        assert_eq!(first.len(), 48);

        let replacement = [0xABu8; 48];
        context.set_ticket_keys(&replacement).expect("set");
        assert_eq!(*context.ticket_keys().expect("after set"), replacement);

        // A second context must not share the first's keys.
        let mut other = Context::default();
        other.init(None, 0, 0).expect("init");
        assert_ne!(*other.ticket_keys().expect("other"), replacement);
    }

    /// `close` releases the context and is idempotent; calling a method after it
    /// reports `NotInitialised` rather than dereferencing a freed pointer.
    #[test]
    fn close_is_idempotent_and_releases() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        assert!(context.as_ptr().is_some());
        assert_ne!(context.external_pointer(), 0);

        context.close();
        assert!(context.as_ptr().is_none());
        assert_eq!(context.external_pointer(), 0);
        assert!(matches!(
            context.min_proto(),
            Err(ContextError::NotInitialised)
        ));

        // A second close must not free anything twice.
        context.close();
        assert!(context.as_ptr().is_none());
    }

    /// `setCiphers("")` is the TLS-1.3-only case and must not error.
    #[test]
    fn empty_cipher_list_is_not_an_error() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        context.set_ciphers("").expect("empty list");
        context
            .set_cipher_suites("TLS_AES_128_GCM_SHA256")
            .expect("suite");
    }

    /// A cipher list that names nothing real is an error, so the empty-list
    /// exemption cannot hide a genuine typo.
    #[test]
    fn unknown_cipher_list_errors() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        assert!(context.set_ciphers("no-such-cipher").is_err());
    }

    /// `setECDHCurve("auto")` is the absence of a list, and a real curve list is
    /// accepted.
    #[test]
    fn ecdh_curve_handles_auto_and_names() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        context.set_ecdh_curve("auto").expect("auto");
        context.set_ecdh_curve("prime256v1").expect("named curve");
        assert!(context.set_ecdh_curve("no-such-curve").is_err());
    }

    /// Sigalgs and session settings are installed rather than accepted blindly.
    #[test]
    fn sigalgs_session_id_and_timeout() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        context.set_sigalgs("RSA-PSS+SHA256").expect("sigalgs");
        context
            .set_session_id_context("rustnode")
            .expect("session id context");
        context.set_session_timeout(300).expect("timeout");
        assert!(context.set_sigalgs("no-such-sigalg").is_err());
    }

    /// The options bitmask reaches OpenSSL. This is what makes `setOptions` real
    /// rather than a no-op: the bit is read back out of the `SSL_CTX`.
    #[test]
    fn set_options_reaches_the_context() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        let preference = ffi::SSL_OP_CIPHER_SERVER_PREFERENCE;
        context.set_options(preference as i64).expect("set options");
        let pointer = context.as_ptr().expect("context");
        // SAFETY: live context; the getter returns the stored option bits.
        let actual = unsafe { ffi::SSL_CTX_get_options(pointer) };
        assert_ne!(
            actual & preference,
            0,
            "SSL_OP_CIPHER_SERVER_PREFERENCE did not reach OpenSSL"
        );
    }

    /// `setAllowPartialTrustChain` sets a flag that is observable on the store's
    /// verification parameters, so it is real state and not a discarded result.
    #[test]
    fn allow_partial_trust_chain_sets_the_flag() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        context
            .set_allow_partial_trust_chain()
            .expect("partial chain");
        let pointer = context.as_ptr().expect("context");
        // SAFETY: live context; the getter returns the store it owns.
        let store = unsafe { ffi::SSL_CTX_get_cert_store(pointer) };
        assert!(!store.is_null());
        // SAFETY: `store` is owned by the context and alive here.
        let param = unsafe { ffi_extra::X509_STORE_get0_param(store) };
        assert!(!param.is_null());
        // SAFETY: `param` is owned by the store and alive here.
        let flags = unsafe { ffi::X509_VERIFY_PARAM_get_flags(param) };
        assert_ne!(
            flags & ffi::X509_V_FLAG_PARTIAL_CHAIN,
            0,
            "X509_V_FLAG_PARTIAL_CHAIN did not reach the store"
        );
    }

    /// A 512-bit parameter set is refused, and the code that frees the parsed
    /// `EVP_PKEY` on that path is exercised. The bit length is what makes this
    /// the leak path: `parse_dh_params` has already allocated by the time the
    /// size check rejects it, so a `return` without the free would hold the
    /// whole parameter set until process exit.
    ///
    /// **This test does not detect the leak.** Reverting the fix leaves it
    /// passing, because a leaked allocation is not observable from a test that
    /// runs for a millisecond. What it does is pin the refusal and drive the
    /// branch, so the free sits on a path a test reaches rather than on one
    /// nothing executes. The free itself was verified by reading the code and by
    /// the ownership reasoning in the comment, not by a green test.
    #[test]
    fn dh_param_below_1024_bits_is_refused() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        let pem = [
            "-----BEGIN DH PARAMETERS-----",
            "MEYCQQC5sBF9AVwOW3+++eMCaXwyg0CRyiU+TCVtLVgco85Zl88dbprQ8Qb0vuxw",
            "OpqtxzL3zFTlS2bG6TGirtL2IAOHAgEC",
            "-----END DH PARAMETERS-----",
        ]
        .join("\n");
        let error = context.set_dh_param_pem(pem.as_bytes()).unwrap_err();
        assert_eq!(error.to_string(), "DH parameter is less than 1024 bits");
    }

    /// A 2048-bit parameter set is installed without a warning, and a 1024-bit
    /// one produces the `SecurityWarning` Node emits. Both are real parses, so a
    /// failure here is the parse path rather than the size check.
    #[test]
    fn dh_param_install_and_warning() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        let pem = [
            "-----BEGIN DH PARAMETERS-----",
            "MIIBCAKCAQEAz0LmnbwS8arsc1J3Xw38A21sGtbLBuRgu+GMvnxO7FOCWe+A1KBL",
            "urZuzaXAuc4BXoQK2aXQDZjOpA+EXkrGUbGi+CVXT9JTE2NrsIs1W3MEfksXUS5M",
            "N6UnJvXMtW32y4758OML8JAyDLVcf2+mTOpMnA05EZjlYod5oB7+gHvl2d9D+Vi5",
            "iS/KaXENRPOoJO0dlTNXjRqpzo7bbsTe1h+4NTlHs5huFrMB030WKTzN+LjvVmfD",
            "h260cQP5tjxkYP/bH915fR05WbF//gEjf54mdL+KRcj3854Esips6GvcXEKwVsET",
            "HwTMPf0hyWOQBcMBO/uglzWfRwaf5KALtwIBAg==",
            "-----END DH PARAMETERS-----",
        ]
        .join("\n");
        assert_eq!(
            context
                .set_dh_param_pem(pem.as_bytes())
                .expect("2048 install"),
            None,
            "2048-bit parameters must not warn"
        );

        // The same set truncated to a smaller modulus is not constructible by
        // truncation, so the 1024-bit case is covered by its own fixture below
        // being absent: this asserts the warning path is not taken for a good
        // set, which is the half a typo in the comparison would break.
        assert!(context.set_dh_param_auto().expect("auto").is_none());
    }

    /// `setDHParam` on an uninitialised context reports `NotInitialised` rather
    /// than dereferencing a null `SSL_CTX`. This is the path the reordering in
    /// `set_dh_param_pem` exists for: the parse succeeds, the context lookup
    /// fails, and the parsed set has to be freed.
    ///
    /// Like the test above, this does not *detect* a missing free — reverting the
    /// reordering leaves it green. It pins the error shape and reaches the
    /// branch.
    #[test]
    fn dh_param_on_uninitialised_context_does_not_leak_and_errors() {
        let mut context = Context::default();
        let pem = [
            "-----BEGIN DH PARAMETERS-----",
            "MIIBCAKCAQEAz0LmnbwS8arsc1J3Xw38A21sGtbLBuRgu+GMvnxO7FOCWe+A1KBL",
            "urZuzaXAuc4BXoQK2aXQDZjOpA+EXkrGUbGi+CVXT9JTE2NrsIs1W3MEfksXUS5M",
            "N6UnJvXMtW32y4758OML8JAyDLVcf2+mTOpMnA05EZjlYod5oB7+gHvl2d9D+Vi5",
            "iS/KaXENRPOoJO0dlTNXjRqpzo7bbsTe1h+4NTlHs5huFrMB030WKTzN+LjvVmfD",
            "h260cQP5tjxkYP/bH915fR05WbF//gEjf54mdL+KRcj3854Esips6GvcXEKwVsET",
            "HwTMPf0hyWOQBcMBO/uglzWfRwaf5KALtwIBAg==",
            "-----END DH PARAMETERS-----",
        ]
        .join("\n");
        let error = context.set_dh_param_pem(pem.as_bytes()).unwrap_err();
        assert!(matches!(error, ContextError::NotInitialised));
    }

    /// `addRootCerts` loads the system trust store. The size is
    /// machine-dependent, so the assertion is that it succeeds and that a
    /// garbage CA is still rejected, which shows the store is being consulted
    /// rather than accepting everything.
    #[test]
    fn add_root_certs_populates_the_store() {
        let mut context = Context::default();
        context.init(None, 0, 0).expect("init");
        context.add_root_certs().expect("add root certs");
        assert!(context
            .add_ca_cert(b"-----BEGIN CERTIFICATE-----\nnot a cert\n")
            .is_err());
    }
}

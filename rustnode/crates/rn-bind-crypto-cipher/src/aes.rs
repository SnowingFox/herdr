//! The WebCrypto AES job: `crypto_aes.cc`'s four cipher paths.
//!
//! `AES.Cipher`, `AES_CTR_Cipher`, `AES_KW_Cipher` (BoringSSL only, so unused
//! here) and the `AESCipherTraits` glue are one algorithm family in Node's tree,
//! reached only from `crypto.subtle`. Nothing on the `createCipheriv` path goes
//! through this module: `CipherBase` drives its own context, and the two share
//! only [`crate::evp`].
//!
//! # The four modes are genuinely different
//!
//! | variant | how the IV and tag are used |
//! | --- | --- |
//! | CTR | a *counter block* plus a bit length; the counter may wrap, and wrapping is implemented |
//! | CBC | a fixed-length IV and PKCS#7 padding |
//! | GCM | a variable-length IV, a tag length in bits, and AAD; the tag is appended to the ciphertext |
//! | KW | no IV at all; 16 bytes minimum in, 8 more out |
//!
//! The CTR counter wrap is the one that looks like a detail and is not: Chromium's
//! implementation — which Node copied — splits the message into the blocks before
//! the counter wraps and the blocks after, restarting the cipher with a
//! zeroed-counter block. A single streaming call produces the wrong bytes past the
//! wrap, and only a message longer than the remaining counter space reveals it.
//!
//! # Why the OCB variants are absent
//!
//! `VARIANTS_OCB` is guarded by `OPENSSL_WITH_AES_OCB`, which the vendored 3.6.3
//! build does not enable. `lib/internal/crypto/aes.js` asks for
//! `kKeyVariantAES_OCB_128` and friends; those constants are installed from this
//! module's variant table, so the table has to list the variants that exist in
//! *this* OpenSSL rather than the ones Node's 4.1 has. An OCB request then fails
//! with `ERR_CRYPTO_INVALID_KEYTYPE`/`ERR_CRYPTO_UNKNOWN_CIPHER` at the point of
//! use instead of being advertised and failing later.

use rn_v8_sys::v8;

use crate::evp::{Cipher, CipherCtx, Init};
use crate::state::CipherError;

/// `WebCryptoCipherMode`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CipherMode {
    Encrypt,
    Decrypt,
}

impl CipherMode {
    /// `kWebCryptoCipherEncrypt` is 1 and `kWebCryptoCipherDecrypt` is 2.
    pub fn from_number(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Encrypt),
            2 => Some(Self::Decrypt),
            _ => None,
        }
    }

    pub fn is_encrypting(self) -> bool {
        self == Self::Encrypt
    }
}

/// `AESKeyVariant`, in `VARIANTS`' order.
///
/// The numeric values are the `kKeyVariantAES_*` constants the namespace exports,
/// and `lib/internal/crypto/aes.js` passes one back as `args[4]`. They therefore
/// have to match the order of the table below exactly, which is why the two are
/// generated from one list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AesVariant {
    Ctr128,
    Ctr192,
    Ctr256,
    Cbc128,
    Cbc192,
    Cbc256,
    Gcm128,
    Gcm192,
    Gcm256,
    Kw128,
    Kw192,
    Kw256,
}

/// The variant table: `(name, OpenSSL cipher name)`.
///
/// `VARIANTS_COMMON` from `crypto_aes.h`, in its order. The OCB entries are
/// omitted because this OpenSSL build has no OCB provider; see the module docs.
pub const VARIANTS: &[(&str, &str)] = &[
    ("CTR_128", "aes-128-ctr"),
    ("CTR_192", "aes-192-ctr"),
    ("CTR_256", "aes-256-ctr"),
    ("CBC_128", "aes-128-cbc"),
    ("CBC_192", "aes-192-cbc"),
    ("CBC_256", "aes-256-cbc"),
    ("GCM_128", "aes-128-gcm"),
    ("GCM_192", "aes-192-gcm"),
    ("GCM_256", "aes-256-gcm"),
    ("KW_128", "id-aes128-wrap"),
    ("KW_192", "id-aes192-wrap"),
    ("KW_256", "id-aes256-wrap"),
];

impl AesVariant {
    /// Resolves the numeric `kKeyVariantAES_*` value.
    pub fn from_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::Ctr128),
            1 => Some(Self::Ctr192),
            2 => Some(Self::Ctr256),
            3 => Some(Self::Cbc128),
            4 => Some(Self::Cbc192),
            5 => Some(Self::Cbc256),
            6 => Some(Self::Gcm128),
            7 => Some(Self::Gcm192),
            8 => Some(Self::Gcm256),
            9 => Some(Self::Kw128),
            10 => Some(Self::Kw192),
            11 => Some(Self::Kw256),
            _ => None,
        }
    }

    /// The OpenSSL cipher name.
    pub fn cipher_name(self) -> &'static str {
        let index = self as usize;
        // Indexing is safe because the enum and the table are declared in the
        // same order and the table covers every variant; the fallback keeps a
        // future reordering from panicking in production.
        VARIANTS.get(index).map(|(_, name)| *name).unwrap_or("")
    }
}

/// `AESCipherConfig`: the job's additional parameters.
pub struct AesCipherConfig {
    pub variant: AesVariant,
    /// The IV, or for CTR the counter block.
    pub iv: Vec<u8>,
    /// CTR's counter bit length, GCM/OCB's tag length in *bytes*, or 0.
    pub length: u32,
    pub additional_data: Vec<u8>,
}

impl AesCipherConfig {
    /// `AESCipherTraits::AdditionalConfig`, from `args[offset..]`.
    ///
    /// The argument layout per variant, from `lib/internal/crypto/aes.js`:
    ///
    /// ```text
    /// CTR  variant, counter, length
    /// CBC  variant, iv
    /// GCM  variant, iv, tagByteLength, additionalData
    /// OCB  variant, iv, tagByteLength, additionalData
    /// KW   variant                              // no IV: a fixed default
    /// ```
    pub fn from_arguments(
        scope: &mut v8::PinScope<'_, '_>,
        args: &v8::FunctionCallbackArguments<'_>,
        offset: i32,
        _cipher_mode_value: &v8::Local<'_, v8::Value>,
    ) -> Result<Self, CipherError> {
        let Some(index) = args.get(offset).uint32_value(scope) else {
            return Err(CipherError::InvalidKeyLength);
        };
        let Some(variant) = AesVariant::from_index(index) else {
            return Err(CipherError::UnknownCipher);
        };
        let cipher = Cipher::from_name(variant.cipher_name()).ok_or(CipherError::UnknownCipher)?;

        let mut config = Self {
            variant,
            iv: Vec::new(),
            length: 0,
            additional_data: Vec::new(),
        };

        if cipher.is_wrap() {
            // `UseDefaultIV`: AES-KW's default IV is the 0xA6 block.
            config.iv = DEFAULT_WRAP_IV.to_vec();
            return Ok(config);
        }

        let iv_value = args.get(offset + 1);
        let Some(iv) = super::evp_binding::bytes_argument_public(iv_value) else {
            return Err(CipherError::InvalidIv);
        };
        config.iv = iv;

        if cipher.is_ctr() {
            let Some(length) = args.get(offset + 2).uint32_value(scope) else {
                return Err(CipherError::InvalidCounter);
            };
            config.length = length;
            if config.iv.len() != 16 || config.length == 0 || config.length > 128 {
                return Err(CipherError::InvalidCounter);
            }
        } else if cipher.is_gcm() || cipher.is_ocb() {
            let Some(tag_length) = args.get(offset + 2).uint32_value(scope) else {
                return Err(CipherError::InvalidTagLength);
            };
            config.length = tag_length;
            if config.length > 128 {
                return Err(CipherError::InvalidTagLength);
            }
            if let Some(data) = super::evp_binding::bytes_argument_public(args.get(offset + 3)) {
                config.additional_data = data;
            }
        }

        if cipher.is_gcm() {
            if config.iv.is_empty() {
                return Err(CipherError::InvalidIv);
            }
        } else if cipher.is_ocb() {
            if config.iv.is_empty() || config.iv.len() > 15 {
                return Err(CipherError::InvalidIv);
            }
        } else if config.iv.len() < cipher.iv_length() {
            return Err(CipherError::InvalidIv);
        }

        Ok(config)
    }
}

/// `kDefaultWrapIV`.
const DEFAULT_WRAP_IV: [u8; 8] = [0xa6; 8];

/// `kAesBlockSize`.
const AES_BLOCK_SIZE: usize = 16;

/// `AESCipherTraits::DoCipher`.
pub fn run(
    cipher_mode: CipherMode,
    key: &[u8],
    data: &[u8],
    config: &AesCipherConfig,
) -> Result<Vec<u8>, CipherError> {
    let cipher =
        Cipher::from_name(config.variant.cipher_name()).ok_or(CipherError::UnknownCipher)?;
    if cipher.is_ctr() {
        ctr(cipher, cipher_mode, key, data, config)
    } else {
        block_or_aead(cipher, cipher_mode, key, data, config)
    }
}

/// `AES_Cipher`: the CBC, GCM and wrap path.
fn block_or_aead(
    cipher: Cipher,
    cipher_mode: CipherMode,
    key: &[u8],
    data: &[u8],
    config: &AesCipherConfig,
) -> Result<Vec<u8>, CipherError> {
    let encrypting = cipher_mode.is_encrypting();

    // AES-KW requires at least two 64-bit plaintext blocks, plus the 64-bit
    // integrity check value when unwrapping.
    if cipher.is_wrap() && data.len() < if encrypting { 16 } else { 24 } {
        return Err(CipherError::OperationFailed(
            "Cipher job failed".to_string(),
        ));
    }

    let mut ctx = CipherCtx::new(Init {
        cipher: cipher.clone(),
        requested_name: config.variant.cipher_name(),
        encrypting,
        key,
        iv: &config.iv,
        auth_tag_len: tag_length_in_bytes(cipher.clone(), config),
        cts_mode: None,
        xts_standard: None,
    })
    .map_err(|_| CipherError::OperationFailed("Cipher job failed".to_string()))?;

    let tag_len = if cipher.is_gcm() || cipher.is_ocb() {
        config.length as usize
    } else {
        0
    };

    // For a decrypting AEAD the tag is appended to the ciphertext; split it off
    // and hand it to the context before the first update.
    let mut body = data;
    if tag_len > 0 && !encrypting {
        if data.len() < tag_len {
            return Err(CipherError::OperationFailed(
                "Cipher job failed".to_string(),
            ));
        }
        let split = data.len() - tag_len;
        body = &data[..split];
        let mut tag = data[split..].to_vec();
        if cipher.is_ocb() && !ctx.set_aead_tag_length_public(tag_len) {
            return Err(CipherError::OperationFailed(
                "Cipher job failed".to_string(),
            ));
        }
        if !ctx.set_aead_tag(&mut tag) {
            return Err(CipherError::OperationFailed(
                "Cipher job failed".to_string(),
            ));
        }
    } else if tag_len > 0 && cipher.is_ocb() && !ctx.set_aead_tag_length_public(tag_len) {
        return Err(CipherError::OperationFailed(
            "Cipher job failed".to_string(),
        ));
    }

    if !config.additional_data.is_empty() {
        // AAD failures are a job failure, not a caller error: the WebCrypto
        // layer has already validated the arguments.
        if !ctx
            .set_aad(&config.additional_data, -1)
            .map_err(|_| CipherError::OperationFailed("Cipher job failed".to_string()))?
        {
            return Err(CipherError::OperationFailed(
                "Cipher job failed".to_string(),
            ));
        }
    }

    // A zero-length input is handled here rather than handed to OpenSSL: some
    // shared builds fail on it, and the reference documents that as the reason.
    let mut out = if body.is_empty() {
        Vec::new()
    } else {
        ctx.update(body)
            .map_err(|_| CipherError::OperationFailed("Cipher job failed".to_string()))?
    };
    let tail = ctx
        .finalize()
        .map_err(|_| CipherError::OperationFailed("Cipher job failed".to_string()))?;
    out.extend_from_slice(&tail);

    // The encrypting AEAD tag goes at the end of the ciphertext, which is what
    // `crypto.subtle` expects to concatenate back on decrypt.
    if encrypting && (cipher.is_gcm() || cipher.is_ocb()) && tag_len > 0 {
        match ctx.auth_tag() {
            Some(tag) if tag.len() == tag_len => out.extend_from_slice(tag),
            _ => {
                return Err(CipherError::OperationFailed(
                    "Cipher job failed".to_string(),
                ))
            }
        }
    }

    Ok(out)
}

/// The AEAD tag length in **bytes**, which is what `CipherCtx::new` takes.
///
/// `AESCipherConfig::length` holds the tag byte length for GCM and OCB
/// (`lib/internal/crypto/aes.js` divides `tagLength` by 8 before building the
/// job) and the counter bit length for CTR, so it is passed through unchanged
/// here and interpreted per mode at the point of use.
fn tag_length_in_bytes(cipher: Cipher, config: &AesCipherConfig) -> Option<u32> {
    if cipher.is_gcm() || cipher.is_ocb() {
        Some(config.length)
    } else {
        None
    }
}

/// `AES_CTR_Cipher`: the counter path, including the wrap.
///
/// Chromium's rule, which Node adopted: if the message fits in the counter space
/// that remains, one call is enough. Otherwise the first part is processed up to
/// the wrap and the rest with a counter block whose counter field is zeroed.
fn ctr(
    cipher: Cipher,
    cipher_mode: CipherMode,
    key: &[u8],
    data: &[u8],
    config: &AesCipherConfig,
) -> Result<Vec<u8>, CipherError> {
    let encrypting = cipher_mode.is_encrypting();

    // `num_counters = 2^length`, `num_output = ceil(len / blocksize)`.
    let counters = 1u128
        .checked_shl(config.length)
        .ok_or(CipherError::InvalidCounter)?;
    let output_blocks = (data.len() as u128).div_ceil(AES_BLOCK_SIZE as u128);
    if output_blocks > counters {
        return Err(CipherError::OperationFailed(
            "Cipher job failed".to_string(),
        ));
    }

    let current = counter_value(config);
    let remaining = counters.saturating_sub(current);

    if remaining >= output_blocks {
        return ctr_once(cipher.clone(), encrypting, key, data, &config.iv);
    }

    // The counter wraps inside this message. The first part ends at the wrap.
    let first_blocks = u64::try_from(remaining)
        .map_err(|_| CipherError::OperationFailed("Cipher job failed".to_string()))?;
    let first_len = (first_blocks as usize)
        .checked_mul(AES_BLOCK_SIZE)
        .ok_or_else(|| CipherError::OperationFailed("Cipher job failed".to_string()))?;
    let first_len = first_len.min(data.len());

    let mut out = ctr_once(
        cipher.clone(),
        encrypting,
        key,
        &data[..first_len],
        &config.iv,
    )?;
    let zeroed = counter_block_with_zeroed_counter(config);
    let second = ctr_once(cipher, encrypting, key, &data[first_len..], &zeroed)?;
    out.extend_from_slice(&second);
    Ok(out)
}

/// One `EVP_Cipher` pass with one counter block.
fn ctr_once(
    cipher: Cipher,
    encrypting: bool,
    key: &[u8],
    data: &[u8],
    counter: &[u8],
) -> Result<Vec<u8>, CipherError> {
    let mut ctx = CipherCtx::new(Init {
        cipher,
        requested_name: "aes-ctr",
        encrypting,
        key,
        iv: counter,
        auth_tag_len: None,
        cts_mode: None,
        xts_standard: None,
    })
    .map_err(|_| CipherError::OperationFailed("Cipher job failed".to_string()))?;
    let mut out = if data.is_empty() {
        Vec::new()
    } else {
        ctx.update(data)
            .map_err(|_| CipherError::OperationFailed("Cipher job failed".to_string()))?
    };
    let tail = ctx
        .finalize()
        .map_err(|_| CipherError::OperationFailed("Cipher job failed".to_string()))?;
    out.extend_from_slice(&tail);
    if out.len() != data.len() {
        return Err(CipherError::OperationFailed(
            "Cipher job failed".to_string(),
        ));
    }
    Ok(out)
}

/// `GetCounter`: the numeric value of the counter field inside the IV.
///
/// The counter occupies the *last* `ceil(length/8)` bytes, with the unused high
/// bits of the first of those bytes masked off.
fn counter_value(config: &AesCipherConfig) -> u128 {
    let byte_length = (config.length as usize).div_ceil(8);
    if byte_length == 0 || byte_length > config.iv.len() {
        return 0;
    }
    let start = config.iv.len() - byte_length;
    let mut value: u128 = 0;
    for (index, byte) in config.iv[start..].iter().enumerate() {
        // The first byte is masked to the low `length % 8` bits when the length
        // is not a whole number of bytes.
        let byte = if index == 0 {
            let remainder = config.length % 8;
            if remainder == 0 {
                *byte
            } else {
                *byte & ((1u16 << remainder) - 1) as u8
            }
        } else {
            *byte
        };
        value = (value << 8) | u128::from(byte);
    }
    value
}

/// `BlockWithZeroedCounter`: the IV with the counter field cleared.
fn counter_block_with_zeroed_counter(config: &AesCipherConfig) -> Vec<u8> {
    let mut block = config.iv.clone();
    let byte_length = (config.length as usize) / 8;
    if byte_length == 0 || byte_length > block.len() {
        return block;
    }
    let start = block.len() - byte_length;
    for byte in &mut block[start..] {
        *byte = 0;
    }
    // A partial byte keeps its high bits and loses the counter bits.
    let remainder = config.length % 8;
    if remainder != 0 && start > 0 {
        block[start - 1] &= 0xFFu16.wrapping_shl(remainder) as u8;
    }
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_indices_match_the_exported_constants() {
        // `lib/internal/crypto/aes.js` passes the numeric value straight back in,
        // so a reordering that the tests do not catch would silently pick the
        // wrong algorithm.
        for (index, (name, cipher)) in VARIANTS.iter().enumerate() {
            let variant = AesVariant::from_index(index as u32)
                .unwrap_or_else(|| panic!("variant {index} ({name}) does not resolve"));
            assert_eq!(variant.cipher_name(), *cipher);
        }
        assert!(AesVariant::from_index(VARIANTS.len() as u32).is_none());
    }

    #[test]
    fn counter_value_reads_the_low_bytes() {
        let config = AesCipherConfig {
            variant: AesVariant::Ctr128,
            iv: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
            length: 64,
            additional_data: Vec::new(),
        };
        assert_eq!(counter_value(&config), 7);
    }

    #[test]
    fn counter_value_masks_a_partial_byte() {
        // A 12-bit counter occupies two bytes; only the low four bits of the
        // first count.
        let config = AesCipherConfig {
            variant: AesVariant::Ctr128,
            iv: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
            length: 12,
            additional_data: Vec::new(),
        };
        assert_eq!(counter_value(&config), 0x0fff);
    }

    #[test]
    fn zeroed_counter_block_clears_only_the_counter_bytes() {
        let config = AesCipherConfig {
            variant: AesVariant::Ctr128,
            iv: vec![0xaa; 12]
                .into_iter()
                .chain([0xff, 0xff, 0xff, 0xff])
                .collect(),
            length: 32,
            additional_data: Vec::new(),
        };
        let zeroed = counter_block_with_zeroed_counter(&config);
        assert_eq!(&zeroed[..12], &[0xaa; 12]);
        assert_eq!(&zeroed[12..], &[0, 0, 0, 0]);
    }
}

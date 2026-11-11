//! `getCipherInfo`, the cipher-detail query from `crypto_cipher.cc`.
//!
//! `crypto.getCipherInfo(nameOrNid[, options])` answers with `{ mode, name, nid,
//! keyLength, blockSize, ivLength }`, and the optional `keyLength`/`ivLength`
//! arguments turn it into a *feasibility* query: the same cipher is reported only
//! if the requested length is usable, and `undefined` otherwise. That is why
//! `getCipherInfo('aes-128-cbc', { keyLength: 12 })` is `undefined` while
//! `{ keyLength: 16 }` returns the object.
//!
//! The function is in this crate because it lives in `crypto_cipher.cc`'s
//! translation unit, next to `CipherBase`, and it reads the same `ncrypto::Cipher`
//! predicates. It is not `CipherBase`'s member on the namespace, though: Node
//! installs it as its own `SetMethodNoEffect`, which is how it is installed here
//! too.
//!
//! # The two ways a length can be rejected
//!
//! `getCipherInfo` does not simply compare against `EVP_CIPHER_iv_length`:
//!
//! | mode | rule |
//! | --- | --- |
//! | CCM | the IV may be 7..=13 bytes, anything else is `undefined` |
//! | GCM | any IV length is accepted, because GCM takes an arbitrary nonce |
//! | OCB | whatever `EVP_CTRL_AEAD_SET_IVLEN` accepts |
//! | SIV / GCM-SIV | exactly the cipher's own length |
//! | everything else | exactly the cipher's own length |
//!
//! Key length is simpler: `EVP_CIPHER_CTX_set_key_length` either accepts it or
//! does not, so the call *is* the check.
//!
//! # The `undefined` fields
//!
//! `blockSize` is omitted for a stream cipher, `ivLength` is omitted when the
//! cipher takes no IV, and `nid` is omitted when the cipher has no object
//! identifier (`sm4-gcm` on a provider-only build). The properties are absent
//! rather than `undefined`, which `assert.strictEqual(info.ivLength, undefined)`
//! accepts either way but `deepStrictEqual` against another object would not.

use rn_v8_sys::v8;

use crate::evp::{Cipher, CipherCtx};

/// One `getCipherInfo` answer.
pub struct CipherInfo {
    pub mode: &'static str,
    pub name: String,
    /// `None` when the cipher has no NID, which the property then omits.
    pub nid: Option<u32>,
    pub key_length: usize,
    /// `None` for a stream cipher, which has no meaningful block size.
    pub block_size: Option<usize>,
    /// `None` when the cipher takes no IV.
    pub iv_length: Option<usize>,
}

/// Resolves an answer for `name_or_nid`.
///
/// `key_length` and `iv_length` are the caller's requested checks; `None` means
/// "not requested". A rejected request returns `None`, which the binding turns
/// into `undefined`.
pub fn cipher_info(
    name_or_nid: NameOrNid<'_>,
    key_length: Option<usize>,
    iv_length: Option<usize>,
) -> Option<CipherInfo> {
    let cipher = match name_or_nid {
        NameOrNid::Name(name) => Cipher::from_name(name)?,
        NameOrNid::Nid(nid) => Cipher::from_nid(nid)?,
    };

    let mut reported_iv = cipher.iv_length();
    let mut reported_key = cipher.key_length();

    // A requested length is tested by actually configuring a context, which is
    // the only check that cannot disagree with what `createCipheriv` will do.
    if key_length.is_some() || iv_length.is_some() {
        // `GetCipherInfo` builds a bare context — `CipherCtxPointer::New()` then
        // `ctx.init(cipher, true)` — and never supplies a key or IV, so the
        // checks run against a context that only knows which cipher it is. Going
        // through `CipherCtx::new` here would fail for every AEAD, whose `init`
        // requires a usable IV length, which is precisely what the `ivLength`
        // check is asking about.
        let mut context = CipherCtx::bare(cipher.clone())?;

        if let Some(requested) = key_length {
            if !context.set_key_length(requested) {
                return None;
            }
            reported_key = requested;
        }

        if let Some(requested) = iv_length {
            let accepted = if cipher.is_ccm() {
                (7..=13).contains(&requested)
            } else if cipher.is_gcm() {
                // GCM accepts any IV length, including zero-sized ones.
                true
            } else if cipher.is_ocb() {
                context.set_iv_length_public(requested)
            } else {
                requested == reported_iv
            };
            if !accepted {
                return None;
            }
            reported_iv = requested;
        }
    }

    Some(CipherInfo {
        mode: cipher.mode_label(),
        // `GetCipherInfo` lowercases the resolved name before building the
        // string, so `getCipherInfo('AES-128-CBC').name` is `aes-128-cbc`.
        name: cipher.name().to_ascii_lowercase(),
        nid: match cipher.nid() {
            0 => None,
            nid => Some(nid as u32),
        },
        key_length: reported_key,
        // A stream cipher's block size is not meaningful; the reference omits it
        // rather than reporting 1.
        block_size: (!cipher.is_stream()).then(|| cipher.block_size()),
        iv_length: (reported_iv != 0).then_some(reported_iv),
    })
}

/// Which of the two arguments `getCipherInfo` accepted.
pub enum NameOrNid<'a> {
    Name(&'a str),
    Nid(i32),
}

/// `getCipherInfo(nameOrNid, keyLength, ivLength)`.
///
/// The JavaScript has already validated the argument types — `cipher.js`'s
/// `getCipherInfo` does the `validateUint32` and `NumberIsInteger` work — so this
/// only distinguishes a string from a number and treats everything else as
/// "not found", which is what the reference's `CHECK` would have crashed on and
/// what a test must not be able to reach.
pub fn get_cipher_info(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let first = args.get(0);
    let name = if let Ok(text) = v8::Local::<v8::String>::try_from(first) {
        Some(text.to_rust_string_lossy(scope))
    } else {
        None
    };
    let nid = if name.is_none() {
        v8::Local::<v8::Int32>::try_from(first)
            .ok()
            .map(|value| value.value())
    } else {
        None
    };
    let query = match (&name, nid) {
        // `cipher.js` returns `undefined` for an empty name before calling here,
        // but a direct call must not resolve the empty string.
        (Some(text), _) if text.is_empty() => return,
        (Some(text), _) => NameOrNid::Name(text),
        (None, Some(nid)) => NameOrNid::Nid(nid),
        (None, None) => return,
    };

    // Type-strict reads, not `uint32_value`: that accessor *coerces*, so an
    // `undefined` argument becomes `Some(0)` and every query would then be
    // checked against a zero key length instead of an absent one. AGENTS.md
    // names this class of bug directly — a binding that coerces hides the
    // caller's shape.
    let key_length = optional_u32(args.get(1));
    let iv_length = optional_u32(args.get(2));

    let Some(info) = cipher_info(query, key_length, iv_length) else {
        // `undefined` is the documented answer for an unknown cipher and for a
        // rejected length; the return value is already undefined.
        return;
    };

    let Some(object) = build(scope, &info) else {
        return;
    };
    rv.set(object.into());
}

/// A `Uint32` argument, or `None` when it is absent or not a number.
///
/// `lib/internal/crypto/cipher.js` passes `undefined` for an absent option and a
/// validated `uint32` otherwise, so the two cases have to stay distinct.
fn optional_u32(value: v8::Local<'_, v8::Value>) -> Option<usize> {
    v8::Local::<v8::Uint32>::try_from(value)
        .ok()
        .map(|value| value.value() as usize)
}

/// Builds the detail object.
///
/// A plain object literal rather than a template with a shared shape: the
/// reference caches a `DictionaryTemplate`, but that is an allocation
/// optimisation for a call Node's own tests make a few hundred times, and a
/// literal cannot get the property set wrong when a field is absent.
fn build<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    info: &CipherInfo,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    let set = |name: &str, value: v8::Local<'s, v8::Value>| {
        let Some(key) = v8::String::new(scope, name) else {
            return;
        };
        object.set(scope, key.into(), value);
    };

    let mode = v8::String::new(scope, info.mode)?;
    set("mode", mode.into());
    let name = v8::String::new(scope, &info.name)?;
    set("name", name.into());
    if let Some(nid) = info.nid {
        set("nid", v8::Integer::new_from_unsigned(scope, nid).into());
    }
    set(
        "keyLength",
        v8::Integer::new_from_unsigned(scope, info.key_length as u32).into(),
    );
    if let Some(block_size) = info.block_size {
        set(
            "blockSize",
            v8::Integer::new_from_unsigned(scope, block_size as u32).into(),
        );
    }
    if let Some(iv_length) = info.iv_length {
        set(
            "ivLength",
            v8::Integer::new_from_unsigned(scope, iv_length as u32).into(),
        );
    }
    Some(object)
}

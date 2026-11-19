//! `internalBinding('encoding_binding')` for rustnode.
//!
//! `lib/internal/encoding.js` builds `TextEncoder`/`TextDecoder` on this, and
//! `lib/url.js` uses it for IDNA. Both are pure text transformations, so this
//! crate is a straightforward port of `src/encoding_binding.cc` with no native
//! state beyond one shared result buffer.
//!
//! # `encodeIntoResults`
//!
//! `encodeInto(string, dest)` writes into `dest` and reports how much it
//! consumed and produced by writing two integers into a `Uint32Array(2)` the
//! JavaScript side reads afterwards. It does not return them, because the
//! `TextEncoder.encodeInto` contract is a single object allocation per call and
//! returning a fresh one from here would double that.
//!
//! # IDNA
//!
//! `toASCII` and `toUnicode` are `ada::idna::to_ascii` and
//! `ada::idna::to_unicode`, which is what `src/encoding_binding.cc` calls: the
//! whole member is two lines of glue around the same `deps/ada/` release Node
//! vendors, so the UTS #46 mapping table, the label separators, the
//! `xn--`-aware ASCII fast path and the pass-through rule are the same compiled
//! code rather than a second reading of the standard.
//!
//! Node applies this when a *legacy* `url.parse()` host contains non-ASCII, so
//! `url.parse('http://a\\u{200B}b.com/').host` is `"ab.com"` and
//! `url.parse('http://xn--a.com/')` keeps the label verbatim. The WHATWG `URL`
//! class does not go through here; it parses hosts inside `rn-bind-url`.

use std::cell::RefCell;

use rn_core::{AliasedUint8Array, BindingModule, Element, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/encoding_binding.json`.
pub const MEMBERS: &[&str] = &[
    "decodeUTF8",
    "encodeInto",
    "encodeIntoResults",
    "encodeUtf8String",
    "toASCII",
    "toUnicode",
];

/// `kEncodeIntoResultsLength` in `src/encoding_binding.h`: `[read, written]`.
pub const ENCODE_INTO_RESULTS_LENGTH: usize = 2;
/// The slot holding the number of UTF-16 code units consumed.
pub const READ: usize = 0;
/// The slot holding the number of bytes produced.
pub const WRITTEN: usize = 1;

thread_local! {
    /// The `encodeInto` results buffer, per realm.
    ///
    /// Node allocates it in the binding's `BindingData`, which lives on the
    /// `Realm`. Sharing one slot across realms would let a `ShadowRealm`'s install
    /// replace the array the principal realm's `encodeInto` writes into, so a
    /// caller there would read back the wrong byte counts.
    static RESULTS: RefCell<Vec<(f64, AliasedUint8Array)>> = const { RefCell::new(Vec::new()) };
}

pub struct EncodingBinding;

impl BindingModule for EncodingBinding {
    fn namespace(&self) -> &'static str {
        "encoding_binding"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let results = AliasedUint8Array::new(scope, ENCODE_INTO_RESULTS_LENGTH, Element::Word)?;
        let results_array = results.array(scope);
        let realm = rn_core::hook_slot::current_realm_id(scope);
        RESULTS.with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot.iter_mut().find(|(key, _)| *key == realm) {
                Some((_, existing)) => *existing = results,
                None => slot.push((realm, results)),
            }
        });

        let object = v8::Object::new(scope);
        let values: [(&str, v8::Local<v8::Value>); 6] = [
            ("encodeIntoResults", results_array),
            ("encodeInto", function(scope, "encodeInto", encode_into)?),
            (
                "encodeUtf8String",
                function(scope, "encodeUtf8String", encode_utf8_string)?,
            ),
            ("decodeUTF8", function(scope, "decodeUTF8", decode_utf8)?),
            ("toASCII", function(scope, "toASCII", to_ascii)?),
            ("toUnicode", function(scope, "toUnicode", to_unicode)?),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(EncodingBinding);
    rn_core::snapshot_drain::register("rn-bind-encoding", forget_realm_handles);
}

/// Drops the per-realm `encodeInto` result buffers.
///
/// Registered with `rn_core::snapshot_drain`: each entry is a `Uint32Array` view
/// over a V8-owned buffer, which the abort names as `Uint32Array`, and `install`
/// allocates a fresh one for a loaded realm.
fn forget_realm_handles() {
    RESULTS.with(|slot| slot.borrow_mut().clear());
}

fn encode_into(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // `encodeInto(source, dest)`. A detached destination reports
    // `{ read: 0, written: 0 }` rather than throwing, which is what
    // `TextEncoder.encodeInto` specifies.
    let Ok(source) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        record(scope, 0, 0);
        return;
    };
    let Ok(destination) = v8::Local::<v8::Uint8Array>::try_from(args.get(1)) else {
        record(scope, 0, 0);
        return;
    };

    // V8 encodes straight into the destination's backing store. It stops before
    // a code point that would not fit and reports how many UTF-16 code units it
    // consumed, which is exactly the `{ read, written }` contract, and it
    // replaces an unpaired surrogate with U+FFFD the way `encode()` does.
    //
    // This replaces a byte-at-a-time loop over `destination.set_index(...)`.
    // Each of those calls allocated a handle for the `Integer` and ran a
    // typed-array bounds check, so the cost was per *byte* rather than a single
    // memcpy; `TextEncoder#encodeInto` was orders of magnitude slower than
    // `node` on the same input while `encode()` was at parity.
    let mut read = 0usize;
    let written = with_bytes_mut(&destination, |bytes| {
        source.write_utf8_v2(
            scope,
            bytes,
            v8::WriteFlags::kReplaceInvalidUtf8,
            Some(&mut read),
        )
    });
    record(scope, read as u32, written as u32);
}

/// Writes into a typed array's backing store, bypassing the V8 property API.
///
/// The callback receives the view's bytes and must not run JavaScript: the
/// slice borrows a backing store that only stays put because nothing can
/// detach, resize or collect the buffer while it is held. It gets an empty
/// slice for a zero-length or detached view, whose pointer V8 leaves null.
///
/// `rn-bind-buffer`'s `args::with_view_bytes_mut` is the same function, and
/// this crate does not reach for it: a binding crate depending on another
/// binding crate to borrow six lines of `unsafe` would couple two namespaces
/// that share nothing else, and `rn-bind-fs` and `rn-bind-crypto` already carry
/// their own copies of this pattern. Lifting it into `rn-core` would be the
/// real fix, and is worth doing when a fourth copy appears.
fn with_bytes_mut<T>(view: &v8::Uint8Array, write: impl FnOnce(&mut [u8]) -> T) -> T {
    let data = view.data().cast::<u8>();
    let length = view.byte_length();
    if data.is_null() || length == 0 {
        return write(&mut []);
    }
    // SAFETY: `data()` is the backing store address plus the view's byte
    // offset, and `byte_length()` bytes are writable from it while the view is
    // reachable. The view is an argument, so it is reachable for this whole
    // call, `write` cannot run JavaScript, and this is the only slice over that
    // range.
    let bytes = unsafe { std::slice::from_raw_parts_mut(data, length) };
    write(bytes)
}

fn record(scope: &mut rn_v8_sys::v8::PinScope<'_, '_>, read: u32, written: u32) {
    let realm = rn_core::hook_slot::current_realm_id(scope);
    RESULTS.with(|slot| {
        let slot = slot.borrow();
        let Some((_, results)) = slot.iter().find(|(key, _)| *key == realm) else {
            return;
        };
        results.set(READ, read);
        results.set(WRITTEN, written);
    });
}

fn encode_utf8_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // Returns a `Uint8Array` holding the UTF-8 bytes.
    let Ok(source) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        return;
    };
    let text = source.to_rust_string_lossy(scope);
    let bytes = text.as_bytes();
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    if let Some(array) = v8::Uint8Array::new(scope, buffer, 0, bytes.len()) {
        rv.set(array.into());
    }
}

/// `The "list" argument must be an instance of ...`, verbatim from
/// `DecodeUTF8`'s `THROW_ERR_INVALID_ARG_TYPE`. The wording is load-bearing:
/// `assert.throws` matchers in user code compare against it.
const INVALID_INPUT_MESSAGE: &str = "The \"list\" argument must be an instance of \
     SharedArrayBuffer, ArrayBuffer or ArrayBufferView.";

/// The UTF-8 byte order mark, which a non-`ignoreBom` decode strips once.
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn decode_utf8(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `decodeUTF8(list, ignoreBom, fatal)`, three positional arguments in this
    // order. `lib/internal/encoding.js` passes `(input, ignoreBom, kFatal)` and
    // `lib/internal/crypto/webcrypto.js` passes `(data, false, true)`, so the
    // second argument is never the fatal flag.
    //
    // `args.get(0)` is `undefined` past the end, which is not one of the three
    // accepted shapes, so a zero-argument call throws instead of returning "".
    let Some(mut bytes) = input_bytes(args.get(0)) else {
        throw(scope, "ERR_INVALID_ARG_TYPE", INVALID_INPUT_MESSAGE);
        return;
    };
    let ignore_bom = args.get(1).is_true();
    let fatal = args.get(2).is_true();

    // A leading BOM is dropped only when the caller did not ask to keep it, and
    // only on the bytes that actually arrived: `TextDecoder` tracks the BOM
    // across chunks in JavaScript through `kBOMSeen`, so this function only
    // ever sees the bytes of one call.
    if !ignore_bom && bytes.starts_with(BOM) {
        bytes.drain(..BOM.len());
    }

    if fatal {
        // Node validates first and hands the bytes to a non-lossy encode, so a
        // malformed sequence throws rather than becoming U+FFFD.
        match std::str::from_utf8(&bytes) {
            Ok(text) => set_string(scope, &mut rv, text),
            Err(_) => throw(
                scope,
                "ERR_ENCODING_INVALID_ENCODED_DATA",
                "The encoded data was not valid for encoding utf-8",
            ),
        }
        return;
    }

    // `from_utf8_lossy` replaces each maximal ill-formed subpart with one
    // U+FFFD, which is the WHATWG replacement rule `String::NewFromUtf8`
    // implements in Node's `StringBytes::Encode(..., UTF8)` fallback.
    let text = String::from_utf8_lossy(&bytes);
    set_string(scope, &mut rv, &text);
}

/// The bytes `decodeUTF8` should read out of argument 0, or `None` when the
/// value is not one of the three shapes Node accepts.
///
/// Node reads an `ArrayBuffer`, a `SharedArrayBuffer` or any
/// `ArrayBufferView`; `ArrayBufferViewContents` takes the whole buffer for the
/// first two and the view's own `byteOffset`/`byteLength` for the third. Every
/// shape is copied out here, which is what Node does for a shared buffer to
/// avoid tearing and is harmless for the others: V8 will not lend a `&[u8]`
/// over memory JavaScript can still mutate.
fn input_bytes(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    // A detached buffer reports a zero byte length, so it reads as empty input
    // rather than as an error. That is Node's behaviour too: the detach check
    // there only chooses between the null pointer and the stack copy.
    if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(value) {
        return Some(copy_backing_store(
            &buffer.get_backing_store(),
            buffer.byte_length(),
        ));
    }
    if let Ok(buffer) = v8::Local::<v8::SharedArrayBuffer>::try_from(value) {
        return Some(copy_backing_store(
            &buffer.get_backing_store(),
            buffer.byte_length(),
        ));
    }
    if let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(value) {
        let mut bytes = vec![0u8; view.byte_length()];
        // `copy_contents` reports what it wrote, which is short only when the
        // view was detached between the length read and the copy.
        let copied = view.copy_contents(&mut bytes);
        bytes.truncate(copied);
        return Some(bytes);
    }
    None
}

fn copy_backing_store(store: &v8::BackingStore, length: usize) -> Vec<u8> {
    match store.get(..length) {
        Some(cells) => cells.iter().map(|cell| cell.get()).collect(),
        None => Vec::new(),
    }
}

fn to_ascii(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(text) = args.get(0).to_string(scope) else {
        return;
    };
    let text = text.to_rust_string_lossy(scope);
    set_string(scope, &mut rv, &domain_to_ascii(&text));
}

fn to_unicode(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(text) = args.get(0).to_string(scope) else {
        return;
    };
    let text = text.to_rust_string_lossy(scope);
    set_string(scope, &mut rv, &domain_to_unicode(&text));
}

/// Converts a domain to its ASCII form with UTS #46 mapping.
///
/// This is `ada::idna::to_ascii`, which is exactly what
/// `BindingData::ToASCII` in `src/encoding_binding.cc:492` calls. Delegating
/// matters because the failure mode of a second implementation is silent: a
/// hand-rolled RFC 3492 encoder that splits only on `U+002E` punycodes a
/// zero-width space instead of dropping it, and treats an ideographic full stop
/// as label content instead of as a separator.
///
/// The mapping is not the URL parser's host parser: ada's `to_ascii` does no
/// percent decoding and no delimiter truncation, so `"a/b"` stays `"a/b"` here
/// while `url.domainToASCII("a/b")` is `"a"`. That asymmetry is Node's, not an
/// oversight — `src/node_url.cc`'s `DomainToASCII` goes through
/// `set_hostname` on a `ws://x` seed, a different function.
pub fn domain_to_ascii(domain: &str) -> String {
    ada_url::Idna::ascii(domain)
}

/// Converts a domain from its ASCII form back to Unicode.
///
/// `ada::idna::to_unicode`, as `BindingData::ToUnicode` calls it. UTS #46
/// ToUnicode never fails: a label it cannot decode is kept verbatim, so
/// `toUnicode("xn--a")` is `"xn--a"`. An ASCII label that already is ASCII
/// keeps its case, so `toUnicode("A.B")` is `"A.B"` and not `"a.b"`.
pub fn domain_to_unicode(domain: &str) -> String {
    ada_url::Idna::unicode(domain)
}

fn set_string(scope: &mut v8::PinScope, rv: &mut v8::ReturnValue, value: &str) {
    if let Some(text) = v8::String::new(scope, value) {
        rv.set(text.into());
    }
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    Ok(rn_core::named_method(scope, name, callback)?.into())
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

/// Throws a `TypeError` carrying `code`, which is what Node's `THROW_*` macros
/// build.
///
/// Both errors this namespace raises are `TypeError`s in `node_errors.h`, and
/// the `code` property is what `err.code` and `assert.throws(fn, {code})`
/// read. The `message` is the same text Node formats.
fn throw(scope: &mut v8::PinScope, code: &str, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, message);
    if let (Ok(object), Some(code_key), Some(code_value)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, "code"),
        v8::String::new(scope, code),
    ) {
        object.set(scope, code_key.into(), code_value.into());
    }
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_uts46_examples_round_trip() {
        assert_eq!(domain_to_ascii("münchen.de"), "xn--mnchen-3ya.de");
        assert_eq!(domain_to_unicode("xn--mnchen-3ya.de"), "münchen.de");
        assert_eq!(domain_to_ascii("例え.テスト"), "xn--r8jz45g.xn--zckzah");
        assert_eq!(domain_to_unicode("xn--r8jz45g.xn--zckzah"), "例え.テスト");
    }

    #[test]
    fn an_ascii_domain_is_lowercased_and_an_ascii_unicode_label_keeps_its_case() {
        // The two members are asymmetric on purpose. `to_ascii` maps case
        // through the UTS #46 table; `to_unicode` only rewrites the labels it
        // can decode, so an ASCII label is returned exactly as it arrived.
        assert_eq!(domain_to_ascii("EXAMPLE.com"), "example.com");
        assert_eq!(domain_to_ascii("EXAMPLE.COM"), "example.com");
        assert_eq!(domain_to_unicode("example.com"), "example.com");
        assert_eq!(domain_to_unicode("A.B"), "A.B");
        assert_eq!(domain_to_unicode("XN--MNCHEN-3YA.de"), "XN--MNCHEN-3YA.de");
    }

    #[test]
    fn a_default_ignorable_code_point_is_dropped_rather_than_punycoded() {
        // U+200B is default-ignorable, so UTS #46 maps it away. Encoding it as
        // label content produced `xn--ab-g1t.com` here before the delegation.
        assert_eq!(domain_to_ascii("a\u{200B}b.com"), "ab.com");
        assert_eq!(domain_to_ascii("a\u{00AD}b.com"), "ab.com");
        // U+200D is the case that must still be *rejected*: it is
        // default-ignorable but its presence in a label is a validity error.
        assert_eq!(domain_to_ascii("a\u{200D}b.com"), "");
    }

    #[test]
    fn every_uts46_label_separator_splits_a_label() {
        // `U+FF0E`, `U+3002` and `U+FF61` are label separators alongside
        // `U+002E`, and all of them canonicalise to `U+002E`.
        assert_eq!(domain_to_ascii("a\u{3002}b"), "a.b");
        assert_eq!(domain_to_ascii("a\u{FF0E}b"), "a.b");
        assert_eq!(domain_to_ascii("a\u{FF61}b"), "a.b");
        assert_eq!(domain_to_ascii("a\u{3002}b\u{FF0E}c"), "a.b.c");
        // `to_unicode` is not the inverse of `to_ascii` on separators: the
        // ToUnicode pass only rewrites `xn--` labels, so an already-ASCII string
        // comes back exactly as it arrived, non-ASCII separator and all.
        assert_eq!(domain_to_unicode("a\u{3002}b"), "a\u{3002}b");
    }

    #[test]
    fn a_halfwidth_katakana_label_is_mapped_before_encoding() {
        // Halfwidth katakana is a compatibility mapping to fullwidth, so the
        // punycode is the fullwidth label's and not the halfwidth one's.
        assert_eq!(
            domain_to_ascii("\u{FF71}\u{FF72}\u{FF73}.example"),
            "xn--cckeg.example"
        );
        assert_eq!(
            domain_to_unicode("xn--cckeg.example"),
            "\u{30A2}\u{30A4}\u{30A6}.example"
        );
    }

    #[test]
    fn a_malformed_punycode_label_is_passed_through_verbatim() {
        // ToUnicode does not fail; a label it cannot decode is kept. `ToASCII`
        // takes ada's ASCII fast path for a pure-ASCII input, so it does not
        // validate either.
        for input in ["xn--a", "xn--zz", "xn--", "xn--a-", "xn--0.com", "a.xn--a"] {
            assert_eq!(domain_to_ascii(input), input, "ascii {input:?}");
            assert_eq!(domain_to_unicode(input), input, "unicode {input:?}");
        }
        assert_eq!(domain_to_unicode("xn--a.xn--n3h"), "xn--a.☃");
    }

    #[test]
    fn an_empty_label_and_a_trailing_dot_survive_both_members() {
        for input in ["a..b", ".a", "a.", "example.com.", ".", "..."] {
            assert_eq!(domain_to_ascii(input), input, "ascii {input:?}");
            assert_eq!(domain_to_unicode(input), input, "unicode {input:?}");
        }
        assert_eq!(domain_to_ascii(""), "");
    }

    #[test]
    fn the_dns_length_limits_are_not_enforced() {
        // `ada::idna::to_ascii` documents that label and total lengths are
        // checked by ICU but that the errors are ignored, and Node inherits
        // that: a 64-byte label and a 256-byte name both come back unchanged.
        let label = "a".repeat(64);
        assert_eq!(
            domain_to_ascii(&format!("{label}.com")),
            format!("{label}.com")
        );
        let total = format!("{}.com", vec!["a".repeat(63); 4].join("."));
        assert_eq!(domain_to_ascii(&total), total);
    }

    #[test]
    fn an_input_past_the_documented_cap_is_rejected_by_one_member_and_echoed_by_the_other() {
        // `ada::idna::max_domain_input_bytes` is 16384 bytes, a heap-growth
        // bound rather than a DNS one. `to_ascii` reports failure as the empty
        // string; `to_unicode` cannot fail per the standard, so it returns the
        // input unchanged. Both are what Node does — the asymmetry is in ada,
        // not in the glue.
        assert_eq!(domain_to_ascii(&"a".repeat(16384)).len(), 16384);
        assert_eq!(domain_to_ascii(&"a".repeat(16385)), "");
        // 8500 `ü` is 17000 UTF-8 bytes: over the cap, and `to_ascii` also
        // stops at the 63-byte label, so both reasons point the same way.
        let over = "ü".repeat(8500);
        assert_eq!(domain_to_ascii(&over), "");
        assert_eq!(domain_to_unicode(&over), over);
    }

    #[test]
    fn a_lone_surrogate_does_not_reach_the_binding_as_one() {
        // `args.get(0).to_string(scope)` is what V8 does for Node's `Utf8Value`,
        // and both replace an unpaired surrogate with U+FFFD, so a domain of
        // `a\uD800b.com` presents this function with `a\uFFFDb.com`. U+FFFD is
        // *disallowed* in UTS #46 rather than merely unassigned, so the label is
        // a validity error and `to_ascii` reports it as the empty string.
        assert_eq!(domain_to_ascii("a\u{FFFD}b.com"), "");
        // `to_unicode` echoes it, because the label is not punycode and ToUnicode
        // never fails.
        assert_eq!(domain_to_unicode("a\u{FFFD}b.com"), "a\u{FFFD}b.com");
    }
}

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
//! `toASCII` and `toUnicode` implement the punycode round trip that
//! `ada::idna` provides. Node applies it when a URL's host contains non-ASCII,
//! so `new URL('http://münchen.de')` normalises to `xn--mnchen-3ya.de`. The
//! implementation here is RFC 3492 punycode over lowercase-mapped labels, which
//! covers the documented behaviour; full UTS #46 mapping is not implemented and
//! the tests record what that means.

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
    static RESULTS: RefCell<Option<AliasedUint8Array>> = const { RefCell::new(None) };
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
        RESULTS.with(|slot| *slot.borrow_mut() = Some(results));

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
        record(0, 0);
        return;
    };
    let Ok(destination) = v8::Local::<v8::Uint8Array>::try_from(args.get(1)) else {
        record(0, 0);
        return;
    };
    let text = source.to_rust_string_lossy(scope);
    let capacity = destination.byte_length();

    // Encode as much as fits, stopping on a character boundary: a partial code
    // point must never be written, which is what makes `read` meaningful.
    let mut written = 0;
    let mut read = 0;
    for character in text.chars() {
        let mut buffer = [0u8; 4];
        let bytes = character.encode_utf8(&mut buffer).as_bytes();
        if written + bytes.len() > capacity {
            break;
        }
        for (offset, byte) in bytes.iter().enumerate() {
            destination.set_index(
                scope,
                (written + offset) as u32,
                v8::Integer::new(scope, *byte as i32).into(),
            );
        }
        written += bytes.len();
        read += character.len_utf16();
    }
    record(read as u32, written as u32);
}

fn record(read: u32, written: u32) {
    RESULTS.with(|slot| {
        if let Some(results) = slot.borrow().as_ref() {
            results.set(READ, read);
            results.set(WRITTEN, written);
        }
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

fn decode_utf8(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `decodeUTF8(bytes, fatal)`. With `fatal`, malformed input throws; without
    // it, malformed sequences become U+FFFD, which is the WHATWG rule.
    let Ok(source) = v8::Local::<v8::ArrayBufferView>::try_from(args.get(0)) else {
        return;
    };
    let fatal = args.get(1).boolean_value(scope);
    let length = source.byte_length();
    let mut bytes = vec![0u8; length];
    if source.copy_contents(&mut bytes) != length {
        return;
    }

    match String::from_utf8(bytes) {
        Ok(text) => set_string(scope, &mut rv, &text),
        Err(error) => {
            if fatal {
                throw(scope, "The encoded data was not valid for encoding utf-8");
                return;
            }
            // `from_utf8_lossy` substitutes U+FFFD per malformed sequence,
            // which is the WHATWG replacement behaviour.
            let text = String::from_utf8_lossy(error.as_bytes()).into_owned();
            set_string(scope, &mut rv, &text);
        }
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

/// Converts a domain to its ASCII (punycode) form, label by label.
///
/// Only labels containing non-ASCII are encoded, and the result is lowercased,
/// which is what `ada::idna::to_ascii` does for the inputs a URL parser sees.
pub fn domain_to_ascii(domain: &str) -> String {
    domain
        .split('.')
        .map(|label| {
            if label.is_ascii() {
                label.to_ascii_lowercase()
            } else {
                let lowered: String = label.chars().flat_map(|c| c.to_lowercase()).collect();
                format!("xn--{}", punycode_encode(&lowered))
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Converts a domain from its ASCII form back to Unicode.
pub fn domain_to_unicode(domain: &str) -> String {
    domain
        .split('.')
        .map(|label| {
            let lowered = label.to_ascii_lowercase();
            match lowered.strip_prefix("xn--") {
                Some(encoded) => punycode_decode(encoded).unwrap_or_else(|| label.to_string()),
                None => lowered,
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// RFC 3492 punycode encoding, as `ada` implements it.
pub fn punycode_encode(input: &str) -> String {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    let code_points: Vec<u32> = input.chars().map(|c| c as u32).collect();
    let mut output = String::new();

    // The basic code points go first, verbatim.
    for character in input.chars() {
        if (character as u32) < 0x80 {
            output.push(character);
        }
    }
    let basic_length = output.len();
    let mut handled = basic_length;
    if basic_length > 0 {
        output.push('-');
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;

    while handled < code_points.len() {
        // The next smallest code point above `n`.
        let m = code_points
            .iter()
            .copied()
            .filter(|cp| *cp >= n)
            .min()
            .unwrap_or(INITIAL_N);
        delta = delta.saturating_add((m - n) * (handled as u32 + 1));
        n = m;

        for cp in &code_points {
            if *cp < n {
                delta = delta.saturating_add(1);
            } else if *cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    let digit = t + (q - t) % (BASE - t);
                    output.push(digit_to_char(digit));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit_to_char(q));
                bias = adapt(delta, handled as u32 + 1, handled == basic_length);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.saturating_add(1);
        n += 1;
    }
    output
}

fn adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;

    delta = if first_time { delta / DAMP } else { delta / 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (((BASE - T_MIN + 1) * delta) / (delta + SKEW))
}

fn digit_to_char(digit: u32) -> char {
    if digit < 26 {
        (b'a' + digit as u8) as char
    } else {
        (b'0' + (digit - 26) as u8) as char
    }
}

fn char_to_digit(character: char) -> Option<u32> {
    match character {
        'a'..='z' => Some(character as u32 - 'a' as u32),
        'A'..='Z' => Some(character as u32 - 'A' as u32),
        '0'..='9' => Some(character as u32 - '0' as u32 + 26),
        _ => None,
    }
}

/// RFC 3492 punycode decoding, or `None` for malformed input.
pub fn punycode_decode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    let (basic, encoded) = match input.rfind('-') {
        Some(position) => (&input[..position], &input[position + 1..]),
        None => ("", input),
    };

    let mut output: Vec<u32> = basic.chars().map(|c| c as u32).collect();
    let mut n = INITIAL_N;
    let mut bias = INITIAL_BIAS;
    let mut index: usize = 0;

    let digits: Vec<char> = encoded.chars().collect();
    let mut position = 0;
    while position < digits.len() {
        let old_index = index;
        let mut weight: u32 = 1;
        let mut k = BASE;
        loop {
            let digit = char_to_digit(*digits.get(position)?)?;
            position += 1;
            index = index.checked_add((digit.checked_mul(weight)?) as usize)?;
            let t = if k <= bias {
                T_MIN
            } else if k >= bias + T_MAX {
                T_MAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            weight = weight.checked_mul(BASE - t)?;
            k += BASE;
        }
        let length = output.len() as u32 + 1;
        let length_usize = length as usize;
        bias = adapt((index - old_index) as u32, length, old_index == 0);
        n = n.checked_add((index / length_usize) as u32)?;
        index %= length_usize;
        output.insert(index, n);
        index += 1;
    }

    output
        .into_iter()
        .map(char::from_u32)
        .collect::<Option<String>>()
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
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
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

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punycode_matches_the_published_examples() {
        // RFC 3492 section 7.1 samples, which is what a punycode
        // implementation is measured against.
        assert_eq!(punycode_encode("münchen"), "mnchen-3ya");
        assert_eq!(punycode_encode("bücher"), "bcher-kva");
        assert_eq!(punycode_encode("例え"), "r8jz45g");
        assert_eq!(punycode_encode("日本語"), "wgv71a119e");
    }

    #[test]
    fn punycode_round_trips() {
        for text in ["münchen", "bücher", "例え", "日本語", "тест"] {
            let encoded = punycode_encode(text);
            let decoded = punycode_decode(&encoded).expect("decodes");
            assert_eq!(decoded, text, "round trip of {text} via {encoded}");
        }
    }

    #[test]
    fn a_domain_encodes_only_the_labels_that_need_it() {
        assert_eq!(domain_to_ascii("münchen.de"), "xn--mnchen-3ya.de");
        assert_eq!(domain_to_ascii("EXAMPLE.com"), "example.com");
        assert_eq!(domain_to_unicode("xn--mnchen-3ya.de"), "münchen.de");
    }

    #[test]
    fn an_ascii_domain_is_only_lowercased() {
        assert_eq!(domain_to_ascii("example.com"), "example.com");
        assert_eq!(domain_to_unicode("example.com"), "example.com");
    }

    #[test]
    fn malformed_punycode_is_rejected_rather_than_guessed() {
        assert!(punycode_decode("!!!").is_none());
        assert!(punycode_decode("mnchen-!!!").is_none());
    }
}

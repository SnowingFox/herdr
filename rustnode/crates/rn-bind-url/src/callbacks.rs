//! The eight callable members.
//!
//! Each is a plain `fn` with an explicit `'s` lifetime on the scope. The
//! lifetime has to be named: V8's callback signature ties the scope, the
//! arguments and the return value to one handle scope, and an elided lifetime
//! would let them unify with the wrong one and fail to compile.
//!
//! The argument shapes are not defensive guesses. `lib/internal/url.js` coerces
//! every value to a string before calling in, so a non-string argument can only
//! arrive from direct misuse of the binding; the callbacks reproduce Node's
//! `CHECK`-based behaviour by treating it as a programming error and answering
//! with the failure value instead of corrupting the components buffer.

use rn_v8_sys::v8;
use url::Url as ParsedUrl;

use crate::format;
use crate::idna;
use crate::install;
use crate::model::Offsets;
use crate::update;
use crate::{path, write_components};

/// `parse(input, base, raiseException)`.
///
/// Returns the canonical `href`, or `undefined` when the input does not parse.
/// `raiseException` switches that `undefined` for a thrown `ERR_INVALID_URL`, and
/// only `lib/internal/url.js`'s `URL` constructor passes `true`.
pub fn parse<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(input) = install::argument_string(scope, &args, 0) else {
        return;
    };
    let base = install::is_string(&args, 1)
        .then(|| install::argument_string(scope, &args, 1))
        .flatten();
    let raise = install::is_true(&args, 2);

    // A base that does not parse is a separate failure from the input not
    // parsing, and Node reports the base in the error. It has to be resolved
    // before the input so the two are not confused.
    if let Some(base) = base.as_deref() {
        if ParsedUrl::parse(base).is_err() {
            if raise {
                install::throw_invalid_url(scope, Some(&input), Some(base));
            }
            return;
        }
    }

    match resolve(&input, base.as_deref()) {
        Some(url) => {
            write_components(Offsets::of(&url).as_array());
            let href = url.as_str();
            match install::string(scope, href) {
                Ok(text) => rv.set(text.into()),
                Err(message) => install::throw_error(scope, &message),
            }
        }
        None => {
            if raise {
                install::throw_invalid_url(scope, Some(&input), base.as_deref());
            }
        }
    }
}

/// Parses `input`, resolving against `base` when one is given.
///
/// `Url::parse` handles the absolute case; `join` is the spec's relative
/// resolution. A URL that cannot be a base refuses relative input, and so does
/// this, matching ada.
fn resolve(input: &str, base: Option<&str>) -> Option<ParsedUrl> {
    match base {
        Some(base) => {
            let base = ParsedUrl::parse(base).ok()?;
            base.join(input).ok()
        }
        None => ParsedUrl::parse(input).ok(),
    }
}

/// `canParse(input, base)`.
///
/// Node implements this as `ada::can_parse`, which is defined to agree with
/// `parse`: it must return true exactly when `parse` would succeed. Implementing
/// it as `resolve(...).is_some()` keeps that relation true by construction
/// rather than by two implementations happening to match.
pub fn can_parse<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(input) = install::argument_string(scope, &args, 0) else {
        return;
    };
    let base = install::is_string(&args, 1)
        .then(|| install::argument_string(scope, &args, 1))
        .flatten();
    let parses = match base.as_deref() {
        // A base that does not parse makes the answer false, not an error.
        Some(base) if ParsedUrl::parse(base).is_err() => false,
        base => resolve(&input, base).is_some(),
    };
    rv.set(v8::Boolean::new(scope, parses).into());
}

/// `getOrigin(input)`.
///
/// Throws `ERR_INVALID_URL` for input that does not parse, and answers
/// `"null"` for every scheme whose origin is opaque. The `blob:` case recurses:
/// a `blob:` URL's origin is the origin of its path, but only when that path
/// parses to an `http` or `https` URL.
pub fn get_origin<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(input) = install::argument_string(scope, &args, 0) else {
        return;
    };
    let Some(url) = ParsedUrl::parse(&input).ok() else {
        // `GetOrigin` calls `ThrowInvalidURL(env, "Invalid URL")` with no input
        // and no base, so the error carries neither property.
        install::throw_invalid_url(scope, None, None);
        return;
    };
    let origin = format::origin(&url);
    match install::string(scope, &origin) {
        Ok(text) => rv.set(text.into()),
        Err(message) => install::throw_error(scope, &message),
    }
}

/// `format(href, fragment, unicode, search, auth)`.
///
/// Re-parses `href`, drops the components the flags turn off, optionally
/// re-encodes the host as Unicode, and returns the serialization. The flags are
/// "keep" flags: `fragment = false` removes the fragment.
pub fn format<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(href) = install::argument_string(scope, &args, 0) else {
        return;
    };
    let keep_fragment = install::is_true(&args, 1);
    let unicode = install::is_true(&args, 2);
    let keep_search = install::is_true(&args, 3);
    let keep_auth = install::is_true(&args, 4);

    let rendered = format::format(&href, keep_fragment, unicode, keep_search, keep_auth);
    match install::string(scope, &rendered) {
        Ok(text) => rv.set(text.into()),
        Err(message) => install::throw_error(scope, &message),
    }
}

/// `update(href, action, value)`.
///
/// Returns the new `href`, or `false` when the action rejects the value. The
/// components buffer is written only on success, because
/// `lib/internal/url.js` keeps using the old context when it sees `false`.
pub fn update<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(href) = install::argument_string(scope, &args, 0) else {
        return;
    };
    let action = args.get(1).uint32_value(scope).unwrap_or(u32::MAX);
    let Some(value) = install::argument_string(scope, &args, 2) else {
        return;
    };

    match update::update(&href, action, &value) {
        Ok(href) => match ParsedUrl::parse(&href) {
            Ok(url) => {
                write_components(Offsets::of(&url).as_array());
                match install::string(scope, &href) {
                    Ok(text) => rv.set(text.into()),
                    Err(message) => install::throw_error(scope, &message),
                }
            }
            // The setter produced a string its own parser rejects, which means
            // the caller must not adopt it.
            Err(_) => rv.set(v8::Boolean::new(scope, false).into()),
        },
        Err(_) => rv.set(v8::Boolean::new(scope, false).into()),
    }
}

/// `pathToFileURL(input, windows[, hostname])`.
///
/// The path is percent-encoded first and parsed second, which is Node's order:
/// `EncodePathChars` covers characters the URL parser would treat as structure,
/// so escaping before the parse is what makes a `#` in a filename stay part of
/// the filename.
///
/// The third argument is the Windows UNC hostname. Node only consults it when
/// `windows` is true, and rustnode runs on POSIX, so it is accepted and ignored;
/// `lib/internal/url.js` only passes it from the UNC branch of `pathToFileURL`,
/// which requires `windows` to be true.
pub fn path_to_file_url<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(input) = install::argument_string(scope, &args, 0) else {
        return;
    };
    let windows = install::is_true(&args, 1);
    if input.is_empty() {
        // Node CHECKs the input is non-empty; an empty path has no `file:` URL.
        install::throw_invalid_url(scope, Some(&input), None);
        return;
    }

    let encoded = path::encode_path(&input, path::PathFlavour::from_windows_flag(windows));
    match ParsedUrl::parse(&encoded) {
        Ok(url) => {
            write_components(Offsets::of(&url).as_array());
            match install::string(scope, url.as_str()) {
                Ok(text) => rv.set(text.into()),
                Err(message) => install::throw_error(scope, &message),
            }
        }
        Err(_) => install::throw_invalid_url(scope, Some(&input), None),
    }
}

/// `domainToASCII(domain)`.
pub fn domain_to_ascii<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(input) = install::argument_string(scope, &args, 0) else {
        return;
    };
    match install::string(scope, &idna::domain_to_ascii(&input)) {
        Ok(text) => rv.set(text.into()),
        Err(message) => install::throw_error(scope, &message),
    }
}

/// `domainToUnicode(domain)`.
pub fn domain_to_unicode<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(input) = install::argument_string(scope, &args, 0) else {
        return;
    };
    match install::string(scope, &idna::domain_to_unicode(&input)) {
        Ok(text) => rv.set(text.into()),
        Err(message) => install::throw_error(scope, &message),
    }
}

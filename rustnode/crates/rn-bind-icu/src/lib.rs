//! `internalBinding('icu')` for rustnode.
//!
//! `lib/internal/util/inspect.js` calls `getStringWidth` on every non-ASCII code
//! point it prints, `lib/buffer.js` calls `transcode` for
//! `Buffer.from(source, from, to)`, and `lib/internal/encoding.js` calls
//! `getConverter`/`decode`/`hasConverter` to build every `TextDecoder` that is
//! not UTF-8 and not a single-byte legacy encoding. Node guards all of them
//! behind `internalBinding('config').hasIntl`, which is true here because V8 is
//! linked with full ICU (`Intl.Segmenter` exists).
//!
//! # Why `getStringWidth` is the important one
//!
//! `util.inspect` uses it to decide column layout, and `internal/util/inspect`
//! is loaded by `internal/errors`, which is loaded by the realm bootstrap. So a
//! missing `icu` namespace fails `require('events')`, `require('fs')` and
//! `require('util')` — not with an ICU error but with
//! `internalBinding('icu'): the namespace has no Rust implementation yet`
//! thrown from deep inside the inspect code. That is why this namespace matters
//! out of proportion to its member count.
//!
//! # Where the ICU calls come from
//!
//! The two subsystems whose answers depend on Unicode property data — column
//! width and the converter surface — ask the ICU that `librusty_v8.a` already
//! carries, through the declarations in [`ffi`], because every hand-copied
//! approximation of those answers disagreed with Node somewhere measurable:
//!
//! * [`width`] is `GetColumnWidth` from `src/node_i18n.cc`. A table-driven
//!   version reported zero columns for `Cn` (unassigned) code points and for
//!   `Mc` spacing marks, where Node reports one for both.
//! * [`converter`] is `ConverterObject`: an ICU handle with its own decoder
//!   state, which is what lets `TextDecoder({ stream: true })` end a chunk
//!   mid-character.
//!
//! [`transcode`] is the exception, and it is the interesting one. It is written
//! out in Rust rather than routed through ICU, because the ICU inside
//! `librusty_v8.a` is a 37-name data subset in which `us-ascii` and `iso8859-1`
//! both alias `windows-1252-html` — so calling it would have produced
//! `windows-1252` semantics for a label that means ISO-8859-1. Node links full
//! ICU, where they are distinct. The four encodings `transcode` accepts make
//! that a total function of four cases rather than a table.
//!
//! The crate's doc comment used to claim the converter surface "needs an ICU
//! converter handle over the ICU V8 bundles" and deferred it on that basis. The
//! claim was wrong in the direction that matters: the whole converter API is in
//! the archive we link, and only absent from the binary because nothing
//! referenced it. See [`ffi`].

pub mod converter;
pub mod ffi;
pub mod transcode;
pub mod width;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/icu.json`.
pub const MEMBERS: &[&str] = &[
    "decode",
    "getConverter",
    "getStringWidth",
    "hasConverter",
    "icuErrName",
    "transcode",
];

/// Members this build does not install.
///
/// Empty: every member `src/node_i18n.cc` publishes is implemented here. The
/// constant stays because `BindingModule::deferred` returns a slice and an empty
/// one is a stronger statement than omitting the override.
pub const DEFERRED: &[(&str, &str)] = &[];

// The one-shot converter template `getConverter` instantiates.
//
// Node builds it per isolate (`isolate_data->set_i18n_converter_template`) and
// instantiates it with `ObjectTemplate::NewInstance`, i.e. without a JavaScript
// constructor. The `FunctionTemplate` here exists only to own an instance
// template carrying one internal field; `new` is unreachable because the
// template is never published.
thread_local! {
    static CONVERTER_TEMPLATE: std::cell::RefCell<Option<v8::Global<v8::ObjectTemplate>>> =
        const { std::cell::RefCell::new(None) };
}

fn converter_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::ObjectTemplate>> {
    CONVERTER_TEMPLATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|template| v8::Local::new(scope, template))
    })
}

pub struct Icu;

impl BindingModule for Icu {
    fn namespace(&self) -> &'static str {
        "icu"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        install_converter_template(scope)?;

        let object = v8::Object::new(scope);
        // Every value is built before any `set`, because `set` takes the scope
        // mutably and constructing inside its arguments would need two live
        // borrows.
        let values: [(&str, v8::Local<'s, v8::Value>); 6] = [
            ("decode", function(scope, "decode", decode)?),
            (
                "getConverter",
                function(scope, "getConverter", get_converter)?,
            ),
            (
                "getStringWidth",
                function(scope, "getStringWidth", get_string_width)?,
            ),
            (
                "hasConverter",
                function(scope, "hasConverter", has_converter)?,
            ),
            ("icuErrName", function(scope, "icuErrName", icu_err_name)?),
            ("transcode", function(scope, "transcode", transcode)?),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Icu);
    rn_core::snapshot_data::register("rn-bind-icu", attach_for_snapshot, restore_from_snapshot);
}

/// Hands the cached converter instance template to the snapshot build.
///
/// Registered with `rn_core::snapshot_data`. The abort names this handle as
/// `OBJECT_TEMPLATE_INFO_TYPE`: `CONVERTER_TEMPLATE` is a `Global<ObjectTemplate>`
/// kept so `getConverter` can build instances later, and nothing in a serialised
/// context reaches it. Attaching it is what makes the template itself
/// serialisable, so a loaded realm builds converters from the same template the
/// build-time realm used — and keeps its internal-field count.
fn attach_for_snapshot<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _context: v8::Local<'s, v8::Context>,
) -> v8::Local<'s, v8::Data> {
    let template = CONVERTER_TEMPLATE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|template| v8::Local::new(scope, template))
    });
    match template {
        Some(template) => template.into(),
        // Never reached for a realm that installed `icu`: `install_converter_template`
        // is the first thing `install` does. `undefined` would not be `Data`-
        // convertible to a template, so the placeholder is the build's own
        // refusal rather than a silent absence — but an uninstalled namespace has
        // no provider call at all, so this is unreachable in practice.
        None => v8::undefined(scope).into(),
    }
}

/// Puts the converter instance template back from the blob.
fn restore_from_snapshot(
    scope: &mut v8::PinScope<'_, '_>,
    data: v8::Local<'_, v8::Data>,
) -> Result<(), String> {
    // `undefined` is what the provider hands over for a realm that never
    // installed `icu`, and it converts to a `Value` but not to a template. An
    // `ObjectTemplate` is `Data` rather than `Value`, so the two checks are in
    // this order: a `Value` means "nothing to restore", anything else must be the
    // template.
    if let Ok(value) = v8::Local::<v8::Value>::try_from(data) {
        if value.is_undefined() {
            CONVERTER_TEMPLATE.with(|slot| *slot.borrow_mut() = None);
            return Ok(());
        }
        return Err("the blob's icu entry is a value, not an instance template".to_string());
    }
    let Ok(template) = v8::Local::<v8::ObjectTemplate>::try_from(data) else {
        return Err("the blob's icu entry is not an instance template".to_string());
    };
    let rooted = v8::Global::new(scope.as_ref(), template);
    CONVERTER_TEMPLATE.with(|slot| *slot.borrow_mut() = Some(rooted));
    Ok(())
}

fn install_converter_template(scope: &mut v8::PinScope<'_, '_>) -> Result<(), String> {
    // `set_internal_field_count` is on the instance template, so the object is
    // built from a `FunctionTemplate`'s instance template rather than from a
    // bare `ObjectTemplate` — the same shape `blob` uses for its handles.
    let template = v8::FunctionTemplate::builder(no_converter_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    if let Some(name) = v8::String::new(scope, "Converter") {
        template.set_class_name(name);
    }
    let instance = template.instance_template(scope);
    CONVERTER_TEMPLATE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, instance)));
    Ok(())
}

/// A handle is only ever built by `getConverter`, so `new` is refused.
fn no_converter_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    throw_type_error(scope, "Illegal constructor");
}

fn get_string_width(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // Node's `CHECK(args[0]->IsString())` is a hard abort there; a binding must
    // not abort here, so a non-string is a `TypeError` and the caller sees a
    // bug rather than a silent `0`.
    let Ok(text) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        throw_type_error(scope, "getStringWidth expects a string");
        return;
    };
    // `getStringWidth(str, ambiguousAsFullWidth, expandEmojiSequence)`.
    let ambiguous_as_full_width = args.get(1).is_true();
    let expand_emoji = !args.get(2).is_boolean() || args.get(2).is_true();

    // `TwoByteValue`, not a Rust `&str`: a lone surrogate is a legal unit in the
    // string Node measures, and it takes one column.
    let mut units = vec![0u16; text.length()];
    text.write_v2(scope, 0, &mut units, v8::WriteFlags::empty());

    let width = width::string_width(&units, ambiguous_as_full_width, expand_emoji);
    rv.set(v8::Integer::new(scope, width as i32).into());
}

fn transcode(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `transcode(source, fromEncoding, toEncoding)` returns either a Buffer or a
    // numeric `UErrorCode`. `lib/buffer.js` checks `typeof result !== 'number'`
    // and builds the error from `icuErrName` when it got one.
    let Some(source) = view_bytes(args.get(0)) else {
        rv.set(v8::Integer::new(scope, ffi::U_ILLEGAL_ARGUMENT_ERROR).into());
        return;
    };
    // `ParseEncoding` returns its default for a non-string, and the default is
    // `BUFFER`, which `SupportedEncoding` rejects — so a missing label is the
    // same `U_ILLEGAL_ARGUMENT_ERROR` as an unknown one.
    let from = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let to = args
        .get(2)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();

    match transcode::transcode(&source, &from, &to) {
        Ok(bytes) => rv.set(make_buffer(scope, &bytes)),
        Err(code) => rv.set(v8::Integer::new(scope, code).into()),
    }
}

fn get_converter(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `getConverter(label, flags)`. `lib/internal/encoding.js` passes exactly
    // two arguments and treats `undefined` as "not supported", so a missing or
    // unresolvable label leaves the return value unset.
    let Some(label) = args
        .get(0)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
    else {
        return;
    };
    let flags = args.get(1).uint32_value(scope).unwrap_or(0);
    let Some(template) = converter_template(scope) else {
        return;
    };
    if let Some(object) = converter::create(scope, template, &label, flags) {
        rv.set(object.into());
    }
}

fn decode(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `decode(handle, input, flags, encoding)`.
    let Ok(handle) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"handle\" argument must be an instance of Converter",
        );
        return;
    };
    let Some(input) = view_bytes(args.get(1)) else {
        throw_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"input\" argument must be an instance of SharedArrayBuffer, \
             ArrayBuffer or ArrayBufferView.",
        );
        return;
    };
    let flags = args.get(2).uint32_value(scope).unwrap_or(0);
    // The fourth argument is only used to name the encoding in the error, and
    // Node words it from the JavaScript side's own label. Keeping it out of the
    // Rust path means the message is produced where the label lives.
    let encoding = args
        .get(3)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
        .unwrap_or_default();

    match converter::decode(handle, &input, flags) {
        Ok(units) => {
            if let Some(text) = converter::units_to_string(scope, &units) {
                rv.set(text.into());
            }
        }
        Err(converter::DecodeError::NotAHandle) => throw_with_code(
            scope,
            "ERR_INVALID_ARG_TYPE",
            "The \"handle\" argument must be an instance of Converter",
        ),
        Err(converter::DecodeError::InvalidData) => throw_with_code(
            scope,
            "ERR_ENCODING_INVALID_ENCODED_DATA",
            &format!("The encoded data was not valid for encoding {encoding}"),
        ),
    }
}

fn has_converter(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(label) = args
        .get(0)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope))
    else {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    };
    rv.set(v8::Boolean::new(scope, converter::has_converter(&label)).into());
}

fn icu_err_name(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // Node's `CHECK(args[0]->IsInt32())` becomes a coercion here: the only
    // caller is `lib/buffer.js`, which passes the `UErrorCode` number it got
    // back from `transcode`.
    let code = args.get(0).int32_value(scope).unwrap_or(ffi::U_ZERO_ERROR);
    if let Some(text) = v8::String::new(scope, &transcode::error_name(code)) {
        rv.set(text.into());
    }
}

/// The bytes of an `ArrayBuffer`, `SharedArrayBuffer` or `ArrayBufferView`
/// argument, or `None` when it is none of those.
///
/// `ArrayBufferViewContents` reads a whole buffer for the first two and the
/// view's own `byteOffset`/`byteLength` for the third. Copying is what Node does
/// for a shared buffer to avoid tearing, and it is harmless for the others: a
/// borrowed slice into memory JavaScript can still mutate cannot be held across
/// a call that might run JavaScript.
fn view_bytes(value: v8::Local<v8::Value>) -> Option<Vec<u8>> {
    // A detached buffer reports a zero byte length, so it reads as empty input
    // rather than as an error.
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

/// A `Buffer` over `bytes`.
///
/// `Buffer` *is* a `Uint8Array` carrying `Buffer.prototype`, so setting the
/// prototype is what makes `Buffer.isBuffer` true on the result. Reading the
/// prototype off the global rather than through `rn-bind-buffer` keeps one
/// binding out of another's state, which is the choice `udp_wrap` and
/// `http_parser` also made.
fn make_buffer<'s>(scope: &mut v8::PinScope<'s, '_>, bytes: &[u8]) -> v8::Local<'s, v8::Value> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let Some(view) = v8::Uint8Array::new(scope, buffer, 0, bytes.len()) else {
        return v8::undefined(scope).into();
    };
    if let Some(prototype) = buffer_prototype(scope) {
        view.set_prototype(scope, prototype.into());
    }
    view.into()
}

fn buffer_prototype<'s>(scope: &v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Buffer")?;
    let buffer = global.get(scope, key.into())?;
    let object = v8::Local::<v8::Object>::try_from(buffer).ok()?;
    let prototype = v8::String::new(scope, "prototype")?;
    let value = object.get(scope, prototype.into())?;
    v8::Local::<v8::Object>::try_from(value).ok()
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

/// Throws a `TypeError` carrying `code`, which is the shape
/// `ERR_ENCODING_INVALID_ENCODED_DATA` and `ERR_INVALID_ARG_TYPE` have once
/// Node's error machinery has built them.
fn throw_with_code(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str) {
    let text = v8::String::new(scope, message).unwrap_or_else(|| v8::String::empty(scope));
    let exception = v8::Exception::type_error(scope, text);
    if let (Ok(object), Some(code_key), Some(code_value)) = (
        v8::Local::<v8::Object>::try_from(exception),
        v8::String::new(scope, "code"),
        v8::String::new(scope, code),
    ) {
        object.set(scope, code_key.into(), code_value.into());
    }
    scope.throw_exception(exception);
}

/// `rn_core::named_method`, which is `SetMethod` complete: name and length 0.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_contract_member_is_installed_and_none_is_deferred() {
        // `contracts/icu.json` records six members. Node publishes all six from
        // `CreatePerIsolateProperties`, and this build now does too.
        assert_eq!(MEMBERS.len(), 6);
        for member in [
            "decode",
            "getConverter",
            "getStringWidth",
            "hasConverter",
            "icuErrName",
            "transcode",
        ] {
            assert!(MEMBERS.contains(&member), "{member} must be installed");
        }
        assert!(DEFERRED.is_empty(), "nothing is deferred");
    }

    #[test]
    fn error_names_come_from_icu() {
        // The old table knew two codes and called everything else
        // U_UNKNOWN_ERROR; `lib/buffer.js` puts this name in the thrown error's
        // message, so an unknown code was a misleading message rather than a
        // missing one.
        assert_eq!(transcode::error_name(0), "U_ZERO_ERROR");
        assert_eq!(
            transcode::error_name(ffi::U_ILLEGAL_ARGUMENT_ERROR),
            "U_ILLEGAL_ARGUMENT_ERROR"
        );
        // `u_errorName`'s answer for an unassigned code is ICU's own
        // "[BOGUS UErrorCode]", which is what the C++ passes straight through.
        assert_eq!(transcode::error_name(0x1010), "[BOGUS UErrorCode]");
    }
}

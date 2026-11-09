//! Installing the `buffer` namespace object.
//!
//! The 40 names come from `Initialize()` in `src/node_buffer.cc`, which is the
//! authoritative list: every `SetMethod`/`SetMethodNoSideEffect`/
//! `SetFastMethod` call there is one member, plus the two constants it sets
//! directly and the three fast-API callbacks. `lib/buffer.js`,
//! `lib/internal/buffer.js` and `lib/internal/webstreams/util.js` between them
//! destructure all 40, which is what `contracts/buffer.json` records.
//!
//! # Callback style
//!
//! Every callback is a plain `fn`, not a closure. V8 stores callback data in a
//! statically sized slot, and a capturing closure would overrun it; a plain
//! function has no captures and monomorphises to a bare pointer.
//!
//! Each `mkfn!` call hoists the built function into a local before handing it to
//! `define`, because `FunctionTemplate::builder(...).build(scope)` borrows the
//! scope mutably and `object.set(scope, ...)` would need it again in the same
//! expression — which the borrow checker rejects as two live mutable borrows.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;
use rn_v8_sys::v8::Local;

use crate::bytes;
use crate::codec::Encoding;
use crate::encoding;
use crate::misc;

/// Binds a Rust callback as a namespace function.
macro_rules! mkfn {
    ($installer:expr, $name:expr, $callback:expr) => {{
        let template = v8::FunctionTemplate::builder($callback).build($installer.scope);
        let function = template
            .get_function($installer.scope)
            .ok_or_else(|| format!("cannot allocate buffer.{}", $name))?;
        $installer.define($name, function.into())?;
    }};
}

/// The `internalBinding('buffer')` namespace.
pub struct Buffer;

impl BindingModule for Buffer {
    fn namespace(&self) -> &'static str {
        "buffer"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        let mut installer = Installer { scope, object };
        installer.install_all()?;
        installer.define_constants()?;
        Ok(installer.object)
    }
}

/// Every member `Initialize()` installs, and the only members
/// `lib/**` reads.
pub const MEMBERS: &[&str] = &[
    // Encoding: decode.
    "asciiSlice",
    "base64Slice",
    "base64urlSlice",
    "latin1Slice",
    "hexSlice",
    "ucs2Slice",
    "utf8Slice",
    // Encoding: encode.
    "base64Write",
    "base64urlWrite",
    "hexWrite",
    "ucs2Write",
    "asciiWriteStatic",
    "latin1WriteStatic",
    "utf8WriteStatic",
    // Lengths.
    "byteLengthUtf8",
    "byteLengthUtf8Fast",
    "stringLengthUtf8",
    // Predicates.
    "isUtf8",
    "isAscii",
    "isLatin1",
    // Byte manipulation.
    "compare",
    "compareOffset",
    "copy",
    "fill",
    "indexOfBuffer",
    "indexOfNumber",
    "indexOfString",
    "swap16",
    "swap32",
    "swap64",
    "mask",
    // Misc.
    "atob",
    "btoa",
    "setBufferPrototype",
    "setDetachKey",
    "createUnsafeArrayBuffer",
    "copyArrayBuffer",
    "arrayBufferAlignedOffset",
    // Constants.
    "kMaxLength",
    "kStringMaxLength",
];

struct Installer<'a, 's, 'i> {
    scope: &'a mut v8::PinScope<'s, 'i>,
    object: Local<'s, v8::Object>,
}

impl<'a, 's, 'i> Installer<'a, 's, 'i> {
    fn install_all(&mut self) -> Result<(), String> {
        // Encoding. The closures below are *not* capturing: each one is a plain
        // `fn` with the encoding supplied at the call site inside the function.
        mkfn!(self, "asciiSlice", ascii_slice);
        mkfn!(self, "base64Slice", base64_slice);
        mkfn!(self, "base64urlSlice", base64url_slice);
        mkfn!(self, "latin1Slice", latin1_slice);
        mkfn!(self, "hexSlice", hex_slice);
        mkfn!(self, "ucs2Slice", ucs2_slice);
        mkfn!(self, "utf8Slice", utf8_slice);

        mkfn!(self, "base64Write", base64_write);
        mkfn!(self, "base64urlWrite", base64url_write);
        mkfn!(self, "hexWrite", hex_write);
        mkfn!(self, "ucs2Write", ucs2_write);
        mkfn!(self, "asciiWriteStatic", ascii_write_static);
        mkfn!(self, "latin1WriteStatic", latin1_write_static);
        mkfn!(self, "utf8WriteStatic", utf8_write_static);

        // Lengths.
        mkfn!(self, "byteLengthUtf8", byte_length_utf8);
        mkfn!(self, "byteLengthUtf8Fast", byte_length_utf8_fast);
        mkfn!(self, "stringLengthUtf8", string_length_utf8);

        // Predicates.
        mkfn!(self, "isUtf8", is_utf8);
        mkfn!(self, "isAscii", is_ascii);
        mkfn!(self, "isLatin1", is_latin1);

        // Byte manipulation.
        mkfn!(self, "compare", compare);
        mkfn!(self, "compareOffset", compare_offset);
        mkfn!(self, "copy", copy);
        mkfn!(self, "fill", fill);
        mkfn!(self, "indexOfBuffer", index_of_buffer);
        mkfn!(self, "indexOfNumber", index_of_number);
        mkfn!(self, "indexOfString", index_of_string);
        mkfn!(self, "swap16", swap16);
        mkfn!(self, "swap32", swap32);
        mkfn!(self, "swap64", swap64);
        mkfn!(self, "mask", mask);

        // Misc.
        mkfn!(self, "atob", atob);
        mkfn!(self, "btoa", btoa);
        mkfn!(self, "setBufferPrototype", set_buffer_prototype);
        mkfn!(self, "setDetachKey", set_detach_key);
        mkfn!(self, "createUnsafeArrayBuffer", create_unsafe_array_buffer);
        mkfn!(self, "copyArrayBuffer", copy_array_buffer);
        mkfn!(
            self,
            "arrayBufferAlignedOffset",
            array_buffer_aligned_offset
        );
        Ok(())
    }

    fn define_constants(&mut self) -> Result<(), String> {
        let max_length = v8::Number::new(self.scope, misc::max_length() as f64);
        self.define("kMaxLength", max_length.into())?;
        let string_max_length = v8::Number::new(self.scope, misc::string_max_length() as f64);
        self.define("kStringMaxLength", string_max_length.into())
    }

    fn define(&mut self, name: &str, value: Local<'s, v8::Value>) -> Result<(), String> {
        let key = v8::String::new(self.scope, name)
            .ok_or_else(|| format!("cannot allocate name for buffer.{name}"))?;
        self.object
            .set(self.scope, key.into(), value)
            .ok_or_else(|| format!("cannot define buffer.{name}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn ascii_slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::slice(scope, args, Encoding::Ascii) {
        rv.set(value.into());
    }
}

fn base64_slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::slice(scope, args, Encoding::Base64) {
        rv.set(value.into());
    }
}

fn base64url_slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::slice(scope, args, Encoding::Base64Url) {
        rv.set(value.into());
    }
}

fn latin1_slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::slice(scope, args, Encoding::Binary) {
        rv.set(value.into());
    }
}

fn hex_slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::slice(scope, args, Encoding::Hex) {
        rv.set(value.into());
    }
}

fn ucs2_slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::slice(scope, args, Encoding::Ucs2) {
        rv.set(value.into());
    }
}

fn utf8_slice<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::slice(scope, args, Encoding::Utf8) {
        rv.set(value.into());
    }
}

fn base64_write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::write(scope, args, Encoding::Base64) {
        rv.set_double(value);
    }
}

fn base64url_write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::write(scope, args, Encoding::Base64Url) {
        rv.set_double(value);
    }
}

fn hex_write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::write(scope, args, Encoding::Hex) {
        rv.set_double(value);
    }
}

fn ucs2_write<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::write(scope, args, Encoding::Ucs2) {
        rv.set_double(value);
    }
}

fn ascii_write_static<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::write(scope, args, Encoding::Ascii) {
        rv.set_double(value);
    }
}

fn latin1_write_static<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::write(scope, args, Encoding::Binary) {
        rv.set_double(value);
    }
}

fn utf8_write_static<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::write(scope, args, Encoding::Utf8) {
        rv.set_double(value);
    }
}

// ---------------------------------------------------------------------------
// Lengths and predicates
// ---------------------------------------------------------------------------

fn byte_length_utf8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::byte_length_utf8(scope, args) {
        rv.set_double(value);
    }
}

fn byte_length_utf8_fast<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::byte_length_utf8_fast(scope, args) {
        rv.set_double(value);
    }
}

fn string_length_utf8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::string_length_utf8(scope, args) {
        rv.set_double(value);
    }
}

fn is_utf8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::is_utf8(scope, args) {
        rv.set_bool(value);
    }
}

fn is_ascii<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::is_ascii(scope, args) {
        rv.set_bool(value);
    }
}

fn is_latin1<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = encoding::is_latin1(scope, args) {
        rv.set_bool(value);
    }
}

// ---------------------------------------------------------------------------
// Byte manipulation
// ---------------------------------------------------------------------------

fn compare<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::compare(scope, args) {
        rv.set_int32(value);
    }
}

fn compare_offset<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::compare_offset(scope, args) {
        rv.set_int32(value);
    }
}

fn copy<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::copy(scope, args) {
        rv.set_double(value);
    }
}

fn fill<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::fill(scope, args) {
        rv.set_int32(value);
    }
}

fn index_of_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::index_of_buffer(scope, args) {
        rv.set_double(value);
    }
}

fn index_of_number<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::index_of_number(scope, args) {
        rv.set_double(value);
    }
}

fn index_of_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::index_of_string(scope, args) {
        rv.set_double(value);
    }
}

fn swap16<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::swap(scope, args, 2) {
        rv.set_bool(value);
    }
}

fn swap32<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::swap(scope, args, 4) {
        rv.set_bool(value);
    }
}

fn swap64<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::swap(scope, args, 8) {
        rv.set_bool(value);
    }
}

fn mask<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = bytes::mask(scope, args) {
        rv.set_bool(value);
    }
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

fn atob<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let value = args.get(0);
    if !crate::args::require_string(scope, value) {
        return;
    }
    match misc::atob_result(scope, value) {
        Ok(text) => rv.set(text.into()),
        Err(code) => rv.set_int32(code),
    }
}

fn btoa<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let value = args.get(0);
    if !crate::args::require_string(scope, value) {
        return;
    }
    match misc::btoa_result(scope, value) {
        Ok(text) => rv.set(text.into()),
        Err(code) => rv.set_int32(code),
    }
}

fn set_buffer_prototype<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = misc::set_buffer_prototype(scope, args) {
        rv.set_bool(value);
    }
}

fn set_detach_key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = misc::set_detach_key(scope, args) {
        rv.set_bool(value);
    }
}

fn create_unsafe_array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(buffer) = misc::create_unsafe_array_buffer(scope, args) {
        rv.set(buffer.into());
    }
}

fn copy_array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = misc::copy_array_buffer(scope, args) {
        rv.set_double(value);
    }
}

fn array_buffer_aligned_offset<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    if let Some(value) = misc::array_buffer_aligned_offset(scope, args) {
        rv.set_double(value);
    }
}

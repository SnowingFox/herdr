//! `crc32()` for `internalBinding('zlib')`.
//!
//! `lib/zlib.js` exposes `crc32(data, value = 0)` and seeds the accumulator
//! from `value`, so this has to be zlib's running CRC-32 (the reflected
//! polynomial 0xEDB88320), not a one-shot hash.

use libz_rs_sys as z;
use rn_v8_sys::v8;

/// Extends the running zlib CRC-32 in `value` with `data`.
///
/// `value` is the running checksum, exactly what the JS layer threads through
/// repeated `crc32(chunk, state)` calls in `internal/zip/`.
pub fn crc32(value: u32, data: &[u8]) -> u32 {
    // SAFETY: `data` is a valid slice for its own length, which is what `crc32`
    // requires. A null pointer is only passed for an empty slice, which zlib
    // explicitly allows.
    let crc = unsafe { z::crc32(value as std::ffi::c_ulong, data.as_ptr(), data.len() as u32) };
    crc as u32
}

/// Installs `crc32` and `ZLIB_VERSION` on the namespace object.
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let function = v8::Function::builder(crc32_callback).build(scope);
    let Some(function) = function else {
        return Err("cannot allocate zlib crc32".to_string());
    };
    let Some(key) = v8::String::new(scope, "crc32") else {
        return Err("cannot allocate zlib crc32 name".to_string());
    };
    target.set(scope, key.into(), function.into());

    let Some(version) = v8::String::new(scope, crate::constants::ZLIB_VERSION) else {
        return Err("cannot allocate zlib version".to_string());
    };
    let Some(key) = v8::String::new(scope, "ZLIB_VERSION") else {
        return Err("cannot allocate zlib version name".to_string());
    };
    target.set(scope, key.into(), version.into());
    Ok(())
}

/// `crc32(data, value = 0)`, where `data` is a string or any `ArrayBufferView`.
fn crc32_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let value = args.get(1).uint32_value(scope).unwrap_or(0);
    let data = args.get(0);

    let checksum = if data.is_string() {
        // `lib/zlib.js` passes strings straight through; Node's `Utf8Value`
        // encodes them as UTF-8 before checksumming.
        let Some(text) = data.to_string(scope) else {
            return;
        };
        let encoded = text.to_rust_string_lossy(scope);
        crc32(value, encoded.as_bytes())
    } else {
        let Ok(view) = v8::Local::<v8::ArrayBufferView>::try_from(data) else {
            let Some(message) = v8::String::new(scope, "data must be a string or a Buffer") else {
                return;
            };
            let exception = v8::Exception::type_error(scope, message);
            scope.throw_exception(exception);
            return;
        };
        let pointer = view.data().cast::<u8>();
        let length = view.byte_length();
        if pointer.is_null() || length == 0 {
            crc32(value, &[])
        } else {
            // SAFETY: the view's backing store holds `byte_length()` bytes at
            // `data()`.
            crc32(value, unsafe {
                std::slice::from_raw_parts(pointer, length)
            })
        }
    };

    rv.set_uint32(checksum);
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn crc32_of_hello_world_matches_zlib() {
        // The gate value from the task: zlib's crc32 of the ASCII bytes.
        assert_eq!(crc32(0, b"hello world"), 0x0d4a_1185);
    }

    #[test]
    fn crc32_matches_the_published_check_value() {
        assert_eq!(crc32(0, b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(0, b""), 0);
    }

    #[test]
    fn crc32_accumulates_across_chunks() {
        let data = b"chunked accumulation over several calls";
        let whole = crc32(0, data);

        // Splitting the input must not change the result: the second call
        // continues from the first call's checksum.
        for split in 1..data.len() {
            let (head, tail) = data.split_at(split);
            let state = crc32(0, head);
            assert_eq!(crc32(state, tail), whole, "split at {split}");
        }
    }

    #[test]
    fn crc32_seed_is_used_as_the_running_value() {
        // Seeding with a previous result equals checksumming the concatenation.
        let first = b"first part ";
        let second = b"second part";
        let seeded = crc32(crc32(0, first), second);
        assert_eq!(seeded, crc32(0, &[&first[..], &second[..]].concat()));
        assert_ne!(seeded, crc32(0, second));
    }
}

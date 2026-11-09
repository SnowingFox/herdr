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

/// Reflected CRC-32C (Castagnoli) polynomial, `0x1EDC6F41` reversed.
const CRC32C_POLYNOMIAL: u32 = 0x82f6_3b78;

/// The 256-entry lookup table for the reflected CRC-32C polynomial.
static CRC32C_TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(|| {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC32C_POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
});

/// Extends the running CRC-32C in `value` with `data`.
///
/// Node implements this with `absl::ExtendCrc32c`, which uses the same
/// "running checksum in, running checksum out" convention as `crc32()`, so the
/// JS layer can thread a partial result through repeated calls the same way.
pub fn crc32c(value: u32, data: &[u8]) -> u32 {
    let table = &*CRC32C_TABLE;
    let mut crc = !value;
    for byte in data {
        crc = table[((crc ^ u32::from(*byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Installs `crc32`, `crc32c` and `ZLIB_VERSION` on the namespace object.
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    let crc32_function = v8::Function::builder(crc32_callback).build(scope);
    let Some(crc32_function) = crc32_function else {
        return Err("cannot allocate zlib crc32".to_string());
    };
    let Some(key) = v8::String::new(scope, "crc32") else {
        return Err("cannot allocate zlib crc32 name".to_string());
    };
    target.set(scope, key.into(), crc32_function.into());

    let crc32c_function = v8::Function::builder(crc32c_callback).build(scope);
    let Some(crc32c_function) = crc32c_function else {
        return Err("cannot allocate zlib crc32c".to_string());
    };
    let Some(key) = v8::String::new(scope, "crc32c") else {
        return Err("cannot allocate zlib crc32c name".to_string());
    };
    target.set(scope, key.into(), crc32c_function.into());

    let Some(version) = v8::String::new(scope, crate::constants::ZLIB_VERSION) else {
        return Err("cannot allocate zlib version".to_string());
    };
    let Some(key) = v8::String::new(scope, "ZLIB_VERSION") else {
        return Err("cannot allocate zlib version name".to_string());
    };
    target.set(scope, key.into(), version.into());
    Ok(())
}

/// Reads `crc32`-style arguments and applies `checksum` to them.
///
/// `lib/zlib.js` already validated that `data` is a string or an
/// `ArrayBufferView` and that `value` is a `uint32`, so this only has to handle
/// those two shapes.
fn checksum_callback(
    scope: &mut v8::PinScope,
    args: &v8::FunctionCallbackArguments,
    rv: &mut v8::ReturnValue,
    checksum: fn(u32, &[u8]) -> u32,
) {
    let value = args.get(1).uint32_value(scope).unwrap_or(0);
    let data = args.get(0);

    let result = if data.is_string() {
        // Node converts the argument with `Utf8Value`, so a string is checksummed
        // as its UTF-8 bytes.
        match data.to_string(scope) {
            Some(text) => checksum(value, text.to_rust_string_lossy(scope).as_bytes()),
            None => return,
        }
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
            checksum(value, &[])
        } else {
            // SAFETY: the view's backing store holds `byte_length()` bytes at
            // `data()`.
            checksum(value, unsafe {
                std::slice::from_raw_parts(pointer, length)
            })
        }
    };

    rv.set_uint32(result);
}

/// `crc32(data, value = 0)`.
fn crc32_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    checksum_callback(scope, &args, &mut rv, crc32);
}

/// `crc32c(data, value = 0)`, the Castagnoli variant.
fn crc32c_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    checksum_callback(scope, &args, &mut rv, crc32c);
}

#[cfg(test)]
mod tests {
    use super::{crc32, crc32c};

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
    fn crc32c_matches_the_published_check_value() {
        // The Castagnoli polynomial's standard check value.
        assert_eq!(crc32c(0, b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(0, b""), 0);
    }

    #[test]
    fn crc32c_accumulates_across_chunks() {
        let data = b"chunked crc32c accumulation";
        let whole = crc32c(0, data);
        for split in 1..data.len() {
            let (head, tail) = data.split_at(split);
            assert_eq!(crc32c(crc32c(0, head), tail), whole, "split at {split}");
        }
    }

    #[test]
    fn crc32_and_crc32c_are_different_algorithms() {
        // Different polynomials must not collide on ordinary input.
        let data = b"hello world";
        assert_ne!(crc32(0, data), crc32c(0, data));
        assert_eq!(crc32(0, data), 0x0d4a_1185);
        assert_eq!(crc32c(0, data), 0xc994_65aa);
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

//! Where every published value came from.
//!
//! The tables in `config` and `constants` are not transcribed from a running
//! Node binary, because that would freeze one machine's build options. They are
//! derived from the headers Node 28 itself compiles against, so regenerating
//! against a new Node pin is mechanical.
//!
//! # Regeneration
//!
//! `tools/node-pin.toml` names the pinned Node revision. With that checkout at
//! `/tmp/node` (`git sparse-checkout set src lib benchmark deps`), compile
//! `xtask/constants_probe.c` against `deps/uv/include`, `deps/zlib`,
//! `deps/brotli/c/include`, `deps/zstd/lib` and `deps/openssl/openssl/include`
//! with `_GNU_SOURCE` defined:
//!
//! ```text
//! gcc -D_GNU_SOURCE -o probe xtask/constants_probe.c \
//!   -Ideps/uv/include -Ideps/zlib -Ideps/brotli/c/include -Ideps/zstd/lib \
//!   -Ideps/openssl/openssl/include -Ideps/openssl/config
//! ./probe
//! ```
//!
//! It prints one `NAME VALUE` line per constant, which is what the `*_VALUES`
//! tables contain. `MODE_*` lines in the output are renamed to the mode names
//! Node publishes (`DEFLATE`, `GZIP`, ...) and `UV_PRIORITY_*` to
//! `PRIORITY_*`, matching the local aliases in `src/node_constants.cc`.
//!
//! The probe must define `_GNU_SOURCE` for the same reason Node's build does:
//! `<fcntl.h>` only exposes `O_DIRECT` and `O_NOATIME` with it, and Node
//! publishes both.
//!
//! `tests/platform.rs` re-derives the OS, fs, signal, errno and dlopen tables
//! from `libc` at test time, so a stale table fails the build rather than
//! drifting silently.
//!
//! # Provenance per table
//!
//! | Table | Source in Node 28 |
//! | --- | --- |
//! | `config::VALUES` | `src/node_config.cc` |
//! | `constants::OS_VALUES` | `uv.h`, `UV_UDP_REUSEADDR` |
//! | `constants::DLOPEN_VALUES` | `DefineDLOpenConstants`, `<dlfcn.h>` |
//! | `constants::ERRNO_VALUES` | `DefineErrnoConstants`, `<cerrno>` |
//! | `constants::SIGNALS_VALUES` | `DefineSignalConstants`, `<csignal>` |
//! | `constants::PRIORITY_VALUES` | `DefinePriorityConstants`, `uv.h` |
//! | `constants::FS_VALUES` | `DefineFsConstants`, `<fcntl.h>`, `<sys/stat.h>`, `uv.h` |
//! | `constants::CRYPTO_VALUES` | `DefineCryptoConstants`, OpenSSL 4.1.0 headers |
//! | `constants::ZLIB_VALUES` | `DefineZlibConstants`, `zlib.h`, `brotli`, `zstd` |
//! | `constants::TRACE_VALUES` | `DefineTraceConstants`, V8 trace phase macros |
//! | `constants::INTERNAL_VALUES` | `DefineInternalConstants`, `src/node_constants.h` |
//!
//! # Values that are not header-derived
//!
//! These have no single header expression, so they are written out with the
//! reason recorded next to them in the source:
//!
//! - `RSA_SSLV23_PADDING` and the three `RSA_PSS_SALTLEN_*` entries: modern
//!   OpenSSL hides them behind `OPENSSL_NO_DEPRECATED`, and Node restores them
//!   with explicit `#define` fallbacks in `src/node_constants.cc`.
//! - `Z_MIN_*`, `Z_MAX_*`, `Z_DEFAULT_*` and the `node_zlib_mode` entries:
//!   `src/node_zlib.cc` defines them, not a dependency header. `Z_MAX_CHUNK` is
//!   `std::numeric_limits<double>::infinity()`, which JavaScript sees as
//!   `Infinity`.
//! - `TRACE_EVENT_PHASE_*`: V8 declares them as character literals; the
//!   published number is the character code.
//! - `crypto.defaultCoreCipherList`: `DEFAULT_CIPHER_LIST_CORE` in
//!   `src/node_constants.h` is a chain of adjacent string literals.
//! - `config.bits`: `8 * sizeof(intptr_t)`, computed at runtime in `config.rs`.
//!
//! # Deliberate omissions
//!
//! Node wraps several `NODE_DEFINE_CONSTANT` calls in `#ifdef`. On Linux those
//! guards exclude exactly these names, and publishing them would report a
//! platform fact that is false:
//!
//! - `signals`: `SIGBREAK` (Windows only), `SIGLOST` and `SIGINFO` (BSD and
//!   Solaris only), `SIGUNUSED` (removed from glibc).
//! - `fs`: `O_SYMLINK` (macOS and BSD only). `lib/fs.js` gates `lchmod` on it,
//!   so its absence is what keeps `fs.lchmod` undefined on Linux, as in Node.

/// Node revision the tables were generated against.
pub const NODE_REVISION: &str = "f344e7f552e3656bd37517151c5dc87d22b33771";

/// Versions of the dependencies whose headers produced the numeric tables.
///
/// These are recorded because `OPENSSL_VERSION_NUMBER`, `ZLIB_VERNUM` and the
/// zstd/brotli tables change with the dependency, not with Node.
pub mod dependency_versions {
    /// `deps/openssl/VERSION.dat`.
    pub const OPENSSL_VERSION: &str = "4.1.0";
    /// `OPENSSL_VERSION_NUMBER` for the above, from `opensslv.h`.
    pub const OPENSSL_VERSION_NUMBER: i64 = 1_074_790_400;
    /// `deps/zlib/zlib.h`.
    pub const ZLIB_VERSION: &str = "1.3.2.1-motley";
    /// `ZLIB_VERNUM` for the above.
    pub const ZLIB_VERNUM: i64 = 0x1321;
    /// `deps/uv/include/uv/version.h`.
    pub const LIBUV_VERSION: &str = "1.52.1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CRYPTO_VALUES, ZLIB_VALUES};
    use crate::Value;

    fn lookup(table: &[(&'static str, Value)], name: &str) -> Option<Value> {
        table
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    }

    #[test]
    fn version_constants_match_recorded_versions() {
        assert_eq!(
            lookup(CRYPTO_VALUES, "OPENSSL_VERSION_NUMBER"),
            Some(Value::int(dependency_versions::OPENSSL_VERSION_NUMBER))
        );
        assert_eq!(
            lookup(ZLIB_VALUES, "ZLIB_VERNUM"),
            Some(Value::int(dependency_versions::ZLIB_VERNUM))
        );
    }

    #[test]
    fn recorded_node_revision_is_a_full_sha() {
        assert_eq!(NODE_REVISION.len(), 40);
        assert!(NODE_REVISION.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

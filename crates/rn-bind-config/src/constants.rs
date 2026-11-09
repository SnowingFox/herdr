//! `internalBinding('constants')`.
//!
//! `src/node_constants.cc` in Node 28, plus the zlib table from
//! `src/node_zlib.cc::DefineZlibConstants`. The namespace is a tree:
//!
//! ```text
//! constants
//!   os        UV_UDP_REUSEADDR, dlopen{}, errno{}, signals{}, priority{}
//!   fs        open/mode/access/copy flags
//!   crypto    OpenSSL options, padding and conversions
//!   zlib      zlib, brotli and zstd values and modes
//!   trace     trace event phase characters
//!   internal  extensionless module formats
//! ```
//!
//! `lib/constants.js` flattens `os.dlopen`, `os.errno`, `os.priority`,
//! `os.signals`, `fs` and `crypto` into the deprecated public
//! `require('constants')` export, so every one of those sub-objects is
//! user-visible and cannot be trimmed to what `lib/**` reads internally.
//!
//! All numbers come from Node 28's own vendored headers (see `sources.rs`), not
//! from transcribing a running binary, so they track the pinned Node version.
//! Every table below is published as a `DontDelete | ReadOnly` constant through
//! `NODE_DEFINE_CONSTANT`, and every sub-object is a null-prototype object.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::value::{Member, Value};

/// Top-level members of the `constants` namespace.
pub const MEMBERS: &[&str] = &["os", "fs", "crypto", "zlib", "trace", "internal"];

/// Members of the `os` sub-object.
pub const OS_MEMBERS: &[&str] = &["UV_UDP_REUSEADDR", "dlopen", "errno", "signals", "priority"];

/// `NODE_DEFINE_CONSTANT(os_constants, UV_UDP_REUSEADDR)` from `uv.h`.
pub const OS_VALUES: &[Member] = &[("UV_UDP_REUSEADDR", Value::int(4))];

/// `DefineDLOpenConstants`. Linux `RTLD_*` values from `<dlfcn.h>`.
pub const DLOPEN_VALUES: &[Member] = &[
    ("RTLD_LAZY", Value::int(1)),
    ("RTLD_NOW", Value::int(2)),
    ("RTLD_GLOBAL", Value::int(256)),
    ("RTLD_LOCAL", Value::int(0)),
    ("RTLD_DEEPBIND", Value::int(8)),
];

/// `DefineErrnoConstants`. Linux `errno.h` values; `EWOULDBLOCK` aliases
/// `EAGAIN` and `ENOTSUP` aliases `EOPNOTSUPP`, exactly as in glibc.
pub const ERRNO_VALUES: &[Member] = &[
    ("E2BIG", Value::int(7)),
    ("EACCES", Value::int(13)),
    ("EADDRINUSE", Value::int(98)),
    ("EADDRNOTAVAIL", Value::int(99)),
    ("EAFNOSUPPORT", Value::int(97)),
    ("EAGAIN", Value::int(11)),
    ("EALREADY", Value::int(114)),
    ("EBADF", Value::int(9)),
    ("EBADMSG", Value::int(74)),
    ("EBUSY", Value::int(16)),
    ("ECANCELED", Value::int(125)),
    ("ECHILD", Value::int(10)),
    ("ECONNABORTED", Value::int(103)),
    ("ECONNREFUSED", Value::int(111)),
    ("ECONNRESET", Value::int(104)),
    ("EDEADLK", Value::int(35)),
    ("EDESTADDRREQ", Value::int(89)),
    ("EDOM", Value::int(33)),
    ("EDQUOT", Value::int(122)),
    ("EEXIST", Value::int(17)),
    ("EFAULT", Value::int(14)),
    ("EFBIG", Value::int(27)),
    ("EHOSTUNREACH", Value::int(113)),
    ("EIDRM", Value::int(43)),
    ("EILSEQ", Value::int(84)),
    ("EINPROGRESS", Value::int(115)),
    ("EINTR", Value::int(4)),
    ("EINVAL", Value::int(22)),
    ("EIO", Value::int(5)),
    ("EISCONN", Value::int(106)),
    ("EISDIR", Value::int(21)),
    ("ELOOP", Value::int(40)),
    ("EMFILE", Value::int(24)),
    ("EMLINK", Value::int(31)),
    ("EMSGSIZE", Value::int(90)),
    ("EMULTIHOP", Value::int(72)),
    ("ENAMETOOLONG", Value::int(36)),
    ("ENETDOWN", Value::int(100)),
    ("ENETRESET", Value::int(102)),
    ("ENETUNREACH", Value::int(101)),
    ("ENFILE", Value::int(23)),
    ("ENOBUFS", Value::int(105)),
    ("ENODATA", Value::int(61)),
    ("ENODEV", Value::int(19)),
    ("ENOENT", Value::int(2)),
    ("ENOEXEC", Value::int(8)),
    ("ENOLCK", Value::int(37)),
    ("ENOLINK", Value::int(67)),
    ("ENOMEM", Value::int(12)),
    ("ENOMSG", Value::int(42)),
    ("ENOPROTOOPT", Value::int(92)),
    ("ENOSPC", Value::int(28)),
    ("ENOSR", Value::int(63)),
    ("ENOSTR", Value::int(60)),
    ("ENOSYS", Value::int(38)),
    ("ENOTCONN", Value::int(107)),
    ("ENOTDIR", Value::int(20)),
    ("ENOTEMPTY", Value::int(39)),
    ("ENOTSOCK", Value::int(88)),
    ("ENOTSUP", Value::int(95)),
    ("ENOTTY", Value::int(25)),
    ("ENXIO", Value::int(6)),
    ("EOPNOTSUPP", Value::int(95)),
    ("EOVERFLOW", Value::int(75)),
    ("EPERM", Value::int(1)),
    ("EPIPE", Value::int(32)),
    ("EPROTO", Value::int(71)),
    ("EPROTONOSUPPORT", Value::int(93)),
    ("EPROTOTYPE", Value::int(91)),
    ("ERANGE", Value::int(34)),
    ("EROFS", Value::int(30)),
    ("ESPIPE", Value::int(29)),
    ("ESRCH", Value::int(3)),
    ("ESTALE", Value::int(116)),
    ("ETIME", Value::int(62)),
    ("ETIMEDOUT", Value::int(110)),
    ("ETXTBSY", Value::int(26)),
    ("EWOULDBLOCK", Value::int(11)),
    ("EXDEV", Value::int(18)),
];

/// `DefineSignalConstants`. Linux `<csignal>` values. `SIGUNUSED`, `SIGLOST`
/// and `SIGINFO` do not exist on Linux and are therefore absent, matching Node.
pub const SIGNALS_VALUES: &[Member] = &[
    ("SIGHUP", Value::int(1)),
    ("SIGINT", Value::int(2)),
    ("SIGQUIT", Value::int(3)),
    ("SIGILL", Value::int(4)),
    ("SIGTRAP", Value::int(5)),
    ("SIGABRT", Value::int(6)),
    ("SIGIOT", Value::int(6)),
    ("SIGBUS", Value::int(7)),
    ("SIGFPE", Value::int(8)),
    ("SIGKILL", Value::int(9)),
    ("SIGUSR1", Value::int(10)),
    ("SIGSEGV", Value::int(11)),
    ("SIGUSR2", Value::int(12)),
    ("SIGPIPE", Value::int(13)),
    ("SIGALRM", Value::int(14)),
    ("SIGTERM", Value::int(15)),
    ("SIGCHLD", Value::int(17)),
    ("SIGSTKFLT", Value::int(16)),
    ("SIGCONT", Value::int(18)),
    ("SIGSTOP", Value::int(19)),
    ("SIGTSTP", Value::int(20)),
    ("SIGTTIN", Value::int(21)),
    ("SIGTTOU", Value::int(22)),
    ("SIGURG", Value::int(23)),
    ("SIGXCPU", Value::int(24)),
    ("SIGXFSZ", Value::int(25)),
    ("SIGVTALRM", Value::int(26)),
    ("SIGPROF", Value::int(27)),
    ("SIGWINCH", Value::int(28)),
    ("SIGIO", Value::int(29)),
    ("SIGPOLL", Value::int(29)),
    ("SIGPWR", Value::int(30)),
    ("SIGSYS", Value::int(31)),
];

/// `DefinePriorityConstants`. These are libuv's Linux priority mappings, which
/// Node publishes under the portable names without the `UV_` prefix.
pub const PRIORITY_VALUES: &[Member] = &[
    ("PRIORITY_LOW", Value::int(19)),
    ("PRIORITY_BELOW_NORMAL", Value::int(10)),
    ("PRIORITY_NORMAL", Value::int(0)),
    ("PRIORITY_ABOVE_NORMAL", Value::int(-7)),
    ("PRIORITY_HIGH", Value::int(-14)),
    ("PRIORITY_HIGHEST", Value::int(-20)),
];

/// `DefineFsConstants`. Open flags, `stat` modes, access modes, directory entry
/// types and copy modes.
///
/// The `UV_FS_O_*` Windows-only flags are 0 here, which is what `uv/unix.h`
/// defines them to. `O_SYNC` includes `O_DSYNC` because Linux defines
/// `O_SYNC = O_DSYNC | 0x100000`.
pub const FS_VALUES: &[Member] = &[
    ("UV_FS_SYMLINK_DIR", Value::int(1)),
    ("UV_FS_SYMLINK_JUNCTION", Value::int(2)),
    ("O_RDONLY", Value::int(0)),
    ("O_WRONLY", Value::int(1)),
    ("O_RDWR", Value::int(2)),
    ("UV_DIRENT_UNKNOWN", Value::int(0)),
    ("UV_DIRENT_FILE", Value::int(1)),
    ("UV_DIRENT_DIR", Value::int(2)),
    ("UV_DIRENT_LINK", Value::int(3)),
    ("UV_DIRENT_FIFO", Value::int(4)),
    ("UV_DIRENT_SOCKET", Value::int(5)),
    ("UV_DIRENT_CHAR", Value::int(6)),
    ("UV_DIRENT_BLOCK", Value::int(7)),
    ("S_IFMT", Value::int(61440)),
    ("S_IFREG", Value::int(32768)),
    ("S_IFDIR", Value::int(16384)),
    ("S_IFCHR", Value::int(8192)),
    ("S_IFBLK", Value::int(24576)),
    ("S_IFIFO", Value::int(4096)),
    ("S_IFLNK", Value::int(40960)),
    ("S_IFSOCK", Value::int(49152)),
    ("O_CREAT", Value::int(64)),
    ("O_EXCL", Value::int(128)),
    ("UV_FS_O_FILEMAP", Value::int(0)),
    ("UV_FS_O_TEMPORARY", Value::int(0)),
    ("UV_FS_O_SHORT_LIVED", Value::int(0)),
    ("UV_FS_O_SEQUENTIAL", Value::int(0)),
    ("UV_FS_O_RANDOM", Value::int(0)),
    ("O_NOCTTY", Value::int(256)),
    ("O_TRUNC", Value::int(512)),
    ("O_APPEND", Value::int(1024)),
    ("O_DIRECTORY", Value::int(65536)),
    ("O_NOATIME", Value::int(262144)),
    ("O_NOFOLLOW", Value::int(131072)),
    ("O_SYNC", Value::int(1052672)),
    ("O_DSYNC", Value::int(4096)),
    ("O_DIRECT", Value::int(16384)),
    ("O_NONBLOCK", Value::int(2048)),
    ("S_IRWXU", Value::int(448)),
    ("S_IRUSR", Value::int(256)),
    ("S_IWUSR", Value::int(128)),
    ("S_IXUSR", Value::int(64)),
    ("S_IRWXG", Value::int(56)),
    ("S_IRGRP", Value::int(32)),
    ("S_IWGRP", Value::int(16)),
    ("S_IXGRP", Value::int(8)),
    ("S_IRWXO", Value::int(7)),
    ("S_IROTH", Value::int(4)),
    ("S_IWOTH", Value::int(2)),
    ("S_IXOTH", Value::int(1)),
    ("F_OK", Value::int(0)),
    ("R_OK", Value::int(4)),
    ("W_OK", Value::int(2)),
    ("X_OK", Value::int(1)),
    ("UV_FS_COPYFILE_EXCL", Value::int(1)),
    ("COPYFILE_EXCL", Value::int(1)),
    ("UV_FS_COPYFILE_FICLONE", Value::int(2)),
    ("COPYFILE_FICLONE", Value::int(2)),
    ("UV_FS_COPYFILE_FICLONE_FORCE", Value::int(4)),
    ("COPYFILE_FICLONE_FORCE", Value::int(4)),
];

/// `DEFAULT_CIPHER_LIST_CORE` from `src/node_constants.h`.
///
/// Node builds this from adjacent string literals, so there is no header
/// expression to derive it from. The TLS 1.3 suites are OpenSSL's defaults; the
/// rest is Node's own selection.
const DEFAULT_CORE_CIPHER_LIST: &str = concat!(
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_AES_128_GCM_SHA256:",
    "ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES128-GCM-SHA256:",
    "ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:",
    "DHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-RSA-AES128-SHA256:",
    "DHE-RSA-AES128-SHA256:",
    "ECDHE-RSA-AES256-SHA384:",
    "DHE-RSA-AES256-SHA384:",
    "ECDHE-RSA-AES256-SHA256:",
    "DHE-RSA-AES256-SHA256:",
    "HIGH:",
    "!aNULL:",
    "!eNULL:",
    "!EXPORT:",
    "!DES:",
    "!RC4:",
    "!MD5:",
    "!PSK:",
    "!SRP:",
    "!CAMELLIA",
);

/// `DefineCryptoConstants`. Values are OpenSSL 4.1.0's, the version vendored in
/// `deps/openssl` by Node 28.
///
/// `RSA_SSLV23_PADDING` and the `RSA_PSS_SALTLEN_*` entries are absent from
/// modern OpenSSL headers under `OPENSSL_NO_DEPRECATED`; Node restores them with
/// its own fallback defines, so their values are the documented ones, not
/// header-derived.
pub const CRYPTO_VALUES: &[Member] = &[
    ("OPENSSL_VERSION_NUMBER", Value::int(1074790400)),
    ("SSL_OP_ALL", Value::int(2147485760)),
    ("SSL_OP_ALLOW_NO_DHE_KEX", Value::int(1024)),
    (
        "SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION",
        Value::int(262144),
    ),
    ("SSL_OP_CIPHER_SERVER_PREFERENCE", Value::int(4194304)),
    ("SSL_OP_CISCO_ANYCONNECT", Value::int(32768)),
    ("SSL_OP_COOKIE_EXCHANGE", Value::int(8192)),
    ("SSL_OP_CRYPTOPRO_TLSEXT_BUG", Value::int(2147483648)),
    ("SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS", Value::int(2048)),
    ("SSL_OP_LEGACY_SERVER_CONNECT", Value::int(4)),
    ("SSL_OP_NO_COMPRESSION", Value::int(131072)),
    ("SSL_OP_NO_ENCRYPT_THEN_MAC", Value::int(524288)),
    ("SSL_OP_NO_QUERY_MTU", Value::int(4096)),
    ("SSL_OP_NO_RENEGOTIATION", Value::int(1073741824)),
    (
        "SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION",
        Value::int(65536),
    ),
    ("SSL_OP_NO_SSLv2", Value::int(0)),
    ("SSL_OP_NO_SSLv3", Value::int(33554432)),
    ("SSL_OP_NO_TICKET", Value::int(16384)),
    ("SSL_OP_NO_TLSv1", Value::int(67108864)),
    ("SSL_OP_NO_TLSv1_1", Value::int(268435456)),
    ("SSL_OP_NO_TLSv1_2", Value::int(134217728)),
    ("SSL_OP_NO_TLSv1_3", Value::int(536870912)),
    ("SSL_OP_PRIORITIZE_CHACHA", Value::int(2097152)),
    ("SSL_OP_TLS_ROLLBACK_BUG", Value::int(8388608)),
    ("DH_CHECK_P_NOT_SAFE_PRIME", Value::int(2)),
    ("DH_CHECK_P_NOT_PRIME", Value::int(1)),
    ("DH_UNABLE_TO_CHECK_GENERATOR", Value::int(4)),
    ("DH_NOT_SUITABLE_GENERATOR", Value::int(8)),
    ("RSA_PKCS1_PADDING", Value::int(1)),
    ("RSA_SSLV23_PADDING", Value::int(2)),
    ("RSA_NO_PADDING", Value::int(3)),
    ("RSA_PKCS1_OAEP_PADDING", Value::int(4)),
    ("RSA_X931_PADDING", Value::int(5)),
    ("RSA_PKCS1_PSS_PADDING", Value::int(6)),
    ("RSA_PSS_SALTLEN_DIGEST", Value::int(-1)),
    ("RSA_PSS_SALTLEN_MAX_SIGN", Value::int(-2)),
    ("RSA_PSS_SALTLEN_AUTO", Value::int(-2)),
    ("TLS1_VERSION", Value::int(769)),
    ("TLS1_1_VERSION", Value::int(770)),
    ("TLS1_2_VERSION", Value::int(771)),
    ("TLS1_3_VERSION", Value::int(772)),
    ("POINT_CONVERSION_COMPRESSED", Value::int(2)),
    ("POINT_CONVERSION_UNCOMPRESSED", Value::int(4)),
    ("POINT_CONVERSION_HYBRID", Value::int(6)),
    // `DEFAULT_CIPHER_LIST_CORE` from src/node_constants.h. A release build does
    // not override it with `--openssl-default-cipher-list`, so this is the
    // built-in Node list. `lib/crypto.js` re-assigns `defaultCipherList` from
    // `--tls-cipher-list`; this is the separate core list a tls context falls
    // back to. Node composes it with per-line string literals, so it has no
    // single header expression to derive from.
    (
        "defaultCoreCipherList",
        Value::Str(DEFAULT_CORE_CIPHER_LIST),
    ),
];

/// `DefineZlibConstants`. zlib values come from `zlib.h`, brotli from
/// `brotli/encode.h` and `brotli/decode.h`, zstd from `zstd.h` and
/// `zstd_errors.h`.
///
/// The `Z_MIN_*`/`Z_MAX_*`/`Z_DEFAULT_*` range entries and the mode entries
/// (`DEFLATE` through `ZSTD_DECOMPRESS`) are Node-local: they are defined in
/// `src/node_zlib.cc`, not by a dependency header.
pub const ZLIB_VALUES: &[Member] = &[
    ("Z_NO_FLUSH", Value::int(0)),
    ("Z_PARTIAL_FLUSH", Value::int(1)),
    ("Z_SYNC_FLUSH", Value::int(2)),
    ("Z_FULL_FLUSH", Value::int(3)),
    ("Z_FINISH", Value::int(4)),
    ("Z_BLOCK", Value::int(5)),
    ("Z_OK", Value::int(0)),
    ("Z_STREAM_END", Value::int(1)),
    ("Z_NEED_DICT", Value::int(2)),
    ("Z_ERRNO", Value::int(-1)),
    ("Z_STREAM_ERROR", Value::int(-2)),
    ("Z_DATA_ERROR", Value::int(-3)),
    ("Z_MEM_ERROR", Value::int(-4)),
    ("Z_BUF_ERROR", Value::int(-5)),
    ("Z_VERSION_ERROR", Value::int(-6)),
    ("Z_NO_COMPRESSION", Value::int(0)),
    ("Z_BEST_SPEED", Value::int(1)),
    ("Z_BEST_COMPRESSION", Value::int(9)),
    ("Z_DEFAULT_COMPRESSION", Value::int(-1)),
    ("Z_FILTERED", Value::int(1)),
    ("Z_HUFFMAN_ONLY", Value::int(2)),
    ("Z_RLE", Value::int(3)),
    ("Z_FIXED", Value::int(4)),
    ("Z_DEFAULT_STRATEGY", Value::int(0)),
    ("ZLIB_VERNUM", Value::int(4897)),
    ("Z_MIN_WINDOWBITS", Value::int(8)),
    ("Z_MAX_WINDOWBITS", Value::int(15)),
    ("Z_DEFAULT_WINDOWBITS", Value::int(15)),
    ("Z_MIN_CHUNK", Value::int(64)),
    ("Z_MAX_CHUNK", Value::Num(f64::INFINITY)),
    ("Z_DEFAULT_CHUNK", Value::int(16384)),
    ("Z_MIN_MEMLEVEL", Value::int(1)),
    ("Z_MAX_MEMLEVEL", Value::int(9)),
    ("Z_DEFAULT_MEMLEVEL", Value::int(8)),
    ("Z_MIN_LEVEL", Value::int(-1)),
    ("Z_MAX_LEVEL", Value::int(9)),
    ("Z_DEFAULT_LEVEL", Value::int(-1)),
    ("DEFLATE", Value::int(1)),
    ("INFLATE", Value::int(2)),
    ("GZIP", Value::int(3)),
    ("GUNZIP", Value::int(4)),
    ("DEFLATERAW", Value::int(5)),
    ("INFLATERAW", Value::int(6)),
    ("UNZIP", Value::int(7)),
    ("BROTLI_DECODE", Value::int(8)),
    ("BROTLI_ENCODE", Value::int(9)),
    ("ZSTD_COMPRESS", Value::int(10)),
    ("ZSTD_DECOMPRESS", Value::int(11)),
    ("BROTLI_OPERATION_PROCESS", Value::int(0)),
    ("BROTLI_OPERATION_FLUSH", Value::int(1)),
    ("BROTLI_OPERATION_FINISH", Value::int(2)),
    ("BROTLI_OPERATION_EMIT_METADATA", Value::int(3)),
    ("BROTLI_PARAM_MODE", Value::int(0)),
    ("BROTLI_MODE_GENERIC", Value::int(0)),
    ("BROTLI_MODE_TEXT", Value::int(1)),
    ("BROTLI_MODE_FONT", Value::int(2)),
    ("BROTLI_DEFAULT_MODE", Value::int(0)),
    ("BROTLI_PARAM_QUALITY", Value::int(1)),
    ("BROTLI_MIN_QUALITY", Value::int(0)),
    ("BROTLI_MAX_QUALITY", Value::int(11)),
    ("BROTLI_DEFAULT_QUALITY", Value::int(11)),
    ("BROTLI_PARAM_LGWIN", Value::int(2)),
    ("BROTLI_MIN_WINDOW_BITS", Value::int(10)),
    ("BROTLI_MAX_WINDOW_BITS", Value::int(24)),
    ("BROTLI_LARGE_MAX_WINDOW_BITS", Value::int(30)),
    ("BROTLI_DEFAULT_WINDOW", Value::int(22)),
    ("BROTLI_PARAM_LGBLOCK", Value::int(3)),
    ("BROTLI_MIN_INPUT_BLOCK_BITS", Value::int(16)),
    ("BROTLI_MAX_INPUT_BLOCK_BITS", Value::int(24)),
    (
        "BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING",
        Value::int(4),
    ),
    ("BROTLI_PARAM_SIZE_HINT", Value::int(5)),
    ("BROTLI_PARAM_LARGE_WINDOW", Value::int(6)),
    ("BROTLI_PARAM_NPOSTFIX", Value::int(7)),
    ("BROTLI_PARAM_NDIRECT", Value::int(8)),
    ("BROTLI_DECODER_RESULT_ERROR", Value::int(0)),
    ("BROTLI_DECODER_RESULT_SUCCESS", Value::int(1)),
    ("BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT", Value::int(2)),
    ("BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT", Value::int(3)),
    (
        "BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION",
        Value::int(0),
    ),
    ("BROTLI_DECODER_PARAM_LARGE_WINDOW", Value::int(1)),
    ("BROTLI_DECODER_NO_ERROR", Value::int(0)),
    ("BROTLI_DECODER_SUCCESS", Value::int(1)),
    ("BROTLI_DECODER_NEEDS_MORE_INPUT", Value::int(2)),
    ("BROTLI_DECODER_NEEDS_MORE_OUTPUT", Value::int(3)),
    (
        "BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_NIBBLE",
        Value::int(-1),
    ),
    ("BROTLI_DECODER_ERROR_FORMAT_RESERVED", Value::int(-2)),
    (
        "BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_META_NIBBLE",
        Value::int(-3),
    ),
    (
        "BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET",
        Value::int(-4),
    ),
    (
        "BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME",
        Value::int(-5),
    ),
    ("BROTLI_DECODER_ERROR_FORMAT_CL_SPACE", Value::int(-6)),
    ("BROTLI_DECODER_ERROR_FORMAT_HUFFMAN_SPACE", Value::int(-7)),
    (
        "BROTLI_DECODER_ERROR_FORMAT_CONTEXT_MAP_REPEAT",
        Value::int(-8),
    ),
    ("BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_1", Value::int(-9)),
    (
        "BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_2",
        Value::int(-10),
    ),
    ("BROTLI_DECODER_ERROR_FORMAT_TRANSFORM", Value::int(-11)),
    ("BROTLI_DECODER_ERROR_FORMAT_DICTIONARY", Value::int(-12)),
    ("BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS", Value::int(-13)),
    ("BROTLI_DECODER_ERROR_FORMAT_PADDING_1", Value::int(-14)),
    ("BROTLI_DECODER_ERROR_FORMAT_PADDING_2", Value::int(-15)),
    ("BROTLI_DECODER_ERROR_FORMAT_DISTANCE", Value::int(-16)),
    ("BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH", Value::int(-17)),
    ("BROTLI_DECODER_ERROR_COMPOUND_DICTIONARY", Value::int(-18)),
    ("BROTLI_DECODER_ERROR_DICTIONARY_NOT_SET", Value::int(-19)),
    ("BROTLI_DECODER_ERROR_INVALID_ARGUMENTS", Value::int(-20)),
    ("BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES", Value::int(-21)),
    ("BROTLI_DECODER_ERROR_ALLOC_TREE_GROUPS", Value::int(-22)),
    ("BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MAP", Value::int(-25)),
    ("BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_1", Value::int(-26)),
    ("BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_2", Value::int(-27)),
    (
        "BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES",
        Value::int(-30),
    ),
    ("BROTLI_DECODER_ERROR_UNREACHABLE", Value::int(-31)),
    ("ZSTD_e_continue", Value::int(0)),
    ("ZSTD_e_flush", Value::int(1)),
    ("ZSTD_e_end", Value::int(2)),
    ("ZSTD_fast", Value::int(1)),
    ("ZSTD_dfast", Value::int(2)),
    ("ZSTD_greedy", Value::int(3)),
    ("ZSTD_lazy", Value::int(4)),
    ("ZSTD_lazy2", Value::int(5)),
    ("ZSTD_btlazy2", Value::int(6)),
    ("ZSTD_btopt", Value::int(7)),
    ("ZSTD_btultra", Value::int(8)),
    ("ZSTD_btultra2", Value::int(9)),
    ("ZSTD_c_compressionLevel", Value::int(100)),
    ("ZSTD_c_windowLog", Value::int(101)),
    ("ZSTD_c_hashLog", Value::int(102)),
    ("ZSTD_c_chainLog", Value::int(103)),
    ("ZSTD_c_searchLog", Value::int(104)),
    ("ZSTD_c_minMatch", Value::int(105)),
    ("ZSTD_c_targetLength", Value::int(106)),
    ("ZSTD_c_strategy", Value::int(107)),
    ("ZSTD_c_enableLongDistanceMatching", Value::int(160)),
    ("ZSTD_c_ldmHashLog", Value::int(161)),
    ("ZSTD_c_ldmMinMatch", Value::int(162)),
    ("ZSTD_c_ldmBucketSizeLog", Value::int(163)),
    ("ZSTD_c_ldmHashRateLog", Value::int(164)),
    ("ZSTD_c_contentSizeFlag", Value::int(200)),
    ("ZSTD_c_checksumFlag", Value::int(201)),
    ("ZSTD_c_dictIDFlag", Value::int(202)),
    ("ZSTD_c_nbWorkers", Value::int(400)),
    ("ZSTD_c_jobSize", Value::int(401)),
    ("ZSTD_c_overlapLog", Value::int(402)),
    ("ZSTD_d_windowLogMax", Value::int(100)),
    ("ZSTD_CLEVEL_DEFAULT", Value::int(3)),
    ("ZSTD_error_no_error", Value::int(0)),
    ("ZSTD_error_GENERIC", Value::int(1)),
    ("ZSTD_error_prefix_unknown", Value::int(10)),
    ("ZSTD_error_version_unsupported", Value::int(12)),
    ("ZSTD_error_frameParameter_unsupported", Value::int(14)),
    ("ZSTD_error_frameParameter_windowTooLarge", Value::int(16)),
    ("ZSTD_error_corruption_detected", Value::int(20)),
    ("ZSTD_error_checksum_wrong", Value::int(22)),
    ("ZSTD_error_literals_headerWrong", Value::int(24)),
    ("ZSTD_error_dictionary_corrupted", Value::int(30)),
    ("ZSTD_error_dictionary_wrong", Value::int(32)),
    ("ZSTD_error_dictionaryCreation_failed", Value::int(34)),
    ("ZSTD_error_parameter_unsupported", Value::int(40)),
    (
        "ZSTD_error_parameter_combination_unsupported",
        Value::int(41),
    ),
    ("ZSTD_error_parameter_outOfBound", Value::int(42)),
    ("ZSTD_error_tableLog_tooLarge", Value::int(44)),
    ("ZSTD_error_maxSymbolValue_tooLarge", Value::int(46)),
    ("ZSTD_error_maxSymbolValue_tooSmall", Value::int(48)),
    ("ZSTD_error_stabilityCondition_notRespected", Value::int(50)),
    ("ZSTD_error_stage_wrong", Value::int(60)),
    ("ZSTD_error_init_missing", Value::int(62)),
    ("ZSTD_error_memory_allocation", Value::int(64)),
    ("ZSTD_error_workSpace_tooSmall", Value::int(66)),
    ("ZSTD_error_dstSize_tooSmall", Value::int(70)),
    ("ZSTD_error_srcSize_wrong", Value::int(72)),
    ("ZSTD_error_dstBuffer_null", Value::int(74)),
    ("ZSTD_error_noForwardProgress_destFull", Value::int(80)),
    ("ZSTD_error_noForwardProgress_inputEmpty", Value::int(82)),
];

/// `DefineTraceConstants`. Each value is the character code of a trace event
/// phase letter from V8's `trace-event-no-perfetto.h`, widened to a number by
/// `NODE_DEFINE_CONSTANT`.
pub const TRACE_VALUES: &[Member] = &[
    ("TRACE_EVENT_PHASE_BEGIN", Value::int(66)),
    ("TRACE_EVENT_PHASE_END", Value::int(69)),
    ("TRACE_EVENT_PHASE_COMPLETE", Value::int(88)),
    ("TRACE_EVENT_PHASE_INSTANT", Value::int(73)),
    ("TRACE_EVENT_PHASE_ASYNC_BEGIN", Value::int(83)),
    ("TRACE_EVENT_PHASE_ASYNC_STEP_INTO", Value::int(84)),
    ("TRACE_EVENT_PHASE_ASYNC_STEP_PAST", Value::int(112)),
    ("TRACE_EVENT_PHASE_ASYNC_END", Value::int(70)),
    ("TRACE_EVENT_PHASE_NESTABLE_ASYNC_BEGIN", Value::int(98)),
    ("TRACE_EVENT_PHASE_NESTABLE_ASYNC_END", Value::int(101)),
    ("TRACE_EVENT_PHASE_NESTABLE_ASYNC_INSTANT", Value::int(110)),
    ("TRACE_EVENT_PHASE_FLOW_BEGIN", Value::int(115)),
    ("TRACE_EVENT_PHASE_FLOW_STEP", Value::int(116)),
    ("TRACE_EVENT_PHASE_FLOW_END", Value::int(102)),
    ("TRACE_EVENT_PHASE_METADATA", Value::int(77)),
    ("TRACE_EVENT_PHASE_COUNTER", Value::int(67)),
    ("TRACE_EVENT_PHASE_SAMPLE", Value::int(80)),
    ("TRACE_EVENT_PHASE_CREATE_OBJECT", Value::int(78)),
    ("TRACE_EVENT_PHASE_SNAPSHOT_OBJECT", Value::int(79)),
    ("TRACE_EVENT_PHASE_DELETE_OBJECT", Value::int(68)),
    ("TRACE_EVENT_PHASE_MEMORY_DUMP", Value::int(118)),
    ("TRACE_EVENT_PHASE_MARK", Value::int(82)),
    ("TRACE_EVENT_PHASE_CLOCK_SYNC", Value::int(99)),
];

/// `DefineInternalConstants`. `src/node_constants.h` defines both.
pub const INTERNAL_VALUES: &[Member] = &[
    ("EXTENSIONLESS_FORMAT_JAVASCRIPT", Value::int(0)),
    ("EXTENSIONLESS_FORMAT_WASM", Value::int(1)),
];

/// The `constants` namespace.
#[derive(Debug, Default, Clone, Copy)]
pub struct Constants;

impl Constants {
    /// Builds the `os` sub-object, including its four nested tables.
    fn install_os<'s>(
        scope: &mut v8::PinScope<'s, '_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let os = crate::null_proto_object(scope);
        for (name, value) in OS_VALUES {
            crate::install_constant(scope, os, name, *value)?;
        }
        let nested = [
            ("dlopen", DLOPEN_VALUES),
            ("errno", ERRNO_VALUES),
            ("signals", SIGNALS_VALUES),
            ("priority", PRIORITY_VALUES),
        ];
        for (name, table) in nested {
            let child = crate::table_object(scope, table)?;
            let key = crate::string(scope, name)?;
            os.set(scope, key.into(), child.into())
                .ok_or_else(|| format!("constants.os.{name}: could not define property"))?;
        }
        Ok(os)
    }
}

impl BindingModule for Constants {
    fn namespace(&self) -> &'static str {
        "constants"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = crate::null_proto_object(scope);

        let subtrees: [(&str, &[Member]); 5] = [
            ("fs", FS_VALUES),
            ("crypto", CRYPTO_VALUES),
            ("zlib", ZLIB_VALUES),
            ("trace", TRACE_VALUES),
            ("internal", INTERNAL_VALUES),
        ];
        for (name, table) in subtrees {
            let child = crate::table_object(scope, table)?;
            let key = crate::string(scope, name)?;
            object
                .set(scope, key.into(), child.into())
                .ok_or_else(|| format!("constants.{name}: could not define property"))?;
        }

        let os = Self::install_os(scope)?;
        let key = crate::string(scope, "os")?;
        object
            .set(scope, key.into(), os.into())
            .ok_or_else(|| "constants.os: could not define property".to_string())?;

        Ok(object)
    }
}

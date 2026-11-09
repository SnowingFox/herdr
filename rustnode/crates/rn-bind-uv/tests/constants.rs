//! Cross-checks every published value against libuv's own headers.
//!
//! The table in `generated.rs` is a transcription, and a transcription error in
//! an `errno` mapping is invisible at the JavaScript level: `UV_ENOENT` would
//! simply compare unequal to the `-2` that `fs` reports, and errors would lose
//! their `code`. So rather than testing that the table contains what the
//! generator wrote, these tests re-read the *headers* and recompute every value
//! independently:
//!
//! 1. `UV_ERRNO_MAP` is parsed here again and compared entry for entry.
//! 2. `UV__<NAME>` is resolved here again (`UV__ERR(SYM)` -> `-SYM`, literal
//!    `(-NNNN)` kept as is) and compared with the published number.
//! 3. Every `UV__ERR(SYM)` mapping is confirmed against `libc`, which is the
//!    `<errno.h>` Node's build actually compiles against. That is the third,
//!    independent opinion: header says `-ENOENT`, libc says `ENOENT == 2`, so
//!    the published value must be `-2`.
//! 4. `UV_DIRENT_*` is parsed from the enum and compared.
//!
//! The tests read the header through `include_str!`, so the copy under
//! `tools/uv-headers/` is the same one the generator used and no Node checkout
//! is needed. Reading the header at test time is the whole point: a table that
//! disagrees with it fails here.

use std::collections::BTreeMap;

use rn_bind_uv::{by_name, by_value, DIRENT, ERRORS, UV_CC_REGISTRATIONS};

/// `uv.h` as vendored for the generator.
const UV_H: &str = include_str!("../tools/uv-headers/uv.h");
/// `uv/errno.h` as vendored for the generator.
const ERRNO_H: &str = include_str!("../tools/uv-headers/uv/errno.h");

/// Returns the body of `UV_ERRNO_MAP(XX)` from `uv.h`.
fn errno_map_body() -> &'static str {
    let start = UV_H
        .find("#define UV_ERRNO_MAP(XX)")
        .expect("uv.h must define UV_ERRNO_MAP");
    let rest = &UV_H[start..];
    // The macro ends at the first line that does not continue it.
    let mut end = 0;
    for line in rest.split_inclusive('\n') {
        end += line.len();
        if !line.trim_end().ends_with('\\') {
            break;
        }
    }
    &rest[..end]
}

/// Normalizes a preprocessor line to the canonical `#define NAME value` spelling.
///
/// The header writes some of these as `# define`, with the space GCC allows, so
/// a `strip_prefix("#define ")` over the raw line would silently miss them.
fn define_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start();
    let rest = line.strip_prefix('#')?.trim_start();
    let rest = rest.strip_prefix("define")?.trim_start();
    let (name, value) = rest.split_once(char::is_whitespace)?;
    Some((name, value.trim()))
}

/// Parses `XX(NAME, "message")` lines, independently of the generator's regex.
fn parse_errno_map() -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for line in errno_map_body().lines() {
        let line = line.trim().trim_end_matches('\\').trim();
        let Some(rest) = line.strip_prefix("XX(") else {
            continue;
        };
        let rest = rest.trim_end_matches(')').trim_end_matches(',');
        let (name, message) = rest
            .split_once(',')
            .expect("every XX() line has a name and a message");
        let message = message.trim();
        let message = message
            .strip_prefix('"')
            .and_then(|text| text.strip_suffix('"'))
            .expect("every XX() message is a string literal");
        entries.push((name.trim().to_string(), message.to_string()));
    }
    entries
}

/// All `UV__<NAME>` definitions in the header, in file order.
///
/// A name appears more than once when the header guards one branch on
/// `#if defined(SYM)`: `UV__ECHARSET` has a `UV__ERR(ECHARSET)` branch and a
/// literal `(-4080)` branch, and only one of them is taken on a given target.
fn header_candidates(name: &str) -> Vec<&'static str> {
    let marker = format!("UV__{name}");
    let found: Vec<&'static str> = ERRNO_H
        .lines()
        .filter_map(define_line)
        .filter_map(|(defined, value)| (defined == marker).then_some(value))
        .collect();
    assert!(
        !found.is_empty(),
        "uv/errno.h must define UV__{name} somewhere"
    );
    found
}

/// Resolves `UV__<NAME>` the way `uv/errno.h` resolves it on this host.
///
/// `UV__ERR(SYM)` means `-(SYM)` and is only taken when `<errno.h>` defines
/// `SYM`; the `#else` branch carries a literal fallback such as `(-4028)`.
/// `libc` answers the "is it defined" question, which is what makes this an
/// independent check of the generator's preprocessor.
fn header_value(name: &str) -> i64 {
    let candidates = header_candidates(name);
    for candidate in &candidates {
        if let Some(symbol) = candidate
            .strip_prefix("UV__ERR(")
            .and_then(|text| text.strip_suffix(')'))
        {
            if let Some(system) = libc_errno(symbol) {
                // The `EHOSTDOWN` case has a third branch for BSD, where the
                // symbol is hidden but always 64; on Linux libc answers first.
                return -system;
            }
        }
    }
    // No `UV__ERR` branch applies on this host, so the literal fallback is the
    // one the compiler uses.
    candidates
        .iter()
        .rev()
        .find_map(|candidate| {
            candidate
                .trim_start_matches('(')
                .trim_end_matches(')')
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no usable definition of UV__{name} in uv/errno.h"))
}

/// The numeric value of a platform errno symbol, as `<errno.h>` defines it.
///
/// `libc` is the same header set the C++ build sees, so this is an independent
/// opinion from the `uv/errno.h` text parsed above. Two of libuv's names never
/// take a `UV__ERR` branch on Linux — glibc defines no `EFTYPE`, and `ECHARSET`
/// is libuv's own invention — so `libc_errno` returning `None` for them is the
/// correct answer, not a gap.
fn libc_errno(symbol: &str) -> Option<i64> {
    // Spelled out rather than generated: this list *is* the assertion that the
    // names libuv maps to system errnos are all real, and a macro-expanded table
    // would not fail when a name stopped existing.
    let value = match symbol {
        "E2BIG" => libc::E2BIG,
        "EACCES" => libc::EACCES,
        "EADDRINUSE" => libc::EADDRINUSE,
        "EADDRNOTAVAIL" => libc::EADDRNOTAVAIL,
        "EAFNOSUPPORT" => libc::EAFNOSUPPORT,
        "EAGAIN" => libc::EAGAIN,
        "EALREADY" => libc::EALREADY,
        "EBADF" => libc::EBADF,
        "EBUSY" => libc::EBUSY,
        "ECANCELED" => libc::ECANCELED,
        "ECONNABORTED" => libc::ECONNABORTED,
        "ECONNREFUSED" => libc::ECONNREFUSED,
        "ECONNRESET" => libc::ECONNRESET,
        "EDESTADDRREQ" => libc::EDESTADDRREQ,
        "EEXIST" => libc::EEXIST,
        "EFAULT" => libc::EFAULT,
        "EFBIG" => libc::EFBIG,
        "EHOSTDOWN" => libc::EHOSTDOWN,
        "EHOSTUNREACH" => libc::EHOSTUNREACH,
        "EILSEQ" => libc::EILSEQ,
        "EINTR" => libc::EINTR,
        "EINVAL" => libc::EINVAL,
        "EIO" => libc::EIO,
        "EISCONN" => libc::EISCONN,
        "EISDIR" => libc::EISDIR,
        "ELOOP" => libc::ELOOP,
        "EMFILE" => libc::EMFILE,
        "EMLINK" => libc::EMLINK,
        "EMSGSIZE" => libc::EMSGSIZE,
        "ENAMETOOLONG" => libc::ENAMETOOLONG,
        "ENETDOWN" => libc::ENETDOWN,
        "ENETUNREACH" => libc::ENETUNREACH,
        "ENFILE" => libc::ENFILE,
        "ENOBUFS" => libc::ENOBUFS,
        "ENODATA" => libc::ENODATA,
        "ENODEV" => libc::ENODEV,
        "ENOENT" => libc::ENOENT,
        "ENOEXEC" => libc::ENOEXEC,
        "ENOMEM" => libc::ENOMEM,
        "ENONET" => libc::ENONET,
        "ENOPROTOOPT" => libc::ENOPROTOOPT,
        "ENOSPC" => libc::ENOSPC,
        "ENOSYS" => libc::ENOSYS,
        "ENOTCONN" => libc::ENOTCONN,
        "ENOTDIR" => libc::ENOTDIR,
        "ENOTEMPTY" => libc::ENOTEMPTY,
        "ENOTSOCK" => libc::ENOTSOCK,
        "ENOTSUP" => libc::ENOTSUP,
        "ENOTTY" => libc::ENOTTY,
        "ENXIO" => libc::ENXIO,
        "EOVERFLOW" => libc::EOVERFLOW,
        "EPERM" => libc::EPERM,
        "EPIPE" => libc::EPIPE,
        "EPROTO" => libc::EPROTO,
        "EPROTONOSUPPORT" => libc::EPROTONOSUPPORT,
        "EPROTOTYPE" => libc::EPROTOTYPE,
        "ERANGE" => libc::ERANGE,
        "EREMOTEIO" => libc::EREMOTEIO,
        "EROFS" => libc::EROFS,
        "ESHUTDOWN" => libc::ESHUTDOWN,
        "ESOCKTNOSUPPORT" => libc::ESOCKTNOSUPPORT,
        "ESPIPE" => libc::ESPIPE,
        "ESRCH" => libc::ESRCH,
        "ETIMEDOUT" => libc::ETIMEDOUT,
        "ETXTBSY" => libc::ETXTBSY,
        "EUNATCH" => libc::EUNATCH,
        "EXDEV" => libc::EXDEV,
        _ => return None,
    };
    Some(value as i64)
}

/// Every `NAME` whose `UV__ERR(SYM)` branch is the one taken on this host.
fn errno_wrapped_names() -> Vec<String> {
    ERRNO_H
        .lines()
        .filter_map(define_line)
        .filter_map(|(name, value)| {
            let name = name.strip_prefix("UV__")?;
            let symbol = value.strip_prefix("UV__ERR(")?.strip_suffix(')')?;
            // A guard like `#if defined(ECHARSET)` fails on glibc, so the header
            // falls through to its literal branch and this host never uses the
            // wrapped form.
            libc_errno(symbol).map(|_| name.to_string())
        })
        .collect()
}

#[test]
fn table_matches_the_header_entry_for_entry() {
    let expected = parse_errno_map();
    assert_eq!(
        expected.len(),
        ERRORS.len(),
        "generated.rs has {} entries, uv.h's UV_ERRNO_MAP has {}",
        ERRORS.len(),
        expected.len()
    );
    for (index, ((name, message), error)) in expected.iter().zip(ERRORS).enumerate() {
        assert_eq!(&error.name, name, "entry {index} has the wrong name");
        assert_eq!(
            &error.message, message,
            "entry {index} ({name}) has the wrong message"
        );
    }
}

#[test]
fn table_matches_the_registration_count_in_node_s_uv_cc() {
    // `UV_CC_REGISTRATIONS` is what tools/generate.py compiled out of Node's own
    // `uv_errors_map` initializer. If someone edits the generated table by hand,
    // this is the assertion that catches a dropped row.
    assert_eq!(
        ERRORS.len(),
        UV_CC_REGISTRATIONS,
        "the error table must have one entry per constant src/uv.cc registers"
    );
    // If the generator ever ran without compiling uv.cc, it would have stamped 0
    // here rather than a verified count, and the assertion above would pass on a
    // table of zero entries.
    const VERIFIED: () = assert!(UV_CC_REGISTRATIONS > 0);
    let () = VERIFIED;
}

#[test]
fn every_published_value_matches_the_header() {
    let expected = parse_errno_map();
    for (name, _) in &expected {
        let error = by_name(name).unwrap_or_else(|| panic!("{name} is missing from the table"));
        let from_header = header_value(name);
        assert_eq!(
            i64::from(error.value),
            from_header,
            "{name} is {} but uv/errno.h says {from_header}",
            error.value
        );
    }
    assert_eq!(ERRORS.len(), expected.len());
}

#[test]
fn errno_mapped_values_agree_with_libc() {
    // The independent cross-check: for every `UV__ERR(SYM)` entry the header
    // resolves through a system errno, the published value must be `-SYM` for
    // this host's `<errno.h>`. This is the comparison a wrong constant fails.
    let wrapped = errno_wrapped_names();
    assert!(
        wrapped.len() > 60,
        "expected most entries to map to a system errno, found {}",
        wrapped.len()
    );
    for name in wrapped {
        let system = libc_errno(&name)
            .unwrap_or_else(|| panic!("{name} maps to a system errno but libc has no constant"));
        let error = by_name(&name).unwrap_or_else(|| panic!("{name} is missing from the table"));
        assert_eq!(
            i64::from(error.value),
            -system,
            "UV_{name} must be -{name} ({})",
            -system
        );
    }
}

#[test]
fn errno_values_are_all_negative_and_distinct() {
    let mut seen: BTreeMap<i32, &str> = BTreeMap::new();
    for error in ERRORS {
        assert!(
            error.value < 0,
            "{} has value {}, but libuv errors are negative",
            error.name,
            error.value
        );
        if let Some(other) = seen.insert(error.value, error.name) {
            panic!("{} and {} both claim {}", other, error.name, error.value);
        }
    }
    assert_eq!(seen.len(), ERRORS.len());
}

#[test]
fn lookup_by_value_finds_every_entry() {
    for error in ERRORS {
        let found = by_value(error.value).expect("every published value must be findable");
        assert_eq!(found.name, error.name);
    }
    assert!(
        by_value(0).is_none(),
        "0 is success, not an error, and is deliberately absent from the map"
    );
    assert!(by_value(-1024).is_none(), "-1024 is not a libuv error");
}

#[test]
fn dirent_types_match_the_enum_in_uv_h() {
    let start = UV_H
        .find("uv_dirent_type_t")
        .expect("uv.h must declare uv_dirent_type_t");
    let start = UV_H[..start]
        .rfind("typedef enum {")
        .expect("the enum precedes its typedef name");
    let end = UV_H[start..]
        .find("} uv_dirent_type_t;")
        .expect("the enum body must terminate");
    let body = &UV_H[start..start + end];

    let expected: Vec<(String, i32)> = body
        .lines()
        .filter_map(|line| {
            let name = line.trim().trim_end_matches(',');
            name.starts_with("UV_DIRENT_").then(|| name.to_string())
        })
        .zip(0..)
        .collect();

    assert_eq!(expected.len(), DIRENT.len(), "UV_DIRENT_* count mismatch");
    for ((name, value), (published, published_value)) in expected.iter().zip(DIRENT) {
        assert_eq!(published, name);
        assert_eq!(*published_value, *value);
    }
}

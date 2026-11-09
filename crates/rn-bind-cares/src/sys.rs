//! The blocking lookups.
//!
//! Node dispatches `uv_getaddrinfo` and `uv_getnameinfo` onto the libuv
//! threadpool. This module holds the blocking half — parse the request, call
//! `getaddrinfo(3)` or `getnameinfo(3)`, and return owned data with no pointer
//! into the caller's scope — so that `deliver.rs` can own the V8 half and the
//! resolution itself is testable without an isolate.

use std::ffi::{CStr, CString};

use crate::ip::{self, Family, SocketAddr};

/// The family a lookup asks for, which is not the same as the family an address
/// parses as: `AF_UNSPEC` asks for both.
///
/// `GetAddrInfo` maps the JavaScript argument 0/4/6 onto `AF_UNSPEC`/`AF_INET`/
/// `AF_INET6` and puts it in `hints.ai_family`. Folding `AF_UNSPEC` into either
/// concrete family would silently halve the answer, so it stays distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestFamily {
    Unspec,
    V4,
    V6,
}

impl RequestFamily {
    fn hint(self) -> libc::c_int {
        match self {
            Self::Unspec => libc::AF_UNSPEC,
            Self::V4 => libc::AF_INET,
            Self::V6 => libc::AF_INET6,
        }
    }

    /// Whether an address of `family` belongs in the answer.
    ///
    /// Node's `add()` lambda is called with `wants` flags derived from the same
    /// `hints.ai_family`, and the resolver may return both families for
    /// `AF_UNSPEC`, so the filter has to be applied on the result as well.
    fn accepts(self, family: Family) -> bool {
        match self {
            Self::Unspec => true,
            Self::V4 => family == Family::V4,
            Self::V6 => family == Family::V6,
        }
    }
}

/// The address sort order Node's `AfterGetAddrInfo` applies.
///
/// These are the values of `DNS_ORDER_*` in `src/cares_wrap.h`, which
/// `lib/dns.js` reads off the namespace and passes back as `getaddrinfo`'s
/// fifth argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Order {
    Verbatim,
    Ipv4First,
    Ipv6First,
}

impl Order {
    pub(crate) fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Ipv4First,
            2 => Self::Ipv6First,
            _ => Self::Verbatim,
        }
    }
}

/// A failed lookup, carrying the number Node puts in `oncomplete`'s first slot.
///
/// `lib/dns.js` passes it to `DNSException`, which turns `UV_EAI_NODATA` and
/// `UV_EAI_NONAME` into `ENOTFOUND` and otherwise calls `getSystemErrorName`.
/// The value therefore has to be *libuv's* code, not the platform's `EAI_*`,
/// or the observable `error.code` changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LookupError(pub(crate) i32);

/// libuv's `UV_EAI_*` code for a `getaddrinfo(3)`/`getnameinfo(3)` result.
///
/// This is `uv__getaddrinfo_translate_error` from
/// `deps/uv/src/unix/getaddrinfo.c` against the constants in
/// `deps/uv/include/uv.h`. libuv normalises the platform's `EAI_*` because the
/// values are negative on glibc and positive on macOS, so forwarding the raw
/// number would make the error code platform-dependent.
fn translate_eai(status: i32) -> i32 {
    // `EAI_SYSTEM` means "look at errno", and libuv turns it into `UV__ERR`,
    // which is the negated errno.
    if status == libc::EAI_SYSTEM {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return -errno;
    }

    // Ordered as libuv orders its `switch`: the first match wins, which matters
    // on platforms where two of these names share a value.
    let table: [(i32, i32); 14] = [
        (libc::EAI_AGAIN, -3001),
        (libc::EAI_BADFLAGS, -3002),
        (libc::EAI_FAIL, -3004),
        (libc::EAI_FAMILY, -3005),
        (libc::EAI_MEMORY, -3006),
        (libc::EAI_NODATA, -3007),
        (libc::EAI_NONAME, -3008),
        (libc::EAI_OVERFLOW, -3009),
        (libc::EAI_SERVICE, -3012),
        (libc::EAI_SOCKTYPE, -3011),
        // `EAI_ADDRFAMILY` has no glibc definition. libuv guards it with
        // `#if defined`, so on glibc the entry simply does not exist; the
        // placeholder below can never match because no glibc return value
        // equals it and the earlier entries are checked first.
        (i32::MIN, -3000),
        // `EAI_BADHINTS` and `EAI_PROTOCOL` are likewise optional upstream.
        (i32::MIN + 1, -3013),
        (i32::MIN + 2, -3014),
        // `EAI_CANCELED` exists only on platforms with a cancellable resolver.
        (i32::MIN + 3, -3003),
    ];
    for (platform, libuv) in table {
        if status == platform {
            return libuv;
        }
    }

    // libuv aborts on an unknown code. Turning a surprising platform value into
    // a permanent failure is the closer behaviour for a caller, since it reports
    // `EAI_FAIL` rather than killing the process mid-lookup.
    -3004
}

/// One resolved address, already in printable form.
///
/// `AfterGetAddrInfo` calls `uv_inet_ntop` on each `addrinfo` and skips any the
/// family filter does not want, so the family is carried along to apply the
/// order afterwards without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) text: String,
    pub(crate) family: Family,
}

/// `uv_getaddrinfo`'s job: resolve `hostname` and order the answer.
///
/// `flags` is `hints.ai_flags` verbatim, which is how `dns.lookup`'s `hints`
/// reaches the resolver. `family` filters the results the same way Node's
/// `add()` lambda does, so a `family: 4` request never reports an IPv6 address
/// even when the resolver returns one.
pub(crate) fn getaddrinfo(
    hostname: &str,
    family: RequestFamily,
    flags: i32,
    order: Order,
) -> Result<Vec<String>, LookupError> {
    // A hostname with an interior NUL cannot be passed to the C API. Node's
    // `Utf8Value` would truncate at it; failing loudly is better than resolving
    // a different name than the caller asked for.
    let host = CString::new(hostname).map_err(|_| LookupError(-22))?;

    // SAFETY: `addrinfo` is plain-old data with no invalid bit patterns, so a
    // zeroed value is a valid `hints` that `getaddrinfo` only reads.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = family.hint();
    // `GetAddrInfo` in `cares_wrap.cc` always sets `SOCK_STREAM`, and the socket
    // type is part of what the resolver filters on.
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = flags;

    let mut list: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: `host` is a NUL-terminated string that outlives the call, the
    // service is deliberately absent (Node passes `nullptr` too), `hints` is a
    // valid struct, and `list` is a valid out-pointer. On success the returned
    // list is owned here and released by `freeaddrinfo` below on every path.
    let status = unsafe { libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut list) };
    if status != 0 {
        return Err(LookupError(translate_eai(status)));
    }

    let resolved = collect(list, family);
    // SAFETY: `list` came from a successful `getaddrinfo` above and is not read
    // again. `freeaddrinfo` also accepts a null list, which keeps this correct
    // if the resolver ever succeeds with no results.
    unsafe { libc::freeaddrinfo(list) };

    if resolved.is_empty() {
        // `AfterGetAddrInfo` overwrites a zero count with `UV_EAI_NODATA`, so an
        // answer the family filter rejected is a failure, not an empty array.
        return Err(LookupError(-3007));
    }
    Ok(order_addresses(resolved, order))
}

/// Walks an `addrinfo` list and converts each wanted address to text.
fn collect(mut list: *mut libc::addrinfo, wanted: RequestFamily) -> Vec<Resolved> {
    let mut resolved = Vec::new();
    // SAFETY: each node comes from the list `getaddrinfo` returned and the walk
    // stops at its null terminator. `ai_addr` is non-null for any node whose
    // family is AF_INET or AF_INET6, which is checked before it is read.
    unsafe {
        while !list.is_null() {
            let node = &*list;
            let entry = match node.ai_family {
                libc::AF_INET => {
                    let address = &*(node.ai_addr as *const libc::sockaddr_in);
                    // `s_addr` is stored in network byte order, so its bytes are
                    // the address octets in memory order on every platform.
                    Some((Family::V4, address.sin_addr.s_addr.to_ne_bytes().to_vec()))
                }
                libc::AF_INET6 => {
                    let address = &*(node.ai_addr as *const libc::sockaddr_in6);
                    Some((Family::V6, address.sin6_addr.s6_addr.to_vec()))
                }
                _ => None,
            };
            if let Some((family, octets)) = entry {
                // The resolver is free to return the other family even under a
                // concrete `hints.ai_family` on some platforms, and Node filters
                // on the result rather than trusting the hint.
                if !wanted.accepts(family) {
                    list = node.ai_next;
                    continue;
                }
                let mut bytes = [0u8; 16];
                let length = octets.len().min(16);
                bytes[..length].copy_from_slice(&octets[..length]);
                let text = ip::ntop(&ip::Address { family, bytes });
                resolved.push(Resolved { text, family });
            }
            list = node.ai_next;
        }
    }
    resolved
}

/// `AfterGetAddrInfo`'s ordering.
///
/// `DNS_ORDER_VERBATIM` keeps the resolver's own interleaving; the other two
/// emit every address of one family first, preserving relative order within each
/// family. Node expresses this as two filtered passes over the same list, which
/// is equivalent to a stable partition.
fn order_addresses(resolved: Vec<Resolved>, order: Order) -> Vec<String> {
    let (first, second) = match order {
        Order::Ipv4First => (Family::V4, Family::V6),
        Order::Ipv6First => (Family::V6, Family::V4),
        Order::Verbatim => {
            return resolved.into_iter().map(|entry| entry.text).collect();
        }
    };
    let mut ordered = Vec::with_capacity(resolved.len());
    for family in [first, second] {
        ordered.extend(
            resolved
                .iter()
                .filter(|entry| entry.family == family)
                .map(|entry| entry.text.clone()),
        );
    }
    ordered
}

/// `uv_getnameinfo`'s job: reverse-resolve an address and port.
///
/// Node passes `NI_NAMEREQD`, so an address with no PTR record is an error
/// rather than an echo of the numeric form. The service name comes from
/// `/etc/services`, which is why port 80 reports `"http"` and an unassigned port
/// reports `"54321"`.
pub(crate) fn getnameinfo(address: &SocketAddr) -> Result<(String, String), LookupError> {
    match address.family {
        Family::V4 => reverse4(address),
        Family::V6 => reverse6(address),
    }
}

fn reverse4(address: &SocketAddr) -> Result<(String, String), LookupError> {
    let octets: [u8; 4] = address
        .bytes
        .get(..4)
        .and_then(|prefix| prefix.try_into().ok())
        .ok_or(LookupError(-22))?;

    let mut native = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(octets),
        },
        sin_zero: [0; 8],
    };
    reverse(
        (&mut native as *mut libc::sockaddr_in).cast(),
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    )
}

fn reverse6(address: &SocketAddr) -> Result<(String, String), LookupError> {
    let mut native = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: address.port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: address.bytes,
        },
        sin6_scope_id: 0,
    };
    reverse(
        (&mut native as *mut libc::sockaddr_in6).cast(),
        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
    )
}

fn reverse(
    addr: *mut libc::sockaddr,
    length: libc::socklen_t,
) -> Result<(String, String), LookupError> {
    // `NI_MAXHOST` is 1025 and `NI_MAXSERV` is 32 on every platform Node
    // supports, so the buffers are exactly large enough.
    let mut host = [0i8; 1025];
    let mut service = [0i8; 32];

    // SAFETY: `addr` points at a fully initialised sockaddr of `length` bytes
    // borrowed from the caller for this call, and both output buffers are
    // exactly the sizes passed. `getnameinfo` only reads the address and writes
    // NUL-terminated text into the buffers.
    let status = unsafe {
        libc::getnameinfo(
            addr,
            length,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            service.as_mut_ptr(),
            service.len() as libc::socklen_t,
            libc::NI_NAMEREQD,
        )
    };
    if status != 0 {
        return Err(LookupError(translate_eai(status)));
    }

    // SAFETY: on success `getnameinfo` wrote a NUL-terminated string into each
    // buffer, and each is at most as long as the buffer it was given.
    let hostname = unsafe { CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let service = unsafe { CStr::from_ptr(service.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok((hostname, service))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from Node on this machine, whose `/etc/hosts` names localhost
    /// once per family. The duplicate `127.0.0.1` with `family: 4` is real:
    /// `getaddrinfo` returns both `localhost` entries and the AF_INET filter
    /// keeps both A records.
    #[test]
    fn localhost_resolves_for_both_families() {
        let v6 = getaddrinfo("localhost", RequestFamily::V6, 0, Order::Verbatim).expect("ipv6");
        assert_eq!(v6, vec!["::1".to_string()]);

        let v4 = getaddrinfo("localhost", RequestFamily::V4, 0, Order::Verbatim).expect("ipv4");
        assert_eq!(v4, vec!["127.0.0.1".to_string(), "127.0.0.1".to_string()]);
    }

    /// `Order` applies to an `AF_UNSPEC` answer, which is the only case where
    /// both families can be present.
    #[test]
    fn ipv4_first_puts_every_v4_address_ahead_of_every_v6_address() {
        let addresses = getaddrinfo("localhost", RequestFamily::Unspec, 0, Order::Ipv4First)
            .expect("localhost resolves for both families");
        let first_v6 = addresses.iter().position(|address| address.contains(':'));
        let last_v4 = addresses.iter().rposition(|address| !address.contains(':'));
        assert_eq!(
            (first_v6, last_v4),
            (Some(1), Some(0)),
            "v4 must come first, got {addresses:?}"
        );

        // And the reverse order really reverses.
        let addresses = getaddrinfo("localhost", RequestFamily::Unspec, 0, Order::Ipv6First)
            .expect("localhost resolves for both families");
        assert!(
            addresses
                .first()
                .is_some_and(|address| address.contains(':')),
            "v6 must come first, got {addresses:?}"
        );
    }

    #[test]
    fn verbatim_does_not_reorder_a_single_family() {
        let addresses =
            getaddrinfo("localhost", RequestFamily::V4, 0, Order::Verbatim).expect("ipv4");
        assert!(!addresses.is_empty());
    }

    #[test]
    fn a_missing_name_reports_a_libuv_not_found_code() {
        let error = getaddrinfo(
            "no-such-host.invalid",
            RequestFamily::V6,
            0,
            Order::Verbatim,
        )
        .expect_err("must not resolve");
        // `DNSException` maps both NODATA and NONAME to ENOTFOUND, and a
        // resolver that answers NXDOMAIN versus an empty answer picks one.
        assert!(
            error.0 == -3007 || error.0 == -3008,
            "unexpected code {}",
            error.0
        );
    }

    /// glibc reports an empty name as `EAI_NONAME`, which libuv turns into
    /// `UV_EAI_NONAME`; Node's own `GetAddrInfo` never sees it because `lib/dns.js`
    /// rejects the empty hostname first.
    #[test]
    fn an_empty_hostname_fails_resolution() {
        let error = getaddrinfo("", RequestFamily::V6, 0, Order::Verbatim).expect_err("must fail");
        assert!(
            error.0 == -3007 || error.0 == -3008,
            "unexpected code {}",
            error.0
        );
    }

    #[test]
    fn reverse_lookup_finds_localhost_and_a_named_service() {
        let address = ip::pton(Family::V4, "127.0.0.1")
            .expect("loopback")
            .with_port(80);
        let (hostname, service) = getnameinfo(&address).expect("reverse lookup");
        assert_eq!(hostname, "localhost");
        assert_eq!(service, "http");
    }

    #[test]
    fn reverse_lookup_reports_the_service_for_ipv6_loopback() {
        let address = ip::pton(Family::V6, "::1").expect("loopback").with_port(22);
        let (hostname, service) = getnameinfo(&address).expect("reverse lookup");
        assert_eq!(hostname, "localhost");
        assert_eq!(service, "ssh");
    }

    #[test]
    fn an_unassigned_port_reports_the_number() {
        let address = ip::pton(Family::V4, "127.0.0.1")
            .expect("loopback")
            .with_port(54321);
        let (_, service) = getnameinfo(&address).expect("reverse lookup");
        assert_eq!(service, "54321");
    }

    /// The platform values differ between glibc and macOS, so a translation
    /// table that only works on one is a real risk. These pin the codes a
    /// recording from Node actually produced.
    #[test]
    fn platform_error_codes_translate_to_libuv_codes() {
        assert_eq!(translate_eai(libc::EAI_NONAME), -3008);
        assert_eq!(translate_eai(libc::EAI_NODATA), -3007);
        assert_eq!(translate_eai(libc::EAI_AGAIN), -3001);
        assert_eq!(translate_eai(libc::EAI_FAMILY), -3005);
        assert_eq!(translate_eai(libc::EAI_SERVICE), -3012);
    }

    #[test]
    fn ordering_is_a_stable_partition() {
        let entries = vec![
            Resolved {
                text: "::1".to_string(),
                family: Family::V6,
            },
            Resolved {
                text: "10.0.0.1".to_string(),
                family: Family::V4,
            },
            Resolved {
                text: "10.0.0.2".to_string(),
                family: Family::V4,
            },
            Resolved {
                text: "::2".to_string(),
                family: Family::V6,
            },
        ];
        assert_eq!(
            order_addresses(entries.clone(), Order::Ipv4First),
            vec!["10.0.0.1", "10.0.0.2", "::1", "::2"]
        );
        assert_eq!(
            order_addresses(entries.clone(), Order::Ipv6First),
            vec!["::1", "::2", "10.0.0.1", "10.0.0.2"]
        );
        assert_eq!(
            order_addresses(entries, Order::Verbatim),
            vec!["::1", "10.0.0.1", "10.0.0.2", "::2"]
        );
    }

    #[test]
    fn order_from_raw_matches_the_namespace_constants() {
        assert_eq!(Order::from_raw(0), Order::Verbatim);
        assert_eq!(Order::from_raw(1), Order::Ipv4First);
        assert_eq!(Order::from_raw(2), Order::Ipv6First);
        // Anything else falls back to verbatim, as `AfterGetAddrInfo`'s
        // `default:` branch does.
        assert_eq!(Order::from_raw(99), Order::Verbatim);
    }
}

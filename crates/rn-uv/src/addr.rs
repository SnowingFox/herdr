//! `sockaddr` conversions and the address object `lib/net.js` reads.
//!
//! `getsockname()`/`getpeername()` do not return a string: `src/tcp_wrap.cc`'s
//! `AddressToJS` fills a caller-provided object with `address`, `family` and
//! `port`, and `lib/net.js` reads those three properties:
//!
//! ```js
//! const out = {};
//! const err = handle.getsockname(out);
//! // out.address, out.family ('IPv4' | 'IPv6'), out.port
//! ```
//!
//! A pipe's `getsockname` is different — it sets only `address`, to the bound
//! path — which is why the pipe binding has its own small implementation rather
//! than reusing this one.

use std::ffi::CStr;

use libuv_sys2 as uv;

/// The `family` string Node reports for an address object.
pub const IPV4: &str = "IPv4";
/// The `family` string Node reports for an address object.
pub const IPV6: &str = "IPv6";

/// `UV_EINVAL` — what libuv returns for a malformed address literal.
pub const EINVAL: i32 = uv::uv_errno_t_UV_EINVAL;

/// `AF_INET`, as the family value a `sockaddr` carries.
const AF_INET: i32 = uv::AF_INET as i32;
/// `AF_INET6`, as the family value a `sockaddr` carries.
const AF_INET6: i32 = uv::AF_INET6 as i32;

/// A parsed socket address, in the form the address object needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The textual address, e.g. `127.0.0.1` or `::1`.
    pub address: String,
    /// [`IPV4`] or [`IPV6`].
    pub family: &'static str,
    /// The port, in host byte order.
    pub port: u16,
}

/// `uv_ip4_addr`, returning libuv's status code.
pub fn ip4(host: &str, port: u16) -> Result<uv::sockaddr_in, i32> {
    let mut address = std::mem::MaybeUninit::<uv::sockaddr_in>::zeroed();
    let Ok(host) = std::ffi::CString::new(host) else {
        // An interior NUL cannot be part of an address; `uv_ip4_addr` has no
        // code for it, and `UV_EINVAL` is what libuv returns for malformed
        // input.
        return Err(EINVAL);
    };
    // SAFETY: `address` is a live, correctly-sized out-parameter and `host` is a
    // NUL-terminated string.
    let status = unsafe { uv::uv_ip4_addr(host.as_ptr(), i32::from(port), address.as_mut_ptr()) };
    if status != 0 {
        return Err(status);
    }
    // SAFETY: libuv filled it in and returned success.
    Ok(unsafe { address.assume_init() })
}

/// `uv_ip6_addr`, returning libuv's status code.
pub fn ip6(host: &str, port: u16) -> Result<uv::sockaddr_in6, i32> {
    let mut address = std::mem::MaybeUninit::<uv::sockaddr_in6>::zeroed();
    let Ok(host) = std::ffi::CString::new(host) else {
        return Err(EINVAL);
    };
    // SAFETY: as in `ip4`.
    let status = unsafe { uv::uv_ip6_addr(host.as_ptr(), i32::from(port), address.as_mut_ptr()) };
    if status != 0 {
        return Err(status);
    }
    // SAFETY: libuv filled it in and returned success.
    Ok(unsafe { address.assume_init() })
}

/// Renders a `sockaddr` as an [`Address`].
///
/// Returns `None` for a family this does not know, which is a unix-domain
/// address (handled by the pipe binding) or an empty socket.
pub fn from_sockaddr(address: &uv::sockaddr) -> Option<Address> {
    match i32::from(address.sa_family) {
        AF_INET => {
            // SAFETY: the family says this is a `sockaddr_in`, and libuv hands
            // out the fully-initialised struct.
            let v4 = unsafe { &*std::ptr::from_ref(address).cast::<uv::sockaddr_in>() };
            Some(Address {
                address: text_v4(&v4.sin_addr),
                family: IPV4,
                port: u16::from_be(v4.sin_port),
            })
        }
        AF_INET6 => {
            // SAFETY: as above, for `sockaddr_in6`.
            let v6 = unsafe { &*std::ptr::from_ref(address).cast::<uv::sockaddr_in6>() };
            Some(Address {
                address: text_v6(&v6.sin6_addr),
                family: IPV6,
                port: u16::from_be(v6.sin6_port),
            })
        }
        _ => None,
    }
}

/// `uv_inet_ntop` for an IPv4 address.
fn text_v4(address: &uv::in_addr) -> String {
    let mut buffer = [0i8; 16];
    // SAFETY: `buffer` is the 16 bytes `INET_ADDRSTRLEN` requires and `address`
    // points at a live 4-byte address.
    let status = unsafe {
        uv::uv_inet_ntop(
            AF_INET,
            std::ptr::from_ref(address).cast(),
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if status != 0 {
        return String::new();
    }
    // SAFETY: `uv_inet_ntop` NUL-terminated the buffer on success.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// `uv_inet_ntop` for an IPv6 address.
fn text_v6(address: &uv::in6_addr) -> String {
    let mut buffer = [0i8; 46];
    // SAFETY: `buffer` is the 46 bytes `INET6_ADDRSTRLEN` requires.
    let status = unsafe {
        uv::uv_inet_ntop(
            AF_INET6,
            std::ptr::from_ref(address).cast(),
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if status != 0 {
        return String::new();
    }
    // SAFETY: `uv_inet_ntop` NUL-terminated the buffer on success.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_round_trips_through_a_sockaddr() {
        let address = ip4("127.0.0.1", 8080).expect("127.0.0.1 is a valid address");
        // SAFETY: `sockaddr_in` and `sockaddr` are layout-compatible for the
        // leading family field, which is all `from_sockaddr` reads before it
        // casts back.
        let sockaddr = unsafe { &*std::ptr::from_ref(&address).cast::<uv::sockaddr>() };
        let parsed = from_sockaddr(sockaddr).expect("an AF_INET address parses");
        assert_eq!(parsed.address, "127.0.0.1");
        assert_eq!(parsed.family, IPV4);
        assert_eq!(parsed.port, 8080);
    }

    #[test]
    fn ipv6_round_trips_through_a_sockaddr() {
        let address = ip6("::1", 443).expect("::1 is a valid address");
        // SAFETY: as above, for `sockaddr_in6`.
        let sockaddr = unsafe { &*std::ptr::from_ref(&address).cast::<uv::sockaddr>() };
        let parsed = from_sockaddr(sockaddr).expect("an AF_INET6 address parses");
        assert_eq!(parsed.address, "::1");
        assert_eq!(parsed.family, IPV6);
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn a_malformed_address_is_rejected() {
        let error = ip4("not an address", 1).expect_err("libuv rejects a hostname");
        assert_eq!(error, EINVAL);
    }
}

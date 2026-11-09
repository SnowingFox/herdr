//! `SocketAddress`: the value type the blocklist rules are written in.
//!
//! Node's `src/node_sockaddr.h` wraps a `sockaddr_storage`, and its identity
//! rules are narrower than the struct suggests. Three separate comparisons
//! exist there and the blocklist depends on the difference:
//!
//! * `operator==` compares family plus the *whole* `sockaddr` (port, address,
//!   and for IPv6 the flow label and scope id). `removeSubnet` matches rules
//!   this way, so removing a subnet must name the same port as the add did.
//! * `IpHash`/`IpEqual` ignore the port entirely; that is what makes `address`
//!   rules answer a lookup for any port.
//! * `compare` orders two addresses by address bytes alone and answers
//!   *unordered* across families, except that a `::ffff:x.x.x.x` IPv6 address
//!   is ordered against IPv4 by its embedded quad. Range rules are ordered
//!   comparisons, so they inherit exactly that behaviour: an IPv4 range
//!   contains `::ffff:10.0.0.5` but not `2001:db8::1`.
//!
//! Parsing and formatting go through libuv rather than a Rust IP type. That is
//! deliberate: `uv_ip4_addr`, `uv_ip6_addr` and `uv_inet_ntop` are the exact
//! functions Node calls, so the accepted spellings, the zone handling and the
//! compressed output form cannot drift. In particular `::ffff:1.2.3.4` prints
//! back as dotted quad because libuv's `inet_ntop6` emits an embedded IPv4 for
//! a run of zeros followed by `ffff`, and the rules serialise that text.

use std::cmp::Ordering;
use std::ffi::{CStr, CString};

use libuv_sys2 as uv;

/// `AF_INET`, the family value the JavaScript layer passes back in.
pub const AF_INET: i32 = uv::AF_INET as i32;
/// `AF_INET6`, the family value the JavaScript layer passes back in.
pub const AF_INET6: i32 = uv::AF_INET6 as i32;

/// The address family of a [`SocketAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// `AF_INET`.
    V4,
    /// `AF_INET6`.
    V6,
}

impl Family {
    /// The family for an `AF_INET`/`AF_INET6` value, or `None` for anything
    /// else. Node `UNREACHABLE()`s on a third family; a binding cannot abort
    /// the process, so an unknown value is reported as a parse failure.
    pub fn from_af(af: i32) -> Option<Self> {
        match af {
            AF_INET => Some(Self::V4),
            AF_INET6 => Some(Self::V6),
            _ => None,
        }
    }

    /// The `AF_*` value.
    pub fn af(self) -> i32 {
        match self {
            Self::V4 => AF_INET,
            Self::V6 => AF_INET6,
        }
    }

    /// The `IPv4`/`IPv6` spelling `AddressToJS` and the rules use.
    pub fn label(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }

    /// The number of address bits, which is the trie depth for this family.
    pub fn bits(self) -> usize {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

/// One parsed address, in the form the blocklist rules need.
///
/// The address bytes are kept in network order, so a lexicographic comparison
/// of the byte slice is the numeric comparison Node gets from `ntohl` on IPv4
/// and `memcmp` on IPv6. Only the first four bytes are meaningful for IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAddress {
    family: Family,
    port: u16,
    flow_label: u32,
    scope_id: u32,
    bytes: [u8; 16],
}

/// The `::ffff:` prefix that marks an IPv4-mapped IPv6 address.
const IPV4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

impl SocketAddress {
    /// Parses `host` as an address of `family`, the way `SocketAddress::New`
    /// does.
    ///
    /// Returns `None` for anything libuv rejects, which is how `checkString`
    /// turns `'999.999.999.999'` into `false` rather than an exception.
    pub fn parse(family: Family, host: &str, port: u16) -> Option<Self> {
        // A NUL inside the JavaScript string truncates the address for Node
        // too: the C++ hands libuv a `char*`, which stops there.
        let host = host.split('\0').next().unwrap_or("");
        let host = CString::new(host).ok()?;
        match family {
            Family::V4 => {
                let mut raw = std::mem::MaybeUninit::<uv::sockaddr_in>::zeroed();
                // SAFETY: `raw` is a live out-parameter of the exact type
                // `uv_ip4_addr` writes, and `host` outlives the call.
                let status =
                    unsafe { uv::uv_ip4_addr(host.as_ptr(), i32::from(port), raw.as_mut_ptr()) };
                if status != 0 {
                    return None;
                }
                // SAFETY: libuv reported success, so it initialised `raw`.
                let raw = unsafe { raw.assume_init() };
                // `s_addr` holds the four octets in network order, which is
                // the byte order `to_ne_bytes` reproduces on this host.
                let mut bytes = [0u8; 16];
                bytes[..4].copy_from_slice(&raw.sin_addr.s_addr.to_ne_bytes());
                Some(Self {
                    family,
                    port,
                    flow_label: 0,
                    scope_id: 0,
                    bytes,
                })
            }
            Family::V6 => {
                let mut raw = std::mem::MaybeUninit::<uv::sockaddr_in6>::zeroed();
                // SAFETY: as above, for `uv_ip6_addr`.
                let status =
                    unsafe { uv::uv_ip6_addr(host.as_ptr(), i32::from(port), raw.as_mut_ptr()) };
                if status != 0 {
                    return None;
                }
                // SAFETY: libuv reported success, so it initialised `raw`.
                let raw = unsafe { raw.assume_init() };
                // SAFETY: `in6_addr` is a union whose `__u6_addr8` arm is the
                // sixteen octets; libuv wrote them with `inet_pton`.
                let bytes = unsafe { raw.sin6_addr.__in6_u.__u6_addr8 };
                Some(Self {
                    family,
                    port,
                    flow_label: 0,
                    scope_id: raw.sin6_scope_id,
                    bytes,
                })
            }
        }
    }

    /// Builds an address from a family and raw network-order bytes.
    ///
    /// Used for the cross-family counterparts `addAddress` and `addSubnet`
    /// maintain, which are derived rather than parsed.
    pub fn from_bytes(family: Family, bytes: [u8; 16], port: u16) -> Self {
        Self {
            family,
            port,
            flow_label: 0,
            scope_id: 0,
            bytes,
        }
    }

    /// The address family.
    pub fn family(&self) -> Family {
        self.family
    }

    /// The port, in host byte order.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The IPv6 flow label. Always zero for IPv4, as `set_flow_label` is a
    /// no-op there.
    pub fn flow_label(&self) -> u32 {
        self.flow_label
    }

    /// Sets the IPv6 flow label. Like `set_flow_label`, this does nothing for
    /// an IPv4 address.
    pub fn set_flow_label(&mut self, label: u32) {
        if self.family == Family::V6 {
            self.flow_label = label;
        }
    }

    /// The scope id, which `uv_ip6_addr` derives from a `%zone` suffix.
    pub fn scope_id(&self) -> u32 {
        self.scope_id
    }

    /// The raw address bytes: four for IPv4, sixteen for IPv6.
    pub fn raw(&self) -> &[u8] {
        match self.family {
            Family::V4 => &self.bytes[..4],
            Family::V6 => &self.bytes[..],
        }
    }

    /// `uv_inet_ntop` of the address, which is the text the rules serialise
    /// and `detail()` reports.
    pub fn text(&self) -> String {
        let (af, length) = match self.family {
            Family::V4 => (AF_INET, 16usize),
            Family::V6 => (AF_INET6, 46usize),
        };
        let mut buffer = [0 as std::ffi::c_char; 46];
        // SAFETY: `buffer` is at least `length` bytes, `self.bytes` holds the
        // address `af` names, and both outlive the call.
        let status = unsafe {
            uv::uv_inet_ntop(af, self.bytes.as_ptr().cast(), buffer.as_mut_ptr(), length)
        };
        if status != 0 {
            return String::new();
        }
        // SAFETY: `uv_inet_ntop` NUL-terminated the buffer on success.
        unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }

    /// The embedded IPv4 quad when this is a `::ffff:x.x.x.x` address.
    pub fn ipv4_mapped(&self) -> Option<[u8; 4]> {
        if self.family != Family::V6 || self.bytes[..12] != IPV4_MAPPED_PREFIX {
            return None;
        }
        let mut quad = [0u8; 4];
        quad.copy_from_slice(&self.bytes[12..]);
        Some(quad)
    }

    /// This IPv4 address as `::ffff:x.x.x.x`, which is the counterpart
    /// `addAddress` also stores so both spellings resolve.
    pub fn to_ipv4_mapped(&self) -> Option<Self> {
        if self.family != Family::V4 {
            return None;
        }
        let mut bytes = [0u8; 16];
        bytes[..12].copy_from_slice(&IPV4_MAPPED_PREFIX);
        bytes[12..].copy_from_slice(&self.bytes[..4]);
        Some(Self {
            family: Family::V6,
            port: self.port,
            flow_label: 0,
            scope_id: 0,
            bytes,
        })
    }

    /// The `IpEqual` key: what identifies the address for an exact-address
    /// rule. The port is deliberately not part of it, so a rule added for
    /// `1.2.3.4:80` also answers a lookup of `1.2.3.4:443`.
    pub fn ip_key(&self) -> (Family, [u8; 16]) {
        (self.family, self.bytes)
    }

    /// `SocketAddress::compare`: the ordering range rules use.
    ///
    /// `None` is Node's `std::partial_ordering::unordered`, which an ordered
    /// comparison against either endpoint treats as "does not match".
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self.family, other.family) {
            (Family::V4, Family::V4) => Some(self.bytes[..4].cmp(&other.bytes[..4])),
            (Family::V6, Family::V6) => Some(self.bytes.cmp(&other.bytes)),
            (Family::V4, Family::V6) => {
                // The IPv6 side has to be the mapped form, and the comparison
                // is then between the two quads.
                let mapped = other.ipv4_mapped()?;
                Some(self.bytes[..4].cmp(&mapped[..]))
            }
            (Family::V6, Family::V4) => {
                let mapped = self.ipv4_mapped()?;
                Some(mapped[..].cmp(&other.bytes[..4]))
            }
        }
    }

    /// Whether `self` is at or after `other`, treating unordered as a miss.
    pub fn at_or_after(&self, other: &Self) -> bool {
        matches!(
            self.compare(other),
            Some(Ordering::Greater | Ordering::Equal)
        )
    }

    /// Whether `self` is at or before `other`, treating unordered as a miss.
    pub fn at_or_before(&self, other: &Self) -> bool {
        matches!(self.compare(other), Some(Ordering::Less | Ordering::Equal))
    }

    /// The `AddressToJS` shape: `{ address, family, port }`.
    ///
    /// A link-local IPv6 address with a scope id gets a `%interface` suffix,
    /// which is the only place `uv_if_indextoiid` is needed.
    pub fn display_text(&self) -> String {
        let text = self.text();
        if self.family != Family::V6 || self.scope_id == 0 {
            return text;
        }
        // `IN6_IS_ADDR_LINKLOCAL`: fe80::/10.
        if !(self.bytes[0] == 0xfe && (self.bytes[1] & 0xc0) == 0x80) {
            return text;
        }
        let mut buffer = vec![0 as std::ffi::c_char; 64];
        let mut size = buffer.len();
        // SAFETY: `buffer` is writable for `size` bytes and `size` is an
        // in/out length, as `uv_if_indextoiid` requires.
        let status = unsafe { uv::uv_if_indextoiid(self.scope_id, buffer.as_mut_ptr(), &mut size) };
        if status != 0 {
            return text;
        }
        // SAFETY: on success libuv wrote a NUL-terminated name into `buffer`.
        let name = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy();
        format!("{text}%{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> SocketAddress {
        SocketAddress::parse(Family::V4, text, 0).expect("a valid IPv4 literal")
    }

    fn v6(text: &str) -> SocketAddress {
        SocketAddress::parse(Family::V6, text, 0).expect("a valid IPv6 literal")
    }

    #[test]
    fn ipv4_round_trips_through_text() {
        assert_eq!(v4("1.2.3.4").text(), "1.2.3.4");
        assert_eq!(v4("0.0.0.0").text(), "0.0.0.0");
        assert_eq!(v4("255.255.255.255").text(), "255.255.255.255");
    }

    #[test]
    fn ipv6_compresses_and_keeps_the_mapped_form_dotted() {
        assert_eq!(v6("::").text(), "::");
        assert_eq!(v6("::1").text(), "::1");
        assert_eq!(
            v6("8592:757c:efae:4e45:0:0:0:0").text(),
            "8592:757c:efae:4e45::"
        );
        // libuv prints the embedded quad rather than two hex groups.
        assert_eq!(v6("::ffff:1.2.3.4").text(), "::ffff:1.2.3.4");
        assert_eq!(v6("::ffff:0102:0304").text(), "::ffff:1.2.3.4");
    }

    #[test]
    fn a_malformed_literal_is_rejected() {
        assert!(SocketAddress::parse(Family::V4, "999.1.1.1", 0).is_none());
        assert!(SocketAddress::parse(Family::V4, "1.1.1", 0).is_none());
        assert!(SocketAddress::parse(Family::V4, "::1", 0).is_none());
        assert!(SocketAddress::parse(Family::V6, "1.1.1.1", 0).is_none());
        assert!(SocketAddress::parse(Family::V6, "not_valid_ipv6", 0).is_none());
        assert!(SocketAddress::parse(Family::V4, "", 0).is_none());
    }

    #[test]
    fn an_ipv4_zone_is_rejected_but_an_ipv6_one_is_not() {
        assert!(SocketAddress::parse(Family::V4, "1.1.1.1%eth0", 0).is_none());
        // An unknown interface name leaves the scope id at zero, which is what
        // libuv documents.
        assert_eq!(v6("fe80::1%zzz").scope_id(), 0);
    }

    #[test]
    fn ordering_is_by_address_bytes_and_unordered_across_families() {
        assert_eq!(v4("1.1.1.1").compare(&v4("1.1.1.2")), Some(Ordering::Less));
        assert_eq!(
            v4("1.1.1.2").compare(&v4("1.1.1.1")),
            Some(Ordering::Greater)
        );
        assert_eq!(v4("1.1.1.1").compare(&v4("1.1.1.1")), Some(Ordering::Equal));

        assert_eq!(v6("::1").compare(&v6("::2")), Some(Ordering::Less));
        assert_eq!(
            v6("2001:db8::1").compare(&v6("2001:db8::2")),
            Some(Ordering::Less)
        );

        // Cross-family only orders through the mapped form.
        assert_eq!(
            v4("1.1.1.1").compare(&v6("::ffff:1.1.1.2")),
            Some(Ordering::Less)
        );
        assert_eq!(
            v6("::ffff:1.1.1.2").compare(&v4("1.1.1.1")),
            Some(Ordering::Greater)
        );
        assert_eq!(v4("1.1.1.1").compare(&v6("2001:db8::1")), None);
        assert_eq!(v6("2001:db8::1").compare(&v4("1.1.1.1")), None);
    }

    #[test]
    fn the_mapped_counterpart_round_trips() {
        let mapped = v4("10.0.0.1").to_ipv4_mapped().expect("IPv4 maps");
        assert_eq!(mapped.family(), Family::V6);
        assert_eq!(mapped.ipv4_mapped(), Some([10, 0, 0, 1]));
        assert_eq!(mapped.text(), "::ffff:10.0.0.1");
        assert_eq!(v6("2001:db8::1").ipv4_mapped(), None);
    }

    #[test]
    fn identity_includes_the_port_and_the_flow_label() {
        let one = SocketAddress::parse(Family::V4, "1.1.1.1", 80).expect("valid");
        let two = SocketAddress::parse(Family::V4, "1.1.1.1", 443).expect("valid");
        assert_ne!(one, two);
        // ...but the address key ignores the port, which is what makes an
        // address rule apply to every port.
        assert_eq!(one.ip_key(), two.ip_key());
    }
}

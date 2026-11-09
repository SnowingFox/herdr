//! `uv_inet_pton` and `uv_inet_ntop`, transcribed from libuv.
//!
//! `canonicalizeIP` and `convertIpv6StringToBuffer` in Node's `cares_wrap.cc`
//! are thin wrappers over these two functions, and they are *not*
//! `inet_pton(3)`/`inet_ntop(3)`: libuv ships its own copies so the output is
//! identical across platforms. The differences are observable from JavaScript,
//! so the C control flow is reproduced here rather than delegated to libc:
//!
//! * `uv_inet_pton` strips an IPv6 scope id at `%`, so `fe80::1%eth0` parses.
//!   `inet_pton(3)` rejects it on Linux.
//! * `uv_inet_pton4` refuses an octet with a leading zero (`192.168.000.001`).
//!   Some libcs accept it as octal.
//! * `uv_inet_ntop6` writes the dotted-quad form for IPv4-mapped, IPv4-compatible
//!   and NAT64 addresses, and picks the *first* longest zero run rather than any
//!   longest run.
//!
//! Every case below is pinned by a test, and the test data was recorded from a
//! real Node binary.

/// The address family an address parsed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    V4,
    V6,
}

/// IPv6 under a name that reads better where the family is all that is needed,
/// such as `getnameinfo`'s parser or `convertIpv6StringToBuffer`.
pub(crate) const FAMILY_V6: Family = Family::V6;

/// A parsed address, held in the 16-byte buffer `uv_inet_pton` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Address {
    pub(crate) family: Family,
    /// The first 4 bytes hold an IPv4 address; all 16 hold an IPv6 one.
    pub(crate) bytes: [u8; 16],
}

/// A family-tagged address and port, which `getnameinfo` turns into a
/// `sockaddr`.
///
/// The address bytes are kept in the same 16-byte buffer `uv_inet_pton` writes
/// so there is no fallible conversion between the two types; the syscall module
/// copies out the prefix the family needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SocketAddr {
    pub(crate) bytes: [u8; 16],
    pub(crate) port: u16,
    pub(crate) family: Family,
}

impl Address {
    /// `uv_ip4_addr`/`uv_ip6_addr`: the address plus a port.
    pub(crate) fn with_port(&self, port: u16) -> SocketAddr {
        SocketAddr {
            bytes: self.bytes,
            port,
            family: self.family,
        }
    }
}

/// `uv_inet_pton(af, src, dst)`, returning the same success/failure split.
///
/// libuv returns 0 on success and a negative error otherwise; only "did it
/// parse" is observable from JavaScript, so the error value collapses to `None`.
pub(crate) fn pton(family: Family, source: &str) -> Option<Address> {
    match family {
        Family::V4 => pton4(source).map(|bytes| Address {
            family: Family::V4,
            bytes: {
                let mut buffer = [0u8; 16];
                buffer[..4].copy_from_slice(&bytes);
                buffer
            },
        }),
        // libuv strips a scope id before parsing: `p = strchr(src, '%')` and, if
        // found, only the prefix is passed to `inet_pton6`. The scope is
        // discarded, which is why `fe80::1%eth0` canonicalises to `fe80::1`.
        Family::V6 => {
            let text = match source.find('%') {
                Some(index) => &source[..index],
                None => source,
            };
            pton6(text).map(|bytes| Address {
                family: Family::V6,
                bytes,
            })
        }
    }
}

/// Parses the first family in `families` that accepts `source`.
///
/// `CanonicalizeIP` in Node tries `AF_INET` then `AF_INET6` and keeps whichever
/// matched, because the family decides how the address is printed back.
pub(crate) fn parse_any(source: &str) -> Option<Address> {
    pton(Family::V4, source).or_else(|| pton(Family::V6, source))
}

/// `inet_pton4` from libuv's `inet.c`.
///
/// The two checks that matter are the leading-zero rejection (`saw_digit &&
/// *tp == 0`) and the `octets > 4` guard, neither of which every libc has.
fn pton4(source: &str) -> Option<[u8; 4]> {
    let mut result = [0u8; 4];
    let mut tp = 0usize;
    let mut saw_digit = false;
    let mut octets = 0u32;

    for byte in source.bytes() {
        if byte.is_ascii_digit() {
            let digit = u32::from(byte - b'0');
            let current = u32::from(result[tp]);
            let next = current * 10 + digit;
            // `if (saw_digit && *tp == 0) return UV_EINVAL;` — refuses `00` and
            // `01`, which are octal in some resolvers and decimal in others.
            if saw_digit && result[tp] == 0 {
                return None;
            }
            if next > 255 {
                return None;
            }
            result[tp] = next as u8;
            if !saw_digit {
                octets += 1;
                if octets > 4 {
                    return None;
                }
                saw_digit = true;
            }
        } else if byte == b'.' && saw_digit {
            if octets == 4 {
                return None;
            }
            tp += 1;
            result[tp] = 0;
            saw_digit = false;
        } else {
            return None;
        }
    }

    if octets < 4 {
        return None;
    }
    Some(result)
}

/// `inet_pton6` from libuv's `inet.c`.
fn pton6(source: &str) -> Option<[u8; 16]> {
    let bytes = source.as_bytes();
    let mut tmp = [0u8; 16];
    let mut tp = 0usize;
    let endp = tmp.len();
    let mut colonp: Option<usize> = None;
    let mut index = 0usize;

    // A leading `::` is a zero run at offset zero; a single leading `:` is not
    // an address at all.
    if bytes.first() == Some(&b':') {
        index += 1;
        if bytes.get(index) != Some(&b':') {
            return None;
        }
    }
    let mut curtok = index;
    let mut seen_xdigits = 0u32;
    let mut val: u32 = 0;

    while index < bytes.len() {
        let ch = bytes[index];
        index += 1;

        if let Some(digit) = hex_value(ch) {
            val = (val << 4) | digit;
            seen_xdigits += 1;
            if seen_xdigits > 4 {
                return None;
            }
            continue;
        }

        if ch == b':' {
            curtok = index;
            if seen_xdigits == 0 {
                if colonp.is_some() {
                    return None;
                }
                colonp = Some(tp);
                continue;
            } else if index == bytes.len() {
                // A `:` must be followed by more digits or another `:`.
                return None;
            }
            if tp + 2 > endp {
                return None;
            }
            tmp[tp] = ((val >> 8) & 0xff) as u8;
            tmp[tp + 1] = (val & 0xff) as u8;
            tp += 2;
            seen_xdigits = 0;
            val = 0;
            continue;
        }

        if ch == b'.' && tp + 4 <= endp {
            // An embedded dotted quad fills the last four bytes.
            if let Some(quad) = pton4(&source[curtok..]) {
                tmp[tp..tp + 4].copy_from_slice(&quad);
                tp += 4;
                seen_xdigits = 0;
                // The quad consumed the rest of the input, so the loop has
                // nothing left to read. `index` is not advanced because the
                // loop ends on the next check.
                break;
            }
        }

        return None;
    }

    if seen_xdigits > 0 {
        if tp + 2 > endp {
            return None;
        }
        tmp[tp] = ((val >> 8) & 0xff) as u8;
        tmp[tp + 1] = (val & 0xff) as u8;
        tp += 2;
    }

    if let Some(colon) = colonp {
        // Expand `::` by shifting the tail right, exactly as the C loop does.
        let count = tp - colon;
        if tp == endp {
            return None;
        }
        for offset in 1..=count {
            tmp[endp - offset] = tmp[colon + count - offset];
            tmp[colon + count - offset] = 0;
        }
        tp = endp;
    }

    if tp != endp {
        return None;
    }
    Some(tmp)
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(u32::from(byte - b'A') + 10),
        _ => None,
    }
}

/// `uv_inet_ntop6` from libuv's `inet.c`.
///
/// The `i == 6 && best.base == 0` branch is what makes `::ffff:127.0.0.1` print
/// as a dotted quad instead of `::ffff:7f00:1`; it covers IPv4-mapped,
/// IPv4-compatible, and NAT64 (`64:ff9b::/96`) addresses.
pub(crate) fn ntop(address: &Address) -> String {
    match address.family {
        Family::V4 => format!(
            "{}.{}.{}.{}",
            address.bytes[0], address.bytes[1], address.bytes[2], address.bytes[3]
        ),
        Family::V6 => ntop6(&address.bytes),
    }
}

/// The IPv6 formatter on its own, for callers that already have the octets.
pub(crate) fn ntop6(bytes: &[u8; 16]) -> String {
    let mut words = [0u16; 8];
    for (index, word) in words.iter_mut().enumerate() {
        *word = (u16::from(bytes[index * 2]) << 8) | u16::from(bytes[index * 2 + 1]);
    }

    // Longest run of zero words, but libuv keeps the *first* one of equal
    // length (`cur.len > best.len`, not `>=`), and only runs of two or more are
    // worth abbreviating.
    let mut best: Option<(usize, usize)> = None;
    let mut current: Option<(usize, usize)> = None;
    for (index, word) in words.iter().enumerate() {
        if *word == 0 {
            current = match current {
                Some((base, len)) => Some((base, len + 1)),
                None => Some((index, 1)),
            };
        } else if let Some(run) = current.take() {
            if best.is_none_or(|(_, best_len)| run.1 > best_len) {
                best = Some(run);
            }
        }
    }
    if let Some(run) = current {
        if best.is_none_or(|(_, best_len)| run.1 > best_len) {
            best = Some(run);
        }
    }
    if let Some((_, len)) = best {
        if len < 2 {
            best = None;
        }
    }

    let mut out = String::new();
    let mut index = 0usize;
    while index < words.len() {
        if let Some((base, len)) = best {
            if index >= base && index < base + len {
                if index == base {
                    out.push(':');
                }
                index += 1;
                continue;
            }
        }
        if index != 0 {
            out.push(':');
        }
        // The IPv4-embedded forms, in libuv's exact order.
        let embedded = index == 6
            && best.is_some_and(|(base, len)| {
                base == 0
                    && (len == 6
                        || (len == 7 && words[7] != 0x0001)
                        || (len == 5 && words[5] == 0xffff))
            });
        if embedded {
            out.push_str(&format!(
                "{}.{}.{}.{}",
                bytes[12], bytes[13], bytes[14], bytes[15]
            ));
            break;
        }
        out.push_str(&format!("{:x}", words[index]));
        index += 1;
    }
    if let Some((base, len)) = best {
        if base + len == words.len() {
            out.push(':');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(source: &str) -> Option<String> {
        parse_any(source).map(|address| ntop(&address))
    }

    /// Every expectation here was recorded from a real Node binary; see the
    /// `canonicalize` map in the delivery report.
    #[test]
    fn canonicalize_matches_node() {
        let cases = [
            ("127.0.0.1", Some("127.0.0.1")),
            ("0.0.0.0", Some("0.0.0.0")),
            ("255.255.255.255", Some("255.255.255.255")),
            // A leading zero is refused, not read as octal.
            ("192.168.000.001", None),
            ("01.2.3.4", None),
            ("1.2.3.04", None),
            ("0x7f.0.0.1", None),
            ("1.2.3", None),
            ("1.2.3.4.5", None),
            ("not-an-ip", None),
            ("", None),
            // Surrounding whitespace is not trimmed.
            (" 1.2.3.4", None),
            ("1.2.3.4 ", None),
            ("::1", Some("::1")),
            ("::", Some("::")),
            ("2001:db8::1", Some("2001:db8::1")),
            (
                "2001:0DB8:0000:0000:0000:0000:0000:0001",
                Some("2001:db8::1"),
            ),
            ("0:0:0:0:0:0:0:0", Some("::")),
            ("1:2:3:4:5:6:7:8", Some("1:2:3:4:5:6:7:8")),
            ("1:2:3:4:5:6:7:8:9", None),
            ("12345::", None),
            ("1::2", Some("1::2")),
            ("1::2::3", None),
            (":::1", None),
            // The scope id is stripped before parsing.
            ("fe80::1%eth0", Some("fe80::1")),
            ("FE80::1", Some("fe80::1")),
            // IPv4-embedded forms.
            ("::ffff:127.0.0.1", Some("::ffff:127.0.0.1")),
            ("::ffff:1.2.3.4", Some("::ffff:1.2.3.4")),
            ("::0.0.0.0", Some("::")),
            ("::1.2.3.4", Some("::1.2.3.4")),
            // No zero run, so the embedded quad stays in hex.
            ("1:2:3:4:5:6:1.2.3.4", Some("1:2:3:4:5:6:102:304")),
            ("2001:db8:0:0:1:0:0:1", Some("2001:db8::1:0:0:1")),
            // The first longest zero run wins.
            ("2001:DB8::0:1:0:0:1", Some("2001:db8::1:0:0:1")),
        ];
        for (input, expected) in cases {
            assert_eq!(
                canonical(input).as_deref(),
                expected,
                "canonicalizeIP({input:?})"
            );
        }
    }

    #[test]
    fn convert_ipv6_yields_sixteen_bytes() {
        // `convertIpv6StringToBuffer` only ever parses AF_INET6, so an IPv4
        // literal is an error even though `canonicalizeIP` accepts it.
        let cases = [
            ("::1", "00000000000000000000000000000001"),
            ("::", "00000000000000000000000000000000"),
            ("2001:db8::1", "20010db8000000000000000000000001"),
            ("::ffff:127.0.0.1", "00000000000000000000ffff7f000001"),
            ("fe80::1%eth0", "fe800000000000000000000000000001"),
            (
                "2001:0DB8:0000:0000:0000:0000:0000:0001",
                "20010db8000000000000000000000001",
            ),
        ];
        for (input, expected) in cases {
            let address = pton(Family::V6, input).expect("valid ipv6");
            let hex: String = address
                .bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(hex, expected, "convertIpv6StringToBuffer({input:?})");
        }
        for input in ["not-an-ip", "1.2.3.4", ""] {
            assert!(
                pton(Family::V6, input).is_none(),
                "convertIpv6StringToBuffer({input:?}) must fail"
            );
        }
    }

    #[test]
    fn ipv4_parsing_accepts_the_full_range() {
        for octet in [0u8, 1, 9, 10, 99, 100, 127, 200, 255] {
            let text = format!("10.0.{octet}.1");
            let address = pton(Family::V4, &text).expect("valid ipv4");
            assert_eq!(ntop(&address), text);
        }
        assert!(pton(Family::V4, "256.0.0.1").is_none());
        assert!(pton(Family::V4, "1.2.3.4.").is_none());
    }
}

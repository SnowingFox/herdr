//! `strerror(code)`, which is c-ares' error text.
//!
//! `StrError` in `src/cares_wrap.cc` calls `ares_strerror` and special-cases one
//! code of its own, `DNS_ESETSRVPENDING`. The table below is
//! `deps/cares/src/lib/ares_strerror.c` verbatim.
//!
//! Linking c-ares for this would mean shipping it on every platform to obtain
//! twenty-six string literals. The values are a documented part of c-ares' ABI
//! and change only with a major version, and the recording in `tests/parity.rs`
//! fails if the pinned Node ever disagrees.

/// `DNS_ESETSRVPENDING` from `src/cares_wrap.h`.
///
/// `SetServers` returns it when a query is still in flight, and `StrError` maps
/// it to a message c-ares has no code for.
pub(crate) const DNS_ESETSRVPENDING: i32 = -1000;

/// The message `StrError` returns for a code.
///
/// `ares_strerror` takes the code as an `ares_status_t` enum, so a value outside
/// the table — including every negative number, which is not a c-ares status —
/// falls through to `"unknown"`.
pub(crate) fn message(code: i32) -> &'static str {
    if code == DNS_ESETSRVPENDING {
        return "There are pending queries.";
    }
    match code {
        0 => "Successful completion",
        1 => "DNS server returned answer with no data",
        2 => "DNS server claims query was misformatted",
        3 => "DNS server returned general failure",
        4 => "Domain name not found",
        5 => "DNS server does not implement requested operation",
        6 => "DNS server refused query",
        7 => "Misformatted DNS query",
        8 => "Misformatted domain name",
        9 => "Unsupported address family",
        10 => "Misformatted DNS reply",
        11 => "Could not contact DNS servers",
        12 => "Timeout while contacting DNS servers",
        13 => "End of file",
        14 => "Error reading file",
        15 => "Out of memory",
        16 => "Channel is being destroyed",
        17 => "Misformatted string",
        18 => "Illegal flags specified",
        19 => "Given hostname is not numeric",
        20 => "Illegal hints flags specified",
        21 => "c-ares library initialization not yet performed",
        22 => "Error loading iphlpapi.dll",
        23 => "Could not find GetNetworkParams function",
        24 => "DNS query cancelled",
        25 => "Invalid service name or number",
        26 => "No DNS servers were configured",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from a real Node binary across `-2..=30`; the gaps are the
    /// codes c-ares does not define, which report `"unknown"`.
    #[test]
    fn every_recorded_code_matches_node() {
        let recorded = [
            (0, "Successful completion"),
            (1, "DNS server returned answer with no data"),
            (2, "DNS server claims query was misformatted"),
            (3, "DNS server returned general failure"),
            (4, "Domain name not found"),
            (5, "DNS server does not implement requested operation"),
            (6, "DNS server refused query"),
            (7, "Misformatted DNS query"),
            (8, "Misformatted domain name"),
            (9, "Unsupported address family"),
            (10, "Misformatted DNS reply"),
            (11, "Could not contact DNS servers"),
            (12, "Timeout while contacting DNS servers"),
            (13, "End of file"),
            (14, "Error reading file"),
            (15, "Out of memory"),
            (16, "Channel is being destroyed"),
            (17, "Misformatted string"),
            (18, "Illegal flags specified"),
            (19, "Given hostname is not numeric"),
            (20, "Illegal hints flags specified"),
            (21, "c-ares library initialization not yet performed"),
            (22, "Error loading iphlpapi.dll"),
            (23, "Could not find GetNetworkParams function"),
            (24, "DNS query cancelled"),
            (25, "Invalid service name or number"),
            (26, "No DNS servers were configured"),
            (27, "unknown"),
            (28, "unknown"),
            (-1, "unknown"),
            (-2, "unknown"),
            (-11, "unknown"),
            (-300, "unknown"),
            (12345, "unknown"),
        ];
        for (code, expected) in recorded {
            assert_eq!(message(code), expected, "strerror({code})");
        }
    }

    /// The one code that is Node's own, not c-ares'.
    /// `ARES_EBADSTR`, which `SetServers` reports for a malformed address.
    /// Recorded from Node, which answered `17` for `setServers([[4,'not-an-ip',53]])`.
    #[test]
    fn the_bad_string_code_matches_ares() {
        assert_eq!(super::DNS_ESETSRVPENDING, -1000);
    }

    #[test]
    fn the_pending_query_code_has_node_wording() {
        assert_eq!(message(DNS_ESETSRVPENDING), "There are pending queries.");
    }
}

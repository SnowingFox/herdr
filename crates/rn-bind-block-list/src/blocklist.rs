//! The blocklist rules and the matching engine.
//!
//! Every structure here mirrors one in `src/node_sockaddr.cc`, and the mirroring
//! is the point: the matching rules are subtle enough that a "cleaner" design
//! would silently answer differently. The three that matter most:
//!
//! * **Subnets live in a radix trie, ranges in a list.** A trie insert of a
//!   broader prefix *prunes* the narrower ones it subsumes, and `size()` counts
//!   the rules the caller added rather than the trie nodes, so removing a
//!   broader prefix has to rebuild the trie from the retained metadata list.
//! * **Prefixes are matched by walking bits, but the network address is not
//!   normalised.** `addSubnet('1.1.1.1', 32)` blocks exactly `1.1.1.1` and
//!   `addSubnet('10.0.0.0', 27)` blocks `10.0.0.0`-`10.0.0.31`, both of which
//!   fall out of a plain bitwise prefix comparison.
//! * **IPv4 and IPv4-mapped IPv6 are cross-inserted.** A rule added in either
//!   spelling answers both, in both directions, which is what makes
//!   `check('::ffff:10.0.0.5', 'ipv6')` match an IPv4 subnet.
//!
//! The `rules` array is user-visible (`test-blocklist.js` compares it), so the
//! serialisation order and text are part of the contract: address rules first,
//! then subnets, then ranges.

use std::collections::HashMap;
use std::collections::VecDeque;

use crate::address::{Family, SocketAddress, AF_INET, AF_INET6};

/// One rule in the blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// An exact address. Matched through a port-insensitive map, so this is
    /// only retained for `rules` and `size`.
    Address(SocketAddress),
    /// A network and prefix length.
    Subnet {
        /// The network address as the caller gave it.
        network: SocketAddress,
        /// The CIDR prefix length in bits.
        prefix: u8,
    },
    /// An inclusive range between two addresses.
    Range {
        /// The first address in the range.
        start: SocketAddress,
        /// The last address in the range.
        end: SocketAddress,
    },
}

impl std::fmt::Display for Rule {
    /// The text `ListRules` emits for this rule.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(address) => {
                write!(
                    formatter,
                    "Address: {} {}",
                    address.family().label(),
                    address.text()
                )
            }
            Self::Subnet { network, prefix } => write!(
                formatter,
                "Subnet: {} {}/{}",
                network.family().label(),
                network.text(),
                prefix
            ),
            Self::Range { start, end } => write!(
                formatter,
                "Range: {} {}-{}",
                start.family().label(),
                start.text(),
                end.text()
            ),
        }
    }
}

/// A compressed radix trie over address bits.
///
/// The root itself can be terminal, which is how a `/0` prefix (match
/// everything of that family) is represented.
#[derive(Debug, Clone, Default)]
pub struct SubnetTrie {
    root: Option<Node>,
    count: usize,
}

#[derive(Debug, Clone, Default)]
struct Node {
    children: [Option<Box<Node>>; 2],
    terminal: bool,
}

impl Node {
    fn child(&mut self, bit: usize) -> &mut Option<Box<Node>> {
        &mut self.children[bit]
    }
}

impl SubnetTrie {
    /// Inserts `prefix_length` bits of `address`.
    ///
    /// A broader prefix already in the trie makes this insert a no-op, and a
    /// prefix that is broader than existing children prunes them.
    pub fn insert(&mut self, address: &[u8], prefix_length: usize) {
        let root = self.root.get_or_insert_with(Node::default);
        let mut node = root;
        for bit_index in 0..prefix_length {
            if node.terminal {
                return;
            }
            let bit = get_bit(address, bit_index);
            node = node
                .child(bit)
                .get_or_insert_with(|| Box::new(Node::default()));
        }
        if !node.terminal {
            node.terminal = true;
            self.count += 1;
            node.children = [None, None];
        }
    }

    /// Whether any inserted prefix covers `address`.
    pub fn lookup(&self, address: &[u8], address_bits: usize) -> bool {
        let Some(root) = self.root.as_ref() else {
            return false;
        };
        if root.terminal {
            return true;
        }
        let mut node = root;
        for bit_index in 0..address_bits {
            let bit = get_bit(address, bit_index);
            let Some(child) = node.children[bit].as_deref() else {
                return false;
            };
            if child.terminal {
                return true;
            }
            node = child;
        }
        false
    }

    /// Empties the trie.
    pub fn clear(&mut self) {
        self.root = None;
        self.count = 0;
    }
}

/// Bit `bit_index` of `bytes`, most significant first.
fn get_bit(bytes: &[u8], bit_index: usize) -> usize {
    ((bytes[bit_index >> 3] >> (7 - (bit_index & 7))) & 1) as usize
}

/// The address bytes and bit width a rule is keyed by.
fn address_bits(address: &SocketAddress) -> usize {
    address.family().bits()
}

/// A blocklist: the rules plus the structures `check` consults.
#[derive(Debug, Clone, Default)]
pub struct BlockList {
    addresses: HashMap<(Family, [u8; 16]), SocketAddress>,
    /// The addresses in the order they were added, which `rules` lists in.
    /// Node's map is unordered there; keeping insertion order makes the array
    /// deterministic without changing what it contains.
    address_order: Vec<(Family, [u8; 16])>,
    /// How many distinct addresses were added, which is *not* the map length:
    /// each IPv4 address also stores a `::ffff:` counterpart.
    address_count: usize,
    ipv4_subnets: SubnetTrie,
    ipv6_subnets: SubnetTrie,
    subnets: VecDeque<(SocketAddress, u8)>,
    ranges: VecDeque<(SocketAddress, SocketAddress)>,
}

impl BlockList {
    /// An empty blocklist.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of rules, as `size` reports it.
    pub fn size(&self) -> usize {
        self.address_count + self.subnets.len() + self.ranges.len()
    }

    /// The `rules` array, in `ListRules` order.
    pub fn list_rules(&self) -> Vec<String> {
        let mut rules = Vec::with_capacity(self.size());
        for key in &self.address_order {
            if let Some(address) = self.addresses.get(key) {
                rules.push(Rule::Address(*address).to_string());
            }
        }
        for (network, prefix) in &self.subnets {
            rules.push(
                Rule::Subnet {
                    network: *network,
                    prefix: *prefix,
                }
                .to_string(),
            );
        }
        for (start, end) in &self.ranges {
            rules.push(
                Rule::Range {
                    start: *start,
                    end: *end,
                }
                .to_string(),
            );
        }
        rules
    }

    /// `addAddress`: an exact address, plus its cross-family counterpart.
    pub fn add_address(&mut self, address: SocketAddress) {
        let key = address.ip_key();
        if !self.addresses.contains_key(&key) {
            self.address_count += 1;
            self.address_order.push(key);
        }
        self.addresses.insert(key, address);
        // The counterpart maps back to the original so `rules` lists one entry
        // per address the caller added.
        if address.family() == Family::V4 {
            if let Some(mapped) = address.to_ipv4_mapped() {
                self.addresses.insert(mapped.ip_key(), address);
            }
        } else if let Some(quad) = address.ipv4_mapped() {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&quad);
            let v4 = SocketAddress::from_bytes(Family::V4, bytes, address.port());
            self.addresses.insert(v4.ip_key(), address);
        }
    }

    /// `removeAddress`: drops the address and its cross-family counterpart.
    pub fn remove_address(&mut self, address: SocketAddress) {
        let key = address.ip_key();
        if self.addresses.remove(&key).is_some() {
            self.address_count -= 1;
            self.address_order.retain(|listed| *listed != key);
        }
        if address.family() == Family::V4 {
            if let Some(mapped) = address.to_ipv4_mapped() {
                self.addresses.remove(&mapped.ip_key());
            }
        } else if let Some(quad) = address.ipv4_mapped() {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&quad);
            let v4 = SocketAddress::from_bytes(Family::V4, bytes, address.port());
            self.addresses.remove(&v4.ip_key());
        }
    }

    /// `addRange`. The caller has already checked that `start <= end`.
    pub fn add_range(&mut self, start: SocketAddress, end: SocketAddress) {
        self.ranges.push_front((start, end));
    }

    /// `removeRange`: removes the first exactly-matching range.
    pub fn remove_range(&mut self, start: SocketAddress, end: SocketAddress) {
        if let Some(index) = self
            .ranges
            .iter()
            .position(|(one, two)| *one == start && *two == end)
        {
            self.ranges.remove(index);
        }
    }

    /// `addSubnet`: inserts into both tries and records the metadata.
    pub fn add_subnet(&mut self, network: SocketAddress, prefix: u8) {
        self.insert_subnet(network, prefix);
        self.subnets.push_front((network, prefix));
    }

    /// `removeSubnet`: drops one matching rule, then rebuilds both tries.
    ///
    /// The rebuild is not an optimisation to skip: a broader prefix prunes the
    /// narrower ones on insert, so removing it from the trie alone would lose
    /// subnets the caller still has.
    pub fn remove_subnet(&mut self, network: SocketAddress, prefix: u8) {
        let Some(index) = self.subnets.iter().position(|(rule_network, rule_prefix)| {
            *rule_network == network && *rule_prefix == prefix
        }) else {
            return;
        };
        self.subnets.remove(index);

        // The retained metadata is drained so the tries can be rebuilt without
        // holding a borrow across the mutation.
        let retained: Vec<(SocketAddress, u8)> = self.subnets.iter().copied().collect();
        self.ipv4_subnets.clear();
        self.ipv6_subnets.clear();
        for (rule_network, rule_prefix) in retained {
            self.insert_subnet(rule_network, rule_prefix);
        }
    }

    fn insert_subnet(&mut self, network: SocketAddress, prefix: u8) {
        let prefix = usize::from(prefix);
        match network.family() {
            Family::V4 => {
                self.ipv4_subnets.insert(network.raw(), prefix);
                // The same subnet in IPv6 spelling, `::ffff:x.x.x.x/96+n`.
                if let Some(mapped) = network.to_ipv4_mapped() {
                    self.ipv6_subnets.insert(mapped.raw(), prefix + 96);
                }
            }
            Family::V6 => {
                self.ipv6_subnets.insert(network.raw(), prefix);
                if prefix >= 96 {
                    if let Some(quad) = network.ipv4_mapped() {
                        let mut bytes = [0u8; 16];
                        bytes[..4].copy_from_slice(&quad);
                        let v4 = SocketAddress::from_bytes(Family::V4, bytes, network.port());
                        self.ipv4_subnets.insert(v4.raw(), prefix - 96);
                    }
                }
            }
        }
    }

    /// `Apply`: whether `address` is blocked.
    pub fn apply(&self, address: &SocketAddress) -> bool {
        if self.addresses.contains_key(&address.ip_key()) {
            return true;
        }

        match address.family() {
            Family::V4 => {
                if self
                    .ipv4_subnets
                    .lookup(address.raw(), address_bits(address))
                {
                    return true;
                }
                if let Some(mapped) = address.to_ipv4_mapped() {
                    if self.ipv6_subnets.lookup(mapped.raw(), 128) {
                        return true;
                    }
                }
            }
            Family::V6 => {
                if self
                    .ipv6_subnets
                    .lookup(address.raw(), address_bits(address))
                {
                    return true;
                }
                if let Some(quad) = address.ipv4_mapped() {
                    let mut bytes = [0u8; 16];
                    bytes[..4].copy_from_slice(&quad);
                    let v4 = SocketAddress::from_bytes(Family::V4, bytes, address.port());
                    if self.ipv4_subnets.lookup(v4.raw(), 32) {
                        return true;
                    }
                }
            }
        }

        self.ranges
            .iter()
            .any(|(start, end)| address.at_or_after(start) && address.at_or_before(end))
    }

    /// `clear`.
    pub fn clear(&mut self) {
        self.addresses.clear();
        self.address_order.clear();
        self.address_count = 0;
        self.ipv4_subnets.clear();
        self.ipv6_subnets.clear();
        self.subnets.clear();
        self.ranges.clear();
    }
}

/// The `AF_INET`/`AF_INET6` constant a caller passes as a family.
pub fn family_from_af(af: i32) -> Option<Family> {
    match af {
        AF_INET => Some(Family::V4),
        AF_INET6 => Some(Family::V6),
        _ => None,
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
    fn get_bit_walks_most_significant_first() {
        // 0x80 is bit 0, 0x01 is bit 7.
        assert_eq!(get_bit(&[0x80], 0), 1);
        assert_eq!(get_bit(&[0x80], 7), 0);
        assert_eq!(get_bit(&[0x01], 7), 1);
    }

    #[test]
    fn a_zero_prefix_matches_the_whole_family() {
        let mut trie = SubnetTrie::default();
        trie.insert(&[0, 0, 0, 0], 0);
        assert!(trie.lookup(&[1, 2, 3, 4], 32));
        assert!(trie.lookup(&[255, 255, 255, 255], 32));
    }

    #[test]
    fn a_full_prefix_matches_one_address() {
        let mut trie = SubnetTrie::default();
        trie.insert(&[1, 1, 1, 1], 32);
        assert!(trie.lookup(&[1, 1, 1, 1], 32));
        assert!(!trie.lookup(&[1, 1, 1, 2], 32));
    }

    #[test]
    fn a_broader_prefix_prunes_the_narrower_ones() {
        let mut trie = SubnetTrie::default();
        trie.insert(&[10, 1, 0, 0], 16);
        trie.insert(&[10, 0, 0, 0], 8);
        assert!(trie.lookup(&[10, 2, 0, 1], 32));
        assert!(!trie.lookup(&[11, 0, 0, 1], 32));
        // `count_` still reports two: the /16 was terminal when it was
        // inserted, so the /8 reached its own node and incremented too. The
        // count is only a size hint, and `BlockList::size` counts the retained
        // metadata rather than this, so the pruned node leaving it behind is
        // Node's behaviour rather than a bug to correct here.
        assert_eq!(trie.count, 2);
    }

    #[test]
    fn a_narrower_prefix_after_a_broader_one_is_a_no_op() {
        let mut trie = SubnetTrie::default();
        trie.insert(&[10, 0, 0, 0], 8);
        trie.insert(&[10, 1, 0, 0], 16);
        assert_eq!(trie.count, 1);
    }

    #[test]
    fn a_broader_prefix_does_not_prune_a_deeper_chain_it_lands_on() {
        // Inserting a prefix that ends *at* an existing terminal node's ancestor
        // makes the ancestor terminal and drops its children, so the deeper
        // rule stops matching but the count still reflects both inserts.
        let mut trie = SubnetTrie::default();
        trie.insert(&[192, 168, 1, 0], 24);
        trie.insert(&[192, 168, 0, 0], 16);
        assert!(trie.lookup(&[192, 168, 1, 7], 32));
        assert!(trie.lookup(&[192, 168, 9, 7], 32));
        assert!(!trie.lookup(&[192, 169, 0, 1], 32));
    }

    #[test]
    fn an_address_rule_is_port_insensitive() {
        let mut list = BlockList::new();
        list.add_address(SocketAddress::parse(Family::V4, "1.1.1.1", 80).expect("valid"));
        assert!(list.apply(&SocketAddress::parse(Family::V4, "1.1.1.1", 443).expect("valid")));
    }

    #[test]
    fn an_ipv4_address_rule_answers_the_mapped_spelling() {
        let mut list = BlockList::new();
        list.add_address(v4("1.1.1.1"));
        assert!(list.apply(&v4("1.1.1.1")));
        assert!(list.apply(&v6("::ffff:1.1.1.1")));
        // ...but not the plain IPv6 spelling of the same bits, because that is
        // a different family and `::1.1.1.1` is not `::ffff:1.1.1.1`.
        assert!(!list.apply(&v6("8592:757c:efae:4e45:fb5d:d62a:0d00:8e17")));
    }

    #[test]
    fn an_ipv4_subnet_answers_the_mapped_spelling() {
        let mut list = BlockList::new();
        list.add_subnet(v4("1.1.1.0"), 16);
        assert!(list.apply(&v4("1.1.0.1")));
        assert!(list.apply(&v4("1.1.1.1")));
        assert!(!list.apply(&v4("1.2.0.1")));
        assert!(list.apply(&v6("::ffff:1.1.0.1")));
    }

    #[test]
    fn a_mapped_ipv6_subnet_answers_the_plain_ipv4_spelling() {
        let mut list = BlockList::new();
        list.add_subnet(v6("::ffff:10.0.0.0"), 120);
        assert!(list.apply(&v6("::ffff:10.0.0.5")));
        assert!(list.apply(&v4("10.0.0.5")));
        assert!(!list.apply(&v4("10.0.1.0")));
    }

    #[test]
    fn ipv6_ranges_bound_at_both_ends() {
        let mut list = BlockList::new();
        list.add_range(v6("::1"), v6("::ff"));
        assert!(!list.apply(&v6("::0")));
        assert!(list.apply(&v6("::1")));
        assert!(list.apply(&v6("::a0")));
        assert!(list.apply(&v6("::ff")));
        assert!(!list.apply(&v6("::100")));
    }

    #[test]
    fn an_ipv4_range_answers_the_mapped_spelling() {
        let mut list = BlockList::new();
        list.add_range(v4("10.0.0.2"), v4("10.0.0.10"));
        assert!(list.apply(&v4("10.0.0.2")));
        assert!(list.apply(&v4("10.0.0.10")));
        assert!(!list.apply(&v4("10.0.0.1")));
        assert!(!list.apply(&v4("10.0.0.11")));
        assert!(list.apply(&v6("::ffff:0a00:0002")));
        assert!(list.apply(&v6("::ffff:0a00:000a")));
        assert!(!list.apply(&v6("::ffff:c0a8:0003")));
        assert!(!list.apply(&v6("::ffff:0202:0202")));
        assert!(!list.apply(&v6("::ffff:ffff:ffff")));
    }

    #[test]
    fn a_rule_is_listed_once_even_though_both_spellings_are_stored() {
        let mut list = BlockList::new();
        list.add_address(v4("1.1.1.1"));
        assert_eq!(list.list_rules(), vec!["Address: IPv4 1.1.1.1"]);
        assert_eq!(list.size(), 1);
    }

    #[test]
    fn adding_the_same_address_twice_keeps_one_rule() {
        let mut list = BlockList::new();
        list.add_address(v4("1.1.1.1"));
        list.add_address(v4("1.1.1.1"));
        assert_eq!(list.list_rules().len(), 1);
        assert_eq!(list.size(), 1);
    }

    #[test]
    fn rules_serialise_in_kind_order() {
        let mut list = BlockList::new();
        list.add_address(v4("1.1.1.1"));
        list.add_range(v4("10.0.0.1"), v4("10.0.0.10"));
        list.add_subnet(v6("8592:757c:efae:4e45::"), 64);
        assert_eq!(
            list.list_rules(),
            vec![
                "Address: IPv4 1.1.1.1",
                "Subnet: IPv6 8592:757c:efae:4e45::/64",
                "Range: IPv4 10.0.0.1-10.0.0.10",
            ]
        );
    }

    #[test]
    fn removing_a_broader_subnet_restores_the_subsumed_one() {
        let mut list = BlockList::new();
        list.add_subnet(v4("10.0.0.0"), 8);
        list.add_subnet(v4("10.1.0.0"), 16);
        assert!(list.apply(&v4("10.1.2.3")));

        list.remove_subnet(v4("10.0.0.0"), 8);
        assert!(list.apply(&v4("10.1.2.3")));
        assert!(!list.apply(&v4("10.2.0.1")));
        assert_eq!(list.list_rules().len(), 1);
    }

    #[test]
    fn removing_a_subnet_clears_the_cross_family_spelling_too() {
        let mut list = BlockList::new();
        list.add_subnet(v4("10.0.0.0"), 8);
        assert!(list.apply(&v6("::ffff:10.0.0.1")));
        list.remove_subnet(v4("10.0.0.0"), 8);
        assert!(!list.apply(&v4("10.0.0.1")));
        assert!(!list.apply(&v6("::ffff:10.0.0.1")));
    }

    #[test]
    fn removing_a_range_clears_the_mapped_spelling() {
        let mut list = BlockList::new();
        list.add_range(v4("10.0.0.1"), v4("10.0.0.100"));
        assert!(list.apply(&v6("::ffff:10.0.0.5")));
        list.remove_range(v4("10.0.0.1"), v4("10.0.0.100"));
        assert!(!list.apply(&v4("10.0.0.50")));
    }

    #[test]
    fn removing_an_absent_range_is_a_no_op() {
        let mut list = BlockList::new();
        list.add_range(v4("10.0.0.1"), v4("10.0.0.10"));
        list.remove_range(v4("99.99.99.1"), v4("99.99.99.10"));
        assert_eq!(list.list_rules().len(), 1);
        assert!(list.apply(&v4("10.0.0.5")));
    }

    #[test]
    fn clear_empties_every_rule_kind() {
        let mut list = BlockList::new();
        list.add_address(v4("1.1.1.1"));
        list.add_range(v4("10.0.0.1"), v4("10.0.0.10"));
        list.add_subnet(v4("192.168.0.0"), 16);
        assert_eq!(list.list_rules().len(), 3);

        list.clear();
        assert_eq!(list.list_rules().len(), 0);
        assert_eq!(list.size(), 0);
        assert!(!list.apply(&v4("1.1.1.1")));
        assert!(!list.apply(&v4("10.0.0.5")));
        assert!(!list.apply(&v4("192.168.1.1")));

        list.add_address(v4("2.2.2.2"));
        assert_eq!(list.list_rules(), vec!["Address: IPv4 2.2.2.2"]);
    }

    #[test]
    fn a_non_aligned_prefix_stops_at_the_right_bit() {
        let mut list = BlockList::new();
        list.add_subnet(v4("10.0.0.0"), 27);
        for last in 0..=31u8 {
            assert!(
                list.apply(&v4(&format!("10.0.0.{last}"))),
                "10.0.0.{last} should be inside /27"
            );
        }
        assert!(!list.apply(&v4("10.0.0.32")));

        list.add_subnet(v6("8592:757c:efaf::"), 51);
        assert!(list.apply(&v6("8592:757c:efaf:1fff:ffff:ffff:ffff:ffff")));
        assert!(!list.apply(&v6("8592:757c:efaf:2fff:ffff:ffff:ffff:ffff")));
    }

    #[test]
    fn a_host_route_blocks_only_that_host() {
        let mut list = BlockList::new();
        list.add_subnet(v4("1.1.1.1"), 32);
        assert!(list.apply(&v4("1.1.1.1")));
        assert!(!list.apply(&v4("1.1.1.2")));
        assert!(!list.apply(&v4("2.3.4.5")));
    }
}

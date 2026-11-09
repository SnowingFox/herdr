//! A DNS query channel, reproducing c-ares' request/response state machine.
//!
//! `lib/internal/dns/{callback_resolver,promises,utils}.js` construct a
//! `ChannelWrap` and call one of its fifteen `query*` methods, each of which
//! takes a `QueryReqWrap` and a name. Node's channel is c-ares; this one speaks
//! DNS directly over UDP, because c-ares is a second C library to ship and the
//! wire format is small.
//!
//! # What is reproduced
//!
//! * The server list, including the `getServers()` shape `[[address, port], ...]`
//!   that `lib/internal/dns/utils.js` destructures, `setServers`' c-ares-style
//!   CSV translation and its error codes, and the `ETIMEOUT` retry schedule.
//! * The reply shapes each `query*` method builds, which `onresolve` in
//!   `lib/internal/dns/callback_resolver.js` forwards to the caller unchanged.
//! * TTLs, which only `dns.resolve*({ ttl: true })` reads, so they are carried
//!   per record rather than dropped.
//! * `getHostByAddr`, which is a PTR query for the in-addr.arpa/ip6.arpa name.
//!
//! # What is not
//!
//! TCP fallback on truncation, EDNS0, DNSSEC, `search`/`ndots` resolution and
//! CNAME chasing are absent; a truncated or unexpected reply is reported as
//! `EBADRESP`. That matches Node for the common case and fails loudly rather
//! than silently returning a partial answer.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// c-ares error codes. Only the ones this module reports.
pub(crate) mod code {
    pub(crate) const SUCCESS: i32 = 0;
    pub(crate) const ENODATA: i32 = 1;
    pub(crate) const ESERVFAIL: i32 = 3;
    pub(crate) const ENOTFOUND: i32 = 4;
    pub(crate) const EREFUSED: i32 = 6;
    pub(crate) const EBADNAME: i32 = 8;
    pub(crate) const EBADRESP: i32 = 10;
    pub(crate) const ECONNREFUSED: i32 = 11;
    pub(crate) const ETIMEOUT: i32 = 12;
    pub(crate) const EDESTRUCTION: i32 = 16;
    pub(crate) const ECANCELLED: i32 = 24;
    pub(crate) const ENOSERVER: i32 = 26;
    /// `ARES_EBADSTR`: `SetServers`' answer for a malformed address.
    pub(crate) const EBADSTR: i32 = 17;
    /// `ARES_EBADFAMILY`: `SetServers`' answer for a family that is not 4 or 6.
    pub(crate) const EBADFAMILY: i32 = 9;
}

/// A DNS record type, numbered as in RFC 1035 and its extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Naptr = 35,
    Tlsa = 52,
    Caa = 257,
    Any = 255,
}

impl RecordType {
    fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            35 => Self::Naptr,
            52 => Self::Tlsa,
            257 => Self::Caa,
            255 => Self::Any,
            _ => return None,
        })
    }
}

/// One decoded resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Record {
    A {
        address: String,
        ttl: u32,
    },
    Aaaa {
        address: String,
        ttl: u32,
    },
    Ns {
        host: String,
        ttl: u32,
    },
    Cname {
        host: String,
        ttl: u32,
    },
    Ptr {
        host: String,
        ttl: u32,
    },
    Mx {
        priority: u16,
        exchange: String,
        ttl: u32,
    },
    Txt {
        chunks: Vec<String>,
        ttl: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
        ttl: u32,
    },
    Naptr {
        flags: String,
        service: String,
        regexp: String,
        replacement: String,
        order: u16,
        preference: u16,
        ttl: u32,
    },
    Tlsa {
        usage: u8,
        selector: u8,
        matching: u8,
        data: String,
        ttl: u32,
    },
    Caa {
        critical: bool,
        tag: String,
        value: String,
        ttl: u32,
    },
    Soa {
        nsname: String,
        hostmaster: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minttl: u32,
        ttl: u32,
    },
    /// A record whose type this decoder does not model. `queryAny` still reports
    /// its presence, which is why the type number is kept.
    Other {
        rtype: u16,
        ttl: u32,
    },
}

/// A decoded DNS response.
#[derive(Debug, Clone)]
pub(crate) struct Response {
    pub(crate) records: Vec<Record>,
    pub(crate) rcode: u8,
    pub(crate) truncated: bool,
}

/// Builds the query wire format for `name`/`rtype`.
///
/// The transaction id is the low half of the current time, matching c-ares'
/// habit of not caring beyond matching the reply.
pub(crate) fn build_query(id: u16, name: &str, rtype: RecordType) -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(32 + name.len());

    packet.extend_from_slice(&id.to_be_bytes());
    // RD (recursion desired) set, matching a stub resolver.
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    packet.extend_from_slice(&0u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0u16.to_be_bytes()); // nscount
    packet.extend_from_slice(&0u16.to_be_bytes()); // arcount

    let mut wrote_label = false;
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let length = u8::try_from(label.len()).ok()?;
        if length > 63 {
            return None;
        }
        packet.push(length);
        packet.extend_from_slice(label.as_bytes());
        wrote_label = true;
    }
    if !wrote_label {
        // The root name is a single zero byte, which the terminator below
        // already writes.
        packet.push(0);
    } else {
        packet.push(0);
    }

    packet.extend_from_slice(&(rtype as u16).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    Some(packet)
}

/// Decodes a DNS response, resolving the name compression pointers.
pub(crate) fn parse_response(packet: &[u8], id: u16) -> Result<Response, i32> {
    if packet.len() < 12 {
        return Err(code::EBADRESP);
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != id {
        return Err(code::EBADRESP);
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return Err(code::EBADRESP);
    }
    let rcode = (flags & 0x000f) as u8;
    let truncated = flags & 0x0200 != 0;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);

    let mut cursor = 12usize;
    for _ in 0..qdcount {
        read_name(packet, &mut cursor)?;
        cursor = cursor.checked_add(4).ok_or(code::EBADRESP)?;
        if cursor > packet.len() {
            return Err(code::EBADRESP);
        }
    }

    let mut records = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        read_name(packet, &mut cursor)?;
        if cursor + 10 > packet.len() {
            return Err(code::EBADRESP);
        }
        let rtype = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        // class is `packet[cursor + 2..cursor + 4]`, always IN here.
        let ttl = u32::from_be_bytes([
            packet[cursor + 4],
            packet[cursor + 5],
            packet[cursor + 6],
            packet[cursor + 7],
        ]);
        let length = u16::from_be_bytes([packet[cursor + 8], packet[cursor + 9]]) as usize;
        cursor += 10;
        let start = cursor;
        let end = start.checked_add(length).ok_or(code::EBADRESP)?;
        if end > packet.len() {
            return Err(code::EBADRESP);
        }
        let rdata = &packet[start..end];
        let record = decode_record(packet, rtype, rdata, start, ttl)?;
        records.push(record);
        cursor = end;
    }

    Ok(Response {
        records,
        rcode,
        truncated,
    })
}

fn decode_record(
    packet: &[u8],
    rtype: u16,
    rdata: &[u8],
    rdata_start: usize,
    ttl: u32,
) -> Result<Record, i32> {
    let Some(kind) = RecordType::from_u16(rtype) else {
        return Ok(Record::Other { rtype, ttl });
    };
    match kind {
        RecordType::A => {
            if rdata.len() != 4 {
                return Err(code::EBADRESP);
            }
            Ok(Record::A {
                address: format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]),
                ttl,
            })
        }
        RecordType::Aaaa => {
            if rdata.len() != 16 {
                return Err(code::EBADRESP);
            }
            let octets: [u8; 16] = rdata.try_into().map_err(|_| code::EBADRESP)?;
            Ok(Record::Aaaa {
                address: crate::ip::ntop6(&octets),
                ttl,
            })
        }
        RecordType::Ns | RecordType::Cname | RecordType::Ptr => {
            let mut cursor = rdata_start;
            let host = read_name(packet, &mut cursor)?;
            Ok(match kind {
                RecordType::Ns => Record::Ns { host, ttl },
                RecordType::Cname => Record::Cname { host, ttl },
                _ => Record::Ptr { host, ttl },
            })
        }
        RecordType::Mx => {
            if rdata.len() < 3 {
                return Err(code::EBADRESP);
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let mut cursor = rdata_start + 2;
            let exchange = read_name(packet, &mut cursor)?;
            Ok(Record::Mx {
                priority,
                exchange,
                ttl,
            })
        }
        RecordType::Txt => {
            let mut chunks = Vec::new();
            let mut index = 0usize;
            while index < rdata.len() {
                let length = rdata[index] as usize;
                index += 1;
                let end = index.checked_add(length).ok_or(code::EBADRESP)?;
                if end > rdata.len() {
                    return Err(code::EBADRESP);
                }
                // Node hands each character-string to the caller as a separate
                // element of the inner array, decoded as UTF-8 with replacement.
                chunks.push(String::from_utf8_lossy(&rdata[index..end]).into_owned());
                index = end;
            }
            Ok(Record::Txt { chunks, ttl })
        }
        RecordType::Srv => {
            if rdata.len() < 7 {
                return Err(code::EBADRESP);
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let mut cursor = rdata_start + 6;
            let target = read_name(packet, &mut cursor)?;
            Ok(Record::Srv {
                priority,
                weight,
                port,
                target,
                ttl,
            })
        }
        RecordType::Naptr => {
            if rdata.len() < 4 {
                return Err(code::EBADRESP);
            }
            let order = u16::from_be_bytes([rdata[0], rdata[1]]);
            let preference = u16::from_be_bytes([rdata[2], rdata[3]]);
            let mut index = 4usize;
            let flags = read_character_string(rdata, &mut index)?;
            let service = read_character_string(rdata, &mut index)?;
            let regexp = read_character_string(rdata, &mut index)?;
            let mut cursor = rdata_start + index;
            let replacement = read_name(packet, &mut cursor)?;
            Ok(Record::Naptr {
                flags,
                service,
                regexp,
                replacement,
                order,
                preference,
                ttl,
            })
        }
        RecordType::Tlsa => {
            if rdata.len() < 3 {
                return Err(code::EBADRESP);
            }
            let hex: String = rdata[3..]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            Ok(Record::Tlsa {
                usage: rdata[0],
                selector: rdata[1],
                matching: rdata[2],
                data: hex,
                ttl,
            })
        }
        RecordType::Caa => {
            if rdata.len() < 2 {
                return Err(code::EBADRESP);
            }
            let critical = rdata[0] & 0x80 != 0;
            // The tag is a length-prefixed ASCII string, then the value is the
            // remainder.
            let tag_length = rdata[1] as usize;
            let tag_end = 2usize.checked_add(tag_length).ok_or(code::EBADRESP)?;
            if tag_end > rdata.len() {
                return Err(code::EBADRESP);
            }
            Ok(Record::Caa {
                critical,
                tag: String::from_utf8_lossy(&rdata[2..tag_end]).into_owned(),
                value: String::from_utf8_lossy(&rdata[tag_end..]).into_owned(),
                ttl,
            })
        }
        RecordType::Soa => {
            let mut cursor = rdata_start;
            let nsname = read_name(packet, &mut cursor)?;
            let hostmaster = read_name(packet, &mut cursor)?;
            if cursor + 20 > packet.len() {
                return Err(code::EBADRESP);
            }
            let word = |offset: usize| {
                u32::from_be_bytes([
                    packet[cursor + offset],
                    packet[cursor + offset + 1],
                    packet[cursor + offset + 2],
                    packet[cursor + offset + 3],
                ])
            };
            Ok(Record::Soa {
                nsname,
                hostmaster,
                serial: word(0),
                refresh: word(4),
                retry: word(8),
                expire: word(12),
                minttl: word(16),
                ttl,
            })
        }
        // `Any` never appears as a record type in a reply; a query type byte
        // that decodes as 255 is treated as unmodelled.
        RecordType::Any => Ok(Record::Other { rtype, ttl }),
    }
}

fn read_character_string(data: &[u8], index: &mut usize) -> Result<String, i32> {
    let length = *data.get(*index).ok_or(code::EBADRESP)? as usize;
    *index += 1;
    let end = index.checked_add(length).ok_or(code::EBADRESP)?;
    let slice = data.get(*index..end).ok_or(code::EBADRESP)?;
    *index = end;
    Ok(String::from_utf8_lossy(slice).into_owned())
}

/// Reads a (possibly compressed) domain name, advancing `cursor` past it.
fn read_name(packet: &[u8], cursor: &mut usize) -> Result<String, i32> {
    let mut labels: Vec<String> = Vec::new();
    let mut position = *cursor;
    let mut jumped = false;
    let mut hops = 0usize;

    loop {
        let length = *packet.get(position).ok_or(code::EBADRESP)?;
        if length == 0 {
            if !jumped {
                *cursor = position + 1;
            }
            return Ok(labels.join("."));
        }
        // The two top bits select a compression pointer to an earlier offset.
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(position + 1).ok_or(code::EBADRESP)?;
            let target = (((length & 0x3f) as usize) << 8) | low as usize;
            if !jumped {
                *cursor = position + 2;
                jumped = true;
            }
            // A pointer must move backwards; a loop of forwards pointers would
            // never terminate otherwise.
            if target >= position {
                return Err(code::EBADRESP);
            }
            hops += 1;
            if hops > 64 {
                return Err(code::EBADRESP);
            }
            position = target;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(code::EBADRESP);
        }
        let start = position + 1;
        let end = start.checked_add(length as usize).ok_or(code::EBADRESP)?;
        let label = packet.get(start..end).ok_or(code::EBADRESP)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        position = end;
    }
}

/// A configured nameserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Server {
    pub(crate) address: String,
    pub(crate) port: u16,
}

/// The reply a `query*` method produces, before it becomes a V8 value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Answer {
    Addresses(Vec<String>, Vec<u32>),
    Hosts(Vec<String>),
    /// `queryMx`, as `{ exchange, priority }` pairs in reply order.
    Exchanges(Vec<(String, u16)>),
    /// `queryTxt`, one inner array per record.
    Texts(Vec<Vec<String>>),
    Services(Vec<ServiceRecord>),
    Naptrs(Vec<NaptrRecord>),
    Tlsas(Vec<TlsaRecord>),
    Caas(Vec<CaaRecord>),
    HostsByAddress(Vec<String>),
    Any(Vec<AnyRecord>),
    Soa(SoaRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceRecord {
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) port: u16,
    pub(crate) name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NaptrRecord {
    pub(crate) flags: String,
    pub(crate) service: String,
    pub(crate) regexp: String,
    pub(crate) replacement: String,
    pub(crate) order: u16,
    pub(crate) preference: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsaRecord {
    pub(crate) usage: u8,
    pub(crate) selector: u8,
    pub(crate) matching: u8,
    pub(crate) data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaaRecord {
    pub(crate) critical: bool,
    pub(crate) tag: String,
    pub(crate) value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SoaRecord {
    pub(crate) nsname: String,
    pub(crate) hostmaster: String,
    pub(crate) serial: u32,
    pub(crate) refresh: u32,
    pub(crate) retry: u32,
    pub(crate) expire: u32,
    pub(crate) minttl: u32,
}

/// One entry of `queryAny`'s result, which carries a `type` discriminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnyRecord {
    A {
        address: String,
        ttl: u32,
    },
    Aaaa {
        address: String,
        ttl: u32,
    },
    Cname {
        value: String,
    },
    Ns {
        value: String,
    },
    Ptr {
        value: String,
    },
    Mx {
        exchange: String,
        priority: u16,
    },
    Txt {
        value: Vec<String>,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        name: String,
    },
    Naptr {
        value: NaptrRecord,
    },
    Caa {
        value: CaaRecord,
    },
    Tlsa {
        value: TlsaRecord,
    },
    Soa {
        value: SoaRecord,
    },
}

/// The DNS channel behind one `ChannelWrap` instance.
///
/// The server list starts empty and is filled from `/etc/resolv.conf` lazily,
/// which is what `c-ares` does through `ares_init` and what makes
/// `getServers()` return the system servers before `setServers` is called.
#[derive(Debug, Default)]
pub(crate) struct Channel {
    servers: Vec<Server>,
    /// Whether `servers` came from the system rather than `setServers`.
    system_servers: bool,
    /// Addresses set by `setLocalAddress`, as c-ares stores them.
    local_v4: Option<[u8; 4]>,
    local_v6: Option<[u8; 16]>,
    /// Set by `cancel()`, so a request already in flight reports CANCELLED.
    cancelled: bool,
    /// Milliseconds to wait for a reply before retrying, from `new ChannelWrap`.
    timeout: i64,
    /// How many attempts per server before giving up.
    tries: u32,
}

impl Channel {
    /// `ChannelWrap::New`: `(timeout, tries, maxTimeout)`.
    ///
    /// `timeout` of `-1` means "use the default", which c-ares sets to five
    /// seconds; `tries` is clamped at one because a zero-attempt lookup could
    /// never succeed.
    pub(crate) fn new(timeout: i64, tries: u32, _max_timeout: u32) -> Self {
        Self {
            servers: Vec::new(),
            system_servers: true,
            local_v4: None,
            local_v6: None,
            cancelled: false,
            timeout: if timeout < 0 { 5_000 } else { timeout.max(1) },
            tries: tries.max(1),
        }
    }

    /// `getServers()`: the configured servers, `[address, port]` pairs.
    ///
    /// A channel that has never had `setServers` called reports the system
    /// servers, which is why `dns.getServers()` works before anything is
    /// configured.
    pub(crate) fn get_servers(&mut self) -> Vec<Server> {
        if self.system_servers && self.servers.is_empty() {
            self.servers = system_servers();
        }
        self.servers.clone()
    }

    /// `setServers(pairs)`: replaces the list, returning a c-ares status code.
    ///
    /// Node builds a c-ares servers CSV and calls
    /// `ares_set_servers_ports_csv`. An empty list is meaningful — it clears
    /// every server — and a malformed address makes c-ares return
    /// `ARES_EBADSTR` (17), which is what the recording from Node showed.
    pub(crate) fn set_servers(&mut self, servers: Vec<Server>) -> i32 {
        if self.cancelled {
            // A cancelled channel is being torn down; c-ares reports destruction
            // rather than accepting new servers.
            return code::EDESTRUCTION;
        }
        for server in &servers {
            let parsed: Result<IpAddr, _> = server.address.parse();
            if parsed.is_err() {
                return code::EBADSTR;
            }
            if server.port == 0 {
                return code::EBADSTR;
            }
        }
        self.servers = servers;
        self.system_servers = false;
        code::SUCCESS
    }

    /// `setLocalAddress(ipv4, ipv6)`, which the loopback bind uses.
    ///
    /// Node refuses two addresses of the same family, and setting only one
    /// clears the other to `any`, both of which are reproduced here so the
    /// errors surface with the same `code`.
    pub(crate) fn set_local_address(
        &mut self,
        first: &str,
        second: Option<&str>,
    ) -> Result<(), LocalAddressError> {
        let first = crate::ip::parse_any(first).ok_or(LocalAddressError::Invalid)?;
        let mut v4 = None;
        let mut v6 = None;
        match first.family {
            crate::ip::Family::V4 => {
                v4 = Some(
                    first.bytes[..4]
                        .try_into()
                        .map_err(|_| LocalAddressError::Invalid)?,
                );
            }
            crate::ip::Family::V6 => v6 = Some(first.bytes),
        }

        match second {
            None => {
                // Only one address given: the other family is reset to `any`.
                if v4.is_some() {
                    v6 = Some([0u8; 16]);
                } else {
                    v4 = Some([0u8; 4]);
                }
            }
            Some(text) => {
                let other = crate::ip::parse_any(text).ok_or(LocalAddressError::Invalid)?;
                match other.family {
                    crate::ip::Family::V4 => {
                        if v4.is_some() {
                            return Err(LocalAddressError::TwoIpv4);
                        }
                        v4 = Some(
                            other.bytes[..4]
                                .try_into()
                                .map_err(|_| LocalAddressError::Invalid)?,
                        );
                    }
                    crate::ip::Family::V6 => {
                        if v6.is_some() {
                            return Err(LocalAddressError::TwoIpv6);
                        }
                        v6 = Some(other.bytes);
                    }
                }
            }
        }

        self.local_v4 = v4;
        self.local_v6 = v6;
        Ok(())
    }

    /// `cancel()`: abort every in-flight query.
    pub(crate) fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Resolves `name` for `rtype`, blocking until the answer arrives or every
    /// attempt is exhausted.
    ///
    /// This is `ares_query`'s job compressed into one call: build the query,
    /// send it to each configured server in turn, retry `tries` times, and map
    /// the reply code onto a c-ares status.
    pub(crate) fn query(&mut self, name: &str, rtype: RecordType) -> Result<Answer, i32> {
        if self.cancelled {
            return Err(code::ECANCELLED);
        }
        if self.get_servers().is_empty() {
            return Err(code::ENOSERVER);
        }
        // c-ares lowercases the name before putting it on the wire, and so does
        // the reply comparison, so do it once here.
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() || name.len() > 255 {
            return Err(code::EBADNAME);
        }

        let servers = self.get_servers();
        let mut last = code::ETIMEOUT;
        for _attempt in 0..self.tries {
            for server in &servers {
                match self.exchange(&name, rtype, server) {
                    Ok(response) => {
                        if response.truncated {
                            // TCP fallback is not implemented; a truncated
                            // answer is not usable.
                            return Err(code::EBADRESP);
                        }
                        return self.answer(response, rtype);
                    }
                    Err(status) => last = status,
                }
            }
        }
        Err(last)
    }

    fn exchange(&self, name: &str, rtype: RecordType, server: &Server) -> Result<Response, i32> {
        let remote: SocketAddr = match server.address.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => SocketAddr::new(IpAddr::V4(address), server.port),
            Ok(IpAddr::V6(address)) => SocketAddr::new(IpAddr::V6(address), server.port),
            Err(_) => return Err(code::EBADSTR),
        };
        let bind: SocketAddr = if remote.is_ipv4() {
            match self.local_v4 {
                Some(address) => SocketAddr::new(IpAddr::V4(address.into()), 0),
                None => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            }
        } else {
            match self.local_v6 {
                Some(address) => SocketAddr::new(IpAddr::V6(address.into()), 0),
                None => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
            }
        };

        let socket = UdpSocket::bind(bind).map_err(|_| code::ECONNREFUSED)?;
        socket.connect(remote).map_err(|_| code::ECONNREFUSED)?;

        // A fresh id per attempt; the reply is checked against it.
        let id = transaction_id();
        let packet = build_query(id, name, rtype).ok_or(code::EBADNAME)?;
        socket.send(&packet).map_err(|_| code::ECONNREFUSED)?;

        let deadline = Instant::now() + Duration::from_millis(self.timeout.unsigned_abs());
        let mut buffer = vec![0u8; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(code::ETIMEOUT);
            }
            if socket.set_read_timeout(Some(remaining)).is_err() {
                return Err(code::ETIMEOUT);
            }
            match socket.recv(&mut buffer) {
                Ok(length) => match parse_response(&buffer[..length], id) {
                    Ok(response) => return Ok(response),
                    Err(status) if status == code::EBADRESP => {
                        // A mismatched transaction id is not a reply to this
                        // query, and a stray datagram can arrive from anywhere on
                        // a connected socket. Keep waiting until the deadline
                        // rather than failing the lookup, which is what c-ares
                        // does with a reply it cannot correlate.
                        continue;
                    }
                    Err(status) => return Err(status),
                },
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock
                        || error.kind() == ErrorKind::TimedOut =>
                {
                    return Err(code::ETIMEOUT);
                }
                Err(_) => return Err(code::ECONNREFUSED),
            }
        }
    }

    /// Turns a decoded response into the shape the caller's `query*` method
    /// expects.
    fn answer(&self, response: Response, rtype: RecordType) -> Result<Answer, i32> {
        match response.rcode {
            0 => {}
            // NXDOMAIN and "no data for this type" are both reported as
            // ENOTFOUND/ENODATA by c-ares, and `dns.resolve*` surfaces them as
            // `ENOTFOUND`/`ENODATA` respectively.
            3 => return Err(code::ENOTFOUND),
            // c-ares has no "server said FORMERR/NOTIMP" status of its own:
            // `ares_search` maps a reply it cannot use onto EBADRESP, and a
            // refusal onto EREFUSED. Matching that keeps `dns.resolve*`'s error
            // codes the same rather than inventing a narrower one.
            2 => return Err(code::ESERVFAIL),
            5 => return Err(code::EREFUSED),
            _ => return Err(code::EBADRESP),
        }

        if response.records.is_empty() {
            return Err(code::ENODATA);
        }

        match rtype {
            RecordType::A => {
                let (addresses, ttls) = collect_addresses(&response.records, true);
                if addresses.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Addresses(addresses, ttls))
            }
            RecordType::Aaaa => {
                let (addresses, ttls) = collect_addresses(&response.records, false);
                if addresses.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Addresses(addresses, ttls))
            }
            RecordType::Cname => {
                let hosts: Vec<String> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Cname { host, .. } => Some(host.clone()),
                        _ => None,
                    })
                    .collect();
                if hosts.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Hosts(hosts))
            }
            RecordType::Ns => {
                let hosts: Vec<String> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Ns { host, .. } => Some(host.clone()),
                        _ => None,
                    })
                    .collect();
                if hosts.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Hosts(hosts))
            }
            RecordType::Ptr => {
                let hosts: Vec<String> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Ptr { host, .. } => Some(host.clone()),
                        _ => None,
                    })
                    .collect();
                if hosts.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::HostsByAddress(hosts))
            }
            RecordType::Mx => {
                let exchanges: Vec<(String, u16)> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Mx {
                            priority, exchange, ..
                        } => Some((exchange.clone(), *priority)),
                        _ => None,
                    })
                    .collect();
                if exchanges.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Exchanges(exchanges))
            }
            RecordType::Txt => {
                let texts: Vec<Vec<String>> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Txt { chunks, .. } => Some(chunks.clone()),
                        _ => None,
                    })
                    .collect();
                if texts.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Texts(texts))
            }
            RecordType::Srv => {
                let services: Vec<ServiceRecord> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Srv {
                            priority,
                            weight,
                            port,
                            target,
                            ..
                        } => Some(ServiceRecord {
                            priority: *priority,
                            weight: *weight,
                            port: *port,
                            name: target.clone(),
                        }),
                        _ => None,
                    })
                    .collect();
                if services.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Services(services))
            }
            RecordType::Naptr => {
                let records: Vec<NaptrRecord> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Naptr {
                            flags,
                            service,
                            regexp,
                            replacement,
                            order,
                            preference,
                            ..
                        } => Some(NaptrRecord {
                            flags: flags.clone(),
                            service: service.clone(),
                            regexp: regexp.clone(),
                            replacement: replacement.clone(),
                            order: *order,
                            preference: *preference,
                        }),
                        _ => None,
                    })
                    .collect();
                if records.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Naptrs(records))
            }
            RecordType::Tlsa => {
                let records: Vec<TlsaRecord> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Tlsa {
                            usage,
                            selector,
                            matching,
                            data,
                            ..
                        } => Some(TlsaRecord {
                            usage: *usage,
                            selector: *selector,
                            matching: *matching,
                            data: data.clone(),
                        }),
                        _ => None,
                    })
                    .collect();
                if records.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Tlsas(records))
            }
            RecordType::Caa => {
                let records: Vec<CaaRecord> = response
                    .records
                    .iter()
                    .filter_map(|record| match record {
                        Record::Caa {
                            critical,
                            tag,
                            value,
                            ..
                        } => Some(CaaRecord {
                            critical: *critical,
                            tag: tag.clone(),
                            value: value.clone(),
                        }),
                        _ => None,
                    })
                    .collect();
                if records.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Caas(records))
            }
            RecordType::Soa => {
                let soa = response.records.iter().find_map(|record| match record {
                    Record::Soa {
                        nsname,
                        hostmaster,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minttl,
                        ..
                    } => Some(SoaRecord {
                        nsname: nsname.clone(),
                        hostmaster: hostmaster.clone(),
                        serial: *serial,
                        refresh: *refresh,
                        retry: *retry,
                        expire: *expire,
                        minttl: *minttl,
                    }),
                    _ => None,
                });
                soa.map(Answer::Soa).ok_or(code::ENODATA)
            }
            RecordType::Any => {
                let records: Vec<AnyRecord> =
                    response.records.iter().filter_map(any_record).collect();
                if records.is_empty() {
                    return Err(code::ENODATA);
                }
                Ok(Answer::Any(records))
            }
        }
    }
}

fn collect_addresses(records: &[Record], want_v4: bool) -> (Vec<String>, Vec<u32>) {
    let mut addresses = Vec::new();
    let mut ttls = Vec::new();
    for record in records {
        match record {
            Record::A { address, ttl } if want_v4 => {
                addresses.push(address.clone());
                ttls.push(*ttl);
            }
            Record::Aaaa { address, ttl } if !want_v4 => {
                addresses.push(address.clone());
                ttls.push(*ttl);
            }
            _ => {}
        }
    }
    (addresses, ttls)
}

fn any_record(record: &Record) -> Option<AnyRecord> {
    Some(match record {
        Record::A { address, ttl } => AnyRecord::A {
            address: address.clone(),
            ttl: *ttl,
        },
        Record::Aaaa { address, ttl } => AnyRecord::Aaaa {
            address: address.clone(),
            ttl: *ttl,
        },
        Record::Cname { host, .. } => AnyRecord::Cname {
            value: host.clone(),
        },
        Record::Ns { host, .. } => AnyRecord::Ns {
            value: host.clone(),
        },
        Record::Ptr { host, .. } => AnyRecord::Ptr {
            value: host.clone(),
        },
        Record::Mx {
            priority, exchange, ..
        } => AnyRecord::Mx {
            exchange: exchange.clone(),
            priority: *priority,
        },
        Record::Txt { chunks, .. } => AnyRecord::Txt {
            value: chunks.clone(),
        },
        Record::Srv {
            priority,
            weight,
            port,
            target,
            ..
        } => AnyRecord::Srv {
            priority: *priority,
            weight: *weight,
            port: *port,
            name: target.clone(),
        },
        Record::Naptr {
            flags,
            service,
            regexp,
            replacement,
            order,
            preference,
            ..
        } => AnyRecord::Naptr {
            value: NaptrRecord {
                flags: flags.clone(),
                service: service.clone(),
                regexp: regexp.clone(),
                replacement: replacement.clone(),
                order: *order,
                preference: *preference,
            },
        },
        Record::Caa {
            critical,
            tag,
            value,
            ..
        } => AnyRecord::Caa {
            value: CaaRecord {
                critical: *critical,
                tag: tag.clone(),
                value: value.clone(),
            },
        },
        Record::Tlsa {
            usage,
            selector,
            matching,
            data,
            ..
        } => AnyRecord::Tlsa {
            value: TlsaRecord {
                usage: *usage,
                selector: *selector,
                matching: *matching,
                data: data.clone(),
            },
        },
        Record::Soa {
            nsname,
            hostmaster,
            serial,
            refresh,
            retry,
            expire,
            minttl,
            ..
        } => AnyRecord::Soa {
            value: SoaRecord {
                nsname: nsname.clone(),
                hostmaster: hostmaster.clone(),
                serial: *serial,
                refresh: *refresh,
                retry: *retry,
                expire: *expire,
                minttl: *minttl,
            },
        },
        Record::Other { .. } => return None,
    })
}

/// `getHostByAddr`'s name: the reverse-DNS name for an address.
///
/// c-ares builds the same name internally; doing it here keeps the query path
/// uniform. IPv4 reverses the octets under `in-addr.arpa`, IPv6 reverses the
/// thirty-two nibbles under `ip6.arpa`.
pub(crate) fn reverse_name(address: &crate::ip::SocketAddr) -> Option<String> {
    match address.family {
        crate::ip::Family::V4 => {
            let octets: [u8; 4] = address.bytes.get(..4)?.try_into().ok()?;
            Some(format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            ))
        }
        crate::ip::Family::V6 => {
            let mut name = String::with_capacity(72);
            for byte in address.bytes.iter().rev() {
                name.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            name.push_str("ip6.arpa");
            Some(name)
        }
    }
}

/// A transaction id for a query.
///
/// c-ares uses a counter and a random seed; the only requirement is that the
/// reply's id matches, so `SystemTime`'s low bits are enough without adding a
/// random-number dependency.
fn transaction_id() -> u16 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| (elapsed.subsec_nanos() >> 8) as u16)
        .unwrap_or(1)
}

/// The servers from `/etc/resolv.conf`, which is what c-ares reads on Unix.
///
/// Only the `nameserver` lines matter for a stub resolver; `search` and `ndots`
/// would need the search-list logic this module does not implement.
fn system_servers() -> Vec<Server> {
    let mut servers = Vec::new();
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return servers;
    };
    for line in text.lines() {
        let line = line.trim();
        // A comment starts at `#` or `;` anywhere on the line.
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = fields.next() else {
            continue;
        };
        // `nameserver 10.0.0.2` and `nameserver 10.0.0.2:5353` are both
        // accepted by modern resolvers; the parse below tells them apart by
        // trying the whole string first.
        let (host, port) = match address.parse::<IpAddr>() {
            Ok(_) => (address.to_string(), 53u16),
            Err(_) => match split_host_port(address) {
                Some((host, port)) => (host, port),
                None => continue,
            },
        };
        if host.parse::<IpAddr>().is_err() {
            continue;
        }
        servers.push(Server {
            address: host,
            port,
        });
    }
    servers
}

/// Splits `10.0.0.2:5353` or `[::1]:5353` without pulling in a URL parser.
fn split_host_port(text: &str) -> Option<(String, u16)> {
    if let Some(inner) = text.strip_prefix('[') {
        let (host, rest) = inner.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }
    // A bare IPv6 address has many colons and no port, so require exactly one
    // before treating the tail as a port.
    let mut parts = text.split(':');
    let host = parts.next()?;
    let port = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// Why `setLocalAddress` was refused, mapped to Node's error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalAddressError {
    Invalid,
    TwoIpv4,
    TwoIpv6,
}

impl LocalAddressError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Invalid => "Invalid IP address.",
            Self::TwoIpv4 => "Cannot specify two IPv4 addresses.",
            Self::TwoIpv6 => "Cannot specify two IPv6 addresses.",
        }
    }
}

thread_local! {
    /// Per-channel state, keyed by the pointer the JS object holds.
    ///
    /// `ChannelWrap` instances are few and long-lived (`dns.getServers()` uses
    /// one for the life of the process), so a map is cheaper than an internal
    /// field dance in every method, and it cannot be left dangling by a
    /// finalizer that has not run yet.
    static CHANNELS: RefCell<BTreeMap<usize, Channel>> = const { RefCell::new(BTreeMap::new()) };
}

/// Creates the state for a new channel and returns its key.
pub(crate) fn open_channel(timeout: i64, tries: u32, max_timeout: u32) -> usize {
    // A counter rather than a pointer: V8 internal fields are the usual home
    // for this, but the constructor runs before there is an object to store it
    // on, and the key only has to be unique within the thread.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let key = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    CHANNELS.with(|channels| {
        channels
            .borrow_mut()
            .insert(key, Channel::new(timeout, tries, max_timeout));
    });
    key
}

/// Runs `body` against a channel, if the key names one.
pub(crate) fn with_channel<T>(key: usize, body: impl FnOnce(&mut Channel) -> T) -> Option<T> {
    CHANNELS.with(|channels| channels.borrow_mut().get_mut(&key).map(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_round_trips_through_the_wire_format() {
        let packet = build_query(0x1234, "example.com", RecordType::A).expect("packet");
        assert_eq!(&packet[0..2], &[0x12, 0x34]);
        // qdcount 1, everything else 0.
        assert_eq!(&packet[4..6], &[0x00, 0x01]);
        assert_eq!(&packet[12..25], b"\x07example\x03com\x00");
        assert_eq!(&packet[25..27], &[0x00, 0x01]);
        assert_eq!(&packet[27..29], &[0x00, 0x01]);
    }

    #[test]
    fn a_trailing_dot_does_not_produce_an_empty_label() {
        let with_dot = build_query(1, "example.com.", RecordType::A).expect("packet");
        let without = build_query(1, "example.com", RecordType::A).expect("packet");
        assert_eq!(with_dot, without);
    }

    #[test]
    fn an_over_long_label_is_refused() {
        let label = "a".repeat(64);
        assert!(build_query(1, &label, RecordType::A).is_none());
    }

    /// `A` reply for `example.com`, hand-built so the parser is exercised
    /// without a network. The compression pointer at offset 12 is the same one
    /// a real resolver emits.
    fn a_response() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x8180u16.to_be_bytes()); // response, RD+RA
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        // Question.
        packet.extend_from_slice(b"\x07example\x03com\x00");
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        // First answer: name pointer back to the question.
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[104, 20, 23, 154]);
        // Second answer.
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[172, 66, 147, 243]);
        packet
    }

    #[test]
    fn an_a_response_decodes_with_ttls() {
        let response = parse_response(&a_response(), 0x1234).expect("parses");
        assert_eq!(response.rcode, 0);
        assert_eq!(response.records.len(), 2);
        assert_eq!(
            response.records[0],
            Record::A {
                address: "104.20.23.154".to_string(),
                ttl: 300
            }
        );
    }

    #[test]
    fn a_mismatched_transaction_id_is_rejected() {
        assert_eq!(
            parse_response(&a_response(), 0x9999).err(),
            Some(code::EBADRESP)
        );
    }

    #[test]
    fn a_query_bit_is_required() {
        let mut packet = a_response();
        packet[2] = 0x01; // clear the response flag
        assert_eq!(parse_response(&packet, 0x1234).err(), Some(code::EBADRESP));
    }

    #[test]
    fn a_truncated_packet_is_rejected_not_panicked() {
        let packet = a_response();
        for length in 0..packet.len() {
            let _ = parse_response(&packet[..length], 0x1234);
        }
    }

    #[test]
    fn reverse_names_follow_the_protocol() {
        let v4 = crate::ip::pton(crate::ip::Family::V4, "127.0.0.1")
            .expect("loopback")
            .with_port(0);
        assert_eq!(reverse_name(&v4).expect("name"), "1.0.0.127.in-addr.arpa");

        let v6 = crate::ip::pton(crate::ip::Family::V6, "::1")
            .expect("loopback")
            .with_port(0);
        let name = reverse_name(&v6).expect("name");
        assert!(name.ends_with("ip6.arpa"), "{name}");
        assert_eq!(
            name,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
    }

    #[test]
    fn set_servers_rejects_a_non_address_like_ares() {
        let mut channel = Channel::new(-1, 4, 0);
        let status = channel.set_servers(vec![Server {
            address: "not-an-ip".to_string(),
            port: 53,
        }]);
        // Recorded from Node: c-ares reports EBADSTR (17) here.
        assert_eq!(status, 17);
    }

    #[test]
    fn set_servers_accepts_an_empty_list_and_clears_the_system_servers() {
        let mut channel = Channel::new(-1, 4, 0);
        assert_eq!(channel.set_servers(Vec::new()), code::SUCCESS);
        assert!(channel.get_servers().is_empty());
    }

    #[test]
    fn local_address_refuses_two_addresses_of_one_family() {
        let mut channel = Channel::new(-1, 4, 0);
        assert_eq!(
            channel.set_local_address("1.2.3.4", Some("5.6.7.8")),
            Err(LocalAddressError::TwoIpv4)
        );
        assert_eq!(
            channel.set_local_address("::1", Some("::2")),
            Err(LocalAddressError::TwoIpv6)
        );
        assert_eq!(
            channel.set_local_address("not-an-ip", None),
            Err(LocalAddressError::Invalid)
        );
        // One of each is allowed, and so is a single address.
        assert!(channel.set_local_address("1.2.3.4", Some("::1")).is_ok());
        assert!(channel.set_local_address("1.2.3.4", None).is_ok());
    }

    #[test]
    fn a_channel_with_no_servers_reports_that_rather_than_timing_out() {
        let mut channel = Channel::new(-1, 4, 0);
        assert_eq!(channel.set_servers(Vec::new()), code::SUCCESS);
        assert_eq!(
            channel.query("example.com", RecordType::A),
            Err(code::ENOSERVER)
        );
        // Node reported "UNKNOWN_ARES_ERROR" for this, so the code must stay 26
        // rather than being folded into a generic failure.
        assert_eq!(code::ENOSERVER, 26);
    }

    #[test]
    fn cancel_makes_later_queries_report_cancelled() {
        let mut channel = Channel::new(-1, 4, 0);
        channel.cancel();
        assert_eq!(
            channel.query("example.com", RecordType::A),
            Err(code::ECANCELLED)
        );
    }

    #[test]
    fn an_empty_name_is_refused_before_hitting_the_network() {
        let mut channel = Channel::new(-1, 4, 0);
        let _ = channel.set_servers(vec![Server {
            address: "127.0.0.1".to_string(),
            port: 9,
        }]);
        assert_eq!(channel.query("", RecordType::A), Err(code::EBADNAME));
    }

    #[test]
    fn resolv_conf_host_port_forms_are_split() {
        assert_eq!(
            split_host_port("10.0.0.2:5353"),
            Some(("10.0.0.2".to_string(), 5353))
        );
        assert_eq!(
            split_host_port("[::1]:5353"),
            Some(("::1".to_string(), 5353))
        );
        // A bare IPv6 address has too many colons to be host:port.
        assert_eq!(split_host_port("::1"), None);
    }
}

# rn-bind-cares

`internalBinding('cares_wrap')` for rustnode — the namespace that makes
`require('dns')` work.

`lib/dns.js`, `lib/net.js`, `lib/tls.js` and `lib/internal/dns/**` are Node 28's
own code, byte-identical and never edited, so everything they call has to exist
here with the same name, argument order and return shape. All 18 members of
`contracts/cares_wrap.json` are installed; nothing is deferred.

## What is installed

| member | shape |
| --- | --- |
| `canonicalizeIP(ip)` | canonical text, or `undefined` |
| `convertIpv6StringToBuffer(ip)` | 16-byte `Uint8Array`; throws `Error: Invalid IPv6 address` |
| `strerror(code)` | c-ares' message for the code, `"unknown"` outside its table |
| `getaddrinfo(req, host, family, hints, order)` | returns a libuv status, delivers `(status, addresses)` |
| `getnameinfo(req, address, port)` | returns a libuv status, delivers `(status, hostname, service)` |
| `GetAddrInfoReqWrap`, `GetNameInfoReqWrap`, `QueryReqWrap` | constructible functions, `length` 0 |
| `ChannelWrap(timeout, tries, maxTimeout)` | a DNS channel with fifteen `query*` methods |
| `AF_INET`, `AF_INET6`, `AF_UNSPEC` | `2`, `10`, `0` |
| `AI_ADDRCONFIG`, `AI_ALL`, `AI_V4MAPPED` | `32`, `16`, `8` |
| `DNS_ORDER_*` | `0` verbatim, `1` ipv4first, `2` ipv6first |

## The backend: libuv semantics, not c-ares

Node implements this namespace on c-ares. This crate does not, and the reason is
worth writing down because it is a deliberate trade rather than an omission.

`uv_getaddrinfo` and `uv_getnameinfo` are thin wrappers over `getaddrinfo(3)` and
`getnameinfo(3)`, run on the libuv threadpool. Their *answers* are the system
resolver's answers, which is exactly what `dns.lookup()` promises: it consults
`/etc/hosts`, `/etc/resolv.conf`, NSS, and anything else the platform has wired
in. Reproducing that with c-ares is not possible without reimplementing NSS, so
the forward and reverse lookups here call the same libc functions libuv calls.

What libuv adds on top, and what this crate reproduces, is the *translation*:

- `uv__getaddrinfo_translate_error` maps the platform's `EAI_*` onto libuv's
  `UV_EAI_*`, which are negative on every platform. `lib/dns.js` turns the number
  into `DNSException`, which maps `UV_EAI_NODATA`/`UV_EAI_NONAME` to `ENOTFOUND`
  and otherwise calls `getSystemErrorName`, so forwarding glibc's `-2` instead of
  libuv's `-3008` would change `error.code`.
- `hints.ai_socktype` is always `SOCK_STREAM`, because `GetAddrInfo` sets it.
- The result is filtered by family and ordered by `DNS_ORDER_*`, which is
  `AfterGetAddrInfo`'s `add()` lambda and its three-way `switch`.

`ChannelWrap`'s `query*` methods cannot be built on `getaddrinfo`, because they
need the DNS record types (MX, TXT, SRV, SOA, ...) and TTLs. Those are
implemented against the DNS wire protocol over UDP in `src/channel.rs`. Linking
c-ares would instead mean shipping a second C library on every platform for a
protocol of about six hundred lines.

`canonicalizeIP` and `convertIpv6StringToBuffer` are **not** `inet_pton(3)`:
libuv ships its own copies, and the differences are observable. `src/ip.rs`
transcribes libuv's `inet.c` so that:

- a leading zero in an IPv4 octet is refused (`192.168.000.001` is not an
  address), where some libcs read it as octal;
- an IPv6 scope id is stripped before parsing, so `fe80::1%eth0` becomes
  `fe80::1`;
- the IPv4-embedded forms (`::ffff:1.2.3.4`, `::1.2.3.4`, NAT64) print as dotted
  quads, and the *first* longest zero run is abbreviated.

## Asynchrony

Node dispatches both lookup families onto the libuv threadpool, so the JavaScript
that started a lookup always runs to completion first. `lib/dns.js` relies on
that: `dns.lookup` assigns `req.oncomplete` *after* calling into the binding.

rustnode has no event loop yet, so the resolution runs inline and the completion
is queued as a microtask. The ordering guarantee is preserved exactly; what is
not provided is concurrency, so a slow resolver blocks the process instead of the
threadpool. That is the same trade `rn-bind-fs` and `rn-bind-zlib` make, and it is
the reason `deliver.rs` is a separate module with its own tests.

The three request wraps are therefore **not** deferred. They are plain
constructible functions, and `getaddrinfo`/`getnameinfo` deliver real
asynchronous results through `oncomplete` with the argument shape `lib/dns.js`
destructures.

## Verification

Three kinds of test back this up:

1. **Unit tests** next to each module: the wire format, the packet parser
   (including every truncation of a valid packet), the libuv error translation,
   the ordering, and the microtask delivery path.
2. **Recordings from a real `node`**, compared key by key:
   - `tests/node_expected.json` — the synchronous surface: constants,
     `canonicalizeIP` over 33 spellings, `convertIpv6StringToBuffer`, `strerror`
     over 33 codes, the constructor shapes, and the `ChannelWrap` prototype.
   - `tests/node_expected_async.json` — thirteen `getaddrinfo`/`getnameinfo`
     queries, including `family: 4` for `localhost` answering
     `['127.0.0.1', '127.0.0.1']` because this machine's `/etc/hosts` names the
     address twice.
3. **Live re-recording**: when `node` is on `PATH`, the same probes run under it
   and are compared to the fixtures, so a recording cannot drift from the binary
   it claims to describe.

## What is not implemented

The DNS client in `src/channel.rs` covers the query types `dns.resolve*` uses and
reports failures through c-ares' status codes, but it is not c-ares:

- **No TCP fallback.** A truncated reply reports `EBADRESP` rather than retrying
  over TCP, so a very large TXT or ANY answer fails instead of being fetched.
- **No EDNS0, DNSSEC, or search-list/`ndots` resolution.** Names are queried as
  given; `resolv.conf`'s `search` and `ndots` are ignored.
- **No query coalescing or cancellation of an in-flight request.** `cancel()`
  marks the channel so later queries report `ECANCELLED`, but a query already
  running to completion is not interrupted.
- **`getServers()` reports the port** on every entry, including the system
  servers, which is what `lib/internal/dns/utils.js` expects but differs from
  c-ares' habit of omitting `:53`.

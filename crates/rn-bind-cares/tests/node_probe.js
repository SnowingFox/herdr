// The same queries `tests/parity.rs` runs against the Rust binding, run against
// a real `node`. Kept as a file rather than an inline `-e` string so the two
// sides are readable side by side and a change to one is obvious in review.
//
// Under a real `node`, `--expose-internals` is required for the
// `internal/test/binding` helper the probe uses to reach the namespace. Under
// rustnode the namespace is injected as `globalThis.__cares` before the probe
// runs, because `internal/test/binding` needs `process.emitWarning`, which the
// bootstrap does not provide yet.
//
// Only synchronous members are probed here: the asynchronous ones need a running
// event loop, and `tests/async_parity.rs` covers them from the other direction by
// asserting on the answers recorded in `node_expected_async.json`.
//
// The result is written to `__out` as a JSON string, which is what the Rust test
// compares against its own run. When run directly under `node`, it prints that
// string instead.
(function probe() {
  // The Rust test injects the namespace as `__cares`; under a real `node` the
  // same object comes from the internals test helper. One probe, two sources,
  // so the queries below cannot drift apart.
  const binding = globalThis.__cares ??
    require('internal/test/binding').internalBinding('cares_wrap');
  const out = {};

  const guard = (fn) => {
    try {
      const value = fn();
      return value === undefined ? '__undefined__' : value;
    } catch (error) {
      return 'THREW:' + error.name + ':' + error.message;
    }
  };

  out.constants = {
    AF_INET: binding.AF_INET,
    AF_INET6: binding.AF_INET6,
    AF_UNSPEC: binding.AF_UNSPEC,
    AI_ADDRCONFIG: binding.AI_ADDRCONFIG,
    AI_ALL: binding.AI_ALL,
    AI_V4MAPPED: binding.AI_V4MAPPED,
    DNS_ORDER_VERBATIM: binding.DNS_ORDER_VERBATIM,
    DNS_ORDER_IPV4_FIRST: binding.DNS_ORDER_IPV4_FIRST,
    DNS_ORDER_IPV6_FIRST: binding.DNS_ORDER_IPV6_FIRST,
  };

  // Every spelling whose answer is not obvious: leading zeros, scope ids,
  // IPv4-embedded forms, and inputs that must fail.
  out.canonicalize = {};
  for (const ip of [
    '127.0.0.1', '0.0.0.0', '255.255.255.255', '192.168.000.001',
    '::1', '::', '2001:db8::1', '2001:0DB8:0000:0000:0000:0000:0000:0001',
    '::ffff:127.0.0.1', '::ffff:1.2.3.4', 'fe80::1%eth0', 'FE80::1',
    '1.2.3', '1.2.3.4.5', 'not-an-ip', '', ' 1.2.3.4', '1.2.3.4 ',
    '0:0:0:0:0:0:0:0', '::0.0.0.0', '01.2.3.4', '1.2.3.04',
    '0x7f.0.0.1', '1::2::3', ':::1', '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8:9',
    '12345::', '1::2', '::1.2.3.4', '1:2:3:4:5:6:1.2.3.4',
    '2001:db8:0:0:1:0:0:1', '2001:DB8::0:1:0:0:1',
  ]) {
    out.canonicalize[ip] = guard(() => binding.canonicalizeIP(ip));
  }

  out.convert_ipv6 = {};
  for (const ip of [
    '::1', '::', '2001:db8::1', '::ffff:127.0.0.1', 'fe80::1%eth0',
    'not-an-ip', '1.2.3.4', '',
  ]) {
    out.convert_ipv6[ip] = guard(() => {
      const buffer = binding.convertIpv6StringToBuffer(ip);
      // Hex by hand: rustnode's bare test scope has no `Buffer`, and the value
      // under test is the byte contents, not the buffer class.
      let hex = '';
      for (let i = 0; i < buffer.length; i++) {
        hex += buffer[i].toString(16).padStart(2, '0');
      }
      return { length: buffer.length, hex };
    });
  }

  out.strerror = {};
  for (const code of [
    -1000, -1, -2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 12345,
  ]) {
    out.strerror[code] = guard(() => binding.strerror(code));
  }

  out.request_wraps = {};
  for (const name of [
    'GetAddrInfoReqWrap', 'GetNameInfoReqWrap', 'QueryReqWrap', 'ChannelWrap',
  ]) {
    out.request_wraps[name] = {
      kind: typeof binding[name],
      length: binding[name].length,
      name: binding[name].name,
    };
  }

  // The channel's prototype is where `lib/internal/dns/utils.js` finds every
  // `query*` method, so a missing one is a `TypeError` at `dns.Resolver` use.
  const channel = new binding.ChannelWrap(-1, 4, 0);
  out.channel = {
    prototype: Object.getOwnPropertyNames(Object.getPrototypeOf(channel)).sort(),
    own: Object.getOwnPropertyNames(channel).sort(),
    // `SetServers` reports c-ares status codes, which is why a malformed
    // address is 17 and not a throw.
    set_bad: channel.setServers([[4, 'not-an-ip', 53]]),
  };

  const json = JSON.stringify(out);
  globalThis.__out = json;
  // Under rustnode there is no `process.stdout` in the bare test scope, and
  // `__cares` being set is the signal that a test is reading `__out` instead.
  if (!globalThis.__cares && typeof process !== 'undefined') {
    process.stdout.write(json);
  }
})();

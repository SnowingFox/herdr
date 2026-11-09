// Records what a real `node` answers for the asynchronous members.
//
// `node_probe.js` covers the synchronous surface, which needs no event loop.
// These queries do: `req.oncomplete` only fires from the loop, so this probe
// collects the answers and writes them from `setImmediate`, which runs after
// every lookup queued by this script has completed.
//
// The output goes to `node_expected_async.json` and is asserted by
// `tests/async_parity.rs`.
(function probe() {
  const binding = globalThis.__cares ??
    require('internal/test/binding').internalBinding('cares_wrap');

  const completions = [];
  let outstanding = 0;

  const addrinfo = (label, host, family, hints, order) => {
    outstanding++;
    const req = new binding.GetAddrInfoReqWrap();
    req.oncomplete = (status, addresses) => {
      completions.push([
        label,
        status,
        addresses === null ? null : Array.from(addresses),
      ]);
      outstanding--;
    };
    const status = binding.getaddrinfo(req, host, family, hints, order);
    if (status) {
      // A synchronous failure never reaches `oncomplete`.
      completions.push([label, 'sync', status]);
      outstanding--;
    }
  };

  const nameinfo = (label, address, port) => {
    outstanding++;
    const req = new binding.GetNameInfoReqWrap();
    req.oncomplete = (status, hostname, service) => {
      completions.push([label, status, hostname, service]);
      outstanding--;
    };
    const status = binding.getnameinfo(req, address, port);
    if (status) {
      completions.push([label, 'sync', status]);
      outstanding--;
    }
  };

  addrinfo('localhost_unspec_verbatim', 'localhost', 0, 0, 0);
  addrinfo('localhost_unspec_v4first', 'localhost', 0, 0, 1);
  addrinfo('localhost_unspec_v6first', 'localhost', 0, 0, 2);
  addrinfo('localhost_v4', 'localhost', 4, 0, 0);
  addrinfo('localhost_v6', 'localhost', 6, 0, 0);
  addrinfo('localhost_addrconfig', 'localhost', 0, 32, 0);
  addrinfo('ipv4_literal', '127.0.0.1', 0, 0, 0);
  addrinfo('ipv6_literal', '::1', 0, 0, 0);
  addrinfo('nonexistent', 'no-such-host.invalid', 0, 0, 0);
  nameinfo('nameinfo_v4', '127.0.0.1', 80);
  nameinfo('nameinfo_v6', '::1', 80);
  nameinfo('nameinfo_ssh', '127.0.0.1', 22);
  nameinfo('nameinfo_unassigned', '127.0.0.1', 54321);

  // `setImmediate` runs after the loop has drained every completed lookup.
  // Without an event loop the Rust side drives the same list itself, so this
  // scheduling exists only for the `node` half of the recording.
  if (typeof setImmediate === 'function') {
    setImmediate(() => {
      globalThis.__out = JSON.stringify(completions.sort((a, b) => (a[0] < b[0] ? -1 : 1)));
      if (typeof process !== 'undefined' && !globalThis.__cares) {
        process.stdout.write(globalThis.__out);
      }
    });
  }
})();

'use strict';
// The S4 acceptance probe: constructs `SecureContext` through Node's real TLS
// configuration path and reports, per method, whether it works, throws, or is a
// declared stub.
//
// S4 alone moves zero test files — it cannot be observed until S6 (`TLSWrap`)
// exists — so file counts are not an available acceptance signal. This is the
// substitute: it drives the same sequence `lib/internal/tls/common.js:88` and
// `lib/internal/tls/secure-context.js` drive, and prints a table.
//
// WHAT THIS DOES NOT PROVE: that TLS works. There is no handshake here and no
// `tls_wrap` binding. A context that configures cleanly is a context that can
// be handed to `tls_wrap.wrap`; it is not a working connection.
//
// Usage: rustnode --expose-internals tools/secure-context-probe.js
//
// Output is one `KEY|value` line per observation so a shell can compare two
// runs with `diff` and so a missing line is visibly missing rather than absent
// from prose. Exit status is 0 when the class exists and constructs, 1 when it
// does not — the same shape as the negative control, so the "before" tree fails
// on the first observation rather than producing a table of `undefined`.

const { internalBinding } = require('internal/test/binding');
const { configSecureContext } = require('internal/tls/secure-context');

// A fixed self-signed pair for CN=rustnode-secure-context-probe, RSA-2048,
// valid for ten years from generation. Generated with
//   openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
//     -subj '/CN=rustnode-secure-context-probe'
// and embedded so the probe needs no fixture file: a missing fixture would
// otherwise turn `setCert` into a parse error that reads like a wiring bug.
// The private key is public and only proves the path runs; it signs nothing.
const PROBE_KEY_PEM = [
  '-----BEGIN PRIVATE KEY-----',
  'MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDByFPI1JmNLmno',
  'VEDEpfDR24N4god0aqip3s5ylLkN+SByrpx+cJS0yHdRqyZ/JsCoVbPFrZdR5oEa',
  'VOY3epBtDiEYEEBk+Si4XNHoZJ24CUkBstzPtmDPUoOsHQzk6rrpehC0yrlCnPC8',
  'C4JEbbwydeK6mSolp9cfzDE0KTHYUWGxuqpqCMFzber5N4vz6MkFKwomijDhwcoT',
  'DdC6gU3Xt2CilF0pNviEltEKDJR8eiIbcZbvgPzsFLiPchvdL612bACQaqlt8wZ0',
  'j2kMprJzmwM0SS3vO+kByV1YGVrK//yZ1CqXqnwNX6ljEzVLjIw4pg9B+ZsjYRrz',
  '6A+I7m2HAgMBAAECggEAGDt4LrmskfkR3q8FLRIghpL6t8vVgHtYqBVn9PAgIV0x',
  'ROYM78rIQxXRG0dZwwtnitAHcQV/fLW5wz8xTWgS6MWcNyl2bqoHAOGqkMhe6K/7',
  'OdknaloWH8GOcawYUVqru507ZZWhi8ZFsbOGu2PgOuHUU8fqJgH9EXQ0BZ/OeeGg',
  'qDBGVF3oGOjrufpgPHaifk16sfFJcy5mOzpRtbAyfzv0dlDn3kdC7ssf4rw20uFL',
  'Q1I6sc0PJTKlGuvu/h3eV2gS/OTNpVMhm+nVncIRV9tAyAtba8KZi1C1TLEyJpsL',
  'QZ+yDUxLsLMrDVjHC/O4P1XN1DfirpTliqtrWOgNUQKBgQD5lq0nDgs7Az6Vbz50',
  'cdtPLJ9vBJQtBvrqY6wWiYsIZcENYtcWgI54GN40nN6mkB9n8F0+J8Y9OLu/3R6o',
  'eofLjBEtuiE0f1AYTc+mPA70zY5mR527VfbdU4fWLAs1rmQeUx6mbUaJaZdNCfad',
  'RHDzW/mIHJRlL8wWeA2BTIOBYwKBgQDGwqnu66dWXqkDxfdbTvEqeVBpURvqGbbb',
  'Ys/3NTaSmSP2QezFkfcpNF3rG3BP3rs0TsSw86LP9O58CBzfFwje0Hoxv1LaTbgk',
  'eLusVjGveCH1mQ23ToIAOsuJNfkl43LuT7JMbZTVpCwem2xh5ujR46C5up1I6ImK',
  'Br8Q9txOjQJ/RTiEzVAXzUYZFVjE+YaaTFsT3LZoYhSNgnQiRh3fcXTHFe9Tt+nv',
  'mV9MQUtAdPGDxE/ljFd7o38Ykx3AYvmYr9so6IW2r9ifXh42eOQvQbXAyJ0UIeC1',
  'lqyT/9I3SawUGFT1KzMjXPjr/XHF89gHe3cGvbkvbuDSuWiSVkniLwKBgARQz73H',
  'Uh/W+FaDouZRpXzlm3Bd+XwwyL6ku51Dg4bVWmmLbuevTq2PXIaxVtP1Ix10pGKv',
  'N5bKW69HwdC6QFAOOMkBvXvN+jSYhoKscHG96wbZJuoXA02b+TVmfZ1r/d/czSNJ',
  'sdSdtvOHLmhFykJcbe36dlXR7sKXeOiWY5w1AoGBAIZPNQ2v41Uuc1tzXrHYixoP',
  'SpRoIFjXnuP4jrkk/moC/EOuXtZQ6mEqfp1UbWxa22uMh9bgBdrjBySV3998N2Vd',
  'cUVXPqoFViSBBcr4LTLWnHfVtzYMUfH6xBeVZB16j7d+40ah2OZlWtZfxosvJrwu',
  'KXA2r2Gdx8SfhNcJg8xQ',
  '-----END PRIVATE KEY-----',
].join('\n');

const PROBE_CERT_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIDMTCCAhmgAwIBAgIUUgQmPMSbJYBcsyfOo8kqsOhOUMgwDQYJKoZIhvcNAQEL',
  'BQAwKDEmMCQGA1UEAwwdcnVzdG5vZGUtc2VjdXJlLWNvbnRleHQtcHJvYmUwHhcN',
  'MjYxMTExMDk1MDM2WhcNMzYxMTA4MDk1MDM2WjAoMSYwJAYDVQQDDB1ydXN0bm9k',
  'ZS1zZWN1cmUtY29udGV4dC1wcm9iZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC',
  'AQoCggEBAMHIU8jUmY0uaehUQMSl8NHbg3iCh3RqqKneznKUuQ35IHKunH5wlLTI',
  'd1GrJn8mwKhVs8Wtl1HmgRpU5jd6kG0OIRgQQGT5KLhc0ehknbgJSQGy3M+2YM9S',
  'g6wdDOTquul6ELTKuUKc8LwLgkRtvDJ14rqZKiWn1x/MMTQpMdhRYbG6qmoIwXNt',
  '6vk3i/PoyQUrCiaKMOHByhMN0LqBTde3YKKUXSk2+ISW0QoMlHx6Ihtxlu+A/OwU',
  'uI9yG90vrXZsAJBqqW3zBnSPaQymsnObAzRJLe876QHJXVgZWsr//JnUKpeqfA1f',
  'qWMTNUuMjDimD0H5myNhGvPoD4jubYcCAwEAAaNTMFEwHQYDVR0OBBYEFI8vuNLk',
  'iI/asoSXjIrJuffWwmmpMB8GA1UdIwQYMBaAFI8vuNLkiI/asoSXjIrJuffWwmmp',
  'MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABe4sQNV2G/2ukPg',
  'kJr6L4Gdl7KSiqllKH78T6tMTnz5yk+G4+2qdXRCtMLPiCB6NuaCFB9dHx7Eb4FC',
  'FFkUJBTS/rT+3cNcBFLNPK0haRIj0bE9uXu2bxmCbVqU1VHk3eyTYJLM16sMX7kl',
  'vZYqfLxYqODX7Hh2UFlRtDoFSy/AfuXhgRawRfjtOTRNWMCk7vbRO/AZIBFhJhth',
  're30fWzZUdS0ci2nKMgzx8sPLM4828yQe17bmqK73cEnTH0uQUAQgA0qjhtssvEW',
  'RACHZo5d7d8VtrvQxWpv51vCobBL73gp+hG9UbW7I6dQBJsImLPOD32RNd1qJ4TL',
  'mylS6Lg=',
  '-----END CERTIFICATE-----',
].join('\n');

const out = [];
function report(key, value) {
  out.push(`${key}|${value}`);
}

// ---------------------------------------------------------------------------
// (1) The class exists, constructs, and is instanceof-checkable.
//
// This is the milestone the plan defines for S4: `wrap.js:832` does
// `if (!(context.context instanceof NativeSecureContext)) throw
// ERR_TLS_INVALID_CONTEXT`, so the class has to exist and brand-check before
// S6 can be written at all.
// ---------------------------------------------------------------------------
const binding = internalBinding('crypto');

if (typeof binding.SecureContext !== 'function') {
  report('class', `MISSING: typeof is ${typeof binding.SecureContext}`);
  // Print what we have and stop: every later observation would be a cascade off
  // this one, and a cascade is what makes a control unreadable.
  process.stdout.write(`${out.join('\n')}\n`);
  process.exit(1);
}

report('class', 'present');
report('class.name', binding.SecureContext.name);

const NativeSecureContext = binding.SecureContext;
let context;
try {
  context = new NativeSecureContext();
  report('construct', 'ok');
} catch (error) {
  report('construct', `THREW ${error.constructor.name}: ${error.message}`);
  process.stdout.write(`${out.join('\n')}\n`);
  process.exit(1);
}

report(
  'construct.instanceof',
  String(context instanceof NativeSecureContext));
report('construct.distinct', String(context !== new NativeSecureContext()));

// The 27 prototype methods `crypto_context.cc:1312-1343` installs, plus the
// `_external` accessor. A missing name here is a `TypeError: ... is not a
// function` for whoever calls it, which is why the list is asserted whole.
const PROTOTYPE_METHODS = [
  'init', 'setKey', 'setCert', 'addCACert', 'setAllowPartialTrustChain',
  'addCRL', 'addRootCerts', 'setCipherSuites', 'setCiphers', 'setSigalgs',
  'setECDHCurve', 'setDHParam', 'setMaxProto', 'setMinProto', 'getMaxProto',
  'getMinProto', 'setOptions', 'setSessionIdContext', 'setSessionTimeout',
  'setCertificateCompression', 'close', 'loadPKCS12', 'setTicketKeys',
  'enableTicketKeyCallback', 'getTicketKeys', 'getCertificate', 'getIssuer',
];
const missing = PROTOTYPE_METHODS.filter(
  (name) => typeof NativeSecureContext.prototype[name] !== 'function');
report('prototype.methods', missing.length === 0 ?
  `all ${PROTOTYPE_METHODS.length} present` :
  `MISSING ${missing.join(',')}`);
// `_external` is an accessor with a getter, not a prototype method, and reading
// it on the prototype throws from the `Signature` guard. Both were checked
// against a real `node` 22 before being asserted here.
report('prototype._external descriptor', (() => {
  const d = Object.getOwnPropertyDescriptor(
    NativeSecureContext.prototype, '_external');
  if (d === undefined) return 'MISSING';
  return `get=${typeof d.get} enumerable=${d.enumerable} configurable=${d.configurable}`;
})());
report('prototype._external read', (() => {
  try {
    void NativeSecureContext.prototype._external;
    return 'no-throw (Node throws TypeError)';
  } catch (error) {
    return `${error.name} (as in Node)`;
  }
})());

// ---------------------------------------------------------------------------
// (2) `init`, exactly as `common.js:88` calls it.
//
// `toV` in `common.js` turns 'TLSv1.2' into TLS1_2_VERSION and the default max
// into TLS1_3_VERSION; the numbers are inlined here because this probe does not
// require `tls` (see the note at the top of the file about tls_wrap).
// ---------------------------------------------------------------------------
const TLS1_2_VERSION = 0x0303;
const TLS1_3_VERSION = 0x0304;

try {
  context.init(undefined, TLS1_2_VERSION, TLS1_3_VERSION);
  report('init', `ok min=${context.getMinProto()} max=${context.getMaxProto()}`);
} catch (error) {
  report('init', `THREW ${error.constructor.name}: ${error.message}`);
}

// A second context, because `init` after a failed `init` is not the same state
// and the probe should not inherit the first context's luck.
function fresh(secureProtocol) {
  const c = new NativeSecureContext();
  c.init(secureProtocol, TLS1_2_VERSION, TLS1_3_VERSION);
  return c;
}

// ---------------------------------------------------------------------------
// (3) The 19 methods `configSecureContext` calls, plus the ones `wrap.js` and
// `tls.js` call that the plan's list omits.
//
// Each is exercised through `configSecureContext` where that is how Node calls
// it, because that is the real path: `configSecureContext` is the actual
// function from `lib/internal/tls/secure-context.js`, so the argument shapes it
// builds are Node's, not this probe's invention.
//
// The result of each attempt is classified as:
//   OK        the call completed
//   STUB      it threw ERR_CRYPTO_UNSUPPORTED_OPERATION (a declared gap)
//   THREW     it threw anything else (a defect, or a bad argument here)
// ---------------------------------------------------------------------------
function classify(operation) {
  try {
    operation();
    return 'OK';
  } catch (error) {
    const code = error && error.code ? error.code : '<no code>';
    if (code === 'ERR_CRYPTO_UNSUPPORTED_OPERATION') return `STUB ${code}`;
    return `THREW ${code}: ${error.message}`;
  }
}

// A refusal that must happen: SSLv2 and SSLv3 are disabled on purpose, so a
// landing that *accepted* them would be a regression. Reported as OK when the
// expected code is thrown, REFUSED-ANYWAY when the call succeeded.
function classifyRefusal(operation, expectedCode) {
  try {
    operation();
    return `ACCEPTED (should have thrown ${expectedCode})`;
  } catch (error) {
    if (error && error.code === expectedCode) return `OK refused ${expectedCode}`;
    return `THREW ${error && error.code ? error.code : '<no code>'}: ${error.message}`;
  }
}

// `configSecureContext` with one option at a time, so a single failing option
// does not hide the rest. Every call gets a fresh context because these mutate.
const OPTION_CASES = [
  ['setCipherSuites+setCiphers', { ciphers: 'DEFAULT' }],
  ['setCipherSuites (TLS1.3 only)', {
    // Only TLS_ names, so `processCiphers` puts every one in the 1.3 list and
    // leaves the TLS-1.2 list empty. `configSecureContext` then calls
    // `setCiphers('')`, which must not be an error; this is the case
    // `SecureContext::SetCiphers` special-cases on `SSL_R_NO_CIPHER_MATCH`.
    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384',
  }],
  ['addRootCerts', { ca: undefined }],
  ['setAllowPartialTrustChain', { allowPartialTrustChain: true }],
  ['setECDHCurve', { ecdhCurve: 'prime256v1' }],
  ['setECDHCurve (auto)', { ecdhCurve: 'auto' }],
  ['setSigalgs', { sigalgs: 'RSA-PSS+SHA256' }],
  ['setSessionIdContext', { sessionIdContext: 'rustnode-probe' }],
  ['setSessionTimeout', { sessionTimeout: 300 }],
  ['setTicketKeys', { ticketKeys: Buffer.alloc(48, 0xab) }],
  ['setDHParam (auto)', { dhparam: 'auto' }],
  ['setCertificateCompression', { certificateCompression: ['zlib'] }],
];

// `configSecureContext` defaults `ciphers` and `ecdhCurve` lazily through
// `require('tls')`, and `tls` requires `internal/tls/wrap.js`, which calls
// `internalBinding('tls_wrap')` at module scope. That namespace is S6 and does
// not exist yet, so asking for Node's *defaults* here would fail on S6 and
// report S6's gap as an S4 result. Supplying both explicitly is what lets this
// probe exercise the real `configSecureContext` on the real path without
// depending on a later slice. Every other option is passed as Node would.
const NODE_DEFAULT_CIPHERS = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:' +
  'TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:' +
  'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:' +
  'ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384';

for (const [name, options] of OPTION_CASES) {
  const result = classify(() => configSecureContext(fresh(undefined), {
    ciphers: NODE_DEFAULT_CIPHERS,
    ecdhCurve: 'auto',
    ...options,
  }));
  report(`config.${name}`, result);
}

// `getTicketKeys` is called by `Server.prototype.getTicketKeys` in `tls.js`, and
// `setTicketKeys` round-trips through `configSecureContext` above.
report('getTicketKeys', classify(() => {
  const keys = fresh(undefined).getTicketKeys();
  if (!Buffer.isBuffer(keys)) throw new Error('not a Buffer');
  if (keys.length !== 48) throw new Error(`length ${keys.length}, want 48`);
}));

// `getCertificate`/`getIssuer` are read by the OCSP request path in
// `wrap.js:416`, and are `null` until a certificate is installed.
report('getCertificate (no cert)', classify(() => {
  if (fresh(undefined).getCertificate() !== null) throw new Error('not null');
}));
report('getIssuer (no cert)', classify(() => {
  if (fresh(undefined).getIssuer() !== null) throw new Error('not null');
}));

// `close()` is called from `wrap.js:768` for single-use contexts.
report('close', classify(() => {
  const c = fresh(undefined);
  c.close();
  c.close();
}));

// `setOptions` is called by the `common.js` constructor when `secureOptions` is
// set, not by `configSecureContext`.
report('setOptions', classify(() => fresh(undefined).setOptions(0x400000)));

// `setCert`, `setKey`, `addCACert` and `addCRL` need real PEM material, so they
// are driven with a self-signed pair generated here rather than with a fixture
// file the probe would have to ship. Only these four need it.
report('setCert+setKey (generated pair)', classify(() => {
  const c = fresh(undefined);
  c.setCert(PROBE_CERT_PEM);
  c.setKey(PROBE_KEY_PEM, undefined);
  const der = c.getCertificate();
  if (der === null) throw new Error('getCertificate still null after setCert');
  if (!Buffer.isBuffer(der)) throw new Error('getCertificate is not a Buffer');
}));

// `getIssuer` needs the issuer to be *reachable*: a self-signed leaf with no CA
// installed has no issuer to resolve and reports null. Verified against a real
// `node` 22 oracle, which returns null for the same pair and a Buffer only once
// the certificate is also added as a CA. Asserting a Buffer here would have been
// asserting a behaviour Node does not have.
report('getIssuer (self-signed, no ca)', classify(() => {
  const c = fresh(undefined);
  c.setCert(PROBE_CERT_PEM);
  c.setKey(PROBE_KEY_PEM, undefined);
  if (c.getIssuer() !== null) throw new Error('expected null without a CA');
}));
report('getIssuer (ca=self)', classify(() => {
  const c = fresh(undefined);
  c.addCACert(PROBE_CERT_PEM);
  c.setCert(PROBE_CERT_PEM);
  c.setKey(PROBE_KEY_PEM, undefined);
  const issuer = c.getIssuer();
  if (issuer === null) throw new Error('null with the CA installed');
  if (!Buffer.isBuffer(issuer)) throw new Error('issuer is not a Buffer');
}));
report('addCACert', classify(() => {
  const c = fresh(undefined);
  c.addCACert(PROBE_CERT_PEM);
}));
report('addCRL', classify(() => {
  // An empty CRL PEM: parse must fail rather than silently accept, which is the
  // behaviour `setCRL` documents ("Failed to parse CRL").
  const c = fresh(undefined);
  try {
    c.addCRL(Buffer.from('-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n'));
  } catch (error) {
    if (error.code === 'ERR_CRYPTO_UNSUPPORTED_OPERATION') throw error;
    // A parse rejection is the expected outcome for invalid input, so this
    // counts as the method being wired.
    return;
  }
  throw new Error('invalid CRL was accepted');
}));

// `loadPKCS12` and `enableTicketKeyCallback` are called by `configSecureContext`
// (`pfx`) and by the ticket-key path respectively.
report('loadPKCS12', classify(() => {
  fresh(undefined).loadPKCS12(Buffer.from('not a pfx'), undefined);
}));
report('enableTicketKeyCallback', classify(() => {
  fresh(undefined).enableTicketKeyCallback();
}));

// ---------------------------------------------------------------------------
// (4) The methods Node refuses on purpose, which must still refuse.
//
// These are not stubs: they are `ERR_TLS_INVALID_PROTOCOL_METHOD`, and a
// landing that accepted SSLv2 would be worse than one that lacks the class.
// ---------------------------------------------------------------------------
report('init(SSLv2_method)', classifyRefusal(() => {
  new NativeSecureContext().init('SSLv2_method', 0, 0);
}, 'ERR_TLS_INVALID_PROTOCOL_METHOD'));

// ---------------------------------------------------------------------------
// Emit. One `KEY|value` line per observation.
// ---------------------------------------------------------------------------
process.stdout.write(`${out.join('\n')}\n`);

// The probe's own pass condition. A `THREW` line is a defect or a bad argument
// in this file; a `STUB` line is a declared gap and is reported, not failed.
// The distinction is the whole point: a stub that reported OK would hide a gap.
const threw = out.filter((line) => line.includes('|THREW '));
if (threw.length > 0) {
  process.stderr.write(`${threw.length} observation(s) threw unexpectedly:\n`);
  for (const line of threw) process.stderr.write(`  ${line}\n`);
  process.exit(2);
}
process.exit(0);

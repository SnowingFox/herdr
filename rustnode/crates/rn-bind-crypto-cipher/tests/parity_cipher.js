'use strict';
// Byte-identical parity between rustnode and a real `node` for the cipher
// surface this slice implements. Every value printed is deterministic: a fixed
// key, a fixed IV and fixed plaintext, so the two binaries' output can be
// compared with `diff` and any difference is a defect rather than noise.
//
// The four cases the slice is judged on are all here:
//   * aes-256-gcm with a real auth tag (and a tag-mismatch failure)
//   * chacha20-poly1305
//   * aes-256-ctr, a stream cipher with no padding and no tag
//   * a large multi-chunk payload, which forces the incremental update path
//     rather than a single one-shot call

const crypto = require('crypto');

const out = [];
function show(label, value) {
  out.push(`${label}: ${value}`);
}

function hex(buffer) {
  return Buffer.from(buffer).toString('hex');
}

// ---------------------------------------------------------------------------
// aes-256-gcm, with the auth tag round-tripped
// ---------------------------------------------------------------------------
{
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
  const iv = Buffer.from('101112131415161718191a1b', 'hex');
  const aad = Buffer.from('additional authenticated data', 'utf8');
  const plaintext = Buffer.from(
    'The quick brown fox jumps over the lazy dog, twice: ' +
    'The quick brown fox jumps over the lazy dog.', 'utf8');

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  show('gcm.ciphertext', hex(ciphertext));
  show('gcm.tag', hex(tag));

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  show('gcm.roundtrip', hex(decrypted));
  show('gcm.matches', String(decrypted.equals(plaintext)));

  // A wrong tag must fail rather than return bytes.
  const bad = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  bad.setAAD(aad);
  bad.setAuthTag(Buffer.alloc(16));
  bad.update(ciphertext);
  try {
    bad.final();
    show('gcm.badtag', 'no-throw');
  } catch (error) {
    show('gcm.badtag', `${error.code === undefined ? 'no-code' : error.code}|${error.message}`);
  }

  // A 12-byte tag, to prove the length is per-construction and not hardcoded.
  const short = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 12 });
  const shortText = Buffer.concat([short.update(plaintext), short.final()]);
  show('gcm12.ciphertext', hex(shortText));
  show('gcm12.tag', hex(short.getAuthTag()));
}

// ---------------------------------------------------------------------------
// chacha20-poly1305
// ---------------------------------------------------------------------------
{
  const key = Buffer.from('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'hex');
  const iv = Buffer.from('404142434445464748494a4b', 'hex');
  const plaintext = Buffer.from('chacha20-poly1305 over a message longer than one block', 'utf8');

  const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  show('chacha.ciphertext', hex(ciphertext));
  show('chacha.tag', hex(tag));

  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  show('chacha.roundtrip', decrypted.toString('utf8'));
}

// ---------------------------------------------------------------------------
// aes-256-ctr, a stream cipher
// ---------------------------------------------------------------------------
{
  const key = Buffer.from('505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f', 'hex');
  const iv = Buffer.from('707172737475767778797a7b7c7d7e7f', 'hex');
  const plaintext = Buffer.from('stream ciphers have no padding and no tag', 'utf8');

  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  show('ctr.ciphertext', hex(ciphertext));
  show('ctr.lengths', `${plaintext.length}/${ciphertext.length}`);

  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  show('ctr.roundtrip', decrypted.toString('utf8'));

  // A stream cipher must produce output for every input byte, including a
  // partial final block, which is where a one-shot implementation would drift.
  const odd = Buffer.from('12345678901234567', 'utf8');
  const oddCipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  show('ctr.odd', hex(Buffer.concat([oddCipher.update(odd), oddCipher.final()])));
}

// ---------------------------------------------------------------------------
// A large multi-chunk payload: 1 MiB in 1 KiB pieces.
//
// This is the case that only an incremental implementation passes. A one-shot
// `update` plus `final` would produce the same bytes for CTR but not for CBC
// with padding, because the padding is only correct when the tail is finalised
// once, and a per-chunk `final` would pad every chunk.
// ---------------------------------------------------------------------------
{
  const key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
  const iv = Buffer.from('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf', 'hex');
  const chunk = Buffer.alloc(1024);
  for (let index = 0; index < chunk.length; index += 1) {
    chunk[index] = (index * 31 + 7) & 0xff;
  }

  const pieces = [];
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  for (let index = 0; index < 1024; index += 1) {
    pieces.push(cipher.update(chunk));
  }
  pieces.push(cipher.final());
  const ciphertext = Buffer.concat(pieces);
  show('large.ciphertext.length', String(ciphertext.length));
  show('large.ciphertext.sha256',
       crypto.createHash('sha256').update(ciphertext).digest('hex'));

  // Decrypt in differently sized pieces, which must not matter.
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const recovered = [];
  let offset = 0;
  let step = 1;
  while (offset < ciphertext.length) {
    const end = Math.min(offset + step * 97, ciphertext.length);
    recovered.push(decipher.update(ciphertext.subarray(offset, end)));
    offset = end;
    step += 1;
  }
  recovered.push(decipher.final());
  const plaintext = Buffer.concat(recovered);
  show('large.roundtrip.length', String(plaintext.length));
  show('large.roundtrip.sha256',
       crypto.createHash('sha256').update(plaintext).digest('hex'));
}

// ---------------------------------------------------------------------------
// aes-128-ecb, which takes no IV at all: the null-IV path.
// ---------------------------------------------------------------------------
{
  const key = Buffer.from('b0b1b2b3b4b5b6b7b8b9babbbcbdbebf', 'hex');
  const plaintext = Buffer.from('sixteen bytes!!!', 'utf8');
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  show('ecb.ciphertext', hex(Buffer.concat([cipher.update(plaintext), cipher.final()])));
}

// ---------------------------------------------------------------------------
// aes-128-wrap, which needs the wrap-allow flag before the cipher is chosen.
// ---------------------------------------------------------------------------
{
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const plaintext = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const iv = Buffer.alloc(8, 0xa6);
  const cipher = crypto.createCipheriv('aes-128-wrap', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  show('wrap.ciphertext', hex(ciphertext));

  const decipher = crypto.createDecipheriv('aes-128-wrap', key, iv);
  show('wrap.roundtrip', hex(Buffer.concat([decipher.update(ciphertext), decipher.final()])));
}

// ---------------------------------------------------------------------------
// The error shapes, which are part of the observable surface.
//
// Two of these deliberately disagree with a local `node` v22, and agree with the
// pinned Node 28 tree instead. At the pin, three files assert
// ERR_CRYPTO_UNSUPPORTED_OPERATION for `ctsMode`/`xtsStandard` on a cipher that
// does not implement them: `test/parallel/test-crypto-cipherbase-options-fast-path.js`,
// `test/parallel/test-crypto-cipheriv-cbc-cts.js` and
// `test/parallel/test-crypto-cipheriv-decipheriv.js`. That is what
// `CipherBase::CommonInit` throws; the v22 on this machine predates that check and
// accepts the option silently. (`test/parallel/test-crypto-cipheriv-xts.js` is not
// one of them: it round-trips XTS ciphers and checks the repeated-update state
// errors, and contains no such assertion.) The pin is authoritative, so these
// print the pin's answer and the diff against v22 is expected. See
// `docs/compat-status.md`'s "Version skew against the local `node` binary".
// ---------------------------------------------------------------------------
{
  const key = Buffer.alloc(16);
  const iv = Buffer.alloc(16);
  const shape = (label, body) => {
    try {
      body();
      show(label, 'no-throw');
    } catch (error) {
      show(label, `${error.constructor.name}|${error.code === undefined ? 'no-code' : error.code}|${error.message}`);
    }
  };
  shape('err.unknown', () => crypto.createCipheriv('aes-127', key, null));
  shape('err.keylen', () => crypto.createCipheriv('aes-128-ecb', Buffer.alloc(17), null));
  shape('err.iv.null', () => crypto.createCipheriv('aes-128-cbc', key, null));
  shape('err.iv.short', () => crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(8)));
  shape('err.iv.ecb', () => crypto.createCipheriv('aes-128-ecb', key, Buffer.alloc(5)));
  shape('err.gcm.iv0', () => crypto.createCipheriv('aes-128-gcm', key, Buffer.alloc(0)));
  shape('err.cts', () => crypto.createCipheriv('aes-128-cbc', key, iv, { ctsMode: 'CS1' }));
  shape('err.xts', () => crypto.createCipheriv('aes-128-cbc', key, iv, { xtsStandard: 'GB' }));
  shape('err.notmult', () => {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    cipher.setAutoPadding(false);
    cipher.update(Buffer.alloc(17));
    cipher.final();
  });
  shape('err.baddecrypt', () => {
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    decipher.update(Buffer.alloc(16, 0xff));
    decipher.final();
  });
  shape('err.secondfinal', () => {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    cipher.update(Buffer.alloc(16));
    cipher.final();
    cipher.final();
  });
  shape('err.getauthtag.cbc', () => {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    cipher.getAuthTag();
  });
}

process.stdout.write(`${out.join('\n')}\n`);

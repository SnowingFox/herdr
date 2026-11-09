# rn-bind-buffer

`internalBinding('buffer')` for rustnode.

`lib/buffer.js` and `lib/internal/buffer.js` are unchanged Node code and between
them read all 40 members `Initialize()` in `src/node_buffer.cc` installs. This
crate is that native layer. Nothing is deferred.

## Member map

| Group | Members | Where |
| --- | --- | --- |
| Decode | `asciiSlice`, `base64Slice`, `base64urlSlice`, `latin1Slice`, `hexSlice`, `ucs2Slice`, `utf8Slice` | `encoding::slice` |
| Encode | `base64Write`, `base64urlWrite`, `hexWrite`, `ucs2Write`, `asciiWriteStatic`, `latin1WriteStatic`, `utf8WriteStatic` | `encoding::write` |
| Lengths | `byteLengthUtf8`, `byteLengthUtf8Fast`, `stringLengthUtf8` | `encoding` |
| Predicates | `isUtf8`, `isAscii`, `isLatin1` | `encoding` |
| Bytes | `compare`, `compareOffset`, `copy`, `fill`, `indexOfBuffer`, `indexOfNumber`, `indexOfString`, `swap16`, `swap32`, `swap64`, `mask` | `bytes` |
| Misc | `atob`, `btoa`, `setBufferPrototype`, `setDetachKey`, `createUnsafeArrayBuffer`, `copyArrayBuffer`, `arrayBufferAlignedOffset`, `kMaxLength`, `kStringMaxLength` | `misc` |

The byte arithmetic those members sit on — hex, base64, UTF-8 and UCS-2
conversion, byte search — is in `codec` and has no V8 types, so it is
unit-tested directly.

## Where simdutf is used

`isUtf8`, `isAscii`, `atob`, `btoa` and the UTF-8/UTF-16 length calculations
call the same simdutf functions Node calls, through the `v8` crate's
`v8::simdutf` module. That module wraps the copy of simdutf already compiled
into V8, so using it adds no dependency artifact and no second implementation
of the validation rules.

This matters for more than tidiness:

* `isUtf8` must reject overlong encodings, surrogate code points and truncated
  sequences exactly as `simdutf::validate_utf8` does. A hand-rolled validator is
  easy to get subtly wrong around the `E0`/`ED`/`F0`/`F4` continuation ranges,
  which are exactly the cases `tests/parity.json` covers.
* `atob` needs simdutf's strict `base64_default` decoder, which is *not* the
  forgiving decoder `Buffer.from(s, 'base64')` uses. `atob('a-_h')` throws while
  `Buffer.from('a-_h', 'base64')` decodes, and both behaviours have to exist in
  the same crate.

Everything else is written out here. No dependency was added beyond `v8`, which
the crate needed for simdutf and which `rn-v8-sys` already re-exports.

## Behaviour worth knowing

Three of Node's conversions look like bugs until the C++ is read:

* **`ascii` masks with `0x7f` on decode.** `StringBytes::Encode` runs
  `nbytes::ForceAscii`, i.e. `src[i] & 0x7f`, so `0x80` decodes to `\u0000` and
  `0xff` to `\u007f`. On *encode* there is no mask; `StringBytes::Write` just
  casts each code unit to a byte.
* **`utf8` decode replaces one U+FFFD per *maximal subpart*.** `0xE2 0x82`
  (truncated) is one replacement character; `0xED 0xA0 0x80` (a surrogate
  half encoded in UTF-8) is three, one per byte, because the `ED` continuation
  range fails. `codec::utf16_units_from_invalid_utf8` is
  `Utf16LengthFromInvalidUtf8` from `node_buffer.cc` transcribed, and
  `codec::decode_utf8_lossy` is pinned to agree with it.
* **`fill` splits characters and `write` does not.** `Buffer.alloc(3).fill('😀')`
  is `f0 9f 98`, because `Fill` encodes once and `memcpy`s; `Buffer.alloc(3)
  .write('😀')` is 0 bytes, because `WriteUtf8V2` stops at a character
  boundary. `bytes::encode_fill_pattern` and `encoding::encode_units` differ for
  that reason.

`ucs2` is little-endian on every platform: `StringBytes` byte-swaps on
big-endian hosts so the documented layout holds, which is why `codec` writes
`to_le_bytes` unconditionally.

## Deliberate deviations

1. **`byteLengthUtf8Fast` returns the real length**, not Node's `-1` sentinel.
   In Node the fast-API callback's slow fallback returns `-1` unconditionally so
   `lib/buffer.js` re-calls `byteLengthUtf8`; the JS is `length === -1 ?
   byteLengthUtf8Slow(string) : length`, so a correct length is equally valid
   and saves a call.
2. **`arrayBufferAlignedOffset` computes the real padding.** Node's C++ returns
   `0` while building a snapshot (so a serialized buffer does not bake in this
   process's addresses), and the real offset otherwise. rustnode has no snapshot
   path, so the real offset is always correct here.
3. **`createUnsafeArrayBuffer` always uses an uninitialised backing store** for
   non-zero sizes. Node falls back to a zeroed buffer for `size == 0` and when
   `--zero-fill-buffers` is set; the zero-size case is handled and the flag does
   not exist yet.
4. **`setBufferPrototype` stores the prototype in a thread-local**, because
   rustnode has no `Realm` object. `node_buffer.cc` puts it on the `Realm`; when
   `rn-core` grows one this should move there. `misc::buffer_prototype()` reads
   it back for whoever constructs a Buffer natively.
5. **`swap*` throws a `RangeError`** where Node throws
   `ERR_INVALID_BUFFER_SIZE`. The error-code registry is owned by another crate;
   the message text matches.
6. **`copyArrayBuffer` returns the number of bytes copied** where the C++
   `CHECK_EQ`s it to the requested count. A short copy is a programming error on
   the JS side (`assert(canCopyArrayBuffer(...))` guards every call), and
   reporting it beats aborting the process.

## Tests

`cargo test -p rn-bind-buffer` runs two suites:

* **31 unit tests** in `src/**`, exercising the codec and each module's helpers
  directly. No isolate needed.
* **1 integration test** in `tests/binding.rs` that installs the namespace into a
  real V8 isolate and drives it through the exact call sequences
  `lib/internal/buffer.js` and `lib/buffer.js` use.

The integration test's expectations come from `tests/parity.json`, which is
generated by `tools/buffer-parity.mjs` against a real `node` binary:

```bash
node crates/rn-bind-buffer/tools/buffer-parity.mjs > crates/rn-bind-buffer/tests/parity.json
```

196 recorded cases, every one expressed against the *public* `Buffer` API so the
file can be reviewed and regenerated. 195 of them are asserted directly; the
last is `arrayBufferAlignedOffset`'s contract, which has no public-API oracle
and is checked structurally instead (the offset must be less than the alignment,
and a view created at that offset must report that `byteOffset`). They cover:

* all seven decode encodings over a byte pattern that exercises the `0x7f` mask
  and the high bit,
* multi-byte UTF-8 split at every position of a 2-byte and a 4-byte character,
  plus overlong, surrogate and truncated sequences,
* base64/base64url padding for input lengths 0 through 7,
* 22 write cases including odd-length hex, invalid hex digits, unpadded and
  whitespace-containing base64, and truncation that must not split a character,
* 15 fill cases including numbers, Buffers and multi-byte values into
  odd-length windows,
* `compare`, `compare` over sub-ranges, `indexOf`/`lastIndexOf` for numbers,
  strings and Buffers including negative offsets and empty needles, and `ucs2`
  lookups,
* `swap16`/`swap32`/`swap64` on lengths that are and are not multiples of the
  word size,
* `byteLengthUtf8`, `stringLengthUtf8`, `isUtf8`/`isAscii` over overlong and
  surrogate sequences, and `isLatin1`,
* `atob`/`btoa` including the cases where they diverge from `Buffer.from`,
* `mask` against a reference XOR, in both the separate and in-place forms.

Node 22 has no `Buffer.isUtf8`, no `Buffer.isAscii` and no
`ArrayBuffer.prototype.detach`, so those three oracles are a fatal
`TextDecoder`, the documented "every byte < 0x80", and a V8-side check
respectively. `tools/buffer-parity.mjs` says so where it applies them.

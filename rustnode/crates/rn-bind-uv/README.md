# rn-bind-uv

`internalBinding('uv')` for rustnode.

This is the namespace every other part of the standard library stands on.
`lib/internal/errors.js` reads it lazily on the first error it builds
(`lazyUv`, `uvErrmapGet`) and both `lib/internal/util.js` and `lib/util.js`
reach it the same way, so `require('internal/util')` fails outright until this
exists. Everything above `internal/util` — `buffer`, `fs`, `net`, `stream`,
`events` — inherits that dependency.

## Members

96 members, exactly `contracts/uv.json`, which is what `src/uv.cc`'s
`Initialize()` registers:

| member | kind | behaviour |
| --- | --- | --- |
| `UV_E2BIG` … `UV_EXDEV` | 85 numbers | one per `UV_ERRNO_MAP` entry, `ReadOnly \| DontDelete` |
| `UV_DIRENT_UNKNOWN` … `UV_DIRENT_BLOCK` | 8 numbers | `uv_dirent_type_t`, values 0–7 |
| `errname` | function | `uv_err_name`: the name for a negative code |
| `getErrorMap` | function | `Map<number, [name, message]>` |
| `getErrorMessage` | function | `uv_strerror`: the text for a negative code |

`UV_DIRENT_*` belongs to `constants` in Node as well, but
`lib/internal/vfs/providers/composable.js` destructures all eight out of *this*
namespace and the contract records them here.

## Where the numbers come from

Nothing is transcribed by hand. `tools/generate.py` reads
`tools/uv-headers/uv.h` and `tools/uv-headers/uv/errno.h` — verbatim copies from
the Node revision in `tools/node-pin.toml` — and writes `src/generated.rs`.

```bash
cd rustnode
./crates/rn-bind-uv/tools/generate.py --uv-cc /tmp/node/src/uv.cc
./crates/rn-bind-uv/tools/generate.py --uv-cc /tmp/node/src/uv.cc --check
```

The generator has to be *told* where Node's `src/uv.cc` is, and refuses to run
without it. That file is the count check: the generator compiles uv.cc's own
`uv_errors_map` initializer, including the `V` macro extracted from that file,
and stops if the resulting length differs from the table it parsed. A regex that
matched half of `UV_ERRNO_MAP` therefore fails the run instead of shipping a
namespace with 40 constants. The verified number is also written into the
generated file as `UV_CC_REGISTRATIONS`, and a test asserts `ERRORS.len()` equals
it, so a hand-edited table cannot silently drop a row.

Values resolve through the C preprocessor (`cc -E -dM`), not by evaluating
`#if defined(...)` chains in Python: `ENOTSUP` is `EOPNOTSUPP` on glibc, `ECHARSET`
and `EFTYPE` have no glibc spelling at all and fall through to libuv's literal
`(-4080)`/`(-4028)` branch, and `UV__ERR(x)` is `-(x)`. All three cases are
decided exactly as the compiler decides them.

## Why not link libuv

`uv_strerror` and `uv_err_name` are what Node calls, so calling them directly is
the obvious approach. It was rejected:

- It adds a C library that is built and shipped on every platform, into a
  workspace whose only current bindings are `libc`. `rn-io` describes libuv
  semantics as its target but links nothing today.
- The strings would be identical anyway: libuv generates its `uv_strerror`
  switch from `UV_ERRNO_MAP` in the same header this crate vendors. A table and
  a linked call cannot disagree unless the headers disagree.
- A table is checkable offline. `tests/constants.rs` parses the headers again at
  test time and recomputes all 85 values, and compares the 67 syscall-mapped
  ones against `libc` as a third opinion. A linked call would only prove that
  libuv works.

## `errname` does not abort

`src/uv.cc` opens both `ErrName` and `GetErrMessage` with `CHECK_LT(err, 0)`, so
`binding.errname(0)` kills the process. rustnode returns libuv's own output for
that input (`Unknown system error 0`) instead. Nothing in `lib/**` can reach it:
`util.getSystemErrorName` range-checks in JavaScript first and reads the map, not
this function. The difference is only reachable from user code that crashed under
Node.

## Tests

22 tests, `cargo test -p rn-bind-uv`.

`tests/constants.rs` re-derives the table from the headers:

- `UV_ERRNO_MAP` parsed again, compared entry for entry (name and message)
- every `UV__<NAME>` resolved again, honouring the `#if defined` guards
- all 67 `UV__ERR(SYM)` entries checked against `libc::SYM`, so `UV_ENOENT` must
  be `-libc::ENOENT`
- `ERRORS.len() == UV_CC_REGISTRATIONS`
- `UV_DIRENT_*` parsed from the enum

A deliberately wrong value (`UV_ENOENT = -99`) fails four of these and the
message names the constant; a deliberately dropped row fails four more.

`tests/binding.rs` drives a real V8 isolate and checks what
`lib/internal/errors.js` actually depends on: `getErrorMap()` is a `Map` with one
entry per error keyed by number with `[name, message]` values, a fresh `Map` per
call (so `uvBinding.errmap` caching cannot leak mutations), `errname` and
`getErrorMessage` returning the exact libuv strings including the
`Unknown system error N` fallback, `ReadOnly | DontDelete` on every constant,
`Object.keys()` order, and the `SetConstructorFunction` vs `SetMethod` difference
(only `errname` is constructible and has a `prototype`).

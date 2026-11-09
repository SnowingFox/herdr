# rn-bind-cjs-lexer

`internalBinding('cjs_lexer')` for rustnode — one member, `parse(source)`, and it
is what unblocks `require('module')`.

`lib/internal/modules/esm/translators.js` destructures `parse` at module scope:

```js
const { parse: cjsParse } = internalBinding('cjs_lexer');
```

so before this namespace existed, `require('module')` threw
`internalBinding('cjs_lexer'): the namespace has no Rust implementation yet`
before any of its exports could be touched. The answer `parse` produces also
outlives that call: it is the export list an ESM `import` of a CommonJS file
observes, so a wrong answer is not an error anywhere — it is just a different
module.

## What is installed

| member | shape |
| --- | --- |
| `parse(source)` | `[Set<string>, Array<string>]` |

From `contracts/cjs_lexer.json`: one function member, nothing deferred.

`[0]` is the set of names the module statically defines as exports. `[1]` is the
module specifiers of reexports, `require('./other')` in `module.exports`.

A missing argument, `null`, `undefined`, and any source that does not parse as
CommonJS all return a fresh `[new Set(), []]` and never throw. Only a non-string
argument throws (`TypeError`), where Node `CHECK`s and aborts the process.

## The lexer is merve, not a reimplementation

`vendor/merve` is `deps/merve` copied byte-identical from the pinned Node
revision. It is compiled by `build.rs` as one C++20 translation unit and called
through its own `extern "C"` surface, so no `std::vector`, `std::variant` or
`std::string_view` is ever mirrored in Rust.

The rules are subtle enough that an approximation agrees with itself and
disagrees with Node. Every one of these was recorded from a real binary
(`tests/record.cjs`, pinned in `tests/node_expected.json`) and several are the
opposite of the obvious guess:

| source | exports | why |
| --- | --- | --- |
| `exports.x = 1;` | `x` | the plain form |
| `module.exports.z = 42;` | `z` | same, through `module.exports` |
| `exports.a.b = 1;` | — | the assignment lands on `a`, not the module |
| `module.exports = {a, b};` | `a`, `b` | shorthand only |
| `module.exports = { a: 1 };` | — | a named property is not an export statement |
| `module.exports = { a, b: 2, c };` | `a` | mixed: only the shorthand names count |
| `exports['quoted'] = 1;` | `quoted` | bracket form |
| `exports['\u0061b'] = 1;` | `ab` | escaped names are unescaped |
| `Object.defineProperty(exports, 'd1', { value: 1 })` | `d1` | carries a value |
| `Object.defineProperty(exports, 'd3', { get() {…} })` | — | a getter is not a static name |
| `Object.defineProperty(exports, "__esModule", …)` | `__esModule` | it *is* reported |
| `var exports = {}; exports.nope = 1;` | `nope` | the analysis is textual, not scoped |

Reexports produce specifiers rather than names, because the names live in the
other module:

| source | reexports |
| --- | --- |
| `module.exports = require('./other');` | `./other` |
| `module.exports = { ...require('./spread'), own: 1 };` | `./spread` |
| `__export(require('./z'));` | `./z` |
| `Object.keys(require('./k')).forEach(…)` | — |

ESM syntax anywhere — `import`, `export`, `import.meta` — fails the analysis,
and so do unterminated literals and unbalanced brackets. Node reports every one
of those as the same empty pair, so the distinction only exists inside
[`ffi`](src/ffi.rs).

## One thing that will bite a port

merve's scanner seeds `pos = source - 1` and loops `while (pos++ < end)`, so the
final iteration reads `source[len]` — one byte past the input. Node satisfies
that because `Utf8Value` always zero-terminates. A Rust `&str` does not: an empty
`String`'s `as_ptr()` is a dangling `0x1` (immediate segfault), and a non-empty
one reads whatever heap byte follows (usually harmless, always undefined).

`ffi::parse_commonjs` therefore copies the source into a `Vec` with an explicit
trailing NUL and passes that, which is the shape Node hands merve. The handle
borrows the buffer, so the borrow checker enforces that every name is read out
before the buffer goes away.

## Updating

Replace the four files under `vendor/merve` from a newer `deps/merve`, record the
commit in `vendor/merve/README.md`, and regenerate `vendor/merve/MERVE.sha256`.
`tools/verify-merve.sh` is in the gate and fails when the vendored tree no longer
matches the pin. There is no patch file because there is no patch.

## Testing

```bash
cargo test -p rn-bind-cjs-lexer
```

`src/tests.rs` has two layers. The `merve` module drives the linked lexer
directly, which is where a vendoring or build mistake shows up. The `binding`
module installs the namespace into a real isolate and calls `parse` as
JavaScript, covering the `[Set, Array]` shape, the argument handling, and that
export names are internalized. `every_recorded_case_matches_node` compares all 26
recorded cases against `tests/node_expected.json` and fails when the case list
and the recording disagree about which cases exist.

To re-record after a Node bump:

```bash
node --expose-internals tests/record.cjs > tests/node_expected.json
```

The recording was made with `v27.0.0-alpha.0.0.0`, the version
`tools/node-pin.toml` names as `recorder_version`, because Node 28 has no
published binary yet.

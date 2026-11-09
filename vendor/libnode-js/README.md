# Node's builtin JavaScript, as vendored by rustnode

Two trees are copied byte-identical from the Node revision pinned in
`tools/node-pin.toml` (`f344e7f552e`, which reports itself as 28.0.0):

    lib/**                    435 .js files, Node's own builtin layer
    deps/undici/undici.js     1 .js file, the `deps_files` entry lib/** requires

`LIBJS.sha256` records the SHA-256 of every file in both trees, keyed by the
path Node's js2c sees (`lib/fs.js`, `deps/undici/undici.js`). That is what
`sha256sum -c` verifies, so `tools/verify-libjs.sh`, `rn-js2c`'s build script and
`crates/rn-js2c/tests/builtins.rs` all check the same fact from one file.

`LICENSE` is Node's, copied from the same revision.

## Why `deps/` is vendored at all

Node's `tools/js2c.cc` embeds two sets of files: `lib/**`, which it globs, and an
explicit `deps_files` list from `node.gyp`. `lib/**` requires the second set by
builtin id, so a build that embeds only `lib/**` cannot load those modules:

    lib/internal/process/pre_execution.js   require('internal/deps/undici/undici')
    lib/internal/wasm_web_api.js           require('internal/deps/undici/undici')
    lib/internal/worker/io.js              require('internal/deps/undici/undici')
    lib/internal/webworker.js              require('internal/deps/undici/undici')
    lib/http.js                            require('internal/deps/undici/undici')
    lib/internal/bootstrap/web/exposed-window-or-worker.js
                                           require('internal/deps/undici/undici')

Without it, `require('internal/deps/undici/undici')` throws
`Missing internal module`, and anything that touches `fetch`, `Response`,
`FormData`, `EventSource` or the `wasm_web_api` streaming callback with it.

`deps/undici/undici.js` is a single self-contained esbuild bundle: no external
`require`, no `internalBinding`, ~830 KB and ~19,000 lines. It is vendored
instead of undici's source tree because that is exactly what Node's build
produces and embeds — the source tree's thousands of modules are not builtins
and shipping them would reproduce a different artifact than Node runs.

`deps/v8/tools/**` and `deps/acorn/**` are also in Node's `deps_files`, and
`lib/internal/repl/*` requires `internal/deps/acorn/acorn/dist/acorn`. They are
**not** vendored yet, so `internal/repl` remains unreachable from rustnode. That
is a separate gap from the one this tree closes, and it is visible rather than
silent: the id has no entry in the table, so `require` throws `Missing internal
module` naming it.

## Why the counts are separate

`[counts]` in `tools/node-pin.toml` records `builtin_files = 435` and
`deps_files = 1`, and `rn-js2c` enforces each against its own tree.

A single total over both trees would be weaker than it looks: if `lib/` lost a
file and `deps/` gained one, the sum would still be 436 and every check would
pass while the embedded table had drifted from what Node's js2c would produce.
The two trees are separate inputs to js2c, so they stay separate counts.

## Updating

Re-copy both trees from the newer Node checkout, regenerate `LIBJS.sha256` over
`lib/**` and `deps/**`, and update `commit` and both counts in
`tools/node-pin.toml` — all in one commit. `TABLE_DIGEST` in
`crates/rn-js2c/tests/builtins.rs` fails with the new value to paste.

Regenerate the manifest in a way that keeps the existing `lib/` lines
byte-identical where they have not changed, so a re-pin's diff shows only the
files that actually moved:

```bash
cd vendor/libnode-js
find lib deps -name '*.js' -type f | sort | xargs sha256sum > LIBJS.sha256
```

`tools/verify-libjs.sh` checks the result and prints both counts.

# llhttp, as vendored by Node

`include/llhttp.h` and the three files in `src/` are copied byte-identical from
`deps/llhttp` in the Node revision pinned in `tools/node-pin.toml`
(`f344e7f552e`, which reports itself as 28.0.0). llhttp is version 9.4.3 there.

    deps/llhttp/LICENSE
    deps/llhttp/include/llhttp.h
    deps/llhttp/src/api.c
    deps/llhttp/src/http.c
    deps/llhttp/src/llhttp.c

MIT licensed; see `LICENSE`.

## Why the C rather than a Rust parser

HTTP request parsing is a security surface. Node's parser is a generated state
machine with years of hardening behind it, and the failure mode of a
hand-written replacement is request smuggling: two parsers disagreeing about
where a request ends. rustnode's thesis is that only the *native glue* is
rewritten, so the parser stays C and this project owns only
`crates/rn-bind-http-parser/shim/rn_llhttp.c`.

## Updating

Replace all four files from a newer Node checkout and update this file with the
new commit. `tools/verify-llhttp.sh` checks that the vendored tree still matches
the pin, so an accidental local edit fails the gate instead of silently changing
parse behaviour.

`rn_llhttp.c` is the only file here that may be edited, and it should need
editing only when llhttp's public API changes.

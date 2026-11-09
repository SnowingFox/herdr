# gen-options.py

Generates `crates/rn-bind-options/src/table.rs`: Node's command-line option
table, extracted from `src/node_options.cc` and `src/node_options.h`.

## Why generated

The `options` binding is almost entirely a 251-entry table. Every
`AddOption(...)` call carries a name, help text, an overload that selects the
option's type, an `OptionEnvvarSettings`, optionally a `default_is_true` hint,
and a namespace. The default value for each option lives in the field the call
binds, in a different file.

Hand-transcribing that is a silent-drift machine: a typo in a help string or a
wrong `env_setting` produces a working build whose `--help` output or
`process.allowedNodeEnvironmentFlags` quietly disagrees with Node. So the table
is extracted and committed. A normal `cargo build` never needs a Node checkout.

## Regenerate

```bash
python3 tools/gen-options.py --node-src /path/to/node
python3 tools/gen-options.py --node-src /path/to/node --check   # diff only
```

The Node checkout must be the revision in `tools/node-pin.toml`. `--check`
exits 1 when the committed file is stale, which is what a CI job with a Node
checkout should run.

## What is extracted, and from where

| Source | Extracted |
| --- | --- |
| `src/node_options.cc` | every `AddOption` / `AddAlias` call, in source order, with the parser constructor it appears in |
| `src/node_options.h` | each options struct's field declarations: the C++ type selects `OptionType`, the initializer is the default |
| `src/node_constants.h` | `DEFAULT_CIPHER_LIST_CORE`, the default of `--tls-cipher-list` |

The parser constructor identifies the struct (`DebugOptions`,
`EnvironmentOptions`, `PerIsolateOptions`, `PerProcessOptions`), which is what
maps a `BOOL_FIELD(foo)` or `&Struct::bar` argument to a declared field. Field
types then decide the option type without a second hand-written list:
`uint64_t Options::*` selects the `kUInteger` overload, `int64_t` `kInteger`,
and so on.

## The preprocessor pass

Options live inside `#if` blocks, so the extractor has to evaluate them. The
macro configuration at the top of the script describes **one concrete Node
build** — the default `./configure && make` on Linux x64 that rustnode
targets — and every entry states where its value comes from. In particular
`HAVE_FFI=1` (configure enables bundled libffi on x64/arm64) and `HAVE_DTLS=0`
(opt-in only) decide whether `--experimental-ffi`, `--allow-ffi` and
`--experimental-dtls` appear at all.

Deliberately absent from the script: any attempt to discover these from the
local machine. A generator that changes its output based on who runs it makes
the committed file unreviewable.

## Guarding against a silent short parse

Two counts are emitted next to the table:

* `SOURCE_ADD_OPTION_SITES` — raw `AddOption(` occurrences in the file.
* `PARSED_OPTION_COUNT` — entries that survived preprocessing.

`crates/rn-bind-options/src/values.rs` asserts both equal `OPTIONS.len()`, plus
that every name is unique and every type and env setting is in range. A parser
change that drops a call fails `cargo test` instead of shipping a table that is
merely smaller than Node's.

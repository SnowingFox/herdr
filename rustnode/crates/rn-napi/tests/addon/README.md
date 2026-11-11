# Node-API headers, pinned

The four headers here are copied verbatim from the Node revision this project
targets, `f344e7f552e` (`tools/node-pin.toml`):

| File | Upstream path |
| --- | --- |
| `node_api.h` | `src/node_api.h` |
| `node_api_types.h` | `src/node_api_types.h` |
| `js_native_api.h` | `src/js_native_api.h` |
| `js_native_api_types.h` | `src/js_native_api_types.h` |

## Why they are vendored rather than taken from the system

`addon.c` is compiled by tests and by `tests/negative-control.sh`, and the whole
claim being tested is that an addon built against *this* project's target ABI
loads. Compiling against whichever `node` happens to be installed (`v22.23.4` on
this image, which is two majors behind) would test a different ABI and could pass
while the real one was broken. The headers are also what `rn-napi`'s
`#[repr(C)]` types are asserted against: `abi.rs` compiles a probe against these
files and compares `sizeof`, so a layout error is caught against the real
declarations rather than a restatement of them.

They are not modified. If the Node pin moves, re-copy all four and re-run
`cargo test -p rn-napi`.

## Reproducing the copy

```bash
for file in node_api.h node_api_types.h js_native_api.h js_native_api_types.h; do
  curl -sfL -o "$file" \
    "https://raw.githubusercontent.com/nodejs/node/f344e7f552e/src/$file"
done
```

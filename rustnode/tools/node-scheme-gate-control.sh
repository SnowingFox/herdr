#!/usr/bin/env bash
# Control for the `node:`-scheme builtin gate.
#
# The defect: a `node:`-prefixed id reached the realm's *internal* loader, which
# has no allow-list by design — Node's own internals require gated modules at
# their own scope — so `require('node:quic')` loaded a module
# `BuiltinModule.canBeRequiredByUsers('quic')` reports false for. The schemeless
# branch was already correct (`require('quic')` was `MODULE_NOT_FOUND`), which is
# what narrowed this to one branch of the resolver rather than to a broken policy
# table.
#
# The table prints one row per case with rustnode's outcome, Node's outcome, and
# the expectation the verdict is decided by. The expectation comes from the
# pinned Node 28 sources under `tools/node-pin.toml`, not from either binary:
#
#   * `experimental_quic`, `experimental_dtls`, `experimental_bench` and
#     `experimental_ffi` default to `EXPERIMENTALS_DEFAULT_VALUE`/`HAVE_FFI`,
#     both false, so those ids are withheld with no flags.
#   * `experimental_sqlite` defaults to `HAVE_SQLITE`, which this build sets, and
#     `experimental_vfs` is written `= true` in the pin, so both are exposed.
#   * every entry in `builtinModulePolicies` with `schemeOnly: true` is
#     `MODULE_NOT_FOUND` without the scheme: it never matches a builtin, so the
#     request falls through to a filesystem lookup.
#
# Node's column is printed for comparison and never decides the verdict. The
# node on `PATH` is v22, which predates `node:vfs`, `node:quic`, `node:dtls` and
# `--experimental-ffi`, so it disagrees on exactly the rows that are new in the
# pin. Deciding on it would fail this control for a version difference instead of
# for the defect, and skipping those rows would leave the newest surface
# unmeasured.
#
# `--expose-internals` is used only for the two rows at the end that assert the
# internal loader is still reachable. The defect is about what *user* code can
# reach, so the main table runs with no flags.
#
# Exit codes: 0 every row matched, 1 a row did not match (the runtime behaved
# differently from the pinned expectation), 3 no verdict (the tree did not build
# or rustnode could not be run, so the table says nothing about the runtime).
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

binary="target/debug/rustnode"
rows=0
failures=0

fail() {
  printf 'RESULT: FAIL — %s\n' "$1" >&2
  exit 1
}

# The binary has to come from this tree. `test -x` alone is not enough: a stale
# `target/debug/rustnode` from an older commit reports the *old* resolver, which
# is exactly how a control for this defect could pass against the defect. Touching
# `main.rs` makes the build non-no-op and the mtime comparison proves the
# artifact came from this invocation.
echo "building $binary"
touch crates/rn-cli/src/main.rs
start=$(date +%s)
if ! cargo build -p rn-cli >/tmp/node-scheme-gate-build.log 2>&1; then
  printf 'RESULT: NO VERDICT — the tree did not build; see /tmp/node-scheme-gate-build.log\n' >&2
  exit 3
fi
[ -x "$binary" ] || fail "the build produced no $binary"
binary_mtime=$(stat -c %Y "$binary")
[ "$binary_mtime" -ge "$start" ] ||
  fail "the binary predates this build ($binary_mtime < $start), so the table describes another tree"

node_bin="${NODE_BIN:-$(command -v node || true)}"
if [ -n "$node_bin" ] && ! "$node_bin" --version >/dev/null 2>&1; then
  node_bin=""
fi

# `outcome <binary> <id> [flag...]` prints `LOADS`, the thrown `code`, or
# `UNSUPPORTED` when the runtime rejected the flags outright.
#
# The code is read from `error.code` and nothing else. A message comparison would
# not separate `ERR_UNKNOWN_BUILTIN_MODULE` from #23's `ERR_INVALID_MODULE`, and
# keeping those two apart is half of what this control is for.
outcome() {
  local binary_path="$1" id="$2"
  shift 2
  local output status
  output="$("$binary_path" "$@" -e "
    try { require('$id'); console.log('LOADS'); }
    catch (error) { console.log(String(error && error.code)); }
  " 2>/dev/null)"
  status=$?
  if [ "$status" -ne 0 ] && [ -z "$output" ]; then
    printf 'UNSUPPORTED'
  else
    printf '%s' "${output:-NO_OUTPUT}"
  fi
}

# One row: `check <label> <id> <expected> <node-flag> [rustnode flags...]`
#
# `expected` is the pinned expectation and is the only thing that can fail the
# control. `node-flag` is what Node is given for the same row: the empty string
# means the same flags rustnode got, `-` means the row is not worth asking Node
# about (a flag v22 rejects, or an id it does not have), and any other value is
# used verbatim.
check() {
  local label="$1" id="$2" expected="$3" node_flag="$4"
  shift 4
  local rustnode_out node_out verdict
  rows=$((rows + 1))
  rustnode_out="$(outcome "$binary" "$id" "$@")"
  if [ -z "$node_bin" ]; then
    node_out="absent"
  elif [ "$node_flag" = "-" ]; then
    node_out="not compared"
  elif [ -n "$node_flag" ]; then
    node_out="$(outcome "$node_bin" "$id" "$node_flag")"
  else
    node_out="$(outcome "$node_bin" "$id" "$@")"
  fi
  if [ "$rustnode_out" = "$expected" ]; then
    verdict="ok"
  else
    verdict="MISMATCH"
    failures=$((failures + 1))
  fi
  printf '  %-8s %-38s rustnode=%-26s node=%-26s expected=%s\n' \
    "$verdict" "$label" "$rustnode_out" "$node_out" "$expected"
}

printf '\n== require() with no flags ==\n'
# Withheld: the option is off in a default build, so the id is a builtin the
# table knows and the allow-list refuses.
check "node:quic" node:quic ERR_UNKNOWN_BUILTIN_MODULE "" 
check "node:bench" node:bench ERR_UNKNOWN_BUILTIN_MODULE ""
check "node:dtls" node:dtls ERR_UNKNOWN_BUILTIN_MODULE ""
check "node:ffi" node:ffi ERR_UNKNOWN_BUILTIN_MODULE "-"
# Exposed: the pin defaults these options on. `sqlite` is the regression case,
# because it shares the policy table with `quic` and differs only in its default.
check "node:sqlite" node:sqlite LOADS ""
check "node:vfs" node:vfs LOADS "-"
# Ungated core builtins, which the gate must not touch.
check "node:fs" node:fs LOADS ""
check "node:path" node:path LOADS ""
check "node:assert" node:assert LOADS ""
# Not a builtin at all, but the scheme branch still owes the same code.
check "node:nonexistent" node:nonexistent ERR_UNKNOWN_BUILTIN_MODULE ""
# The schemeless branch, which was correct throughout and is the reference the
# fix was copied from. Every gated id is `schemeOnly`, so the request is a
# filesystem lookup that finds nothing.
check "quic" quic MODULE_NOT_FOUND ""
check "bench" bench MODULE_NOT_FOUND ""
check "dtls" dtls MODULE_NOT_FOUND ""
check "ffi" ffi MODULE_NOT_FOUND "-"
check "sqlite" sqlite MODULE_NOT_FOUND ""
check "vfs" vfs MODULE_NOT_FOUND "-"
check "fs" fs LOADS ""
check "path" path LOADS ""
check "assert" assert LOADS ""

printf '\n== the option value decides, not the policy table ==\n'
check "--no-experimental-sqlite node:sqlite" node:sqlite ERR_UNKNOWN_BUILTIN_MODULE "" --no-experimental-sqlite
check "--experimental-bench node:bench" node:bench LOADS "" --experimental-bench
check "--no-experimental-vfs node:vfs" node:vfs ERR_UNKNOWN_BUILTIN_MODULE "-" --no-experimental-vfs
check "--experimental-vfs node:vfs" node:vfs LOADS "-" --experimental-vfs
check "--experimental-quic node:quic" node:quic LOADS "" --experimental-quic

printf '\n== the realm loader is still reachable for the ids only it serves ==\n'
# `internal/bootstrap/realm` is the one id `realm.js` keeps out of the list the
# CJS loader consults, so it has to come from the realm loader. If the scheme
# branch stopped falling back to it, this would break and the fix would have
# traded one defect for a larger one.
check "--expose-internals internal/bootstrap/realm" internal/bootstrap/realm LOADS "-" --expose-internals
check "--expose-internals node:internal/util" node:internal/util LOADS "-" --expose-internals

printf '\n%d row(s) checked, %d mismatch(es)\n' "$rows" "$failures"
if [ "$failures" -ne 0 ]; then
  printf 'RESULT: FAIL — %d row(s) disagreed with the pinned expectation\n' "$failures" >&2
  exit 1
fi
printf 'RESULT: PASS — every row matched the pinned expectation\n'
exit 0

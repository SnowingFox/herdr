#!/usr/bin/env bash
# Regenerates rustnode/contracts/*.json from the vendored Node builtin JS.
#
#     cd rustnode && ./tools/contract-gen/generate.sh
#
# Options:
#   --node <path>   Node binary to record with (default: `node` on PATH)
#   --check         regenerate into a temporary directory and diff instead of
#                   writing; exits 1 when the committed contracts are stale
#
# What it runs:
#   1. record.cjs  - under `--expose-internals`, walks vendor/libnode-js/lib
#                    with acorn and reads every reachable internalBinding
#                    namespace from the running Node. Emits /tmp/recorded.json.
#   2. contract-gen - splits that recording into one contracts/<ns>.json.
#   3. rn-compat   - re-checks the written contracts against the Rust registry.
#
# The pin in tools/node-pin.toml is Node 28. Any Node that can expose internals
# works: `kind`, `arity` and member names are stable across these versions. The
# recording records the producing version in meta.node so a diff is explainable.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

node_bin="node"
mode="write"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node) node_bin="$2"; shift 2 ;;
    --check) mode="check"; shift ;;
    -h|--help)
      sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! command -v "$node_bin" >/dev/null 2>&1 && [[ ! -x "$node_bin" ]]; then
  echo "node not found: $node_bin" >&2
  exit 2
fi

pin_version="$(sed -n 's/^version = "\(.*\)"/\1/p' tools/node-pin.toml | head -1)"
have_version="$("$node_bin" -p 'process.version.replace(/^v/, "")')"
if [[ "$have_version" != "$pin_version" ]]; then
  echo "note: using Node $have_version, pin is $pin_version; shapes are stable across these" >&2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

"$node_bin" --expose-internals tools/contract-gen/record.cjs \
  --lib vendor/libnode-js/lib \
  --pin tools/node-pin.toml \
  --out "$workdir/recorded.json"

if [[ "$mode" == "check" ]]; then
  cargo run --quiet -p contract-gen -- "$workdir/recorded.json" --out "$workdir/contracts"
  if diff -ru contracts "$workdir/contracts"; then
    echo "contracts are up to date"
    exit 0
  fi
  echo "contracts are stale; run ./tools/contract-gen/generate.sh" >&2
  exit 1
fi

cargo run --quiet -p contract-gen -- "$workdir/recorded.json" --out contracts
# Report-only: generation succeeded even when binding crates have not caught up
# yet. CI enforces the strict mode (`rn-compat contracts`) separately.
cargo run --quiet -p rn-compat -- contracts --report

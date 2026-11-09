#!/usr/bin/env bash
# Records the differential fixtures from the pin's reference `node` binary.
#
# The two fixtures this crate's tests compare against are captured, not written
# by hand: `tests/corpus/matches-glob.expected.txt` from
# `internalBinding('glob').matchesGlob`, and `tests/corpus/walk.json` from
# `globSync` over a fixed directory tree. Hand-writing them would only restate
# what the Rust code already believes.
#
# Usage:
#   tools/record-glob-fixtures.sh [path-to-node]
#
# The binary must understand `--expose-internals`, which the v27 recorder build
# named in `tools/node-pin.toml` does.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
node_bin="${1:-node}"
corpus="$root/tests/corpus"

if ! "$node_bin" --expose-internals -e '0' >/dev/null 2>&1; then
  echo "error: $node_bin cannot run with --expose-internals" >&2
  exit 1
fi

echo "recording matchesGlob expectations with $("$node_bin" --version)"
"$node_bin" --expose-internals - "$corpus/matches-glob.txt" \
  "$corpus/matches-glob.expected.txt" <<'JS'
const { internalBinding } = require('internal/test/binding');
const g = internalBinding('glob');
const fs = require('fs');
const [input, output] = process.argv.slice(2);
const lines = fs.readFileSync(input, 'utf8').split('\n');
const recorded = [];
for (const line of lines) {
  if (!line) continue;
  const split = line.indexOf('|');
  const path = line.slice(0, split);
  const pattern = line.slice(split + 1);
  let answer;
  try {
    answer = g.matchesGlob(path, pattern, 0);
  } catch (error) {
    answer = 'THROW:' + error.message;
  }
  recorded.push(JSON.stringify([path, pattern, answer]));
}
fs.writeFileSync(output, recorded.join('\n') + '\n');
JS

echo "walk fixtures are recorded in tests/corpus/walk.json"
echo "re-record them with tools/record-walk-fixtures.js once the tree in"
echo "tests/walk_parity.rs changes"

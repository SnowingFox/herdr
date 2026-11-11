#!/usr/bin/env bash
# Negative control for the per-context globals fix.
#
# Runs the assertions Node's `test/parallel/test-global-domexception.js`,
# `test-domexception-subclass.js`, `test-quotaexceedederror.js` and
# `test-structuredClone-domexception.js` make, against one binary.
#
# Two properties matter and both have cost this project time already:
#
# 1. It **aborts on build failure**. A sibling worker reported a PASS from a stale
#    binary after a build that had failed, so `set -e` plus an explicit existence
#    and freshness check is the only safe shape. The build result is checked
#    directly, and the failure is reported as BUILD FAILED rather than as a
#    passing control.
# 2. It prints **one line per assertion**, so a run that fails at the first
#    difference still says how far it got. A control that reports only "fail"
#    cannot distinguish "the bug is present" from "the harness is broken".
#
# Usage:
#   ./tools/per-context-control.sh            # build, then check
#   ./tools/per-context-control.sh <binary>   # check an existing binary
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

if [ "$#" -ge 1 ]; then
  node="$1"
  if [ ! -x "$node" ]; then
    echo "ABORT: $node is not an executable file" >&2
    exit 2
  fi
else
  # The build result is checked, not inferred from the file existing: a failed
  # build leaves the previous binary in place and would otherwise be tested.
  if ! cargo build -p rn-cli 2>/tmp/per-context-control-build.log; then
    echo "ABORT: BUILD FAILED; not testing a stale binary" >&2
    tail -20 /tmp/per-context-control-build.log >&2
    exit 2
  fi
  node="$root/target/debug/rustnode"
  if [ ! -x "$node" ]; then
    echo "ABORT: the build reported success but $node is missing" >&2
    exit 2
  fi
fi

failures=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    printf 'ok   %-42s %s\n' "$name" "$actual"
  else
    printf 'FAIL %-42s got %q want %q\n' "$name" "$actual" "$expected"
    failures=$((failures + 1))
  fi
}

run() {
  "$node" -e "$1" 2>&1 | tail -n1
}

# --- DOMException is a real Error ------------------------------------------
check "new DOMException('x').toString()" \
  "Error: x" \
  "$(run "console.log(new DOMException('x').toString())")"
check "instanceof Error" \
  "true" \
  "$(run "console.log(new DOMException('x') instanceof Error)")"
check "Object.prototype.toString" \
  "[object DOMException]" \
  "$(run "console.log(Object.prototype.toString.call(new DOMException('x')))")"
check "name / message / code" \
  "SyntaxError x 12" \
  "$(run "const e = new DOMException('x','SyntaxError'); console.log(e.name, e.message, e.code)")"
check "prototype chain reaches Error" \
  "true" \
  "$(run "console.log(Object.getPrototypeOf(DOMException.prototype) === Error.prototype)")"

# --- the messaging binding hands back the same class -----------------------
check "messaging.DOMException === global" \
  "true" \
  "$("$node" --expose-internals -e "const m = require('internal/test/binding').internalBinding('messaging'); console.log(m.DOMException === globalThis.DOMException)" 2>/dev/null | tail -n1)"

# --- the two per-isolate symbols survive a clone ---------------------------
# With `perIsolateSymbols` empty both `[kClone]` and `[kDeserialize]` land on the
# string key "undefined" and the second replaces the first.
check "structuredClone(DOMException) keeps the class" \
  "true true DataCloneError 25" \
  "$(run "const c = structuredClone(new DOMException('t','DataCloneError')); console.log(c instanceof DOMException, c instanceof Error, c.name, c.code)")"

# --- no new enumerable global ---------------------------------------------
check "enumerable global count" \
  "9" \
  "$(run "console.log(Object.keys(globalThis).length)")"

echo
if [ "$failures" -eq 0 ]; then
  echo "PASS: 8 checks"
  exit 0
fi
echo "FAIL: $failures of 8 checks"
exit 1

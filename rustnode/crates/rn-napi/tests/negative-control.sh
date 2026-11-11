#!/usr/bin/env bash
# The negative control for Node-API addon support.
#
# A negative control is a check that must FAIL before the feature exists and PASS
# after. Without one, "the tests pass" only proves the tests agree with the
# implementation; it does not prove they are measuring the feature at all. Two
# failure modes are ruled out here that a normal test cannot rule out:
#
#   1. **A stale binary.** The addon is recompiled from source on every run into a
#      fresh directory, and the build is aborted (`abort()`, not a panic) if `cc`
#      fails, so a run cannot report a result measured against an artifact nobody
#      built. The `--verify-binaries` step re-checks that the `rustnode` binary
#      being tested is the one `cargo` just produced.
#   2. **A feature that already worked.** `--before` mode asserts every check FAILS.
#      Running it against a build without this slice is the way to prove the control
#      is sensitive; running it against the current build must show every check
#      passing.
#
# Usage:
#   tests/negative-control.sh            # assert the control passes (current tree)
#   tests/negative-control.sh --before   # assert the control fails (pre-feature tree)
#   tests/negative-control.sh --verbose  # print each check's output
#
# Exit status is 0 when the expectation holds, 1 when it does not, and 2 when the
# control could not be evaluated at all (a build failure), which is never a pass.

set -uo pipefail

# The script lives in `crates/rn-napi/tests/`, so the crate root is two levels up and
# the Cargo workspace root is two more. `root` is the workspace root, because the
# binary and the `cargo` invocations are relative to it.
script_dir="$(cd "$(dirname "$0")" && pwd)"
crate_dir="$(cd "$script_dir/.." && pwd)"
root="$(cd "$crate_dir/../.." && pwd)"
cd "$root"

mode="after"
verbose=0
override_binary=""
while [ $# -gt 0 ]; do
  case "$1" in
    --before) mode="before"; shift ;;
    --verbose) verbose=1; shift ;;
    # Points the control at a different build. Used to run the `--before` check
    # against a tree that predates the feature: the control has to be evaluated
    # against a binary that genuinely lacks it, and that binary lives somewhere
    # else.
    --binary)
      override_binary="${2:?--binary needs a path}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

# The binding recipe from rustnode/AGENTS.md. Without `CXX` the vendored C++ fails
# to configure, and without the `-L` the linker cannot find libstdc++'s `.so`; both
# have been misreported as a broken tree.
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

binary="$root/target/debug/rustnode"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/rn-napi-control.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

# The addon is built into the scratch directory, never into `target/`, so a previous
# run's artifact can never be picked up. `-Werror` makes a warning a build failure,
# which is stricter than the test harness needs and catches a broken fixture early.
addon="$scratch/addon.node"
echo "== building the test addon from source =="
if ! cc -shared -fPIC -Wall -Wextra -Werror \
      -I "$root/crates/rn-napi/tests/addon" \
      -o "$addon" \
      "$root/crates/rn-napi/tests/addon/addon.c"; then
  echo "FATAL: the test addon failed to build. Refusing to evaluate any check." >&2
  exit 2
fi
if [ ! -f "$addon" ]; then
  echo "FATAL: cc reported success but $addon does not exist." >&2
  exit 2
fi
# The runtime finds the addon through this symbol; a build without it is not an
# addon, and every check below would be measuring the wrong thing.
if ! nm -D --defined-only "$addon" | grep -q "napi_register_module_v1"; then
  echo "FATAL: $addon does not export napi_register_module_v1." >&2
  exit 2
fi

echo "== verifying the binary under test is current =="
binary="${override_binary:-$root/target/debug/rustnode}"
if [ ! -x "$binary" ]; then
  echo "FATAL: $binary does not exist. Run: cargo build -p rn-cli" >&2
  exit 2
fi
# A binary older than the sources it was built from is stale, and a stale binary is
# what produced a false PASS in this project before. The check is skipped for an
# explicit `--binary`, because that build is deliberately from another tree.
if [ -z "$override_binary" ]; then
  newest_source="$(find "$root/crates/rn-napi/src" "$root/crates/rn-bind-process-methods/src" \
                     "$root/crates/rn-cli/src" -name '*.rs' -newer "$binary" -print -quit)"
  if [ -n "$newest_source" ]; then
    echo "FATAL: $binary is older than $newest_source; rebuild before evaluating." >&2
    exit 2
  fi
fi
echo "   binary: $binary"

# Each check is a JS expression whose stdout is compared against an expectation.
# `name | script | expected` — the script runs through `rustnode -e`.
checks=(
  "process.dlopen is a function|console.log(typeof process.dlopen)|function"
  "the addon loads and exports its marker|const a=require('$addon');console.log(a.addonName)|rustnode-test-addon"
  "a native function computes a value|const a=require('$addon');console.log(a.add(2,3))|5"
  "a native function calls back into JS|const a=require('$addon');console.log(a.callWithNativeArgument(t=>'<'+t+'>'))|<from native code>"
  "a missing addon reports ERR_DLOPEN_FAILED|try{process.dlopen({exports:{}},'$scratch/absent.node')}catch(e){console.log(e.code)}|ERR_DLOPEN_FAILED"
  "a non-addon shared object reports no self-registration|const s='$scratch/plain.node';const f='$scratch/plain.c';require('fs').writeFileSync(f,'int x(void){return 1;}');if(require('child_process').spawnSync('cc',['-shared','-fPIC','-o',s,f]).status!==0)throw new Error('fixture');try{process.dlopen({exports:{}},s)}catch(e){console.log(e.code)}|ERR_DLOPEN_FAILED"
)

pass=0
fail=0
for entry in "${checks[@]}"; do
  name="${entry%%|*}"
  rest="${entry#*|}"
  script="${rest%|*}"
  expected="${rest##*|}"
  actual="$(cd "$scratch" && "$binary" -e "$script" 2>&1)"
  if [ "$actual" = "$expected" ]; then
    pass=$((pass + 1))
    [ "$verbose" -eq 1 ] && printf '  PASS  %s\n' "$name"
  else
    fail=$((fail + 1))
    if [ "$verbose" -eq 1 ]; then
      printf '  FAIL  %s\n        expected: %s\n        actual:   %s\n' \
        "$name" "$expected" "$actual"
    fi
  fi
done

echo
echo "checks: $pass passed, $fail failed (${#checks[@]} total)"

# `--before` asserts the control is *sensitive*: on a tree without addon support every
# check must fail. If any check passed there, it is not measuring the feature.
if [ "$mode" = "before" ]; then
  if [ "$pass" -eq 0 ]; then
    echo "BEFORE: correctly failing on every check — the control is sensitive."
    exit 0
  fi
  echo "BEFORE: $pass check(s) passed on a tree without the feature;" >&2
  echo "        those checks are not measuring it." >&2
  exit 1
fi

if [ "$fail" -eq 0 ]; then
  echo "AFTER: every check passes."
  exit 0
fi
echo "AFTER: $fail check(s) failed; the feature is incomplete." >&2
exit 1

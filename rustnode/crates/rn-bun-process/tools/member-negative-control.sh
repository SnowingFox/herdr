#!/usr/bin/env bash
# Proves the members' tests can fail.
#
# Every test in this crate passes against the current implementation, which on its
# own says nothing: a test written after its code is a description, not a guard.
# This puts each defect back, one at a time, rebuilds, and requires the test named
# for it to fail. A mutation that leaves the suite green is reported as the defect
# it is — a test that cannot see the thing it claims to check.
#
# The mutations are all real shapes:
#
#   argv-copy       publish a *copy* of `process.argv` instead of the same array.
#                   An equality test on values passes; the identity assertion is
#                   the only thing that catches it.
#   env-copy        the same for `process.env`, which additionally stops a write
#                   through `Bun.env` reaching a child.
#   color-hex       print the alpha in `hex`, which Bun drops.
#   lab-f64         do the Lab chain in `f64`, which changes the last digits.
#   gc-undefined    return `undefined` from `Bun.gc`, the stub the spec's
#                   invariant would pass.
#   snapshot-object return the `jsc` object for `'v8'`, which fails the return-type
#                   split.
#   spawn-enoent    return a result with `error` set instead of throwing, which is
#                   Node's shape and the silent divergence §6.3 names.
#   udp-arity       check the payload type before the arity, which changes which
#                   message a caller sees.
#
# Usage: ./tools/member-negative-control.sh
set -euo pipefail

# The crate lives at `<rustnode>/crates/rn-bun-process`, so three levels up is
# the workspace root: tools -> rn-bun-process -> crates -> rustnode.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"
export RUSTNODE_BUN_ORACLE="${RUSTNODE_BUN_ORACLE:-/tmp/bun-dl/bun-linux-x64/bun}"

src="crates/rn-bun-process/src"
tests="crates/rn-bun-process/tests"
backup="$(mktemp -d)"
trap 'rm -rf "$backup"' EXIT

# Copies the crate's sources aside so a failed run can be restored exactly.
cp -a "$src" "$backup/src"
cp -a "$tests" "$backup/tests"

restore() {
  rm -rf "$src" "$tests"
  cp -a "$backup/src" "$src"
  cp -a "$backup/tests" "$tests"
}

failures=0

# `expect_failure <name> <test filter>`: runs after the caller has mutated the
# source, and fails this control when the named test does *not* fail.
#
# # Why the CLI is rebuilt first
#
# The differential tests execute `target/debug/rustnode`, which `cargo test -p
# rn-bun-process` does not rebuild: it compiles the crate's lib and test binary and
# leaves the binary the test *spawns* at its previous build. Measured on this
# control's first run: every mutation left its test green, because the test was
# exercising the unmutated binary. That is the "a negative control that runs a
# stale binary is not a control" trap, and the explicit build is the fix.
expect_failure() {
  local name="$1"
  local filter="$2"
  local output status
  set +e
  output="$(cargo build -p rn-cli 2>&1)"
  status=$?
  if [ "$status" -ne 0 ]; then
    set -e
    echo "CONTROL DEFECT: $name failed to build, so no test ran" >&2
    failures=$((failures + 1))
    return 1
  fi
  output="$(cargo test -p rn-bun-process -- "$filter" 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "CONTROL DEFECT: $name left '$filter' green; the test does not check it" >&2
    failures=$((failures + 1))
    return 1
  fi
  # A build failure is not the test failing: it proves nothing about the check.
  if printf '%s' "$output" | grep -q '^error\[E[0-9]'; then
    echo "CONTROL DEFECT: $name failed to compile, so no test ran" >&2
    failures=$((failures + 1))
    return 1
  fi
  echo "ok: $name turns '$filter' red"
  return 0
}

echo "== argv is the same array, not a copy =="
python3 - <<'PY'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/values.rs")
s = p.read_text()
# Publish a copy: the identity assertion is the only check that sees this.
before = '    crate::define_value(scope, target, "argv", argv, Attr::DONT_DELETE)?;'
after = (
    '    let copy_array = v8::Array::new(scope, 0);\n'
    '    if let Ok(source) = v8::Local::<v8::Array>::try_from(argv) {\n'
    '        for index in 0..source.length() {\n'
    '            if let Some(value) = source.get_index(scope, index) {\n'
    '                copy_array.set_index(scope, index, value);\n'
    '            }\n'
    '        }\n'
    '    }\n'
    '    crate::define_value(scope, target, "argv", copy_array.into(), Attr::DONT_DELETE)?;'
)
assert before in s, "the argv mutation did not match; the control is stale"
p.write_text(s.replace(before, after))
PY
expect_failure "argv-copy" "the_process_members" || true
restore

echo "== Bun.env is process.env, not a copy =="
python3 - <<'PY'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/values.rs")
s = p.read_text()
s = s.replace(
    '    crate::define_value(\n        scope,\n        target,\n        "env",\n        env,\n        Attr::READ_ONLY | Attr::DONT_DELETE,\n    )?;',
    '    let env_copy = v8::Object::new(scope);\n    if let Ok(original) = v8::Local::<v8::Object>::try_from(env) {\n        if let Some(names) = original.get_own_property_names(scope, Default::default()) {\n            for index in 0..names.length() {\n                if let Some(key) = names.get_index(scope, index) {\n                    if let Some(value) = original.get(scope, key) {\n                        let _ = env_copy.set(scope, key, value);\n                    }\n                }\n            }\n        }\n    }\n    crate::define_value(\n        scope,\n        target,\n        "env",\n        env_copy.into(),\n        Attr::READ_ONLY | Attr::DONT_DELETE,\n    )?;',
)
p.write_text(s)
PY
expect_failure "env-copy" "the_process_members" || true
restore

echo "== hex drops the alpha, as Bun's does =="
python3 - <<'PY'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/color.rs")
s = p.read_text()
before = '            &format!("#{:02x}{:02x}{:02x}", rgba.red, rgba.green, rgba.blue),'
after = '            &format!("#{:02x}{:02x}{:02x}{:02x}", rgba.red, rgba.green, rgba.blue, rgba.alpha),'
assert before in s, "the hex mutation did not match; the control is stale"
p.write_text(s.replace(before, after))
PY
expect_failure "color-hex" "the_color_members" || true
restore

echo "== lab is Bun's matrix chain, not an approximation =="
python3 - <<'PY_MUTATION'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/color.rs")
s = p.read_text()
# Replace the W3C sRGB -> XYZ matrix with the rounded one from an older draft.
# A different matrix is the real defect this test exists to catch; changing the
# *precision* of the same matrix does not move the `f32` result, which was
# measured, so that is not a mutation but an equivalent program.
s = s.replace(
    "        0.41239079926595934,\n        0.357584339383878,\n        0.1804807884018343,\n        0.21263900587151027,\n        0.715168678767756,\n        0.07219231536073371,\n        0.01933081871559182,\n        0.11919477979462598,\n        0.9505321522496607,",
    "        0.4124,\n        0.3576,\n        0.1805,\n        0.2126,\n        0.7152,\n        0.0722,\n        0.0193,\n        0.1192,\n        0.9505,",
)
p.write_text(s)
PY_MUTATION
expect_failure "lab-matrix" "the_color_members" || true
restore

echo "== Bun.gc returns a real number =="
python3 - <<'PY'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/gc.rs")
s = p.read_text()
s = s.replace(
    '    let used = used.unwrap_or(0);\n    rv.set(v8::Number::new(scope, used as f64).into());',
    '    let _ = used;\n    rv.set(v8::undefined(scope).into());',
)
p.write_text(s)
PY
expect_failure "gc-undefined" "the_gc_and_snapshot" || true
restore

echo "== generateHeapSnapshot keeps the return-type split =="
python3 - <<'PY'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/gc.rs")
s = p.read_text()
s = s.replace(
    '    if v8_format {\n        if want_array_buffer {',
    '    if v8_format {\n        // Mutation: always return the object form.\n        let _ = want_array_buffer;\n        match jsc_object(scope, &json) {\n            Some(object) => rv.set(object.into()),\n            None => rv.set(v8::undefined(scope).into()),\n        }\n        return;\n        #[allow(unreachable_code)]\n        if want_array_buffer {',
)
p.write_text(s)
PY
expect_failure "snapshot-object" "the_gc_and_snapshot" || true
restore

echo "== a missing executable throws =="
python3 - <<'PY_MUTATION'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/spawn.rs")
s = p.read_text()
# Make the unresolvable-name path fall through to `uv_spawn` instead of throwing.
# That is what a Node-shaped implementation does: Node's `spawnSync` returns
# `{error, status: null}`, so a wrapper that reused it would pass every
# success-path test and differ only here. §6.3 names this as the most likely
# silent divergence, which is why the throw has its own test.
before = '    match search_path(program, env) {\n        Some(path) => Ok(path),\n        None => {'
after = '    match search_path(program, env).or_else(|| CString::new(program).ok()) {\n        Some(path) => Ok(path),\n        None => {'
assert before in s, "the spawn mutation did not match; the control is stale"
p.write_text(s.replace(before, after))
PY_MUTATION
# The message test, not the class/code test: `uv_spawn` also reports ENOENT for a
# bare name, so the class and code survive this mutation and only the *message*
# distinguishes "not found in $PATH" from `posix_spawn`. Measured: mutating the
# resolution path leaves `a_missing_executable_throws` green and turns this red.
expect_failure "spawn-enoent" "the_failure_messages_match_bun_verbatim" || true
restore

echo "== udpSocket checks arity before the payload type =="
python3 - <<'PY'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/udp.rs")
s = p.read_text()
# Move the payload check ahead of the arity check.
s = s.replace(
    "    if arity != 3 && !(connected && arity == 1) {\n        throw_type_error(scope, &format!(\"Expected 3 arguments, got {arity}\"));\n        return;\n    }",
    "    if !args.get(0).is_string() && unsafe { crate::udp::view_bytes(args.get(0)) }.is_none() {\n        throw_type_error(scope, \"Expected ArrayBufferView or string as first argument\");\n        return;\n    }\n    if arity != 3 && !(connected && arity == 1) {\n        throw_type_error(scope, &format!(\"Expected 3 arguments, got {arity}\"));\n        return;\n    }",
)
p.write_text(s)
PY
expect_failure "udp-arity" "the_udp_socket" || true
restore

echo "== Bun.version reports the marker, not undefined or a release number =="
python3 - <<'PY'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/version.rs")
s = p.read_text()
# Drop the install call: the property stays declared, so the *registry* refuses
# it, and the differential probe would see `undefined` under a name that exists.
before = '    let version = v8::String::new(scope, COMPAT_MARKER).ok_or("cannot allocate the version")?;\n    crate::define_value(\n        scope,\n        target,\n        "version",\n        version.into(),\n        v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,\n    )?;\n\n'
assert before in s, "the version mutation did not match; the control is stale"
p.write_text(s.replace(before, ''))
PY
expect_failure "version-missing" "the_process_members" || true
restore

echo "== Bun.version is not a bare Bun release number =="
python3 - <<'PY'
import pathlib
p = pathlib.Path("crates/rn-bun-process/src/version.rs")
s = p.read_text()
# The one value that must never ship: it makes `startsWith('1.')` a lie and it
# makes `>= "1.4.4"` claim a release this is not.
before = 'pub const COMPAT_MARKER: &str = "1.4.4-rsnode";'
assert before in s, "the marker mutation did not match; the control is stale"
p.write_text(s.replace(before, 'pub const COMPAT_MARKER: &str = "1.4.4";'))
PY
expect_failure "version-bare-release" "the_marker" || true
restore

echo
if [ "$failures" -ne 0 ]; then
  echo "member negative control: $failures mutation(s) did not turn their test red" >&2
  exit 1
fi
echo "member negative control: every mutation turned its test red"

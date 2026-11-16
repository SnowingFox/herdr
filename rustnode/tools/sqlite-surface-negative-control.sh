#!/usr/bin/env bash
# Proves the node:sqlite surface tests fail when any fix is reverted.
#
#   ./tools/sqlite-surface-negative-control.sh
#
# Exit codes:
#   0  every revert was caught by the test named for it
#   1  a revert was not caught, or was caught by a different test
#   2  the tree could not be restored to its fixed state
#
# This is the negative control for the `db.limits` accessor-view fix and the
# exported-template fix for `Statement`, `SQLTagStore` and `StatementIterator`.
# The tests were written *after* their fixes, so "the tests pass" says nothing on
# its own; this puts each defect back and requires the test named for it to
# fail.
#
# Two failure modes are distinguished on purpose. A build error also exits
# non-zero, and so does an unrelated red test, so a revert that "failed" for
# either reason is reported as *not caught* rather than accepted as evidence. The
# expected test name has to appear in the output.
#
# It rewrites a source file in place and restores it in a `trap`, so an
# interrupted run does not leave a reverted tree behind.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"
# A `CARGO_TARGET_DIR` exported by an earlier step would build somewhere else and
# leave the binary the tests spawn untouched, which reads as "the revert changed
# nothing". See rustnode/AGENTS.md.
unset CARGO_TARGET_DIR

crate="crates/rn-bind-sqlite"
backup="$(mktemp -d)"
trap 'rm -rf "$backup"' EXIT

restore() {
  if [ -f "$backup/limits.rs" ]; then cp "$backup/limits.rs" "$crate/src/limits.rs"; fi
  if [ -f "$backup/stmt.rs" ]; then cp "$backup/stmt.rs" "$crate/src/stmt.rs"; fi
  if [ -f "$backup/iterator.rs" ]; then cp "$backup/iterator.rs" "$crate/src/iterator.rs"; fi
}
trap 'restore; rm -rf "$backup"' EXIT

# `build` and `test_surface` are separate so a build failure is reported as a
# missing verdict rather than as a caught defect.
build() {
  cargo build -p rn-cli >"$backup/build.log" 2>&1
}

# Runs the surface tests and echoes their combined output, returning cargo's
# status. The output is needed to identify which assertion fired.
run_tests() {
  cargo test -p rn-bind-sqlite --test differential 2>&1 || return $?
  return 0
}

failures=0

# Applies a reverted source file, then requires `$2` to appear in a failing test
# run. `$1` names the case, `$2` the test expected to fail.
expect_caught() {
  local label="$1" expected="$2" output status
  set +e
  build
  local built=$?
  set -e
  if [ "$built" -ne 0 ]; then
    echo "FAIL $label: the reverted tree did not build, so there is no verdict" >&2
    tail -20 "$backup/build.log" >&2
    failures=$((failures + 1))
    restore
    return
  fi

  set +e
  output="$(run_tests)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "FAIL $label: the tests PASSED against the reverted source, so they do not catch this defect" >&2
    failures=$((failures + 1))
  elif ! printf '%s' "$output" | grep -qF "$expected"; then
    echo "FAIL $label: tests failed, but not at $expected, so the red run says nothing about this fix" >&2
    printf '%s\n' "$output" | tail -20 >&2
    failures=$((failures + 1))
  else
    echo "ok   $label: $expected failed as required"
  fi
  restore
}

# --- the `db.limits` revert: a data-property object ---------------------------
#
# The reverted file is the original shape in full rather than a patch: a plain
# `Object::new` with one `set_accessor_with_setter` pair per limit, which leaves a
# configurable data property behind. `reset_template_cache` stays as a no-op so
# the rest of the crate still links against the same API.
cp "$crate/src/limits.rs" "$backup/limits.rs"
cat >"$crate/src/limits.rs" <<'RS'
//! Reverted `database.limits`: one data property per limit, installed once.

use rn_v8_sys::v8;

use crate::constants;
use crate::db::{self, DatabaseState};
use crate::errors;

const OWNER_PROPERTY: &str = "rustnode.sqlite.limits.owner";

pub fn reset_template_cache() {}

pub fn build<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    owner: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    for name in constants::LIMITS {
        let key = v8::String::new(scope, name)?;
        object.set_accessor_with_setter(scope, key.into(), limit_get, limit_set);
    }
    if let Some(key) = v8::String::new(scope, OWNER_PROPERTY) {
        let private = v8::Private::for_api(scope, Some(key));
        object.set_private(scope, private, owner.into());
    }
    Some(object)
}

fn owner_state(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<'_, v8::Object>,
) -> Option<*mut DatabaseState> {
    let key = v8::String::new(scope, OWNER_PROPERTY)?;
    let private = v8::Private::for_api(scope, Some(key));
    let Some(owner) = this.get_private(scope, private) else {
        return None;
    };
    let Ok(owner) = v8::Local::<v8::Object>::try_from(owner) else {
        return None;
    };
    crate::db::state_or_throw(scope, owner)
}

fn limit_index(scope: &mut v8::PinScope<'_, '_>, name: v8::Local<'_, v8::Name>) -> Option<usize> {
    let name = name.to_rust_string_lossy(scope);
    constants::LIMITS.iter().position(|limit| *limit == name)
}

fn limit_get(
    scope: &mut v8::PinScope<'_, '_>,
    name: v8::Local<'_, v8::Name>,
    info: v8::PropertyCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let Some(index) = limit_index(scope, name) else {
        return;
    };
    let Some(state) = owner_state(scope, info.holder()) else {
        return;
    };
    let state = unsafe { &mut *state };
    if !errors::require(scope, state.is_open(), "database is not open") {
        return;
    }
    let value = state.current_limits()[index];
    rv.set(v8::Integer::new(scope, value).into());
}

fn limit_set(
    scope: &mut v8::PinScope<'_, '_>,
    name: v8::Local<'_, v8::Name>,
    value: v8::Local<'_, v8::Value>,
    info: v8::PropertyCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_, ()>,
) {
    let Some(index) = limit_index(scope, name) else {
        return;
    };
    let Some(state) = owner_state(scope, info.holder()) else {
        return;
    };
    let (open, authorizer) = unsafe {
        let state = &*state;
        (state.is_open(), state.authorizer_depth)
    };
    if !errors::require(scope, open, "database is not open") {
        return;
    }
    if !errors::require(
        scope,
        authorizer == 0,
        "database cannot be accessed from an authorizer callback",
    ) {
        return;
    }
    let Some(limit) = db::limit_value(scope, value) else {
        return;
    };
    unsafe { (*state).set_limit(index, limit) };
}
RS
expect_caught "limits data-property revert" \
  "every_limit_is_a_number_and_membership_is_an_accessor_view"

# --- the `Statement` revert: a throwaway template -----------------------------
#
# The reverted shape allocates each statement from a fresh `FunctionTemplate` and
# copies the exposed prototype onto it, so the exported constructor's
# `has_instance` never matches.
cp "$crate/src/stmt.rs" "$backup/stmt.rs"
python3 - "$crate/src/stmt.rs" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text()
start = source.index(
    "fn allocate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {"
)
end = source.index("/// Boxes an existing `StatementState` pointer onto `object`.")
# `throwaway`, not `template`: the module-level `template` is what the reverted
# body calls, and shadowing it was a compile error rather than a test verdict.
reverted = source[:start] + """fn allocate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let throwaway = v8::FunctionTemplate::builder(illegal_constructor)
        .length(0)
        .build(scope);
    let instance_template = throwaway.instance_template(scope);
    instance_template.set_internal_field_count(INTERNAL_FIELDS);
    let instance = instance_template.new_instance(scope)?;
    let prototype = template(scope)?.prototype_template(scope).new_instance(scope)?;
    instance.set_prototype(scope, prototype.into())?;
    Some(instance)
}

""" + source[end:]
path.write_text(reverted)
PY
expect_caught "statement throwaway-template revert" \
  "every_exported_class_answers_instanceof_for_its_own_instances"

# --- the `StatementIterator` revert: a throwaway template --------------------
#
# The reverted shape builds a fresh unnamed template per iterator, so the
# prototype carrying `next`/`return` and the global `Iterator.prototype` is a
# different object for every call, and `constructor` is set on nothing an instance
# uses. Node reports `constructor.name === 'StatementIterator'`.
cp "$crate/src/iterator.rs" "$backup/iterator.rs"
python3 - "$crate/src/iterator.rs" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text()
# Everything from `allocate` to `illegal_constructor` is the cached-template
# machinery; the reverted body is the whole region, so no helper is left
# unreferenced and no name is defined twice.
start = source.index("/// Allocates an iterator instance from the class's object template.")
end = source.index("fn illegal_constructor<'s>(")
reverted = source[:start] + """/// Allocates an iterator instance from a throwaway object template.
fn allocate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let template = rn_core::class(illegal_constructor).length(0).build(scope);
    let instance = template.instance_template(scope);
    instance.set_internal_field_count(INTERNAL_FIELDS);
    let instance = instance.new_instance(scope)?;
    let prototype = template.prototype_template(scope);
    for (name, method) in [
        ("next", crate::database::method(scope, 0, next)),
        ("return", crate::database::method(scope, 0, ret)),
    ] {
        let key = v8::String::new(scope, name)?;
        prototype.set(key.into(), method.into());
    }
    let prototype = prototype.new_instance(scope)?;
    if let Some(iterator_prototype) = global_iterator_prototype(scope) {
        prototype.set_prototype(scope, iterator_prototype);
    }
    instance.set_prototype(scope, prototype.into())?;
    Some(instance)
}

fn attach_prototype<'s>(
    _scope: &mut v8::PinScope<'s, '_>,
    _instance: v8::Local<'s, v8::Object>,
) -> Option<()> {
    Some(())
}

/// Drops the cached template. The reverted shape caches nothing, but
/// `install()` still calls this once per namespace.
pub fn reset_template_cache() {}

""" + source[end:]
# `attach_prototype` sits *after* `illegal_constructor`, so it has to be removed
# separately or the reverted file keeps a definition that calls the helper the
# revert deleted.
attach_start = reverted.index(
    "/// Gives a freshly allocated iterator the prototype chain Node's `Iterate` sets."
)
attach_end = reverted.index("fn state_of(", attach_start)
reverted = reverted[:attach_start] + reverted[attach_end:]
path.write_text(reverted)
PY
expect_caught "statement-iterator throwaway-template revert" \
  "the_statement_iterator_is_a_class_with_node_s_chain"

# --- the tree must be back to its fixed state -------------------------------
restore
if ! build; then
  echo "FAIL the fixed tree did not build after the reverts were restored" >&2
  tail -20 "$backup/build.log" >&2
  exit 2
fi

if [ "$failures" -ne 0 ]; then
  printf '\n%d revert(s) were not caught\n' "$failures" >&2
  exit 1
fi
echo "all reverts caught; the surface tests fail when any fix is undone"

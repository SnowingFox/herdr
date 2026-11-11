#!/usr/bin/env bash
# Tests for the crate matcher in tools/regen-bindings.sh.
#
#   ./tools/regen-bindings.test.sh
#
# A crate joins the registry when it *declares* `pub fn register(...)`. The
# matcher used to be `grep -qs "pub fn register"`, which also matched prose: a
# doc comment explaining not to use that name registered the crate that was
# warning against it, and the generated `install_all` then called a function
# that did not exist. Renaming the offending helper does not fix that class,
# because the comment alone is enough, so these tests pin the declaration match
# rather than the absence of any particular function name.
#
# The last case is the ratchet: the real tree must still classify exactly as it
# did, byte for byte, so tightening the matcher cannot quietly drop a crate.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
regen="$here/regen-bindings.sh"
install_all_rel="crates/rn-bindings/src/install_all.rs"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0
ok() { printf 'ok   %s\n' "$1"; }
no() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

# Every fixture is a standalone tree: the script resolves its root from its own
# path, so copying it into <tree>/tools makes it operate on <tree> instead of
# the checkout. That keeps the real `install_all.rs` out of the fixtures' way.
new_tree() {
  local root="$tmp/$1"
  mkdir -p "$root/tools" "$root/crates/rn-bindings/src"
  cp "$regen" "$root/tools/regen-bindings.sh"
  printf '%s\n' "$root"
}

# add_crate <tree> <crate> ; the lib.rs body comes from stdin.
add_crate() {
  local tree="$1" crate="$2"
  mkdir -p "$tree/crates/$crate/src"
  printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' "$crate" \
    >"$tree/crates/$crate/Cargo.toml"
  cat >"$tree/crates/$crate/src/lib.rs"
}

run_regen() {
  local tree="$1"
  ( cd "$tree" && ./tools/regen-bindings.sh ) >"$tree/stdout" 2>"$tree/stderr"
}

# The generated file is the artifact that matters: it is what the build links.
called_in() {
  local tree="$1" crate="$2" module
  module="${crate//-/_}"
  grep -qx "    $module::register(registry);" "$tree/$install_all_rel"
}

expect_registered() {
  if called_in "$1" "$2"; then ok "$3"; else no "$3 (expected $2 in install_all.rs)"; fi
}

expect_skipped() {
  local tree="$1" crate="$2" name="$3"
  if called_in "$tree" "$crate"; then
    no "$name (unexpected $crate in install_all.rs)"
  elif ! grep -qF "$crate" "$tree/stderr"; then
    no "$name (not reported as skipped either)"
  else
    ok "$name"
  fi
}

tree="$(new_tree matcher)"

# Control: a plain top-level declaration is registered, so a fixture tree always
# has at least one crate and the script's "no crates found" exit cannot mask a
# matcher bug.
add_crate "$tree" rn-bind-real <<'RS'
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Real);
}
RS

# Case 1, the reported bug: prose alone must not register a crate. This is the
# doc comment that warned against the name and thereby used it.
add_crate "$tree" rn-bind-doc-only <<'RS'
//! Namespace that deliberately does not export an entry point.
//!
//! Do not copy the shape `pub fn register(registry: &mut rn_core::BindingRegistry)`
//! from a finished crate: this one is mid-landing and ships no registry hook.
///
/// pub fn register(registry: &mut rn_core::BindingRegistry) {}
pub fn unrelated_helper() -> usize {
    0
}
RS

# Case 1, the second reported shape: a block comment is prose too, and a line
# anchor alone does not exclude it.
add_crate "$tree" rn-bind-block <<'RS'
/*
The entry point this crate does not have:

pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Missing);
}
*/
pub fn unrelated_helper() -> usize {
    0
}
RS

# Case 3: a real helper whose name merely starts with `register`. A substring
# match cannot tell this from an entry point; a declaration match can.
add_crate "$tree" rn-bind-helper <<'RS'
pub fn register_current_thread() -> usize {
    0
}
RS

# Case 2: a genuine declaration, indented because it lives in a module. The
# matcher must allow leading whitespace.
add_crate "$tree" rn-bind-nested <<'RS'
mod inner {
    pub fn register(registry: &mut rn_core::BindingRegistry) {
        registry.register_module(Inner);
    }
}
RS

# The method shape `rn-core` has. A rule that only anchors on the name registers
# this crate and then calls a `register` that wants &mut self and a Namespace.
add_crate "$tree" rn-bind-method <<'RS'
pub struct Registry;

impl Registry {
    pub fn register(&mut self, namespace: Namespace) {
        let _ = namespace;
    }
}
RS

# A signature rustfmt has split. It is a real entry point, so the matcher must
# see it across the newline; missing it skips a crate that does export register.
add_crate "$tree" rn-bind-split <<'RS'
pub fn register(
    registry: &mut rn_core::BindingRegistry,
) {
    registry.register_module(Split);
}
RS

# A nested block comment. Rust block comments nest, so stopping at the first
# close would resume scanning prose as code and register this crate.
add_crate "$tree" rn-bind-nested-comment <<'RS'
/* outer /* inner */
pub fn register(registry: &mut rn_core::BindingRegistry) {}
*/
pub fn unrelated_helper() -> usize {
    0
}
RS

# The false-negative side of stripping comments: `/*` and `**/*` appear inside
# string literals here, and a stripper that keys on the characters rather than
# on the lexer would treat the rest of the file as a comment and lose the real
# declaration below it.
add_crate "$tree" rn-bind-literals <<'RS'
pub fn patterns() -> [&'static str; 2] {
    ["/*", "a/**/*.rs"]
}

pub const SLASH: u8 = b'/';

pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Literals);
}
RS

if run_regen "$tree"; then
  expect_registered "$tree" rn-bind-real "crate with a top-level register is registered"
  expect_registered "$tree" rn-bind-nested "indented register inside a module is registered"
  expect_registered "$tree" rn-bind-split "register split across lines is registered"
  expect_registered "$tree" rn-bind-literals "/* inside a string does not hide a later register"
  expect_skipped "$tree" rn-bind-doc-only "doc comment mentioning pub fn register is skipped"
  expect_skipped "$tree" rn-bind-block "block comment mentioning pub fn register is skipped"
  expect_skipped "$tree" rn-bind-nested-comment "nested block comment is skipped"
  expect_skipped "$tree" rn-bind-helper "helper named register_current_thread is skipped"
  expect_skipped "$tree" rn-bind-method "register method taking &mut self is skipped"
else
  no "regen-bindings.sh failed on the fixture tree"
  sed 's/^/     /' "$tree/stderr"
fi

# Case 4, the ratchet: on the real tree the matcher must produce the same file
# as the committed one, so no existing crate changes classification. The tree is
# copied rather than regenerated in place, because regenerating in place would
# let this test approve whatever the script just wrote.
ratchet="$tmp/ratchet"
mkdir -p "$ratchet/tools"
cp "$regen" "$ratchet/tools/regen-bindings.sh"
git -C "$repo" ls-files -z -- crates | tar -C "$repo" --null -T - -cf - | tar -xf - -C "$ratchet"

if ( cd "$ratchet" && ./tools/regen-bindings.sh ) >"$ratchet/stdout" 2>"$ratchet/stderr"; then
  if git -C "$repo" show "HEAD:rustnode/$install_all_rel" >"$ratchet/committed.rs" 2>/dev/null; then
    if diff -u "$ratchet/committed.rs" "$ratchet/$install_all_rel" >"$ratchet/diff"; then
      ok "real tree still generates the committed install_all.rs byte for byte"
    else
      no "real tree classifies a crate differently than the committed install_all.rs"
      sed 's/^/     /' "$ratchet/diff"
    fi
  else
    no "cannot read the committed install_all.rs from HEAD"
  fi
else
  no "regen-bindings.sh failed on the real tree"
  sed 's/^/     /' "$ratchet/stderr"
fi

if [ "$failures" -ne 0 ]; then
  printf '\n%d matcher case(s) failed\n' "$failures" >&2
  exit 1
fi
printf '\nall regen-bindings matcher cases passed\n'

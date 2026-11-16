#!/usr/bin/env bash
# Proves that adding a contribution crate needs no edit to `rn-bun`.
#
#   ./tools/regen-bun-contributions.test.sh
#
# The registry is only worth having if the six Tier-1 workers can each add a crate
# and have it work, without any of them touching `rn-bun/src/lib.rs`,
# `rn-bun-members/src/install_all.rs`, or a shared member list. That is a claim
# about a mechanism, so it can be tested: this script builds a *synthetic*
# contribution crate in a temporary copy of the tree, regenerates, links it, and
# checks the member is on `Bun` — all without any file under `crates/rn-bun/` or
# `crates/rn-bun-members/` being edited by hand.
#
# It also pins the matcher, with the same fixtures `tools/regen-bindings.test.sh`
# uses: this scanner was copied from that one, and a copy is exactly how a
# regression travels. The two differences are deliberate and are asserted here —
# an `internalBinding` crate must be skipped, and a `BunRegistry` crate must be
# picked up.
#
# This is opt-in (it compiles a crate), so it is not in `tools/check.sh`'s hot
# path; `tools/check.sh` runs the cheaper `bun-surface-guard.test.sh` and the real
# guard. Run this when changing the generator or the registry.
#
# Exit codes:
#   0  the mechanism works and every matcher case behaved
#   1  a case behaved differently than required
#   2  a prerequisite is missing (no cargo, no writable temp directory)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"
# An exported `CARGO_TARGET_DIR` defeats every stale-binary check in this tree.
unset CARGO_TARGET_DIR

regen="$root/tools/regen-bun-contributions.sh"

tmp="$(mktemp -d)" || exit 2
trap 'rm -rf "$tmp"' EXIT

failures=0
checks=0
ok() { printf 'ok   %s\n' "$1"; checks=$((checks + 1)); }
no() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); checks=$((checks + 1)); }

# ---------------------------------------------------------------------------
# Part 1: the matcher, on fixture trees.
#
# Each fixture is a standalone tree containing the generator, so the script
# resolves its root to the fixture rather than to this checkout.
# ---------------------------------------------------------------------------
new_tree() {
  local name="$1" tree="$tmp/$1"
  mkdir -p "$tree/tools" "$tree/crates/rn-bun-members/src"
  cp "$regen" "$tree/tools/regen-bun-contributions.sh"
  printf '%s\n' "$tree"
}

# add_crate <tree> <crate>; lib.rs from stdin.
add_crate() {
  local tree="$1" crate="$2"
  mkdir -p "$tree/crates/$crate/src"
  printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' "$crate" \
    >"$tree/crates/$crate/Cargo.toml"
  cat >"$tree/crates/$crate/src/lib.rs"
}

run_regen() { ( cd "$1" && ./tools/regen-bun-contributions.sh ) >"$1/stdout" 2>"$1/stderr"; }

called_in() {
  local tree="$1" crate="$2" module
  module="${crate//-/_}"
  grep -qx "    $module::register(&mut registry)?;" \
    "$tree/crates/rn-bun-members/src/install_all.rs"
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

# The control: a plain declaration is registered, so the fixture tree is never
# empty and the script's "no crates found" exit cannot mask a matcher bug.
add_crate "$tree" rn-bun-real <<'RS'
pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Real)
}
RS

# An `internalBinding` crate. This is the whole reason the Bun matcher exists as a
# second scanner: the crate below is a valid namespace provider, and registering it
# here would make the aggregator call a `register` that takes a different type.
add_crate "$tree" rn-bind-internal <<'RS'
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Internal);
}
RS

# Prose must not register a crate.
add_crate "$tree" rn-bun-doc-only <<'RS'
//! Does not export an entry point.
//!
//! Do not copy `pub fn register(registry: &mut rn_bun_api::BunRegistry)` from a
//! finished crate.
pub fn unrelated_helper() -> usize {
    0
}
RS

# A method named `register` must not register a crate.
add_crate "$tree" rn-bun-method <<'RS'
pub struct Registry;

impl Registry {
    pub fn register(&mut self, member: &str) {
        let _ = member;
    }
}
RS

# A signature rustfmt split across lines is still a declaration.
add_crate "$tree" rn-bun-split <<'RS'
pub fn register(
    registry: &mut rn_bun_api::BunRegistry,
) -> Result<(), String> {
    registry.register_module(Split)
}
RS

# An unqualified `BunRegistry` (imported) is still the right argument type.
add_crate "$tree" rn-bun-imported <<'RS'
use rn_bun_api::BunRegistry;

pub fn register(registry: &mut BunRegistry) -> Result<(), String> {
    registry.register_module(Imported)
}
RS

# `/*` inside a string must not swallow a later declaration.
add_crate "$tree" rn-bun-literals <<'RS'
pub fn patterns() -> [&'static str; 2] {
    ["/*", "a/**/*.rs"]
}

pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Literals)
}
RS

if run_regen "$tree"; then
  expect_registered "$tree" rn-bun-real "a BunRegistry declaration is registered"
  expect_registered "$tree" rn-bun-split "a split signature is registered"
  expect_registered "$tree" rn-bun-imported "an imported BunRegistry is registered"
  expect_registered "$tree" rn-bun-literals "/* in a string does not hide a declaration"
  expect_skipped "$tree" rn-bind-internal "an internalBinding crate is skipped"
  expect_skipped "$tree" rn-bun-doc-only "prose mentioning the signature is skipped"
  expect_skipped "$tree" rn-bun-method "a register method is skipped"
else
  no "the generator failed on the fixture tree"
  sed 's/^/     /' "$tree/stderr"
fi

# ---------------------------------------------------------------------------
# Part 2: the mechanism, end to end.
#
# A temporary crate is added to the real tree, regenerated, built, and asked what
# `Bun` holds. Nothing under `crates/rn-bun/` or `crates/rn-bun-members/src/install_all.rs`
# is edited by hand: the member appears because the crate exists and the generator
# saw the declaration.
#
# The crate is removed in the `trap`-protected cleanup below, so a failure part-way
# through cannot leave the tree modified.
# ---------------------------------------------------------------------------
crate_dir="$root/crates/rn-bun-mechanism-probe"
cleanup_mechanism() {
  rm -rf "$crate_dir"
  # Restore the generated files to what the real crates produce: without this a
  # run that failed before the restore leaves the probe in `install_all.rs`, and the
  # next build fails to find the crate name.
  ( cd "$root" && ./tools/regen-bun-contributions.sh >/dev/null 2>&1 ) || true
}
trap 'cleanup_mechanism; rm -rf "$tmp"' EXIT

if [ -e "$crate_dir" ]; then
  no "the probe crate path is already taken: $crate_dir"
else
  mkdir -p "$crate_dir/src"
  cat >"$crate_dir/Cargo.toml" <<'TOML'
[package]
name = "rn-bun-mechanism-probe"
version = "0.1.0"
edition = "2021"
license = "MIT"
description = "A temporary contribution crate proving the registry needs no shared edit"

[dependencies]
rn-bun-api = { path = "../rn-bun-api" }
rn-core = { path = "../rn-core" }
rn-v8-sys = { path = "../rn-v8-sys" }
TOML
  cat >"$crate_dir/src/lib.rs" <<'RS'
//! A contribution crate that exists only for `tools/regen-bun-contributions.test.sh`.
//!
//! It is written and deleted by that script, and it is deliberately in this shape —
//! no edit to `rn-bun`, no shared member list, nothing but this file and a
//! `Cargo.toml` — because that is the property under test.

use rn_bun_api::BunModule;
use rn_v8_sys::v8;

pub struct Probe;

impl BunModule for Probe {
    fn contributor(&self) -> &'static str {
        "rn-bun-mechanism-probe"
    }

    fn members(&self) -> &'static [&'static str] {
        &["registerMacro"]
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        target: v8::Local<'s, v8::Object>,
    ) -> Result<(), String> {
        rn_core::set_method(scope, target, "registerMacro", probe)?;
        Ok(())
    }
}

fn probe(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::String::new(scope, "registered without editing rn-bun")
        .map(v8::Local::into)
        .unwrap_or_else(|| v8::undefined(scope).into()));
}

pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Probe)
}
RS

  # The two files that must NOT be touched. Their content before and after is
  # compared, which is the assertion "no shared edit": a diff here would mean the
  # mechanism does not hold and the test's own claim is false.
  bun_lib_before="$(sha256sum "$root/crates/rn-bun/src/lib.rs" | cut -d' ' -f1)"
  bun_members_before="$(sha256sum "$root/crates/rn-bun-members/src/lib.rs" | cut -d' ' -f1)"

  if ! ( cd "$root" && ./tools/regen-bun-contributions.sh ) >"$tmp/regen.out" 2>"$tmp/regen.err"; then
    no "the generator failed after the probe crate was added"
    sed 's/^/     /' "$tmp/regen.err"
  elif ! grep -q "rn_bun_mechanism_probe::register" "$root/crates/rn-bun-members/src/install_all.rs"; then
    # The generated call uses the crate name with `-` mapped to `_`, which is what
    # a Rust path requires; grepping the hyphenated form would report a correct
    # `install_all.rs` as a miss.
    no "the generator did not add the probe crate to install_all.rs"
    sed 's/^/     /' "$root/crates/rn-bun-members/src/install_all.rs"
  else
    ok "the generator discovered the probe crate from disk alone"
  fi

  bun_lib_after="$(sha256sum "$root/crates/rn-bun/src/lib.rs" | cut -d' ' -f1)"
  bun_members_after="$(sha256sum "$root/crates/rn-bun-members/src/lib.rs" | cut -d' ' -f1)"
  if [ "$bun_lib_before" = "$bun_lib_after" ] &&
     [ "$bun_members_before" = "$bun_members_after" ]; then
    ok "adding the crate edited neither rn-bun nor rn-bun-members source"
  else
    no "adding the crate changed a shared source file"
  fi

  # A build plus a runtime read: the member has to be on the global, not merely in
  # a generated list. `cargo build -p rn-cli` is what proves the aggregator links.
  if cargo build -p rn-cli >"$tmp/build.log" 2>&1; then
    ok "the workspace builds with the probe crate linked"
    if output="$(./target/debug/rustnode -e 'console.log(globalThis.Bun.registerMacro())' 2>&1)"; then
      if [ "$output" = "registered without editing rn-bun" ]; then
        ok "the probe member runs on the installed Bun global"
      else
        no "the probe member returned $output"
      fi
    else
      no "the probe member threw: $output"
    fi
    # And the gate accepts it in both directions, which is the composition that
    # matters: the member is on the object *and* declared *and* real in Bun 1.4.4.
    # `registerMacro` is a genuine Bun member (tier 3 in the plan, out of scope),
    # so a crate providing it should raise the guard's implemented count rather
    # than fail it. A probe that invented a name would be rejected by mode 4,
    # which is a separate case in `bun-surface-guard.test.sh`.
    if python3 tools/bun-surface-guard.py >"$tmp/guard.out" 2>&1; then
      if grep -q "implemented  Bun.registerMacro" "$tmp/guard.out"; then
        ok "the guard reports the probe as implemented"
      else
        no "the guard did not report the probe as implemented"
        sed 's/^/     /' "$tmp/guard.out"
      fi
    else
      no "the guard failed with the probe crate present"
      sed 's/^/     /' "$tmp/guard.out"
    fi
  else
    no "the workspace did not build with the probe crate"
    tail -20 "$tmp/build.log" | sed 's/^/     /'
  fi
fi

printf '\n%d check(s), %d failure(s)\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
  exit 1
fi

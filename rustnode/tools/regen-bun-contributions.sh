#!/usr/bin/env bash
# Regenerates the Bun contribution registry from the crates present on disk.
#
# Every crate that declares
#
#     pub fn register(registry: &mut rn_bun_api::BunRegistry)
#
# is discovered, so a workstream that adds a `Bun.*` member group never edits a
# shared file. A crate without that function is reported and skipped rather than
# failing the build, so a crate can land before its registration wiring.
#
# This is `tools/regen-bindings.sh` with a different declaration to look for and a
# different generated call. The scanner — comment/string/raw-string aware, nested
# block comments, char literals distinguished from lifetimes — is copied verbatim
# on purpose rather than shared: the two scripts disagree about the *signature*
# (`&mut rn_core::BindingRegistry` vs `&mut rn_bun_api::BunRegistry`) and that
# disagreement is the whole point of having two. Sharing the scanner would mean
# sharing the pattern, and one matcher that accepts both would register every
# `internalBinding` crate here, which is exactly the false positive the original
# script spent a section explaining.
#
# `tools/regen-bun-contributions.test.sh` pins this matcher with the same
# fixtures, so a copied-in regression fails there before a crate is silently
# dropped from the registry.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

crates=()
skipped=()

# Prints the file when it declares the Bun contribution entry point, or nothing.
#
# The match is a *declaration* with the `BunRegistry` argument, not the substring
# `pub fn register`: `rn-core` has `pub fn register(&mut self, namespace: …)` and
# every `internalBinding` crate has `pub fn register(registry: &mut
# rn_core::BindingRegistry)`, so both would match a name-only rule. Requiring the
# argument type is what makes the rule mean "this crate contributes a `Bun.*`
# member" instead of "these bytes appear".
read -r -d '' scanner <<'AWK' || true
# Tracks block comments, string literals, raw strings and char literals across
# lines, so text inside any of them cannot satisfy the declaration match below.
BEGIN { sq = "\047" }
FNR == 1 { emit(); mode = ""; code = ""; file = FILENAME; depth = 0 }
{
  line = $0
  n = length(line)
  out = ""
  i = 1
  while (i <= n) {
    c = substr(line, i, 1)
    two = substr(line, i, 2)

    if (mode == "block") {
      if (two == "/*") { depth++; i += 2; continue }
      if (two == "*/") {
        depth--
        i += 2
        if (depth <= 0) { mode = ""; depth = 0 }
        continue
      }
      i++
      continue
    }
    if (mode == "str") {
      if (c == "\\") { i += 2; continue }
      if (c == "\"") { mode = "" }
      i++
      continue
    }
    if (mode == "raw") {
      if (substr(line, i, rawlen) == rawclose) { mode = ""; i += rawlen } else { i++ }
      continue
    }

    if (two == "//") { break }
    if (two == "/*") { mode = "block"; depth = 1; i += 2; continue }

    if (c == sq) {
      if (substr(line, i, 2) == "\\" sq) { i += 4; continue }
      if (substr(line, i + 2, 1) == sq) { i += 3; continue }
      out = out c
      i++
      continue
    }

    if ((c == "r" || c == "b") && (i == 1 || substr(line, i - 1, 1) !~ /[A-Za-z0-9_]/)) {
      j = i
      if (c == "b") { j++ }
      if (substr(line, j, 1) == "r") {
        hashes = ""
        k = j + 1
        while (substr(line, k, 1) == "#") { hashes = hashes "#"; k++ }
        if (substr(line, k, 1) == "\"") {
          rawclose = "\"" hashes
          rawlen = length(rawclose)
          mode = "raw"
          i = k + 1
          continue
        }
      }
    }

    if (c == "\"") { mode = "str"; i++; continue }
    out = out c
    i++
  }
  code = code out "\n"
}
END { emit() }

function emit() {
  if (code ~ /(^|\n)[[:space:]]*pub[[:space:]]+fn[[:space:]]+register[[:space:]]*\([[:space:]]*registry[[:space:]]*:[[:space:]]*&[[:space:]]*mut[[:space:]]*(rn_bun_api[[:space:]]*::[[:space:]]*)?BunRegistry/) {
    print file
  }
  code = ""
}
AWK

# Any crate that declares the entry point joins, whatever it is called, so a
# workstream is not forced to name its crate a particular way. The excluded names
# are the crates that exist to make the registry work and never contribute a
# member themselves; `rn-bun-api` owns the trait and its own tests declare a
# `register` in fixtures, and `rn-bun` installs the global rather than filling it.
for dir in crates/*; do
  [ -d "$dir" ] || continue
  case "$dir" in
    crates/rn-bun-api|crates/rn-bun|crates/rn-bun-members) continue ;;
  esac
  name="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$dir/Cargo.toml" | head -1)"
  [ -n "$name" ] || continue
  found=0
  while IFS= read -r hit; do
    [ -n "$hit" ] && found=1
  done < <(find "$dir/src" -name '*.rs' -type f -print0 2>/dev/null |
    xargs -0r awk "$scanner")
  if [ "$found" -eq 1 ]; then
    crates+=("$name")
  else
    skipped+=("$name")
  fi
done

if [ ${#skipped[@]} -gt 0 ]; then
  echo "skipped (no Bun contribution entry point): ${skipped[*]}" >&2
fi

if [ ${#crates[@]} -eq 0 ]; then
  echo "no Bun contribution crates found" >&2
  exit 1
fi

IFS=$'\n' sorted=($(printf '%s\n' "${crates[@]}" | LC_ALL=C sort)); unset IFS

{
  cat <<'HEADER'
// Generated by tools/regen-bun-contributions.sh. Do not edit by hand.
//
// One line per Bun contribution crate on disk. Regenerate after adding a crate;
// CI checks that this file matches the directory listing.

use rn_bun_api::BunRegistry;

/// Registers every Bun contribution crate this build contains.
///
/// A crate's `register` may fail: two crates declaring the same member name, or a
/// deferral contradicting an install, are refused by the registry. The failure is
/// returned rather than panicking so the caller can report which crates collided
/// before any isolate exists.
pub fn install_all() -> Result<BunRegistry, String> {
    let mut registry = BunRegistry::new();
HEADER
  for crate in "${sorted[@]}"; do
    module="${crate//-/_}"
    printf '    %s::register(&mut registry)?;\n' "$module"
  done
  cat <<'FOOTER'
    Ok(registry)
}
FOOTER
} >crates/rn-bun-members/src/install_all.rs.tmp

mv crates/rn-bun-members/src/install_all.rs.tmp crates/rn-bun-members/src/install_all.rs

{
  cat <<'HEADER'
# Generated by tools/regen-bun-contributions.sh. Do not edit by hand.
[package]
name = "rn-bun-members"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
description = "Aggregates every Bun.* contribution crate implemented in Rust"

[dependencies]
rn-bun-api = { path = "../rn-bun-api" }
HEADER
  for crate in "${sorted[@]}"; do
    printf '%s = { path = "../%s" }\n' "$crate" "$crate"
  done
} >crates/rn-bun-members/Cargo.toml.tmp

mv crates/rn-bun-members/Cargo.toml.tmp crates/rn-bun-members/Cargo.toml

echo "registered ${#sorted[@]} Bun contribution crate(s): ${sorted[*]}"

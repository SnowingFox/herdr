#!/usr/bin/env bash
# Regenerates the binding registry from the crates present on disk.
#
# Every `crates/rn-bind-*` crate is discovered, so a workstream that adds a
# crate never edits a shared manifest. Crates opt in by exporting
#
#     pub fn register(registry: &mut rn_core::BindingRegistry)
#
# A crate without that function is reported and skipped rather than failing the
# whole build, so a crate can land before its registration wiring.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

crates=()
skipped=()

# Prints the declaration that marks a crate as a namespace provider, or nothing.
#
# The match is a *declaration*, not a substring. `grep -rqs "pub fn register"`
# was wrong in both directions:
#
#   * it matched prose. A doc comment explaining not to name a helper this way,
#     or a note that says "export a `register` function", registered the crate
#     that contained only the words, and the generated `install_all` then called
#     a symbol nothing exported. That happened twice, so the failure is real.
#   * it matched unrelated methods. `crates/rn-core/src/binding.rs` has
#     `pub fn register(&mut self, namespace: Namespace)` and
#     `pub fn register_module<M: ...>`, so `rn-core` is a live false positive
#     under the substring rule.
#
#     The exclusion below still names `rn-core`, but only as a safeguard: the
#     matcher now requires a `BindingRegistry` argument in the declaration, and
#     `rn-core` has no function of that signature, so it is already classified as
#     skipped without the exclusion. Removing it was measured to produce the same
#     output. It is kept so that a future widening of the matcher cannot silently
#     register `rn-core`, which would generate a call to a `register` that takes
#     `&mut self` and break the build for every crate.
#
# Anchoring to the start of a line is not sufficient on its own: a crate can
# legitimately write the signature at column 0 inside a comment. Requiring the
# argument to be a `BindingRegistry` is what makes the match mean "this is the
# discovery entry point" rather than "these bytes appear at the start of a line".
#
# Which direction this errs in, deliberately: a false positive breaks the build
# for every crate with a call to a function that does not exist, while a false
# negative only shows up as "skipped" and then as a missing namespace at
# runtime. Neither is good, but the false negative is worse to diagnose, so this
# scanner errs toward *matching*: when it cannot tell code from prose it treats
# the bytes as code.
#
# `#[cfg(test)]` modules are deliberately NOT excluded. A `register` in a test
# module would be registered by mistake, but excluding it needs brace tracking
# that is easy to get wrong, and getting it wrong skips a crate that really
# does export the function. Widening the matcher is the safer trade, so a crate
# that only defines `register` under `#[cfg(test)]` is a crate whose tests do
# not link; that is caught by the build, not here.
read -r -d '' scanner <<'AWK' || true
# Tracks block comments, string literals, raw strings and char literals across
# lines, so that text inside any of them cannot satisfy the declaration match
# below. It is not a parser: `/*` appears inside string literals in this tree
# (`"**/*.js"`, `b"/*"`), so a character-level comment stripper would treat the
# rest of such a file as a comment and lose a real declaration in it.
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
      # Rust block comments nest, so a `/*` inside one opens another level and
      # only its matching close ends the comment. Stopping at the first close
      # would resume scanning comment prose as code.
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

    # A char literal is quoted and short; a lifetime such as 'a is not, and is
    # left as code so that a signature mentioning &'a cannot swallow the file.
    if (c == sq) {
      if (substr(line, i, 2) == "\\" sq) { i += 4; continue }
      if (substr(line, i + 2, 1) == sq) { i += 3; continue }
      out = out c
      i++
      continue
    }

    # r"..." / r#"..."# / br#"..."#, only where the r starts a token. At column
    # 1 there is no preceding character to inspect.
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
  if (code ~ /(^|\n)[[:space:]]*pub[[:space:]]+fn[[:space:]]+register[[:space:]]*\([[:space:]]*registry[[:space:]]*:[[:space:]]*&[[:space:]]*mut[[:space:]]*(rn_core[[:space:]]*::[[:space:]]*)?BindingRegistry/) {
    print file
  }
  code = ""
}
AWK

# Any crate that declares `register` joins the registry, whatever it is called,
# so a workstream is not forced to name its crate a particular way.
for dir in crates/*; do
  [ -d "$dir" ] || continue
  case "$dir" in
    crates/rn-core|crates/rn-v8-sys|crates/rn-io|crates/rn-cli|crates/rn-bindings|crates/rn-module|crates/rn-napi) continue ;;
  esac
  name="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$dir/Cargo.toml" | head -1)"
  [ -n "$name" ] || continue
  # A crate joins the registry by declaring the discovery function. Without it
  # the crate is mid-landing: report it and leave it out, so an unfinished crate
  # cannot break the build for everyone else.
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
  echo "skipped (no pub fn register yet): ${skipped[*]}" >&2
fi

if [ ${#crates[@]} -eq 0 ]; then
  echo "no rn-bind-* crates found" >&2
  exit 1
fi

IFS=$'\n' sorted=($(printf '%s\n' "${crates[@]}" | LC_ALL=C sort)); unset IFS

{
  cat <<'HEADER'
// Generated by tools/regen-bindings.sh. Do not edit by hand.
//
// One line per `crates/rn-bind-*` crate on disk. Regenerate after adding a
// crate; CI checks that this file matches the directory listing.

use rn_core::BindingRegistry;

/// Registers every namespace this build implements.
pub fn install_all(registry: &mut BindingRegistry) {
HEADER
  for crate in "${sorted[@]}"; do
    module="${crate//-/_}"
    printf '    %s::register(registry);\n' "$module"
  done
  cat <<'FOOTER'
}
FOOTER
} >crates/rn-bindings/src/install_all.rs.tmp

mv crates/rn-bindings/src/install_all.rs.tmp crates/rn-bindings/src/install_all.rs

{
  cat <<'HEADER'
# Generated by tools/regen-bindings.sh. Do not edit by hand.
[package]
name = "rn-bindings"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
description = "Aggregates every internalBinding namespace implemented in Rust"

[dependencies]
rn-core.workspace = true
rn-io.workspace = true
rn-v8-sys.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
HEADER
  for crate in "${sorted[@]}"; do
    printf '%s = { path = "../%s" }\n' "$crate" "$crate"
  done
} >crates/rn-bindings/Cargo.toml.tmp

mv crates/rn-bindings/Cargo.toml.tmp crates/rn-bindings/Cargo.toml

echo "registered ${#sorted[@]} binding crate(s): ${sorted[*]}"

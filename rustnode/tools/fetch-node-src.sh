#!/usr/bin/env bash
# Provides the pinned Node *source* tree that `tools/gen-options.py` reads.
#
#   ./tools/fetch-node-src.sh              # fetch into the cache, print its path
#   ./tools/fetch-node-src.sh --check      # report status, fetch nothing
#   ./tools/fetch-node-src.sh --dir <dir>  # use (or fetch into) another directory
#
# # Why a source tree is needed at all
#
# `crates/rn-bind-options/src/table.rs` is generated from `src/node_options.cc`
# and `src/node_options.h`, and `--check` can only compare against a real
# checkout of the pinned revision. `tools/check.sh` used to have no step running
# that comparison, so the table was free to drift (CLA-213).
#
# # Why a sparse checkout of `src/` only
#
# The generator reads exactly those files and `src/node_constants.h`. A full
# checkout is ~150 MB; `src/` alone is a few MB, and the blob filter means the
# history is not downloaded either. The tree is cached at
# `${RUSTNODE_NODE_SRC_CACHE:-${TMPDIR:-/tmp}}/rustnode-node-src` so a second
# run is free, the same way `fetch-node-oracle.sh` caches the binary.
#
# An existing checkout that is already at the pinned commit is left completely
# alone. That matters because `/workspace/node` is the maintainer convention
# (see `rustnode/AGENTS.md`) and belongs to whoever put it there.
#
# # Exit codes
#
#   0  a source tree at the pinned revision is available; its path is on stdout
#   1  the fetch failed, or what arrived is not the pinned revision
#   3  `--check` and no usable tree (distinct so a caller can explain rather
#      than report a download failure that did not happen)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

check_only=0
dir=""

while [ $# -gt 0 ]; do
  case "$1" in
    --check)
      check_only=1
      shift
      ;;
    --dir)
      dir="${2:?--dir needs a directory}"
      shift 2
      ;;
    -h | --help)
      sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "fetch-node-src: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# The `[node]` table only; a bare key scan would pick up a `[counts]` key.
pin_value() {
  awk -v want="$1" '
    /^[[:space:]]*\[/ { section = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section); next }
    section == "node" {
      key = $0; sub(/[[:space:]]*=.*$/, "", key); gsub(/^[[:space:]]+/, "", key)
      if (key != want) next
      value = $0; sub(/^[^=]*=[[:space:]]*"/, "", value); sub(/".*$/, "", value)
      print value; exit
    }
  ' tools/node-pin.toml
}

pin_commit="$(pin_value commit)"
if [ -z "$pin_commit" ]; then
  echo "fetch-node-src: no [node] commit in tools/node-pin.toml" >&2
  exit 1
fi

repository="$(pin_value repository)"
repository="${repository:-https://github.com/nodejs/node}"
cache_dir="${RUSTNODE_NODE_SRC_CACHE:-${TMPDIR:-/tmp}}"
dir="${dir:-$cache_dir/rustnode-node-src}"

# What makes a tree usable: the two files the generator reads, at the pin.
# Git metadata is not required, because a tarball extraction has none.
usable() {
  [ -f "$1/src/node_options.cc" ] && [ -f "$1/src/node_options.h" ] &&
    [ -f "$1/src/node_constants.h" ]
}

at_pin() {
  [ -d "$1/.git" ] || return 1
  local head
  head="$(git -C "$1" rev-parse HEAD 2>/dev/null || true)"
  case "$head" in
    "$pin_commit"*) return 0 ;;
    *) return 1 ;;
  esac
}

if usable "$dir"; then
  if at_pin "$dir" || [ ! -d "$dir/.git" ]; then
    echo "$dir"
    exit 0
  fi
  # A checkout of the wrong revision: replace it rather than generating from it,
  # because a stale source tree produces a table that looks generated and is not.
  if [ "$check_only" -eq 1 ]; then
    echo "fetch-node-src: $dir is not at $pin_commit" >&2
    exit 3
  fi
  echo "fetch-node-src: $dir is not at $pin_commit; refetching" >&2
  rm -rf "$dir"
elif [ "$check_only" -eq 1 ]; then
  echo "fetch-node-src: no usable Node source at $dir" >&2
  exit 3
fi

mkdir -p "$(dirname "$dir")"

# `git` is preferred because it can verify the revision, but it cannot fetch a
# *short* SHA from a remote: `f344e7f552e` names a commit the upload-pack will
# not resolve, and the fetch fails with `couldn't find remote ref`. The pin
# records a short SHA on purpose (it is what the vendoring notes quote), so a
# short pin goes down the tarball path — codeload resolves the abbreviated SHA
# itself, which is the whole reason that path exists.
pin_is_full_sha=0
case "$pin_commit" in
  *[!0-9a-f]*) pin_is_full_sha=0 ;;
  *) [ "${#pin_commit}" -eq 40 ] && pin_is_full_sha=1 ;;
esac

if command -v git >/dev/null 2>&1 && [ "$pin_is_full_sha" -eq 1 ]; then
  echo "fetch-node-src: fetching $pin_commit into $dir" >&2
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  if ! git -C "$tmp" init -q ||
    ! git -C "$tmp" remote add origin "$repository" ||
    ! git -C "$tmp" fetch --depth 1 --filter=blob:none origin "$pin_commit" 2>/dev/null; then
    echo "fetch-node-src: git fetch failed for $pin_commit from $repository" >&2
    echo "fetch-node-src: set NODE_SRC to an existing checkout at that revision instead" >&2
    exit 1
  fi
  git -C "$tmp" checkout -q FETCH_HEAD 2>/dev/null || {
    echo "fetch-node-src: checkout of $pin_commit failed" >&2
    exit 1
  }
  rm -rf "$dir"
  mv "$tmp" "$dir"
  trap - EXIT
else
  echo "fetch-node-src: downloading the source tarball for $pin_commit" >&2
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  url="https://codeload.github.com/nodejs/node/tar.gz/$pin_commit"
  if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/src.tar.gz" "$url"; then
    echo "fetch-node-src: download failed: $url" >&2
    exit 1
  fi
  tar xzf "$tmp/src.tar.gz" -C "$tmp"
  extracted="$(find "$tmp" -maxdepth 1 -type d -name 'node-*' | head -1)"
  if [ -z "$extracted" ]; then
    echo "fetch-node-src: $url did not contain a node-* directory" >&2
    exit 1
  fi
  rm -rf "$dir"
  mv "$extracted" "$dir"
  trap - EXIT
fi

if ! usable "$dir"; then
  echo "fetch-node-src: $dir has no src/node_options.cc; the pin may be wrong" >&2
  exit 1
fi
echo "fetch-node-src: ready at $dir (pin $pin_commit)" >&2
echo "$dir"

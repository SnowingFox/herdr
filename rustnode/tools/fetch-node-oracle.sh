#!/usr/bin/env bash
# Fetches the pinned Node binary that the differential tests compare against.
#
#   ./tools/fetch-node-oracle.sh              # fetch into the pin's `oracle` dir
#   ./tools/fetch-node-oracle.sh --check      # report status, fetch nothing
#   ./tools/fetch-node-oracle.sh --dir <dir>  # fetch somewhere else
#
# `tools/check.sh` and the rustnode CI workflow call this before `cargo test`,
# so the tests get the pinned oracle instead of whatever `node` is on `PATH`.
# It is idempotent: a directory that already reports the pinned version is left
# alone, which is what keeps the cache in `/tmp` cheap across runs.
#
# # Why the nightly, and why the version check is loose
#
# `tools/node-pin.toml` pins Node 28 to commit f344e7f552e, which is not a
# release. The binary for that commit is the nightly whose `--version` reports
# `v28.0.0-nightly<date><short-sha>`. The directory in the pin already spells
# that build, so this script reads the directory name and downloads exactly it
# rather than reconstructing a date from the commit. `RN_NODE_ORACLE_VERSION`
# overrides the expected version string, which is what a re-pin needs when the
# nightly date moves but the vendored source has not been re-copied yet.
#
# # Exit codes
#
#   0  an oracle at the pinned version is present (fetched or already there)
#   1  the fetch failed, or what arrived does not report the pinned version
#   3  `--check` and no usable oracle (distinct so the caller can explain rather
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
      sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "fetch-node-oracle: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# The `[node]` table only. A bare `key = "..."` scan would pick up `[counts]`
# keys if the file is ever reordered, so the section is tracked explicitly.
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

pin_version="$(pin_value version)"
pin_commit="$(pin_value commit)"
oracle_dir="$(pin_value oracle)"
oracle_version="$(pin_value oracle_version)"
expected_version="${RN_NODE_ORACLE_VERSION:-${oracle_version:-v$pin_version}}"

if [ -z "$pin_version" ]; then
  echo "fetch-node-oracle: no [node] version in tools/node-pin.toml" >&2
  exit 1
fi
if [ -z "$oracle_dir" ]; then
  echo "fetch-node-oracle: no [node] oracle in tools/node-pin.toml." >&2
  echo "fetch-node-oracle: add the pinned nightly's directory, or set RN_NODE_ORACLE." >&2
  exit 1
fi
dir="${dir:-$oracle_dir}"
binary="$dir/bin/node"

# A pre-existing oracle wins: the same directory is reused by every run, and
# re-downloading 30 MB per gate would be pure cost.
if [ -x "$binary" ]; then
  have="$("$binary" --version 2>/dev/null || true)"
  if [ "$have" = "$expected_version" ]; then
    echo "fetch-node-oracle: $binary already reports $have"
    exit 0
  fi
  if [ "$check_only" -eq 1 ]; then
    echo "fetch-node-oracle: $binary reports ${have:-nothing}, wanted $expected_version" >&2
    exit 3
  fi
  echo "fetch-node-oracle: $binary reports ${have:-nothing}, replacing it" >&2
elif [ "$check_only" -eq 1 ]; then
  echo "fetch-node-oracle: no oracle at $binary" >&2
  exit 3
fi

# The tarball's directory name is the `oracle` directory's own basename, which is
# how the build is identified without restating the nightly date in the pin.
name="$(basename "$dir")"
platform=""
for candidate in linux-x64 linux-arm64 darwin-x64 darwin-arm64; do
  case "$name" in
    node-v*-"$candidate")
      platform="$candidate"
      break
      ;;
  esac
done
if [ -z "$platform" ]; then
  echo "fetch-node-oracle: $name is not a Node distribution directory name" >&2
  echo "fetch-node-oracle: expected node-v<version>-<platform> in the pin's oracle key" >&2
  exit 1
fi

# The version is everything between `node-v` and the platform suffix, so a
# nightly keeps its date and short SHA and a release keeps its plain version.
version_part="${name#node-v}"
version_part="${version_part%-"$platform"}"
# Nightlies and releases live under different paths on nodejs.org.
case "$name" in
  *-nightly*) url="https://nodejs.org/download/nightly/v$version_part/$name.tar.xz" ;;
  *) url="https://nodejs.org/dist/v$version_part/$name.tar.xz" ;;
esac

echo "fetch-node-oracle: downloading $url"
mkdir -p "$(dirname "$dir")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/node.tar.xz" "$url"; then
  echo "fetch-node-oracle: download failed: $url" >&2
  echo "fetch-node-oracle: set RN_NODE_ORACLE to a Node $pin_version binary instead" >&2
  exit 1
fi

# Verified when the distribution publishes a manifest for it. A nightly's
# `SHASUMS256.txt` is served next to the tarball; when it is absent the download
# is still over HTTPS from nodejs.org, which is the same trust the rest of this
# repository's tooling places in that host.
if curl -fsSL --retry 2 -o "$tmp/SHASUMS256.txt" "$(dirname "$url")/SHASUMS256.txt" 2>/dev/null; then
  expected_sha="$(awk -v name="$name.tar.xz" '$2 == name { print $1 }' "$tmp/SHASUMS256.txt")"
  if [ -n "$expected_sha" ]; then
    actual_sha="$(sha256sum "$tmp/node.tar.xz" | awk '{ print $1 }')"
    if [ "$actual_sha" != "$expected_sha" ]; then
      echo "fetch-node-oracle: checksum mismatch for $name.tar.xz" >&2
      echo "fetch-node-oracle:   expected $expected_sha" >&2
      echo "fetch-node-oracle:   actual   $actual_sha" >&2
      exit 1
    fi
    echo "fetch-node-oracle: checksum matches SHASUMS256.txt"
  fi
fi

tar -xJf "$tmp/node.tar.xz" -C "$tmp"
if [ ! -x "$tmp/$name/bin/node" ]; then
  echo "fetch-node-oracle: $name.tar.xz did not contain $name/bin/node" >&2
  exit 1
fi

# Replaced in place so a stale tree cannot survive a partial extract, and so the
# path in the pin never points at a mixture of two builds.
rm -rf "$dir"
mv "$tmp/$name" "$dir"

have="$("$dir/bin/node" --version 2>/dev/null || true)"
if [ "$have" != "$expected_version" ]; then
  echo "fetch-node-oracle: $dir/bin/node reports ${have:-nothing}, wanted $expected_version" >&2
  echo "fetch-node-oracle: set RN_NODE_ORACLE_VERSION if the pin has moved ahead of the nightly" >&2
  exit 1
fi

echo "fetch-node-oracle: ready at $dir/bin/node ($have, pin $pin_version @ $pin_commit)"

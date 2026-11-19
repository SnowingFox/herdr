#!/usr/bin/env bash
# Fetches the Bun build that `tools/bench.py` compares against.
#
#   ./tools/fetch-bun-oracle.sh              # fetch into the default directory
#   ./tools/fetch-bun-oracle.sh --check      # report status, fetch nothing
#   ./tools/fetch-bun-oracle.sh --dir <dir>  # fetch somewhere else
#
# Unlike the Node oracle this one is not part of `tools/check.sh`: Bun is an
# optional third column in a benchmark, and the gate has to stay green on a
# machine that has no network and no Bun. `tools/bench.py` discovers a Bun at
# `BUN_BIN`, then at the default directory below, then on `PATH`, and prints the
# unchanged two-way table when it finds none.
#
# # Why a pin, and why the version is checked
#
# A `bun` from a package manager is whatever version the machine happens to
# have, and Bun's startup time is not stable across releases. A recorded number
# is only comparable to another one from the same engine, so this script
# downloads one release, verifies it against the checksum GitHub publishes for
# it, and leaves the version it installed in the path it was asked to use.
#
# # Exit codes
#
#   0  the pinned Bun is present (fetched or already there)
#   1  the fetch failed, the checksum did not match, or the binary does not
#      report the pinned version
#   3  `--check` and no usable Bun (distinct so the caller can explain rather
#      than report a download failure that did not happen)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Keep these two in step with BUN_DEFAULT and the recorded table in
# `docs/benchmarks.md`. A bump is a new baseline, not a small edit.
bun_version="1.4.4"
default_dir="/tmp/bun-dl/bun-linux-x64"
binary_name="bun"

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
      sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "fetch-bun-oracle: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

architecture="$(uname -m)"
case "$architecture" in
  x86_64 | amd64) bun_arch="x64" ;;
  aarch64 | arm64) bun_arch="aarch64" ;;
  *)
    echo "fetch-bun-oracle: no Bun build for $architecture" >&2
    exit 1
    ;;
esac

dir="${dir:-$default_dir}"
# `--dir` names the directory the binary goes in, so a caller can point the
# script somewhere else without also having to match this script's layout.
binary="$dir/$binary_name"
asset="bun-linux-${bun_arch}.zip"
base_url="https://github.com/oven-sh/bun/releases/download/bun-v${bun_version}"

# A pre-existing binary wins: the directory is reused by every run, and
# re-downloading 100 MB to answer "is it still 1.4.4" would be pure cost.
if [ -x "$binary" ]; then
  have="$("$binary" --version 2>/dev/null || true)"
  if [ "$have" = "$bun_version" ]; then
    echo "fetch-bun-oracle: $binary already reports $have"
    exit 0
  fi
  if [ "$check_only" -eq 1 ]; then
    echo "fetch-bun-oracle: $binary reports ${have:-nothing}, wanted $bun_version" >&2
    exit 3
  fi
  echo "fetch-bun-oracle: $binary reports ${have:-nothing}, replacing it" >&2
elif [ "$check_only" -eq 1 ]; then
  echo "fetch-bun-oracle: no Bun at $binary" >&2
  exit 3
fi

if ! command -v unzip >/dev/null 2>&1; then
  echo "fetch-bun-oracle: unzip is required to unpack $asset" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "fetch-bun-oracle: downloading $base_url/$asset"
if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/$asset" "$base_url/$asset"; then
  echo "fetch-bun-oracle: download failed: $base_url/$asset" >&2
  echo "fetch-bun-oracle: set BUN_BIN to a Bun $bun_version binary instead" >&2
  exit 1
fi

# The release publishes SHASUMS256.txt next to the assets. It is fetched
# separately and the asset is verified against it rather than trusted from
# HTTPS alone, because this is a 100 MB executable that the benchmark then runs.
if ! curl -fsSL --retry 2 -o "$tmp/SHASUMS256.txt" "$base_url/SHASUMS256.txt"; then
  echo "fetch-bun-oracle: could not fetch $base_url/SHASUMS256.txt" >&2
  exit 1
fi
expected_sha="$(awk -v name="$asset" '$2 == name { print $1 }' "$tmp/SHASUMS256.txt")"
if [ -z "$expected_sha" ]; then
  echo "fetch-bun-oracle: SHASUMS256.txt does not list $asset" >&2
  exit 1
fi
actual_sha="$(sha256sum "$tmp/$asset" | awk '{ print $1 }')"
if [ "$actual_sha" != "$expected_sha" ]; then
  echo "fetch-bun-oracle: checksum mismatch for $asset" >&2
  echo "fetch-bun-oracle:   expected $expected_sha" >&2
  echo "fetch-bun-oracle:   actual   $actual_sha" >&2
  exit 1
fi
echo "fetch-bun-oracle: checksum matches SHASUMS256.txt"

unzip -oq "$tmp/$asset" -d "$tmp"
# The archive holds `bun-linux-<arch>/bun`. Accept either that shape or a bare
# `bun`, so a `--dir` pointing at the unpacked directory keeps working.
if [ -x "$tmp/bun-linux-$bun_arch/bun" ]; then
  unpacked="$tmp/bun-linux-$bun_arch/bun"
elif [ -x "$tmp/bun" ]; then
  unpacked="$tmp/bun"
else
  echo "fetch-bun-oracle: $asset did not contain a bun executable" >&2
  exit 1
fi

# Moved into place rather than copied while an older binary may still sit
# there, so a failed replace cannot leave a half-written executable behind.
mkdir -p "$dir"
rm -f "$binary"
mv "$unpacked" "$binary"
chmod +x "$binary"

have="$("$binary" --version 2>/dev/null || true)"
if [ "$have" != "$bun_version" ]; then
  echo "fetch-bun-oracle: $binary reports ${have:-nothing}, wanted $bun_version" >&2
  exit 1
fi

echo "fetch-bun-oracle: ready at $binary ($have)"

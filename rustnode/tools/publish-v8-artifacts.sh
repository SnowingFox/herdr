#!/usr/bin/env bash
# Publishes the V8 15.6.75 artifacts to the herdr GitHub release that
# vendor/rusty-v8's build.rs downloads from by default.
#
#   GH_TOKEN=... ./tools/publish-v8-artifacts.sh [archive-dir]
#
# Run `tools/build-v8-15.6.sh` first; this only uploads what it produced.
#
# Why a release of our own rather than denoland's: upstream `rusty_v8` never
# published a prebuilt library for V8 15.6 (its V8 submodule went 15.2 -> 15.8),
# so the default URL in `build.rs` points at this repository. A plain
# `cargo build` therefore works on a clean machine with no setup, which is the
# property worth protecting; re-run this when the engine changes.
set -euo pipefail

readonly TAG="v8-15.6.75"
readonly REPO="${REPO:-SnowingFox/herdr}"
readonly ARCHIVE_DIR=${1:-$PWD/target/v8-15.6}
readonly LIB="librusty_v8_release_x86_64-unknown-linux-gnu.a"
readonly BINDING="src_binding_release_x86_64-unknown-linux-gnu.rs"

[ -f "$ARCHIVE_DIR/$LIB" ] || {
  echo "no $LIB in $ARCHIVE_DIR; run tools/build-v8-15.6.sh first" >&2; exit 1; }
[ -f "$ARCHIVE_DIR/$BINDING" ] || {
  echo "no $BINDING in $ARCHIVE_DIR" >&2; exit 1; }
: "${GH_TOKEN:?set GH_TOKEN to a token with release write access}"

# The library is ~360 MB raw and downloads on every cold cache, so it ships
# gzipped: the build script decompresses `.gz` transparently.
gzip -9 -c "$ARCHIVE_DIR/$LIB" > "$ARCHIVE_DIR/$LIB.gz"

tag_sha=$(sha256sum "$ARCHIVE_DIR/$LIB.gz" | cut -d' ' -f1)
echo "librusty_v8_release_x86_64-unknown-linux-gnu.a.gz sha256: $tag_sha"
echo
echo "Update DEFAULT_ARCHIVE_SHA256 in vendor/rusty-v8/build.rs to that value."
echo

release_id=$(gh api "repos/$REPO/releases/tags/$TAG" --jq .id 2>/dev/null || true)
if [ -z "$release_id" ]; then
  release_id=$(gh api -X POST "repos/$REPO/releases" \
    -f tag_name="$TAG" \
    -f target_commitish=master \
    -f name="V8 15.6.75 prebuilt (rusty_v8 15.8 bindings)" \
    -f body="Prebuilt static library and Rust bindings for the V8 15.6.75 engine that \`tools/node-pin.toml\` pins. Built by \`rustnode/tools/build-v8-15.6.sh\`." \
    --jq .id)
  echo "created release $release_id"
fi

for file in "$LIB.gz" "$BINDING"; do
  # Replacing an existing asset needs the old one deleted first; GitHub rejects
  # a duplicate name.
  existing=$(gh api "repos/$REPO/releases/$release_id/assets" \
    --jq ".[] | select(.name == \"$file\") | .id")
  [ -n "$existing" ] && gh api -X DELETE "repos/$REPO/releases/assets/$existing"
  gh release upload "$TAG" "$ARCHIVE_DIR/$file" --repo "$REPO" --clobber
  echo "uploaded $file"
done

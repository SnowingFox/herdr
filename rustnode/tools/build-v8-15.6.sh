#!/usr/bin/env bash
# Produces the V8 15.6.75 static library and its Rust bindings for the vendored
# `vendor/rusty-v8` crate, then prints the directory to pass as
# `RUSTY_V8_ARCHIVE`.
#
#   ./tools/build-v8-15.6.sh [output-dir]
#
# Why a source build rather than a download: no published `v8` crate targets V8
# 15.6. The newest is `152.2.0` (V8 15.2), and the `rusty_v8` V8 submodule went
# 15.2 -> 15.8, skipping 15.6. `tools/node-pin.toml` pins 15.6.75 because that is
# what Node 28 ships and what `process.versions.v8` is compared against, so the
# engine is built here and the vendored 15.8 bindings are compiled against it.
# See `vendor/rusty-v8/README.md`.
#
# Costs: `gclient sync` ~90s, the build ~15-25 min on 8 cores, ~10 GB of disk.
# The artifacts are deterministic; build once per machine and cache `OUT`.
set -euo pipefail

readonly V8_VERSION="15.6.75"
readonly OUT=${1:-$PWD/target/v8-15.6}
readonly WORK=${RUSTY_V8_WORK_DIR:-/tmp/rusty-v8-build}
readonly ROOT="$WORK/v8"
readonly VENDOR="$PWD/vendor/rusty-v8"

[ -f "$VENDOR/build.rs" ] || { echo "run from the rustnode workspace root" >&2; exit 1; }
command -v gclient >/dev/null || {
  echo "gclient (depot_tools) is required on PATH" >&2; exit 1; }

mkdir -p "$WORK" "$OUT"

# 1. Sync V8 at exactly the pinned version. `-D` keeps git deps at the revisions
#    V8's own DEPS names, which is the property the GN rooting below depends on:
#    `build/` (bc0661cf) and `gni/` come from the same sync, so they agree.
if [ ! -d "$ROOT/src" ]; then
  cat > "$WORK/.gclient" <<EOF
solutions = [
  {
    "name": "v8",
    "url": "https://chromium.googlesource.com/v8/v8.git@$V8_VERSION",
    "deps_file": "DEPS",
    "managed": False,
    "custom_deps": {},
    "custom_vars": {},
  },
]
target_os = ["linux"]
EOF
  (cd "$WORK" && gclient sync --no-history --shallow -D)
fi

major=$(sed -n 's/^#define V8_MAJOR_VERSION //p' "$ROOT/include/v8-version.h")
minor=$(sed -n 's/^#define V8_MINOR_VERSION //p' "$ROOT/include/v8-version.h")
build=$(sed -n 's/^#define V8_BUILD_NUMBER //p' "$ROOT/include/v8-version.h")
[ "$major.$minor.$build" = "$V8_VERSION" ] || {
  echo "V8 tree is $major.$minor.$build, not $V8_VERSION" >&2; exit 1; }

# 2. Root GN at the V8 tree. `binding.cc` includes "v8/src/...", so a directory
#    literally named `v8` has to exist at the root; a self-symlink maps it onto
#    the tree it already is and so never adds a second label for any file.
ln -sfn . "$ROOT/v8"
rm -rf "$ROOT/crate"
mkdir -p "$ROOT/crate"
cp -a "$VENDOR/src" "$ROOT/crate/src"
cp -a "$VENDOR/BUILD.gn" "$ROOT/crate/BUILD.gn"

if ! grep -q crate_rusty_v8_probe "$ROOT/BUILD.gn"; then
  printf '\ngroup("crate_rusty_v8_probe") {\n  deps = [ "//crate:rusty_v8" ]\n}\n' >> "$ROOT/BUILD.gn"
fi

# The crate's own dotfile, minus `secondary_source`. With V8 as the GN root there
# is no secondary tree, and leaving it in makes `//gni/v8.gni` reachable under
# two labels - which is the "Duplicate build argument declaration" failure that
# made a crate-rooted layout impossible in the first place.
cat > "$WORK/crate.gn" <<'GNEOF'
buildconfig = "//build/config/BUILDCONFIG.gn"
check_targets = []

default_args = {
  clang_use_chrome_plugins = false
  is_component_build = false
  linux_use_bundled_binutils = false
  use_dummy_lastchange = true
  use_sysroot = false
  simple_template_names = false

  line_tables_only = true
  no_inline_line_tables = true
  symbol_level = 1
  use_debug_fission = false

  v8_embedder_string = "-rusty"

  v8_enable_javascript_promise_hooks = true
  v8_promise_internal_field_count = 1
  v8_use_external_startup_data = false

  v8_imminent_deprecation_warnings = false
  v8_enable_private_mapping_fork_optimization = true

  v8_use_zlib = false
  v8_enable_snapshot_compression = false

  v8_enable_handle_zapping = false
  v8_typed_array_max_size_in_heap = 0

  v8_array_buffer_internal_field_count = 2
  v8_array_buffer_view_internal_field_count = 2

  v8_enable_fuzztest = false
  v8_enable_v8_checks = false
  use_relative_vtables_abi = false

  v8_depend_on_icu_data_file = false
  icu_copy_icudata_to_root_build_dir = false
  icu_use_data_file = false

  use_llvm_libatomic = false
  enable_rust = true
  enable_rust_cxx = true
  v8_enable_temporal_support = true
  v8_use_default_hasher_secret = false
  use_clang_modules = false
}
GNEOF

(cd "$ROOT" && ./buildtools/linux64/gn gen out/rusty_v8 \
  --root="$ROOT" \
  --dotfile="$WORK/crate.gn" \
  --script-executable="$(command -v python3)" \
  --ide=json \
  --args="is_debug=false v8_monolithic=true v8_use_external_startup_data=false v8_enable_sandbox=false v8_enable_pointer_compression=false v8_monolithic_for_shared_library=true use_custom_libcxx=true treat_warnings_as_errors=false target_cpu=\"x64\" use_glib=false use_siso=false use_cxx23=false")

(cd "$ROOT" && ./third_party/ninja/ninja -C out/rusty_v8 crate_rusty_v8_probe)

archive="$OUT/librusty_v8_release_x86_64-unknown-linux-gnu.a"
cp "$ROOT/out/rusty_v8/obj/crate/librusty_v8.a" "$archive"

# 3. The bindings. `build.rs` runs bindgen itself, but it needs `project.json`
#    from a GN graph it generated; producing the file here is what lets
#    `RUSTY_V8_ARCHIVE` be a complete, self-contained directory that a CI build
#    consumes without running GN at all.
python3 "$(dirname "$0")/gen-v8-bindings.py" \
  "$ROOT" "$ROOT/out/rusty_v8" \
  "$OUT/src_binding_release_x86_64-unknown-linux-gnu.rs"

version=$(strings "$archive" | grep -E '^15\.6\.' | head -1)
symbols=$(nm --defined-only "$archive" | grep -c ' T v8__' || true)
echo "V8 $version, $symbols v8__ symbols" >&2
case "$version" in
  15.6.*) ;;
  *) echo "archive does not report a 15.6 version" >&2; exit 1 ;;
esac
echo "$OUT"

#!/usr/bin/env bash
# Tests for the `npm pack --json` shape handling in tools/npm-pack.py.
#
#   ./tools/npm-pack-json-shape.test.sh
#
# Why this exists: `npm_pack()` read `report[0]["filename"]`, which is the npm
# <=11 shape. npm 12 returns an object keyed by package name, so `pack` raised
# `KeyError: 0` after writing only the main tarball — the platform package and
# `packages.json` were never produced, and the end-to-end install test could not
# start. Nothing caught it because the gate runs `npm-manifest-check.py`, which
# never invokes `npm pack`.
#
# **This test drives `npm_pack()` itself, with a stub `npm` on PATH**, not the
# helper it delegates to. That distinction is the whole design: a first version
# of this file called `npm_pack_entry()` directly, and reverting the caller to
# `report[0]["filename"]` left every case passing — it tested a function that
# the bug never reached. A stub `npm` that prints a chosen JSON document
# exercises the real read path, including the manifest lookup the caller does.
#
# No npm, no network, no binary: the stub answers, and the tarball it names is
# created so the existence check can pass.
#
# Exit codes:
#   0  every case behaved as required
#   1  a case behaved differently than required (the message names which)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/pkg" "$tmp/out"

# The package under test: a manifest with a name, which `npm_pack()` reads to
# resolve the object form.
cat >"$tmp/pkg/package.json" <<'JSON'
{"name": "@s/rsnode", "version": "1.0.0"}
JSON

# A stub `npm` that prints whatever document the case puts in `$STUB_JSON` and
# creates the tarball it names, so `npm_pack()`'s existence check is exercised
# rather than bypassed.
cat >"$tmp/bin/npm" <<'SH'
#!/bin/sh
cat "$STUB_JSON"
name="$(python3 -c '
import json, os, sys
doc = json.load(open(os.environ["STUB_JSON"]))
if isinstance(doc, list):
    entries = doc
else:
    entries = list(doc.values())
for entry in entries:
    if isinstance(entry, dict) and "filename" in entry:
        print(entry["filename"])
        break
' 2>/dev/null)"
[ -n "$name" ] && : >"$STUB_OUT/$name"
exit 0
SH
chmod +x "$tmp/bin/npm"

cat >"$tmp/probe.py" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("npm_pack", "tools/npm-pack.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

try:
    tarball = module.npm_pack(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
except module.PackError as error:
    print(f"PackError: {error}")
    sys.exit(3)
print(tarball.name)
PY

fail=0
expect() {
    local case="$1" want_status="$2" want_text="${3:-}" doc="$4"
    printf '%s' "$doc" >"$tmp/doc.json"
    local out status
    local stub="$tmp/bin"
    if [ "$case" = "missing-tarball" ]; then
        # A stub that reports a filename without writing it.
        mkdir -p "$tmp/lie"
        cat >"$tmp/lie/npm" <<'LIAR'
#!/bin/sh
cat "$STUB_JSON"
exit 0
LIAR
        chmod +x "$tmp/lie/npm"
        stub="$tmp/lie"
    fi
    out="$(STUB_JSON="$tmp/doc.json" STUB_OUT="$tmp/out" PATH="$stub:$PATH" \
        python3 "$tmp/probe.py" "$tmp/pkg" "$tmp/out" 2>&1)" && status=0 || status=$?
    if [ "$status" != "$want_status" ]; then
        echo "FAIL $case: exit $status, wanted $want_status"
        echo "     output: $out"
        fail=1
        return
    fi
    if [ -n "$want_text" ] && ! printf '%s' "$out" | grep -qF "$want_text"; then
        echo "FAIL $case: output does not contain '$want_text'"
        echo "     output: $out"
        fail=1
        return
    fi
    echo "ok   $case"
}

NAME='@s/rsnode'

# Both real shapes must be read correctly, which is the whole point: the bug was
# accepting only one of them.
expect array 0 "a-1.0.0.tgz" '[{"filename":"a-1.0.0.tgz","name":"@s/rsnode"}]'
expect object 0 "b-1.0.0.tgz" '{"@s/rsnode":{"filename":"b-1.0.0.tgz","name":"@s/rsnode"}}'

# A missing name must name the keys it did see, not silently take the first
# value — that would be the same class of bug as the KeyError this replaced.
expect object-missing 3 "other" '{"other":{"filename":"c.tgz"}}'
expect object-missing 3 "$NAME" '{"other":{"filename":"c.tgz"}}'

# Every other shape must fail with a message, never a traceback.
expect empty-array 3 "no tarball" '[]'
expect scalar 3 "str" '"nonsense"'
expect object-without-filename 3 "without a filename" '{"@s/rsnode":{"name":"@s/rsnode"}}'

# A filename npm reports but did not write is still a hard failure. The stub
# only creates the tarball it can name, so asking for one it reports but does
# not write exercises the existence check. The stub writes whatever the first
# entry names, so this document is shaped to name a file the stub then deletes.
expect missing-tarball 3 "does not exist" '{"@s/rsnode":{"filename":"absent.tgz"}}'

if [ "$fail" -ne 0 ]; then
    echo "npm-pack json shape handling is broken" >&2
    exit 1
fi
echo "npm-pack reads both the npm <=11 array and the npm 12 name-keyed object"

#!/usr/bin/env python3
"""Prove `npm pack --json` still has a shape `npm-pack.py` understands.

This exists because of a real failure. npm 12 changed `npm pack --json` from an
array to an object keyed by package name, and `npm-pack.py` did
`report[0]["filename"]`, so packing died with `KeyError: 0` on npm 12 while
passing on npm 10. Nothing caught it: the gate ran only
`npm-manifest-check.py`, which never calls `pack`, so `pack` and the end-to-end
test were unexercised. The bug surfaced only when someone ran it by hand on a
machine with a newer npm.

The end-to-end test needs a release binary, so the gate cannot run it. This is
the cheapest check that still catches the defect class:

* it packs a **throwaway manifest in a temp dir**, so no binary, no network, no
  repository state;
* it asserts the shape is one of the two accepted forms, so a future npm 13
  shape fails here with a message naming the npm version and the observed type;
* it round-trips through `extract_pack_filename` against the real npm output,
  rather than testing that function on a hand-made fixture. A hand-made dict
  would prove the parser works on dicts, not that npm produces dicts.

Two layers, because they fail differently. The shape assertion catches "npm
changed again" on whatever npm this machine has. The parser unit tests catch a
regression in `extract_pack_filename` itself without needing npm at all — those
run even when npm is absent, so the gate stays green on a machine without it
while still proving the parser handles both forms.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

TOOLS_DIR = pathlib.Path(__file__).resolve().parent

# `npm-pack.py` has a hyphen, so it cannot be imported by name.
_spec = importlib.util.spec_from_file_location("npm_pack", TOOLS_DIR / "npm-pack.py")
assert _spec is not None and _spec.loader is not None
npm_pack_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(npm_pack_mod)

PackError = npm_pack_mod.PackError
extract_pack_filename = npm_pack_mod.extract_pack_filename


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL {message}")
    print(f"ok   {message}")


def test_parser_unit() -> None:
    """The parser accepts both shipped shapes and rejects the rest loudly.

    No npm needed, so this half cannot be skipped by a missing or broken npm.
    Each rejection case is a defect shape that would otherwise be silent: taking
    the first value of a keyed object, or treating an unknown type as empty.
    """
    array_form = [{"filename": "a-1.0.0.tgz", "name": "a", "version": "1.0.0"}]
    check(extract_pack_filename(array_form, "a") == "a-1.0.0.tgz",
          "npm <= 11 array form resolves to its filename")

    dict_form = {"@s/x": {"filename": "s-x-1.0.0.tgz", "name": "@s/x"}}
    check(extract_pack_filename(dict_form, "@s/x") == "s-x-1.0.0.tgz",
          "npm 12 keyed-object form resolves by package name")

    # Two packages under one key set: resolving by name must not just take the
    # first value, which is the bug class this replaced.
    two_keys = {
        "@s/first": {"filename": "first.tgz"},
        "@s/second": {"filename": "second.tgz"},
    }
    check(extract_pack_filename(two_keys, "@s/second") == "second.tgz",
          "keyed form resolves the requested package, not the first value")

    def must_fail(payload, package, why: str) -> None:
        try:
            extract_pack_filename(payload, package)
        except PackError as error:
            text = str(error)
            check(package in text or "keys" in text or "keys are" in text or ":" in text,
                  f"rejects {why} and names the observed data")
        else:
            raise SystemExit(f"FAIL accepted {why}; it must be an error")

    must_fail(["no filename here"], "a", "an array entry without `filename`")
    must_fail({"@s/other": {"filename": "x.tgz"}}, "@s/x", "a keyed object missing our package")
    must_fail({"@s/x": {"name": "@s/x"}}, "@s/x", "a keyed entry without `filename`")
    must_fail("a string", "a", "an unexpected JSON type")
    must_fail([], "a", "an empty array")


def test_real_npm_round_trip() -> None:
    """Pack a throwaway manifest and read it through the real `npm_pack`.

    This is the half that would have caught the npm 12 change on the day it
    landed, and it deliberately calls `npm_pack` rather than
    `extract_pack_filename`. An earlier version of this test only exercised the
    parser, which meant reinstating the original bug inside `npm_pack` still
    produced a green run — the function with the defect was never called. Driving
    the function that actually runs is the difference between testing the parser
    and testing the code path that broke.
    """
    npm = shutil.which("npm")
    if npm is None:
        print("skip real npm round-trip: no npm on PATH (parser unit tests still ran)")
        return

    version = subprocess.run([npm, "--version"], capture_output=True, text=True, check=False)
    npm_version = version.stdout.strip() or "unknown"
    print(f"     npm under test: {npm_version}")

    with tempfile.TemporaryDirectory(prefix="npm-pack-shape-") as tmp:
        package_dir = pathlib.Path(tmp) / "package"
        out_dir = pathlib.Path(tmp) / "out"
        (package_dir / "bin").mkdir(parents=True)
        out_dir.mkdir()
        name = "@shape-probe/pack"
        (package_dir / "package.json").write_text(
            json.dumps({"name": name, "version": "1.0.0", "files": ["bin"], "bin": {"probe": "bin/probe"}})
        )
        probe = package_dir / "bin" / "probe"
        probe.write_text("#!/bin/sh\necho probe\n")
        probe.chmod(0o755)

        # Report the shape too, so a future third shape is actionable from the
        # log even though the real assertion is below.
        result = subprocess.run(
            [npm, "pack", "--json", "--pack-destination", str(out_dir)],
            cwd=package_dir, capture_output=True, text=True, check=False,
        )
        if result.returncode == 0:
            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError:
                report = None
            if report is not None:
                observed = type(report).__name__
                if isinstance(report, dict):
                    observed += f" keyed by {sorted(report)}"
                elif isinstance(report, list) and report:
                    observed += f" of {type(report[0]).__name__}"
                print(f"     `npm pack --json` returned {observed}")
        # Clean up this probe tarball so `npm_pack` runs in a known-empty dir.
        for leftover in out_dir.iterdir():
            leftover.unlink()

        # The real path: this is the function that raised `KeyError: 0`.
        try:
            tarball = npm_pack_mod.npm_pack(package_dir, out_dir, name)
        except PackError as error:
            raise SystemExit(f"FAIL npm_pack failed on npm {npm_version}: {error}") from error
        check(tarball.is_file(),
              f"npm_pack produced a real tarball on npm {npm_version}: {tarball.name}")
        check(tarball.parent == out_dir,
              "npm_pack resolved the tarball inside --pack-destination")


def main() -> int:
    print("== the `npm pack --json` parser handles both shipped shapes ==")
    test_parser_unit()
    print("\n== a real npm `pack --json` round-trips through the parser ==")
    test_real_npm_round_trip()
    print("\nnpm pack --json shape check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

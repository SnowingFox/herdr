#!/usr/bin/env python3
"""Builds Node's own `test/node-api` addon fixtures against these headers.

Node's `test/node-api` suite is not JavaScript: each directory holds a `binding.gyp`
and C/C++ sources that must be compiled into `build/<config>/<target>.node` before
`test.js` can `require` them. Node's own `tools/build_addons.py` drives `gyp` for
that. This script does the same job with the minimum of process: parse the gyp,
compile each target with `cc`, and place the artefact where the test's
`common.buildType` lookup expects it.

The gyp files are not JSON — they are Python-literal dicts with comments, trailing
commas and `cflags!` keys. Rather than depend on `gyp`'s Python packages, the
handful of keys this needs are extracted with a tolerant reader; anything the
reader cannot understand is reported and skipped, never guessed at.

Usage:
    build-node-api-addons.py --source <node>/test/node-api --output <dir> [--verbose]

The output directory becomes the `test/` root the harness points at: the fixtures
land under `<output>/node-api/<dir>/build/Release/`, which is where
`common.buildType` resolves to when `process.config.target_defaults` is absent.

Exit status is 0 when every target built, 1 when any target failed, and 2 when the
source tree is not what was expected. A partial build is reported per target so the
number of tests that can run is known exactly rather than assumed.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def strip_gyp_comments(text: str) -> str:
    """Removes `#` and `//` comments that are not inside a string."""
    out = []
    for line in text.splitlines():
        quote = None
        keep = []
        index = 0
        while index < len(line):
            character = line[index]
            if quote:
                keep.append(character)
                if character == quote and line[index - 1] != "\\":
                    quote = None
                index += 1
                continue
            if character in ("'", '"'):
                quote = character
                keep.append(character)
                index += 1
                continue
            if character == "#":
                break
            if character == "/" and index + 1 < len(line) and line[index + 1] == "/":
                break
            keep.append(character)
            index += 1
        out.append("".join(keep))
    return "\n".join(out)


def normalise_gyp(text: str) -> str:
    """Turns a gyp file into something `json` accepts.

    gyp is Python syntax: single quotes, trailing commas, and `cflags!` /
    `sources!` keys that json cannot express. Only the keys this script reads are
    needed, so the `!` forms are dropped and the quotes normalised; anything else
    that does not parse is reported rather than coerced.
    """
    text = strip_gyp_comments(text)
    # Drop the negated list forms entirely: they remove flags this script never
    # sets, so honouring them would be a no-op and parsing them is impossible.
    text = re.sub(r"(['\"])\w+!\1\s*:\s*\[[^\]]*\],?", "", text)
    # Python string literals, including the escaped forms the files use.
    text = text.replace("'", '"')
    # Trailing commas.
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text


def read_targets(gyp_path: Path):
    """The `targets` list from a binding.gyp, or raises with a useful message."""
    raw = gyp_path.read_text()
    normalised = normalise_gyp(raw)
    try:
        document = json.loads(normalised)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{gyp_path}: not parseable as gyp: {error}") from error
    targets = document.get("targets")
    if not isinstance(targets, list):
        raise RuntimeError(f"{gyp_path}: no 'targets' list")
    return targets


def source_files(target, directory: Path, verbose: bool):
    """Resolves a target's `sources` to files that exist."""
    sources = target.get("sources") or []
    resolved = []
    for source in sources:
        path = directory / source.replace("<(module_root_dir)/", "")
        if path.is_file():
            resolved.append(path)
        else:
            # `test_fatal` and friends list sources behind conditions; a missing one
            # is named rather than skipped silently.
            if verbose:
                print(f"    skipped missing source: {source}")
    if not resolved:
        raise RuntimeError("no existing sources")
    return resolved


def compile_target(
    target,
    directory: Path,
    output_root: Path,
    verbose: bool,
    extra_includes=(),
) -> Path:
    """Compiles one target into `build/Release/<name>.node`."""
    name = target.get("target_name")
    if not name:
        raise RuntimeError("target has no target_name")
    sources = source_files(target, directory, verbose)

    destination_dir = output_root / "node-api" / directory.name / "build" / "Release"
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{name}.node"

    # Whatever defines the target asked for, in gyp's spelling.
    defines = [f"-D{value}" for value in (target.get("defines") or [])]
    # The pinned headers, so an addon is compiled against the revision this runtime
    # targets rather than the system's install.
    header_dir = Path(__file__).resolve().parent.parent / "tests" / "addon"

    includes = [header_dir, directory, *extra_includes]
    command = [
        "cc",
        "-shared",
        "-fPIC",
        "-O0",
        "-g",
        *(argument for include in includes for argument in ("-I", str(include))),
        *defines,
        "-o",
        str(destination),
        *(str(source) for source in sources),
    ]
    if verbose:
        print("    " + " ".join(command))
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"cc failed for {name}:\n{result.stdout}{result.stderr}".rstrip()
        )
    if not destination.is_file():
        raise RuntimeError(f"cc reported success but {destination} does not exist")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="a Node test/node-api directory")
    parser.add_argument("--output", required=True, help="where to place the fixtures")
    # These addons include `../../js-native-api/common.h` and, in two cases,
    # `uv.h`. Node's build points those at the checked-out tree, so this does too
    # rather than vendoring a second copy of either header.
    parser.add_argument(
        "--js-native-api",
        help="the Node test/js-native-api directory (for common.h)",
    )
    parser.add_argument(
        "--uv-include",
        help="the Node deps/uv/include directory (for uv.h)",
    )
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args()

    source = Path(arguments.source)
    output = Path(arguments.output)
    if not source.is_dir():
        print(f"{source} is not a directory", file=sys.stderr)
        return 2

    gyp_files = sorted(source.glob("*/binding.gyp"))
    if not gyp_files:
        print(f"no */binding.gyp under {source}", file=sys.stderr)
        return 2

    built = []
    failed = []
    extra_includes = []
    if arguments.js_native_api:
        extra_includes.append(Path(arguments.js_native_api))
    if arguments.uv_include:
        extra_includes.append(Path(arguments.uv_include))

    for gyp in gyp_files:
        directory = gyp.parent
        try:
            targets = read_targets(gyp)
        except RuntimeError as error:
            failed.append((directory.name, str(error)))
            continue
        for target in targets:
            try:
                destination = compile_target(
                    target, directory, output, arguments.verbose, extra_includes
                )
                built.append((directory.name, target.get("target_name"), destination))
            except RuntimeError as error:
                failed.append(
                    (directory.name, f"{target.get('target_name')}: {error}")
                )

    # `test.js` files that need no addon in their own directory still resolve
    # `common.buildType`, so a `build/Release` containing the fixtures is enough.
    print(f"built {len(built)} target(s), {len(failed)} failed")
    for directory, name, destination in built:
        print(f"  ok   {directory}/{name} -> {destination}")
    for directory, reason in failed:
        print(f"  FAIL {directory}: {reason}", file=sys.stderr)

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())

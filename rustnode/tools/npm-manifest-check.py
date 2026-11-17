#!/usr/bin/env python3
"""Check the npm package manifests against the sources they duplicate.

The npm packaging repeats three facts that are owned elsewhere:

* the version, which is `[workspace.package] version` in `rustnode/Cargo.toml`;
* the platform list, which is `npm/platforms.json`;
* the command name and binary path, which the wrapper in `npm/bin/` resolves.

Each of those is a copy, and every copy can drift. The drifts are all silent:
a version mismatch publishes a tarball whose optional dependency can never
resolve, and an `os`/`cpu` typo publishes a package npm happily installs on a
host where its command cannot work.

This is the cheap half of the check — no build, no network, no `npm` — so it can
run in the per-commit gate. `npm-pack.py pack` is the strong half: it builds the
tarballs, reads them back, and hashes the binary inside each one. That needs a
release build, so it belongs to CI rather than here.

Exit status is the verdict, and every check names the file and the values it
compared, so a failure is actionable without re-deriving anything.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
RUSTNODE_DIR = TOOLS_DIR.parent
NPM_DIR = RUSTNODE_DIR / "npm"


class Drift(Exception):
    """A manifest disagrees with a source of truth."""


def cargo_version() -> str:
    with (RUSTNODE_DIR / "Cargo.toml").open("rb") as handle:
        version = tomllib.load(handle)["workspace"]["package"]["version"]
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", version):
        raise Drift(f"rustnode/Cargo.toml: [workspace.package] version {version!r} is not a semver")
    return version


def load(path: pathlib.Path) -> dict:
    with path.open("rb") as handle:
        return json.load(handle)


def main() -> int:
    failures: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if condition:
            print(f"ok   {message}")
        else:
            failures.append(message)
            print(f"FAIL {message}", file=sys.stderr)

    version = cargo_version()
    platforms = load(NPM_DIR / "platforms.json")
    package = load(NPM_DIR / "package.json")

    scope = platforms["scope"]
    command = platforms["command"]
    binary = platforms["binary"]

    # The main manifest's identity.
    expect(package["name"] == f"{scope}/{command}",
           f"package.json name {package['name']!r} is {scope}/{command}")
    expect(package["version"] == version,
           f"package.json version {package['version']!r} matches Cargo.toml {version!r}")
    expect(package.get("bin") == {command: f"bin/{command}"},
           f"package.json installs {command!r} from bin/{command}")

    # Every platform dependency is present, at this version, and nothing else is.
    expected_deps = {f"{scope}/{command}-{entry['target']}": version for entry in platforms["platforms"]}
    expect(package.get("optionalDependencies") == expected_deps,
           f"optionalDependencies is exactly what platforms.json generates ({len(expected_deps)} entries)")

    # os/cpu/libc are the npm-level gate. They must agree with the platform
    # list, or npm installs a package whose command cannot find a binary.
    expect(set(package.get("os", [])) == {entry["os"] for entry in platforms["platforms"]},
           f"package.json os {package.get('os')} covers the platform list")
    expect(set(package.get("cpu", [])) == {entry["cpu"] for entry in platforms["platforms"]},
           f"package.json cpu {package.get('cpu')} covers the platform list")
    listed_libcs = {entry["libc"] for entry in platforms["platforms"] if "libc" in entry}
    expect(set(package.get("libc", [])) == listed_libcs,
           f"package.json libc {package.get('libc')} matches the platform list")

    # `files` must name the wrapper and the documents the packages promise. This
    # is the reduction that produced the class of bug `npm-pack.py` exists to
    # catch, so at least the static half is enforced here.
    files = package.get("files", [])
    for required in (f"bin/{command}", "LICENSE", "README.md", "THIRD-PARTY-NOTICES.md"):
        expect(required in files, f"package.json files includes {required}")
    for shipped in ("LICENSE", "README.md", "THIRD-PARTY-NOTICES.md", f"bin/{command}"):
        expect((NPM_DIR / shipped).is_file(), f"npm/{shipped} exists")

    # The wrapper has to name the same scope, package and platform names the
    # table does, or it resolves a path nothing installs. Reading the script is
    # crude but exact: these are the literals it interpolates into every path.
    wrapper = (NPM_DIR / "bin" / command).read_text(encoding="utf-8")
    expect(wrapper.startswith("#!/bin/sh\n"), f"bin/{command} is a POSIX sh script")
    expect(f"scope={scope}" in wrapper, f"bin/{command} hard-codes scope={scope}")
    expect(f"package={command}" in wrapper, f"bin/{command} hard-codes package={command}")
    expect(f"platform={command}-{platforms['platforms'][0]['target']}" in wrapper,
           f"bin/{command} names platform {command}-{platforms['platforms'][0]['target']}")
    expect("exec " in wrapper, f"bin/{command} execs the binary (signals and exit status pass through)")
    # Only builtins may run before the exec: an external `dirname`/`pwd` here
    # costs a fork on every invocation, which is what the measurements in that
    # file exist to prevent. Full-line comments are excluded because this file's
    # prose deliberately quotes the slow version it replaced, and a check that
    # read its own documentation as code would make explaining the defect
    # impossible.
    code = "\n".join(
        line for line in wrapper.splitlines()
        if not line.lstrip().startswith("#")
    )
    for forbidden in ("$(dirname", "$(pwd", "`dirname", "`pwd"):
        expect(forbidden not in code, f"bin/{command} never forks for {forbidden!r}")
    # `readlink` is allowed, but only past the fast path: it is the fallback for
    # a layout npm does not produce, and calling it on the common path measured
    # +0.4 ms per invocation. The helper that wraps it is *defined* above the
    # fast path, which costs nothing — what matters is that nothing calls it
    # before the candidates have been tried, so this looks for calls.
    slow_marker = "if ! find_binary \"$self\"; then"
    expect(slow_marker in code, f"bin/{command} keeps the fast path first and the link-walking fallback second")
    if slow_marker in code:
        fast_path, slow_path = code.split(slow_marker, 1)
        expect("resolve_link " not in fast_path,
               f"bin/{command}'s fast path never calls the readlink helper")
        expect("resolve_link " in slow_path,
               f"bin/{command}'s fallback still follows links")

    # The binary's name in the platform package must be the file the wrapper
    # looks for, and the platform package must ship it.
    expect(binary == command, f"platforms.json binary {binary!r} is the file the wrapper execs")
    expect(platforms["node_compat"] in (NPM_DIR / "README.md").read_text(encoding="utf-8"),
           f"README documents the Node API level {platforms['node_compat']}")

    if failures:
        print(f"\nnpm-manifest-check: {len(failures)} problem(s)", file=sys.stderr)
        return 1
    print("\nnpm manifests agree with their sources")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Drift as error:
        print(f"npm-manifest-check: {error}", file=sys.stderr)
        sys.exit(1)

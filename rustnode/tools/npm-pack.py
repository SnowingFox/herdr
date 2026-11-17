#!/usr/bin/env python3
"""Build and verify the npm packages that ship the rustnode binary.

Two commands, because they answer two different questions:

    pack    build the tarballs, and prove each one carries its binary
    check   re-verify tarballs that already exist, without rebuilding them

`pack` is the one you run before publishing. It is deterministic: the same
binary and version produce byte-identical tarballs, which is what makes a
checksum in a release note meaningful. `npm pack` already normalises every
member's mtime to 1985-10-26 and its uid/gid to 0, so this script adds no
timestamps of its own and copies the binary without touching it.

Why the tarball is read back rather than trusted: npm's `files` field is a
*reduction* list, and a reduction that silently drops the binary produces an
install that succeeds and a command that does not exist. Every packaging mistake
in this directory is of that shape, so the check opens each tarball, asserts the
binary is present at the path the wrapper resolves, and compares its sha256 to
the input. A package whose `files` field is wrong cannot pass.

The platform list is `platforms.json`; the version comes from the `[workspace.
package]` table in `rustnode/Cargo.toml`, so the two cannot drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib

# Where this script lives, and the tree it packages.
TOOLS_DIR = pathlib.Path(__file__).resolve().parent
RUSTNODE_DIR = TOOLS_DIR.parent
REPO_DIR = RUSTNODE_DIR.parent
NPM_DIR = RUSTNODE_DIR / "npm"

DEFAULT_TARGET = RUSTNODE_DIR / "target" / "release" / "rustnode"
DEFAULT_OUT = RUSTNODE_DIR / "target" / "npm"

# Files every package of this set ships. The LICENSE is the MIT text the
# rustnode workspace declares; the notices cover what that MIT grant does not:
# the vendored Node, llhttp, merve, nghttp2 and SQLite sources and the statically
# linked OpenSSL, all of which end up inside the binary that gets published.
LICENSE_SRC = NPM_DIR / "LICENSE"
NOTICES_SRC = NPM_DIR / "THIRD-PARTY-NOTICES.md"
MAIN_README_SRC = NPM_DIR / "README.md"
BIN_SRC = NPM_DIR / "bin" / "rsnode"


class PackError(Exception):
    """A packaging failure whose message is meant for the operator."""


def read_version() -> str:
    """The version both packages carry, from the rustnode workspace table.

    `rn-cli` declares `version.workspace = true`, so this is the one number that
    describes the binary. Taking it from here rather than from an npm field
    means a version bump cannot leave the two disagreeing.
    """
    manifest = RUSTNODE_DIR / "Cargo.toml"
    with manifest.open("rb") as handle:
        cargo = tomllib.load(handle)
    try:
        version = cargo["workspace"]["package"]["version"]
    except KeyError as error:
        raise PackError(f"{manifest} has no [workspace.package] version: {error}") from error
    if not isinstance(version, str) or not version:
        raise PackError(f"{manifest}: [workspace.package] version is not a non-empty string")
    return version


def read_platforms() -> dict:
    """The platform table, with the fields this script depends on validated."""
    path = NPM_DIR / "platforms.json"
    with path.open("rb") as handle:
        table = json.load(handle)
    for key in ("scope", "command", "binary", "node_compat", "platforms"):
        if key not in table:
            raise PackError(f"{path}: missing required key {key!r}")
    if not table["platforms"]:
        raise PackError(f"{path}: no platforms listed; refusing to publish a package with no binary")
    for entry in table["platforms"]:
        missing = {"target", "os", "cpu"} - entry.keys()
        if missing:
            raise PackError(f"{path}: platform {entry.get('target', '?')} is missing {sorted(missing)}")
    return table


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def platform_package_name(table: dict, entry: dict) -> str:
    """`@scope/rsnode-linux-x64`, matching what the wrapper resolves."""
    return f"{table['scope']}/{table['command']}-{entry['target']}"


def main_package_name(table: dict) -> str:
    return f"{table['scope']}/{table['command']}"


def platform_manifest(table: dict, entry: dict, version: str) -> dict:
    """The platform package's package.json.

    `os`/`cpu`/`libc` are what make npm pick this package on this host and skip
    it everywhere else, so they are copied from the table rather than inferred.
    `preferUnplugged` asks yarn not to zip it: a binary executed out of a zip
    archive is at best slower and at worst impossible.
    """
    manifest = {
        "name": platform_package_name(table, entry),
        "version": version,
        "description": (
            f"The {entry['os']} {entry['cpu']} rustnode binary. Installed by "
            f"{main_package_name(table)}; not meant to be depended on directly."
        ),
        "homepage": "https://github.com/SnowingFox/herdr/tree/master/rustnode",
        "repository": {
            "type": "git",
            "url": "git+https://github.com/SnowingFox/herdr.git",
            "directory": "rustnode",
        },
        "license": "MIT",
        "os": [entry["os"]],
        "cpu": [entry["cpu"]],
        "preferUnplugged": True,
        # The binary is not a `bin` of this package. npm links only the
        # top-level package's bins into a prefix, so a `bin` here would be
        # linked in a local install and silently not linked in a global one;
        # the wrapper in the main package owns the command on both paths.
        "files": [table["binary"], "LICENSE", "THIRD-PARTY-NOTICES.md"],
    }
    if "libc" in entry:
        manifest["libc"] = [entry["libc"]]
    return manifest


def main_manifest(table: dict, version: str) -> dict:
    """The main package's package.json, with optionalDependencies generated.

    The `optionalDependencies` block is derived from platforms.json so a new
    target cannot be added to the table and forgotten here; `pack` rewrites this
    file in the staging copy and `check` compares against it.
    """
    path = NPM_DIR / "package.json"
    with path.open("rb") as handle:
        manifest = json.load(handle)
    expected_name = main_package_name(table)
    if manifest.get("name") != expected_name:
        raise PackError(
            f"{path}: name is {manifest.get('name')!r} but platforms.json generates {expected_name!r}"
        )
    if manifest.get("version") != version:
        raise PackError(f"{path}: version is {manifest.get('version')!r} but Cargo.toml says {version!r}")
    manifest["optionalDependencies"] = {
        platform_package_name(table, entry): version for entry in table["platforms"]
    }
    # os/cpu/libc on the main package describe the hosts it is *willing* to
    # install on. Deriving them keeps this from drifting from the platform list,
    # and npm uses them to refuse the install outright on anything else rather
    # than installing a package whose command cannot work.
    manifest["os"] = sorted({entry["os"] for entry in table["platforms"]})
    manifest["cpu"] = sorted({entry["cpu"] for entry in table["platforms"]})
    libcs = sorted({entry["libc"] for entry in table["platforms"] if "libc" in entry})
    if libcs:
        manifest["libc"] = libcs
    else:
        manifest.pop("libc", None)
    return manifest


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def npm_pack(package_dir: pathlib.Path, out_dir: pathlib.Path) -> pathlib.Path:
    """Run `npm pack` and return the tarball it wrote.

    `--pack-destination` keeps the tarball out of the package directory, which
    matters because a tarball left there would be picked up by the next pack.
    """
    result = subprocess.run(
        ["npm", "pack", "--pack-destination", str(out_dir), "--json"],
        cwd=package_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise PackError(f"npm pack failed in {package_dir}:\n{result.stderr or result.stdout}")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PackError(f"npm pack in {package_dir} printed unparseable JSON: {error}") from error
    if not report:
        raise PackError(f"npm pack in {package_dir} reported no tarball")
    filename = report[0]["filename"]
    tarball = out_dir / filename
    if not tarball.is_file():
        raise PackError(f"npm pack reported {filename} but {tarball} does not exist")
    return tarball


def verify_tarball(
    tarball: pathlib.Path,
    *,
    required: list[str],
    binary_member: str | None = None,
    binary_sha256: str | None = None,
    manifest_member: str = "package/package.json",
) -> dict:
    """Open a tarball and assert it carries what the package claims.

    `required` is checked against the real member list, not against `files`: the
    question is what a user receives, and `files` is only a prediction of it.
    When `binary_member` is given, its content is hashed and compared to the
    input binary, so a truncated or replaced member fails here rather than on a
    user's machine.
    """
    with tarfile.open(tarball, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        for name in required:
            if name not in members:
                raise PackError(
                    f"{tarball.name} does not contain {name}; `files` dropped it. "
                    f"Present: {sorted(members)}"
                )
        manifest_file = archive.extractfile(manifest_member)
        if manifest_file is None:
            raise PackError(f"{tarball.name} has no readable {manifest_member}")
        manifest = json.loads(manifest_file.read().decode("utf-8"))
        if binary_member is not None:
            member = members.get(binary_member)
            if member is None:
                raise PackError(f"{tarball.name} does not contain the binary at {binary_member}")
            # The exec bit is not cosmetic: npm preserves the mode it packs, and
            # a non-executable binary fails at exec time, after a successful
            # install.
            if not member.mode & 0o111:
                raise PackError(
                    f"{tarball.name}: {binary_member} is mode {member.mode:o}, which is not executable"
                )
            extracted = archive.extractfile(member)
            if extracted is None:
                raise PackError(f"{tarball.name}: cannot read {binary_member}")
            digest = hashlib.sha256()
            for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                digest.update(chunk)
            actual = digest.hexdigest()
            if binary_sha256 is not None and actual != binary_sha256:
                raise PackError(
                    f"{tarball.name}: {binary_member} hashes to {actual}, "
                    f"but the input binary is {binary_sha256}"
                )
    return manifest


def stage_common(stage: pathlib.Path) -> None:
    shutil.copy2(LICENSE_SRC, stage / "LICENSE")
    shutil.copy2(NOTICES_SRC, stage / "THIRD-PARTY-NOTICES.md")


def command_pack(args: argparse.Namespace) -> int:
    table = read_platforms()
    version = read_version()
    binary = args.binary
    if not binary.is_file():
        raise PackError(
            f"no binary at {binary}. Build one with `cargo build --release -p rn-cli`, "
            "or pass --binary, before packing."
        )
    digest = sha256(binary)
    out_dir = args.out
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    print(f"binary   {binary}")
    print(f"sha256   {digest}")
    print(f"version  {version}")
    print(f"out      {out_dir}")

    results = []
    # The staging tree lives outside the repository so a failed run cannot leave
    # a half-written package where the next `git status` has to explain it.
    with tempfile.TemporaryDirectory(prefix="rsnode-npm-stage-") as staging_root:
        staging_root = pathlib.Path(staging_root)

        main_stage = staging_root / "main"
        (main_stage / "bin").mkdir(parents=True)
        shutil.copy2(BIN_SRC, main_stage / "bin" / table["command"])
        (main_stage / "bin" / table["command"]).chmod(0o755)
        shutil.copy2(MAIN_README_SRC, main_stage / "README.md")
        stage_common(main_stage)
        write_json(main_stage / "package.json", main_manifest(table, version))
        main_tarball = npm_pack(main_stage, out_dir)
        manifest = verify_tarball(
            main_tarball,
            required=[
                "package/package.json",
                "package/README.md",
                "package/LICENSE",
                "package/THIRD-PARTY-NOTICES.md",
                f"package/bin/{table['command']}",
            ],
        )
        results.append(
            {
                "package": manifest["name"],
                "version": manifest["version"],
                "tarball": main_tarball.name,
                "sha256": sha256(main_tarball),
                "size": main_tarball.stat().st_size,
            }
        )

        for entry in table["platforms"]:
            stage = staging_root / entry["target"]
            stage.mkdir()
            shutil.copy2(binary, stage / table["binary"])
            (stage / table["binary"]).chmod(0o755)
            stage_common(stage)
            write_json(stage / "package.json", platform_manifest(table, entry, version))
            tarball = npm_pack(stage, out_dir)
            manifest = verify_tarball(
                tarball,
                # The binary is required by name: this is the assertion that a
                # narrowed `files` field cannot pass.
                required=[
                    "package/package.json",
                    "package/LICENSE",
                    "package/THIRD-PARTY-NOTICES.md",
                    f"package/{table['binary']}",
                ],
                binary_member=f"package/{table['binary']}",
                binary_sha256=digest,
            )
            if manifest.get("name") != platform_package_name(table, entry):
                raise PackError(f"{tarball.name}: manifest names {manifest.get('name')!r}")
            results.append(
                {
                    "package": manifest["name"],
                    "version": manifest["version"],
                    "tarball": tarball.name,
                    "sha256": sha256(tarball),
                    "size": tarball.stat().st_size,
                }
            )

    write_json(out_dir / "packages.json", {"binary_sha256": digest, "packages": results})
    print()
    for result in results:
        print(f"{result['tarball']}  {result['size']:>10} bytes  sha256 {result['sha256']}")
    print(f"\nwrote {out_dir / 'packages.json'}")
    return 0


def command_check(args: argparse.Namespace) -> int:
    """Re-verify tarballs already in `--out` against the current tree.

    Separate from `pack` so a release can be verified from the artifacts alone,
    which is the only form in which "these are the bytes we published" can be
    asked after the fact.
    """
    table = read_platforms()
    version = read_version()
    out_dir = args.out
    index_path = out_dir / "packages.json"
    if not index_path.is_file():
        raise PackError(f"{index_path} is missing; run `pack` first")
    with index_path.open("rb") as handle:
        index = json.load(handle)
    if args.binary:
        expected_binary_sha = sha256(args.binary)
        if index.get("binary_sha256") != expected_binary_sha:
            raise PackError(
                f"{index_path} records binary {index.get('binary_sha256')}, "
                f"but {args.binary} is {expected_binary_sha}"
            )
    failures = 0
    for record in index["packages"]:
        tarball = out_dir / record["tarball"]
        try:
            if not tarball.is_file():
                raise PackError(f"{tarball} is missing")
            actual = sha256(tarball)
            if actual != record["sha256"]:
                raise PackError(f"{tarball.name} hashes to {actual}, index says {record['sha256']}")
            with tarfile.open(tarball, "r:gz") as archive:
                names = sorted(archive.getnames())
                manifest_file = archive.extractfile("package/package.json")
                if manifest_file is None:
                    raise PackError(f"{tarball.name} has no readable package/package.json")
                manifest = json.loads(manifest_file.read().decode("utf-8"))
            if manifest["version"] != version:
                raise PackError(f"{tarball.name} is version {manifest['version']}, tree says {version}")
            if record["package"] == main_package_name(table):
                expected = {platform_package_name(table, e): version for e in table["platforms"]}
                if manifest.get("optionalDependencies") != expected:
                    raise PackError(
                        f"{tarball.name}: optionalDependencies {manifest.get('optionalDependencies')} "
                        f"do not match platforms.json {expected}"
                    )
            else:
                binary_member = f"package/{table['binary']}"
                if binary_member not in names:
                    raise PackError(f"{tarball.name} does not contain {binary_member}")
            print(f"ok  {tarball.name}  ({len(names)} files)")
        except PackError as error:
            failures += 1
            print(f"FAIL {error}", file=sys.stderr)
    if failures:
        raise PackError(f"{failures} of {len(index['packages'])} packages failed verification")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pack = subparsers.add_parser("pack", help="build the tarballs and verify each one")
    pack.add_argument("--binary", type=pathlib.Path, default=DEFAULT_TARGET)
    pack.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    pack.set_defaults(func=command_pack)

    check = subparsers.add_parser("check", help="verify tarballs that already exist")
    check.add_argument("--binary", type=pathlib.Path, default=None)
    check.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    check.set_defaults(func=command_check)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PackError as error:
        print(f"npm-pack: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

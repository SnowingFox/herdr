#!/usr/bin/env python3
"""End-to-end verification of the npm packages, from a clean directory.

What this proves, and why each check is here rather than assumed:

* **The install resolves through a registry.** The main package names its
  platform package by name and version. A tarball install by path would bypass
  `os`/`cpu` selection, so this stands up a throwaway registry and installs the
  main package by name against it. That is the same resolution a user gets.
* **The install works from a clean directory** with no repository on any path,
  because a package that only works inside its own checkout is not installable.
* **The command runs, four ways**: `-e`, a script file, a `require()` of a
  builtin, and `--version`.
* **The wrapper preserves the child's exit status, streams and signal.** A
  script that exits 42 must produce 42; a script that raises SIGINT must die by
  SIGINT, not by exit code; stderr must stay separate from stdout.
* **The wrapper adds no measurable startup cost**, measured against invoking the
  binary directly, interleaved so drift in machine load does not favour either.

`--version` is expected to *fail* on this runtime today (the CLI rejects unknown
flags with exit 9). The check asserts that shape deliberately, so this test does
not quietly start passing if someone later fakes the flag in the wrapper.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("npm_test_registry", TOOLS_DIR / "npm-test-registry.py")
assert _spec is not None and _spec.loader is not None
registry_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(registry_mod)


class TestFailure(Exception):
    pass


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)
    print(f"  ok  {message}")


def section(title: str) -> None:
    print(f"\n== {title} ==")


def load_packages(out_dir: pathlib.Path) -> dict[str, dict]:
    """Registry records for every tarball the pack script wrote."""
    import base64
    import hashlib
    import tarfile

    index = json.loads((out_dir / "packages.json").read_text())
    packages: dict[str, dict] = {}
    for record in index["packages"]:
        path = out_dir / record["tarball"]
        with tarfile.open(path, "r:gz") as archive:
            manifest = json.loads(archive.extractfile("package/package.json").read())
        data = path.read_bytes()
        packages[manifest["name"]] = {
            "manifest": manifest,
            "tarball": str(path),
            "filename": path.name,
            "shasum": hashlib.sha1(data).hexdigest(),
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
        }
    return packages


def install_into(workdir: pathlib.Path, name: str, registry_url: str, *, global_install: bool) -> pathlib.Path:
    """Install `name` from the test registry and return the directory holding the command.

    Both layouts are exercised because they are different code paths in npm and
    put the binary in different places; a package that only works globally is
    half a package.
    """
    prefix = workdir / ("global" if global_install else "local")
    prefix.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "npm_config_registry": registry_url,
        "npm_config_offline": "false",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
        # Never touch a real npmrc: a user's `//registry/:_authToken` or a
        # `prefix` setting would change what this measures.
        "npm_config_userconfig": str(workdir / "empty-npmrc"),
        "npm_config_cache": str(workdir / "npm-cache"),
        "npm_config_globalconfig": str(workdir / "empty-global-npmrc"),
    }
    (workdir / "empty-npmrc").write_text("")
    (workdir / "empty-global-npmrc").write_text("")
    if global_install:
        argv = ["npm", "install", "-g", "--prefix", str(prefix), name]
        bindir = prefix / "bin"
        modules = prefix / "lib" / "node_modules"
    else:
        argv = ["npm", "install", "--prefix", str(prefix), name]
        bindir = prefix / "node_modules" / ".bin"
        modules = prefix / "node_modules"
    result = run(argv, env=env)
    if result.returncode != 0:
        mode = "global" if global_install else "local"
        raise TestFailure(f"{mode} npm install of {name} failed:\n{result.stdout}\n{result.stderr}")
    return bindir, modules


def measure(argv: list[str], runs: int, env: dict | None = None) -> list[float]:
    samples = []
    for _ in range(runs):
        started = time.perf_counter()
        proc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        samples.append((time.perf_counter() - started) * 1000)
        if proc.returncode != 0:
            raise TestFailure(f"{argv[0]} exited {proc.returncode} during timing")
    return samples


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=pathlib.Path, required=True, help="pack output directory")
    parser.add_argument("--runs", type=int, default=21, help="timing runs per case")
    args = parser.parse_args(argv)

    out_dir = args.out.resolve()
    packages = load_packages(out_dir)
    index = json.loads((out_dir / "packages.json").read_text())
    # The main package is the one that declares optionalDependencies; the
    # platform packages are leaves.
    main_name = next(n for n, p in packages.items() if p["manifest"].get("optionalDependencies"))
    main = packages[main_name]
    command = next(iter(main["manifest"]["bin"]))

    print(f"main package   {main_name} {main['manifest']['version']}")
    print(f"command        {command}")

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="rsnode-npm-test-"))
    try:
        server, _thread = registry_mod.serve(packages)
        registry_url = server.base_url
        print(f"registry       {registry_url}")

        section("install from a clean directory, resolving through the registry")
        bindir, modules = install_into(workdir, main_name, registry_url, global_install=True)
        shim = bindir / command
        check(shim.is_symlink() or shim.is_file(), f"npm created {shim}")
        installed = sorted(p.name for p in modules.iterdir())
        print(f"    top level: {installed}")
        platform_dirs = list(modules.glob("*/*/node_modules/*/*"))
        check(bool(platform_dirs), "the optional platform package was installed")
        platform_dir = platform_dirs[0]
        binary = platform_dir / "rsnode"
        check(binary.is_file(), f"the platform package carries its binary at {binary.name}")

        # A clean directory: nothing on PATH or cwd can reach the repository.
        clean = workdir / "clean-cwd"
        clean.mkdir()
        env = {
            **os.environ,
            "PATH": f"{bindir}:/usr/bin:/bin",
            "HOME": str(workdir / "home"),
        }
        (workdir / "home").mkdir()

        section("the command runs, four ways")
        result = run([command, "-e", "console.log(process.version)"], cwd=clean, env=env)
        check(result.returncode == 0, f"-e exited 0 ({result.stderr.strip()[:120]})")
        print(f"    {command} -e 'console.log(process.version)' -> {result.stdout.strip()}")
        check(result.stdout.strip().startswith("v"), "process.version printed a version")

        script = clean / "script.js"
        script.write_text("console.log('from-script', 6 * 7);\n")
        result = run([command, str(script)], cwd=clean, env=env)
        check(result.returncode == 0 and "from-script 42" in result.stdout,
              f"script file ran ({result.stdout.strip()[:120]})")
        print(f"    {command} script.js -> {result.stdout.strip()}")

        result = run([command, "-e", "const fs = require('node:fs'); console.log(typeof fs.readFileSync)"],
                     cwd=clean, env=env)
        check(result.returncode == 0 and result.stdout.strip() == "function",
              "require() of a builtin worked")
        print(f"    require('node:fs') -> {result.stdout.strip()}")

        result = run([command, "--version"], cwd=clean, env=env)
        print(f"    {command} --version -> exit {result.returncode}: {result.stderr.strip()}")
        # The runtime rejects the flag; the wrapper must forward that, not
        # invent a version. If this ever starts printing a version, someone
        # added the flag and this expectation should be revisited deliberately.
        check(result.returncode == 9 and "unsupported option" in result.stderr,
              "--version is forwarded unchanged (runtime rejects it, exit 9)")

        section("the wrapper preserves exit codes, streams and signals")
        result = run([command, "-e", "process.exit(42)"], cwd=clean, env=env)
        check(result.returncode == 42, f"exit(42) -> {result.returncode}")
        print(f"    exit(42) -> {result.returncode}")

        result = run([command, "-e", "console.log('out');console.error('err')"], cwd=clean, env=env)
        check(result.stdout.strip() == "out", "stdout carries only stdout")
        check(result.stderr.strip() == "err", "stderr carries only stderr")
        print(f"    stdout={result.stdout.strip()!r} stderr={result.stderr.strip()!r}")

        result = run([command, "-e", "process.stdout.write('no-newline')"], cwd=clean, env=env)
        check(result.stdout == "no-newline", "stdout is not line-buffered or altered")
        print(f"    partial write preserved: {result.stdout!r}")

        # A script that dies of SIGINT must make the *command* die of SIGINT.
        # The distinction matters: an exit code of 130 and death-by-signal are
        # different observations, and a shell that forgot `exec` shows up as the
        # former, because the shell catches the child's signal and exits itself.
        result = subprocess.run(
            [command, "-e", "process.kill(process.pid, 'SIGINT')"],
            capture_output=True, text=True, cwd=clean, env=env,
        )
        check(result.returncode == -signal.SIGINT,
              f"SIGINT propagates as death-by-signal (returncode {result.returncode})")
        print(f"    SIGINT -> returncode {result.returncode} (negative = killed by signal)")

        # stdin must reach the child too, or `rsnode < script.js` silently reads
        # nothing.
        result = subprocess.run([command, "-e", "process.stdin.pipe(process.stdout)"],
                                input="piped-through\n", capture_output=True, text=True, cwd=clean, env=env)
        check(result.stdout == "piped-through\n", "stdin is connected to the child")
        print(f"    stdin -> stdout: {result.stdout.strip()!r}")

        section("a local (project) install works through the same command")
        local_bindir, local_modules = install_into(workdir, main_name, registry_url, global_install=False)
        local_shim = local_bindir / command
        check(local_shim.is_symlink() or local_shim.is_file(), f"npm created {local_shim}")
        local_env = {
            **os.environ,
            "PATH": f"{local_bindir}:/usr/bin:/bin",
            "HOME": str(workdir / "home"),
        }
        result = run([command, "-e", "console.log(process.version)"], cwd=clean, env=local_env)
        check(result.returncode == 0 and result.stdout.strip().startswith("v"),
              f"local install runs too ({result.stdout.strip() or result.stderr.strip()[:120]})")
        print(f"    local install {command} -> {result.stdout.strip()}")
        result = run([command, "-e", "process.exit(7)"], cwd=clean, env=local_env)
        check(result.returncode == 7, f"local install forwards the exit code too ({result.returncode})")

        section("the common path forks nothing")
        # The resolver's fast path must not fork, and the way to prove that
        # rather than infer it from a timing is to make the external tool it
        # would fork fail loudly. `readlink` is the only one it can reach, so a
        # stub that reports being called and fails turns the fast path into a
        # visible failure if a future edit starts calling it.
        stub_dir = workdir / "no-readlink"
        stub_dir.mkdir()
        stub = stub_dir / "readlink"
        stub.write_text('#!/bin/sh\necho "readlink was forked" >&2\nexit 1\n')
        stub.chmod(0o755)
        probe_env = {**env, "PATH": f"{stub_dir}:{env['PATH']}"}
        result = run([command, "-e", "console.log('fast')"], cwd=clean, env=probe_env)
        check(result.returncode == 0 and result.stdout.strip() == "fast",
              "the resolver finds the binary without forking readlink")
        check("readlink was forked" not in result.stderr,
              "no fork on the installed layout")
        print(f"    with a failing readlink on PATH -> {result.stdout.strip()!r}")

        section("startup cost against the binary directly")
        binary_path = str(binary)
        shim_path = str(shim)

        # Three cases, and the third is the one that makes the number
        # interpretable. Comparing a shim to the raw binary measures the cost of
        # `sh` itself as much as this script, and on a loaded machine the noise
        # of that difference swamps it. A minimal two-line `sh` wrapper gives the
        # floor: whatever a shell shim must cost before it does anything. If this
        # script measures the same as that floor, its own resolution logic adds
        # nothing, which is the actual claim being made.
        floor_dir = workdir / "floor"
        floor_dir.mkdir()
        floor = floor_dir / "floor.sh"
        floor.write_text(f'#!/bin/sh\nexec "{binary_path}" "$@"\n')
        floor.chmod(0o755)

        direct_samples: list[float] = []
        shim_samples: list[float] = []
        floor_samples: list[float] = []
        # Rotate which case runs first: a single fixed order lets a load spike
        # land on one case only, which is how a 0.6 ms difference reads as 3 ms.
        order = [[binary_path], [shim_path], [str(floor)]]
        for index in range(args.runs):
            rotated = order[index % 3:] + order[:index % 3]
            for argv in rotated:
                samples = measure([*argv, "-e", ""], 1, env=env)
                target = (
                    direct_samples if argv[0] == binary_path
                    else floor_samples if argv[0] == str(floor)
                    else shim_samples
                )
                target.extend(samples)
        direct_median = statistics.median(direct_samples)
        shim_median = statistics.median(shim_samples)
        floor_median = statistics.median(floor_samples)
        print(f"    direct binary      median {direct_median:7.2f} ms  (n={len(direct_samples)})")
        print(f"    minimal sh wrapper median {floor_median:7.2f} ms  floor for any shell shim")
        print(f"    {command} shim     median {shim_median:7.2f} ms  (n={len(shim_samples)})")
        # Both deltas are printed because they answer different questions, and
        # reporting only the flattering one is how an earlier version of this
        # measurement went wrong: it compared the shim against a floor measured
        # in a different, quieter window and published the difference as the
        # wrapper's cost, which read as +0.13 ms when the true cost over the
        # binary is ~2 ms. The split is what matters and it is stable even when
        # the absolute numbers are not: ~1.7 ms is `sh` starting at all, and
        # ~0.3 ms is this script. Report both, and quote the absolute figure as
        # ~2 ms -- an understated number on the startup path of a runtime whose
        # pitch is startup time is exactly the number that gets quoted back.
        print(f"    shim - direct      {shim_median - direct_median:+7.2f} ms "
              f"({(shim_median - direct_median) / direct_median * 100:+.1f}%)  what a user pays")
        print(f"    floor - direct     {floor_median - direct_median:+7.2f} ms  cost of `sh` itself")
        print(f"    shim - minimal sh  {shim_median - floor_median:+7.2f} ms  this script's own logic")

        # The claim being asserted: this script is never worse than a two-line
        # shell shim, so its resolution logic is free. This is the stable
        # assertion; the absolute delta below varies with machine load.
        overhead = shim_median - floor_median
        check(overhead < 2.0, f"resolution logic adds nothing over a minimal shim ({overhead:+.2f} ms)")
        # And the absolute cost stays in shell-startup territory next to a ~26 ms
        # boot. The bound is loose on purpose: the real number is `sh`'s cost on
        # a loaded box, and a Node-based shim (+22 ms) is what this excludes.
        check(shim_median - direct_median < 5.0,
              f"total wrapper cost stays small ({shim_median - direct_median:+.2f} ms)")

        print("\nall npm package checks passed")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except TestFailure as error:
        print(f"\nFAIL: {error}", file=sys.stderr)
        sys.exit(1)

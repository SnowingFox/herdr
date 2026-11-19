# Shipping rustnode on npm

This directory holds the npm packaging for the runtime: the wrapper command, the
package manifests, and the documentation that ships with them. The tooling that
builds and verifies the tarballs lives in `../tools/npm-pack.py`.

```text
npm/
  platforms.json              the platform table; the source of truth for targets
  package.json                the main package: bin, files, engines, os/cpu/libc
  bin/rsnode                  the installed command (POSIX sh, execs the binary)
  README.md                   the npm landing page, honest about what this is
  LICENSE                     MIT, plus why the binary needs more than MIT
  THIRD-PARTY-NOTICES.md      what the shipped binary contains and its licenses
```

## The layout, and why

A thin main package plus one package per platform, with the binary in the
platform package and the command in the main one:

| Package | Contains | `os`/`cpu` |
| --- | --- | --- |
| `@example/rsnode` | `bin/rsnode`, docs, `optionalDependencies` on every platform package | the union of its platforms |
| `@example/rsnode-linux-x64` | the 94 MB binary | `linux` / `x64` / `glibc` |

`npm install -g @example/rsnode` installs the main package, npm reads the
platform packages' `os`/`cpu`/`libc`, installs the one that matches, and skips
the rest. This is the shape `esbuild`, `@swc/core`, `@biomejs/biome` and `bun`
all use, for reasons that hold here:

* **No install-time download.** Nothing is fetched by a script, so installs work
  offline and behind a registry proxy, and the tarball hash in a release note
  covers the exact bytes that run.
* **No `postinstall` to trust.** A postinstall downloader runs arbitrary code at
  install time and is the thing `--ignore-scripts` exists to stop; making the
  binary a normal dependency means `--ignore-scripts` costs nothing.
* **The registry is the delivery mechanism**, so integrity is npm's.

### Why not a `postinstall` download

It was considered and rejected. The runtime is one self-contained ELF with no
bundled-library relocation problem (`ldd` shows only `libstdc++`, `libm`,
`libgcc_s`, `libc`), so there is nothing a download would solve that a package
cannot: both deliver the same bytes. The package costs one dependency entry per
platform and buys offline installs, `--ignore-scripts` compatibility, npm's
integrity checking, and a `files` list that a reviewer can read. A downloader
costs a code path that must handle proxies, retries, corporate TLS interception,
and partial writes — and it fails at install time on a network the registry
already reached. The one advantage a download has, a single package for all
platforms, is not worth a second delivery mechanism.

`bun` ships both: an `install.js` postinstall that copies the platform binary
into place, plus the platform packages. That extra step exists because its
wrapper is a Node script that has to find a binary somewhere. Ours does not need
it, because npm links the command itself.

## The wrapper: why `sh` and not Node

`npm` links the **top-level** package's `bin` into the prefix. It does *not* link
a transitive dependency's `bin` — measured on npm 10.9.9, a global install of a
package whose optional dependency declares a `bin` produces no link to it. So the
command has to live in the main package, and the platform package carries only
the binary. That is exactly what esbuild and biome do, and both then write a
**Node** wrapper, because their resolution needs JavaScript.

Ours does not. The platform package always lands at a fixed offset from the
installed command, so the shell can resolve it with `-x` tests:

```text
local    node_modules/.bin/rsnode  ->  ../@scope/rsnode/bin/rsnode
global   <prefix>/bin/rsnode       ->  ../lib/node_modules/@scope/rsnode/bin/rsnode
```

And the difference is not academic, because the wrapper is on the startup path
of every invocation. Two independent measurement rounds on this machine, three
cases rotated within each round so machine drift hits all of them, `-e ''` with
the release binary:

| Implementation | Median `-e ''` | vs the binary | vs the `sh` floor |
| --- | --- | --- | --- |
| the binary directly | 25.76 ms | — | — |
| minimal 2-line `sh` (`exec`) | 27.45 ms | +1.7 ms | — |
| **this wrapper** | 27.76 ms | **+2.0 ms** | **+0.31 ms** |
| `node` + `spawnSync` wrapper | ~51 ms | +22 ms | — |

The wrapper's own logic is free and the shell is the entire cost, and the two
deltas have to be read differently:

* **vs the binary: +0.4 to +2.0 ms, depending on machine load.** This is what a
  user pays, and it is load-sensitive. The row above is the high end, measured
  while other builds were running on this 8-core box; a quieter window measured
  +0.4 ms. Quote it as a range, not a point.
* **vs the `sh` floor: ~0 ms.** Starting any `sh` process costs what a two-line
  `exec` stub with no logic at all measures, and this script sits within noise of
  that. This comparison is stable across load in a way the absolute one is not,
  because both sides move together — which is why "never worse than a two-line
  `sh` script" is the accurate claim and "adds no measurable cost" is not.

Earlier revisions of this document reported only "+0.13 ms", which was a
quiet-window median compared against a floor measured in a different, quieter
window. That reasoning is worth keeping: the defect was not the value, it was
subtracting two numbers taken under different conditions. Later revisions then
reported "+0.4 to +1.5 ms", which was a single batch and missed the high end. The
range above comes from two independent rounds (one run by the maintainer) that
agree on the split: ~1.7 ms of the cost is `sh` starting at all, ~0.3 ms is this
script.

A Node wrapper cannot avoid booting a second runtime before the real one starts,
which is the +22 ms it cannot get below.

### What keeps it free

Every millisecond counts, so the wrapper is written to fork nothing:

* No `dirname`, no `cd`, no `pwd`, no `readlink` on the common path — only
  parameter expansion and `[ -x ]`, both builtins.
* The first version used `$(cd "$(dirname "$0")" && pwd)`, which forks two
  subshells, and measured **+3.3 ms (11%)** on top of the binary. That is why the
  paths are computed from `$0` arithmetically.
* `readlink` costs +0.4 ms alone, so it runs only in the fallback for a tree npm
  does not produce (a hand-made link on `PATH`, a store-based package manager).

Three checks keep that true rather than trusting it: `npm-manifest-check.py`
asserts the fast path contains no fork and that the `readlink` helper is only
called from the fallback, and `npm-package-test.py` runs the installed command
with a failing `readlink` stub first on `PATH`, so a regression fails instead of
getting slower. `npm-package-test.py` also compares the wrapper against a minimal
`sh` shim, not against zero, so `sh`'s inherent cost is not misattributed to it.

### Forwarding

`exec` replaces the shell rather than sitting in the middle, so the binary *is*
the process the caller sees: argv, stdio, signals and exit status need no
handling and cannot be got wrong. `"$@"` is quoted so arguments with spaces or
globs survive. This is verified for exit 42, a partial stdout write, separate
stderr, piped stdin, and SIGINT — the last one checked as **death by signal**
(returncode `-2`), not as exit 130, because those are different observations and
a wrapper that forgot `exec` shows up as the latter.

## What the version story is

The binary reports `v28.0.0-nightly20261111e8c1160d20` for `process.version` **on
purpose**: it is the Node API level the vendored `lib/**` and bindings target,
together with the pinned revision's own pre-release identity, and Node libraries
branch on it. The long string is not a claim that this is a Node release; it is
the identity the pinned tree derives from `src/node_version.h`, which is why
`rsnode --version` can be byte-identical to the reference binary. Reporting a
shortened `v28.0.0` would put `process.version` and `--version` out of step
inside one process. `napi_get_node_version` still carries the three integers
(`28.0.0`) because that ABI field has no room for a suffix.
`process.versions.v8` is `15.2.124.1-rusty`, where the substitution is visible.
The npm package version (`0.1.0`) is rustnode's own and is deliberately
different; `tools/npm-pack.py` reads it from `[workspace.package]` so the two
cannot drift.

`--version` and `--help` **are implemented**: `--version` answers after the V8
argument vector is applied, the way `src/node.cc:1282` does, and `--help` runs
`internal/main/print_help` so the text comes from the option table. The wrapper
forwards both rather than intercepting them, because a second entry point
reporting a version the runtime does not is the misleading thing to avoid.
`README.md` says this in the `--version` and `--help` section and gives
`rsnode -p 'process.versions'` as the honest inventory.

## Packages, step by step

```bash
# Build and verify the tarballs (needs a release binary).
python3 tools/npm-pack.py pack --binary /path/to/rustnode --out /tmp/npm-out

# Verify existing tarballs without rebuilding, e.g. from a downloaded release.
python3 tools/npm-pack.py check --out /tmp/npm-out

# End-to-end: install both layouts from a throwaway registry and exercise them.
python3 tools/npm-package-test.py --out /tmp/npm-out --runs 30
```

`pack` writes `packages.json` with each tarball's sha256 and the binary's
sha256. It is deterministic: npm normalises every member's mtime and ownership,
so the same binary and version produce byte-identical tarballs.

Each tarball is read back and its binary hashed against the input, because
`files` is a reduction list and a reduction that silently drops the binary
produces an install that succeeds and a command that does not exist. That class
of bug is the reason the verification opens the archive rather than trusting the
manifest.

`npm-package-test.py` stands up a throwaway registry rather than installing
tarballs by path. Installing by path skips `os`/`cpu` selection entirely — it
installs whatever you point at, on any host — so it cannot test the thing the
optional-dependency design exists to do.

## Before publishing

The package name is a **placeholder**. `rsnode` is taken on the public registry
by an unrelated `0.0.1`, so `platforms.json` and both manifests use
`@example/` until a real name is chosen. Nothing else depends on the scope: it
is one field in `platforms.json`, one in `package.json`, and the literals the
wrapper interpolates.

Publishing needs a registry credential (`npm login`, or `NPM_TOKEN` for CI) and
must publish the platform packages before the main one, so the optional
dependency resolves.

## The publish, step by step

Run from `rustnode/` after choosing the name in `platforms.json` and
`npm/package.json` (both must agree, or `npm-pack.py` refuses — see the check at
`tools/npm-pack.py:348`).

```bash
# 1. Build the release binary the platform package wraps.
cargo build --release -p rn-cli

# 2. Produce both tarballs. Refuses if the two manifests disagree on the name,
#    so a mismatched scope cannot be published by accident.
python3 tools/npm-pack.py pack --out /tmp/npm-out

# 3. Platform packages FIRST. The root's optionalDependency names them, so a
#    root published first resolves to nothing and every install fails.
for f in /tmp/npm-out/*-linux-x64-*.tgz; do npm publish --access public "$f"; done
#    Repeat for each platform in platforms.json as those builds become available.

# 4. Then the root package.
npm publish --access public /tmp/npm-out/example-rsnode-*.tgz

# 5. Prove it from the registry, in a directory unrelated to this checkout.
cd "$(mktemp -d)" && npm init -y >/dev/null && npm install @<scope>/rsnode
./node_modules/.bin/rsnode -e 'console.log(process.version)'
```

Step 5 is the only evidence that the optional dependency actually resolves from
the registry — the local tests in this repository install tarballs, which
bypasses that resolution entirely. Do not report a publish as successful on the
strength of the tarball tests.

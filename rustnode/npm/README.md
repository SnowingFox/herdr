# rsnode

The **rustnode** runtime, installed by npm as the command `rsnode`.

rustnode is a Node-compatible JavaScript runtime whose native layer is written in
Rust. It keeps the parts of Node that determine observable behaviour — the V8
engine, and the `lib/**` builtin JavaScript copied byte-identical from Node and
hash-frozen in CI — and replaces the C++ native layer underneath them.

```bash
npm install -g @example/rsnode
rsnode -e 'console.log(process.version)'
```

## What this is, and what it is not

**This is not Node.js.** It is not a fork of Node, it is not built by the Node
project, and it is not affiliated with or endorsed by them. It shares Node's
engine and Node's JavaScript, and it aims to be a drop-in replacement for the
`node` command, but it is a separate implementation with its own bug list.

**This is not Bun either.** Bun swaps V8 for JSC and reimplements Node's
JavaScript layer. rustnode does neither, so compatibility is structural rather
than a list of patched-over gaps.

The npm package version (`0.1.0`) is rustnode's own version. It is deliberately
**not** the Node version, and the two numbers below are different on purpose.

## `process.version` names the Node API level, and that is a compatibility claim

```console
$ rsnode -e 'console.log(process.version)'
v28.0.0-nightly20261111e8c1160d20

$ rsnode -p 'process.versions.node'
28.0.0-nightly20261111e8c1160d20
```

`v28.0.0-nightly20261111e8c1160d20` is **the Node API level this build targets**,
not a Node release and not the version of this package. It is reported because the
vendored `lib/**` JavaScript is copied byte-identical from Node 28.0.0 and the
native layer implements the bindings that JavaScript expects; a version string is
how Node code branches on the API surface it can use, so reporting anything else
would make libraries take the wrong branch. `process.versions` lists the other
components the binary actually links, at the versions it actually links them.

The date-and-SHA suffix is part of the identity rather than decoration. Node 28
has not been released, so the tree this build copies reports itself as a nightly
of revision `e8c1160d20`, and `src/node_version.h` derives every version string
in the process from that one release identity. Reporting a shortened `v28.0.0`
would make `process.version` disagree with `rsnode --version` inside a single
process, and `--version` has to match the reference binary byte for byte. The
three-component `28.0.0` still appears where an integer ABI is what is wanted:
`napi_get_node_version` fills major/minor/patch and carries no suffix.

The `v8` entry is `15.2.124.1-rusty`, which is where the substitution is visible
without reading anything else.

## `--version` and `--help`

Both flags work, and both match the runtime they describe rather than being
intercepted by the npm wrapper:

```console
$ rsnode --version
v28.0.0-nightly20261111e8c1160d20

$ rsnode --help
Usage: rustnode [options] [ script.js ] [arguments]
       rustnode inspect [options] [ script.js | host:port ] [arguments]
...
```

`--version` prints the same string as `process.version`, which is the identity
described above: it is the Node API level and the pinned revision, not this
package's version.

`--help` is generated from the runtime's own option table, so the text reflects
the options this build actually has. Its two usage lines name `rustnode` because
that is what the program is; everything after them is the table.

The wrapper forwards both flags unchanged. It does not answer them itself: a
second entry point reporting a version the runtime does not would be the
misleading thing this section exists to avoid. Because both are now real flags,
`rsnode --version` and `rsnode --help` exit 0 rather than being rejected.

The package version is a separate query:

```bash
npm ls -g @example/rsnode        # this package's version
rsnode -p 'process.versions'     # every linked component, at its real version
```

`process.versions` is the useful one: it reports OpenSSL, libuv, nghttp2,
SQLite, ICU and the rest at the versions compiled into the binary.

## Platforms

Published for **linux x64 (glibc)** so far. The runtime depends on `libstdc++`,
`libm`, `libgcc_s` and `libc` and bundles everything else, so there is no
separate system dependency to install.

The binary arrives through an optional dependency,
`@example/rsnode-linux-x64`, which npm selects using that package's
`os`/`cpu`/`libc` fields. npm **silently skips** optional dependencies that do not
match the host, so on another platform the install succeeds and the command
exists but reports that no binary was installed:

```
rsnode: the native binary for this platform is not installed.
```

That is a normal outcome, not a corrupt install. There is no `postinstall`
download: nothing is fetched at install time, so installs work offline and
behind a registry proxy, and the tarball hash in the release notes covers the
exact bytes you run.

## Usage

`rsnode` accepts the `node` command line for the surface it implements:

```bash
rsnode script.js                 # run a file
rsnode -e 'console.log(1+1)'     # evaluate
rsnode -p 'process.platform'     # evaluate and print
echo 'console.log(1)' | rsnode   # run a script from standard input
rsnode --expose-internals        # accepted, see below
```

A script on standard input is a CommonJS module with `module`, `require` and
`__filename`, exactly as `node` runs one; `-` names it explicitly and forwards
the arguments after it (`rsnode - x y`), which `--` does not.

Flags rustnode accepts but does not yet act on are recorded and reported rather
than silently ignored, and flags it has never heard of are an error — a typo
that changes nothing is worse than a rejection. `NODE_OPTIONS` is honoured and
parsed in Node's order.

Because it is a drop-in `node`, it runs ordinary npm tooling:

```bash
rsnode ./node_modules/.bin/some-cli
rsnode -e 'require("fs").readFileSync("/etc/hostname", "utf8")' | cat
```

## Exit codes and signals

The installed command is a small POSIX shell script that `exec`s the real
binary, so the shell is replaced rather than kept in the middle. Arguments,
standard streams, signals and the exit status all belong to the binary's process
because it *is* the process the caller sees:

```console
$ rsnode -e 'process.exit(42)'; echo $?
42

$ rsnode -e 'process.kill(process.pid, "SIGINT")'; echo $?
130
```

The wrapper is a small POSIX `sh` script that `exec`s the binary. It costs what
starting one shell costs: **+0.4 to +2.0 ms over invoking the binary directly,
depending on machine load**, of which roughly 0.3 ms is this script and the rest
is `sh` itself. The size of that absolute figure moves with load; what does not
move is that it is never worse than a two-line `sh` script, because both sides
pay the same shell start. A Node-based wrapper would add ~22 ms by starting a
second runtime first. Measurements are in `rustnode/docs/npm-packaging.md` in the
repository.

## Reporting bugs

<https://github.com/SnowingFox/herdr/issues>

Include `rsnode -p 'process.versions'` and your platform.

## License

MIT for this package and the rustnode source. The published **binary** also
contains third-party components with their own notice requirements — Node's
JavaScript layer, V8, OpenSSL, libuv, nghttp2, llhttp, merve, SQLite, zlib-rs,
zstd, Brotli and ICU. See `THIRD-PARTY-NOTICES.md` in this package, which lists
each one with the version the shipped binary reports.

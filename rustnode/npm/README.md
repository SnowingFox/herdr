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

## `process.version` says `v28.0.0`, and that is a compatibility claim

```console
$ rsnode -e 'console.log(process.version)'
v28.0.0

$ rsnode -p 'process.versions.node'
28.0.0
```

`v28.0.0` is **the Node API level this build targets**, not a Node release and
not the version of this package. It is reported because the vendored `lib/**`
JavaScript is copied byte-identical from Node 28.0.0 and the native layer
implements the bindings that JavaScript expects; a version string is how Node
code branches on the API surface it can use, so reporting anything else would
make libraries take the wrong branch. `process.versions` lists the other
components the binary actually links, at the versions it actually links them.

The `v8` entry is `15.2.124.1-rusty`, which is where the substitution is visible
without reading anything else.

## `--version`

```console
$ rsnode --version
rustnode: unsupported option '--version'
$ echo $?
9
```

**None of the informational flags are implemented yet.** The CLI rejects unknown
flags rather than ignoring them, so all of these exit 9:

```console
$ rsnode --version   # rustnode: unsupported option '--version'
$ rsnode -v          # rustnode: unsupported option '-v'
$ rsnode --help      # rustnode: unsupported option '--help'
```

This package does not intercept `--version` to fake an answer. A second entry
point reporting a version the runtime itself does not report would be the
misleading thing this section exists to avoid, and faking `--version` while
`--help` still failed would make this documentation wrong.

Adding them is a CLI surface change, not a packaging one: it belongs in its own
change, compared byte-for-byte against the Node behaviour it is imitating.

Three ways to get a version that work today:

```bash
rsnode -p 'process.version'      # the Node API level, v28.0.0
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
rsnode --expose-internals        # accepted, see below
```

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

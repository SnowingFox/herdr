# rn-permission

`internalBinding('permission')` and the permission-model checks for rustnode.

Ports `src/permission/` from the pinned Node revision. `--permission` turns the
model on; every scope then denies by default and only `--allow-*` opens it.

## Gated resources

Every place `lib/**` consults `permission.isEnabled()`, `permission.has(...)`,
or the native layer calls `THROW_IF_INSUFFICIENT_PERMISSIONS`:

| Scope | Gated operation | Where |
| --- | --- | --- |
| `fs.read` | `open`, `read`, `stat`/`lstat`, `readdir`, `readlink`, `realpath` (also checks the resolved input up front) | `lib/fs.js`, `lib/internal/fs/promises.js` |
| `fs.write` | `write`, `appendFile`, `mkdir`, `rename`, `unlink`, `link`, `chmod`/`chown`/`utimes` by path, `copyFile`, `cp` | same |
| `fs` | `s.symlink` only — needs both halves because symlinks can bypass the model | `lib/fs.js`, `lib/internal/fs/promises.js` |
| `child` | `spawn`, `spawnSync`, `exec`, `execFile`, `fork` | `process_wrap.cc`, `spawn_sync.cc` |
| `worker` | `new Worker()` | `node_worker.cc` |
| `addon` | `process.dlopen`, linked `internalBinding` | `node_binding.cc` |
| `wasi` | `new WASI()` | `node_wasi.cc` |
| `inspector` | inspector session, `console` value previews, `report.writeReport` | `lib/internal/util/inspector.js`, `lib/internal/process/report.js` |
| `net` | TCP/UDP/pipe servers and sockets | `tcp_wrap.cc`, `udp_wrap.cc`, `pipe_wrap.cc` |
| `env` | every variable except the ones Node keeps | environment scrub at startup |
| `ffi` | `node:ffi` calls | `lib/ffi.js` |
| `openssl.store` | OpenSSL STORE loaders | crypto layer |

Not path-checkable, so denied outright whenever the model is on:

* `fsync`, `fdatasync`, `fchmod`, `fchown`, `futimes` and their `FileHandle`
  equivalents, which act on an already-open descriptor;
* `fs.readdir`'s native recursive walk, which `lib/fs.js` replaces with a
  permission-aware walk;
* `fs.cp`'s native directory copy, likewise replaced by a per-entry walk.

## CLI surface

Supported, with `--flag=value` and `--flag value` both accepted:

| Flag | Effect |
| --- | --- |
| `--permission` | enforce; deny by default |
| `--permission-audit` | check and report, never deny |
| `--allow-fs-read=<paths>` | grant read; repeatable |
| `--allow-fs-write=<paths>` | grant write; repeatable |
| `--allow-child-process` | grant `child` |
| `--allow-worker` | grant `worker` |
| `--allow-addons` | grant `addon` |
| `--allow-wasi` | grant `wasi` |
| `--allow-net` | grant `net` |
| `--allow-inspector` | grant `inspector` |
| `--allow-env=<patterns>` | grant env names / `PREFIX_*` |

Path semantics, matching Node:

* `*` alone grants the whole scope; any other `*` ends the pattern, so
  `/home/*.js` behaves like `/home/*`;
* relative paths resolve against the working directory;
* a grant naming an **existing** directory gains a trailing `/*`, so
  `--allow-fs-read=/tmp` covers everything under `/tmp`; a path that does not
  exist is granted exactly, so pass `/my/new/dir/*` if it will be created later;
* an exact grant covers only itself.

## Check API

```rust
let model = PermissionModel::from_args(cwd, std::env::args());
model.check_fs_read(path)?;        // Err(AccessDenied) on denial
model.check_fs_write(path)?;
model.check_child_process()?;      // or check_child_process_resource(exe)
model.check_worker()?;
model.check_addon()?;              // or check_addon_named(module)
model.check_wasi()?;
```

`AccessDenied` carries the fields Node puts on the error:

```text
code       = "ERR_ACCESS_DENIED"
permission = "FileSystemRead"        // the scope enumerator name
resource   = "/etc/passwd"           // path, executable, or empty
message    = "Access to this API has been restricted. Use --allow-fs-read to manage permissions."
```

Binding crates should hold a `PermissionGate` instead of an `Option<model>`:
`PermissionGate::disabled()` allows everything and every `deny_*` method is a
no-op, so call sites stay branch-free.

## Cost

When the model is off — the default — a check is one boolean load. When it is
on, a filesystem check resolves the path lexically (no canonicalisation, no
filesystem access) and walks a prefix tree of the grants. The only filesystem
access in the crate happens once per grant at startup, when deciding whether to
append the directory wildcard.

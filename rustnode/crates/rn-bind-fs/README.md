# rn-bind-fs

`internalBinding('fs')` for rustnode.

This crate is the native half of Node's filesystem layer. The JavaScript half —
`vendor/libnode-js/lib/fs.js` and `lib/internal/fs/**` — is Node 28's own code,
byte-identical and never edited, so everything those files call has to exist here
with the same name, argument order and return shape.

## What is implemented

The member list below was derived from the JavaScript call sites
(`rg "internalBinding\('fs'\)" vendor/libnode-js/lib`), not from Node's C++
registration table.

### Descriptor and byte-stream operations

| member | JS call shape |
| --- | --- |
| `open` | `open(path, flags, mode, [req])` |
| `close` | `close(fd, [req])` |
| `read` | `read(fd, buffer, offset, length, position, [req])` |
| `readBuffers` | `readBuffers(fd, buffers, position, [req])` |
| `writeBuffer` | `writeBuffer(fd, buffer, offset, length, position, [req])` |
| `writeBuffers` | `writeBuffers(fd, buffers, position, [req])` |
| `writeString` | `writeString(fd, string, position, encoding, [req])` |
| `ftruncate` | `ftruncate(fd, length, [req])` |
| `fsync` | `fsync(fd, [req])` |
| `fdatasync` | `fdatasync(fd, [req])` |

### Metadata

| member | JS call shape |
| --- | --- |
| `stat` | `stat(path, useBigint, [req], [throwIfNoEntry])` |
| `lstat` | `lstat(path, useBigint, [req])` |
| `fstat` | `fstat(fd, useBigint, [req], [shouldNotThrow])` |
| `statfs` | `statfs(path, useBigint, [req])` |

`statfs` has no descriptor form in Node's namespace; there is no `fstatfs`
member to implement.

Stats come back as a flat typed array, never a struct, because
`getStatsFromBinding()` in `lib/internal/fs/utils.js` reads fixed slots. The
layout is `FsStatsOffset` from `src/node_file.h`:

```text
0 dev       1 mode      2 nlink     3 uid       4 gid
5 rdev      6 blksize   7 ino       8 size      9 blocks
10 atime_s  11 atime_ns 12 mtime_s  13 mtime_ns
14 ctime_s  15 ctime_ns 16 birth_s  17 birth_ns
```

The array type is part of the contract: `Float64Array` normally and
`BigInt64Array` when `bigint: true`, because the JS dispatches on it.

### Directories

| member | JS call shape |
| --- | --- |
| `readdir` | `readdir(path, encoding, withFileTypes, [req])` |
| `readdirRecursive` | `readdirRecursive(path, encoding, withFileTypes, [req])` |

`withFileTypes` returns `[names, types]` where each type is a raw
`uv_dirent_type_t` (`UNKNOWN` 0, `FILE` 1, `DIR` 2, `LINK` 3, `FIFO` 4,
`SOCKET` 5, `CHAR` 6, `BLOCK` 7). The recursive form returns
`[names, types, counts, dirs]`, the four parallel arrays
`getRecursiveDirents()` destructures, in breadth-first order.

Names are sorted bytewise ascending, which is what `uv_fs_scandir` does, so
`fs.readdirSync` output matches Node's ordering.

### Path operations

| member | JS call shape |
| --- | --- |
| `rename` | `rename(oldPath, newPath, [req])` |
| `rmdir` | `rmdir(path, [req])` |
| `unlink` | `unlink(path, [req])` |
| `mkdir` | `mkdir(path, mode, recursive, [req])` |
| `link` | `link(existingPath, newPath, [req])` |
| `symlink` | `symlink(target, path, type, [req])` |
| `readlink` | `readlink(path, encoding, [req])` |
| `realpath` | `realpath(path, encoding, [req])` |
| `access` | `access(path, mode, [req])` |
| `copyFile` | `copyFile(src, dest, mode, [req])` |
| `chmod` | `chmod(path, mode, [req])` |
| `fchmod` | `fchmod(fd, mode, [req])` |
| `chown` | `chown(path, uid, gid, [req])` |
| `fchown` | `fchown(fd, uid, gid, [req])` |
| `lchown` | `lchown(path, uid, gid, [req])` |
| `utimes` | `utimes(path, atime, mtime, [req])` |
| `futimes` | `futimes(fd, atime, mtime, [req])` |
| `lutimes` | `lutimes(path, atime, mtime, [req])` |
| `mkdtemp` | `mkdtemp(prefix, encoding, [req])` |
| `mkstemp` | `mkstemp(prefix, encoding, [req])` |

The recursive `mkdir` returns the *first* directory it created, not the deepest,
matching `MKDirpSync`.

### Fast paths and helpers

| member | purpose |
| --- | --- |
| `existsSync` | `fs.existsSync`, never throws |
| `readFileUtf8` | `readFileSync(path, 'utf8')` fast path |
| `writeFileUtf8` | `writeFileSync(path, string)` fast path |
| `rmSync` | `fs.rmSync`'s recursive remove, with Node's retry policy |
| `internalModuleStat` | `0` file, `1` directory, `< 0` errno, for the module loader |
| `handleToFd` | Windows-only; reports `ENOSYS` here |
| `FSReqCallback` | the request-object constructor `new FSReqCallback()` needs |
| `kUsePromises` | the sentinel that selects promise mode |

`handleToFd` is present but not functional on Linux. `lib/internal/fs/streams.js`
throws `ERR_FEATURE_UNAVAILABLE_ON_PLATFORM` before it ever calls the binding, so
having the member exist and fail keeps the JS layer on its documented path.

## The three calling conventions

Every member picks its behaviour from its trailing argument, exactly as
`GetReqWrap()` does in `src/node_file.cc`:

| trailing argument | mode | binding returns |
| --- | --- | --- |
| absent | synchronous | the value, or throws |
| an object (`FSReqCallback` instance) | callback | `undefined`, then calls `req.oncomplete(err, value)` |
| the exact `kUsePromises` symbol | promise | a `Promise` that resolves or rejects |

`kUsePromises` is matched by identity against a symbol created at install time.
A user-created symbol with the same description therefore does not select promise
mode, which matters because the symbol is published on the namespace object.

### Why the callback is deferred, and not threaded

Node runs the syscall on libuv's thread pool and calls back from the event loop.
rustnode runs it inline and queues `oncomplete` as a V8 microtask.

That preserves the observable guarantee the JS depends on. `lib/fs.js` assigns
`req.context` and `req.oncomplete` *after* calling into the binding, and
`bindSignalToReq` assigns `oncomplete` after `new FSReqCallback()`; if the native
side called back inline, those assignments would be too late and every async `fs`
call would silently drop its result. Deferring to a microtask means the script
always returns to its caller first.

It does not implement real concurrency yet. A blocking `read` on a slow device
blocks the whole thread, where Node would not. That is a deliberate first-pass
tradeoff: the callback contract is what the frozen JavaScript observes, and a
thread pool belongs with `rn-io`'s event loop rather than in this crate.

The deferred payload is rooted in `Global` handles. A completion runs after the
native frame has returned and the caller's handle scope has been popped, so
holding `Local` handles there would leave V8 dangling pointers; there is a test
that churns the heap to prove the rooting is correct.

## Errors

Errors cross the boundary as `Error` instances carrying the properties Node's
`UVException` produces:

```js
{ name: 'Error', message: "ENOENT: no such file or directory, stat '/nope'",
  errno: -2, code: 'ENOENT', syscall: 'stat', path: '/nope' }
```

`errno` is *negative*, following libuv's convention, and `message` uses libuv's
wording rather than libc's (libc says "Is a directory"; libuv and Node say
"illegal operation on a directory").

Named codes covered: `EACCES`, `EAGAIN`, `EBADF`, `EBUSY`, `EEXIST`, `EFAULT`,
`EFBIG`, `EINTR`, `EINVAL`, `EIO`, `EISDIR`, `ELOOP`, `EMFILE`, `EMLINK`,
`ENAMETOOLONG`, `ENFILE`, `ENODEV`, `ENOENT`, `ENOMEM`, `ENOSPC`, `ENOSYS`,
`ENOTDIR`, `ENOTEMPTY`, `ENOTSUP`, `ENOTTY`, `ENXIO`, `EPERM`, `EPIPE`,
`EROFS`, `ESPIPE`, `ETXTBSY`, `EXDEV`.

Anything else reports `UNKNOWN` with `strerror_r`'s text, so an exotic errno
still produces a readable message.

## Open flags

`lib/fs.js` converts flag *strings* to numbers before calling in, so the binding
only ever sees libuv's encoding — which is not raw Linux `O_*`. `flags.rs` keeps
libuv's table (`O_CREAT = 0x40`, `O_TRUNC = 0x200`, …) and translates bit by bit
into host flags. An unknown bit is `EINVAL` rather than being silently dropped,
because `fs.open` is not a place to guess.

## Deliberately deferred

These are visible in `src/node_file.cc` and read by *some* JavaScript in
`vendor/libnode-js`, but each needs machinery outside this crate or covers a
surface the rest of the runtime cannot reach yet. They are omitted rather than
stubbed so a caller gets a clear missing-member failure instead of a wrong answer.

| missing | why |
| --- | --- |
| `FileHandle` constructor and class | `lib/internal/fs/promises.js` builds `FileHandle` as an `AsyncWrap` with `StreamBase` behaviour, reference counting, `close` promises and structured-clone transfer. That is a handle-lifecycle feature shared with `net`/`http2`, not a filesystem call. `fs.promises.open()` needs it; plain `fs` does not. |
| `ReadFileJob`, `WriteFileJob` | one-shot open+stat+read (or write+close) jobs that own a libuv work request. They exist purely to collapse three thread-pool round trips into one. Without a thread pool there is nothing to collapse; `lib/fs.js` falls back to `open`/`fstat`/`read`/`close`, which this crate implements, when `options.buffer` is set. |
| `openFileHandle` | returns a `FileHandle`; blocked on the item above. |
| `cpSyncCheckPaths`, `cpSyncCopyDir`, `cpSyncOverrideFile`, `CpDirJob` | the `fs.cp` fast paths. `lib/internal/fs/cp/cp-sync.js` only reaches them when no `filter` is supplied; with a `filter` it walks with `opendir`/`stat`/`copyFile`. `opendir` itself needs the `fs_dir` namespace. |
| `opendir`, and the whole `fs_dir` namespace | `internalBinding('fs_dir')` is a separate binding: it owns `DIR*` handles with async iteration. Out of scope for this crate by namespace, and `Dir` in `lib/internal/fs/dir.js` uses it exclusively. |
| `StatWatcher` | requires an inotify-backed poller and the double-width stats buffer (`kFsStatsBufferLength`). Watch mode belongs with the event loop. The buffer width is still pinned by a test so the layout cannot drift. |
| `internalModuleReadJSON`, `legacyMainResolve`, `getFormatOfExtensionlessFile` | read by `lib/internal/modules/helpers.js`. The latter two are helpers over the JSON reader, and `internalModuleReadJSON` has no call site left in this tree, so implementing it would be guesswork. All three belong to the module-loader crate. |
| `scandir` as a public member | there is no such member in Node's namespace; `readdir` *is* the scandir binding. The syscall name `scandir` is still used in error messages, which is what Node reports. |
| `FICLONE_FORCE` | `FICLONE` is attempted and honoured, but a forced reflink on a filesystem that supports neither reflink nor a fallback fails with `ENOTSUP` rather than degrading. Ordinary copies are correct. |

libuv thread-pool semantics, `io_uring`, and permission-model checks are also not
here. The permission checks live in JS (`lib/fs.js` calls `permission.isEnabled()`
before the binding); this crate does not add a second check.

## Layout

| file | contents |
| --- | --- |
| `lib.rs` | crate documentation and the `Fs` type |
| `install.rs` | the namespace object: every member, argument marshalling |
| `fsops.rs` | the syscalls, free of V8 so they are testable without an isolate |
| `error.rs` | errno to code/message mapping |
| `stats.rs` | `statx`/`statfs` reading and the flat slot layouts |
| `flags.rs` | libuv's open-flag encoding |
| `dirent.rs` | `uv_dirent_type_t` and libuv's sort order |
| `complete.rs` | deferred callback and promise delivery |
| `request.rs` | mode classification, error objects, the `kUsePromises` sentinel |
| `args.rs` | JavaScript value to Rust operand conversion |

## Tests

```bash
cd rustnode
cargo test -p rn-bind-fs
```

Three layers:

* Unit tests beside each module: errno mapping, slot layouts, flag translation,
  dirent typing, plus tempdir round trips for every syscall.
* `tests/js_contract.rs`: installs the real namespace and drives it from
  JavaScript — stat slot values, readdir ordering, callback deferral, promise
  resolution, error properties.
* `tests/node_parity.rs`: runs a real `node` binary and compares output for stat
  fields, readdir order (flat and recursive), error messages, `mkdir` recursive
  return values and link resolution. These skip themselves when `node` is not on
  `PATH`, so the crate gate never depends on it.

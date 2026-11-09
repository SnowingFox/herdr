# rn-bind-glob

`internalBinding('glob')` for rustnode.

`lib/internal/fs/glob.js` is unchanged Node code: it validates options, builds
`Dirent`s and owns the iteration protocol. Everything below the option parsing
is here. The namespace has nine members and three of them carry the whole
feature:

| member | what it decides |
| --- | --- |
| `matchesGlob(path, pattern, flags)` | whether one path matches one pattern |
| `hasMagic(pattern)` | whether a pattern is more than a literal path |
| `globSync(cwd, includes, excludes, flags, excludeFn, maxDepth)` | the whole walk |
| `globStart(...)` | the same walk, pullable in batches |
| `kFlag*` | five constant bit values |

## The engine is a port, not a reimplementation

`src/glob/**` in Node is a minimatch port with its own AST, brace expander,
extglob flattener and NFA matcher. Reimplementing "what globs mean" from
scratch would disagree with Node in a hundred small ways — brace padding,
`!(a)b` semantics, `**` at the end of a pattern, `[:alpha:]` ranges — and each
disagreement is a silently wrong `fs.glob` result.

So the modules here mirror the C++ one to one:

| here | Node |
| --- | --- |
| `ast.rs` | `glob_ast.h` |
| `brace.rs` | the brace half of `glob_parser.cc` |
| `parser.rs` | the AST half of `glob_parser.cc` |
| `program.rs` | `glob_program.cc` |
| `matcher.rs` | `glob_matcher.cc` |
| `unicode.rs` | `glob_unicode.cc` |
| `walker.rs` | `glob_walker.cc` |
| `install.rs` | `node_glob.cc` |

## How it is known to be right

Reading a port carefully is not evidence that it works. Two kinds of test back
this crate:

* **`src/differential.rs`** runs 1304 recorded `matchesGlob` cases through the
  engine and compares against answers captured from the v27 recorder binary. The
  cases cover globstars, dot handling, every POSIX class, extglob nesting,
  brace sequences and padding, trailing separators and the empty pattern. A
  failure prints every disagreeing case.
* **`tests/walk_parity.rs`** rebuilds a directory tree with nested directories,
  dotfiles and two symlinks, and compares a battery of walks — flags, excludes,
  depth limits, a parent-descending pattern — against Node's own `globSync`
  output, order included.

Both fixtures were produced by the binary `tools/node-pin.toml` names, so a
version difference stays visible. Regenerate with `tools/record-glob-fixtures.sh`
when the pin moves.

## Decisions worth knowing

**UTF-16 throughout.** V8 hands the binding a two-byte string, and an unpaired
surrogate is legal input that simply never matches a file name. Converting
through `String` would replace it with U+FFFD and could turn a non-match into a
match. `glob::Pattern` is `Vec<u16>` for that reason.

**The walker runs inline.** Node splits a walk across a scan pool and a
sequencer. rustnode performs each visit inline. The traversal and the output
order are identical, and both are observable: `globSync` returns an array that
Node's own tests compare. What is *not* reproduced is the parallelism, so a very
large tree is slower here — but never wrong.

**`globStart` walks eagerly.** Node pulls one batch at a time from a live
traversal. This implementation runs the whole walk when the handle is created,
then serves `next()` from the completed result. The JavaScript layer only sees
promises that resolve in batch order with the same batches; the difference is
that `cancel()` after the first batch stops nothing, because there is nothing
running. `next()`, `all()` and `cancel()` all exist and behave as documented.

**Directory entries are sorted.** `uv_fs_scandir` sorts with `alphasort`, so
`fs.readdir` — and therefore `fs.globSync` — reports names in byte order. A
plain `read_dir` returns them in whatever order the filesystem produces, which
produced a different result array until this was fixed.

**The `seen` set is keyed on source text.** A path can be reached under more
than one pattern index. The visited set stores the *remaining pattern suffix*,
interned to an integer, and it must key on the part's text as written rather
than its lowered form: `**/*`'s `*` lowers to an empty literal, which collided
with the empty suffix after it and made the walk skip directories it still
needed to descend into.

**Unicode data is generated, not linked.** `glob_unicode.cc` leans on ICU for
case folding and general categories. Depending on ICU here would add a C++
build step and a version to keep aligned, so `tools/gen-unicode-tables.py`
generates `src/unicode_tables.rs` from the UCD version Node reports as
`process.versions.unicode` (17.0.0). The output is deterministic.

**No deferrals.** Every member `contracts/glob.json` records is implemented:
`DEFERRED` is empty.

## Adding a test

The differential fixtures are the highest-value place to add coverage, because
they compare against a real Node rather than against this crate's own reading of
the C++. Add a `path|pattern` line to `tests/corpus/matches-glob.txt` and
regenerate the expectations.

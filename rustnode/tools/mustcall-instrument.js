// Records every `common.mustCall*` registration and every invocation of the
// function it returned, into the JSONL file named by `INSTR_OUT`.
//
// Used by `tools/mustcall-sample.py` to answer a question the exit code cannot:
// in a file that currently *passes*, did the callbacks these assertions wrap
// actually run? A registration with no matching invocation is an assertion the
// suite counted as satisfied without ever checking anything.
//
// Loaded with `--require`, so the patch is in place before the test file calls
// `require('common')`. `common` is a Proxy over a plain object with a `get`
// trap only, so assigning an existing key lands on the target and the file's
// own `require('common')` sees the wrapper; the `validProperties` allowlist was
// built from the same keys and is unaffected.
'use strict';

const fs = require('fs');

const outPath = process.env.INSTR_OUT;
if (!outPath) {
  throw new Error('INSTR_OUT is not set');
}

// Remove this preload from `process.execArgv` so a child process a test forks
// does not inherit it. Two reasons: a forked child writing to the same log
// would have its own registrations counted against the parent's file, and the
// inherited form differs between runtimes -- rustnode rewrites `--require x` to
// `--require=x`, which it then rejects when a child re-parses it, so a forking
// test would exit 9 *because* of the instrumentation. Stripping here makes the
// measurement invisible to the file, which is what a measurement has to be.
//
// Both spellings are handled because the two runtimes normalise differently,
// and the path is matched by basename as well as by full path: `__filename` is
// the resolved path, while the argv entry is whatever the caller typed, and
// this repository is routinely reached through a symlinked checkout
// (`/workspace` -> the real tree). Comparing only the full path silently failed
// to strip in exactly that case, which is how it was found.
const self = __filename;
const selfBase = self.slice(self.lastIndexOf('/') + 1);
for (let index = process.execArgv.length - 1; index >= 0; index--) {
  const arg = process.execArgv[index];
  // A separate-word form puts the path in the next element.
  const next = process.execArgv[index + 1];
  const separate = arg === '--require' || arg === '-r';
  const target = separate ? next : arg.replace(/^--?r(equire)?=/, '');
  if (target === undefined || target === arg && !arg.includes('=')) continue;
  const base = String(target).slice(String(target).lastIndexOf('/') + 1);
  if (target === self || base === selfBase) {
    process.execArgv.splice(index, separate ? 2 : 1);
  }
}

let seq = 0;
// Every process writes to the same file, and a test that forks (cluster,
// child_process, workers) reuses the sequence from 1 in each child. The pid
// prefix is what keeps one process's `exact1` from being matched against
// another's invocation and read as satisfied when it never ran.
const prefix = `${process.pid}.`;
const write = (record) => {
  // Appended synchronously: the process may exit without draining anything
  // asynchronous, which is the very condition under test.
  try {
    fs.appendFileSync(outPath, JSON.stringify(record) + '\n');
  } catch {
    // A failed write must not change the test's own outcome.
  }
};

process.on('exit', () =>
  write({ k: 'end', pid: process.pid, exiting: process._exiting === true })
);

// Installed on first `require` of a module whose id ends in `common/index.js`,
// because the test tree path is passed on the command line rather than known
// here. `Module._load` is hooked rather than each path guessed, so a test that
// requires `../common` and one that requires `.../common/index.js` both work.
const Module = require('module');
const instrumented = new WeakSet();
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const exported = originalLoad.call(this, request, parent, isMain);
  if (
    exported &&
    typeof exported === 'object' &&
    !instrumented.has(exported) &&
    typeof exported.mustCall === 'function' &&
    typeof exported.mustCallAtLeast === 'function'
  ) {
    instrumented.add(exported);
    instrument(exported);
  }
  return exported;
};

function instrument(common) {
  // `common` is a Proxy whose `get` trap throws for a key it does not know, so
  // the guard against double wrapping lives in the WeakSet above rather than in
  // a marker property here. Assigning an existing key is safe: the Proxy has no
  // `set` trap, so the write lands on the target object.
  const wrap = (name, kind) => {
    const original = common[name];
    if (typeof original !== 'function') return;
    common[name] = function (fn, criteria) {
      const id = `${prefix}${kind}${++seq}`;
      const expected =
        typeof fn === 'number' ? fn : criteria === undefined ? 1 : criteria;
      write({ k: 'expect', id, kind, expected });
      const inner = original.apply(this, arguments);
      return function () {
        write({ k: 'hit', id });
        return inner.apply(this, arguments);
      };
    };
  };

  // `mustNotCall` is deliberately not wrapped: it fails from the callback body,
  // so its invocation is not evidence about the exit path.
  wrap('mustCall', 'exact');
  wrap('mustCallAtLeast', 'minimum');
  wrap('mustSucceed', 'succeed');
}

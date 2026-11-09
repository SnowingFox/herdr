#!/usr/bin/env python3
"""Compares rustnode's stdout against node's for the same script.

The per-binding tests check contracts; this checks observable behaviour. It runs
one script on both runtimes and diffs the output byte for byte, which catches
the kind of difference a contract cannot express: a wrong default, an inspect
format that differs by a space, an encoding that maps a character differently.

Only modules both runtimes can actually load are used, so the script is scoped
to what has landed. When a new namespace lands, add a line to the script rather
than to this file.

Usage:
    tools/parity.py
    tools/parity.py --script path/to/script.js
    tools/parity.py --keep        # leave the script for inspection
"""

import argparse
import difflib
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A script touching every module that loads today. Values are chosen to be
# deterministic and identical on both runtimes; anything time-, pid- or
# path-dependent is deliberately excluded, because a diff there says nothing
# about correctness.
DEFAULT_SCRIPT = r"""
const path = require('path');
const util = require('util');
const os = require('os');
const { EventEmitter } = require('events');
const { Buffer } = require('buffer');
const querystring = require('querystring');
const { StringDecoder } = require('string_decoder');

const out = {};

out.path = {
  join: path.join('/a/b', '../c', 'd'),
  normalize: path.normalize('/a//b/../c/'),
  parse: path.parse('/home/user/file.tar.gz'),
  extname: path.extname('index.coffee.md'),
  relative: path.relative('/data/orandea/test/aaa', '/data/orandea/impl/bbb'),
  basename: path.basename('/a/b/c.txt', '.txt'),
  dirname: path.dirname('/a/b/c.txt'),
  isAbsolute: path.isAbsolute('/a/b'),
  sep: path.sep,
};

out.os = {
  bigEndian: os.endianness(),
  arch: os.arch(),
  platform: os.platform(),
  hasCpus: os.cpus().length > 0,
  cpusAreObjects: typeof os.cpus()[0] === 'object',
  timesKeys: Object.keys(os.cpus()[0].times),
  userInfoHasUid: typeof os.userInfo().uid === 'number',
};

out.events = (() => {
  const e = new EventEmitter();
  const seen = [];
  e.on('a', (v) => seen.push('a' + v));
  e.once('b', (v) => seen.push('b' + v));
  e.emit('a', 1);
  e.emit('b', 2);
  e.emit('b', 3);
  seen.push('count' + e.listenerCount('a'));
  e.removeAllListeners('a');
  seen.push('after' + e.listenerCount('a'));
  return seen;
})();

out.inspect = {
  nested: util.inspect({ a: [1, 2], b: { c: 'x' } }),
  depth: util.inspect({ a: { b: { c: { d: 1 } } } }, { depth: 1 }),
  colors: util.inspect({ a: 1 }, { colors: false }),
  string: util.inspect('with "quotes"'),
  array: util.inspect([1, 'two', null, undefined]),
  circular: (() => {
    const o = { name: 'x' };
    o.self = o;
    return util.inspect(o);
  })(),
  typedArray: util.inspect(new Uint8Array([1, 2, 3])),
};

out.format = [
  util.format('%s-%d', 'v', 42),
  util.format('%j', { a: 1 }),
  util.format('%o', { a: 1 }),
  util.format('no args'),
  util.format('%s', {}),
];

out.buffer = {
  base64: Buffer.from('hello world').toString('base64'),
  base64url: Buffer.from('subjects?_d').toString('base64url'),
  hex: Buffer.from([0, 1, 254, 255]).toString('hex'),
  latin1: Buffer.from('cafe').toString('latin1'),
  utf8FromHex: Buffer.from('e282ac', 'hex').toString('utf8'),
  byteLength: Buffer.byteLength('日本語'),
  compare: Buffer.compare(Buffer.from('a'), Buffer.from('b')),
  concat: Buffer.concat([Buffer.from('ab'), Buffer.from('cd')]).toString(),
  slice: Buffer.from('abcdef').subarray(1, 4).toString(),
  allocFilled: Buffer.alloc(4, 'ab').toString(),
  isBuffer: Buffer.isBuffer(Buffer.from('x')),
  json: JSON.stringify(Buffer.from([1, 2])),
};

out.querystring = {
  stringify: querystring.stringify({ a: 1, b: [2, 3], c: 'x y' }),
  parse: querystring.parse('a=1&b=2&b=3&c=x%20y'),
  escape: querystring.escape('a b&c'),
  unescape: querystring.unescape('a%20b%26c'),
};

// A four-byte code point split across two writes is the case that catches a
// decoder retaining the wrong state.
const decoder = new StringDecoder('utf8');
const emoji = Buffer.from('\u{1F44D}');
out.stringDecoder = [
  decoder.write(emoji.subarray(0, 2)),
  decoder.write(emoji.subarray(2)),
  decoder.end(),
];

out.unicode = {
  width: util.inspect('日本').length,
  combining: 'e\u0301'.length,
  emoji: '\u{1F600}'.length,
};

console.log(JSON.stringify(out, null, 2));
"""


def find_node():
    for candidate in (os.environ.get("NODE_BIN"), shutil.which("node")):
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def find_rustnode():
    # The debug build comes first: it is the one under active development, and
    # preferring a stale release binary silently compares against old behaviour.
    for profile in ("debug", "release"):
        candidate = os.path.join(ROOT, "target", profile, "rustnode")
        if os.path.isfile(candidate):
            return candidate
    return None


def run(binary, script_path, cwd):
    return subprocess.run(
        [binary, script_path],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=120,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--script")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    node = find_node()
    rustnode = find_rustnode()
    if node is None:
        print("parity: no node binary on PATH; set NODE_BIN", file=sys.stderr)
        return 2
    if rustnode is None:
        print("parity: build rustnode first (cargo build -p rn-cli)", file=sys.stderr)
        return 2

    if args.script:
        script_path = os.path.abspath(args.script)
        temporary = None
    else:
        handle, script_path = tempfile.mkstemp(suffix=".js", prefix="rustnode-parity-")
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(DEFAULT_SCRIPT)
        temporary = script_path

    # Run from a neutral directory so neither runtime resolves anything through
    # the repository's own package.json.
    workdir = tempfile.mkdtemp(prefix="rustnode-parity-cwd-")
    try:
        reference = run(node, script_path, workdir)
        candidate = run(rustnode, script_path, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        if temporary and not args.keep:
            os.unlink(temporary)

    if reference.returncode != 0:
        print(
            "parity: the reference node run failed, so there is nothing to compare",
            file=sys.stderr,
        )
        print(reference.stderr.strip(), file=sys.stderr)
        return 2
    if candidate.returncode != 0:
        print("parity: rustnode failed", file=sys.stderr)
        print(candidate.stderr.strip(), file=sys.stderr)
        return 1

    if reference.stdout == candidate.stdout:
        print(f"parity: identical output across {len(reference.stdout)} bytes")
        return 0

    difference = difflib.unified_diff(
        reference.stdout.splitlines(keepends=True),
        candidate.stdout.splitlines(keepends=True),
        fromfile="node",
        tofile="rustnode",
    )
    print("".join(difference))
    print()
    print("parity: outputs differ")
    return 1


if __name__ == "__main__":
    sys.exit(main())

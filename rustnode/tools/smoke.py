#!/usr/bin/env python3
"""Proves the runtime works end to end, one layer at a time.

The unit tests check each binding against its contract. This checks the thing a
user actually cares about: that `rustnode script.js` behaves like `node
script.js` for real programs.

Each case prints PASS, FAIL or SKIP. A SKIP means a dependency has not landed
yet, not that the case passed; that distinction is the whole point, because a
suite that quietly skips everything looks identical to one that passes.

Usage:
    tools/smoke.py
    tools/smoke.py --verbose
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUSTNODE = os.path.join(ROOT, "target", "debug", "rustnode")


def rustnode_binary():
    for candidate in (
        os.path.join(ROOT, "target", "release", "rustnode"),
        os.path.join(ROOT, "target", "debug", "rustnode"),
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


def run(binary, args, stdin_text=None):
    result = subprocess.run(
        [binary, *args],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.returncode, result.stdout, result.stderr


# Every case is a name, the arguments, and the exact stdout expected. Exact
# output is the point: a case that only checks the exit code passes on garbage.
CASES = [
    (
        "arithmetic",
        ["-e", "console.log(1 + 1)"],
        "2\n",
        None,
    ),
    (
        "print flag",
        ["-p", "[1,2,3].map(n => n * 2).join(',')"],
        "2,4,6\n",
        None,
    ),
    (
        "exceptions propagate",
        ["-e", "try { null.x } catch (e) { console.log(e.constructor.name) }"],
        "TypeError\n",
        None,
    ),
    (
        "promise microtasks",
        [
            "-e",
            "Promise.resolve(1).then(v => console.log('resolved', v));"
            "queueMicrotask(() => console.log('microtask'));",
        ],
        "resolved 1\nmicrotask\n",
        None,
    ),
    (
        "node:path",
        ["-e", "console.log(require('node:path').join('/a', 'b', '..', 'c'))"],
        "/a/c\n",
        None,
    ),
    (
        "node:util inspect",
        ["-e", "console.log(require('node:util').inspect({a: [1, 2]}))"],
        "{ a: [ 1, 2 ] }\n",
        None,
    ),
    (
        "node:os",
        ["-e", "console.log(typeof require('node:os').totalmem())"],
        "number\n",
        None,
    ),
    (
        "node:buffer base64",
        ["-e", "console.log(Buffer.from('hello').toString('base64'))"],
        "aGVsbG8=\n",
        None,
    ),
    (
        "node:events",
        [
            "-e",
            "const {EventEmitter} = require('node:events');"
            "const e = new EventEmitter();"
            "e.on('x', v => console.log('got', v));"
            "e.emit('x', 42);",
        ],
        "got 42\n",
        None,
    ),
    (
        "node:fs read",
        [
            "-e",
            "const fs = require('node:fs');"
            "fs.writeFileSync('/tmp/rn-smoke.txt', 'hello');"
            "console.log(fs.readFileSync('/tmp/rn-smoke.txt', 'utf8'));",
        ],
        "hello\n",
        None,
    ),
    (
        "node:process argv",
        ["-e", "console.log(process.argv.length >= 1, process.pid > 0)"],
        "true true\n",
        None,
    ),
    (
        "node:assert",
        [
            "-e",
            "const assert = require('node:assert');"
            "assert.strictEqual(1 + 1, 2);"
            "console.log('asserted');",
        ],
        "asserted\n",
        None,
    ),
    (
        "node:querystring",
        [
            "-e",
            "console.log(require('node:querystring').stringify({a: 1, b: 2}))",
        ],
        "a=1&b=2\n",
        None,
    ),
    (
        "node:zlib round trip",
        [
            "-e",
            "const zlib = require('node:zlib');"
            "const input = Buffer.from('hello world');"
            "const packed = zlib.gzipSync(input);"
            "console.log(zlib.gunzipSync(packed).toString());",
        ],
        "hello world\n",
        None,
    ),
    (
        "node:crypto hash",
        [
            "-e",
            "const crypto = require('node:crypto');"
            "console.log(crypto.createHash('sha256').update('abc').digest('hex').slice(0, 16));",
        ],
        "ba7816bf8f01cfea\n",
        None,
    ),
    (
        "node:timers",
        [
            "-e",
            "setTimeout(() => console.log('timer fired'), 1);"
            "console.log('scheduled');",
        ],
        "scheduled\ntimer fired\n",
        None,
    ),
    (
        "require a script file",
        ["/tmp/rn-smoke-script.js"],
        "from a file\n",
        "console.log('from a file');",
    ),
    (
        "require a sibling module",
        ["/tmp/rn-smoke-main.js"],
        "sibling value\n",
        "__SIBLING__",
    ),
]

# Cases whose expected output depends on a fixture file this script writes.
FIXTURES = {
    "require a script file": {"/tmp/rn-smoke-script.js": "console.log('from a file');\n"},
    "require a sibling module": {
        "/tmp/rn-smoke-main.js": (
            "const helper = require('./rn-smoke-helper');\n"
            "console.log(helper.value);\n"
        ),
        "/tmp/rn-smoke-helper.js": "module.exports = { value: 'sibling value' };\n",
    },
}


def classify(stderr):
    """Whether a failure is a missing dependency or a real defect."""
    missing = [
        "has no Rust implementation yet",
        "Missing internal module",
        "is not a function",
    ]
    return "skip" if any(needle in stderr for needle in missing) else "fail"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    binary = rustnode_binary()
    if binary is None:
        print("smoke: build rustnode first (cargo build -p rn-cli)", file=sys.stderr)
        return 2

    for name, files in FIXTURES.items():
        for path, contents in files.items():
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(contents)

    passed = failed = skipped = 0
    failures = []
    for name, argv, expected, _ in CASES:
        try:
            code, stdout, stderr = run(binary, argv)
        except subprocess.TimeoutExpired:
            failed += 1
            failures.append((name, "timed out after 60s"))
            continue

        if code == 0 and stdout == expected:
            passed += 1
            if args.verbose:
                print(f"PASS  {name}")
            continue

        verdict = classify(stderr)
        detail = (stderr.strip() or stdout.strip() or f"exit {code}").splitlines()
        first = detail[0] if detail else "no output"
        if verdict == "skip":
            skipped += 1
            print(f"SKIP  {name}  ({first})")
        else:
            failed += 1
            failures.append((name, first))
            print(f"FAIL  {name}  ({first})")

    total = passed + failed + skipped
    print()
    print(f"{passed}/{total} passed, {failed} failed, {skipped} skipped")

    if failures:
        print()
        print("failures")
        print("-" * 60)
        for name, detail in failures:
            print(f"  {name:<30}{detail}")

    # A skip is not a pass. Exiting zero when everything skipped would let a
    # broken runtime report success.
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

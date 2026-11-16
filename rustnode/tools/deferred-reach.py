#!/usr/bin/env python3
"""Finds deferred binding members that `lib/**` reaches without a guard.

The three-state contract check treats a declared deferral as a pass, which is
correct: declaring an absent member is honest. But it cannot tell you whether
the JavaScript layer tolerates that absence. `zlib` declared `crc32c` deferred
and the contract still reported `zlib 8 recorded 0 missing ok`, while
`lib/zlib.js` destructured it at module scope and `zlib.crc32()` called it
without a guard, so `require('zlib')` failed outright.

# What this tool originally got wrong, and why the rule changed

Until this rewrite the only thing counted was a call at **module scope** (brace
depth 0) in the file that declared the function. That rule came from the
`zlib.crc32c` case, where the damage really is done during `require()`. It is
wrong for a whole class of real defects, and it reported a clean bill of health
on at least six of them:

    modules.getWasmCompileCacheEntry   internal/modules/esm/translators.js:583
    v8.startCpuProfile                 lib/v8.js:241
    performance.Histogram              internal/histogram.js:969
    messaging.broadcastChannel         internal/worker/io.js:383
    crypto.CheckPrimeJob               internal/crypto/random.js:685
    crypto.RandomPrimeJob              internal/crypto/random.js:581

The wasm one is the clearest illustration. `translators.js` destructures both
wasm cache members at module scope (harmless, as the old docstring correctly
said), then calls `getWasmCompileCacheEntry` inside the `wasm` translator:

    translators.set('wasm', function(url, translateContext) {   // depth 0
      ...
      const cacheEntry = getWasmCompileCacheEntry(...);         // depth 1
    });

Depth 1, so the old rule never looked at it. But the translator is *the* code
path for `import('./x.wasm')`, so every `.wasm` import threw
`TypeError: getWasmCompileCacheEntry is not a function`. The same shape repeats
throughout `lib/**`: a callback registered at module scope, or a function
exported at module scope, calls a deferred member when the user first uses the
feature. `require()` succeeds; first use throws.

So the rule is now: **every call site counts, at any depth**, and the question
is no longer "is this at module scope" but "is this reach guarded". A reach is
guarded when the same source file tests the member's presence before using it —
`typeof m === 'function'`, `m === undefined`, `m !== undefined`, `!!m`, or a
`?`-guard. That is the honest question: an unguarded reach of an absent member
throws on first use whether it sits at depth 0 or depth 4.

# What this tool still cannot see

A clean run does not mean the deferred members are safe. It means nothing in
`lib/**` reaches one of them in a shape this script recognises. Specifically it
does not model:

* **Data flow.** An alias passed as an argument is not followed:
  `register(f)` where `register` later calls it, or `const h = f; h()`.
  Only a direct call of a binding-derived name is attributed.
* **Control flow.** A guard anywhere in the file suppresses every reach in that
  file, even if it precedes an unrelated reach, or sits in dead code. A guard in
  a *different* file does not count at all, so a member guarded by its caller is
  reported.
* **Cross-namespace aliasing.** `const b = require('internal/x')` then
  `b.member()` is not attributed unless `x` destructures from `internalBinding`.
* **Reachability.** Every function, exported or not, is treated as reachable.
  A helper nothing calls is reported the same as the ESM wasm translator.
* **Re-exports.** `module.exports = { f }` and `export { f }` in a wrapper are
  not followed, so the eventual call site may be invisible.
* **Runtime behaviour.** Whether a deferred member is *supposed* to be absent
  is a policy question this script cannot answer. `icu.decode` and
  `crypto.Argon2Job` are absent on purpose behind a feature check; a reach with
  no textual guard is flagged the same way as a defect.

# The baseline

Because of (the last point), and because the tree currently holds real defects
in several crates that are not this commit's to fix, every finding that exists
today is named explicitly in `KNOWN_UNGUARDED`. The gate fails on anything not
on that list, so it is enforcing from the first commit rather than red for
reasons the author cannot address. The list shrinking is the proof a fix landed;
adding to it is a visible act that a reviewer can reject, which is the whole
point of not letting the script fail open.

Usage:
    tools/deferred-reach.py
    tools/deferred-reach.py --json
    tools/deferred-reach.py --baseline PATH    # use another allowlist

Exit code is 1 when any at-risk reach is found outside the baseline, so this
can gate CI. Exit code 2 means the analysis could not read a crate's
declarations, which is a bug in this script rather than a finding.
"""

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "vendor", "libnode-js", "lib")

# `crates/<crate>/src/**` declares deferrals as `("member", "reason")` pairs in a
# `DEFERRED` const, which is the convention every binding crate follows.
#
# Both the declaration and its entries are matched as loosely as the convention
# allows, because failing to match is a silent pass. A `DEFERRED` const that is
# re-exported from another const, or written on one line, used to parse as zero
# entries with no error at all; `crate_deferrals` now treats any `pub const
# DEFERRED` it cannot read as an error instead.
DEFERRED_DECL = re.compile(
    r'(?:pub )?const DEFERRED: &\[\(&str, &str\)\]\s*=\s*(?:&\[(?P<body>.*?)\]|(?P<alias>[A-Za-z_][\w:]*))\s*;',
    re.S,
)
# An entry is `("member", "reason")` with rustfmt's optional trailing comma and
# any amount of whitespace between the fields. The trailing comma is not
# cosmetic: rustfmt puts one there as soon as an entry spans several lines, and
# an earlier version of this pattern rejected it, which made every long-reason
# deferral parse as zero entries and the gate fail open.
DEFERRED_ENTRY = re.compile(
    r'\(\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\)', re.S
)
NAMESPACE = re.compile(r"fn namespace\(&self\) -> &'static str \{\s*\"([^\"]+)\"")

# Findings present in the tree today. `namespace.member` for each reach this
# script would otherwise report. Every entry is either a real defect owned by
# another task or a deliberate absence whose guard this script cannot model;
# see the module docstring. Deleting an entry as its defect is fixed is the
# proof the fix landed, and the count is asserted so a stale entry cannot linger.
KNOWN_UNGUARDED = {
    # Real defects, each confirmed against the pinned oracle by calling the
    # public API: rustnode throws where Node returns a value.
    #   crypto.checkPrime        TypeError: CheckPrimeJob is not a constructor
    #   crypto.createECDH        TypeError: _ECDH is not a constructor
    #   crypto.generatePrimeSync TypeError: RandomPrimeJob is not a constructor
    #   crypto.generateKeyPairSync('dsa') TypeError: DsaKeyPairGenJob ...
    #   v8.startCpuProfile       TypeError: _startCpuProfile is not a function
    #   v8.startHeapProfile      TypeError: _startHeapProfile is not a function
    #   perf_hooks.createHistogram TypeError: _Histogram is not a constructor
    #   new BroadcastChannel     TypeError: broadcastChannel is not a function
    #   fs.openAsBlobSync        TypeError: _createBlobFromFilePath is not a function
    #   vm.measureMemory         TypeError: _measureMemory is not a function
    #   v8.queryObjects          TypeError: _queryObjects is not a function
    #
    # The two wasm cache members used to be here. They were removed with the
    # import path fix that installed them, which is what this list shrinking
    # looks like; they are now in `MEMBERS` and called by the `.wasm` tests.
    "blob.createBlobFromFilePath",
    "contextify.measureMemory",
    "internal_only_v8.queryObjects",
    "crypto.CheckPrimeJob",
    "crypto.DsaKeyPairGenJob",
    "crypto.DHBitsJob",
    "crypto.DhKeyPairGenJob",
    "crypto.ECDH",
    "crypto.ECDHConvertKey",
    "crypto.KEMDecapsulateJob",
    "crypto.KEMEncapsulateJob",
    "crypto.KangarooTwelveJob",
    "crypto.KmacJob",
    "crypto.Mac",
    "crypto.RandomBytesJob",
    "crypto.RandomPrimeJob",
    "crypto.TurboShakeJob",
    "crypto.ChaCha20Poly1305CipherJob",
    "crypto.certExportChallenge",
    "crypto.certExportPublicKey",
    "crypto.certVerifySpkac",
    "crypto.getCachedMacAliases",
    "crypto.isCryptoKey",
    "crypto.setFipsCrypto",
    "fs.CpDirJob",
    "fs.cpSyncCopyDir",
    "fs.cpSyncOverrideFile",
    "fs.getFormatOfExtensionlessFile",
    "fs.legacyMainResolve",
    "messaging.broadcastChannel",
    "performance.Histogram",
    "performance.SlidingWindowHistogram",
    "v8.startCpuProfile",
    "v8.startHeapProfile",
    "v8.stopCpuProfile",
    "v8.stopHeapProfile",
    # The three below were *stubs* before: installed, and throwing "not
    # implemented" on every call. They are declared in their crate's `DEFERRED`
    # instead now, which is the honest shape but a shape this script can see for
    # the first time. Each reach is a call the owning module makes, and each is
    # unreachable or already guarded, not a defect being accepted:
    #
    #   builtins.importBuiltinSourceTextModule  internal/main/prof_process.js:32
    #       reached at module scope, and that module is only dispatched by
    #       `--prof-process`, which rustnode rejects at argument parsing.
    #   fs.handleToFd                           internal/fs/streams.js:186
    #       reached inside `importWindowsHandle`, which throws
    #       `ERR_FEATURE_UNAVAILABLE_ON_PLATFORM` before this line on any
    #       non-Windows platform. Node does not install this member on Linux at
    #       all, so the deferred declaration is the platform gap, not a bug.
    #   mksnapshot.compileSerializeMain          internal/main/mksnapshot.js:199
    #       inside `minimalRunCjs`, and `internal/main/mksnapshot` is never
    #       dispatched; it also needs the unimplemented `sea` namespace at module
    #       scope, so it would throw before reaching this line.
    "builtins.importBuiltinSourceTextModule",
    "fs.handleToFd",
    "mksnapshot.compileSerializeMain",
}


# Files that declare a `DEFERRED` list that is *not* an `internalBinding`
# namespace. They are excluded by path, explicitly, so that a new one appearing
# is an error rather than an unexamined skip. `rn-napi`'s list is a set of
# Node-API *symbols* diffed against the oracle by `tools/napi-symbol-coverage.py`,
# which is the gate that owns it; there is no namespace object for `lib/**` to
# reach, so this script has nothing to ask about it.
NON_NAMESPACE_DEFERRALS = {
    "crates/rn-napi/src/shims.rs": (
        "Node-API symbols, gated by tools/napi-symbol-coverage.py; not a namespace"
    ),
    "crates/rn-napi/src/symbols.rs": (
        "Node-API symbol table, gated by tools/napi-symbol-coverage.py; not a namespace"
    ),
}


class UnparsedDeferral(Exception):
    """A `DEFERRED` block whose entries this script could not read."""


def impl_blocks(text):
    """`[(start, end)]` spans of `impl ... { ... }` bodies.

    Deferrals are attributed per impl block rather than per file, because a file
    can hold several: `rn-bind-heap-utils` declares `heap_utils` and
    `internal_only_v8`, each returning a different const. Attributing every
    `DEFERRED` in the file to every namespace produced a member the namespace
    does not have, which is a finding that cannot be fixed.
    """
    spans = []
    for match in re.finditer(r"\bimpl\b[^{]*\{", text):
        start = match.end() - 1
        depth = 0
        for index in range(start, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((start, index))
                    break
    return spans


def const_body(text, name):
    """The `&[ ... ]` body of `const NAME: ... = &[ ... ];`, or None."""
    match = re.search(
        r"const\s+" + re.escape(name) + r"\s*:\s*&\[\(&str,\s*&str\)\]\s*=\s*(?:&\[(.*?)\]|([A-Za-z_][\w:]*))\s*;",
        text,
        re.S,
    )
    if not match:
        return None, None
    return match.group(1), match.group(2)


def parse_entries(body, relative):
    """`[(member, reason)]` from a `DEFERRED` array body, or raise."""
    members = DEFERRED_ENTRY.findall(body)
    # Count the pairs independently of the field split, so a formatting change
    # that stops the entry pattern matching is an error rather than an empty
    # result.
    declared = body.count('("') + body.count('(\n')
    if len(members) != declared:
        raise UnparsedDeferral(
            f"{relative}: read {len(members)} of {declared} DEFERRED entries; "
            "the entry format changed"
        )
    return members


def crate_deferrals():
    """`{namespace: [(member, reason), ...]}` from every binding crate.

    Raises `UnparsedDeferral` when a crate declares deferrals that this script
    cannot read. Failing loudly matters more than it looks: the whole point of
    the check is to catch absent members that break a module, and a regex that
    quietly matches nothing reports a clean bill of health for a crate full of
    at-risk deferrals.

    Three fail-open shapes were found in the tree when this was rewritten, each
    of which used to report a clean result:

    * a single-entry block written as `&[(\\n  "m", "r",\\n)];`, where the `&[`
      is not followed by a newline before `];` — this hid `blob`, `contextify`
      and `heap_utils` entirely, four namespaces and four members in all;
    * a file holding more than one `impl BindingModule`, where every deferral
      was attributed to every namespace in the file;
    * a `DEFERRED` list that is not a namespace at all (`rn-napi`'s symbol
      table), which was skipped with no diagnostic.

    All three now fail closed: an unreadable block raises, attribution is per
    impl block, and a non-namespace list must be named in
    `NON_NAMESPACE_DEFERRALS`.
    """
    deferrals = {}
    crates = os.path.join(ROOT, "crates")
    for entry in sorted(os.listdir(crates)):
        source_dir = os.path.join(crates, entry, "src")
        if not os.path.isdir(source_dir):
            continue
        for name in sorted(os.listdir(source_dir)):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(source_dir, name)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            if "DEFERRED" not in text:
                continue
            relative = os.path.relpath(path, ROOT).replace(os.sep, "/")
            if relative in NON_NAMESPACE_DEFERRALS:
                # Named, not skipped: the entry states why this file cannot hold
                # a namespace deferral, and an unlisted file fails below.
                continue

            attributed = False
            for start, end in impl_blocks(text):
                block = text[start:end]
                namespace = NAMESPACE.search(block)
                if not namespace:
                    continue
                returned = re.search(
                    r"fn deferred\(&self\)[^{]*\{\s*(?:[^;{}]*?\b)?([A-Za-z_][\w:]*)\s*\}",
                    block,
                )
                if not returned:
                    continue
                const_name = returned.group(1)
                body, alias = const_body(text, const_name)
                if body is None and alias is None:
                    raise UnparsedDeferral(
                        f"{relative}: `{namespace.group(1)}` returns `{const_name}` "
                        "from `deferred()` and this script cannot read it"
                    )
                if alias is not None:
                    raise UnparsedDeferral(
                        f"{relative}: `{const_name}` is an alias ({alias}), which "
                        "this script does not follow"
                    )
                members = parse_entries(body, relative)
                attributed = True
                if members:
                    deferrals.setdefault(namespace.group(1), []).extend(members)

            if attributed:
                continue

            # A file that declares deferrals but has no attributable impl block
            # is an error, not a skip. `rn-napi`'s symbol table belongs here and
            # is named above; anything else is a shape this script cannot read
            # and must not silently pass.
            if re.search(r"(?:pub )?const [A-Z_]*DEFERRED[A-Z_]*\b", text):
                raise UnparsedDeferral(
                    f"{relative}: declares a DEFERRED list but no "
                    "`impl BindingModule` with `fn namespace()` to attribute it "
                    "to. If this list is not an internalBinding namespace, add "
                    "it to NON_NAMESPACE_DEFERRALS with the gate that owns it."
                )
    return deferrals


def strip_comments_and_strings(source):
    """`source` with comments blanked and string bodies removed.

    Braces and parentheses inside a comment or a literal would otherwise throw
    off the depth count. The replacement keeps newlines so line numbers still
    line up.
    """
    out = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        pair = source[index : index + 2]
        if pair == "//":
            end = source.find("\n", index)
            end = length if end == -1 else end
            out.append(" " * (end - index))
            index = end
        elif pair == "/*":
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            out.append("".join(c if c == "\n" else " " for c in source[index:end]))
            index = end
        elif char in "\"'`":
            quote = char
            end = index + 1
            while end < length:
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            out.append(quote + "".join(
                c if c == "\n" else " " for c in source[index + 1 : max(end - 1, index + 1)]
            ) + quote)
            index = end
        else:
            out.append(char)
            index += 1
    return "".join(out)


def depth_at(cleaned, offset):
    """Brace depth at `offset`, so 0 means module scope."""
    return cleaned.count("{", 0, offset) - cleaned.count("}", 0, offset)


def line_of(source, offset):
    return source.count("\n", 0, offset) + 1


def is_code(source, cleaned, match):
    """Whether `match` starts in real source rather than a comment or literal.

    Patterns run against the original text so they can see string contents like
    `internalBinding('ns')`, which means a call the author commented out still
    matches. `strip_comments_and_strings` blanks exactly those spans, so a
    blanked character at the match start means the match is not code.
    """
    start = match.start()
    if start >= len(cleaned) or source[start] == "\n":
        return False
    return cleaned[start] == source[start] and not cleaned[start].isspace()


def binding_bindings(source, namespace):
    """`{alias: (member, line)}` for members destructured out of this binding.

    Any depth, not just module scope: a destructuring inside a function still
    binds the absent member, and the call that follows is what throws. Returns
    every alias bound out of this namespace, whether directly from
    `internalBinding` or from a local const that holds the binding.
    """
    bound = {}
    binding_call = r"internalBinding\(\s*'" + re.escape(namespace) + r"'\s*\)"
    # Locals that hold this namespace: `const binding = internalBinding('ns')`.
    locals_with_namespace = {
        match.group(1)
        for match in re.finditer(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*" + binding_call, source
        )
    }
    source_pattern = binding_call
    if locals_with_namespace:
        source_pattern += "|" + "|".join(
            r"\b" + re.escape(name) + r"\b" for name in sorted(locals_with_namespace)
        )

    for match in re.finditer(
        r"(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*(?:" + source_pattern + r")",
        source,
    ):
        line = line_of(source, match.start())
        for piece in match.group(1).split(","):
            piece = piece.strip()
            if not piece or piece.startswith("..."):
                continue
            if ":" in piece:
                key, alias = [part.strip() for part in piece.split(":", 1)]
            else:
                key = alias = piece
            key = key.strip("'\"")
            if not re.fullmatch(r"[A-Za-z_$][\w$]*", alias):
                continue
            bound[alias] = (key, line)
    return bound


def namespace_locals(source, namespace):
    """Locals whose value is the whole namespace object."""
    return {
        match.group(1)
        for match in re.finditer(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*internalBinding\(\s*'"
            + re.escape(namespace)
            + r"'\s*\)",
            source,
        )
    }


def guarded_in(source, member, aliases):
    """Whether this file tests `member`'s presence before reaching it.

    Every pattern here is a presence test that makes an absent member safe:
    `typeof m === 'function'`, `m === undefined`, `m !== undefined`, `!!m`, and
    a `?`-guard. This is deliberately a *file-level* approximation: it asks
    "does the author know this member may be absent", not "is this particular
    reach dominated by the guard". The docstring's "cannot see" section records
    the imprecision rather than hiding it.
    """
    names = [member, *sorted(aliases)]
    for name in names:
        escaped = re.escape(name)
        for pattern in (
            r"\b{e}\s*[!=]==?\s*(?:undefined|null)",
            r"(?:undefined|null)\s*[!=]==?\s*\b{e}\b",
            r"typeof\s+{e}\b",
            r"typeof\s+[A-Za-z_$][\w$.]*\.{e}\b",
            r"!!\s*{e}\b",
            r"\?\s*{e}\b",
            r"\b{e}\s*\?",
        ):
            if re.search(pattern.format(e=escaped), source):
                return True
    return False


def reaches(source, cleaned, namespace, member):
    """`[(line, depth)]` where `member` of `namespace` is called, at any depth."""
    hits = set()
    bound = binding_bindings(source, namespace)
    aliases = [alias for alias, (name, _) in bound.items() if name == member]

    for alias in aliases:
        for match in re.finditer(
            r"(?<![\w$.])" + re.escape(alias) + r"\s*(?:\.\s*call\s*)?\(", source
        ):
            if is_code(source, cleaned, match):
                hits.add((line_of(source, match.start()), depth_at(cleaned, match.start())))

    for local in sorted(namespace_locals(source, namespace)):
        for match in re.finditer(
            r"(?<![\w$.])" + re.escape(local) + r"\s*\.\s*" + re.escape(member)
            + r"\s*\(",
            source,
        ):
            if is_code(source, cleaned, match):
                hits.add((line_of(source, match.start()), depth_at(cleaned, match.start())))

    return sorted(hits), aliases


def builtin_sources():
    """Every builtin's source, keyed by id."""
    sources = {}
    for root, _, files in os.walk(LIB):
        for name in files:
            if not name.endswith(".js"):
                continue
            path = os.path.join(root, name)
            relative = os.path.relpath(path, LIB).replace(os.sep, "/")
            identifier = relative[: -len(".js")]
            with open(path, encoding="utf-8", errors="replace") as handle:
                sources[identifier] = handle.read()
    return sources


def load_baseline(path):
    if path is None:
        return set(KNOWN_UNGUARDED)
    with open(path, encoding="utf-8") as handle:
        return {
            line.strip()
            for line in handle
            if line.strip() and not line.lstrip().startswith("#")
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="read the allowlist of known reaches from PATH instead of the "
        "built-in list (one `namespace.member` per line, `#` comments allowed)",
    )
    parser.add_argument(
        "--show-known",
        action="store_true",
        help="also list the reaches that are on the baseline, so a clean run is "
        "readable as 'these N are known' rather than 'nothing is wrong'",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the analysis over fixtures that are the shapes it must catch "
        "and the shapes it must ignore, and exit non-zero on any mismatch",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    try:
        deferrals = crate_deferrals()
    except UnparsedDeferral as error:
        print(f"deferred-reach: {error}", file=sys.stderr)
        return 2
    if not deferrals:
        print("deferred-reach: no declared deferrals found", file=sys.stderr)
        return 0

    baseline = load_baseline(args.baseline)

    sources = builtin_sources()
    findings = []
    for namespace, members in sorted(deferrals.items()):
        for member, reason in members:
            for identifier, source in sources.items():
                if f"internalBinding('{namespace}')" not in source:
                    continue
                cleaned = strip_comments_and_strings(source)
                lines, aliases = reaches(source, cleaned, namespace, member)
                if not lines:
                    continue
                if guarded_in(source, member, aliases):
                    continue
                findings.append(
                    {
                        "namespace": namespace,
                        "member": member,
                        "reason": reason,
                        "module": identifier,
                        "lines": [line for line, _ in lines],
                        "depths": [depth for _, depth in lines],
                    }
                )

    known = [
        f
        for f in findings
        if f"{f['namespace']}.{f['member']}" in baseline
    ]
    unknown = [
        f
        for f in findings
        if f"{f['namespace']}.{f['member']}" not in baseline
    ]

    if args.json:
        print(json.dumps({"unknown": unknown, "known": known}, indent=2))
        return 1 if unknown else 0

    total = sum(len(m) for m in deferrals.values())
    if not unknown:
        print(
            f"deferred-reach: {total} declared deferral(s) across "
            f"{len(deferrals)} namespace(s); {len(known)} unguarded reach(es) "
            f"on the known list, 0 new"
        )
        if args.show_known:
            for finding in sorted(known, key=lambda f: (f["namespace"], f["member"])):
                locations = ", ".join(str(line) for line in finding["lines"])
                print(
                    f"  known  {finding['namespace']}.{finding['member']}"
                    f"  {finding['module']}.js:{locations}"
                )
        if known:
            print(
                "deferred-reach: the tool cannot tell an intentional absence "
                "from a defect; see its docstring for what it cannot see",
                file=sys.stderr,
            )
        return 0

    print(
        "deferred-reach: these deferred members are reached without a guard, "
        "so the first use of the feature throws"
    )
    print("-" * 78)
    for finding in unknown:
        locations = ", ".join(
            f"{line}@depth{depth}"
            for line, depth in zip(finding["lines"], finding["depths"])
        )
        print(
            f"  {finding['namespace']}.{finding['member']}"
            f"  reached in {finding['module']}.js:{locations}"
        )
        print(f"    declared reason: {finding['reason']}")
    print()
    print(
        f"{len(unknown)} unguarded reach(es) not on the baseline. Either install "
        "the member, guard the reach, or add it to KNOWN_UNGUARDED with a reason "
        "a reviewer can check."
    )
    return 1


def self_test():
    """Assert the analysis catches the shapes it exists for, and misses none.

    A checker that cannot fail is the defect it guards against, and this one
    already shipped a clean report over six live defects. Each case below is a
    minimal input with the verdict it must produce, so a regression in the
    reach rule or in the deferral parser fails here rather than in production.
    """
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r}, wanted {want!r}")

    binding = "const { f } = internalBinding('ns');\n"

    # A direct call at module scope, the shape the original tool caught.
    src = binding + "f();\n"
    clean = strip_comments_and_strings(src)
    check("module-scope call", [l for l, _ in reaches(src, clean, "ns", "f")[0]], [2])
    check("module-scope call is unguarded", guarded_in(src, "f", []), False)

    # The shape the tool used to miss, and the one this rewrite exists for: a
    # call inside a function body. `translators.js:583` is exactly this.
    src = binding + "table.set('wasm', function () {\n  f();\n});\n"
    clean = strip_comments_and_strings(src)
    hits = reaches(src, clean, "ns", "f")[0]
    check("call one level deep", [l for l, _ in hits], [3])
    check("call one level deep has depth 1", [d for _, d in hits], [1])
    check("nested call is unguarded", guarded_in(src, "f", []), False)

    # Deep nesting must not be silently dropped either.
    src = binding + "a(function () {\n b(function () {\n  c(function () {\n   f();\n  });\n });\n});\n"
    clean = strip_comments_and_strings(src)
    check(
        "call three levels deep",
        [d for _, d in reaches(src, clean, "ns", "f")[0]],
        [3],
    )

    # A guard makes the reach safe, and each guard spelling must count.
    for guard in (
        "if (typeof f === 'function') f();",
        "if (f !== undefined) f();",
        "if (f === undefined) {} else { f(); }",
        "const ok = !!f;",
        "f?.();",
    ):
        src = binding + guard + "\n"
        check(f"guard suppresses: {guard}", guarded_in(src, "f", []), True)

    # A guard in a different file must not suppress this one.
    guarded_elsewhere = "if (typeof f === 'function') {}\n"
    src = binding + "f();\n"
    check(
        "guard elsewhere does not suppress",
        guarded_in(src, "f", []),
        False,
    )
    check("the other file is guarded", guarded_in(guarded_elsewhere, "f", []), True)

    # `new` and `.call` are reaches; a bare reference is not a call.
    src = binding + "new f();\n"
    clean = strip_comments_and_strings(src)
    check("new is a reach", [l for l, _ in reaches(src, clean, "ns", "f")[0]], [2])
    src = binding + "f.call(null);\n"
    clean = strip_comments_and_strings(src)
    check("dot-call is a reach", [l for l, _ in reaches(src, clean, "ns", "f")[0]], [2])
    src = binding + "register(f);\n"
    clean = strip_comments_and_strings(src)
    check(
        "passing the alias is not a reach (documented limitation)",
        reaches(src, clean, "ns", "f")[0],
        [],
    )

    # A commented-out call is not a reach.
    src = binding + "// f();\n"
    clean = strip_comments_and_strings(src)
    check("commented call is ignored", reaches(src, clean, "ns", "f")[0], [])

    # The namespace-object spelling, and a destructuring inside a function.
    src = "const b = internalBinding('ns');\nb.f();\n"
    clean = strip_comments_and_strings(src)
    check(
        "namespace.member call",
        [l for l, _ in reaches(src, clean, "ns", "f")[0]],
        [2],
    )
    src = "function g() {\n  const { f } = internalBinding('ns');\n  f();\n}\n"
    clean = strip_comments_and_strings(src)
    check(
        "destructuring inside a function is still a reach",
        [l for l, _ in reaches(src, clean, "ns", "f")[0]],
        [3],
    )

    # The deferral parser must read every accepted layout, and must fail loudly
    # on the ones it cannot. These are the three fail-open shapes found in the
    # tree; each used to report zero deferrals for a whole namespace.
    good = {
        "multiline": (
            "pub const DEFERRED: &[(&str, &str)] = &[\n"
            '    ("a", "reason one"),\n];',
            1,
        ),
        "single entry, no trailing newline before ];": (
            "pub const DEFERRED: &[(&str, &str)] = &[(\n"
            '    "a", "reason one",\n)];',
            1,
        ),
        "one line": ('pub const DEFERRED: &[(&str, &str)] = &[("a", "r")];', 1),
        "two entries": (
            "pub const DEFERRED: &[(&str, &str)] = &[\n"
            '    ("a", "r1"),\n    ("b", "r2"),\n];',
            2,
        ),
        "empty": ("pub const DEFERRED: &[(&str, &str)] = &[];", 0),
    }
    for name, (text, count) in good.items():
        body, alias = const_body(text, "DEFERRED")
        if body is None:
            failures.append(f"parser rejected {name}")
            continue
        check(f"parser reads {name}", len(parse_entries(body, "fixture")), count)

    # A malformed entry must raise rather than read as fewer entries.
    try:
        parse_entries('(\n    "a" "reason"\n)', "fixture")
        failures.append("parser accepted a malformed entry")
    except UnparsedDeferral:
        pass

    if failures:
        print("deferred-reach self-test: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("deferred-reach self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

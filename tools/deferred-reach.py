#!/usr/bin/env python3
"""Finds deferred binding members that `lib/**` calls while a module loads.

The three-state contract check treats a declared deferral as a pass, which is
correct: declaring an absent member is honest. But it cannot tell you whether
the JavaScript layer tolerates that absence. `zlib` declared `crc32c` deferred
and the contract still reported `zlib 8 recorded 0 missing ok`, while
`lib/zlib.js` destructured it at module scope and `zlib.crc32()` called it
without a guard, so `require('zlib')` failed outright.

What matters is whether a member is *called* during module evaluation, not
whether it is read. Destructuring an absent member binds `undefined` and cannot
throw: `const { crc32c } = binding` is harmless, and `if (crc32c === undefined)
{ ... }` is a legitimate way to feature-detect a deferred member. Only reaching
it at module scope does damage, and that means a call, a `new`, or any other
expression that evaluates the binding before a function body runs.

So this reports deferred members that appear in a call at module scope, either
directly (`binding.member(...)`) or through an alias bound by a module-scope
destructuring (`const { member: alias } = binding; ... alias(...)`).

Usage:
    tools/deferred-reach.py
    tools/deferred-reach.py --json

Exit code is 1 when any at-risk deferral is found, so this can gate CI. Exit
code 2 means the analysis could not read a crate's declarations, which is a bug
in this script rather than a finding.
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
DEFERRED_DECL = re.compile(
    r'pub const DEFERRED:\s*&\[\(&str,\s*&str\)\]\s*=\s*&\[(.*?)\n\];', re.S
)
# An entry is `("member", "reason")` with rustfmt's optional trailing comma and
# any amount of whitespace between the fields. The trailing comma is not
# cosmetic: rustfmt puts one there as soon as an entry spans several lines, and
# an earlier version of this pattern rejected it, which made every long-reason
# deferral parse as zero entries and the gate fail open.
DEFERRED_ENTRY = re.compile(
    r'\(\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\)', re.S
)
NAMESPACE = re.compile(r'fn namespace\(&self\) -> &\'static str \{\s*"([^"]+)"')


class UnparsedDeferral(Exception):
    """A `DEFERRED` block whose entries this script could not read."""


def crate_deferrals():
    """`{namespace: [(member, reason), ...]}` from every binding crate.

    Raises `UnparsedDeferral` when a crate declares deferrals that this script
    cannot read. Failing loudly matters more than it looks: the whole point of
    the check is to catch absent members that break a module at load time, and a
    regex that quietly matches nothing reports a clean bill of health for a crate
    full of at-risk deferrals.
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
            namespaces = NAMESPACE.findall(text)
            block = DEFERRED_DECL.search(text)
            if not block or not namespaces:
                continue
            body = block.group(1)
            members = DEFERRED_ENTRY.findall(body)
            # Count the pairs independently of the field split, so a formatting
            # change that stops the entry pattern matching is an error rather
            # than an empty result.
            declared = body.count('("') + body.count('(\n')
            if len(members) != declared:
                raise UnparsedDeferral(
                    f"{os.path.relpath(path, ROOT)}: read {len(members)} of "
                    f"{declared} DEFERRED entries; the entry format changed"
                )
            if members:
                for namespace in namespaces:
                    deferrals.setdefault(namespace, []).extend(members)
    return deferrals


def strip_comments_and_strings(source):
    """`source` with comments blanked and string bodies removed.

    Braces and parentheses inside a comment or a literal would otherwise throw
    off the depth count that separates module scope from a function body. The
    replacement keeps newlines so line numbers still line up.
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


def module_scope_bindings(source, cleaned, namespace):
    """`{alias: (member, line)}` for members destructured at module scope.

    Returns every alias that a module-scope statement bound out of this
    namespace, whether directly from `internalBinding` or from a local const
    that holds the binding. Patterns match the original `source` because
    `strip_comments_and_strings` blanks string bodies, namespace literal
    included; `cleaned` is consulted only for brace depth, and the two are the
    same length so offsets line up.
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
        if depth_at(cleaned, match.start()) != 0:
            continue
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


def module_scope_calls(source, cleaned, namespace, member):
    """Line numbers where `member` of `namespace` is evaluated at module scope."""
    hits = set()
    binding_call = r"internalBinding\(\s*'" + re.escape(namespace) + r"'\s*\)"
    # Locals holding the whole namespace, so `binding.member(...)` is a call on
    # a namespace object rather than on a destructured alias.
    namespace_locals = {
        match.group(1)
        for match in re.finditer(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*" + binding_call, source
        )
    }

    for local in sorted(namespace_locals):
        for match in re.finditer(
            r"(?<![\w$.])" + re.escape(local) + r"\s*\.\s*" + re.escape(member)
            + r"\s*\(",
            source,
        ):
            if is_code(source, cleaned, match) and depth_at(cleaned, match.start()) == 0:
                hits.add(line_of(source, match.start()))

    bindings = module_scope_bindings(source, cleaned, namespace)
    for alias, (bound_member, bind_line) in sorted(bindings.items()):
        if bound_member != member:
            continue
        for match in re.finditer(
            r"(?<![\w$.])" + re.escape(alias) + r"\s*\(", source
        ):
            # The destructuring statement itself is not a call site.
            if line_of(source, match.start()) == bind_line:
                continue
            if is_code(source, cleaned, match) and depth_at(cleaned, match.start()) == 0:
                hits.add(line_of(source, match.start()))
    return sorted(hits)


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        deferrals = crate_deferrals()
    except UnparsedDeferral as error:
        print(f"deferred-reach: {error}", file=sys.stderr)
        return 2
    if not deferrals:
        print("deferred-reach: no declared deferrals found", file=sys.stderr)
        return 0

    sources = builtin_sources()
    findings = []
    for namespace, members in sorted(deferrals.items()):
        for member, reason in members:
            for identifier, source in sources.items():
                if f"internalBinding('{namespace}')" not in source:
                    continue
                cleaned = strip_comments_and_strings(source)
                lines = module_scope_calls(source, cleaned, namespace, member)
                if lines:
                    findings.append(
                        {
                            "namespace": namespace,
                            "member": member,
                            "reason": reason,
                            "module": identifier,
                            "lines": lines,
                        }
                    )

    if args.json:
        print(json.dumps(findings, indent=2))
        return 1 if findings else 0

    if not findings:
        total = sum(len(m) for m in deferrals.values())
        print(
            f"deferred-reach: {total} declared deferral(s) across "
            f"{len(deferrals)} namespace(s), none called at load time"
        )
        return 0

    print(
        "deferred-reach: these deferrals are called while their module loads, "
        "so the module cannot be required"
    )
    print("-" * 78)
    for finding in findings:
        locations = ", ".join(str(line) for line in finding["lines"])
        print(
            f"  {finding['namespace']}.{finding['member']}"
            f"  called in {finding['module']}.js:{locations}"
        )
        print(f"    declared reason: {finding['reason']}")
    print()
    print(
        f"{len(findings)} at-risk deferral(s). Either install the member or make "
        "the JavaScript layer's dependency lazy."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

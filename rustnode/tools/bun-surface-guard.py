#!/usr/bin/env python3
"""Differential guard over the `Bun` global's own property names.

`Bun` is one flat property space that six workers add to in parallel, which makes
it the one surface in this tree where a member can be added and silently not work.
No contract file covers it: `contracts/*.json` are `internalBinding()` namespaces
and `Bun` is a global. So this is the guard.

# What it compares, and the four ways it fails

Three sets, and the run is only meaningful if all three are real:

* **oracle** — `Object.getOwnPropertyNames(Bun)` on Bun 1.4.4, recorded into
  `tools/bun-surface.json` by `--record` or read from it by `--recorded`;
* **declarations** — what the contribution registry claims, from
  `rn-bun-check declarations`, i.e. from the same generated aggregator the runtime
  assembles;
* **installed** — `Object.getOwnPropertyNames(Bun)` on the built `rustnode`, from
  a probe that reads the shipping global after the real bootstrap.

Then:

1. **zero comparisons exits 2.** If the installed set is empty the probe found no
   `Bun` global at all, and if the oracle set is empty the fixture is missing or
   empty. Either way the run compared nothing, and a run that compared nothing is
   not a pass — this project has been burned repeatedly by checks that printed
   clean over an empty table. This is the same contract
   `tools/function-name-audit.py` uses, deliberately: one rule, two guards.
2. **declared but not installed fails.** The `namespace_structure` check applied
   to this surface: a crate lists `Bun.hash` in its `members()` and
   `install()` never sets it, so the registry promises a member the object does
   not have and only `undefined` reaches the caller.
3. **installed but not declared fails.** The opposite direction, and it is not
   hypothetical: it is what a worker produces by copying an install line and
   forgetting the declaration, and nothing else in this tree can see it — no
   contract covers `Bun`, and the member is present and callable, so every
   behavioural test passes.
4. **declared but absent from Bun 1.4.4 fails.** A fabricated member. It passes
   (2) and (3) — declared *and* installed — while shipping a name Bun does not
   have, which is the one thing that makes the surface not Bun-compatible.
   A deferral for a name Bun does not have fails the same way: it is a promise to
   implement something that does not exist.

Absent members are **reported, not failed**. Every Tier-1, Tier-2 and Tier-3
member this runtime does not implement is absent, and that is the intended state
while the surface is being filled in. The number is printed with a per-tier
breakdown so "116 absent" cannot be mistaken for "nothing to do": the tier-1 count
is the remaining work and it only goes down.

A deferred entry is counted separately from an absent one, because the two mean
different things: absent is "not started", deferred is "started, stopped, and here
is why". A deferral without a reason is refused by `BunRegistry` before this runs,
so a reasonless deferral cannot reach here; this checks the reasons are non-empty
anyway, because the file could be hand-edited.

# Why the inputs are JSON rather than only live runtimes

The four failure modes above are the guard's whole value, and a guard whose
blindness is untested is the defect it guards. So the comparison is a pure
function of three JSON documents — `--oracle-json`, `--declarations`,
`--installed` — and `tools/bun-surface-guard.test.sh` feeds it the defect shapes
directly, without a build and without trusting a mutation to survive. The default
inputs are the real ones; the overrides exist for the test.

Usage:
    tools/bun-surface-guard.py                      # oracle fixture + built rustnode + registry
    tools/bun-surface-guard.py --live               # enumerate Bun 1.4.4 instead of the fixture
    tools/bun-surface-guard.py --record             # write the fixture from Bun 1.4.4
    tools/bun-surface-guard.py --json               # machine-readable report
    tools/bun-surface-guard.py --oracle-json P --declarations P --installed P

Exit codes:
    0  every comparison is accounted for, and neither direction disagrees
    1  a member is declared-but-missing, installed-but-undeclared, or not in Bun
    2  zero comparisons: no `Bun` on the runtime under test, or an empty oracle
    3  an input could not be read or run
"""

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ORACLE = "/tmp/bun-dl/bun-linux-x64/bun"
DEFAULT_FIXTURE = os.path.join(ROOT, "tools", "bun-surface.json")
DEFAULT_RUSTNODE = os.path.join(ROOT, "target", "debug", "rustnode")

# The probe. Identical text under both runtimes, so the comparison is of the
# globals rather than of what a script asked differently.
#
# `getOwnPropertyNames` and not `Object.keys`: five of Bun's own members are
# non-enumerable (`cwd`, `jest`, `origin`, `version_with_sha`, `registerMacro`), so
# a `keys`-based probe would agree with itself on a runtime that dropped them. That
# is the same index-versus-name blindness the naming audits exist to avoid.
PROBE = r"""
const bun = globalThis.Bun;
if (bun === undefined || bun === null) {
  process.stdout.write(JSON.stringify({ present: false, members: [] }));
} else {
  process.stdout.write(JSON.stringify({
    present: true,
    members: Object.getOwnPropertyNames(bun).sort(),
    // `typeof` per member, so a member installed as the wrong kind is visible.
    // Bun itself is not uniform here — `version` is a string, `env` an object,
    // most are functions — so the kinds are recorded rather than assumed.
    kinds: Object.fromEntries(
      Object.getOwnPropertyNames(bun).sort().map((n) => [n, typeof bun[n]])),
  }));
}
"""


def clean_environment():
    environment = dict(os.environ)
    environment.pop("CARGO_TARGET_DIR", None)
    return environment


def run_probe(runtime, what):
    """Runs the probe under `runtime` and returns its parsed JSON.

    `-e` under both runtimes: Bun compiles it as a script, and rustnode's `-e`
    path runs the real bootstrap (`realm.js`, `install_early_globals`,
    `prepare_execution`), so the `Bun` global this reads is the shipping one rather
    than one installed by a special test mode. A dedicated CLI flag would be a
    second installation path, which is exactly the kind of divergence this guard is
    supposed to notice.

    An unreadable input is exit 3 and not a surface verdict: "the guard could not
    measure" has to be distinguishable from "the surface disagrees", or a missing
    binary reads as a defect in a member.
    """
    try:
        completed = subprocess.run(
            [runtime, "-e", PROBE],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=ROOT,
            env=clean_environment(),
        )
    except FileNotFoundError:
        raise InputError(
            f"{what}: {runtime} does not exist\n"
            f"bun-surface-guard: build it, or point --oracle at a Bun binary"
        ) from None
    if completed.returncode != 0:
        raise InputError(
            f"{what}: the probe under {runtime} exited {completed.returncode}: "
            f"{completed.stderr.strip()[-800:]}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise InputError(
            f"{what}: the probe under {runtime} did not print JSON ({error}): "
            f"{completed.stdout[:400]!r}"
        ) from None


class InputError(Exception):
    """An input the guard could not read. Exits 3, never 1.

    The distinction is load-bearing: the guard's exit 1 means "the surface
    disagrees", and a missing binary, an unreadable fixture or a runtime whose
    probe threw must not be reported as a defect in a member. `rn-compat` and
    `function-name-audit.py` both separate these, for the same reason.
    """


def declarations_from_registry():
    """The registry's own view, through the binary compiled from it."""
    completed = subprocess.run(
        ["cargo", "run", "-q", "-p", "rn-bun-check", "--", "declarations"],
        capture_output=True,
        text=True,
        timeout=900,
        cwd=ROOT,
        env=clean_environment(),
    )
    if completed.returncode != 0:
        raise InputError(
            f"rn-bun-check declarations failed ({completed.returncode}): "
            f"{completed.stderr.strip()[-800:]}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise InputError(f"rn-bun-check declarations did not print JSON: {error}")


def record(runtime, path):
    """Writes the oracle's members and kinds as the fixture."""
    oracle = run_probe(runtime, "record")
    if not oracle["present"]:
        raise InputError(f"record: {runtime} has no Bun global to record")
    members = oracle["members"]
    if not members:
        raise InputError(f"record: {runtime} reports an empty Bun global")
    version = subprocess.run(
        [runtime, "--version"], capture_output=True, text=True, timeout=120
    ).stdout.strip()
    # The tier is not something the oracle can report; it comes from
    # `docs/bun-compat-plan.md`, so it is recorded here as the plan's classification
    # and printed so a reader can see which absences are the intended work. An
    # unknown member is tier 0 ("in Bun, not classified") and is never silently
    # treated as out of scope.
    tiers = TIER_OF.copy()
    fixture = {
        "version": version,
        "recorded_from": runtime,
        "members": {
            name: {"tier": tiers.get(name, 0), "kind": oracle["kinds"].get(name)}
            for name in members
        },
    }
    with open(path, "w", encoding="utf8") as handle:
        json.dump(fixture, handle, indent=2, sort_keys=True)
        handle.write("\n")
    by_tier = {}
    for entry in fixture["members"].values():
        by_tier[entry["tier"]] = by_tier.get(entry["tier"], 0) + 1
    print(
        f"recorded {len(members)} Bun member(s) from {runtime} ({version}) into {path}; "
        f"by tier: {dict(sorted(by_tier.items()))}"
    )
    return 0


# `docs/bun-compat-plan.md`'s classification, transcribed. Kept here rather than
# parsed out of the document so a reworded plan cannot silently empty the table;
# `tools/bun-surface-guard.test.sh` checks it covers every member the fixture
# records, in one direction only (a plan entry for a member Bun no longer has is
# reported by the guard's absent-from-Bun arm, not here).
TIER_OF = {
    # Tier 1 — encoding and parsing.
    **{name: 1 for name in (
        "YAML", "TOML", "JSON5", "JSONC", "JSONL", "XML", "markdown",
    )},
    # Tier 1 — hashing.
    **{name: 1 for name in (
        "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA512_256",
        "MD4", "MD5", "hash", "CryptoHasher", "sha",
    )},
    # Tier 1 — compression.
    **{name: 1 for name in (
        "gzipSync", "gunzipSync", "deflateSync", "inflateSync",
        "zstdCompressSync", "zstdDecompressSync", "zstdCompress", "zstdDecompress",
    )},
    # Tier 1 — files and paths.
    **{name: 1 for name in (
        "file", "write", "mmap", "Glob", "FileSystemRouter", "which", "resolve",
        "resolveSync", "fileURLToPath", "pathToFileURL",
    )},
    # Tier 1 — text and misc.
    **{name: 1 for name in (
        "stripANSI", "wrapAnsi", "sliceAnsi", "stringWidth", "escapeHTML",
        "deepEquals", "deepMatch", "semver", "randomUUIDv5", "randomUUIDv7",
        "nanoseconds", "sleep", "sleepSync", "inspect", "concatArrayBuffers",
        "allocUnsafe", "indexOfLine", "readableStreamToArray",
        "readableStreamToArrayBuffer", "readableStreamToBlob",
        "readableStreamToBytes", "readableStreamToFormData",
        "readableStreamToJSON", "readableStreamToText", "ArrayBufferSink",
        "shrink", "version", "revision", "version_with_sha", "argv", "env",
        "main", "origin", "cwd", "isMainThread", "enableANSIColors", "color",
        "generateHeapSnapshot", "gc",
    )},
    # Tier 1 — process and system.
    **{name: 1 for name in ("spawn", "spawnSync", "udpSocket")},
    # Tier 2 — each its own project.
    **{name: 2 for name in (
        "serve", "fetch", "SQL", "sql", "postgres", "redis", "s3", "RedisClient",
        "S3Client", "cron", "Transpiler", "Terminal", "CSRF", "CookieMap",
        "Cookie", "FetchSession", "Archive", "ModuleGraph", "embeddedFiles",
        "secrets", "password", "listen", "connect", "dns", "peek",
        "openInEditor", "unsafe", "stdin", "stdout", "stderr",
        "isStandaloneExecutable",
    )},
    # Tier 3 — out of scope.
    **{name: 3 for name in (
        "FFI", "Image", "WebView", "jest", "build", "plugin", "registerMacro", "$",
    )},
}


def load_json(path, what):
    try:
        with open(path, encoding="utf8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise InputError(f"{what}: {path} does not exist") from None
    except json.JSONDecodeError as error:
        raise InputError(f"{what}: {path} is not JSON: {error}") from None


def compare(oracle, declared, deferred, installed):
    """The rows, the counts, and every accounting bucket.

    `oracle` is `{member: {"tier": n, ...}}`, `declared` maps member to the crate
    that declared it, `deferred` likewise with a reason, and `installed` is the set
    of own property names on the shipping `Bun`.

    Returns `(failures, counts, buckets)`.

    # The partition

    Every **oracle** member lands in exactly one of four buckets, and the caller
    asserts the sum closes. Getting this wrong is not cosmetic: the first version
    of this function counted a declared-but-uninstalled member as `contradicted`
    and left it out of `implemented + absent + deferred`, so the sum came up short
    and the guard exited 2 on an input whose real answer was 1. The test that
    caught it is `tools/bun-surface-guard.test.sh`'s "declared but not installed"
    case, which is the reason that case exists.

    * **implemented** — declared, installed, and Bun has it;
    * **contradicted** — declared, and either not installed or not in Bun. This is
      a failure, and it is counted here so it cannot vanish from the sum;
    * **deferred** — declared as a deferral, with a reason, and Bun has it;
    * **absent** — Bun has it and no crate mentions it.

    A member a crate declares that Bun has never heard of is *not* an oracle
    member, so it cannot join the partition; it belongs to the declared side's
    own count and is reported as a failure by name. That asymmetry is deliberate:
    the oracle is the denominator, and a fabricated name must not inflate it.
    """
    failures = []
    implemented = []
    absent = []
    contradicted = []
    deferred_ok = []
    # Declared names Bun does not have. Separate from `contradicted` because they
    # are not in the oracle's denominator; they are listed so the report can say
    # which names were fabricated rather than only counting failures.
    fabricated = []

    # (2) declared but not installed, and (4) declared but not in Bun.
    for member, contributor in sorted(declared.items()):
        if member not in installed:
            failures.append(
                f"{contributor} declares Bun.{member} but the installed Bun object "
                f"does not have it; the registry promises a member that reads "
                f"`undefined`"
            )
            contradicted.append(member)
            continue
        if oracle and member not in oracle:
            failures.append(
                f"{contributor} declares Bun.{member}, which Bun 1.4.4 does not "
                f"expose; this runtime would ship a member Bun does not have"
            )
            fabricated.append(member)
            continue
        implemented.append(member)

    # (3) installed but not declared.
    for member in sorted(installed - set(declared) - set(deferred)):
        failures.append(
            f"Bun.{member} is installed but no contribution crate declares it; add "
            f"it to that crate's members() so the contract and this gate can see it"
        )

    # (4) again, for deferrals: a promise to implement something Bun has no.
    for member, entry in sorted(deferred.items()):
        reasonless = not entry["reason"].strip()
        if oracle and member not in oracle:
            failures.append(
                f"{entry['contributor']} defers Bun.{member}, which Bun 1.4.4 does "
                f"not expose; there is nothing to defer"
            )
            fabricated.append(member)
        else:
            deferred_ok.append(member)
        if reasonless:
            failures.append(
                f"{entry['contributor']} defers Bun.{member} with no reason; a "
                f"deferral has to say why"
            )

    # Absent: in Bun, and the registry says nothing about it.
    for member, entry in sorted(oracle.items()):
        if member in declared or member in deferred:
            continue
        absent.append({"member": member, "tier": entry.get("tier", 0)})

    counts = {
        "oracle": len(oracle),
        "implemented": len(implemented),
        "absent": len(absent),
        "deferred": len(deferred_ok),
        "contradicted": len(contradicted),
        "fabricated": len(fabricated),
        "installed": len(installed),
        "declared": len(declared),
    }
    buckets = {
        "implemented": implemented,
        "absent": absent,
        "contradicted": contradicted,
        "fabricated": fabricated,
        "deferred": deferred_ok,
    }
    return failures, counts, buckets


def report(result, as_json):
    failures, counts, buckets = result
    if as_json:
        json.dump(
            {"failures": failures, "counts": counts, "buckets": buckets},
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        print()
    else:
        by_tier = {}
        for entry in buckets["absent"]:
            by_tier[entry["tier"]] = by_tier.get(entry["tier"], 0) + 1
        tier_text = ", ".join(
            f"tier {tier}: {count}" for tier, count in sorted(by_tier.items())
        )
        print(
            f"Bun surface: {counts['implemented']} implemented, "
            f"{counts['absent']} absent, {counts['deferred']} declared-deferred, "
            f"{counts['contradicted']} declared-but-missing, "
            f"{counts['fabricated']} not-in-Bun of {counts['oracle']} in Bun 1.4.4"
        )
        print(f"  absent by tier: {tier_text or 'none'}")
        print(
            f"  registry: {counts['declared']} declared member(s), "
            f"{counts['installed']} installed on the object"
        )
        for member in buckets["implemented"]:
            print(f"  implemented  Bun.{member}")
        for member in buckets["contradicted"]:
            print(f"  declared-missing  Bun.{member}")
        for member in buckets["fabricated"]:
            print(f"  not-in-Bun        Bun.{member}")
        for member in buckets["deferred"]:
            print(f"  deferred     Bun.{member}")
        for failure in failures:
            print(f"  BAD  {failure}")
        if failures:
            print()
    if failures:
        print(f"{len(failures)} Bun surface defect(s)", file=sys.stderr)
        return 1
    return 0


def deferrals_of(report):
    return {
        entry["member"]: {
            "contributor": entry["contributor"],
            "reason": entry["reason"],
        }
        for entry in report.get("deferred", [])
    }


def declarations_of(report):
    return {entry["member"]: entry["contributor"] for entry in report.get("members", [])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", default=DEFAULT_ORACLE, help="a Bun binary to enumerate")
    parser.add_argument("--rustnode", default=DEFAULT_RUSTNODE, help="the built runtime")
    parser.add_argument("--fixture", default=DEFAULT_FIXTURE, help="the recorded Bun surface")
    parser.add_argument("--record", action="store_true", help="write the fixture and exit")
    parser.add_argument(
        "--live",
        action="store_true",
        help="enumerate --oracle instead of reading the fixture",
    )
    parser.add_argument("--oracle-json", help="an oracle document instead of enumerating")
    parser.add_argument("--declarations", help="a declarations document instead of the registry")
    parser.add_argument("--installed", help="an installed document instead of probing the runtime")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.record:
        return record(args.oracle, args.fixture)

    # ---- the oracle -----------------------------------------------------------
    if args.oracle_json:
        document = load_json(args.oracle_json, "oracle")
    elif args.live:
        probe = run_probe(args.oracle, "oracle")
        document = {
            "members": {name: {"tier": TIER_OF.get(name, 0)} for name in probe["members"]}
        }
    else:
        document = load_json(args.fixture, "fixture")
    oracle = document.get("members", {})
    if not isinstance(oracle, dict):
        print(
            "oracle: `members` must be an object keyed by member name, so the tier "
            "table travels with each name",
            file=sys.stderr,
        )
        return 3

    # ---- the declarations -----------------------------------------------------
    if args.declarations:
        declaration_document = load_json(args.declarations, "declarations")
    else:
        declaration_document = declarations_from_registry()
    declared = declarations_of(declaration_document)
    deferred = deferrals_of(declaration_document)

    # ---- the installed object -------------------------------------------------
    installed_empty_reason = None
    if args.installed:
        installed_document = load_json(args.installed, "installed")
        if isinstance(installed_document, list):
            installed = set(installed_document)
        else:
            installed = set(installed_document.get("members", []))
            if not installed_document.get("present", True):
                installed_empty_reason = (
                    "the installed document reports no Bun global at all"
                )
    else:
        probe = run_probe(args.rustnode, "installed")
        installed = set(probe.get("members", []))
        if not probe.get("present"):
            installed_empty_reason = (
                "the runtime at {path} has no Bun global".format(path=args.rustnode)
            )

    # Zero comparisons short-circuit before the arithmetic below, because the two
    # mean different things and the more specific answer is the useful one. A run
    # with no oracle members or no installed members compared nothing whatever the
    # buckets say; reporting "the sum does not close" would describe the symptom
    # and hide the cause.
    if not installed:
        print(
            "the guard compared zero installed members, which cannot be a pass: "
            f"{installed_empty_reason or 'the installed set is empty'}, so nothing "
            "was compared",
            file=sys.stderr,
        )
        return 2
    if not oracle:
        print(
            "the guard compared zero oracle members, which cannot be a pass: the "
            "fixture or the Bun binary is empty or unreadable",
            file=sys.stderr,
        )
        return 2

    result = compare(oracle, declared, deferred, installed)

    # The arithmetic has to close over the oracle: every member Bun has is
    # implemented, contradicted or deferred by a crate, or absent. A row that is
    # none of those means the classifier missed a shape, and its clean-looking
    # totals are about a measurement it did not make.
    counts = result[1]
    closed = (
        counts["implemented"]
        + counts["absent"]
        + counts["deferred"]
        + counts["contradicted"]
    )
    # `fabricated` names are deliberately outside the oracle's denominator, so
    # they do not join this sum; a fabricated name that is also in the oracle is
    # impossible, because that is the condition that makes it fabricated.
    if closed != counts["oracle"]:
        print(
            f"the guard accounted for {closed} member(s) but the oracle records "
            f"{counts['oracle']}: a member is neither implemented, nor deferred, nor "
            f"absent, nor contradicted",
            file=sys.stderr,
        )
        return 2

    return report(result, args.json)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except InputError as error:
        print(error, file=sys.stderr)
        sys.exit(3)

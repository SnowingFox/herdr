#!/usr/bin/env python3
"""Generates `src/root_certs.rs` from the NSS `certdata.txt` Node pins.

This is the port of `tools/mk-ca-bundle.pl` that `node_root_certs.h` is produced
with. Node does not use `tools/certdata2gyp.py` or anything in
`deps/npm/node_modules` for this: `tools/dep_updaters/update-root-certs.mjs`
fetches `certdata.txt` from the NSS release tag and then runs
`tools/mk-ca-bundle.pl`, whose default output path is `../src/node_root_certs.h`
relative to `tools/`. That Perl script is the whole generator, and
`src/crypto/crypto_context.cc` includes the header it writes and reads the C
array `root_certs` back out of it.

    nodejs/node @ f344e7f552e3656bd37517151c5dc87d22b33771
      tools/certdata.txt          input, the Mozilla trust store
      tools/mk-ca-bundle.pl       generator
      src/node_root_certs.h       output, committed upstream
      node.gyp:306                lists the header as a source file
      src/crypto/crypto_context.cc:79  includes it

Usage
-----
    tools/gen-root-certs.py            # regenerate src/root_certs.rs
    tools/gen-root-certs.py --check    # exit 1 when the committed file is stale

The input is `vendor/certdata/certdata.txt`, committed so regeneration needs no
network and a normal build needs neither. Its SHA-256 and the pin it came from
are embedded in the generated file, so a trust-store change under the same file
name is a test failure rather than a new set of roots.

What is selected
----------------
`mk-ca-bundle.pl` includes a certificate when any of its trust purposes appears
under an included trust level, and skips it when its name matches `TrustCor` or
when it is already expired. The defaults with no arguments are
`SERVER_AUTH:TRUSTED_DELEGATOR`, which is what Node runs, so those are the two
sets below. Every other `CKA_TRUST_*` line (email, code signing, time stamping)
does not select a root.

Expiry is the one part that is not a pure function of the input: the Perl script
compares `# Not Valid After` against *now*, so re-running it on a later date can
drop a root that Node's committed header still contains. A generator that did
the same would not be reproducible, so the comparison is against
`--expiry-cutoff`, defaulting to `NODE_COMMIT_DATE`: the day the pinned Node
revision was cut. Regenerating on any later date therefore reproduces Node's
set rather than today's, and moving the pin is what moves the cutoff.

The output is written already rustfmt-formatted, including the comment column
rustfmt aligns, because `./tools/check.sh` runs both `gen-root-certs.py --check`
and `cargo fmt --check`. Emitting unformatted text would make those two disagree
about the same file, and running `cargo fmt` to fix it would make the
regeneration check fail instead. Both are verified after regenerating.
"""

import argparse
import base64
import datetime
import hashlib
import os
import re
import sys

CRATE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(os.path.dirname(CRATE))
OUT = os.path.join(CRATE, "src", "root_certs.rs")
CERTDATA = os.path.join(ROOT, "vendor", "certdata", "certdata.txt")

NODE_COMMIT = "f344e7f552e3656bd37517151c5dc87d22b33771"
NODE_COMMIT_DATE = datetime.datetime(2026, 11, 9, 6, 49, 29)
NODE_VERSION = "28.0.0"

# `$default_mozilla_trust_purposes` and `$default_mozilla_trust_levels`, i.e.
# the `-p` default `SERVER_AUTH:TRUSTED_DELEGATOR`.
INCLUDED_PURPOSES = {"SERVER_AUTH"}
INCLUDED_LEVELS = {"TRUSTED_DELEGATOR"}

# `mk-ca-bundle.pl` skips a root issued by TrustCor by name even when its trust
# bits say otherwise.
EXCLUDED_NAME = re.compile(r"TrustCor")

# `$opt_w = 72`, the base64 wrap width that decides where a PEM line breaks.
PEM_WIDTH = 72

# The width the emitted Rust string literals are wrapped to, one PEM line per
# literal. 72 base64 characters plus the newline fits inside it.
LITERAL_WIDTH = 76


def parse_certdata(text, cutoff):
    """Yields `(name, der, skip_reason)` per certificate block, in file order."""
    main_block = False
    trust_block = False
    main_name = ""
    name = ""
    value = b""
    start_of_cert = False
    not_after = None
    purposes = {}

    def flush():
        if not main_name:
            return None
        if not_after is None:
            return (main_name, b"", "no Not Valid After")
        if not_after < cutoff:
            return (main_name, b"", "not valid anymore")
        if not start_of_cert or not name or not value:
            return (main_name, b"", "certificate extraction failed")
        if EXCLUDED_NAME.search(name):
            return (name, b"", "excluded by name")
        if not any(
            purpose in INCLUDED_PURPOSES
            for purpose_list in purposes.values()
            for purpose in purpose_list
            if True
        ):
            return (name, b"", "lacks acceptable trust level")
        return (name, value, None)

    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1

        if line.startswith("***** BEGIN LICENSE BLOCK *****"):
            while index < len(lines):
                if lines[index].startswith("***** END LICENSE BLOCK *****"):
                    index += 1
                    break
                index += 1
            continue

        if line.strip() == "":
            main_block = False
            trust_block = False
            continue

        match = re.match(r'^# Certificate "(.*)"', line)
        if match:
            pending = flush()
            if pending is not None:
                yield pending
            main_block = True
            trust_block = False
            main_name = match.group(1)
            name = ""
            value = b""
            start_of_cert = False
            not_after = None
            purposes = {}
            continue

        match = re.match(r'^# Trust for (?:Certificate )?"(.*)"', line)
        if match:
            trust_block = True
            continue

        if not main_block and not trust_block:
            continue

        if line.startswith("#"):
            if main_block:
                match = re.match(r"^# Not Valid After : (.*)$", line)
                if match:
                    not_after = datetime.datetime.strptime(
                        match.group(1).strip(), "%a %b %d %H:%M:%S %Y"
                    )
            continue

        if main_block:
            if line.startswith("CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE"):
                start_of_cert = True
                continue
            if not start_of_cert:
                continue
            match = re.match(r'^CKA_LABEL UTF8 "(.*)"', line)
            if match:
                name = match.group(1)
                continue
            if line.startswith("CKA_VALUE MULTILINE_OCTAL"):
                chunks = []
                while index < len(lines):
                    chunk = lines[index]
                    index += 1
                    if chunk.startswith("END"):
                        break
                    for octal in chunk.split("\\")[1:]:
                        chunks.append(int(octal, 8) & 0xFF)
                value = bytes(chunks)
                continue
            continue

        match = re.match(
            r"^CKA_TRUST_([A-Z_]+)\s+CK_TRUST\s+CKT_NSS_([A-Z_]+)\s*$", line
        )
        if match:
            level, purpose = match.group(2), match.group(1)
            if level in INCLUDED_LEVELS:
                purposes.setdefault(level, []).append(purpose)
        continue

    pending = flush()
    if pending is not None:
        yield pending


def to_pem(der):
    """The PEM string exactly as `mk-ca-bundle.pl` emits it.

    No trailing newline after the END line: the Perl script appends one to each
    base64 chunk only, which is what makes the two byte-identical.
    """
    body = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(
        body[start : start + PEM_WIDTH] for start in range(0, len(body), PEM_WIDTH)
    )
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----"


def rust_literal(text):
    """A Rust string literal for `text`."""
    escaped = (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def render(certdata_bytes, selected, skipped):
    digest = hashlib.sha256(certdata_bytes).hexdigest()
    lines = []
    add = lines.append

    add("//! The bundled root certificates, generated from NSS `certdata.txt`.")
    add("//!")
    add("//! Generated by `crates/rn-bind-crypto-x509/tools/gen-root-certs.py`.")
    add("//! Do not edit by hand; edit the generator or re-run it.")
    add("//!")
    add("//! This is the blob `tls.rootCertificates` and")
    add("//! `tls.getCACertificates('bundled')` report. Node calls the same thing")
    add("//! `src/node_root_certs.h`; the strings below are the same bytes in the")
    add("//! same order, produced from the same trust store by a port of the same")
    add("//! generator.")
    add("//!")
    add("//! Reportable and consulted. `SecureContext#addRootCerts` installs these")
    add("//! by default, the way Node's `NewRootCertStore` does, and adds the system")
    add("//! store on top only under `--use-system-ca`. `--use-openssl-ca` replaces")
    add("//! them with the OS store, which is that flag's documented meaning.")
    add("//!")
    add("//! # Provenance")
    add("//!")
    add(f"//! * Node revision: `{NODE_COMMIT}` (reports itself as {NODE_VERSION})")
    add("//! * input: `vendor/certdata/certdata.txt`, which is `tools/certdata.txt`")
    add("//!   from that revision")
    add(f"//! * input SHA-256: `{digest}`")
    add("//! * upstream generator: `tools/mk-ca-bundle.pl` at that revision, run")
    add("//!   with no arguments, so `SERVER_AUTH:TRUSTED_DELEGATOR`")
    add("//! * upstream output: `src/node_root_certs.h` at that revision")
    add("//!")
    add("//! The input is committed rather than fetched so that a build is offline")
    add("//! and a regeneration is reproducible. [`CERTDATA_SHA256`] is the pin: the")
    add("//! generator's `--check` mode compares it, and a unit test in")
    add("//! `root_store.rs` re-hashes the file on disk, so a trust store that")
    add("//! changed under the blob name is visible instead of silently replacing")
    add("//! the roots.")
    add("")
    add("/// SHA-256 of `vendor/certdata/certdata.txt`, the input this was made from.")
    add("pub const CERTDATA_SHA256: &str =")
    add(f'    "{digest}";')
    add("")
    add("/// The Node revision the input and the generator came from.")
    add(f'pub const NODE_REVISION: &str = "{NODE_COMMIT}";')
    add("")
    add("/// How many certificates `mk-ca-bundle.pl` processed.")
    add("///")
    add("/// Asserted against [`BUNDLED_ROOTS`] by a test here, so a generator")
    add("/// change that silently drops or adds a root fails rather than shipping.")
    add(f"pub const ROOT_CERT_COUNT: usize = {len(selected)};")
    add("")
    add("/// How many certificate blocks the input held and this did not select.")
    add("///")
    add("/// A number rather than a list because the reason an absent root is")
    add("/// absent is the useful fact when someone asks why `tls.rootCertificates`")
    add("/// is short of the Mozilla store: most of these are email and")
    add("/// code-signing roots whose trust bits do not include `SERVER_AUTH`, and")
    add("/// Node does not ship those either.")
    add(f"pub const SKIPPED_CERT_COUNT: usize = {len(skipped)};")
    add("")
    add("/// `root_certs` from `src/node_root_certs.h`: the bundled trust anchors.")
    add("///")
    add("/// PEM rather than DER, because that is what the root-store accessors")
    add("/// return and re-encoding 118 certificates on every call would be work")
    add("/// with no observable difference. Order is Node's order, which is the")
    add("/// input file's order.")
    add("///")
    add("/// The comment on each entry is the `/* ... */` name Node's generator")
    add("/// writes above that certificate, in that order.")
    add("pub const BUNDLED_ROOTS: &[&str] = &[")
    # Trailing comments keep one entry per line, which rustfmt preserves, but it
    # aligns them to a common column. Emitting that column here is what makes the
    # generated file already formatted, so `cargo fmt --check` in the gate does
    # not report it and the regeneration has nothing to tidy.
    entries = [f"    ROOT_{position}," for position in range(len(selected))]
    column = max(len(entry) for entry in entries) + 1
    for position, (name, _) in enumerate(selected):
        padding = " " * (column - len(entries[position]))
        add(f"{entries[position]}{padding}// {name}")
    add("];")
    add("")

    for position, (name, pem) in enumerate(selected):
        add(f"/// {name}")
        add(f"const ROOT_{position}: &str = concat!(")
        pieces = pem.split("\n")
        for index, piece in enumerate(pieces):
            suffix = "\n" if index + 1 < len(pieces) else ""
            add(f"    {rust_literal(piece + suffix)},")
        add(");")
        add("")

    add("#[cfg(test)]")
    add("mod tests {")
    add("    use super::*;")
    add("")
    add("    #[test]")
    add("    fn the_declared_count_is_the_real_count() {")
    add("        assert_eq!(BUNDLED_ROOTS.len(), ROOT_CERT_COUNT);")
    add("    }")
    add("")
    add("    #[test]")
    add("    fn every_root_is_one_pem_certificate_with_no_trailing_newline() {")
    add("        // These strings go to JavaScript unchanged, and")
    add("        // `tls.rootCertificates` is compared to Node's by content, so a")
    add("        // trailing newline would be a difference even though every")
    add("        // certificate still parsed.")
    add("        for (position, pem) in BUNDLED_ROOTS.iter().enumerate() {")
    add('            assert!(')
    add('                pem.starts_with("-----BEGIN CERTIFICATE-----\\n"),')
    add('                "root {position} does not open with a PEM header"')
    add("            );")
    add("            assert!(")
    add('                pem.ends_with("-----END CERTIFICATE-----"),')
    add('                "root {position} does not end with a PEM footer"')
    add("            );")
    add("            assert_eq!(")
    add('                pem.matches("-----BEGIN CERTIFICATE-----").count(),')
    add("                1,")
    add('                "root {position} holds more than one certificate"')
    add("            );")
    add("        }")
    add("    }")
    add("")
    add("    #[test]")
    add("    fn the_roots_are_distinct() {")
    add("        let mut distinct: Vec<&str> = BUNDLED_ROOTS.to_vec();")
    add("        distinct.sort_unstable();")
    add("        distinct.dedup();")
    add("        assert_eq!(distinct.len(), BUNDLED_ROOTS.len(), \"a root repeats\");")
    add("    }")
    add("}")
    add("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate the bundled root certificate module."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate into memory and fail when the committed file differs",
    )
    parser.add_argument(
        "--expiry-cutoff",
        default=None,
        help=(
            "the date '# Not Valid After' is compared against, ISO 8601; "
            "defaults to the pinned Node revision's date"
        ),
    )
    arguments = parser.parse_args()

    cutoff = NODE_COMMIT_DATE
    if arguments.expiry_cutoff is not None:
        cutoff = datetime.datetime.fromisoformat(arguments.expiry_cutoff)

    with open(CERTDATA, "rb") as handle:
        certdata_bytes = handle.read()
    text = certdata_bytes.decode("utf-8", errors="surrogateescape")

    selected = []
    skipped = []
    for name, der, reason in parse_certdata(text, cutoff):
        if reason is None:
            selected.append((name, to_pem(der)))
        else:
            skipped.append((name, reason))

    encoded = render(certdata_bytes, selected, skipped).encode("utf-8")

    if arguments.check:
        try:
            with open(OUT, "rb") as handle:
                committed = handle.read()
        except FileNotFoundError:
            print(f"{OUT} does not exist; run the generator", file=sys.stderr)
            return 1
        if committed != encoded:
            print(
                f"{OUT} is stale: the generator produces {len(selected)} roots and "
                "the committed file differs",
                file=sys.stderr,
            )
            return 1
        print(
            f"{os.path.relpath(OUT, ROOT)} matches "
            f"{os.path.relpath(CERTDATA, ROOT)} "
            f"({len(selected)} roots, {len(skipped)} skipped)"
        )
        return 0

    with open(OUT, "wb") as handle:
        handle.write(encoded)
    print(
        f"wrote {os.path.relpath(OUT, ROOT)} ({len(selected)} roots, "
        f"{len(skipped)} skipped, {len(encoded)} bytes)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

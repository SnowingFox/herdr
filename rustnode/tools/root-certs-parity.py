#!/usr/bin/env python3
"""Compares the bundled root certificates against a real Node's, certificate by
certificate.

A count is not proof. Two trust stores can hold 118 certificates and share none
of them, and a single swapped root would leave the count intact while silently
changing what the runtime trusts. This reads both lists through each runtime's
own `tls` module, then compares the sorted `(subject, SPKI SHA-256)` pairs.

Subjects are compared as the DER of the X.509 `Name`, and the SPKI as the DER of
`SubjectPublicKeyInfo`, both extracted structurally rather than by string
formatting: OpenSSL and Node spell a DN differently (attribute order inside a
multi-valued RDN, whitespace, escaping), so a text comparison would report false
differences and, worse, could hide a real one inside a formatting change.

Usage
-----
    tools/root-certs-parity.py --node /path/to/node
    tools/root-certs-parity.py --node /path/to/node --rustnode target/debug/rustnode

`--ca bundled` compares `tls.getCACertificates('bundled')` instead of
`tls.rootCertificates`. Node returns the same 118 strings from both; comparing
both is what proves the accessor and the property are wired to one list.

Exit codes
----------
0  the two lists are identical certificate by certificate
1  they differ; every difference is printed
2  a runtime could not be run, so there is no verdict
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys


def run(runtime, expression):
    """The JSON value of `expression` evaluated by `runtime`."""
    result = subprocess.run(
        [runtime, "-e", f"process.stdout.write(JSON.stringify({expression}))"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{runtime} exited {result.returncode} on {expression}:\n{result.stderr.strip()}"
        )
    return json.loads(result.stdout)


def der_of(pem):
    match = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S
    )
    if match is None:
        raise ValueError(f"not a PEM certificate: {pem[:40]!r}")
    return base64.b64decode("".join(match.group(1).split()))


def tlv(buffer, offset):
    """`(tag, value_offset, length)` for the element starting at `offset`."""
    tag = buffer[offset]
    offset += 1
    length = buffer[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(buffer[offset : offset + count], "big")
        offset += count
    return tag, offset, length


def subject_and_spki(der):
    """The DER of the certificate's subject `Name` and `SubjectPublicKeyInfo`."""
    _, offset, _ = tlv(der, 0)  # Certificate SEQUENCE
    _, offset, length = tlv(der, offset)  # tbsCertificate SEQUENCE
    end = offset + length

    tag, value, length = tlv(der, offset)
    if tag == 0xA0:  # explicit [0] version
        offset = value + length
        tag, value, length = tlv(der, offset)
    offset = value + length  # past serialNumber
    _, value, length = tlv(der, offset)  # signature AlgorithmIdentifier
    offset = value + length
    _, value, length = tlv(der, offset)  # issuer Name
    offset = value + length
    _, value, length = tlv(der, offset)  # validity
    offset = value + length
    subject_start = offset
    _, value, length = tlv(der, offset)  # subject Name
    subject = der[subject_start : value + length]
    offset = value + length
    spki_start = offset
    _, value, length = tlv(der, offset)  # subjectPublicKeyInfo
    spki = der[spki_start : value + length]
    if value + length > end:
        raise ValueError("subjectPublicKeyInfo overran tbsCertificate")
    return subject, spki


def summarize(certificates):
    """`(subject sha256, spki sha256, subject der, spki der)` per certificate."""
    rows = []
    for pem in certificates:
        subject, spki = subject_and_spki(der_of(pem))
        rows.append(
            (
                hashlib.sha256(subject).hexdigest(),
                hashlib.sha256(spki).hexdigest(),
                subject,
                spki,
            )
        )
    return rows


def common_name(subject_der):
    """The subject's CN, best effort, only to name a difference in the report."""
    # AttributeTypeAndValue has OID 2.5.4.3 (commonName) then a value; the OID's
    # DER is 06 03 55 04 03. The following value is printed as text.
    marker = b"\x06\x03\x55\x04\x03"
    position = subject_der.find(marker)
    if position < 0:
        return "<no CN>"
    _, value, length = tlv(subject_der, position + len(marker))
    return subject_der[value : value + length].decode("utf-8", "replace")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--node", required=True, help="a real Node binary")
    parser.add_argument(
        "--rustnode",
        default="target/debug/rustnode",
        help="the rustnode binary (default: target/debug/rustnode)",
    )
    parser.add_argument(
        "--ca",
        default=None,
        help="compare tls.getCACertificates(<type>) instead of tls.rootCertificates",
    )
    arguments = parser.parse_args()

    expression = (
        "require('tls').rootCertificates"
        if arguments.ca is None
        else f"require('tls').getCACertificates({json.dumps(arguments.ca)})"
    )

    for runtime in (arguments.node, arguments.rustnode):
        if not os.path.exists(runtime):
            print(f"no binary at {runtime}", file=sys.stderr)
            return 2

    try:
        node_certificates = run(arguments.node, expression)
        rustnode_certificates = run(arguments.rustnode, expression)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"ABORT: {error}", file=sys.stderr)
        return 2

    node_version = run(arguments.node, "process.version")
    rustnode_version = run(arguments.rustnode, "process.version")

    node_rows = summarize(node_certificates)
    rustnode_rows = summarize(rustnode_certificates)

    print(f"{expression}")
    print(f"  node     {node_version}: {len(node_rows)} certificates")
    print(f"  rustnode {rustnode_version}: {len(rustnode_rows)} certificates")

    node_pairs = sorted((row[0], row[1]) for row in node_rows)
    rustnode_pairs = sorted((row[0], row[1]) for row in rustnode_rows)

    only_node = [pair for pair in node_pairs if pair not in rustnode_pairs]
    only_rustnode = [pair for pair in rustnode_pairs if pair not in node_pairs]

    failures = 0
    if len(node_rows) != len(rustnode_rows):
        failures += 1
        print(f"COUNT MISMATCH: node {len(node_rows)} != rustnode {len(rustnode_rows)}")
    for pair in only_node:
        failures += 1
        row = next(row for row in node_rows if (row[0], row[1]) == pair)
        print(
            f"  ONLY IN NODE: CN={common_name(row[2])!r} "
            f"subject={pair[0]} spki={pair[1]}"
        )
    for pair in only_rustnode:
        failures += 1
        row = next(row for row in rustnode_rows if (row[0], row[1]) == pair)
        print(
            f"  ONLY IN RUSTNODE: CN={common_name(row[2])!r} "
            f"subject={pair[0]} spki={pair[1]}"
        )

    if failures:
        print(f"FAIL: {failures} difference(s)")
        return 1

    print(f"sorted (subject, SPKI SHA-256) lists are identical: {len(node_pairs)} pairs")
    ordered = [(row[0], row[1]) for row in node_rows] == [
        (row[0], row[1]) for row in rustnode_rows
    ]
    print(f"input order also identical: {ordered}")

    # The identity comparison above is the semantic one the PR records, and it
    # is deliberately structural: subject and SPKI are what a trust anchor *is*.
    # It cannot see a difference outside those two fields, though -- a corrupted
    # outer tag leaves both intact -- so the exact strings are compared too.
    # Node stores the PEM text and hands it out unchanged, so this is a valid
    # requirement rather than a stricter-than-necessary one.
    if node_certificates != rustnode_certificates:
        print("FAIL: the PEM strings differ even though subject and SPKI match")
        for position, (expected, actual) in enumerate(
            zip(node_certificates, rustnode_certificates)
        ):
            if expected != actual:
                print(f"  certificate {position} differs")
                for index, (left, right) in enumerate(zip(expected.split("\n"), actual.split("\n"))):
                    if left != right:
                        print(f"    line {index}: node {left!r} rustnode {right!r}")
                        break
        return 1
    print("exact PEM strings are identical, in the same order")

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

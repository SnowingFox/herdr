#!/usr/bin/env python3
"""Checks that `vendor/certdata/certdata.txt` is the pinned Node trust store.

The file is the Mozilla NSS trust store at the Node revision
`tools/node-pin.toml` pins, and it is the input
`crates/rn-bind-crypto-x509/src/root_certs.rs` is generated from.

Two different failures need catching, and they are not the same check:

* the generated module drifted from this file -- that is
  `crates/rn-bind-crypto-x509/tools/gen-root-certs.py --check`;
* this file changed, and the module was regenerated from the new one, so both
  are self-consistent and the roots are still not Node's. That is this script.

The hash is recorded here rather than read out of the generated module on
purpose. Reading it from the module would make the check compare a value to
itself: a regeneration after a silent trust-store swap would update the module's
`CERTDATA_SHA256` too, and both would agree on the wrong store.

Exit codes: 0 the file is the pinned one, 1 it is not, 2 the file is missing.
"""

import hashlib
import os
import sys

CERTDATA_SHA256 = "3ec2b4d240dc12c747eaf450061db84af757c483bbda302f9e29ceb5d70be510"
NODE_COMMIT = "f344e7f552e3656bd37517151c5dc87d22b33771"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "vendor", "certdata", "certdata.txt")


def main():
    try:
        with open(PATH, "rb") as handle:
            data = handle.read()
    except FileNotFoundError:
        print(f"{PATH} is missing; it is the input for the bundled roots", file=sys.stderr)
        return 2

    digest = hashlib.sha256(data).hexdigest()
    if digest != CERTDATA_SHA256:
        print(
            f"vendor/certdata/certdata.txt is not the pinned trust store: "
            f"sha256 is {digest}, expected {CERTDATA_SHA256} from Node {NODE_COMMIT}",
            file=sys.stderr,
        )
        return 1

    print(
        f"vendor/certdata/certdata.txt is the trust store from Node {NODE_COMMIT} "
        f"(sha256 {CERTDATA_SHA256[:16]}...)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

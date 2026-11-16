# certdata.txt, the trust store the bundled roots come from

`certdata.txt` is copied byte-identical from `tools/certdata.txt` in the Node
revision pinned in `rustnode/tools/node-pin.toml`:

    f344e7f552e3656bd37517151c5dc87d22b33771

    sha256  3ec2b4d240dc12c747eaf450061db84af757c483bbda302f9e29ceb5d70be510

It is the Mozilla NSS trust store, the input Node's `tools/mk-ca-bundle.pl`
reads to produce `src/node_root_certs.h`. Committing it is what makes the
regeneration of `crates/rn-bind-crypto-x509/src/root_certs.rs` offline and
reproducible, and it is why a changed trust store is detectable: the generated
module carries this file's SHA-256, and a unit test in `root_store.rs`
re-hashes the file on disk and compares.

Without this file a regeneration would need a network fetch or a Node checkout,
and nothing would notice if the blob silently became a different set of roots
with the same count.

## Updating

Re-copy the file from the new Node revision, update the hash above, and run:

```bash
crates/rn-bind-crypto-x509/tools/gen-root-certs.py
```

all in the same commit as the pin change in `rustnode/tools/node-pin.toml`.
`./tools/check.sh` fails when the generated module is stale with respect to
this file, so the two cannot drift apart silently.

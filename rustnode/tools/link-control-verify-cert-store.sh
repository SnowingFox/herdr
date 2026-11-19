#!/usr/bin/env bash
# Proves `SSL_set1_verify_cert_store` is a macro and not a symbol.
#
#   ./tools/link-control-verify-cert-store.sh
#   ./tools/link-control-verify-cert-store.sh --self-test
#
# # Why this exists
#
# `crates/rn-bind-tls/src/peer_cert.rs` had
#
#     extern "C" {
#         pub(crate) fn SSL_set1_verify_cert_store(ssl: *mut SSL, store: *mut X509_STORE) -> c_int;
#     }
#
# and it linked, for many commits, because its only caller `set_ca_certs` was
# itself never called. Nothing referenced the symbol, so the linker never had to
# resolve it. The moment the SNI path is wired up, the crate stops linking:
#
#     undefined reference to `SSL_set1_verify_cert_store'
#
# The macro is real and does the work — `ssl.h.in:1440` expands it to
# `SSL_ctrl(s, SSL_CTRL_SET_VERIFY_CERT_STORE, 1, (char *)(st))` — so the fix is
# to perform the control, which `ffi_extra::ssl_set1_verify_cert_store` does.
#
# # What each half proves
#
# 1. `nm` over the built `libssl.a` has no `SSL_set1_verify_cert_store`. That is
#    the fact, measured, rather than read off a header.
# 2. A C object that references the name fails to link, while the macro form with
#    the same arguments links. That is the difference between a declaration that
#    costs nothing today and one that cannot be referenced at all.
# 3. The `SSL_CTX_` spelling is **also** a macro. This is worth measuring rather
#    than assuming, because the obvious way to get this wrong is to reach for the
#    context form believing it is a symbol. Both live at `ssl.h.in:1408-1411`,
#    both are `SSL_CTX_ctrl` over the same command, and neither is exported. The
#    real exported symbols are `SSL_CTX_set_cert_store` and its up-ref variant
#    `SSL_CTX_set1_cert_store`, which the `verify_cert_store` macros are not
#    aliases of: those touch the context's own store, while the macro reaches
#    `ssl_cert_set_cert_store(sc->cert, ...)` — the per-connection `CERT`'s
#    verify store, which is the one SNI has to change.
#
# `--self-test` inverts the symbol expectation and requires that to fail, so this
# control cannot rot into green lines over a measurement it did not make.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

self_test=0
[ "${1:-}" = "--self-test" ] && self_test=1

# The vendored library the workspace links, from a `cargo build` that has already
# run. `tools/check.sh` builds before this step for exactly this reason.
#
# Several `openssl-sys-<hash>` build directories can exist at once — one per
# profile, and one per fingerprint change — so the newest `libssl.a` is the one
# this build actually linked. Picking the first match would compare against a
# stale library and still report a verdict.
#
# The target directory is `CARGO_TARGET_DIR` when set, `target` otherwise, the way
# Cargo resolves it. Reading only `target/` made this step depend on that variable
# being unset: with it pointing elsewhere the loop found nothing and reported "no
# vendored OpenSSL build under target/" while looking in a directory the build
# never used. `tools/audit-ffi-types.py` had the same defect.
target_dir="${CARGO_TARGET_DIR:-target}"
libdir=""
newest=0
for candidate in "$target_dir"/debug/build/openssl-sys-*/out/openssl-build/install/lib \
                 "$target_dir"/release/build/openssl-sys-*/out/openssl-build/install/lib; do
  [ -f "$candidate/libssl.a" ] || continue
  stamp="$(stat -c %Y "$candidate/libssl.a" 2>/dev/null || echo 0)"
  if [ "$stamp" -gt "$newest" ]; then
    newest="$stamp"
    libdir="$candidate"
  fi
done
if [ -z "$libdir" ]; then
  echo "link-control: no vendored OpenSSL build under $target_dir/; run cargo build first" >&2
  exit 1
fi
includedir="$(cd "$libdir/../include" && pwd)"
echo "link-control: vendored library at $libdir"

symbol_count="$(nm -g --defined-only "$libdir/libssl.a" | grep -c ' T SSL_set1_verify_cert_store$' || true)"
ctx_count="$(nm -g --defined-only "$libdir/libssl.a" | grep -c ' T SSL_CTX_set1_verify_cert_store$' || true)"
ctx_real_count="$(nm -g --defined-only "$libdir/libssl.a" | grep -c ' T SSL_CTX_set1_cert_store$' || true)"

if [ "$self_test" -eq 1 ]; then
  # Inverted on purpose: the self-test requires the symbol to be *present*, so a
  # correct tree fails it. If this branch ever passes, the measurement above is
  # not measuring what it claims.
  if [ "$symbol_count" -ne 0 ]; then
    echo "link-control: self-test FAILED: the symbol was found, so the absence check is meaningless"
    exit 1
  fi
  echo "link-control: self-test ok — the absence check distinguishes the two states"
  exit 0
fi

if [ "$symbol_count" -ne 0 ]; then
  echo "link-control: FAILED: libssl.a defines SSL_set1_verify_cert_store, so it is a symbol after all" >&2
  exit 1
fi
# The context form is a macro too; measuring it stops the next reader from
# "fixing" this by reaching for a name that also does not exist.
if [ "$ctx_count" -ne 0 ]; then
  echo "link-control: FAILED: SSL_CTX_set1_verify_cert_store is exported, contradicting ssl.h.in:1410" >&2
  exit 1
fi
if [ "$ctx_real_count" -ne 1 ]; then
  echo "link-control: FAILED: SSL_CTX_set1_cert_store should be a real symbol (found $ctx_real_count)" >&2
  exit 1
fi
echo "link-control: neither verify_cert_store form is a symbol; SSL_CTX_set1_cert_store is"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Undeclaring the macro is what lets the name be referenced at all; without it the
# compiler expands it and the symbol is never mentioned.
cat > "$workdir/broken.c" <<'C'
#include <openssl/ssl.h>
/* Undeclaring the macro is what lets the name be referenced at all; without it
   the compiler expands it and the symbol is never mentioned. The declaration is
   the one the crate used to have, reduced to its linkage.
 *
 * The call is through a volatile function pointer so gcc cannot fold away the
 * reference: `&f != 0` is a constant, and a version of this control that wrote
 * that linked even with the symbol missing and proved nothing. */
#undef SSL_set1_verify_cert_store
extern int SSL_set1_verify_cert_store(SSL *, X509_STORE *);
int main(void) {
  int (*volatile call)(SSL *, X509_STORE *) = SSL_set1_verify_cert_store;
  return call((SSL *) 0, (X509_STORE *) 0);
}
C

cat > "$workdir/works.c" <<'C'
#include <openssl/ssl.h>
int main(void) {
  /* The macro, with the arguments the crate's wrapper passes. */
  return SSL_set1_verify_cert_store((SSL *) 0, (X509_STORE *) 0) != 0;
}
C

if gcc -I"$includedir" -o "$workdir/broken" "$workdir/broken.c" \
     "$libdir/libssl.a" "$libdir/libcrypto.a" -ldl -lpthread 2>"$workdir/broken.err"; then
  echo "link-control: FAILED: referencing SSL_set1_verify_cert_store linked; it is a symbol after all" >&2
  exit 1
fi
if ! grep -q 'undefined reference to .*SSL_set1_verify_cert_store' "$workdir/broken.err"; then
  echo "link-control: FAILED: the link failed for some other reason:" >&2
  cat "$workdir/broken.err" >&2
  exit 1
fi
echo "link-control: referencing the symbol fails to link, as it must"

if ! gcc -I"$includedir" -o "$workdir/works" "$workdir/works.c" \
      "$libdir/libssl.a" "$libdir/libcrypto.a" -ldl -lpthread 2>"$workdir/works.err"; then
  echo "link-control: FAILED: the macro form did not link:" >&2
  cat "$workdir/works.err" >&2
  exit 1
fi
echo "link-control: the SSL_ctrl form the wrapper uses links"

echo "link-control: ok"

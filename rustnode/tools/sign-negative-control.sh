#!/usr/bin/env bash
# Negative control for the Sign/Verify slice, with the stale-binary guard.
#
# Every earlier attempt at this control on this project was vacuously green at
# least once: a worker injected a `compile_error!` into an unreferenced module,
# the build succeeded, and the "failure" it observed was a leftover binary. So
# this script:
#
#   1. deletes the binary before building;
#   2. records the build start time and requires the new binary to be newer;
#   3. aborts if the build fails, rather than testing whatever is on disk;
#   4. proves the guard by making the build *fail on purpose* with a
#      `compile_error!` in a file that is actually compiled, and requiring the
#      guard to abort.
#
# Usage: tools/sign-negative-control.sh [--prove-guard]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
export CXX="${CXX:-g++}"
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"

binary="target/debug/rustnode"
prove_guard=0
[ "${1:-}" = "--prove-guard" ] && prove_guard=1

# The file the deliberate failure is injected into. It is a module the crate
# actually declares and calls into -- `rn-bind-crypto-sign`'s `install_classes`
# is reached from `rn-bind-crypto::install`, which is reached from the namespace
# registration, so this is compiled into every binary. Contrast with a module
# nothing references, where `compile_error!` is never expanded on this toolchain
# and the build happily succeeds.
inject_into="crates/rn-bind-crypto-sign/src/jobs.rs"
backup="$(mktemp)"
cp "$inject_into" "$backup"
restore() { cp "$backup" "$inject_into"; rm -f "$backup"; }
trap restore EXIT

if [ "$prove_guard" -eq 1 ]; then
  echo "== proving the guard: injecting compile_error! into $inject_into =="
  # Appended at the end of the file, inside the module, unconditionally compiled.
  printf '\ncompile_error!("negative control: this build must fail");\n' >> "$inject_into"
  rm -f "$binary"
  started=$(date +%s)
  # The output is captured before it is searched: piping straight into `grep -q`
  # under `set -o pipefail` reports the *cargo* status, so a build that failed
  # exactly as intended would look like a grep miss.
  if cargo build -p rn-cli >/tmp/sign-nc-guard.log 2>&1; then
    echo "FAIL: the build succeeded with a compile_error! in a compiled module" >&2
    exit 1
  fi
  if grep -q 'negative control: this build must fail' /tmp/sign-nc-guard.log; then
    echo "PASS: the deliberate build failure was reported by the compiler"
  else
    echo "FAIL: the build failed but not for the injected reason" >&2
    tail -20 /tmp/sign-nc-guard.log >&2
    exit 1
  fi
  echo "PASS: the build aborted, so the guard's abort path is real"
  if [ -e "$binary" ]; then
    echo "FAIL: a binary exists after a failed build (mtime $(stat -c %Y "$binary"), start $started)" >&2
    exit 1
  fi
  echo "PASS: no binary was left behind by the failed build"
  restore
  trap - EXIT
  echo
fi

echo "== building from scratch with the real sources =="
rm -f "$binary"
started=$(date +%s)
if ! cargo build -p rn-cli >/tmp/sign-nc-build.log 2>&1; then
  echo "ABORT: the build failed; refusing to test a leftover binary" >&2
  tail -20 /tmp/sign-nc-build.log >&2
  exit 1
fi
[ -x "$binary" ] || { echo "ABORT: the build produced no binary" >&2; exit 1; }
mtime=$(stat -c %Y "$binary")
if [ "$mtime" -lt "$started" ]; then
  echo "ABORT: $binary is older than the build start ($mtime < $started)" >&2
  exit 1
fi
echo "PASS: $binary is newer than the build start ($mtime >= $started)"
echo

echo "== control 1: createSign exists at all =="
# Before this slice: "TypeError: _Sign is not a constructor".
out=$("$binary" -e "const c=require('crypto'); const s=c.createSign('sha256'); console.log('Sign exists:', typeof c.Sign, s.constructor.name)" 2>&1) || true
echo "$out"
echo "$out" | grep -q '_Sign is not a constructor' && { echo "FAIL: still missing" >&2; exit 1; }
echo

echo "== control 2: RSA sign then verify =="
out=$("$binary" -e "
const c=require('crypto');
const {privateKey,publicKey}=c.generateKeyPairSync('rsa',{modulusLength:2048});
const data=Buffer.from('the quick brown fox');
const sig=c.createSign('sha256').update(data).sign(privateKey);
const ok=c.createVerify('sha256').update(data).verify(publicKey,sig);
console.log('siglen', sig.length, 'verified', ok);
if(!ok) process.exit(1);
" 2>&1) || true
echo "$out"
echo "$out" | grep -q 'verified true' || { echo "FAIL: RSA round trip" >&2; exit 1; }
echo

echo "== control 3: a bad signature returns false rather than throwing =="
out=$("$binary" -e "
const c=require('crypto');
const {privateKey,publicKey}=c.generateKeyPairSync('rsa',{modulusLength:2048});
const sig=c.createSign('sha256').update(Buffer.from('a')).sign(privateKey);
let threw=false, result;
try { result=c.createVerify('sha256').update(Buffer.from('b')).verify(publicKey,sig); }
catch(e){ threw=true; result='threw: '+e.message; }
console.log('threw', threw, 'result', result);
" 2>&1) || true
echo "$out"
echo "$out" | grep -q 'threw false result false' || { echo "FAIL: bad signature did not return false" >&2; exit 1; }
echo

echo "== control 4: EC and Ed25519 =="
out=$("$binary" -e "
const c=require('crypto');
for (const type of ['ec','ed25519']) {
  const opts = type==='ec' ? {namedCurve:'prime256v1'} : {};
  const {privateKey,publicKey}=c.generateKeyPairSync(type,opts);
  const data=Buffer.from('hello');
  const sig = type==='ed25519' ? c.sign(null,data,privateKey)
                               : c.createSign('sha256').update(data).sign(privateKey);
  const ok = type==='ed25519' ? c.verify(null,data,publicKey,sig)
                              : c.createVerify('sha256').update(data).verify(publicKey,sig);
  console.log(type,'siglen',sig.length,'verified',ok);
  if(!ok) process.exit(1);
}
" 2>&1) || true
echo "$out"
echo "$out" | grep -q 'ec siglen .* verified true' || { echo "FAIL: EC round trip" >&2; exit 1; }
echo "$out" | grep -q 'ed25519 siglen 64 verified true' || { echo "FAIL: Ed25519 round trip" >&2; exit 1; }
echo

echo "ALL CONTROLS PASSED"

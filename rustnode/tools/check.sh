#!/usr/bin/env bash
# The gate every commit has to pass, in one command.
#
#   ./tools/check.sh            # full gate
#   ./tools/check.sh --quick    # skip the workspace test sweep
#
# The order matters. `cargo build -p rn-cli` comes before the tests because
# several crates run the real binary from their integration tests: without it
# they would silently test a stale build, which has already masked a real bug.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.96.1}"
# `vendor/merve` is C++ and cc-rs picks `c++`, which on this image resolves to
# clang++ without the GCC C++ include paths, so it fails on `<cstddef>`. g++
# is installed and works. Pinning it here keeps the gate reproducible instead
# of depending on what `c++` happens to be.
export CXX="${CXX:-g++}"
# Linking a g++-compiled object needs libstdc++, whose `.so` symlink lives only
# in the GCC version directory here, not on the default linker search path.
export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/gcc/x86_64-linux-gnu/13"
quick=0
[ "${1:-}" = "--quick" ] && quick=1

step() { printf '\n== %s ==\n' "$1"; }

step "the binding matcher still classifies crates correctly"
# Runs before the regeneration, and as its own plain statement: a bare command's
# status is the gate's status under `set -e`, whereas piping it into `tee` or
# capturing it in `$( )` would let a failing matcher fall through to a green
# gate. The tests are what justify the scanner's complexity, so they have to be
# able to fail this gate rather than being runnable only by hand.
./tools/regen-bindings.test.sh

step "every opt-in control still has a verdict to report"
# The controls that build the CLI or drive a real Node surface stay opt-in,
# because running them all here would add minutes to every commit. What does not
# stay opt-in is the property that makes them worth having: that each one
# distinguishes success from failure by exit status rather than by printing.
# `cipher-negative-control.sh` shipped documenting exit 2 while exiting 1, and
# nothing caught it because nothing read the script at all. This reads every
# control without running it, and self-tests against the defect shapes so the
# check itself cannot rot into a string of oks.
#
# A bare statement, for the same reason as the line above.
./tools/controls.test.sh

step "regenerating the binding registry"
./tools/regen-bindings.sh

step "the pinned Node oracle is present"
# Differential tests compare rustnode against a real Node, and that Node has to
# be the one `tools/node-pin.toml` pins. Without this step they inherit whatever
# `node` is on `PATH`: on GitHub's ubuntu-latest that is Node 22 while the pin is
# Node 28, and the two disagree about the crypto surface, so
# `rn-bind-crypto/tests/differential.rs` failed on CI and passed locally against
# the right binary. Neither log said which engine it had measured.
#
# `RN_NODE_ORACLE` is exported rather than relying on the pin's recorded
# directory, so the binary this gate uses is explicit in the environment of
# every step below and appears in the log line this prints. A failure here is
# fatal: the gate must not quietly run a weaker set of tests.
oracle_dir="$(sed -n 's/^oracle *= *"\(.*\)"/\1/p' tools/node-pin.toml | head -1)"
expected_oracle_version="$(sed -n 's/^oracle_version *= *"\(.*\)"/\1/p' tools/node-pin.toml | head -1)"
# Everything the resolver would consider, in its order, for the failure message.
# The tests enumerate the same list when they skip; doing it here means a gate
# failure names every candidate rather than only the one that was attempted.
searched_oracle_paths() {
  [ -n "${RN_NODE_ORACLE:-}" ] && printf ' %s (from RN_NODE_ORACLE)' "$RN_NODE_ORACLE"
  [ -n "$oracle_dir" ] && printf ' %s/bin/node ([node] oracle in tools/node-pin.toml)' "$oracle_dir"
  local dir
  local rest="${PATH:-}"
  # `${rest#*:}` returns `rest` unchanged when no colon remains, so the loop is
  # advanced by assigning the remainder each time rather than by a substring.
  while [ -n "$rest" ]; do
    case "$rest" in
      *:*) dir="${rest%%:*}"; rest="${rest#*:}" ;;
      *) dir="$rest"; rest="" ;;
    esac
    [ -n "$dir" ] && printf ' %s/node (PATH)' "$dir"
  done
}
if [ -n "${RN_NODE_ORACLE:-}" ] && [ -x "${RN_NODE_ORACLE}" ]; then
  : # an explicit oracle already in the environment wins
elif ! ./tools/fetch-node-oracle.sh; then
  {
    echo "check: no pinned Node oracle, and the differential tests must not fall back to PATH."
    echo "check: expected Node ${expected_oracle_version:-$oracle_dir}."
    echo "check: searched:$(searched_oracle_paths)"
    echo "check: set RN_NODE_ORACLE to a pinned binary, or allow the download above."
  } >&2
  exit 1
fi
export RN_NODE_ORACLE="${RN_NODE_ORACLE:-${oracle_dir}/bin/node}"
actual_oracle_version="$("$RN_NODE_ORACLE" --version)"
if [ -n "$expected_oracle_version" ] && [ "$actual_oracle_version" != "$expected_oracle_version" ]; then
  echo "check: $RN_NODE_ORACLE reports $actual_oracle_version," >&2
  echo "check: but tools/node-pin.toml records $expected_oracle_version" >&2
  exit 1
fi
echo "check: differential tests will use $RN_NODE_ORACLE ($actual_oracle_version)"

step "building the workspace and the CLI binary"
# The CLI binary is built explicitly: integration tests that spawn it read
# `target/debug/rustnode`, and `cargo test -p <crate>` does not rebuild it.
cargo build --workspace
cargo build -p rn-cli

step "the release profile type-checks"
# Every build above is the debug profile, so nothing in this gate ever compiled
# `cfg(not(debug_assertions))`. PR #72 shipped a `defer_or` whose whole body sat
# behind `#[cfg(debug_assertions)]`: debug returned `bool` as declared, release
# returned `()` and did not compile at all, and nine consecutive green gates
# missed it because a debug build never removes that body. The same `cfg` had a
# worse shape available to it -- had the body been dropped without the type
# mismatch, every submit deferred during `mem_recv` (GOAWAY included) would have
# been discarded silently in release builds, with no error at all.
#
# This is `check` and not `build` on purpose, and the reason is not only cost.
# The bug is a type error: with the body gone, `defer_or` declares `-> bool` and
# drops through to `()`. `cargo check` runs the full type checker over every
# cfg-selected body, so it reports exactly that error; it does not stop after
# name resolution. What `check` cannot see is a *codegen* or link-time
# divergence (a release-only `link`/`#[no_mangle]`/`panic=abort` interaction),
# so this step raises the floor to "the release profile type-checks" rather than
# claiming the release profile is proven to build. `cargo build --release
# --workspace` costs minutes here because `panic = "abort"` and `lto = "thin"`
# force a full codegen of every crate plus the 198 MB `librusty_v8.a` link; that
# belongs in CI, not in the per-commit gate.
#
# The workspace, not just `rn-cli`, because `cfg` divergence is per-crate: the
# crate that breaks may be one `rn-cli` merely depends on, as this one was.
#
# It runs after the debug build and before everything that execs
# `target/debug/rustnode`, and it is not `--quick`-gated: warm it costs ~0.2s
# (measured), which buys the one profile this gate otherwise never type-checks.
cargo check --release --workspace

step "the per-context globals audit"
# Every assertion reads the rustnode realm (`primordials`, `DOMException`, the
# per-context symbol tables), so this needs the binary built above and cannot run
# with system node. It lived outside the gate and reported 44/44 for a while
# while 14 of those checks compared a value to itself.
#
# It runs *before* the cipher self-test, not after. That self-test deletes
# `target/debug/rustnode`, fails the build on purpose, then restores the binary
# by `cp`-ing a `mktemp` backup into the now-absent path, which gives it mode
# 0600 — no execute bit. Cargo restores the mode on any real rebuild, so master's
# remaining steps never noticed: the next one is `cargo test`, which rebuilds.
# This is the first step that execs the binary directly, so running it first
# keeps the audit's own result from depending on that restore behaviour.
# Two passes. The first is the ordinary surface: `primordials` must not be a
# global, and the DOMException/structuredClone behaviour has to hold. The second
# sets `RUSTNODE_DEBUG_REALM_PRIMORDIALS=1`, which publishes the realm's object
# under a debug-only name so the member table `domexception.js` depends on can be
# checked directly. Without the second pass the leak's fix would silently drop
# that coverage; without the first the publication would hide the leak.
./target/debug/rustnode tools/per-context-audit.js
RUSTNODE_DEBUG_REALM_PRIMORDIALS=1 ./target/debug/rustnode tools/per-context-audit.js > /dev/null

step "process has no member the oracle lacks, and lacks none it has"
# The "17 missing process members" finding was a hand count that was wrong twice:
# eleven of the seventeen had already been implemented, and four of the remaining
# names exist only in a child process, where Node also lacks them on the main
# thread. `tools/process-member-audit.py` replaces the count with a measurement
# across the three populations that matter (main, worker, forked), comparing
# `Object.getOwnPropertyNames(process)` on both runtimes.
#
# A bare statement under `set -e`, like the controls above, so a mismatch turns
# the gate red. It reads the debug binary — the only profile this gate builds —
# and the pinned oracle, both of which the build step and the oracle step above
# have already guaranteed, and refuses rather than passing when either is
# missing. The audit's own default is the release binary, which belongs to a
# human or CI run that has one; `process` own-property names do not differ
# between profiles, so naming the debug build measures the same surface.
python3 tools/process-member-audit.py --rustnode target/debug/rustnode

step "the per-context globals still behave as Node's do"
# The control for the per-context work: DOMException is a real `Error`, the
# messaging binding hands back the same class, and `structuredClone` survives the
# per-isolate symbols. It ships as a plain statement for the same reason as the
# matcher tests above -- a bare command's status is the gate's status under
# `set -e`, while `| tee` or `$( )` would let a failing control fall through to a
# green gate. That is not hypothetical here: this control reported a stale PASS
# once already, which is why it re-checks the build it used.
#
# It belongs after the build because every assertion runs against the rustnode
# realm, and warm it costs ~0.4s, so there is no reason to leave it opt-in.
#
# It runs before the cipher self-test for the same reason the audit above does:
# that self-test restores `target/debug/rustnode` by `cp`-ing a `mktemp` backup
# into the path it deleted, which recreates the file mode 0600. This control
# execs the binary directly, so it has to run while the binary is still
# executable. `cargo test` later rebuilds and restores the mode, which is why
# nothing after the self-test noticed.
./tools/per-context-control.sh

step "calling a binding constructor without new matches Node's answer"
# `SecureContext()` aborted with `SetAlignedPointerInInternalField: Internal
# field out of bounds` at 100 of 100 runs before its `new.target` guard, and the
# same shape existed in a dozen other constructors. The audit walks every
# constructor the registry installs, one child process per case, because an
# abort in-process would take the runner with it and silently skip the rest.
#
# This step judges the *value*, not only the crash. Its earlier form was
# `--no-oracle`, and that mode could only ask "did the process survive?": a
# plain call may throw or return `undefined` and both read as `ok` there.
# `tls_wrap.TLSWrap` returning `undefined` where Node aborts, and `uv.errname`
# returning `undefined` where Node returns a string, were both invisible to it.
# Measured both ways on a build with `errname` mutated to return `undefined`:
# the old mode printed `ok` for all 486 members, the current one prints
# `BAD: return type: node string, rustnode undefined` and exits 1.
#
# It now reads the oracle's answers from `tools/no-new-expectations.json` (the
# `--no-oracle` half) *and* re-derives them from the live pinned oracle in the
# same run, which is what keeps the recording from rotting into a statement
# about rustnode. The oracle is guaranteed by the step earlier in this script.
#
# What is still not covered, stated here because the difference matters: a
# constructor rustnode installs that the oracle does not is judged for crashes
# only, since there is no Node answer to compare the call against. There are
# 407 of those today, and the summary line above prints that count so it cannot
# be mistaken for full coverage. `namespace_structure` owns whether they should
# be constructible at all.
#
# It runs after the build because it execs the binary, and before the cipher
# self-test for the same mode-bit reason as the two controls above.
python3 tools/no-new-audit.py

step "binding members accept new exactly when node's do"
# Node builds every `SetMethod`/`SetProtoMethod` function with
# `ConstructorBehavior::kThrow` (`src/util.cc`), so `new binding.fs.open()` is a
# `TypeError` there. rustnode used V8's builder default, which is `Allow`, and
# 405 members accepted `new` that Node rejects — more permissive than the
# reference, so a wrong `new` passed here and failed on Node.
#
# `--recorded` needs no Node binary: `tools/constructible-members.json` is the
# pinned oracle's answer, recorded through `Reflect.construct`. Both directions
# are judged, because over-correcting the default turns real classes into
# `TypeError`s. The run is against the shipping object, after the vendored
# `lib/**` bootstrap, because six members (`util.isUint8Array`,
# `messaging.DOMException`, ...) are replaced there by the JavaScript layer and
# judging the native install alone would report them as defects.
#
# The prototype half reads `tools/constructible-prototypes.json`, which records
# every prototype method *and its kind*. It has to: Node installs these with
# `SetProtoMethod`, i.e. `kThrow`, so a recording filtered to the constructible
# ones is empty for every class and the comparison runs zero times. That is what
# this step used to do, and it printed a clean `0 prototype method(s)` for a
# measurement it had not made. The control below is what keeps that from coming
# back: it requires the shape of the fixture, a non-zero comparison count, and
# the audit's refusal to answer when the count would be zero.
#
# The control runs first because the audit's own exit status is what the gate
# enforces; a step that cannot fail is the defect it guards.
./tools/constructible-audit.test.sh

# A bare statement, so its status is the gate's.
python3 tools/constructible-audit.py --recorded tools/constructible-members.json

step "binding functions are named as node names them, with node's length"
# `SetMethod(context, target, "open", Open)` ends with
# `function->SetName(name_string)`, so a Node binding member reports its property
# name as `f.name`. V8's `FunctionTemplate::builder` leaves it `""`, and every
# crate used that builder, so 403 of 527 members were nameless here — visible in
# stack traces and `util.inspect`, and reported twice before this guard existed.
#
# The same helper call also decides `f.length`, and it decides it **zero**: every
# `SetMethod` variant builds through `NewFunctionTemplate`, which passes an
# explicit 0, and V8 honours whatever length it is handed. So a binding that
# passed its callback's real arity reported a longer function than Node's — 14
# namespace members and 97 prototype methods. The exceptions are real and named:
# V8's own `SimpleInstallFunction` records a length (`trace_events.trace` is 5),
# and `src/node_serdes.cc` calls `SetLength(1)` once. Both invariants come from
# one fixture and one walk, because they are two fields of the same publication.
#
# The audit judges both directions, which is why it stores Node's actual name and
# length rather than a "should be named" flag or "should be zero": `SetFastMethod*`
# omits `SetName` (so `buffer.copy.name` is `""` on Node too),
# `util.getSharedArrayBufferGrowable` is `"get growable"` because it republishes
# V8's own accessor, and `serdes.Deserializer` really is length 1.
#
# `--recorded` needs no Node binary: `tools/function-name-members.json` and
# `tools/function-name-prototypes.json` are the pinned oracle's answers. Every
# half is counted separately — members, prototype methods, member lengths,
# prototype method lengths — because an emptied member fixture leaves 435
# prototype methods that would otherwise report a clean result about a comparison
# it had not made.
#
# The summary also prints the skip accounting: recorded, compared, skipped
# because a crate declared the member deferred, and skipped for no declared
# reason. That last bucket is an error rather than a skip, because a member that
# silently fell out of the install path is exactly what this audit is best placed
# to notice, and printing only the compared count would have hidden it inside a
# number nobody checks.
#
# The control runs first because the audit's own exit status is what the gate
# enforces.
./tools/function-name-audit.test.sh

python3 tools/function-name-audit.py --recorded tools/function-name-members.json

step "the cipher control still reports a void run as a void run"
# The control's exit contract — 3 for "the build failed, so there is no
# verdict", distinct from 1 for "the control misbehaved" — is what stops a
# build failure being reported as a failed control. That was a real defect: a
# `compile_error!` used to exit 1 and print `RESULT: UNEXPECTED`. The contract
# is only worth having if something exercises it, so the self-test runs here
# rather than being a diagnostic nobody invokes. It injects a real
# `compile_error!`, so it sits after the build (warm cache makes it ~1s) and
# before the tests and lints, which would fail loudly if the restore ever left
# the source tree modified.
./tools/cipher-negative-control.sh --self-test

step "the exit handler can still fail a process"
# `common.mustCall` fails a file by calling `process.exit(1)` from inside a
# `process.on('exit')` listener. Before #60 wired the emit, that listener never
# ran on a natural loop exit, so ~2850 files under `test/parallel` reported a
# pass without checking anything and the suite's headline number was overstated.
#
# The Rust suite guards the emit itself (`a_natural_exit_runs_the_exit_handlers`
# and eight neighbours), but not this composition: `same_as_node` asserts
# `status.success()` on *both* runtimes, so no test there can express "exits 1",
# and the one test that calls `process.exit()` inside a handler passes no code.
# A regression where the emit runs but a re-entrant exit's code is dropped would
# leave every one of those green while `mustCall` silently became a no-op again.
#
# `--mechanism` asserts exactly that pair and needs no Node test tree, so it can
# run on every machine. The full six-case matrix still needs Node's own
# `test/common` and stays opt-in; it passes on current master.
#
# The binary is made executable first. The cipher self-test above restores
# `target/debug/rustnode` by `cp`-ing a `mktemp` backup into the path it deleted,
# which leaves the file mode 0600, and the next `cargo` invocation is what
# repairs it. `per-context-control.sh` and its audit work around the same thing
# by running earlier; this step cannot, because a control that execs a
# non-executable binary reports exit 126 and reads as a *runtime* failure rather
# than a missing mode bit. Restoring the mode here is the narrow fix: it makes
# the step independent of how the preceding self-test restored the binary,
# instead of depending on its restore behaviour staying what it is today.
chmod +x target/debug/rustnode
./tools/mustcall-negative-control.sh --mechanism

mustcall_tests="${RUSTNODE_TEST_CACHE:-${TMPDIR:-/tmp}}/rustnode-node-test/test"
if [ -f "$mustcall_tests/common/index.js" ]; then
  echo "mustcall control: a Node test tree is present at $mustcall_tests;"
  echo "mustcall control: ./tools/mustcall-negative-control.sh --quick --tests $mustcall_tests"
  echo "mustcall control: runs the full six-case matrix as well"
fi

if [ "$quick" -eq 0 ]; then
  step "running the workspace tests"
  cargo test --workspace
fi

step "the io_uring readiness backend is exercised, not just requested"
# `crates/rn-uv/tests/readiness_backends.rs` says in its own header that "the
# suite is run twice — once without the variable and once with it". Nothing ran
# it the second time: no gate step and no workflow ever set `HERDR_URING`, so
# `cargo test --workspace` above covers only the epoll path, and `README.md`
# advertises io_uring as an opt-in a user can turn on. The claim was documented
# and unmeasured (CLA-234).
#
# The suite is also what makes the second run meaningful, and it now takes both
# halves of that. #130 gave the helper `rn_uv::poller::installed_backend()`, which
# records what `Installed::install` really produced, so it no longer compares
# `Poller::from_env()` — the request — against itself. That makes a silent
# fallback to epoll *visible*. It does not make it *fail*: a kernel that refuses
# a ring and a request that was ignored both leave epoll installed, and the
# assertion accepted either.
#
# So `the_requested_backend_is_the_installed_one` also probes
# `rn_uv::poller::kernel_supports_io_uring()`, which asks `io_uring_setup(2)`
# directly. With `HERDR_URING=1` and a kernel that grants rings, an epoll
# installation is a defect and fails. Measured on a build whose `install`
# discards the request: #130's assertion alone passes 5/5 (it prints "installed
# the epoll backend" and accepts it); with the probe it fails on the exact
# member, `Epoll` vs `IoUring`.
#
# Three outcomes are distinguished, and the distinction is the point:
#
#   * the second run passes and installed io_uring — the backend is covered;
#   * the kernel refuses a ring (old kernel, seccomp, `io_uring_disabled`) — the
#     test says so, this step reports it, and the gate does NOT fail: making the
#     gate depend on a kernel feature would fail machines for a reason they
#     cannot fix, and is exactly how a step gets switched off;
#   * the kernel grants rings and the request was ignored — the test fails, and
#     so does this step.
#
# A silent skip would recreate the defect, so the middle case is printed loudly
# and the marker it prints is what this step keys on. If the suite stops printing
# either marker the step fails, because then it can no longer say which case it
# was in.
uring_log="$(mktemp)"
trap 'rm -f "$uring_log"' EXIT
HERDR_URING=1 cargo test -p rn-uv --test readiness_backends -- --nocapture 2>&1 | tee "$uring_log"
if grep -q "installed the io_uring backend" "$uring_log"; then
  echo "io_uring backend: installed and exercised by the suite above"
elif grep -q "this kernel refused a ring" "$uring_log"; then
  echo "io_uring backend: NOT MEASURED on this host — the kernel refused a ring,"
  echo "io_uring backend: and the suite verified the documented epoll fallback instead."
  echo "io_uring backend: this is a host capability, not a code defect, so the gate passes."
else
  echo "io_uring backend: the suite reported neither an installed ring nor a refused one," >&2
  echo "io_uring backend: so it cannot say which backend it measured. Failing." >&2
  exit 1
fi

step "the sqlite surface tests fail when their fixes are reverted"
# `tests/differential.rs` in `rn-bind-sqlite` pins `db.limits` as a live accessor
# view, and `Statement`, `SQLTagStore` and `StatementIterator` instances as coming
# from their exported templates. The tests were written after their fixes, so
# passing them says nothing on its own: this puts each defect back, rebuilds, and
# requires the test named for it to fail.
#
# It is here rather than left opt-in because the property under test is exactly
# "the test can fail", and an opt-in control for that rots in the direction of
# never having been run. Warm it costs ~30s, which is the three rebuilds.
./tools/sqlite-surface-negative-control.sh


step "formatting"
cargo fmt --all -- --check

step "lints"
cargo clippy --workspace --all-targets -- -D warnings

step "binding shapes against the recorded contracts"
# `--baseline` is the coverage ratchet: an unregistered namespace is bring-up
# state and passes, but one that used to cover its contract and no longer does
# is a regression. Without it a namespace could silently drop to a placeholder.
cargo run -q -p rn-compat -- contracts --baseline contracts/complete-namespaces.txt

step "installed namespaces match what they declare"
# The check above reads `MEMBERS` and `DEFERRED`; it never looks at the object
# `install()` built. That is how `sqlite` reported `5 0 0 ok` while `backup` was
# undefined: the member sat in `MEMBERS` *and* `DEFERRED`, so the contract
# subtraction cancelled it. This compares the declarations against the installed
# object for every registered namespace, and separately flags an installed member
# whose first call reports that it is not implemented.
#
# Both checks carry an explicit allowlist of the defects that exist today, counted
# and named per namespace and member, so the gate is enforcing from the first
# commit without failing on work that is not the author's to fix. Anything not on
# that list fails. Shrinking the list is the proof a fix landed.
cargo test -p rn-bindings --test namespace_structure

step "the deferred-reach detector can still fail"
# `deferred-reach.py` reported a clean run over six live defects, including the
# unguarded `getWasmCompileCacheEntry` call inside `translators.js` that made
# every `.wasm` import throw. The cause was its reach rule: it only looked at
# module scope, so a call inside a function body was invisible. Its self-test
# pins the shapes it must catch (any depth, `new`, `.call`, a destructuring
# inside a function) and the ones it must ignore (a guard, a comment), and it is
# run first so a regression in the rule fails before the analysis can report
# clean.
./tools/deferred-reach.py --self-test

step "deferred members reached at module scope"
# A declared deferral passes the contract check by design, so this is the only
# gate that catches a member `lib/**` reaches without a guard. It is part of the
# gate because it silently failed open once already. It now reports reaches at
# any depth against a named baseline of the ones that exist today, so "clean"
# means "nothing new", not "nothing wrong" — see its docstring for what it
# cannot see.
./tools/deferred-reach.py

step "the smoke classifier still tells a gap from a defect"
# The classifier decides whether a failure counts against the runtime or is
# merely waiting on a binding. It got that wrong once, turning a missing
# feature into a skip, so the rule is pinned rather than trusted.
python3 tools/smoke.py --self-test

step "every Node-API gap is either exported or declared"
# F6: 16 entry points the oracle exported were missing from this build *and*
# absent from `shims::DEFERRED`, so an addon needing one aborted at its first call
# and nothing reported it. `rn-compat` cannot see this (Node-API is an ABI, not a
# namespace) and `tests/symbols.rs` cannot either (it compares the binary against
# `EXPORTED` in both directions, which is consistent for any split as long as every
# symbol is covered by one side — which was exactly what was false).
#
# Both invocations name `target/debug/rustnode` explicitly. The tool's default is
# `target/release/rustnode`, which is right for a human or CI run that has a
# release build, but this gate never makes one: the step above is
# `cargo check --release`, for the cost reason its comment records. So the
# default was a path the gate does not produce, and on a clean checkout the tool
# exited 2 (`does not exist; build it before running this check`) with nothing
# wrong in the tree. The profile does not change the answer: `nm -D
# --defined-only` reads linked objects, and the debug and release binaries export
# the same 155 symbols and report the same 155/161/6 here. Naming the debug
# binary keeps the exit-2-on-absent-binary refusal intact, which is the guard
# against reporting clean while measuring nothing.
#
# The self-test runs first and is what makes the gate trustworthy: it removes a
# declaration, typos one, contradicts one, and empties the block, requiring the
# specific diagnostic for each. A gate that cannot fail is the defect it guards.
RUSTNODE_NAPI_BINARY="${RUSTNODE_NAPI_BINARY:-target/debug/rustnode}"
export RUSTNODE_NAPI_BINARY
./tools/napi-symbol-coverage.test.sh

# The oracle lives outside the repository, so it may be absent on a machine that
# has not fetched it. That is reported as a skip rather than a pass: the gate
# cannot answer without the reference set, and silently passing would be the
# failure mode this whole step exists to prevent. A machine that has the oracle
# runs it, which is every CI image and every maintainer workstation.
if [ -x "${RUSTNODE_NAPI_ORACLE:-/tmp/oracle-dl/node-v28.0.0-nightly20261111e8c1160d20-linux-x64/bin/node}" ]; then
  ./tools/napi-symbol-coverage.py --rustnode "$RUSTNODE_NAPI_BINARY"
else
  echo "napi symbol coverage: no oracle binary; set RUSTNODE_NAPI_ORACLE to run it"
fi

step "the vendored JavaScript is unchanged"
./tools/verify-libjs.sh

step "the vendored llhttp is unchanged"
# The HTTP parser is C copied from Node's tree and never patched: a local edit
# would change parse behaviour away from the one Node ships, which is the only
# thing the binding exists to reproduce.
./tools/verify-llhttp.sh

step "the vendored merve is unchanged"
# Same reasoning one namespace over: the CommonJS export analysis decides what an
# ESM `import` of a CommonJS file sees, and a local edit to the lexer would
# change that answer without failing anything else.
./tools/verify-merve.sh

step "an http2 request completes and the process exits by itself"
# Two different http2 leaks have already hidden behind a `124` in this family: an
# accepted socket nobody owned, and a body whose END_STREAM was never sent. Both
# cost a timeout per file while looking like slowness. The probe asserts the
# exchange completed (`bodies`/`ends`) and that the loop drained on its own, so a
# silent early exit cannot pass it.
./tools/http2-lifecycle-probe.sh

step "the vendored nghttp2 is unchanged"
# HTTP/2's frame state machine, HPACK tables and error strings are `node:http2`'s
# compatibility surface, so the C library is held to the pinned Node revision
# rather than to a system libnghttp2 whose version depends on the host.
./tools/verify-nghttp2.sh

step "the vendored SQLite is unchanged"
# SQL semantics are `node:sqlite`'s whole compatibility surface, so the
# amalgamation is held to the pinned Node revision rather than to whatever a
# system library happens to be.
./tools/verify-sqlite.sh

step "the bundled root certificates match their input trust store"
# `src/root_certs.rs` is generated, and a generated file that nobody checks is
# free to drift from both the generator and the trust store it came from. This
# regenerates it into memory and compares, the same shape as
# `gen-options.py --check`. It is a bare statement so its status is the gate's:
# a stale blob fails here rather than shipping 118 roots that are not the ones
# the generator says they are.
python3 crates/rn-bind-crypto-x509/tools/gen-root-certs.py --check

step "the vendored certdata.txt is the one this was generated from"
# Separate from the step above because they can disagree: `--check` proves the
# module matches *this* file, and this proves the file is the pinned one. A
# changed trust store that was regenerated from would pass `--check` and still
# be a different set of roots from the one Node ships.
python3 tools/verify-certdata.py

step "the options table is what the pinned Node sources generate"
# `gen-options.py --check` has always existed and no gate step ran it, so the
# table could fall arbitrarily far behind `src/node_options.cc` while every
# check stayed green; it was two entries stale when this step was added
# (CLA-213). The generator needs a Node source tree, so this fetch brings one in
# (cached, `src/`-shaped, pinned by `tools/node-pin.toml`) rather than skipping.
#
# The two entries that differ today are a recorded decision, not a bug: making
# the committed table match the generator would change `getCLIOptionsValues`
# and `process.features`, which belongs to its own change. They are named
# individually in `tools/check-options-drift.py` with the exact fields and
# values that may differ, and that entry list ratchets: a third entry drifting,
# a named entry drifting in another field, or a named entry that stops
# differing all fail. The self-test runs first, because an allowance mechanism
# that cannot reject drift is the same defect one layer up.
python3 tools/check-options-drift.py --self-test
options_node_src="${NODE_SRC:-}"
if [ -z "$options_node_src" ]; then
  # Not `|| true`: a fetch failure here means the table cannot be compared, and
  # silently continuing would be the exact defect this step closes. The fetcher's
  # message says to set NODE_SRC, which is the way out on a machine with no
  # network and a checkout elsewhere.
  options_node_src="$(./tools/fetch-node-src.sh)"
fi
python3 tools/check-options-drift.py --node-src "$options_node_src"

printf '\nall checks passed\n'

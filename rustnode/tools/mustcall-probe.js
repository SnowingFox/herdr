// The negative control for `common.mustCall` enforcement.
//
// Node's `test/common/index.js` implements `mustCall` by counting expected
// invocations and comparing the count in a `process.on('exit')` handler. That
// makes the check only as good as the runtime's natural-exit event: if `exit`
// never fires, the count is never compared and a callback that was never called
// is indistinguishable from one that was.
//
// Each case below is a single, minimal program. The expected exit code is
// asserted by `tools/mustcall-negative-control.sh`, which also runs a case that
// must NOT fail, so a runtime that simply exits non-zero cannot satisfy the
// control.
//
// `RUSTNODE_MUSTCALL_COMMON` names the `test/common/index.js` of a Node test
// tree. The check is only meaningful against Node's own implementation: a
// local reimplementation would test this file rather than the runtime.
//
// One case — `handler-exits-one` — deliberately does not need it. It is the
// mechanism `runCallChecks` relies on, reduced to the two lines that matter, so
// the gate can guard it without a 103 MB test tree. See the note on that case.
'use strict';

const probe = process.argv[2];
// The cases that exercise the exit mechanism directly, with `test/common`
// removed. They are the only ones the gate can run without a Node checkout.
const TREE_FREE = new Set(['handler-exits-one', 'handler-exits-zero']);
const needsCommon = !TREE_FREE.has(probe);

const commonPath = process.env.RUSTNODE_MUSTCALL_COMMON;
if (needsCommon && !commonPath) {
  console.error('RUSTNODE_MUSTCALL_COMMON is not set');
  process.exit(2);
}
const common = needsCommon ? require(commonPath) : null;

switch (probe) {
  // The acceptance probe. `f` is created and deliberately never invoked, so
  // the process has one unsatisfied mustCall when the event loop empties.
  // Node runs the exit handler, which prints the mismatch and exits 1.
  case 'never-called': {
    const f = common.mustCall(() => {}, 1);
    void f;
    break;
  }

  // The same count, satisfied. A runtime that fails everything cannot pass
  // this one, which is what stops the control from accepting a blanket
  // non-zero exit.
  case 'called': {
    const f = common.mustCall(() => {}, 1);
    f();
    break;
  }

  // `mustNotCall` fails from the callback body, not from an exit handler, so
  // it is independent of the exit event and must be reported either way.
  case 'must-not-call-called': {
    common.mustNotCall(() => {})();
    break;
  }

  // `mustCallAtLeast` uses the same exit-handler path with a `minimum` field
  // rather than `exact`, so it covers the other half of `runCallChecks`.
  case 'at-least-never-called': {
    const f = common.mustCallAtLeast(() => {}, 2);
    void f;
    break;
  }

  // `mustSucceed` delegates to `mustCall`, so it inherits the exit-handler
  // path; the difference is that a truthy first argument calls `assert.ifError`
  // from the callback body.
  case 'must-succeed-never-called': {
    const f = common.mustSucceed(() => {});
    void f;
    break;
  }

  // The invocation happens after the script body, which is the common shape in
  // Node's own tests: a timer or a callback satisfies the count. This must
  // pass, so a runtime that checks the count too early is caught.
  case 'called-from-a-timer': {
    const f = common.mustCall(() => {}, 1);
    setTimeout(f, 1);
    break;
  }

  // The mechanism `runCallChecks` depends on, with `test/common` removed: a
  // listener that calls `process.exit(1)` from inside the exit handler.
  //
  // This case earns its own entry because nothing in the Rust suite can express
  // it. `crates/rn-cli/tests/event_loop.rs` has nine exit tests, but its
  // `same_as_node` helper asserts `status.success()` on *both* runtimes, so a
  // script that is supposed to exit 1 cannot go through it; and the one test
  // that does call `process.exit()` inside a handler passes no code, so it
  // asserts termination, not the status. A regression where the emit runs but a
  // re-entrant exit's code is dropped would leave every one of those tests
  // green while `mustCall` silently stopped failing files.
  //
  // No Node test tree is needed, which is what lets `tools/check.sh` run it.
  case 'handler-exits-one': {
    process.on('exit', () => {
      process.exit(1);
    });
    break;
  }

  // The tree-free must-pass counterpart. Without it `handler-exits-one` would
  // accept a runtime that fails every program, which is the same defect the
  // tree-dependent cases guard against one level up.
  case 'handler-exits-zero': {
    process.on('exit', () => {
      console.log('handler ran');
    });
    break;
  }

  default:
    console.error(`unknown probe: ${probe}`);
    process.exit(2);
}

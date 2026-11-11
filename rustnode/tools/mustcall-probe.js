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
'use strict';

const commonPath = process.env.RUSTNODE_MUSTCALL_COMMON;
if (!commonPath) {
  console.error('RUSTNODE_MUSTCALL_COMMON is not set');
  process.exit(2);
}
const common = require(commonPath);

const probe = process.argv[2];
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

  default:
    console.error(`unknown probe: ${probe}`);
    process.exit(2);
}

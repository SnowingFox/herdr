//! `process.domain` stores what is assigned to it, until `lib/domain.js` replaces
//! it — and that replacement is a no-op by design.
//!
//! This exists because a probe reported `process.domain = d; process.domain === d`
//! as `false` and the result was read as a divergence. It is not one: it is `false`
//! on **Node too**, and for a documented reason.
//!
//! `lib/domain.js:77` redefines `process.domain` as an AsyncLocalStorage-backed
//! getter/setter whose setter does nothing when no store exists:
//!
//! ```js
//! set: function(arg) {
//!   const store = getDomainStore();
//!   if (store) { setDomainStore({ domain: arg, stack: store.stack }); }
//!   // If no store exists, setting is a no-op (will be set when domain is entered)
//!   return arg;
//! }
//! ```
//!
//! So the answer depends on *whether `lib/domain.js` has been loaded*, which means
//! a bare read-back probe measures the module's state, not the property's. The two
//! tests below separate those: before `require('domain')` the property is the plain
//! data property `bootstrap/node.js:90` assigns and round-trips; after it, the
//! accessor deliberately does not store.
//!
//! Both runtimes are compared, because "it does not round-trip" is only a
//! divergence if Node does something different — and it does not.

use std::process::Command;

/// Runs `script` under `binary` and returns its trimmed stdout.
fn run(binary: &str, script: &str) -> String {
    let out = Command::new(binary)
        .args(["--no-deprecation", "-e", script])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    assert!(
        out.status.success(),
        "{binary} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The probe: what `process.domain` is, and whether an assignment survives, both
/// before and after `lib/domain.js` loads.
const PROBE: &str = r#"
const d = { marker: 'probe' };
const before = Object.getOwnPropertyDescriptor(process, 'domain');
process.domain = d;
const beforeRoundTrips = process.domain === d;
require('domain');
const after = Object.getOwnPropertyDescriptor(process, 'domain');
process.domain = d;
const afterRoundTrips = process.domain === d;
process.stdout.write(JSON.stringify({
  beforeKind: before.get ? 'accessor' : 'data',
  beforeRoundTrips,
  afterKind: after.get ? 'accessor' : 'data',
  afterRoundTrips,
}));
"#;

/// Before `lib/domain.js`, the property is `node.js:90`'s plain assignment.
///
/// `bootstrap/node.js` sets `process.domain = null`, which is an ordinary
/// enumerable/writable/configurable data property, so an assignment round-trips
/// and the value is the object that was stored — not a copy, not `undefined`.
#[test]
fn the_domain_setter_round_trips_before_domain_js_loads() {
    for (label, binary) in runtimes() {
        let report: serde_json::Value =
            serde_json::from_str(&run(&binary, PROBE)).expect("the probe produced JSON");
        assert_eq!(
            report["beforeKind"], "data",
            "{label}: before `require('domain')` the property is the data property \
             `bootstrap/node.js:90` assigns"
        );
        assert_eq!(
            report["beforeRoundTrips"], true,
            "{label}: an assignment has to survive the read-back"
        );
    }
}

/// After `lib/domain.js`, the accessor is a no-op without an active store —
/// on both runtimes.
///
/// This is the state the reported probe measured. Asserting it on both is what
/// makes it a fact about Node rather than a rustnode defect, and the assertion is
/// on `false` deliberately: if a future change made this round-trip, rustnode
/// would differ from Node in the other direction.
#[test]
fn the_domain_accessor_does_not_store_outside_a_domain_on_either_runtime() {
    for (label, binary) in runtimes() {
        let report: serde_json::Value =
            serde_json::from_str(&run(&binary, PROBE)).expect("the probe produced JSON");
        assert_eq!(
            report["afterKind"], "accessor",
            "{label}: `lib/domain.js` replaces the property with a getter/setter"
        );
        assert_eq!(
            report["afterRoundTrips"], false,
            "{label}: the AsyncLocalStorage-backed setter is a documented no-op when \
             no store exists, so the value must NOT read back"
        );
    }
}

/// The two runtimes under comparison.
fn runtimes() -> Vec<(&'static str, String)> {
    let mut list = vec![("rustnode", env!("CARGO_BIN_EXE_rustnode").to_string())];
    if let Some(oracle) = rn_node_oracle::require_oracle("process.domain parity") {
        list.push(("oracle", oracle.reference_path().to_string()));
    }
    list
}

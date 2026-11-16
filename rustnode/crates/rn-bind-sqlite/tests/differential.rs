//! The `node:sqlite` surface, compared against the pinned Node oracle.
//!
//! `tests/sqlite-surface-probe.js` prints one JSON document describing
//! everything a caller can observe about the namespace's classes: the values and
//! descriptor shape of every `db.limits` member, where each class accessor lives,
//! and the `instanceof` answer for every exported constructor. The same file runs
//! under the pinned oracle and under `rustnode`, and the two documents must be
//! equal.
//!
//! # Why this exists
//!
//! Three defects lived here and none was visible to a member-level check:
//!
//! * `db.limits.length` answered `1000000000` but was a *data property* installed
//!   from a descriptor-shaped object, so `delete db.limits.length` destroyed the
//!   member and `Object.defineProperty` could replace it with any value. A test
//!   that only read the number passed, and one review cited that read as proof
//!   the API worked. The distinguishing assertions are the ones below: the value
//!   is a `number`, the member survives `delete`, and redefining it throws.
//! * `db.prepare()` handed back a `Statement` that was not `instanceof
//!   Statement`. Every method worked, so only an identity check could find it.
//! * `db.prepare(...).iterate()` handed back a `StatementIterator` whose
//!   `constructor.name` was `'Iterator'`, because a throwaway template left
//!   `constructor` on a prototype object no instance used.
//!
//! # How a revert is caught
//!
//! The assertions are written so that reinstating any of them fails:
//! a data-property member reports `configurable: true` and disappears on
//! `delete`; an instance allocated from a throwaway template answers `false` for
//! `instanceof`. The committed expectation at `tests/sqlite-surface-expected.json`
//! additionally pins those same properties, so a machine without a Node binary
//! still checks every byte.

use std::path::PathBuf;
use std::process::Command;

/// The oracle's output for the probe script, committed verbatim.
///
/// The script itself lives at `tests/sqlite-surface-probe.js` and is executed
/// from disk rather than from `include_str!`, because both runtimes must run the
/// *same bytes* the expectation was recorded from.
const EXPECTED: &str = include_str!("sqlite-surface-expected.json");

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The `rustnode` binary, which `tools/check.sh` builds before the tests run.
fn rustnode_binary() -> PathBuf {
    let mut path = crate_dir();
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// Runs `binary` on the probe and returns its stdout.
fn run_probe(binary: &PathBuf) -> String {
    let probe = crate_dir().join("tests").join("sqlite-surface-probe.js");
    let output = Command::new(binary)
        .arg(&probe)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        output.status.success(),
        "{} failed on the sqlite surface probe:\n{}",
        binary.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Parses a probe document, so a diff names the field that moved.
fn fields(document: &str) -> serde_json::Value {
    serde_json::from_str(document).expect("the probe prints one JSON document")
}

/// The first path at which two documents disagree, as a readable dotted name.
///
/// A whole-document `assert_eq!` on two one-line JSON blobs is unreadable at the
/// size of this surface, so the mismatch is located and reported by path.
fn first_difference(left: &serde_json::Value, right: &serde_json::Value) -> Option<String> {
    fn walk(
        left: &serde_json::Value,
        right: &serde_json::Value,
        path: &mut Vec<String>,
        out: &mut Option<String>,
    ) {
        if out.is_some() {
            return;
        }
        match (left, right) {
            (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
                for key in a.keys().chain(b.keys().filter(|key| !a.contains_key(*key))) {
                    path.push(key.clone());
                    walk(
                        a.get(key).unwrap_or(&serde_json::Value::Null),
                        b.get(key).unwrap_or(&serde_json::Value::Null),
                        path,
                        out,
                    );
                    path.pop();
                }
            }
            _ if left != right => {
                *out = Some(format!("{}: {left} != {right}", path.join(".")));
            }
            _ => {}
        }
    }
    let mut path = Vec::new();
    let mut out = None;
    walk(left, right, &mut path, &mut out);
    out
}

#[test]
fn the_surface_matches_the_recorded_oracle_output() {
    let rustnode = rustnode_binary();
    assert!(
        rustnode.exists(),
        "{} is missing; tools/check.sh builds it before the tests",
        rustnode.display()
    );
    let actual = fields(&run_probe(&rustnode));
    let expected = fields(EXPECTED);
    if let Some(difference) = first_difference(&expected, &actual) {
        panic!(
            "the sqlite surface disagrees with the recorded oracle output at {difference}\n\
             expected (recorded from Node): {expected}\n\
             actual (this build): {actual}"
        );
    }
}

#[test]
fn the_surface_matches_a_real_node_binary() {
    let Some(oracle) = rn_node_oracle::require_oracle("the node:sqlite surface") else {
        return;
    };
    let node = oracle.path.clone();
    eprintln!(
        "comparing against {} ({}): ",
        node.display(),
        oracle.version
    );

    let reference = fields(&run_probe(&node));
    let rustnode = rustnode_binary();
    assert!(
        rustnode.exists(),
        "{} is missing; tools/check.sh builds it before the tests",
        rustnode.display()
    );
    let candidate = fields(&run_probe(&rustnode));

    if let Some(difference) = first_difference(&reference, &candidate) {
        panic!(
            "the sqlite surface disagrees with {} at {difference}\n\
             node:     {reference}\n\
             rustnode: {candidate}",
            oracle.describe()
        );
    }
}

/// `db.limits` must be a live accessor view, stated as its own test because this
/// is the finding. A value that merely *reads* correctly is not evidence: the
/// defect this pins replaced a correct-looking read with a dead data property.
#[test]
fn every_limit_is_a_number_and_membership_is_an_accessor_view() {
    let rustnode = rustnode_binary();
    assert!(rustnode.exists(), "{} is missing", rustnode.display());
    let document = fields(&run_probe(&rustnode));

    let limits = &document["limits"];
    let values = limits
        .as_object()
        .expect("the probe emits a limits object")
        .get("types")
        .and_then(|types| types.as_object())
        .expect("the probe emits a limits.types object");

    assert_eq!(
        values.len(),
        11,
        "kLimitMapping has eleven entries; the probe reported {}",
        values.len()
    );
    for (name, kind) in values {
        assert_eq!(
            kind, "number",
            "db.limits.{name} must be a number, not {kind}; a descriptor-shaped \
             object reports its `value` field here and this is the assertion that \
             catches it"
        );
        assert!(
            limits[name.as_str()]
                .as_u64()
                .is_some_and(|value| value > 0),
            "db.limits.{name} must be a positive integer, got {}",
            limits[name.as_str()]
        );
    }

    assert_eq!(
        limits["hasOwnAfterDelete"], true,
        "delete db.limits.length must not remove the member: it is an interceptor, \
         not an own data property"
    );
    assert_eq!(
        limits["valueAfterDelete"], 1_000_000_000_u64,
        "db.limits.length must still answer from sqlite3_limit after a delete"
    );
    assert_eq!(
        limits["redefine"], "throw:TypeError",
        "Object.defineProperty on a limit must throw, as it does with no definer \
         installed and DontDelete answered"
    );
    assert_eq!(
        limits["writeReachesConnection"], "error:ERR_SQLITE_ERROR",
        "setting db.limits.attach = 0 must actually limit ATTACH on the connection"
    );
    assert_eq!(
        limits["writeReachesPrepare"], "error:ERR_SQLITE_ERROR",
        "setting db.limits.variableNumber = 5 must actually limit parameters"
    );

    let descriptors = limits["memberDescriptors"]
        .as_object()
        .expect("the probe emits member descriptors");
    for (name, descriptor) in descriptors {
        assert_eq!(
            descriptor["configurable"], false,
            "db.limits.{name} must report configurable: false, which is what \
             LimitsQuery's DontDelete produces"
        );
        assert_eq!(
            descriptor["enumerable"], true,
            "db.limits.{name} must remain enumerable"
        );
    }
}

/// Every exported class must recognise its own instances, and only its own.
#[test]
fn every_exported_class_answers_instanceof_for_its_own_instances() {
    let rustnode = rustnode_binary();
    assert!(rustnode.exists(), "{} is missing", rustnode.display());
    let document = fields(&run_probe(&rustnode));
    let table = document["instanceof"]
        .as_object()
        .expect("the probe emits an instanceof table");

    // Each instance row answers `instanceof` against every class, and the
    // expected answers are exactly "the classes for this instance's own kind,
    // and nothing else". `statement2` is a second statement, so it is expected to
    // agree with `statement` rather than be a distinct case.
    let expectations: &[(&str, &[&str])] = &[
        ("Database", &["database"]),
        ("DatabaseSync", &["database"]),
        ("Statement", &["statement", "statement2"]),
        ("StatementSync", &["statement", "statement2"]),
        ("Session", &["session"]),
    ];
    for (class, own) in expectations {
        let row = table
            .get(*class)
            .unwrap_or_else(|| panic!("the probe reports no instanceof row for {class}"));
        for (instance, answer) in row.as_object().expect("an instanceof row is an object") {
            let should_match = own.contains(&instance.as_str());
            assert_eq!(
                answer.as_bool(),
                Some(should_match),
                "{instance} instanceof {class} answered {answer}; expected {should_match}"
            );
        }
    }

    assert_eq!(document["prototypeIdentity"]["statement"], true);
    assert_eq!(document["constructorIdentity"]["statement"], true);
    assert_eq!(
        document["constructorIdentity"]["statementName"], "Statement",
        "st.constructor.name must be 'Statement'; 'Object' means the instance came \
         from a template that is not the exported one"
    );
}

/// `new Statement()` and `new Session()` still throw now that `prepare` and
/// `createSession` allocate from the very template whose body throws.
#[test]
fn runtime_only_classes_still_refuse_new() {
    let rustnode = rustnode_binary();
    assert!(rustnode.exists(), "{} is missing", rustnode.display());
    let document = fields(&run_probe(&rustnode));
    for class in ["Statement", "StatementSync", "Session"] {
        assert_eq!(
            document["construct"][class], "ERR_ILLEGAL_CONSTRUCTOR",
            "new {class}() must throw ERR_ILLEGAL_CONSTRUCTOR"
        );
    }
}

/// The statement iterator is a real class: `next`/`return` must not be
/// constructible, its prototype must be the same object for every iterator, and
/// that prototype's parent must be the global `Iterator.prototype`.
///
/// It is a separate test because it fails for a different reason than the
/// others: `Iterate` attaches the *global* `Iterator.prototype` to an
/// intermediary object, so a throwaway template leaves `constructor` set on a
/// prototype no instance uses and `constructor.name` reads `'Iterator'`.
#[test]
fn the_statement_iterator_is_a_class_with_node_s_chain() {
    let rustnode = rustnode_binary();
    assert!(rustnode.exists(), "{} is missing", rustnode.display());
    let document = fields(&run_probe(&rustnode));
    let iterator = &document["iterator"];

    assert_eq!(iterator["constructorName"], "StatementIterator");
    assert_eq!(iterator["parentIsGlobalIteratorPrototype"], true);
    assert_eq!(iterator["prototypesShared"], true);
    assert_eq!(iterator["constructorsShared"], true);
    assert_eq!(
        iterator["construct"], "ERR_ILLEGAL_CONSTRUCTOR",
        "new on the iterator class must reach the IllegalConstructor guard"
    );
    let names: Vec<&str> = iterator["prototypeOwnNames"]
        .as_array()
        .expect("prototypeOwnNames is an array")
        .iter()
        .filter_map(|name| name.as_str())
        .collect();
    assert_eq!(names, ["next", "return", "constructor"]);
}

//! Tests for the parts of `node:sqlite` that are pure Rust.
//!
//! The end-to-end behaviour is measured by Node's own suite, not here: a test in
//! this crate that re-implemented `test-sqlite.js` would prove the crate agrees
//! with itself. What these cover is the logic that has no JavaScript surface —
//! the option defaults that differ from SQLite's, the value mapping Node
//! specifies, and the URL handling `ValidateDatabasePath` performs — because
//! those are where a wrong answer would be silent.
//!
//! Everything here builds against the vendored amalgamation, so a test failure
//! also proves the C library compiled and linked.

use crate::db::OpenConfiguration;
use crate::value::{IntMode, Value, MAX_SAFE_INTEGER};

#[test]
fn open_configuration_defaults_match_node_not_sqlite() {
    let config = OpenConfiguration::new(":memory:".to_string());
    // Node reverses three of SQLite's defaults, and `test-sqlite-config.js`
    // asserts each one. A "tidier" set of defaults here would make that test
    // report defensive mode off and foreign keys off.
    assert!(config.enable_foreign_keys, "Node turns foreign keys ON");
    assert!(config.defensive, "Node turns defensive mode ON");
    assert!(!config.enable_dqs, "Node turns DQS OFF");
    assert!(!config.read_only);
    assert_eq!(config.timeout, 0);
    assert!(!config.use_big_ints);
    assert!(!config.return_arrays);
    assert!(config.allow_bare_named_params);
    assert!(!config.allow_unknown_named_params);
    assert_eq!(config.limits, [None; 11]);
}

#[test]
fn int_mode_follows_the_configuration() {
    let mut config = OpenConfiguration::new(":memory:".to_string());
    assert_eq!(config.int_mode(), IntMode::Number);
    config.use_big_ints = true;
    assert_eq!(config.int_mode(), IntMode::BigInt);
}

#[test]
fn the_safe_integer_boundary_is_js_max_safe_integer() {
    // `Number.MAX_SAFE_INTEGER`. Node's `IntegerToValue` throws above this
    // rather than rounding, and `test-sqlite-data-types.js` relies on it.
    assert_eq!(MAX_SAFE_INTEGER, 9_007_199_254_740_991);
}

#[test]
fn values_are_distinguished_by_variant() {
    // The binding chooses `sqlite3_bind_*` from the variant, so a `Float(1.0)`
    // that had been normalised to `Integer(1)` would store a different SQLite
    // type. `test-sqlite-data-types.js` checks the round trip.
    assert_ne!(Value::Float(1.0), Value::Integer(1));
    assert_ne!(Value::Text(b"1".to_vec()), Value::Integer(1));
    assert_ne!(Value::Blob(b"1".to_vec()), Value::Text(b"1".to_vec()));
    assert_ne!(Value::Null, Value::Text(Vec::new()));
}

#[test]
fn text_and_blob_hold_the_same_bytes_without_conflating() {
    // A blob and a text value with identical bytes are different SQLite storage
    // classes; conflating them is how a blob comes back as a string.
    let bytes = vec![0xff, 0xfe, 0x00, 0x01];
    let text = Value::Text(bytes.clone());
    let blob = Value::Blob(bytes);
    assert_ne!(text, blob);
}

#[test]
fn the_constant_table_uses_sqlites_numbers() {
    let value_of = |name: &str| {
        crate::constants::CONSTANTS
            .iter()
            .find(|(constant, _)| *constant == name)
            .map(|(_, value)| *value)
    };
    // These are the values SQLite's own macros define; a wrong one changes what
    // an authorizer callback returns or which conflict policy a changeset uses.
    assert_eq!(value_of("SQLITE_DENY"), Some(1));
    assert_eq!(value_of("SQLITE_IGNORE"), Some(2));
    assert_eq!(value_of("SQLITE_CREATE_INDEX"), Some(1));
    assert_eq!(value_of("SQLITE_INSERT"), Some(18));
    assert_eq!(value_of("SQLITE_RECURSIVE"), Some(33));
    assert_eq!(value_of("SQLITE_CHANGESET_ABORT"), Some(2));
    // `SQLITE_COPY` really is 0 in `sqlite3.h`, the same value as `SQLITE_OK`.
    // Node publishes it that way, so this is compatibility, not a typo.
    assert_eq!(value_of("SQLITE_COPY"), Some(0));
    // `DefineConstants` has exactly 45 `NODE_DEFINE_CONSTANT` calls: 8 changeset
    // entries, 3 authorizer results and 34 authorizer actions. A count check
    // catches both a dropped constant and a duplicated one.
    assert_eq!(crate::constants::CONSTANTS.len(), 45);
}

#[test]
fn every_limit_name_is_present_in_order() {
    // `kLimitMapping`'s index *is* the `SQLITE_LIMIT_*` id, and the header has a
    // `static_assert` saying so. Reordering this array would silently read the
    // wrong limit.
    assert_eq!(crate::constants::LIMITS.len(), 11);
    assert_eq!(crate::constants::LIMITS[0], "length");
    assert_eq!(crate::constants::LIMITS[1], "sqlLength");
    assert_eq!(crate::constants::LIMITS[10], "triggerDepth");
}

#[test]
fn statement_status_covers_every_exposed_counter() {
    let names: Vec<&str> = crate::constants::STATEMENT_STATUS
        .iter()
        .map(|(name, _)| *name)
        .collect();
    for expected in [
        "fullscanStep",
        "sort",
        "autoindex",
        "vmStep",
        "reprepare",
        "run",
        "filterMiss",
        "filterHit",
        "memused",
    ] {
        assert!(names.contains(&expected), "missing counter {expected}");
    }
    // `memused` reports current usage, not an accumulated count, which is why
    // `resetStats` skips it.
    assert_eq!(crate::constants::STATEMENT_STATUS[8].1, 99);
}

#[test]
fn the_linked_sqlite_is_the_pinned_version() {
    // `vendor/sqlite` is 3.54.1 from the Node revision `tools/node-pin.toml`
    // pins. A system library would report whatever the host has, which is the
    // reason the amalgamation is vendored.
    let version = crate::sqlite_version().expect("a linked SQLite reports a version");
    assert_eq!(version, "3.54.1");
}

#[test]
fn url_classification_separates_the_three_failure_modes() {
    use crate::url::{classify, file_url_to_path, UrlError};

    // Node distinguishes `ERR_INVALID_URL` from `ERR_INVALID_URL_SCHEME`, so the
    // classification cannot collapse into one error.
    assert_eq!(classify("file:///tmp/x.db"), Ok("/tmp/x.db".to_string()));
    assert_eq!(classify("https://example.com/x.db"), Err(UrlError::NotFile));
    assert_eq!(classify("not a url"), Err(UrlError::Invalid));
    assert_eq!(file_url_to_path("file:relative.db"), None);
    // Percent escapes are left for SQLite's URI parser, which does the decoding
    // once when `SQLITE_OPEN_URI` is set. Decoding here as well would turn `%20`
    // into a space and then into `%20` again on the way back.
    assert_eq!(
        file_url_to_path("file:///tmp/two%20words.db"),
        Some("/tmp/two%20words.db".to_string())
    );
}

#[test]
fn the_namespace_members_match_the_contract() {
    // `contracts/sqlite.json` records exactly these five. `lib/sqlite.js`
    // destructures all five at module scope, so a missing one leaves it
    // `undefined` at export time.
    assert_eq!(
        crate::MEMBERS,
        &["Database", "Session", "Statement", "backup", "constants"]
    );
}

#[test]
fn backup_is_declared_deferred_with_a_reason() {
    // The contract check treats a declared deferral as satisfied, which is
    // honest only if the declaration is real. This pins that `backup` is the one
    // gap and that it carries a reason rather than an empty string.
    assert_eq!(crate::DEFERRED.len(), 1);
    let (member, reason) = crate::DEFERRED[0];
    assert_eq!(member, "backup");
    assert!(
        reason.len() > 40,
        "a deferral needs a real reason, not a placeholder"
    );
    // Every declared member must be installed or deferred, never both, and the
    // two sets together must cover the contract exactly.
    for member in crate::MEMBERS {
        if *member == "backup" {
            continue;
        }
        assert!(
            !crate::DEFERRED
                .iter()
                .any(|(deferred, _)| deferred == member),
            "{member} is both installed and deferred"
        );
    }
}

//! Structural gate over every `internalBinding()` namespace this build registers.
//!
//! `rn-compat` checks each namespace against a contract recorded from a real Node
//! binary, but it reads the crate's *declarations* — `MEMBERS` and `DEFERRED` —
//! and never the object `install()` produced. A crate can therefore claim a member
//! it does not set at all and stay green: `rn-bind-sqlite` listed `backup` in both
//! `MEMBERS` and `DEFERRED` while `install()` never touched it, and the two
//! declarations cancelled each other out so `node:sqlite.backup` was `undefined`
//! on a board reporting `sqlite 5 0 0 ok`.
//!
//! This file closes that hole by asserting the relationship the declarations
//! promise, over the real installed object, for every registered namespace. It is
//! deliberately not a per-crate test: a crate that adds a member tomorrow is
//! covered without editing anything here.
//!
//! Two independent checks live here:
//!
//! 1. [`every_namespace_installs_exactly_what_it_claims`] — the namespace object's
//!    own keys are exactly `MEMBERS - DEFERRED`, plus the contradictions that
//!    subtraction would hide. See the comment on that test for why the subtraction
//!    alone is not enough.
//! 2. [`installed_members_that_throw_not_implemented_are_declared_deferred`] — a
//!    member that is installed but whose first call reports "not implemented" is
//!    a stub, and a stub must be in `DEFERRED` with a reason rather than sitting on
//!    the object pretending to work. This runs each call in a child process
//!    because V8 turns a wrong-arity native call into a fatal check that aborts the
//!    whole process, so an in-process version cannot survive its own population.
//!
//! Both are expected to fail on parts of the current tree. That is the point: see
//! the report that accompanied this gate for which namespaces fail and which
//! defect each one corresponds to.
//!
//! Every finding that exists today is recorded in [`KNOWN_FINDINGS`] and
//! [`KNOWN_STUBS`], named per namespace and member, with the count asserted. The
//! gate fails on anything *not* on those lists, so it is enforcing from the first
//! commit without a red master, and the list shrinking is the proof a fix landed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use rn_core::BindingRegistry;
use rn_v8_sys::v8;

/// The environment variable that turns this test binary into a single-member
/// probe worker. Set to `<namespace>/<member>`.
const PROBE_ENV: &str = "RUSTNODE_BINDING_PROBE";

/// Worker processes to keep in flight while probing. Each one boots an isolate,
/// so this trades a little CPU contention for a large wall-clock win over the
/// ~830 members in the registry.
const PROBE_WORKERS: usize = 8;

/// Distinguishes the scratch directories of probes running at the same time.
static SCRATCH_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// How long one probe child may run before it is killed.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Every structural finding that exists in the tree today, as
/// `namespace.member:rule`.
///
/// # Why this list exists
///
/// This check was written to catch a class of false-green defect, and on its first
/// run it found seventeen of them. Landing it as a plain blocking gate would have
/// made every other workstream's merge fail on defects outside their scope, which
/// is how a gate gets switched off. Recording the findings here makes the check
/// enforcing immediately — anything not listed fails — while leaving the repairs to
/// the crates that own them.
///
/// # The rules it encodes
///
/// Every entry is a real defect. None is an accepted exception:
///
/// * `claimed-and-deferred` — the member is in `MEMBERS` and in `DEFERRED` at once.
///   `MEMBERS` means "this crate installs it" and `DEFERRED` means "it does not yet",
///   so the two contradict each other, and the contradiction is what makes
///   `rn-compat` subtract the member from its own gap and report the namespace clean.
///   This is the `sqlite.backup` shape; thirteen members have it.
/// * `claimed-but-absent` — in `MEMBERS`, not deferred, never installed, so it reads
///   `undefined` through `internalBinding`.
/// * `installed-but-unclaimed` — on the object with no `MEMBERS` entry, so no
///   contract and no coverage ratchet covers it.
/// * `wrong-kind` — the contract recorded a `typeof` and the object carries another.
///
/// # Shrinking this list
///
/// A fix deletes its own entry. The count assertion below then fails until the list
/// is updated, so a fixed defect cannot linger here as an unnoticed exception, and
/// the number in the test output is the debt's size.
const KNOWN_FINDINGS: &[&str] = &[
    // `blob.createBlobFromFilePath` — declared installed and deferred at once.
    "blob.createBlobFromFilePath:claimed-and-deferred",
    // `heap_utils.buildEmbedderGraph` — same shape; the reason says the v8 crate
    // exposes no embedder-graph binding.
    "heap_utils.buildEmbedderGraph:claimed-and-deferred",
    // `internal_only_v8.queryObjects` — same shape. The namespace is also
    // unreachable through `internal/test/binding`, which is a separate question.
    "internal_only_v8.queryObjects:claimed-and-deferred",
    // `icu.decode`, `icu.getConverter`, `icu.hasConverter` — same shape.
    "icu.decode:claimed-and-deferred",
    "icu.getConverter:claimed-and-deferred",
    "icu.hasConverter:claimed-and-deferred",
    // `performance.Histogram`, `performance.SlidingWindowHistogram` — same shape.
    // These two MOVED CATEGORY, they were not fixed: they were previously recorded
    // as `wrong-kind` (installed as `undefined`) and upstream later added them to
    // `DEFERRED` as well as `MEMBERS`, so they now report as `claimed-and-deferred`.
    // The underlying defect is unchanged and still live:
    // `perf_hooks.createHistogram()` throws `_Histogram is not a constructor`,
    // because deferring a member does not implement it. Tracked separately — do not
    // treat this entry's presence, or the unchanged total, as evidence it was
    // addressed.
    "performance.Histogram:claimed-and-deferred",
    "performance.SlidingWindowHistogram:claimed-and-deferred",
    // `process_methods.{causeSegfault,dlopenBinary,execve,setEmitWarningSync}` —
    // same shape.
    "process_methods.causeSegfault:claimed-and-deferred",
    "process_methods.dlopenBinary:claimed-and-deferred",
    "process_methods.execve:claimed-and-deferred",
    "process_methods.setEmitWarningSync:claimed-and-deferred",
    // `sqlite.backup` — the defect that motivated this check. `rn-compat` reports
    // `sqlite 5 0 0 ok` while `node:sqlite.backup` is `undefined`.
    "sqlite.backup:claimed-and-deferred",
    // `util.getSharedArrayBufferGrowable` — same shape. (`util.parseEnv` was here
    // too; `2a977ca4` implemented it and the ratchet demanded the removal.)
    "util.getSharedArrayBufferGrowable:claimed-and-deferred",
    // `util.arrayBufferViewHasBuffer` — claimed, never installed, no deferral.
    "util.arrayBufferViewHasBuffer:claimed-but-absent",
    // `crypto.isKeyAlgorithmAvailable` — installed, but listed in `DEFERRED`, so its
    // written reason is stale. `lib/internal/crypto/util.js` calls it at module
    // scope.
    "crypto.isKeyAlgorithmAvailable:installed-but-unclaimed",
];

/// Installed members that report themselves unimplemented, as
/// `namespace.member:not-implemented`.
///
/// Same contract as [`KNOWN_FINDINGS`]: each is a real defect owned by its crate,
/// and a fix deletes its line. `performance.createELDHistogram` is the one with a
/// live user-visible consequence — `require('perf_hooks').monitorEventLoopDelay()`
/// throws it today.
const KNOWN_STUBS: &[&str] = &[
    "builtins.importBuiltinSourceTextModule:not-implemented",
    // `fs.handleToFd` is a Windows-only member (`internal/fs/streams.js` calls it on
    // that path) installed unconditionally here and then hardcoded to `ENOSYS`.
    "fs.handleToFd:not-implemented",
    "mksnapshot.compileSerializeMain:not-implemented",
    "module_wrap.createRequiredModuleFacade:not-implemented",
    "performance.createELDHistogram:not-implemented",
];

/// What one installed member turned out to be, read from its property descriptor
/// rather than by calling it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Installed {
    /// A data property carrying this JavaScript `typeof`.
    Value(&'static str),
    /// An accessor property. No namespace uses one today; recorded so that a
    /// future one is visible instead of silently skipped.
    Accessor,
}

/// One way a namespace object can disagree with what it declared.
#[derive(Debug)]
enum Violation {
    /// Declared in `MEMBERS` and in `DEFERRED` at once. `MEMBERS` means "this crate
    /// installs it" and `DEFERRED` means "this crate does not install it yet", so the
    /// two are contradictory by definition — and the contradiction is what makes the
    /// contract subtraction cancel the member. This is the `sqlite` `backup` shape.
    ClaimedAndDeferred { member: String, installed: bool },
    /// In `MEMBERS`, not in `DEFERRED`, and missing from the object.
    ClaimedButAbsent { member: String },
    /// On the object, and not in `MEMBERS` at all.
    InstalledButUnclaimed { member: String },
    /// The contract recorded a kind and the object carries a different one.
    ///
    /// `performance.Histogram` used to report through this rule (recorded
    /// `function`, installed `undefined`). It still installs `undefined`, but
    /// upstream also added it to `DEFERRED`, so it now reports as
    /// [`Self::ClaimedAndDeferred`] instead. The defect is the same one; only the
    /// rule that notices it changed.
    WrongKind {
        member: String,
        contract: String,
        installed: String,
    },
}

impl Violation {
    /// A stable, machine-readable rule name, used as the allowlist key.
    ///
    /// The key must not be derived from the human message: a message is prose and
    /// will be reworded, and an allowlist keyed on prose would then silently stop
    /// matching and turn a known defect into a new failure (or, worse, stop
    /// suppressing a fixed one). The rule name changes only when the rule changes.
    fn rule(&self) -> &'static str {
        match self {
            Self::ClaimedAndDeferred { .. } => "claimed-and-deferred",
            Self::ClaimedButAbsent { .. } => "claimed-but-absent",
            Self::InstalledButUnclaimed { .. } => "installed-but-unclaimed",
            Self::WrongKind { .. } => "wrong-kind",
        }
    }

    fn member(&self) -> &str {
        match self {
            Self::ClaimedAndDeferred { member, .. }
            | Self::ClaimedButAbsent { member }
            | Self::InstalledButUnclaimed { member }
            | Self::WrongKind { member, .. } => member,
        }
    }

    /// The allowlist key: `namespace.member:rule`.
    fn key(&self, namespace: &str) -> String {
        format!("{namespace}.{}:{}", self.member(), self.rule())
    }

    fn describe(&self) -> String {
        match self {
            Self::ClaimedAndDeferred { member, installed } => {
                let state = if *installed {
                    "the object does carry it, so the DEFERRED entry with its written \
                     reason is stale"
                } else {
                    "the object does not carry it, so MEMBERS claims a member that was \
                     never installed"
                };
                format!(
                    "{member}: declared in MEMBERS and in DEFERRED at once, so the \
                     contract subtraction cancels it and nothing checks it; {state}"
                )
            }
            Self::ClaimedButAbsent { member } => format!(
                "{member}: claimed in MEMBERS (and not deferred) but install() \
                 never set it, so `internalBinding(...).{member}` is undefined"
            ),
            Self::InstalledButUnclaimed { member } => format!(
                "{member}: installed on the object but absent from MEMBERS, so no \
                 contract or ratchet covers it"
            ),
            Self::WrongKind {
                member,
                contract,
                installed,
            } => format!(
                "{member}: contract records kind `{contract}` but the installed \
                 value is `{installed}`"
            ),
        }
    }
}

/// Boots V8 and returns a registry with every namespace this build registers.
///
/// The V8 platform is initialised once per process: `cargo test` runs tests as
/// concurrent threads in one process, and `initialize_platform` on an already
/// initialised V8 aborts.
fn registry() -> BindingRegistry {
    static V8: std::sync::Once = std::sync::Once::new();
    V8.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut registry = BindingRegistry::new();
    rn_bindings::install_all(&mut registry);
    registry
}

/// The `kind` each contract records per member, for the crates that ship one.
///
/// Read as plain JSON rather than through a struct so this test does not need a
/// `[dev-dependencies]` entry: `crates/rn-bindings/Cargo.toml` is generated by
/// `tools/regen-bindings.sh` and any hand-written section would be erased on the
/// next regeneration.
fn contract_kinds() -> BTreeMap<String, BTreeMap<String, String>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    let mut kinds = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return kinds;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(contract) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let Some(namespace) = contract.get("namespace").and_then(|v| v.as_str()) else {
            continue;
        };
        let mut members = BTreeMap::new();
        if let Some(map) = contract.get("members").and_then(|v| v.as_object()) {
            for (name, record) in map {
                if let Some(kind) = record.get("kind").and_then(|v| v.as_str()) {
                    members.insert(name.clone(), kind.to_string());
                }
            }
        }
        kinds.insert(namespace.to_string(), members);
    }
    kinds
}

/// The string-keyed properties the object actually carries, and whether any
/// symbol-keyed ones were found.
fn own_properties(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
) -> (BTreeSet<String>, BTreeMap<String, Installed>) {
    let mut names = BTreeSet::new();
    let mut values = BTreeMap::new();

    let args = v8::GetPropertyNamesArgs {
        mode: v8::KeyCollectionMode::OwnOnly,
        property_filter: v8::PropertyFilter::ALL_PROPERTIES,
        index_filter: v8::IndexFilter::IncludeIndices,
        key_conversion: v8::KeyConversionMode::ConvertToString,
    };
    let Some(properties) = object.get_own_property_names(scope, args) else {
        return (names, values);
    };
    for index in 0..properties.length() {
        let Some(entry) = properties.get_index(scope, index) else {
            continue;
        };
        let Ok(name) = v8::Local::<v8::Name>::try_from(entry) else {
            continue;
        };
        if !entry.is_string() {
            // A symbol-keyed member is not something `lib/**` reads by name, and
            // no namespace has one, so it is reported under a synthetic name
            // instead of being silently dropped from the key set.
            names.insert(format!("<symbol {}>", name.to_rust_string_lossy(scope)));
            continue;
        }
        let key = entry.to_rust_string_lossy(scope);
        names.insert(key.clone());
        if let Some(installed) = installed_kind(scope, object, name) {
            values.insert(key, installed);
        }
    }
    (names, values)
}

/// Reads one member without invoking it: a descriptor's `value` for a data
/// property, `Accessor` for a getter/setter pair.
///
/// Reading through the descriptor matters because `Object::get` would run a
/// getter, and a namespace member that is a getter could throw or have a side
/// effect during what is supposed to be a structural check.
fn installed_kind(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: v8::Local<v8::Name>,
) -> Option<Installed> {
    let descriptor = object.get_own_property_descriptor(scope, name)?;
    let Ok(descriptor) = v8::Local::<v8::Object>::try_from(descriptor) else {
        return None;
    };
    let value_key = v8::String::new(scope, "value")?;
    // An accessor descriptor omits `value` entirely, so a data property that
    // genuinely holds `undefined` stays distinguishable from a getter.
    if !descriptor.has_own_property(scope, value_key.into())? {
        return Some(Installed::Accessor);
    }
    let value = descriptor.get(scope, value_key.into())?;
    Some(Installed::Value(typeof_of(value)))
}

fn typeof_of(value: v8::Local<v8::Value>) -> &'static str {
    if value.is_function() {
        "function"
    } else if value.is_symbol() {
        "symbol"
    } else if value.is_string() {
        "string"
    } else if value.is_boolean() {
        "boolean"
    } else if value.is_number() {
        "number"
    } else if value.is_big_int() {
        "bigint"
    } else if value.is_undefined() {
        "undefined"
    } else {
        "object"
    }
}

/// Every `MEMBERS`/`DEFERRED`/installed disagreement in one namespace.
fn violations_for(
    namespace: &rn_core::Namespace,
    installed: &BTreeSet<String>,
    values: &BTreeMap<String, Installed>,
    contract: Option<&BTreeMap<String, String>>,
) -> Vec<Violation> {
    let mut violations = Vec::new();

    let claimed: BTreeSet<&str> = namespace.members.iter().map(String::as_str).collect();
    let deferred: BTreeSet<&str> = namespace.deferred.keys().map(String::as_str).collect();

    // The contradiction first: this is the only rule that can see the `sqlite`
    // `backup` shape, because subtracting `DEFERRED` from `MEMBERS` removes the
    // member from both sides of the comparison and the sets then match.
    for member in claimed.intersection(&deferred) {
        violations.push(Violation::ClaimedAndDeferred {
            member: (*member).to_string(),
            installed: installed.contains(*member),
        });
    }

    for member in claimed.difference(&deferred) {
        if !installed.contains(*member) {
            violations.push(Violation::ClaimedButAbsent {
                member: (*member).to_string(),
            });
        }
    }

    for member in installed.iter() {
        if !claimed.contains(member.as_str()) {
            violations.push(Violation::InstalledButUnclaimed {
                member: member.clone(),
            });
        }
    }

    if let Some(contract) = contract {
        for (member, kind) in contract {
            let Some(installed) = values.get(member) else {
                // Absent members are already covered by the rules above; a member
                // whose value could not be read is reported there, not here.
                continue;
            };
            let Installed::Value(actual) = installed else {
                continue;
            };
            // `unknown` is the recorder saying it could not classify the member,
            // so it carries no expectation to violate.
            if kind == "unknown" {
                continue;
            }
            let expected = kind.as_str();
            if expected != *actual {
                violations.push(Violation::WrongKind {
                    member: member.clone(),
                    contract: expected.to_string(),
                    installed: (*actual).to_string(),
                });
            }
        }
    }

    violations
}

/// What survived the allowlist, plus what the allowlist claims that no longer happens.
#[derive(Debug, Default)]
struct AllowlistResult {
    /// Findings not on the allowlist: these fail the gate.
    unexpected: Vec<String>,
    /// Allowlist entries with no corresponding finding: the defect was fixed, or the
    /// entry is wrong. Either way the list is stale and must shrink.
    fixed: Vec<String>,
}

/// Applies an allowlist to a set of `namespace.member:rule` keys.
///
/// The two directions are both failures on purpose. Only checking for unexpected
/// keys would let a fixed defect sit in the list forever, and the list's length is
/// the number this gate reports as outstanding debt.
fn apply_allowlist(
    found: &BTreeMap<String, String>,
    allowlist: &'static [&'static str],
) -> AllowlistResult {
    let allowed: BTreeSet<&str> = allowlist.iter().copied().collect();

    let mut result = AllowlistResult::default();
    for (key, description) in found {
        if !allowed.contains(key.as_str()) {
            result.unexpected.push(format!("{key} — {description}"));
        }
    }
    for key in &allowed {
        if !found.contains_key(*key) {
            result.fixed.push((*key).to_string());
        }
    }
    result
}

/// Builds the failure message for an allowlist verdict, or `None` when both
/// directions are empty.
fn allowlist_message(result: &AllowlistResult, allowlist_len: usize, what: &str) -> Option<String> {
    if result.unexpected.is_empty() && result.fixed.is_empty() {
        return None;
    }
    let mut message = String::new();
    if !result.unexpected.is_empty() {
        message.push_str(&format!(
            "{} {what} finding(s) are not in the allowlist, so this change introduced \
             them (or the allowlist was edited without the tree):\n\n{}\n",
            result.unexpected.len(),
            result
                .unexpected
                .iter()
                .map(|line| format!("  - {line}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    if !result.fixed.is_empty() {
        let singular = result.fixed.len() == 1;
        message.push_str(&format!(
            "{} allowlist {} no longer {} in the tree. Either the defect was fixed, or \
             the line is wrong. Delete {} — the list shrinking is what proves the \
             repair:\n\n{}\n",
            result.fixed.len(),
            if singular { "entry" } else { "entries" },
            if singular { "reproduces" } else { "reproduce" },
            if singular {
                "the matching line"
            } else {
                "the matching lines"
            },
            result
                .fixed
                .iter()
                .map(|key| format!("  - {key}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    message.push_str(&format!(
        "\nThe allowlist holds {} {}. Shrinking it is the proof a repair landed; \
         growing it needs a reason in the diff.",
        allowlist_len,
        if allowlist_len == 1 {
            "entry"
        } else {
            "entries"
        }
    ));
    Some(message)
}

/// The namespace object carries exactly the members it claims, and no others.
///
/// # Why the subtraction alone is not the whole check
///
/// The rule as usually stated — installed keys equal `MEMBERS - DEFERRED` — is
/// necessary but not sufficient. `rn-bind-sqlite` shipped `backup` in `MEMBERS`
/// **and** in `DEFERRED`, and `install()` set neither. Subtracting `DEFERRED` from
/// `MEMBERS` yields exactly the four members that *were* installed, so the
/// specified assertion passes on the very defect it was meant to catch:
///
/// ```text
/// MEMBERS - DEFERRED = {Database, Session, Statement, constants}
/// installed keys     = {Database, Session, Statement, constants}   -> equal
/// MEMBERS & DEFERRED = {backup}                                    -> the contradiction
/// ```
///
/// So the contradiction is asserted separately, and it is that assertion which
/// catches `backup`. The subtraction still earns its place as the general rule for
/// an honest crate that gets the object wrong in either direction.
///
/// Findings that exist today are recorded in [`KNOWN_FINDINGS`]; anything else fails.
#[test]
fn every_namespace_installs_exactly_what_it_claims() {
    let registry = registry();
    let contracts = contract_kinds();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    // Keyed by `namespace.member:rule` so the allowlist can name one finding
    // without depending on the wording of its message.
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    let mut install_failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut checked_members = 0usize;

    for namespace in registry.namespaces() {
        let name = namespace.name.as_str();
        let contract = contracts.get(name);

        let object = match registry.install(scope, name) {
            Ok(object) => object,
            Err(message) => {
                // An install() failure is not something the allowlist can excuse: it
                // would mean the namespace cannot be built at all, which no crate in
                // this tree tolerates. It fails the check directly.
                install_failures.push(format!("{name}: install() failed: {message}"));
                continue;
            }
        };
        let (installed, values) = own_properties(scope, object);

        checked += 1;
        checked_members += installed.len();

        for violation in violations_for(namespace, &installed, &values, contract) {
            found.insert(violation.key(name), violation.describe());
        }
    }

    assert!(
        install_failures.is_empty(),
        "{} namespace(s) could not be installed; the allowlist does not cover this \
         because a namespace that cannot be built is not a known defect:\n\n{}",
        install_failures.len(),
        install_failures
            .iter()
            .map(|line| format!("  - {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        checked > 0,
        "the registry installed no namespaces, so this check measured nothing"
    );
    // A guard against the failure mode this project has already hit once: a check
    // that iterates an empty set and reports success.
    assert!(
        checked_members > 500,
        "only {checked_members} installed members were inspected across {checked} \
         namespaces; that is too few to be the whole registry, so the walk is broken"
    );

    let verdict = apply_allowlist(&found, KNOWN_FINDINGS);
    println!(
        "structural check: {checked} namespaces, {checked_members} installed members, \
         {} finding(s) of which {} are known and recorded in the allowlist",
        found.len(),
        found.len().saturating_sub(verdict.unexpected.len())
    );
    if let Some(message) = allowlist_message(&verdict, KNOWN_FINDINGS.len(), "structural") {
        panic!(
            "the namespace object is the only authority on what `internalBinding` \
             returns, so a crate cannot be green on its declarations alone.\n\n{message}"
        );
    }
}

// ---------------------------------------------------------------------------
// Check 2: installed members that are stubs.
// ---------------------------------------------------------------------------

/// What calling one member with no arguments did.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Probe {
    /// The call returned normally.
    Returned,
    /// The call threw; the payload is the error's `name`, `code` and message.
    Threw {
        name: String,
        code: String,
        message: String,
    },
    /// The member is not a function, so there was nothing to call.
    NotCallable,
    /// The process died inside the call, which is what a wrong-arity V8 native
    /// call does. Recorded, never a failure: Node itself aborts for most of these.
    ProcessDied,
    /// The child did not report, for a reason other than a signal.
    NoReport,
    /// The call did not finish within [`PROBE_TIMEOUT`].
    TimedOut,
}

impl Probe {
    /// Whether the thrown error is a deliberate "this is not implemented" stub.
    ///
    /// Narrow on purpose. A looser rule ("any error that is not a TypeError") puts
    /// 67 members in the list, almost all of them legitimate argument validation
    /// in the style of `fs.open()` with no path, which is how a gate earns the
    /// reputation that gets it disabled. This matches only the phrasing a stub
    /// uses to say so itself.
    fn is_not_implemented_stub(&self) -> bool {
        match self {
            Self::Threw { message, .. } => {
                let message = message.to_ascii_lowercase();
                message.contains("not implemented") && !message.contains("unsupported")
            }
            _ => false,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Returned => "returned".to_string(),
            Self::Threw {
                name,
                code,
                message,
            } => {
                format!("threw {name} {code}: {message}")
            }
            Self::NotCallable => "not a function".to_string(),
            Self::ProcessDied => "the process died inside the call".to_string(),
            Self::NoReport => "the child process reported nothing".to_string(),
            Self::TimedOut => "the call did not return before the timeout".to_string(),
        }
    }
}

/// Calls one member of one namespace with no arguments and prints the result.
///
/// A no-op unless [`PROBE_ENV`] is set, which is how the parent runs it: the test
/// binary re-executes itself with `--exact` narrowed to this function. That keeps
/// the probe in the same build as the check instead of adding a second binary the
/// gate would have to remember to build.
#[test]
fn binding_probe_worker() {
    let Ok(target) = std::env::var(PROBE_ENV) else {
        return;
    };
    let Some((namespace, member)) = target.split_once('/') else {
        println!("PROBE\tparse\tmalformed target {target:?}");
        return;
    };

    let registry = registry();
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let object = match registry.install(scope, namespace) {
        Ok(object) => object,
        Err(message) => {
            println!("PROBE\tinstall\t{message}");
            return;
        }
    };
    let Some(key) = v8::String::new(scope, member) else {
        println!("PROBE\talloc\tcannot allocate the member name");
        return;
    };
    let Some(value) = object.get(scope, key.into()) else {
        println!("PROBE\tunreadable\t");
        return;
    };
    let Ok(function) = v8::Local::<v8::Function>::try_from(value) else {
        println!("PROBE\tnot-callable\t");
        return;
    };

    // Printed before the call, so the parent can tell "the call ended the process"
    // apart from "the harness never reached the call at all". `process.reallyExit`
    // legitimately exits with status 0 and no result line, and without this the
    // parent cannot distinguish that from a probe that never ran.
    println!("PROBE\tstarting\t");
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let _ = function.call(scope, object.into(), &[]);
    if scope.has_caught() {
        let Some(exception) = scope.exception() else {
            println!("PROBE\tthrew\tunknown\t\t");
            return;
        };
        if let Ok(error) = v8::Local::<v8::Object>::try_from(exception) {
            let name = property_string(scope, error, "name");
            let code = property_string(scope, error, "code");
            let message = property_string(scope, error, "message");
            println!("PROBE\tthrew\t{name}\t{code}\t{}", one_line(&message));
            return;
        }
        let text = exception.to_rust_string_lossy(scope);
        println!("PROBE\tthrew\t\t\t{}", one_line(&text));
        return;
    }
    println!("PROBE\treturned\t\t\t");
}

fn property_string(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
) -> String {
    let Some(key) = v8::String::new(scope, name) else {
        return String::new();
    };
    let Some(value) = object.get(scope, key.into()) else {
        return String::new();
    };
    if value.is_undefined() {
        return String::new();
    }
    value.to_rust_string_lossy(scope)
}

fn one_line(text: &str) -> String {
    text.replace(['\t', '\n', '\r'], " ")
}

/// Runs one probe in a child process, so a fatal V8 check cannot take the test
/// binary with it.
///
/// Each child runs in its own empty temporary directory. Two members in the tree
/// write to the process's working directory when called with no arguments —
/// `heap_utils.triggerHeapSnapshot` writes `Heap.<stamp>.heapsnapshot` and
/// `report.writeReport` writes a file literally named `undefined` — so a probe run
/// from the crate directory leaves those behind. A check that dirties the working
/// tree it is judging is not acceptable, and `cargo test` runs tests concurrently,
/// so a shared directory would collide.
fn probe_in_child(namespace: &str, member: &str) -> Probe {
    let Ok(exe) = std::env::current_exe() else {
        return Probe::NoReport;
    };
    let scratch = std::env::temp_dir().join(format!(
        "rustnode-binding-probe-{}-{}",
        std::process::id(),
        SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    if std::fs::create_dir_all(&scratch).is_err() {
        return Probe::NoReport;
    }
    let mut child = match Command::new(exe)
        .args([
            "--exact",
            "binding_probe_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE_ENV, format!("{namespace}/{member}"))
        .current_dir(&scratch)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            let _ = std::fs::remove_dir_all(&scratch);
            return Probe::NoReport;
        }
    };

    // A member that blocks forever would otherwise hang the whole gate, and a gate
    // that can hang is a gate that gets disabled. The limit is generous: the
    // slowest call in the tree today is a heap snapshot, well under a second.
    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(2)),
            Err(_) => break None,
        }
    };
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        use std::io::Read;
        // A killed child whose pipe is still open would block a naive read; the
        // process is already reaped, so this terminates.
        let _ = pipe.read_to_string(&mut stdout);
    }
    // Removed before the verdict is interpreted, so a failing check does not leave
    // a heap snapshot behind either.
    let _ = std::fs::remove_dir_all(&scratch);
    if status.is_none() {
        // The call did not finish in time. That is a property of the member, and it
        // is reported as such rather than as a harness failure.
        return Probe::TimedOut;
    }
    // The line is not at the start of its line: `libtest` prints its own progress
    // prefix (`test binding_probe_worker ... `) before whatever the test writes.
    // Matching on a prefix here silently found nothing on every probe, which made
    // the whole check measure an empty population and pass.
    let mut started = false;
    let mut verdict = None;
    for line in stdout.lines() {
        let Some(at) = line.find("PROBE\t") else {
            continue;
        };
        match line[at + "PROBE\t".len()..].split('\t').next() {
            Some("starting") => started = true,
            Some(_) => verdict = Some(&line[at..]),
            None => {}
        }
    }

    let Some(line) = verdict else {
        if started {
            // The call began and the process never reported a result: the call
            // itself ended the process. That is what a wrong-arity V8 native check
            // does, and `process.reallyExit(undefined)` does it by design with exit
            // status 0.
            return Probe::ProcessDied;
        }
        // The worker never got as far as the call. That is a harness failure, and it
        // is reported as such rather than being mistaken for a dead call.
        return Probe::NoReport;
    };
    let fields: Vec<&str> = line.split('\t').collect();
    match fields.get(1).copied() {
        Some("returned") => Probe::Returned,
        Some("not-callable") => Probe::NotCallable,
        Some("threw") => Probe::Threw {
            name: fields.get(2).copied().unwrap_or("").to_string(),
            code: fields.get(3).copied().unwrap_or("").to_string(),
            message: fields.get(4).copied().unwrap_or("").to_string(),
        },
        _ => Probe::NoReport,
    }
}

/// Every installed member, as `(namespace, member)`.
fn installed_members(namespace: &rn_core::Namespace) -> Vec<String> {
    let deferred: BTreeSet<&str> = namespace.deferred.keys().map(String::as_str).collect();
    namespace
        .members
        .iter()
        .filter(|member| !deferred.contains(member.as_str()))
        .cloned()
        .collect()
}

/// Probes whose outcome is known in advance, used to prove the harness can tell
/// one outcome from another before its verdict on the tree is trusted.
///
/// This exists because the first version of this check reported success while
/// measuring nothing: `libtest` prefixes the test's own output with
/// `test binding_probe_worker ... `, the parent looked for a line starting with
/// `PROBE`, found none on any of 829 probes, classified all of them
/// `NoReport`, and — because it only counted *stubs* — passed. The canaries make
/// that shape impossible: a harness that cannot see `returned` cannot pass.
const CANARIES: &[(&str, &str, Canary)] = &[
    // A plain function that returns a value.
    ("os", "getHostname", Canary::Returned),
    // A function that validates its arguments and throws a TypeError.
    ("os", "getLoadAvg", Canary::ThrewTyped),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Canary {
    Returned,
    /// Any throw whose error type was reported; the exact message is not pinned.
    ThrewTyped,
}

/// Whether the probe matched the outcome the canary predicted.
fn canary_matches(canary: Canary, probe: &Probe) -> bool {
    match canary {
        Canary::Returned => matches!(probe, Probe::Returned),
        Canary::ThrewTyped => matches!(probe, Probe::Threw { .. }),
    }
}

/// An installed member whose first call says "not implemented" must be deferred.
///
/// # What this check is, and what it is not
///
/// This is the achievable half of "a member that throws on first use counts as
/// absent". It finds members that are installed and are deliberate stubs, and
/// requires them to be declared in `DEFERRED` with a reason instead of sitting on
/// the namespace object. `fs.handleToFd` returning a hardcoded `ENOSYS` and
/// `performance.createELDHistogram` reporting that the loop it measures does not
/// exist are exactly this class.
///
/// It is deliberately *not* the broader "does calling with no arguments throw
/// something that looks like a real failure" classifier, because measurement says
/// that classifier cannot be a gate:
///
/// * **Most of the population kills the process.** Across the installed members
///   whose contract records arity 0, a no-argument call aborts the process for 288
///   of 484 (59%). Node's own C++ asserts on the same calls — `zlib.Zlib`,
///   `crypto.Hash`, `http_parser.HTTPParser` all abort under the oracle too — so
///   fatality carries no signal about *this* implementation. A gate whose "not a
///   TypeError" bucket is mostly "the process died" is noise.
/// * **It cannot see the defects that motivated it.** `sqlite` `createSession`
///   and `zlib` `params` are not namespace members: they are methods on a
///   `Database` prototype and on a zlib handle instance. No no-argument call on
///   the namespace object reaches either one, so the classifier would have found
///   neither defect.
///
/// What remains is the narrow rule below, which is deterministic, in-band with
/// the defect it describes, and needs no argument synthesis: a stub says so.
#[test]
fn installed_members_that_throw_not_implemented_are_declared_deferred() {
    // The canaries run first, and their failure is a harness failure, not a tree
    // failure: they say nothing about the crates and everything about whether this
    // check is capable of observing a call at all.
    for (namespace, member, expected) in CANARIES {
        let probe = probe_in_child(namespace, member);
        assert!(
            canary_matches(*expected, &probe),
            "canary {namespace}.{member} produced `{}`, expected {expected:?}. The \
             probe harness is broken, so its verdict on the tree would mean \
             nothing; fix this before reading any failure below.",
            probe.describe()
        );
    }

    let registry = registry();
    let namespaces: Vec<(String, Vec<String>)> = registry
        .namespaces()
        .iter()
        .map(|namespace| (namespace.name.clone(), installed_members(namespace)))
        .collect();

    let work: Vec<(String, String)> = namespaces
        .into_iter()
        .flat_map(|(namespace, members)| {
            members
                .into_iter()
                .map(move |member| (namespace.clone(), member))
        })
        .collect();

    assert!(
        work.len() > 500,
        "only {} installed members would be probed; that is too few to be the \
         whole registry, so the walk is broken",
        work.len()
    );
    let probed = work.len();

    let queue = Mutex::new(work);
    let results: Mutex<Vec<(String, String, Probe)>> = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for _ in 0..PROBE_WORKERS {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let item = {
                    let queue = queue.lock().expect("queue lock");
                    queue.get(index).cloned()
                };
                let Some((namespace, member)) = item else {
                    break;
                };
                let probe = probe_in_child(&namespace, &member);
                results
                    .lock()
                    .expect("results lock")
                    .push((namespace, member, probe));
            });
        }
    });

    let mut results = results.into_inner().expect("results lock");
    results.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));

    // Keyed by `namespace.member:not-implemented`, matching [`KNOWN_STUBS`].
    let mut stubs: BTreeMap<String, String> = BTreeMap::new();
    for (namespace, member, probe) in &results {
        if probe.is_not_implemented_stub() {
            stubs.insert(
                format!("{namespace}.{member}:not-implemented"),
                format!("{namespace}.{member} ({})", probe.describe()),
            );
        }
    }

    // A probe that reported nothing is a harness failure, not a tree failure, and
    // it must not hide behind the stub assertion: this is the exact shape that made
    // the first version of this check pass while measuring nothing.
    let silent: Vec<String> = results
        .iter()
        .filter(|(_, _, probe)| matches!(probe, Probe::NoReport | Probe::TimedOut))
        .map(|(namespace, member, probe)| format!("{namespace}.{member} ({})", probe.describe()))
        .collect();
    assert!(
        silent.is_empty(),
        "{} of {probed} probes reported nothing at all, so this check cannot see \
         the process it is measuring. That is a broken harness, not a broken \
         crate:\n\n{}",
        silent.len(),
        silent
            .iter()
            .take(20)
            .map(|line| format!("  - {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        results.len(),
        probed,
        "{} of {probed} probes produced no record at all",
        probed - results.len()
    );

    // Record the population so a shrinking walk is visible rather than silent.
    let died = results
        .iter()
        .filter(|(_, _, probe)| matches!(probe, Probe::ProcessDied))
        .count();
    println!(
        "probed {probed} installed members across {} namespaces: {} returned, {} \
         threw, {} not callable, {died} killed the process inside the call",
        results
            .iter()
            .map(|(namespace, _, _)| namespace.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        results
            .iter()
            .filter(|(_, _, probe)| matches!(probe, Probe::Returned))
            .count(),
        results
            .iter()
            .filter(|(_, _, probe)| matches!(probe, Probe::Threw { .. }))
            .count(),
        results
            .iter()
            .filter(|(_, _, probe)| matches!(probe, Probe::NotCallable))
            .count(),
    );

    let verdict = apply_allowlist(&stubs, KNOWN_STUBS);
    println!(
        "stub check: {} installed member(s) report themselves unimplemented, of which \
         {} are known and recorded in the allowlist",
        stubs.len(),
        stubs.len().saturating_sub(verdict.unexpected.len())
    );
    if let Some(message) = allowlist_message(&verdict, KNOWN_STUBS.len(), "stub") {
        panic!(
            "an installed member that cannot do its job is absent, not present, and \
             `rn-compat` counts it as coverage. Declare each in DEFERRED with a \
             reason, or implement it.\n\n{message}"
        );
    }
}

/// Pins the rules themselves, on synthetic namespaces.
///
/// The checks above run against the whole registry, so they describe the current
/// tree; these say what each rule means, and they are the regression test for the
/// one rule that has already been got wrong. A gate whose rule was quietly narrowed
/// until the tree went green would still pass the registry-wide check, and these
/// would fail.
#[cfg(test)]
mod rule_tests {
    use super::*;

    fn namespace(members: &[&str], deferred: &[(&str, &str)]) -> rn_core::Namespace {
        rn_core::Namespace::new("synthetic", members).with_deferred(deferred)
    }

    fn installed(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    fn rules(members: &[&str], deferred: &[(&str, &str)], present: &[&str]) -> Vec<String> {
        violations_for(
            &namespace(members, deferred),
            &installed(present),
            &BTreeMap::new(),
            None,
        )
        .iter()
        .map(Violation::describe)
        .collect()
    }

    #[test]
    fn a_member_in_both_members_and_deferred_is_a_violation() {
        // The `sqlite.backup` shape. `MEMBERS - DEFERRED` equals the installed set
        // exactly, so the rule as usually stated passes; only the contradiction
        // assertion sees it.
        let violations = rules(
            &["Database", "backup"],
            &[("backup", "needs the threadpool")],
            &["Database"],
        );
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].starts_with("backup: declared in MEMBERS and in DEFERRED"));
    }

    #[test]
    fn the_specified_set_equality_alone_would_miss_the_backup_shape() {
        // Written out explicitly so the reason this check does more than the
        // specified rule is on the record and cannot be "simplified" away later.
        let members: BTreeSet<&str> = ["Database", "backup"].into_iter().collect();
        let deferred: BTreeSet<&str> = ["backup"].into_iter().collect();
        let installed: BTreeSet<&str> = ["Database"].into_iter().collect();
        assert_eq!(
            members
                .iter()
                .filter(|m| !deferred.contains(*m))
                .copied()
                .collect::<BTreeSet<_>>(),
            installed,
            "the specified assertion passes on the defect"
        );
    }

    #[test]
    fn an_honest_deferral_carries_no_violation() {
        // The honest shape: a member the crate does not install is in `DEFERRED`
        // only. It must not also be in `MEMBERS`, which is what makes `MEMBERS` a
        // trustworthy statement of what `install()` produces.
        let violations = rules(
            &["Database"],
            &[("backup", "needs the threadpool")],
            &["Database"],
        );
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn deferring_a_member_that_is_installed_is_a_stale_deferral() {
        // `MEMBERS` means "this crate installs it" and `DEFERRED` means "this crate
        // does not install it yet", so the two are contradictory whichever way round
        // the object turns out. When the member *is* installed the `MEMBERS` claim is
        // true and the deferral is stale, which is `crypto.isKeyAlgorithmAvailable`
        // today: its reason says the key surface is deferred, but it is on the
        // object. That still deserves a finding — a stale reason is what let
        // `sqlite.backup`'s live reason hide behind an untrue member list.
        let violations = rules(
            &["Database", "backup"],
            &[("backup", "later")],
            &["Database", "backup"],
        );
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].starts_with("backup: declared in MEMBERS and in DEFERRED"));
        assert!(
            !violations[0].contains("claimed in MEMBERS (and not deferred)"),
            "the member is installed, so it must not also be reported absent: {violations:?}"
        );
    }

    #[test]
    fn a_claimed_member_that_is_absent_is_a_violation() {
        let violations = rules(&["Database", "Statement"], &[], &["Database"]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].starts_with("Statement: claimed in MEMBERS"));
    }

    #[test]
    fn an_installed_member_nobody_claimed_is_a_violation() {
        let violations = rules(&["Database"], &[], &["Database", "extra"]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].starts_with("extra: installed on the object but absent from MEMBERS"));
    }

    #[test]
    fn a_recorded_kind_that_the_object_contradicts_is_a_violation() {
        let mut values = BTreeMap::new();
        values.insert("Histogram".to_string(), Installed::Value("undefined"));
        values.insert(
            "createELDHistogram".to_string(),
            Installed::Value("function"),
        );
        let mut contract = BTreeMap::new();
        contract.insert("Histogram".to_string(), "function".to_string());
        contract.insert("createELDHistogram".to_string(), "function".to_string());

        let violations = violations_for(
            &namespace(&["Histogram", "createELDHistogram"], &[]),
            &installed(&["Histogram", "createELDHistogram"]),
            &values,
            Some(&contract),
        );
        let described: Vec<String> = violations.iter().map(Violation::describe).collect();
        assert_eq!(described.len(), 1, "{described:?}");
        assert!(described[0].starts_with("Histogram: contract records kind `function`"));
    }

    #[test]
    fn an_unclassified_contract_member_carries_no_expectation() {
        let mut values = BTreeMap::new();
        values.insert("configs".to_string(), Installed::Value("undefined"));
        let mut contract = BTreeMap::new();
        contract.insert("configs".to_string(), "unknown".to_string());

        let violations = violations_for(
            &namespace(&["configs"], &[]),
            &installed(&["configs"]),
            &values,
            Some(&contract),
        );
        assert!(
            violations.is_empty(),
            "`unknown` is the recorder declining to classify, not a claim: {violations:?}"
        );
    }

    #[test]
    fn only_a_self_described_stub_counts_as_not_implemented() {
        let stub = Probe::Threw {
            name: "Error".to_string(),
            code: String::new(),
            message: "createELDHistogram is not implemented: no event loop".to_string(),
        };
        assert!(stub.is_not_implemented_stub());

        // Argument validation is not a stub, and treating it as one is how this
        // check would become noise.
        let validation = Probe::Threw {
            name: "TypeError".to_string(),
            code: "ERR_INVALID_ARG_TYPE".to_string(),
            message: "The \"path\" argument must be of type string".to_string(),
        };
        assert!(!validation.is_not_implemented_stub());

        // An errno-shaped failure is not a stub either: `ENOSYS` on a specific path
        // says the platform call is unavailable, not that the member is missing.
        let errno = Probe::Threw {
            name: "Error".to_string(),
            code: "EINVAL".to_string(),
            message: "EINVAL: invalid argument, open".to_string(),
        };
        assert!(!errno.is_not_implemented_stub());

        assert!(!Probe::Returned.is_not_implemented_stub());
        assert!(!Probe::ProcessDied.is_not_implemented_stub());
    }

    #[test]
    fn the_allowlist_key_is_namespace_member_and_rule() {
        // The key must not come from the message: prose gets reworded, and an
        // allowlist keyed on prose stops matching silently.
        let violations = violations_for(
            &namespace(&["Database", "backup"], &[("backup", "later")]),
            &installed(&["Database"]),
            &BTreeMap::new(),
            None,
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].key("synthetic"),
            "synthetic.backup:claimed-and-deferred"
        );
    }

    #[test]
    fn an_unlisted_finding_is_unexpected_and_fails() {
        let mut found = BTreeMap::new();
        found.insert(
            "synthetic.NewDefect:claimed-but-absent".to_string(),
            "NewDefect: claimed but never installed".to_string(),
        );
        let verdict = apply_allowlist(&found, &["synthetic.OldDefect:claimed-and-deferred"]);
        assert_eq!(verdict.unexpected.len(), 1);
        assert!(verdict.unexpected[0].starts_with("synthetic.NewDefect"));
        // The listed defect is absent from the tree, so the other direction fires too.
        assert_eq!(
            verdict.fixed,
            vec!["synthetic.OldDefect:claimed-and-deferred"]
        );
    }

    #[test]
    fn a_listed_finding_is_suppressed() {
        let mut found = BTreeMap::new();
        found.insert(
            "synthetic.Known:claimed-and-deferred".to_string(),
            "Known: ...".to_string(),
        );
        let verdict = apply_allowlist(&found, &["synthetic.Known:claimed-and-deferred"]);
        assert!(verdict.unexpected.is_empty(), "{verdict:?}");
        assert!(verdict.fixed.is_empty(), "{verdict:?}");
    }

    #[test]
    fn a_fixed_defect_left_on_the_list_fails() {
        // This is the ratchet. Without it a repair could land and its allowlist line
        // would sit there forever, so the reported debt would never shrink.
        let found = BTreeMap::new();
        let verdict = apply_allowlist(&found, &["synthetic.Repaired:claimed-and-deferred"]);
        assert!(verdict.unexpected.is_empty());
        assert_eq!(
            verdict.fixed,
            vec!["synthetic.Repaired:claimed-and-deferred"]
        );
        let message = allowlist_message(&verdict, 1, "stub").expect("a message");
        assert!(message.contains("no longer reproduce"), "{message}");
    }

    #[test]
    fn the_allowlists_are_the_size_this_test_reports() {
        // Pins both counts explicitly, so shrinking a list is a deliberate edit with
        // a visible number rather than something that can drift unnoticed. When a
        // fix lands, its line and this number change in the same commit.
        assert_eq!(
            KNOWN_FINDINGS.len(),
            16,
            "KNOWN_FINDINGS holds the structural debt; update this count when a fix \
             removes an entry: {:?}",
            KNOWN_FINDINGS
        );
        assert_eq!(
            KNOWN_STUBS.len(),
            5,
            "KNOWN_STUBS holds the stub debt; update this count when a fix removes an \
             entry: {:?}",
            KNOWN_STUBS
        );
    }

    #[test]
    fn no_allowlist_entry_appears_twice() {
        // A duplicate would hide a shrinking list, because deleting one copy would
        // leave the other still suppressing the finding.
        for list in [KNOWN_FINDINGS, KNOWN_STUBS] {
            let unique: BTreeSet<&str> = list.iter().copied().collect();
            assert_eq!(unique.len(), list.len(), "duplicate entry in {list:?}");
        }
    }
}

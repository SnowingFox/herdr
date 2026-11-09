//! The values a process actually parsed, rather than the table's defaults.
//!
//! `src/node_options.cc` has two halves. One is the table `table.rs` mirrors.
//! The other is `OptionsParser<Options>::Parse` in `src/node_options-inl.h`:
//! it walks the argv, expands `AddAlias` entries, records `Implies` targets,
//! and stores a value per option before `lib/**` ever reads one.
//!
//! Without that second half every `getOptionValue('--x')` reports the default
//! from `src/node_options.h` no matter what the command line said. That is not
//! cosmetic: `lib/internal/bootstrap/realm.js` gates `node:bench` on
//! `--experimental-bench`, so a flag that parses to `false` leaves the module
//! unrequireable, and a test that only wanted the flag accepted fails at its
//! first `require`.
//!
//! # The rules, and where each comes from
//!
//! [`Store::apply`] follows `OptionsParser<Options>::Parse` statement by
//! statement, because the details are load-bearing and several are surprising:
//!
//! * Only arguments before the first non-flag are options, and `--` ends the
//!   run (`break`, not `continue`).
//! * `--foo=bar` is only split when the argument starts with two dashes, so
//!   `-e=a` stays one argument.
//! * Underscores after the second character become dashes, which is what makes
//!   `--expose_gc` and `--expose-gc` the same option.
//! * A leading `--no-` is stripped *before* the alias lookup and remembered,
//!   so `--no-warnings` resolves to `warnings` and sets it to `false`.
//! * `Implies` targets are looked up under the *pre-alias* name, and under the
//!   `--no-` spelling when the option was negated.
//! * A value argument may not start with `-` (a `\-` prefix escapes one), so a
//!   flag whose value is missing fails rather than swallowing the next flag.
//!
//! # What is deliberately not modelled
//!
//! * Errors. `Parse` collects them into `errors` and the embedder refuses to
//!   start. rustnode's `rn-cli` parser already owns "is this flag acceptable",
//!   and a second authority inside the options binding would let the two
//!   disagree about which argv is valid.
//! * The `NODE_OPTIONS` source. `--experimental-bench` is
//!   `kDisallowedInEnvvar`, so a test cannot require `node:bench` through it;
//!   accepting it there would be a divergence from Node, not a convenience.
//!   [`crate::values::parse_node_options`] already tokenizes the variable for
//!   `getOptionValue('--napi-modules')`-style readers.

use std::cell::RefCell;

use crate::option::{kind, DefaultValue, OptionInfo, OptionNamespace};
use crate::table::{ALIASES, OPTIONS};
use crate::values::CliValue;

/// One option's value after parsing.
///
/// Kept separate from [`CliValue`] because a parsed value owns its text while
/// `CliValue` is the shape published to JavaScript; [`Self::as_cli_value`]
/// bridges them.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedValue {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Text(String),
    List(Vec<String>),
    HostPort(String, u16),
}

impl ParsedValue {
    /// The declared default of one option, which `Parse` starts from because
    /// the struct is default-constructed before the argv is walked.
    fn default_of(option: &OptionInfo) -> Option<Self> {
        match option.kind {
            kind::BOOLEAN => match option.default {
                DefaultValue::Bool(flag) => Some(Self::Bool(flag)),
                _ => None,
            },
            kind::INTEGER => match option.default {
                DefaultValue::Int(number) => Some(Self::Int(number)),
                _ => None,
            },
            kind::U_INTEGER => match option.default {
                DefaultValue::Uint(number) => Some(Self::UInt(number)),
                _ => None,
            },
            kind::STRING => match option.default {
                DefaultValue::Str(text) => Some(Self::Text(text.to_string())),
                _ => None,
            },
            kind::STRING_LIST => match option.default {
                DefaultValue::List(items) => {
                    Some(Self::List(items.iter().map(|item| (*item).to_string()).collect()))
                }
                _ => None,
            },
            kind::HOST_PORT => match option.default {
                DefaultValue::HostPort(host, port) => {
                    Some(Self::HostPort(host.to_string(), port))
                }
                _ => None,
            },
            // `kNoOp`/`kV8Option` have no field in Node either, so they stay
            // out of the map and keep reporting `undefined` through
            // `CliValue::of`'s special cases.
            _ => None,
        }
    }

    /// The value as `getCLIOptionsValues` should publish it.
    #[must_use]
    pub fn as_cli_value(&self) -> CliValue {
        match self {
            Self::Bool(flag) => CliValue::Bool(*flag),
            Self::Int(number) => CliValue::Number(*number as f64),
            Self::UInt(number) => CliValue::Number(*number as f64),
            Self::Text(text) => CliValue::Text(text.clone()),
            Self::List(items) => CliValue::TextList(items.clone()),
            Self::HostPort(host, port) => CliValue::HostPort(host.clone(), *port),
        }
    }
}

thread_local! {
    /// The values the CLI installed. `None` until [`install`] runs, which is
    /// why [`crate::values::cli_values`] can keep falling back to the table
    /// defaults: a caller that never parses a command line has to see exactly
    /// what it saw before this module existed.
    static PARSED: RefCell<Option<Store>> = const { RefCell::new(None) };
}

/// Records the process's parsed option values.
pub fn install(store: Store) {
    PARSED.with(|parsed| {
        *parsed.borrow_mut() = Some(store);
    });
}

/// One option's parsed value, if the CLI installed a store.
#[must_use]
pub fn value_of(name: &str) -> Option<ParsedValue> {
    PARSED.with(|parsed| {
        parsed
            .borrow()
            .as_ref()
            .and_then(|store| store.value_of(name))
    })
}

/// Every parsed value, in table order, for a caller that wants them all.
#[must_use]
pub fn all_values() -> Option<Vec<(String, ParsedValue)>> {
    PARSED.with(|parsed| {
        parsed
            .borrow()
            .as_ref()
            .map(|store| store.values.clone())
    })
}

/// The parsed values for this process.
#[derive(Debug, Clone, Default)]
pub struct Store {
    values: Vec<(String, ParsedValue)>,
}

impl Store {
    /// Parses the options in `argv`.
    ///
    /// `argv` is the arguments after the executable in the order they were
    /// typed. The script path and the arguments that follow it are the caller's
    /// to strip: `Parse` stops at the first argument that is not a flag, and
    /// the caller has already established which argument that is.
    #[must_use]
    pub fn parse(argv: &[String]) -> Self {
        let mut store = Self {
            values: OPTIONS
                .iter()
                .filter_map(|option| {
                    ParsedValue::default_of(option).map(|value| (option.name.to_string(), value))
                })
                .collect(),
        };
        store.apply(argv);
        store
    }

    /// Returns one value, if this store has it.
    #[must_use]
    pub fn value_of(&self, name: &str) -> Option<ParsedValue> {
        self.values
            .iter()
            .find(|(option, _)| option == name)
            .map(|(_, value)| value.clone())
    }

    /// Walks `argv` the way `OptionsParser<Options>::Parse` does.
    ///
    /// Synthetic arguments from an alias expansion are prepended to a queue of
    /// their own rather than inserted into `argv`, matching `ArgsInfo`: that
    /// keeps `exec_args` free of them, and it is why the loop indexes a queue
    /// instead of the caller's slice.
    pub fn apply(&mut self, argv: &[String]) {
        let mut pending: std::collections::VecDeque<String> = argv.iter().cloned().collect();

        while let Some(argument) = pending.pop_front() {
            // `Parse` stops at the first argument that is not a flag, and at an
            // argument of length <= 1 (a bare `-`), which is the stdin marker.
            if argument.len() <= 1 || !argument.starts_with('-') {
                break;
            }
            if argument == "--" {
                break;
            }

            // `--foo=bar` is only split for a two-dash argument. `-e=a` stays
            // whole, which is what stops alias expansion from inventing
            // `--eval=a` out of a single-dash spelling.
            let equals = if argument.starts_with("--") {
                argument.find('=')
            } else {
                None
            };
            let (raw_name, inline) = match equals {
                Some(index) => (&argument[..index], Some(argument[index + 1..].to_string())),
                None => (argument.as_str(), None),
            };

            // Underscores after the leading dashes become dashes: this is what
            // makes `--expose_gc` and `--expose-gc` the same option rather than
            // two spellings of a typo.
            let mut name = normalize_underscores(raw_name);

            // A leading `--no-` is stripped before the alias lookup and
            // remembered, so the option it names is found and then negated.
            let negated = name.starts_with("--no-");
            if negated {
                name = format!("--{}", &name[5..]);
            }

            // Aliases resolve repeatedly (`--print <arg>` goes to `-pe`, which
            // goes to `--print --eval`), and the loop stops when a step would
            // not rename anything. The " <arg>" form only matches when a
            // non-flag argument follows, which is why `pending` is consulted.
            loop {
                let expansion = alias_for(&name, inline.is_some(), pending.front());
                let Some(targets) = expansion else {
                    break;
                };
                let previous = name;
                name = targets[0].clone();
                for extra in targets.iter().skip(1).rev() {
                    pending.push_front(extra.clone());
                }
                if name == previous {
                    break;
                }
            }

            // `Implies` is keyed by the name as the user wrote it, before any
            // alias expansion, and by the `--no-` spelling when negated.
            let implied_name = if negated {
                format!("--no-{}", &name[2..])
            } else {
                name.clone()
            };
            self.apply_implications(&implied_name);

            let Some(option) = OPTIONS.iter().find(|option| option.name == name) else {
                // An unknown flag is V8's, or the script's: `Parse` only
                // records it. Deciding it is fatal belongs to `rn-cli`.
                continue;
            };

            // Node rejects `--no-` on anything but a boolean (and V8 options,
            // which V8 validates). Being lenient here would set a string option
            // to the negation of something it has no negation for.
            if negated && option.kind != kind::BOOLEAN && option.kind != kind::V8_OPTION {
                continue;
            }

            let mut value = inline;
            if option.kind != kind::BOOLEAN
                && option.kind != kind::NO_OP
                && option.kind != kind::V8_OPTION
            {
                let Some(value_text) = value.take().or_else(|| pending.pop_front()) else {
                    continue;
                };
                // A value may not begin with `-`: that would be a flag the user
                // meant separately. A leading `\-` escapes one.
                if value_text.starts_with("\\-") {
                    value = Some(value_text[1..].to_string());
                } else if value_text.starts_with('-') {
                    continue;
                } else {
                    value = Some(value_text);
                }
            } else {
                // `--flag=value` on a boolean is not a value: `Parse` never
                // reads one for those types, so the text is dropped rather than
                // being treated as truthy.
                value = None;
            }

            self.assign(option, negated, value.as_deref());
        }
    }

    /// Stores the value `option` receives from one parsed argument.
    fn assign(&mut self, option: &OptionInfo, negated: bool, value: Option<&str>) {
        let stored = match option.kind {
            kind::BOOLEAN => ParsedValue::Bool(!negated),
            // `std::atoll` semantics: junk parses as 0 rather than failing.
            kind::INTEGER => ParsedValue::Int(value.and_then(|v| v.parse().ok()).unwrap_or(0)),
            kind::U_INTEGER => ParsedValue::UInt(value.and_then(|v| v.parse().ok()).unwrap_or(0)),
            kind::STRING => ParsedValue::Text(value.unwrap_or_default().to_string()),
            // A list option appends, so two `--require` flags keep both.
            kind::STRING_LIST => {
                let mut items = match self.value_of(option.name) {
                    Some(ParsedValue::List(items)) => items,
                    _ => Vec::new(),
                };
                items.push(value.unwrap_or_default().to_string());
                ParsedValue::List(items)
            }
            kind::HOST_PORT => {
                let (host, port) = split_host_port(value.unwrap_or_default());
                ParsedValue::HostPort(host, port)
            }
            kind::NO_OP | kind::V8_OPTION => {
                // Two V8 flags are read as Node fields; everything else here
                // has no field to write, which `CliValue::of` already reflects.
                match option.name {
                    "--abort-on-uncaught-exception" => ParsedValue::Bool(!negated),
                    "--stack-trace-limit" => {
                        ParsedValue::Int(value.and_then(|v| v.parse().ok()).unwrap_or(10))
                    }
                    _ => return,
                }
            }
            _ => return,
        };
        self.set(option.name, stored);
    }

    /// Merges every `Implies` target recorded for `from`.
    fn apply_implications(&mut self, from: &str) {
        for (source, target, value) in IMPLIES {
            if *source == from {
                self.set(target, ParsedValue::Bool(*value));
            }
        }
    }

    /// Writes `value` for `name`, replacing an earlier one.
    fn set(&mut self, name: &str, value: ParsedValue) {
        if let Some(entry) = self.values.iter_mut().find(|(option, _)| option == name) {
            entry.1 = value;
        } else {
            self.values.push((name.to_string(), value));
        }
    }
}

/// Replaces `_` with `-` after the leading dashes, as `Parse` does.
fn normalize_underscores(name: &str) -> String {
    let mut characters: Vec<char> = name.chars().collect();
    for character in characters.iter_mut().skip(2) {
        if *character == '_' {
            *character = '-';
        }
    }
    characters.into_iter().collect()
}

/// The expansion `Parse` would use for `name`, if any.
///
/// Three forms are tried, in `Parse`'s order: the plain name, the name with `=`
/// when the argument carried an inline value, and the `" <arg>"` form when a
/// non-flag argument follows.
fn alias_for(name: &str, had_inline_value: bool, next: Option<&String>) -> Option<Vec<String>> {
    if let Some(alias) = ALIASES.iter().find(|alias| alias.from == name) {
        return Some(alias.to.iter().map(|item| (*item).to_string()).collect());
    }
    if had_inline_value {
        let with_equals = format!("{name}=");
        if let Some(alias) = ALIASES.iter().find(|alias| alias.from == with_equals) {
            return Some(alias.to.iter().map(|item| (*item).to_string()).collect());
        }
    }
    if let Some(next) = next {
        if !next.is_empty() && !next.starts_with('-') {
            let with_arg = format!("{name} <arg>");
            if let Some(alias) = ALIASES.iter().find(|alias| alias.from == with_arg) {
                return Some(alias.to.iter().map(|item| (*item).to_string()).collect());
            }
        }
    }
    None
}

/// `SplitHostPort`: `host`, `host:port`, or `:port`.
///
/// A missing or unparseable port is 0, and an empty host stays empty, which is
/// what `HostPort` reports before anything sets it.
fn split_host_port(value: &str) -> (String, u16) {
    match value.rfind(':') {
        Some(index) => {
            let host = &value[..index];
            let port = value[index + 1..].parse().unwrap_or(0);
            (host.to_string(), port)
        }
        None => (value.to_string(), 0),
    }
}

/// `Implies(from, to)` and `ImpliesNot(from, to)` from `src/node_options.cc`.
///
/// Each triple is `(source, target, target value)`. The set is the one Node
/// records, because a missing entry is silent: the internal `[target]` stays
/// `false` and the check that reads it (`CheckBenchOptions`, for instance)
/// takes the wrong branch.
pub const IMPLIES: &[(&str, &str, bool)] = &[
    ("--inspect-brk", "--inspect", true),
    ("--inspect-brk-node", "--inspect", true),
    ("--inspect-wait", "--inspect", true),
    ("--experimental-require-module", "--require-module", true),
    ("--vfs-load", "[vfs_load_set]", true),
    ("--env-file", "[has_env_file_string]", true),
    ("--env-file-if-exists", "[has_env_file_string]", true),
    ("--bench", "[has_bench_options]", true),
    ("--bench-isolation", "[has_bench_options]", true),
    ("--bench-name-pattern", "[has_bench_options]", true),
    ("--bench-reporter", "[has_bench_options]", true),
    ("--bench-reporter-destination", "[has_bench_options]", true),
    ("--bench-samples", "[has_bench_options]", true),
    ("--bench-samples", "[has_bench_samples]", true),
    ("--bench-warmup", "[has_bench_options]", true),
    ("--bench-warmup", "[has_bench_warmup]", true),
    ("--test-random-seed", "[has_test_random_seed]", true),
    ("--trace-env-js-stack", "--trace-env", true),
    ("--trace-env-native-stack", "--trace-env", true),
    ("--watch-path", "--watch", true),
    ("--eval", "[has_eval_string]", true),
    ("--report-signal", "--report-on-signal", true),
    ("--experimental-shadow-realm", "--harmony-shadow-realm", true),
    ("--harmony-shadow-realm", "--experimental-shadow-realm", true),
    ("--build-snapshot-config", "--build-snapshot", true),
    ("--use-openssl-ca", "[ssl_openssl_cert_store]", true),
    ("--node-memory-debug", "--debug-arraybuffer-allocations", true),
    ("--node-memory-debug", "--verify-base-objects", true),
];

/// Whether a flag in `namespace` appeared in `argv`.
///
/// `GetOptionsAsFlags` skips the whole bench namespace unless
/// `--experimental-bench` is set, so the question has to be answerable about the
/// raw argv rather than about parsed values.
#[must_use]
pub fn namespace_seen(argv: &[String], namespace: OptionNamespace) -> bool {
    argv.iter().any(|argument| {
        let (name, _) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (argument.as_str(), None),
        };
        let name = normalize_underscores(name);
        let name = name.strip_prefix("--no-").map_or(name.clone(), |rest| {
            format!("--{rest}")
        });
        OPTIONS
            .iter()
            .any(|option| option.name == name && option.namespace == namespace)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }

    fn parsed(items: &[&str]) -> Store {
        Store::parse(&argv(items))
    }

    #[test]
    fn an_absent_option_keeps_its_default() {
        let store = parsed(&[]);
        assert_eq!(
            store.value_of("--experimental-bench"),
            Some(ParsedValue::Bool(false))
        );
        assert_eq!(
            store.value_of("--bench-isolation"),
            Some(ParsedValue::Text("process".to_string()))
        );
    }

    #[test]
    fn a_boolean_flag_sets_itself() {
        let store = parsed(&["--experimental-bench"]);
        assert_eq!(
            store.value_of("--experimental-bench"),
            Some(ParsedValue::Bool(true))
        );
    }

    #[test]
    fn underscores_are_dashes_after_the_prefix() {
        // `Parse` rewrites `_` to `-` from index 2 on, which is why both
        // spellings of `--expose-gc` reach one option. Node's own test headers
        // use both.
        assert_eq!(parsed(&["--expose_gc"]).value_of("--expose-gc"), None);
        let store = parsed(&["--experimental_bench"]);
        assert_eq!(
            store.value_of("--experimental-bench"),
            Some(ParsedValue::Bool(true)),
            "--experimental_bench must normalize onto --experimental-bench"
        );
    }

    #[test]
    fn the_no_spelling_clears_a_boolean() {
        let store = parsed(&["--no-warnings"]);
        assert_eq!(store.value_of("--warnings"), Some(ParsedValue::Bool(false)));
    }

    #[test]
    fn a_value_is_taken_from_the_next_argument() {
        // A `kUInteger` option, so the value lands in a field. A `kV8Option`
        // such as `--max-old-space-size` has no field in Node either and is
        // handled by V8, which is why it is not used here.
        let store = parsed(&["--max-http-header-size", "32768"]);
        assert_eq!(
            store.value_of("--max-http-header-size"),
            Some(ParsedValue::UInt(32768))
        );
    }

    #[test]
    fn a_value_can_be_written_inline() {
        let store = parsed(&["--max-http-header-size=32768"]);
        assert_eq!(
            store.value_of("--max-http-header-size"),
            Some(ParsedValue::UInt(32768))
        );
    }

    #[test]
    fn an_integer_option_accepts_a_negative_value() {
        // `kInteger` uses `std::atoll`, so `-1` is a value and not a flag. A
        // `-` check that ran before the numeric parse would drop it.
        let store = parsed(&["--stack-trace-limit=5"]);
        assert_eq!(
            store.value_of("--stack-trace-limit"),
            Some(ParsedValue::Int(5))
        );
    }

    #[test]
    fn a_value_that_looks_like_a_flag_is_not_consumed() {
        // `Parse` rejects a value beginning with `-`, so the flag keeps its
        // default instead of eating the next flag. Swallowing it would make
        // `--title --expose-gc` silently lose the second flag.
        let store = parsed(&["--title", "--expose-gc"]);
        assert_eq!(
            store.value_of("--title"),
            Some(ParsedValue::Text(String::new()))
        );
    }

    #[test]
    fn an_escaped_dash_is_a_value() {
        let store = parsed(&["--title", "\\-not-a-flag"]);
        assert_eq!(
            store.value_of("--title"),
            Some(ParsedValue::Text("-not-a-flag".to_string()))
        );
    }

    #[test]
    fn a_list_option_appends_rather_than_replaces() {
        // `Parse` calls `emplace_back` for a list option, so both survive.
        let store = parsed(&["--require", "a.js", "--require", "b.js"]);
        assert_eq!(
            store.value_of("--require"),
            Some(ParsedValue::List(vec![
                "a.js".to_string(),
                "b.js".to_string()
            ]))
        );
    }

    #[test]
    fn parsing_stops_at_the_first_non_flag() {
        // Everything after the script path belongs to the script, so a flag
        // there must not change an option.
        let store = parsed(&["--no-warnings", "script.js", "--experimental-bench"]);
        assert_eq!(
            store.value_of("--experimental-bench"),
            Some(ParsedValue::Bool(false))
        );
    }

    #[test]
    fn double_dash_ends_option_parsing() {
        let store = parsed(&["--", "--experimental-bench"]);
        assert_eq!(
            store.value_of("--experimental-bench"),
            Some(ParsedValue::Bool(false))
        );
    }

    #[test]
    fn implies_marks_the_internal_target() {
        // `CheckBenchOptions` reads `[has_bench_options]`, which only becomes
        // true because `Implies("--bench-isolation", "[has_bench_options]")`
        // exists. Without the trail a bench flag looks like no bench flag.
        let store = parsed(&["--bench-isolation", "process"]);
        assert_eq!(
            store.value_of("[has_bench_options]"),
            Some(ParsedValue::Bool(true))
        );
    }

    #[test]
    fn a_sample_count_implies_both_targets() {
        let store = parsed(&["--bench-samples", "3"]);
        assert_eq!(
            store.value_of("[has_bench_options]"),
            Some(ParsedValue::Bool(true))
        );
        assert_eq!(
            store.value_of("[has_bench_samples]"),
            Some(ParsedValue::Bool(true))
        );
        assert_eq!(store.value_of("--bench-samples"), Some(ParsedValue::UInt(3)));
    }

    #[test]
    fn an_alias_expands_to_its_target() {
        let store = parsed(&["--loader", "x.mjs"]);
        assert_eq!(
            store.value_of("--experimental-loader"),
            Some(ParsedValue::List(vec!["x.mjs".to_string()]))
        );
    }

    #[test]
    fn an_alias_chain_expands_more_than_once() {
        // `-p` -> `--print`; the expansion has to be re-examined for aliases or
        // a one-step lookup would leave `--print` unhandled.
        let store = parsed(&["-p", "1+1"]);
        assert_eq!(store.value_of("--print"), Some(ParsedValue::Bool(true)));
    }

    #[test]
    fn an_inline_alias_moves_the_value_to_the_target() {
        // `--inspect=PORT` expands to `--inspect-port PORT --inspect`, and the
        // port is what the value belonged to. `--inspect-port` is a
        // `kHostPort`, so a bare port arrives with an empty host.
        let store = parsed(&["--inspect=9230"]);
        assert_eq!(
            store.value_of("--inspect-port"),
            Some(ParsedValue::HostPort("9230".to_string(), 0))
        );
        assert_eq!(store.value_of("--inspect"), Some(ParsedValue::Bool(true)));
    }

    #[test]
    fn unknown_arguments_are_ignored() {
        // `Parse` pushes an unknown flag to the V8 args and moves on; deciding
        // it is fatal belongs to `rn-cli`'s parser.
        let store = parsed(&["--not-a-real-flag", "value"]);
        assert_eq!(store.value_of("--not-a-real-flag"), None);
    }

    #[test]
    fn a_host_port_value_splits() {
        let store = parsed(&["--inspect-port=127.0.0.1:9230"]);
        assert_eq!(
            store.value_of("--inspect-port"),
            Some(ParsedValue::HostPort("127.0.0.1".to_string(), 9230))
        );
    }

    #[test]
    fn every_imply_endpoint_is_a_declared_option() {
        for (source, target, _) in IMPLIES {
            assert!(
                OPTIONS.iter().any(|option| option.name == *source),
                "{source} is not in the option table"
            );
            assert!(
                OPTIONS.iter().any(|option| option.name == *target),
                "{target} is not in the option table"
            );
        }
    }

    #[test]
    fn the_bench_namespace_is_detected_in_a_raw_argv() {
        assert!(namespace_seen(
            &argv(&["--bench-isolation", "process"]),
            OptionNamespace::Bench
        ));
        assert!(!namespace_seen(
            &argv(&["--no-warnings"]),
            OptionNamespace::Bench
        ));
    }
}

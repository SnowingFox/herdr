//! The logic behind each `internalBinding('options')` member.
//!
//! Everything here is ordinary Rust over the generated table: no V8 types, so
//! the option-value rules and the `NODE_OPTIONS` tokenizer can be tested
//! directly. `lib.rs` only converts these results into JavaScript values.

use crate::option::{env_setting, kind, AliasInfo, DefaultValue, OptionInfo, OptionNamespace};
use crate::table::{ALIASES, OPTIONS};

/// What `getCLIOptionsValues` reports for one option.
///
/// `kNoOp` and `kV8Option` entries have no field and are reported as
/// `undefined`, with two deliberate exceptions in Node's own switch:
/// `--abort-on-uncaught-exception` (a V8 flag Node's internals read as a
/// boolean) and `--stack-trace-limit` (a V8 flag whose value Node stores as an
/// integer). Both are copied here.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CliValue {
    Undefined,
    Bool(bool),
    Number(f64),
    Text(&'static str),
    TextList(&'static [&'static str]),
    HostPort(&'static str, u16),
}

impl CliValue {
    /// The value of one table entry, before any `--no-` expansion.
    #[must_use]
    pub fn of(option: &OptionInfo) -> Self {
        match option.kind {
            kind::NO_OP | kind::V8_OPTION => match option.name {
                // `s.original_per_env->abort_on_uncaught_exception`: the
                // EnvironmentOptions field, whose default is false.
                "--abort-on-uncaught-exception" => Self::Bool(false),
                // `_ppop_instance.Lookup<int64_t>`: PerIsolateOptions::
                // stack_trace_limit, default 10.
                "--stack-trace-limit" => Self::Number(10.0),
                _ => Self::Undefined,
            },
            kind::BOOLEAN => match option.default {
                DefaultValue::Bool(flag) => Self::Bool(flag),
                _ => Self::Undefined,
            },
            kind::INTEGER => match option.default {
                DefaultValue::Int(number) => Self::Number(number as f64),
                _ => Self::Undefined,
            },
            kind::U_INTEGER => match option.default {
                DefaultValue::Uint(number) => Self::Number(number as f64),
                _ => Self::Undefined,
            },
            kind::STRING => match option.default {
                DefaultValue::Str(text) => Self::Text(text),
                _ => Self::Undefined,
            },
            kind::STRING_LIST => match option.default {
                DefaultValue::List(items) => Self::TextList(items),
                _ => Self::Undefined,
            },
            kind::HOST_PORT => match option.default {
                DefaultValue::HostPort(host, port) => Self::HostPort(host, port),
                _ => Self::Undefined,
            },
            _ => Self::Undefined,
        }
    }
}

/// Every `[name, value]` pair `getCLIOptionsValues` builds, in table order.
///
/// A `kBoolean` contributes two entries: the option itself and its
/// `--no-<name>` negation with the inverted value. Node pushes the negation
/// *first* (`AddOption`'s loop pushes the pair before falling through to the
/// common push for the option itself), which decides the property order of
/// the returned object, so it is reproduced exactly.
#[must_use]
pub fn cli_values() -> Vec<(String, CliValue)> {
    let mut entries = Vec::with_capacity(OPTIONS.len() * 2);
    for option in OPTIONS {
        let value = CliValue::of(option);
        if option.kind == kind::BOOLEAN {
            if let (Some(negated), CliValue::Bool(flag)) = (option.negated_name(), value) {
                entries.push((negated, CliValue::Bool(!flag)));
            }
        }
        entries.push((option.name.to_string(), value));
    }
    entries
}

/// One option's entry in the map `getCLIOptionsInfo` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionMetadata {
    pub help_text: &'static str,
    pub env_setting: i32,
    pub kind: i32,
    pub default_is_true: bool,
}

impl OptionMetadata {
    #[must_use]
    pub fn of(option: &OptionInfo) -> Self {
        Self {
            help_text: option.help_text,
            env_setting: option.env_setting,
            kind: option.kind,
            default_is_true: option.default_is_true,
        }
    }
}

/// The two maps `getCLIOptionsInfo` returns.
#[must_use]
pub fn cli_info() -> (Vec<(&'static str, OptionMetadata)>, &'static [AliasInfo]) {
    let options = OPTIONS
        .iter()
        .map(|option| (option.name, OptionMetadata::of(option)))
        .collect();
    (options, ALIASES)
}

/// What `getEmbedderOptions` reports for a standalone executable.
///
/// Node reads these from `Environment` flags an embedder sets through
/// `node::InitializeOncePerProcess`; a plain `node` (and rustnode) sets none of
/// them, so every field is false. `hasEmbedderPreload` in particular is
/// `embedder_preload() != nullptr`, and there is no embedder preload without an
/// embedder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmbedderOptions {
    pub should_not_register_esm_loader: bool,
    pub no_global_search_paths: bool,
    pub no_browser_globals: bool,
    pub has_embedder_preload: bool,
}

impl EmbedderOptions {
    /// The values a standalone executable reports: all false.
    ///
    /// Named rather than spelled `Default::default()` at the call site so the
    /// reason the values are false stays next to them; an embedder would fill
    /// these in from its own `Environment` flags.
    #[must_use]
    pub fn for_standalone_executable() -> Self {
        Self::default()
    }
}

/// The `type` string `AddOptionTypeToObject` assigns to an option type, or
/// `None` for the types it skips.
///
/// `kNoOp` and `kV8Option` are skipped: they are V8 flags, not things a
/// config file can set. The remaining cases group `kInteger`, `kUInteger` and
/// `kHostPort` together as `"number"`, which is what the JSON-schema generator
/// consumes.
#[must_use]
pub fn input_type_name(option_kind: i32) -> Option<&'static str> {
    match option_kind {
        kind::BOOLEAN => Some("boolean"),
        kind::INTEGER | kind::U_INTEGER | kind::HOST_PORT => Some("number"),
        kind::STRING => Some("string"),
        kind::STRING_LIST => Some("array"),
        _ => None,
    }
}

/// One entry of `getEnvOptionsInputType` / `getNamespaceOptionsInputType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputType {
    pub name: &'static str,
    pub type_name: &'static str,
    pub help_text: &'static str,
}

/// The options a config file may set from `NODE_OPTIONS`, keyed by name.
///
/// `MapEnvOptionsFlagInputType` keeps every option whose name is non-empty,
/// is not an internal `[target]`, and is `kAllowedInEnvvar`.
#[must_use]
pub fn env_options_input_types() -> Vec<InputType> {
    OPTIONS
        .iter()
        .filter(|option| {
            !option.name.is_empty()
                && !option.is_internal()
                && option.env_setting == env_setting::ALLOWED
        })
        .filter_map(|option| {
            Some(InputType {
                name: option.name,
                type_name: input_type_name(option.kind)?,
                help_text: option.help_text,
            })
        })
        .collect()
}

/// The namespaces `MapAvailableNamespaces` reports, in `OPTION_NAMESPACE_LIST`
/// order with `kNoNamespace` skipped.
pub const NAMESPACES: &[OptionNamespace] = &[
    OptionNamespace::Bench,
    OptionNamespace::Test,
    OptionNamespace::Watch,
    OptionNamespace::Permission,
];

/// `MapNamespaceOptionsAssociations`: every namespace, in `NAMESPACES` order,
/// with the options whose `namespace_id` matches.
///
/// Node inserts an empty map for a namespace with no options too, so the
/// returned list always has one entry per available namespace.
#[must_use]
pub fn namespace_options_input_types() -> Vec<(OptionNamespace, Vec<InputType>)> {
    NAMESPACES
        .iter()
        .map(|namespace| {
            let entries = OPTIONS
                .iter()
                .filter(|option| {
                    !option.name.is_empty()
                        && !option.is_internal()
                        && option.namespace == *namespace
                })
                .filter_map(|option| {
                    Some(InputType {
                        name: option.name,
                        type_name: input_type_name(option.kind)?,
                        help_text: option.help_text,
                    })
                })
                .collect();
            (*namespace, entries)
        })
        .collect()
}

/// `GetOptionsAsFlags`: every option whose value differs from what "no flag
/// given" means, spelled the way it would appear on a command line.
///
/// The rules below are transcribed from the C++ switch:
///
/// * `kNoOp` and `kV8Option` are skipped — they belong to V8, not Node.
/// * An empty name and an internal `[target]` are skipped.
/// * Options in the `bench` namespace are skipped entirely unless
///   `--experimental-bench` is set, because the benchmark runner options are
///   meaningless outside it.
/// * A `kBoolean` reports `--flag` only when its value differs from its
///   `default_is_true` hint (`--no-flag` when it is `true` and the value is
///   `false`); when they agree, the flag's absence already says so.
/// * `kInteger` and `kUInteger` always report `--flag=value`.
/// * `kString` reports `--flag=value` only when the string is non-empty.
/// * `kStringList` reports one `--flag=value` per element.
/// * `kHostPort` reports `--flag=host:port`, omitting the port when it is 0
///   and skipping the entry when both host and port are empty.
///
/// rustnode starts every process with no options, so only options whose
/// declared default is itself reportable appear: `--v8-pool-size=4`,
/// `--max-http-header-size=16384` and the rest of the non-zero numerics, plus
/// the `kHostPort` and non-empty `kString` defaults. That is exactly what Node
/// reports for `node -e ''` with an empty `NODE_OPTIONS`, which is what a
/// caller comparing the two will see.
#[must_use]
pub fn options_as_flags() -> Vec<String> {
    let mut flags = Vec::new();
    for option in OPTIONS {
        if option.name.is_empty() || option.is_internal() {
            continue;
        }
        if option.namespace == OptionNamespace::Bench {
            // `experimental_bench` is false in a process started with no
            // arguments, so every benchmark-runner option is skipped.
            continue;
        }
        match option.kind {
            kind::NO_OP | kind::V8_OPTION => continue,
            kind::BOOLEAN => {
                let DefaultValue::Bool(value) = option.default else {
                    continue;
                };
                if value == option.default_is_true {
                    continue;
                }
                if option.default_is_true {
                    flags.push(format!("--no-{}", &option.name[2..]));
                } else {
                    flags.push(option.name.to_string());
                }
            }
            kind::INTEGER => {
                let DefaultValue::Int(value) = option.default else {
                    continue;
                };
                flags.push(format!("{}={value}", option.name));
            }
            kind::U_INTEGER => {
                let DefaultValue::Uint(value) = option.default else {
                    continue;
                };
                flags.push(format!("{}={value}", option.name));
            }
            kind::STRING => {
                let DefaultValue::Str(value) = option.default else {
                    continue;
                };
                if !value.is_empty() {
                    flags.push(format!("{}={value}", option.name));
                }
            }
            kind::STRING_LIST => {
                let DefaultValue::List(values) = option.default else {
                    continue;
                };
                for value in values {
                    flags.push(format!("{}={value}", option.name));
                }
            }
            kind::HOST_PORT => {
                let DefaultValue::HostPort(host, port) = option.default else {
                    continue;
                };
                if host.is_empty() && port == 0 {
                    continue;
                }
                if port == 0 {
                    flags.push(format!("{}={host}", option.name));
                } else if host.is_empty() {
                    flags.push(format!("{}={port}", option.name));
                } else {
                    flags.push(format!("{}={host}:{port}", option.name));
                }
            }
            _ => continue,
        }
    }
    flags
}

/// A `NODE_OPTIONS` tokenizer error, matching the text
/// `ParseNodeOptionsEnvVar` puts in `errors`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeOptionsError {
    /// A backslash at the very end of the string.
    InvalidEscape,
    /// A `"` that is never closed.
    UnterminatedString,
}

impl NodeOptionsError {
    /// The message Node passes to `Environment::ThrowError`, including the
    /// trailing newline the C++ literal has.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidEscape => "invalid value for NODE_OPTIONS (invalid escape)\n",
            Self::UnterminatedString => "invalid value for NODE_OPTIONS (unterminated string)\n",
        }
    }
}

/// Splits a `NODE_OPTIONS` string into an argv array.
///
/// This is `ParseNodeOptionsEnvVar` from `src/node_options.cc`, which is the
/// specification for the quoting rules every Node process already relies on:
///
/// * Outside a double-quoted run, a space separates arguments and every other
///   character is literal, including a backslash.
/// * Inside a double-quoted run, `\` escapes the next character and `"`
///   toggles the run off. Quotes are consumed, not included.
/// * A trailing backslash inside a string, or a string left open at the end,
///   is an error, and the arguments parsed so far are discarded.
/// * An empty string yields no arguments, and consecutive spaces do not
///   produce empty arguments.
pub fn parse_node_options(text: &str) -> Result<Vec<String>, NodeOptionsError> {
    let characters: Vec<char> = text.chars().collect();
    let mut arguments: Vec<String> = Vec::new();
    let mut in_string = false;
    let mut starts_new_argument = true;
    let mut index = 0;

    while index < characters.len() {
        let mut character = characters[index];
        if character == '\\' && in_string {
            if index + 1 == characters.len() {
                return Err(NodeOptionsError::InvalidEscape);
            }
            index += 1;
            character = characters[index];
        } else if character == ' ' && !in_string {
            starts_new_argument = true;
            index += 1;
            continue;
        } else if character == '"' {
            in_string = !in_string;
            index += 1;
            continue;
        }

        if starts_new_argument {
            arguments.push(String::new());
            starts_new_argument = false;
        }
        if let Some(last) = arguments.last_mut() {
            // Iterating by `char` rather than by byte keeps multi-byte
            // characters whole without any `unsafe` byte push. The C++ loop
            // walks `std::string` bytes, but a byte it copies is part of a
            // UTF-8 character it copies whole, so the reconstructed string is
            // identical.
            last.push(character);
        }
        index += 1;
    }

    if in_string {
        return Err(NodeOptionsError::UnterminatedString);
    }
    Ok(arguments)
}

/// `MapNamespaceOptionsAssociations` restricted to a single namespace, which
/// is what `MapOptionsByNamespace` does.
#[must_use]
pub fn namespace_option_names(namespace: OptionNamespace) -> Vec<&'static str> {
    OPTIONS
        .iter()
        .filter(|option| !option.name.is_empty() && !option.is_internal())
        .filter(|option| option.namespace == namespace)
        .map(|option| option.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option::kind;

    fn option(name: &'static str) -> &'static OptionInfo {
        OPTIONS
            .iter()
            .find(|option| option.name == name)
            .unwrap_or_else(|| panic!("{name} is not in the table"))
    }

    #[test]
    fn every_option_name_is_unique() {
        let mut names: Vec<&str> = OPTIONS.iter().map(|option| option.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "the C++ table is an unordered_map keyed by option name, so a \
             duplicate would silently overwrite an entry"
        );
    }

    #[test]
    fn table_length_matches_the_cpp_sources() {
        // Two independent counts: how many `AddOption(` calls the file has, and
        // how many survived preprocessing. A parser regression usually shows up
        // as the second being smaller than the first.
        assert_eq!(
            crate::table::SOURCE_ADD_OPTION_SITES,
            crate::table::OPTIONS.len(),
            "the generator saw a different number of AddOption calls than it emitted"
        );
        assert_eq!(
            crate::table::PARSED_OPTION_COUNT,
            crate::table::OPTIONS.len(),
            "options were dropped between parsing and emission"
        );
        assert_eq!(
            crate::table::SOURCE_ADD_ALIAS_SITES,
            crate::table::ALIASES.len()
        );
    }

    #[test]
    fn every_kind_and_env_setting_is_in_range() {
        for entry in OPTIONS {
            assert!(
                (0..=kind::MAX).contains(&entry.kind),
                "{} has kind {}",
                entry.name,
                entry.kind
            );
            assert!(
                entry.env_setting == env_setting::ALLOWED
                    || entry.env_setting == env_setting::DISALLOWED,
                "{} has env setting {}",
                entry.name,
                entry.env_setting
            );
        }
    }

    #[test]
    fn every_default_matches_its_declared_type() {
        // A `kBoolean` reporting `undefined` would make `getCLIOptionsValues`
        // disagree with the option's own type, which no consumer expects.
        for entry in OPTIONS {
            let matches = match entry.kind {
                kind::NO_OP | kind::V8_OPTION => {
                    matches!(entry.default, DefaultValue::Undefined)
                }
                kind::BOOLEAN => matches!(entry.default, DefaultValue::Bool(_)),
                kind::INTEGER => matches!(entry.default, DefaultValue::Int(_)),
                kind::U_INTEGER => matches!(entry.default, DefaultValue::Uint(_)),
                kind::STRING => matches!(entry.default, DefaultValue::Str(_)),
                kind::STRING_LIST => matches!(entry.default, DefaultValue::List(_)),
                kind::HOST_PORT => matches!(entry.default, DefaultValue::HostPort(..)),
                other => panic!("{} has unknown kind {other}", entry.name),
            };
            assert!(
                matches,
                "{} has a default that does not fit its kind",
                entry.name
            );
        }
    }

    #[test]
    fn every_public_option_has_a_leading_dashes_name() {
        for entry in OPTIONS {
            assert!(
                entry.name.starts_with("--") || entry.is_internal(),
                "{} is neither a long flag nor an internal target",
                entry.name
            );
        }
    }

    #[test]
    fn option_types_are_the_enum_positions_from_node_options_h() {
        // `lib/internal/main/print_help.js` derives `typeLookup` from
        // `ObjectKeys(types)`, so these names and values are load-bearing.
        let expected = [
            ("kNoOp", 0),
            ("kV8Option", 1),
            ("kBoolean", 2),
            ("kInteger", 3),
            ("kUInteger", 4),
            ("kString", 5),
            ("kHostPort", 6),
            ("kStringList", 7),
        ];
        assert_eq!(crate::table::TYPES, expected);
        for (name, value) in crate::table::TYPES {
            assert_eq!(
                crate::table::TYPES
                    .iter()
                    .filter(|(_, v)| v == value)
                    .count(),
                1,
                "{name} is duplicated"
            );
        }
    }

    #[test]
    fn cli_values_report_the_declared_defaults() {
        let entries: std::collections::BTreeMap<String, CliValue> =
            cli_values().into_iter().collect();

        // A string field with an empty default still reports the empty string,
        // not undefined: `getOptionValue('--title')` relies on that.
        assert_eq!(entries["--title"], CliValue::Text(""));
        assert_eq!(entries["--input-type"], CliValue::Text(""));
        assert_eq!(entries["--conditions"], CliValue::TextList(&[]));
        assert_eq!(entries["--stack-trace-limit"], CliValue::Number(10.0));
        assert_eq!(entries["--v8-pool-size"], CliValue::Number(4.0));
        assert_eq!(entries["--max-http-header-size"], CliValue::Number(16384.0));
        assert_eq!(
            entries["--trace-event-file-pattern"],
            CliValue::Text("node_trace.${rotation}.log")
        );
        assert_eq!(
            entries["--inspect-port"],
            CliValue::HostPort("127.0.0.1", 9229)
        );
    }

    #[test]
    fn no_op_and_v8_options_are_undefined_with_two_exceptions() {
        let entries: std::collections::BTreeMap<String, CliValue> =
            cli_values().into_iter().collect();

        // Both are `kV8Option` entries Node reads for its own purposes.
        assert_eq!(
            entries["--abort-on-uncaught-exception"],
            CliValue::Bool(false)
        );
        assert_eq!(entries["--stack-trace-limit"], CliValue::Number(10.0));

        // Everything else in those two categories is undefined.
        for entry in OPTIONS {
            if entry.kind != kind::NO_OP && entry.kind != kind::V8_OPTION {
                continue;
            }
            if entry.name == "--abort-on-uncaught-exception" || entry.name == "--stack-trace-limit"
            {
                continue;
            }
            assert_eq!(
                entries[entry.name],
                CliValue::Undefined,
                "{} should report undefined",
                entry.name
            );
        }
    }

    #[test]
    fn booleans_also_publish_a_negated_key() {
        let entries = cli_values();
        let position = |name: &str| {
            entries
                .iter()
                .position(|(key, _)| key == name)
                .unwrap_or_else(|| panic!("{name} is missing"))
        };

        // Node pushes the `--no-` pair before the option itself, which decides
        // the property order of the returned object.
        let negated = position("--no-zero-fill-buffers");
        let plain = position("--zero-fill-buffers");
        assert_eq!(negated + 1, plain, "the negated key comes first");
        assert_eq!(entries[negated].1, CliValue::Bool(true));
        assert_eq!(entries[plain].1, CliValue::Bool(false));

        // Options whose field default is true invert the other way: the
        // option reports `true` and the negation reports `false`.
        let negated = position("--no-experimental-webstorage");
        let plain = position("--experimental-webstorage");
        assert_eq!(negated + 1, plain);
        assert_eq!(entries[negated].1, CliValue::Bool(false));
        assert_eq!(entries[plain].1, CliValue::Bool(true));
    }

    #[test]
    fn every_boolean_has_exactly_one_negated_key() {
        let entries = cli_values();
        let booleans = OPTIONS.iter().filter(|o| o.kind == kind::BOOLEAN).count();
        let non_booleans = OPTIONS.len() - booleans;
        assert_eq!(entries.len(), booleans * 2 + non_booleans);
        for entry in OPTIONS {
            if entry.kind != kind::BOOLEAN {
                continue;
            }
            let negated = entry.negated_name().expect("a boolean has a negation");
            assert!(
                entries.iter().any(|(key, _)| *key == negated),
                "{} has no {negated} entry",
                entry.name
            );
        }
    }

    #[test]
    fn cli_info_carries_the_metadata_the_js_layer_reads() {
        let (options, aliases) = cli_info();
        assert_eq!(options.len(), OPTIONS.len());

        let info = |name: &str| {
            options
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, metadata)| *metadata)
                .unwrap_or_else(|| panic!("{name} is missing"))
        };

        // `internal/process/per_thread.js` compares `envVarSettings` against
        // `kAllowedInEnvvar` (0) to build process.allowedNodeEnvironmentFlags.
        assert_eq!(info("--title").env_setting, 0);
        assert_eq!(info("--title").kind, kind::STRING);
        assert_eq!(info("--help").env_setting, 1);
        assert_eq!(info("--help").kind, kind::BOOLEAN);
        // default_is_true is a help-text hint only, and it deliberately
        // disagrees with the field default for a few options: `--addons`
        // hints true, while `--experimental-addon-modules` defaults to true
        // with no hint. Both facts are visible in the table, which is why the
        // hint is kept separate from `default`.
        assert!(info("--addons").default_is_true);
        assert!(!info("--zero-fill-buffers").default_is_true);
        assert!(!info("--experimental-addon-modules").default_is_true);
        assert!(matches!(
            option("--experimental-addon-modules").default,
            DefaultValue::Bool(true)
        ));

        assert_eq!(aliases.len(), crate::table::ALIASES.len());
        let alias = |from: &str| {
            aliases
                .iter()
                .find(|alias| alias.from == from)
                .unwrap_or_else(|| panic!("{from} is missing"))
        };
        assert_eq!(alias("-h").to, &["--help"]);
        assert_eq!(alias("-v").to, &["--version"]);
        assert_eq!(alias("--debug-port").to, &["--inspect-port"]);
        assert_eq!(
            alias("--inspect=").to,
            &["--inspect-port", "--inspect"],
            "a group alias keeps its expansion order"
        );
    }

    #[test]
    fn embedder_options_are_all_false_without_an_embedder() {
        let options = EmbedderOptions::for_standalone_executable();
        assert!(!options.should_not_register_esm_loader);
        assert!(!options.no_global_search_paths);
        assert!(!options.no_browser_globals);
        assert!(!options.has_embedder_preload);
    }

    #[test]
    fn input_type_names_follow_add_option_type_to_object() {
        assert_eq!(input_type_name(kind::BOOLEAN), Some("boolean"));
        // kInteger, kUInteger and kHostPort all become "number".
        assert_eq!(input_type_name(kind::INTEGER), Some("number"));
        assert_eq!(input_type_name(kind::U_INTEGER), Some("number"));
        assert_eq!(input_type_name(kind::HOST_PORT), Some("number"));
        assert_eq!(input_type_name(kind::STRING), Some("string"));
        assert_eq!(input_type_name(kind::STRING_LIST), Some("array"));
        // V8 flags are skipped rather than described.
        assert_eq!(input_type_name(kind::NO_OP), None);
        assert_eq!(input_type_name(kind::V8_OPTION), None);
    }

    #[test]
    fn env_input_types_only_list_options_node_options_may_set() {
        let entries = env_options_input_types();
        assert!(!entries.is_empty());
        for entry in &entries {
            let option = option(entry.name);
            assert_eq!(option.env_setting, env_setting::ALLOWED, "{}", entry.name);
            assert!(!option.is_internal(), "{}", entry.name);
            assert!(!entry.name.is_empty());
            assert_ne!(entry.type_name, "", "{} has no type", entry.name);
        }
        // `--help` is disallowed in NODE_OPTIONS, so it must not appear.
        assert!(
            !entries.iter().any(|entry| entry.name == "--help"),
            "--help is kDisallowedInEnvvar"
        );
        assert!(entries.iter().any(|entry| entry.name == "--title"));
    }

    #[test]
    fn namespace_input_types_cover_every_namespace_in_order() {
        let namespaces = namespace_options_input_types();
        assert_eq!(namespaces.len(), NAMESPACES.len());
        let names: Vec<&str> = namespaces
            .iter()
            .map(|(namespace, _)| namespace.as_str())
            .collect();
        assert_eq!(names, vec!["bench", "test", "watch", "permission"]);

        // Node inserts a map for every available namespace, even an empty one.
        for (namespace, entries) in &namespaces {
            for entry in entries {
                assert_eq!(option(entry.name).namespace, *namespace);
            }
        }
        let permission = namespaces
            .iter()
            .find(|(namespace, _)| *namespace == OptionNamespace::Permission)
            .map(|(_, entries)| entries)
            .expect("permission exists");
        assert!(
            permission
                .iter()
                .any(|entry| entry.name == "--allow-fs-read"),
            "permission options are namespaced"
        );
        let bench = namespaces
            .iter()
            .find(|(namespace, _)| *namespace == OptionNamespace::Bench)
            .map(|(_, entries)| entries)
            .expect("bench exists");
        assert!(bench.iter().any(|entry| entry.name == "--bench-samples"));
    }

    #[test]
    fn options_as_flags_reports_the_reportable_defaults() {
        let flags = options_as_flags();
        // A bare `node -e ''` reports the non-zero numeric and non-empty string
        // defaults, because the C++ switch prints those unconditionally. This
        // is the set Node 22 produces for a bare invocation.
        let expected = [
            // These two boolean fields default to true but carry no
            // default_is_true hint, so the C++ switch reports them by name.
            "--experimental-addon-modules",
            "--node-snapshot",
            "--inspect-port=127.0.0.1:9229",
            "--inspect-publish-uid=stderr,http",
            "--network-family-autoselection-attempt-timeout=500",
            "--heapsnapshot-near-heap-limit=0",
            "--cpu-prof-interval=1000",
            "--heap-prof-interval=524288",
            "--max-http-header-size=16384",
            "--test-concurrency=0",
            "--test-timeout=0",
            "--test-coverage-branches=0",
            "--test-coverage-functions=0",
            "--test-coverage-lines=0",
            "--test-isolation=process",
            "--test-random-seed=0",
            "--watch-kill-signal=SIGTERM",
            "--stack-trace-limit=10",
            "--report-signal=SIGUSR2",
            "--trace-event-file-pattern=node_trace.${rotation}.log",
            "--v8-pool-size=4",
            "--secure-heap=0",
            "--secure-heap-min=2",
            "--use-largepages=off",
        ];
        // The cipher list is long; assert it separately rather than inline.
        assert!(
            flags
                .iter()
                .any(|flag| flag.starts_with("--tls-cipher-list=TLS_AES_256_GCM_SHA384:")),
            "the TLS cipher list default must be reported"
        );
        let mut without_cipher: Vec<&str> = flags
            .iter()
            .filter(|flag| !flag.starts_with("--tls-cipher-list="))
            .map(String::as_str)
            .collect();
        without_cipher.sort_unstable();
        let mut expected_sorted = expected.to_vec();
        expected_sorted.sort_unstable();
        assert_eq!(without_cipher, expected_sorted);

        // V8 flags are never reported: they belong to V8's own parser.
        assert!(!flags
            .iter()
            .any(|flag| flag.starts_with("--max-old-space-size")));
        // A false boolean is reported by its absence.
        assert!(!flags.iter().any(|flag| flag == "--zero-fill-buffers"));
        // Benchmark options are gated behind --experimental-bench.
        assert!(!flags.iter().any(|flag| flag.starts_with("--bench")));
    }

    #[test]
    fn parse_node_options_handles_the_quoting_rules() {
        // Empty input is no arguments, not one empty argument.
        assert_eq!(parse_node_options("").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_node_options("--a --b=c").unwrap(),
            vec!["--a".to_string(), "--b=c".to_string()]
        );
        // Consecutive spaces do not produce empty arguments.
        assert_eq!(
            parse_node_options("  --a   --b  ").unwrap(),
            vec!["--a".to_string(), "--b".to_string()]
        );
        // Quotes group a value containing spaces and are then dropped.
        assert_eq!(
            parse_node_options(r#"--require "./a b/f.js""#).unwrap(),
            vec!["--require".to_string(), "./a b/f.js".to_string()]
        );
        // A backslash escapes the next character inside quotes only.
        assert_eq!(
            parse_node_options(r#"--title="say \"hi\"""#).unwrap(),
            vec!["--title=say \"hi\"".to_string()]
        );
        // Outside quotes a backslash is literal.
        assert_eq!(
            parse_node_options(r"--path=C:\temp").unwrap(),
            vec![r"--path=C:\temp".to_string()]
        );
        // Adjacent quoted and unquoted runs form one argument.
        assert_eq!(
            parse_node_options(r#"--a=pre"mid dle"post"#).unwrap(),
            vec!["--a=premid dlepost".to_string()]
        );
        // Multi-byte characters survive the byte-wise walk.
        assert_eq!(
            parse_node_options("--title=日本語").unwrap(),
            vec!["--title=日本語".to_string()]
        );
    }

    #[test]
    fn parse_node_options_rejects_malformed_input() {
        // A trailing backslash inside a string.
        assert_eq!(
            parse_node_options(r#"--title="abc\"#),
            Err(NodeOptionsError::InvalidEscape)
        );
        // An unterminated string.
        assert_eq!(
            parse_node_options(r#"--title="abc"#),
            Err(NodeOptionsError::UnterminatedString)
        );
        // The messages are what Node throws, newline included.
        assert_eq!(
            NodeOptionsError::InvalidEscape.message(),
            "invalid value for NODE_OPTIONS (invalid escape)\n"
        );
        assert_eq!(
            NodeOptionsError::UnterminatedString.message(),
            "invalid value for NODE_OPTIONS (unterminated string)\n"
        );
    }

    #[test]
    fn parse_node_options_does_not_reject_a_stray_quote_pair() {
        // `""` is an empty quoted run, which produces no argument: the loop
        // consumes both quotes without ever starting one.
        assert_eq!(parse_node_options(r#""""#).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn namespace_lookups_agree_with_the_table() {
        for namespace in NAMESPACES {
            let names = namespace_option_names(*namespace);
            for name in names {
                assert!(!name.is_empty());
                assert!(!name.starts_with('['));
                assert_eq!(option(name).namespace, *namespace);
            }
        }
    }
}

//! Parsing `NODE_OPTIONS`, with Node's rules about what the variable may set.
//!
//! `src/node.cc` parses this variable inside `InitializeNodeWithArgsInternal`,
//! *before* the command line, in two steps:
//!
//! 1. `ParseNodeOptionsEnvVar` (`src/node_options.cc:2575`) tokenizes the
//!    string. Its quoting rules are [`crate::values::parse_node_options`].
//! 2. The result is fed to the same `OptionsParser::Parse` the command line
//!    uses, with `required_env_settings = kAllowedInEnvvar`.
//!
//! The second argument is the whole point of this module. `Parse` takes the
//! setting it *requires* and compares it against each option's own
//! `env_setting` (`src/node_options-inl.h:430`):
//!
//! ```text
//! if ((it == options_.end() ||
//!      it->second.env_setting == kDisallowedInEnvvar) &&
//!     required_env_settings == kAllowedInEnvvar) {
//!   errors->push_back(NotAllowedInEnvErr(original_name));
//!   break;
//! }
//! ```
//!
//! So in this mode an option the table does not know is rejected exactly like
//! one it marks `kDisallowedInEnvvar` — `--not-a-real-flag` and `--eval` both
//! fail with the same message shape. "Parse everything and ignore what does not
//! fit" would accept a typo in the variable and then silently not apply it,
//! which is the failure this module exists to remove.
//!
//! # The four differences from the command-line walk
//!
//! [`Store::apply`](crate::parsed::Store::apply) models the command-line half
//! of `Parse`, where a bad flag is the CLI's problem to report. Here the walk
//! has to stop at the first error and hand back Node's message, because the
//! process does not start. The differences that follow from that:
//!
//! * an unknown option is an error instead of being skipped for the CLI;
//! * `--` is an error rather than the end of the flags (`Parse` says so
//!   explicitly at line 359);
//! * a negated non-boolean is an error rather than being dropped;
//! * a flag whose value is missing is an error rather than being left at its
//!   default.
//!
//! Ordering is otherwise identical, including the parts that are easy to get
//! wrong: aliases expand before the table lookup, `Implies` is keyed by the
//! *post*-alias name, and a `kStringList` option appends so the command line's
//! occurrences follow the environment's.

use std::collections::VecDeque;

use crate::option::{env_setting, kind};
use crate::parsed::{alias_for, normalize_underscores, Store};
use crate::table::OPTIONS;
use crate::values::parse_node_options;

/// What a successful `NODE_OPTIONS` parse produced.
///
/// The parsed values are returned separately by [`parse`] rather than stored
/// here, because they become the base the command line is parsed on top of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvOptions {
    /// The tokenized flags, in the order they appeared.
    ///
    /// The command line is parsed on top of these, which is why a list option
    /// such as `--require` ends up holding the environment's entries before the
    /// command line's. Node's own test for that is `test-process-exec-argv`.
    pub argv: Vec<String>,
    /// The V8 flags among them.
    ///
    /// V8 has to see these before `V8::initialize`, so the CLI cannot wait for
    /// the option store to be installed; it forwards this list separately.
    pub v8_args: Vec<String>,
    /// `NODE_USE_ENV_PROXY`: `use_env_proxy`'s environment spelling.
    ///
    /// This is `HandleEnvOptions` (`src/node_options.cc:2555`), the second
    /// source a `BOOL_FIELD` can come from besides the option table. It runs
    /// from `InitializeOncePerProcess` *before* either `NODE_OPTIONS` or the
    /// command line is parsed, so both of them override it: measured on the
    /// oracle, `NODE_USE_ENV_PROXY=1 ... --no-use-env-proxy` leaves the proxy
    /// off and `NODE_USE_ENV_PROXY=0 ... --use-env-proxy` turns it on.
    ///
    /// Only `use_env_proxy` is here. Node's `HandleEnvOptions` also reads
    /// `NODE_PENDING_DEPRECATION`, `NODE_PRESERVE_SYMLINKS`,
    /// `NODE_PRESERVE_SYMLINKS_MAIN` and `NODE_USE_SYSTEM_CA` into the same
    /// struct; those keep their existing `getOptionValue`-only paths here
    /// because their consumers already read the store and this change is
    /// scoped to the flags it names.
    pub node_use_env_proxy: bool,
}

impl EnvOptions {
    /// Reads the environment-only option sources, the way
    /// `HandleEnvOptions` does.
    ///
    /// Anything other than `"1"` is `false`, including `"0"`, an empty value
    /// and an unset variable: Node compares the whole string to `"1"`.
    #[must_use]
    pub fn from_process_env() -> Self {
        Self {
            node_use_env_proxy: std::env::var("NODE_USE_ENV_PROXY").as_deref() == Ok("1"),
            ..Self::default()
        }
    }
}

/// A rejected `NODE_OPTIONS` value.
///
/// The message is Node's, verbatim, because it is printed after `"<program>: "`
/// and users grep for it. `NotAllowedInEnvErr`, `RequiresArgumentErr` and
/// `NegationImpliesBooleanError` are the three helpers at
/// `src/node_options-inl.h:277-287`; the tokenizer's two messages come from
/// `ParseNodeOptionsEnvVar`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvError(String);

impl EnvError {
    /// The text Node prints after `"<program>: "`.
    ///
    /// A tokenizer message keeps the trailing newline the C++ literal carries,
    /// which is why a malformed escape prints a blank line after the error:
    /// `FPrintF(stderr, "%s: %s\n", …)` adds a second one.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }

    fn not_allowed(name: &str) -> Self {
        Self(format!("{name} is not allowed in NODE_OPTIONS"))
    }

    fn requires_argument(name: &str) -> Self {
        Self(format!("{name} requires an argument"))
    }

    fn invalid_negation(argument: &str) -> Self {
        Self(format!(
            "{argument} is an invalid negation because it is not a boolean option"
        ))
    }
}

/// Tokenizes `text` and applies every flag in it to a fresh option store.
///
/// Returns the flags that were accepted and a store whose values are the
/// environment's. The caller parses the command line on top of that store, so
/// a scalar given in both places takes the command line's value and a list
/// keeps both.
///
/// # Errors
///
/// Returns the first error `Parse` would have recorded. Node collects them in a
/// vector and prints all of them, but its loop breaks on the first one, so there
/// is never more than one.
pub fn parse(text: &str) -> Result<(EnvOptions, Store), EnvError> {
    let argv = parse_node_options(text).map_err(|error| EnvError(error.message().to_string()))?;

    let mut store = Store::parse(&[]);
    let mut v8_args = Vec::new();
    let mut pending: VecDeque<String> = argv.iter().cloned().collect();

    while let Some(first) = pending.front() {
        // `Parse` stops at the first argument that is not a flag, and at an
        // argument of length <= 1 (the stdin marker). Everything after it is
        // not an option, so `NODE_OPTIONS="--require x app.js --bogus"` stops
        // at `app.js` rather than rejecting `--bogus`.
        if first.len() <= 1 || !first.starts_with('-') {
            break;
        }
        let Some(argument) = pending.pop_front() else {
            break;
        };

        if argument == "--" {
            return Err(EnvError::not_allowed("--"));
        }

        // `--foo=bar` is only split for a two-dash argument, so `-e=a` stays
        // one argument and no alias can be invented out of it.
        let equals = if argument.starts_with("--") {
            argument.find('=')
        } else {
            None
        };
        let (raw_name, inline) = match equals {
            Some(index) => (&argument[..index], Some(argument[index + 1..].to_string())),
            None => (argument.as_str(), None),
        };

        // The name as written, before alias expansion, with the `=` a caller
        // typed. This is what the "is not allowed" and "requires an argument"
        // messages name, which is why `--eval=1` reports `--eval=` and not
        // `--eval`.
        let mut original_name = raw_name.to_string();
        if equals.is_some() {
            original_name.push('=');
        }

        let mut name = normalize_underscores(raw_name);

        let negated = name.starts_with("--no-");
        if negated {
            name = format!("--{}", &name[5..]);
        }

        // Aliases resolve repeatedly and the loop stops when a step would not
        // rename anything; synthetic arguments from a multi-target expansion go
        // back to the front of the queue, exactly as `ArgsInfo::synthetic_args`
        // does.
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

        // The unknown-option check comes *before* the implications, and both
        // come before the value is read. A flag this runtime has never heard of
        // therefore fails by name rather than by a downstream symptom.
        let Some(option) = OPTIONS.iter().find(|option| option.name == name) else {
            return Err(EnvError::not_allowed(&original_name));
        };
        if option.env_setting == env_setting::DISALLOWED {
            return Err(EnvError::not_allowed(&original_name));
        }

        // `Implies` is keyed by the post-alias name, and by the `--no-`
        // spelling when the option was negated.
        let implied_name = if negated {
            format!("--no-{}", &name[2..])
        } else {
            name.clone()
        };
        store.apply_implications(&implied_name);

        // `--no-` is only meaningful for a boolean. V8 options are allowed
        // through because V8 validates its own spellings.
        if negated && option.kind != kind::BOOLEAN && option.kind != kind::V8_OPTION {
            return Err(EnvError::invalid_negation(&argument));
        }

        let mut value = inline;
        if option.kind != kind::BOOLEAN
            && option.kind != kind::NO_OP
            && option.kind != kind::V8_OPTION
        {
            // `--run` may be given without a script name so that a bare `--run`
            // lists the available scripts, which is the one option whose value
            // is optional.
            let optional_value = name == "--run";
            match value.take() {
                Some(inline_value) => {
                    if inline_value.is_empty() && !optional_value {
                        return Err(EnvError::requires_argument(&original_name));
                    }
                    value = Some(inline_value);
                }
                None => {
                    let next_looks_like_a_flag =
                        pending.front().is_none_or(|next| next.starts_with('-'));
                    if pending.is_empty() || (optional_value && next_looks_like_a_flag) {
                        if !optional_value {
                            return Err(EnvError::requires_argument(&original_name));
                        }
                    } else {
                        let Some(raw) = pending.pop_front() else {
                            return Err(EnvError::requires_argument(&original_name));
                        };
                        // A value may not begin with `-`, because that is a
                        // flag the user meant separately. `\-` escapes one.
                        if raw.starts_with('-') {
                            return Err(EnvError::requires_argument(&original_name));
                        }
                        value = Some(raw.strip_prefix("\\-").unwrap_or(&raw).to_string());
                    }
                }
            }
        }

        // The two kinds that belong to V8 rather than to a Node field. They are
        // forwarded to V8 before it initialises; recording them here is what
        // makes `NODE_OPTIONS=--max-old-space-size=100` size the heap and
        // `--stack-trace-limit=42` reach `Error.stackTraceLimit`.
        match option.kind {
            kind::V8_OPTION => v8_args.push(argument.clone()),
            kind::INTEGER if name == "--stack-trace-limit" => v8_args.push(argument.clone()),
            _ => {}
        }

        store.assign(option, negated, value.as_deref());
    }

    // `NODE_OPTIONS` is not one of `HandleEnvOptions`'s sources, so the
    // variable-only field stays at its default here; see [`EnvOptions::from_process_env`].
    Ok((
        EnvOptions {
            argv,
            v8_args,
            node_use_env_proxy: false,
        },
        store,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsed::ParsedValue;

    fn parse_ok(text: &str) -> (EnvOptions, Store) {
        parse(text).unwrap_or_else(|error| panic!("{text:?} was rejected: {}", error.message()))
    }

    fn error_of(text: &str) -> String {
        match parse(text) {
            Ok(_) => panic!("{text:?} was accepted"),
            Err(error) => error.message().to_string(),
        }
    }

    #[test]
    fn an_empty_variable_is_no_flags() {
        let (options, store) = parse_ok("");
        assert!(options.argv.is_empty());
        assert!(options.v8_args.is_empty());
        assert_eq!(store.value_of("--warnings"), Some(ParsedValue::Bool(true)));
    }

    #[test]
    fn an_allowed_flag_reaches_the_store() {
        let (options, store) = parse_ok("--max-http-header-size=32768");
        assert_eq!(options.argv, ["--max-http-header-size=32768"]);
        assert_eq!(
            store.value_of("--max-http-header-size"),
            Some(ParsedValue::UInt(32768))
        );
    }

    #[test]
    fn a_list_option_collects_every_occurrence() {
        let (_, store) = parse_ok(r#"--require ./a.js --require "./b c.js""#);
        assert_eq!(
            store.value_of("--require"),
            Some(ParsedValue::List(vec![
                "./a.js".to_string(),
                "./b c.js".to_string()
            ]))
        );
    }

    #[test]
    fn a_value_may_be_a_separate_argument() {
        let (_, store) = parse_ok("--require ./pre.js");
        assert_eq!(
            store.value_of("--require"),
            Some(ParsedValue::List(vec!["./pre.js".to_string()]))
        );
    }

    #[test]
    fn an_alias_resolves_before_the_allow_list_is_consulted() {
        // `-r` is not in the table; `--require` is. Node expands first, so the
        // single-dash spelling is accepted.
        let (options, store) = parse_ok("-r ./pre.js");
        assert_eq!(options.argv, ["-r", "./pre.js"]);
        assert_eq!(
            store.value_of("--require"),
            Some(ParsedValue::List(vec!["./pre.js".to_string()]))
        );
    }

    #[test]
    fn an_unknown_flag_is_rejected() {
        assert_eq!(
            error_of("--not-a-real-flag"),
            "--not-a-real-flag is not allowed in NODE_OPTIONS"
        );
    }

    #[test]
    fn a_disallowed_flag_is_rejected_by_the_name_as_written() {
        assert_eq!(
            error_of("--eval=1"),
            "--eval= is not allowed in NODE_OPTIONS"
        );
        assert_eq!(error_of("-e 1"), "-e is not allowed in NODE_OPTIONS");
        assert_eq!(error_of("--help"), "--help is not allowed in NODE_OPTIONS");
    }

    #[test]
    fn an_underscored_disallowed_flag_is_rejected_by_its_original_spelling() {
        // The `_` to `-` normalization happens after `original_name` is
        // recorded, so the message repeats what the user typed.
        assert_eq!(
            error_of("--expose_internals"),
            "--expose_internals is not allowed in NODE_OPTIONS"
        );
    }

    #[test]
    fn a_negated_disallowed_flag_names_the_negation() {
        assert_eq!(
            error_of("--no-eval"),
            "--no-eval is not allowed in NODE_OPTIONS"
        );
    }

    #[test]
    fn a_double_dash_is_rejected() {
        assert_eq!(error_of("--"), "-- is not allowed in NODE_OPTIONS");
    }

    #[test]
    fn a_missing_value_is_rejected() {
        assert_eq!(error_of("--require"), "--require requires an argument");
        assert_eq!(
            error_of("--max-http-header-size="),
            "--max-http-header-size= requires an argument"
        );
        // A following flag is not a value.
        assert_eq!(
            error_of("--title --expose-gc"),
            "--title requires an argument"
        );
    }

    #[test]
    fn a_negated_non_boolean_is_rejected() {
        assert_eq!(
            error_of("--no-max-http-header-size"),
            "--no-max-http-header-size is an invalid negation because it is not a boolean option"
        );
    }

    #[test]
    fn the_walk_stops_at_the_first_non_flag() {
        // `Parse` breaks rather than continuing, so a flag after a positional
        // argument is never examined and cannot be rejected.
        let (_, store) = parse_ok("--require x.js app.js --bogus");
        assert_eq!(
            store.value_of("--require"),
            Some(ParsedValue::List(vec!["x.js".to_string()]))
        );
    }

    #[test]
    fn a_malformed_quote_reports_the_tokenizer_message_with_its_newline() {
        assert_eq!(
            error_of(r#"--title="abc\"#),
            "invalid value for NODE_OPTIONS (invalid escape)\n"
        );
        assert_eq!(
            error_of(r#"--title="abc"#),
            "invalid value for NODE_OPTIONS (unterminated string)\n"
        );
    }

    #[test]
    fn v8_flags_are_collected_for_forwarding() {
        let (options, store) = parse_ok("--max-old-space-size=100 --stack-trace-limit=42");
        assert_eq!(
            options.v8_args,
            ["--max-old-space-size=100", "--stack-trace-limit=42"]
        );
        // Both still land in the store, where `getOptionValue` reads them.
        assert_eq!(
            store.value_of("--stack-trace-limit"),
            Some(ParsedValue::Int(42))
        );
    }

    #[test]
    fn every_collected_flag_is_allowed_in_an_envvar() {
        // The forwarding list is built from the table, so this pins the
        // property the CLI relies on: nothing it hands to V8 was disallowed.
        //
        // `--stack-size` is deliberately absent from this list. V8 accepts it
        // and rustnode forwards it from the command line, but Node's table has
        // no entry for it, so `NODE_OPTIONS=--stack-size=512` fails with "is not
        // allowed in NODE_OPTIONS" — verified against the oracle.
        let (options, _) = parse_ok(
            "--max-old-space-size=100 --stack-trace-limit=42 \
             --expose-gc --abort-on-uncaught-exception",
        );
        assert_eq!(options.v8_args.len(), 4);
        for argument in &options.v8_args {
            let name = argument
                .split_once('=')
                .map_or(argument.as_str(), |(n, _)| n);
            let name = normalize_underscores(name);
            let option = OPTIONS
                .iter()
                .find(|option| option.name == name)
                .unwrap_or_else(|| panic!("{name} is not in the table"));
            assert_eq!(
                option.env_setting,
                env_setting::ALLOWED,
                "{name} may not be set from NODE_OPTIONS"
            );
        }
    }

    #[test]
    fn a_v8_flag_node_does_not_declare_is_still_rejected() {
        // `--stack-size` reaches V8 on the command line, but `Parse` only
        // forwards a V8 flag it finds an option entry for. A runtime that
        // accepted everything starting with `--` here would let a typo through.
        assert_eq!(
            error_of("--stack-size=512"),
            "--stack-size= is not allowed in NODE_OPTIONS"
        );
    }

    #[test]
    fn a_negated_boolean_clears_it() {
        let (_, store) = parse_ok("--no-warnings");
        assert_eq!(store.value_of("--warnings"), Some(ParsedValue::Bool(false)));
    }

    #[test]
    fn an_implication_still_fires() {
        // `--inspect-brk` implies `--inspect`; the environment half of `Parse`
        // records implications before it looks at the value.
        let (_, store) = parse_ok("--inspect-brk");
        assert_eq!(store.value_of("--inspect"), Some(ParsedValue::Bool(true)));
    }
}

//! The shape of one entry in Node's option table.
//!
//! `src/node_options.h` defines two enums that cross into JavaScript as
//! numbers, so the Rust side has to keep them as numbers too. Everything else
//! here exists to let `table.rs` (generated) describe an option without
//! repeating itself.

/// `options_parser::OptionType` from `src/node_options.h`.
///
/// The numeric values are part of the binding's observable interface: the
/// JavaScript layer receives them as `types` and as each option's `type`
/// field, and `lib/internal/main/print_help.js` builds a reverse lookup table
/// from `types` by index.
pub mod kind {
    pub const NO_OP: i32 = 0;
    pub const V8_OPTION: i32 = 1;
    pub const BOOLEAN: i32 = 2;
    pub const INTEGER: i32 = 3;
    pub const U_INTEGER: i32 = 4;
    pub const STRING: i32 = 5;
    pub const HOST_PORT: i32 = 6;
    pub const STRING_LIST: i32 = 7;

    /// Upper bound for the range check the unit tests apply to the table.
    pub const MAX: i32 = STRING_LIST;
}

/// `node::OptionEnvvarSettings` from `src/node.h`.
///
/// `kAllowedInEnvvar` is 0, so an option may be set through `NODE_OPTIONS`;
/// `kDisallowedInEnvvar` is the default when `AddOption` omits the argument.
pub mod env_setting {
    pub const ALLOWED: i32 = 0;
    pub const DISALLOWED: i32 = 1;
}

/// Which option namespace an option belongs to.
///
/// `options_parser::OptionNamespaces` carries a string for each entry, and
/// `getNamespaceOptionsInputType` keys its result by it. Only `permission`,
/// `test`, `watch` and `bench` have options today; `None` is the empty string
/// and means "not namespaced".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionNamespace {
    None,
    Bench,
    Test,
    Watch,
    Permission,
}

impl OptionNamespace {
    /// The `namespace_id` string the C++ parser stores.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Bench => "bench",
            Self::Test => "test",
            Self::Watch => "watch",
            Self::Permission => "permission",
        }
    }
}

/// The initial value of one option in a process that was started with no
/// arguments.
///
/// rustnode has no command-line option parser yet, so `getCLIOptionsValues`
/// reports these. They come from the field initializers in
/// `src/node_options.h`, which is what Node itself starts from before any
/// source is parsed, rather than from guesswork.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DefaultValue {
    /// `kNoOp` and `kV8Option` options have no field, so they report
    /// `undefined` unless the binding special-cases them.
    Undefined,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Str(&'static str),
    List(&'static [&'static str]),
    /// `HostPort` reports `{ host, port }`, a null-prototype object.
    HostPort(&'static str, u16),
}

/// One `AddOption(...)` call.
#[derive(Debug, Clone, Copy)]
pub struct OptionInfo {
    /// The flag as written, including the leading `--`, or `"[name]"` for an
    /// internal target that is not a public flag.
    pub name: &'static str,
    pub help_text: &'static str,
    /// One of the `kind` constants.
    pub kind: i32,
    /// One of the `env_setting` constants.
    pub env_setting: i32,
    /// Only a hint for `--help` output (`AddOption` says so explicitly): it
    /// does not describe the default value.
    pub default_is_true: bool,
    pub namespace: OptionNamespace,
    pub default: DefaultValue,
}

impl OptionInfo {
    /// Whether this option is an internal parser target rather than a public
    /// flag. `AddOption` writes those names in brackets, and Node's own
    /// readers skip them the same way.
    #[must_use]
    pub fn is_internal(&self) -> bool {
        self.name.starts_with('[')
    }

    /// The `--no-<name>` spelling a boolean option also answers to.
    ///
    /// `getCLIOptionsValues` emits one of these per boolean option with the
    /// negated value, so `--no-foo` resolves through the same table. Node
    /// writes it as `"--no" + item.first.substr(1)`, which keeps the second
    /// dash of the original name: `--title` becomes `--no-title`, not
    /// `--notitle`.
    #[must_use]
    pub fn negated_name(&self) -> Option<String> {
        if self.kind != kind::BOOLEAN {
            return None;
        }
        Some(format!("--no{}", self.name.get(1..)?))
    }
}

/// One `AddAlias(...)` call: `from` expands to `to`.
#[derive(Debug, Clone, Copy)]
pub struct AliasInfo {
    pub from: &'static str,
    pub to: &'static [&'static str],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boolean(name: &'static str) -> OptionInfo {
        OptionInfo {
            name,
            help_text: "",
            kind: kind::BOOLEAN,
            env_setting: env_setting::ALLOWED,
            default_is_true: false,
            namespace: OptionNamespace::None,
            default: DefaultValue::Bool(false),
        }
    }

    #[test]
    fn negated_name_keeps_both_dashes() {
        // Node builds the negated key as `"--no" + name.substr(1)`, so the
        // second dash of `--foo` survives. `--nofoo` would be a different flag
        // and would silently never match `--no-foo`.
        assert_eq!(
            boolean("--zero-fill-buffers").negated_name().as_deref(),
            Some("--no-zero-fill-buffers")
        );
        assert_eq!(
            boolean("--title").negated_name().as_deref(),
            Some("--no-title")
        );
    }

    #[test]
    fn only_booleans_have_a_negated_name() {
        let mut option = boolean("--title");
        option.kind = kind::STRING;
        assert_eq!(option.negated_name(), None);
    }

    #[test]
    fn bracketed_options_are_internal() {
        assert!(boolean("[has_eval_string]").is_internal());
        assert!(!boolean("--eval").is_internal());
    }
}

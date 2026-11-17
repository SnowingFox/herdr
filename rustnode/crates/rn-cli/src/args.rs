//! Command-line parsing.
//!
//! Node's flags are part of its interface: the test suite passes
//! `--no-warnings`, `--expose-internals` and about 40 others, and a runtime that
//! refuses them cannot run those tests at all. So the parser separates three
//! things that were previously one:
//!
//! * flags rustnode acts on (the eval/print forms and `--expose-internals`);
//! * flags it accepts and records without acting on yet, because the feature
//!   behind them has not landed. Accepting a flag whose behaviour is not
//!   implemented is honest as long as the gap is visible, so each one is
//!   reported through [`Options::unimplemented`];
//! * the script itself, which is the first argument that is not a flag.
//!
//! Anything unknown is still an error rather than being silently ignored,
//! because a typo in a flag otherwise changes nothing and hides a mistake.

use std::collections::BTreeSet;

/// Why the process may not start.
///
/// The three sources print differently, and the difference is Node's, not
/// cosmetic:
///
/// * a bad command-line flag is `rustnode: <message>` (Node prints
///   `<program>: bad option: <flag>`, which this parser's own message shape has
///   never matched — see F16 in the loader review);
/// * a bad `NODE_OPTIONS` is `<program>: <message>`, because
///   `StartInternal` prints every collected error as
///   `"%s: %s\n", result->args().at(0), error` and the message is Node's own
///   text. The program name is `argv[0]` verbatim, which is what makes the
///   output byte-identical rather than merely similar;
/// * a rejected option *value* — the errors `CheckOptions` records after the
///   walk, such as a percentage out of range — is printed by that same loop, so
///   it uses `<program>: <message>` too.
///
/// All three exit 9 (`ExitCode::kInvalidCommandLineArgument`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A rejected command-line flag.
    Cli(String),
    /// A rejected `NODE_OPTIONS` value, already in Node's wording.
    NodeOptions(String),
    /// A rejected option value, already in Node's wording.
    ///
    /// Separate from [`ParseError::NodeOptions`] only so the call sites say
    /// which source produced it; both print the same way, because Node's error
    /// vector does not record a source.
    OptionValue(String),
}

/// What the command line asked for.
#[derive(Debug)]
pub struct Options {
    /// `-e`/`--eval`, `-p`/`--print`, or a script path.
    pub source: Source,
    /// Arguments after the script, exposed as `process.argv`.
    pub script_args: Vec<String>,
    /// Every flag seen, in order, for `process.execArgv`.
    pub exec_argv: Vec<String>,
    /// The flags V8 owns, in the order V8 must receive them.
    ///
    /// This is Node's `v8_args` vector (`src/node.cc:756`), and it is filled the
    /// same way `OptionsParser::Parse` fills it: `NODE_OPTIONS`'s flags first,
    /// then the command line's, so a later spelling overrides an earlier one.
    /// An option the table marks `kV8Option` and one the table has never heard
    /// of both land here, because only V8 can say whether a flag exists — that
    /// is the whole reason Node keeps no list of its own.
    ///
    /// `main` hands this to `V8::SetFlagsFromCommandLine` before
    /// `V8::Initialize`, and treats whatever V8 hands back as `bad option`.
    pub v8_args: Vec<String>,
    /// Flags accepted but whose behaviour is not implemented yet.
    pub unimplemented: Vec<String>,
    /// The option layer's view of the same argv.
    ///
    /// `lib/**` reads option values through `internalBinding('options')`, and
    /// that binding reports the table's declared defaults unless the process's
    /// argv was parsed. `--experimental-bench` is the clearest example: without
    /// this, `lib/internal/bootstrap/realm.js` sees `false` and leaves
    /// `node:bench` unrequireable no matter what the command line said.
    pub parsed: rn_bind_options::Store,
    /// The permission model the flags asked for.
    ///
    /// Built by [`finish`] from the same `exec_argv` the parser recorded, and
    /// installed by the CLI before the binding registry exists so
    /// `internalBinding('permission')` and the native checks share one model.
    pub permission: rn_permission::PermissionShared,
    /// The flags that model was built from.
    ///
    /// Kept as well as the model because the environment scrub needs the
    /// `--allow-env` patterns before the model is installed, and re-parsing the
    /// argv to recover them would be a second interpretation of the same flags.
    pub permission_config: rn_permission::PermissionConfig,
    /// `--abort-on-uncaught-exception`: abort the process by signal instead of
    /// reporting an uncaught exception through `process._fatalException`.
    ///
    /// Node reads this from its V8 argument vector in `src/node.cc:794` and
    /// stores it on `EnvironmentOptions`, so it is a real option field rather
    /// than a flag the CLI re-reads at report time. The behavior itself lives in
    /// `rn-errors`, which also consults `shouldAbortOnUncaughtToggle[0]`.
    pub abort_on_uncaught_exception: bool,
    /// The `NODE_OPTIONS` value, already tokenized and accepted.
    ///
    /// `None` when the variable was unset or empty. Kept because the flags have
    /// to reach two places the command line does not: V8 (the variable's flags
    /// go first in [`Self::v8_args`], so a command-line spelling overrides them)
    /// and the option store (`options.parsed` is the environment's values with
    /// the command line applied on top, which is Node's two-pass order).
    ///
    /// They deliberately do **not** reach `exec_argv`: `process.execArgv`
    /// contains only the command line, and passing the environment's flags on
    /// would make a child process inherit them twice.
    pub env_options: Option<rn_bind_options::EnvOptions>,
    /// The flags `NODE_OPTIONS` named, for the parsers that read a list rather
    /// than a single value (the permission model).
    pub env_argv: Vec<String>,
    /// `--inspect`, `--inspect-brk` or `--inspect-wait` was given, in either
    /// source: the endpoint has to be opened.
    ///
    /// Separate from [`Self::inspect`] because `--inspect-port` sets where to
    /// listen without asking to listen at all. Conflating the two made
    /// `rustnode --inspect-port=9339` open a debug socket that Node does not,
    /// and `NODE_OPTIONS=--inspect-port=9339` would have done the same.
    pub inspect_enabled: bool,
    /// `--inspect-brk`: block until a client attaches before running user code.
    pub inspect_wait: bool,
    /// Where the inspector would listen: `--inspect-port`'s value, or
    /// `--inspect`'s when it carried one, or the default.
    ///
    /// This is `process.debugPort` and it is reported whether or not the
    /// endpoint is enabled, which is what makes `--inspect-port` observable
    /// without a socket.
    pub debug_port: InspectRequest,
    /// `--max-old-space-size-percentage`, as the user typed it.
    ///
    /// Kept as the raw string rather than the computed size because it is
    /// converted at the very end of parsing, the way
    /// `PerIsolateOptions::HandleMaxOldSpaceSizePercentage` runs from
    /// `CheckOptions`: the *last* source to set it wins, and only that value is
    /// converted. The conversion needs the machine's memory, so it also cannot
    /// happen during the walk in a way that would be comparable across
    /// processes.
    pub max_old_space_size_percentage: Option<String>,
}

impl Options {
    /// A process that was given no arguments.
    fn new() -> Self {
        Self {
            source: Source::Empty,
            script_args: Vec::new(),
            exec_argv: Vec::new(),
            v8_args: Vec::new(),
            unimplemented: Vec::new(),
            // The table's defaults, which is what a process with no flags
            // reports. `Store::default()` would be empty, and an empty store
            // makes `getCLIOptionsValues` report `undefined` for every option
            // instead of its default.
            parsed: rn_bind_options::Store::parse(&[]),
            permission: rn_permission::PermissionShared::default(),
            permission_config: rn_permission::PermissionConfig::default(),
            abort_on_uncaught_exception: false,
            env_options: None,
            env_argv: Vec::new(),
            inspect_enabled: false,
            inspect_wait: false,
            debug_port: InspectRequest::default_endpoint(),
            max_old_space_size_percentage: None,
        }
    }

    /// Whether `--expose-internals` was passed, which makes `internal/*`
    /// builtins requireable from user code. Node's own tests rely on it.
    pub fn expose_internals(&self) -> bool {
        self.exec_argv
            .iter()
            .any(|flag| flag == "--expose-internals")
    }
}

/// What `--inspect` and its variants asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectRequest {
    /// The port to bind. `0` asks the OS for a free one.
    pub port: u16,
    /// The host to bind.
    pub host: String,
    /// Whether to wait for a client before running user code (`--inspect-brk`).
    pub wait: bool,
}

impl InspectRequest {
    /// The default endpoint: loopback on the inspector's default port.
    fn default_endpoint() -> Self {
        Self {
            port: 9229,
            host: "127.0.0.1".to_string(),
            wait: false,
        }
    }

    /// Parses one `--inspect*` value, keeping `previous_host` when it names no
    /// host.
    ///
    /// This is `SplitHostPort` plus `ParseAndValidatePort`
    /// (`src/node_options.cc:1854-1896`), and every branch is observable:
    ///
    /// * no value means "keep the current address", which is why
    ///   `NODE_OPTIONS=--inspect-port=9339` plus `--inspect` listens on 9339
    ///   rather than falling back to 9229;
    /// * a bare all-digit value is a port and keeps the current host;
    /// * any other colon-free value is a host name and keeps port 9229;
    /// * `[::1]:9339` splits on the last colon and strips the brackets from the
    ///   host half, while a fully bracketed value never splits at all;
    /// * a port that is not a number becomes 0 — `std::from_chars` reports
    ///   `invalid_argument` and leaves the output untouched, which is not one of
    ///   the conditions `ParseAndValidatePort` errors on;
    /// * a port that overflows 16 bits, or that is non-zero below 1024, is
    ///   rejected with Node's exact sentence.
    pub fn parse_with_host(
        value: Option<&str>,
        previous_host: &str,
        wait: bool,
    ) -> Result<Self, String> {
        const BAD_PORT: &str = "must be 0 or in range 1024 to 65535.";

        let Some(value) = value.filter(|value| !value.is_empty()) else {
            return Ok(Self {
                port: 9229,
                host: previous_host.to_string(),
                wait,
            });
        };

        // A pair wrapping the whole value is stripped first and never splits,
        // so `[::1]` is a host and `[::1]:9339` goes on to the colon branch.
        if let Some(host) = value
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            return Ok(Self {
                port: 9229,
                host: host.to_string(),
                wait,
            });
        }

        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => {
                let host = host
                    .strip_prefix('[')
                    .and_then(|rest| rest.strip_suffix(']'))
                    .unwrap_or(host);
                (host, port)
            }
            None => {
                // No colon: a port when every character is a digit, a host name
                // otherwise.
                if !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Ok(Self {
                        port: 9229,
                        host: value.to_string(),
                        wait,
                    });
                }
                ("", value)
            }
        };

        let port = parse_inspect_port(port, BAD_PORT)?;
        Ok(Self {
            port,
            host: if host.is_empty() {
                previous_host.to_string()
            } else {
                host.to_string()
            },
            wait,
        })
    }
}

/// `ParseAndValidatePort`: a `uint16_t` from `std::from_chars`.
///
/// Junk is 0 rather than an error, because `from_chars` reports
/// `invalid_argument` and `ParseAndValidatePort` only checks
/// `result_out_of_range` and the reserved-port rule. A value above 65535 is an
/// error, and so is one in `1..1024`.
fn parse_inspect_port(port: &str, message: &str) -> Result<u16, String> {
    match port.parse::<u32>() {
        Ok(number) => {
            if number > u32::from(u16::MAX) || (number != 0 && number < 1024) {
                Err(message.to_string())
            } else {
                Ok(number as u16)
            }
        }
        Err(error) if *error.kind() == std::num::IntErrorKind::PosOverflow => {
            Err(message.to_string())
        }
        Err(_) => Ok(0),
    }
}

/// Where the code to run comes from.
#[derive(Debug, Default)]
pub enum Source {
    /// Nothing to run: behaves like `-e ''`.
    ///
    /// Only reachable when standard input is a terminal. Node starts the REPL
    /// there, which rustnode does not have, so the closest honest behaviour is
    /// the empty program — an interactive terminal is not a script.
    #[default]
    Empty,
    /// `-e` or `-p`.
    Eval {
        code: String,
        /// `-p` prints the result of the expression.
        print: bool,
    },
    /// A script path.
    File(String),
    /// Standard input, run as a CommonJS module by `internal/main/eval_stdin`.
    ///
    /// This is Node's `eval_stdin` entry point, reached when no script
    /// argument was given and stdin is not a terminal, or when the script
    /// argument was `-`. The two spellings differ in one observable way:
    /// `node -` publishes `"-"` as `process.argv[1]`, while a bare `node` with
    /// a pipe publishes no `argv[1]` at all.
    Stdin {
        /// The `-` marker was given, so it belongs in `process.argv`.
        marker: bool,
    },
}

impl Source {
    /// Whether the entry point is one of Node's `internal/main/**` scripts,
    /// which run pre-execution themselves.
    ///
    /// `-e`, a file and the empty program are driven by the CLI, so the CLI
    /// calls `prepareMainThreadExecution` for them. Stdin is not: the first
    /// line of `eval_stdin.js` is `prepareMainThreadExecution()`, and running it
    /// twice trips `initializeModuleLoaders`' assertion that no user module has
    /// executed.
    pub fn uses_main_script(&self) -> bool {
        matches!(self, Self::Stdin { .. })
    }

    /// The main script id this source runs, when it is one.
    pub fn main_script_id(&self) -> Option<&'static str> {
        match self {
            Self::Stdin { .. } => Some("internal/main/eval_stdin"),
            _ => None,
        }
    }

}

/// Whether standard input is a terminal, which decides what a run with no
/// script argument does.
///
/// Node's dispatch is `first_argv.empty() && uv_guess_handle(STDIN_FILENO) !=
/// UV_TTY` → `internal/main/eval_stdin`. Keeping the answer as a parameter
/// rather than calling `isatty` here keeps this module free of runtime probes
/// and makes both branches testable; the CLI passes what libuv reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinKind {
    /// `uv_guess_handle(STDIN_FILENO) == UV_TTY`.
    Terminal,
    /// Piped, redirected from a file, or `/dev/null` — anything but a tty.
    Redirected,
}

/// Flags that take no separate value and that rustnode deliberately ignores.
///
/// These change Node's behaviour in ways that do not affect whether a script
/// runs: warning categories, source maps, internals exposure. A script that only
/// needs them accepted should run.
///
/// The `--allow-*` permission grants are deliberately *not* here. They carry
/// values, they change what the runtime permits, and accepting them without
/// acting on them was the bug this list used to hide.
///
/// Nor are the flags V8 owns — `--expose-gc` used to be listed here, and being
/// listed meant it was accepted and recorded but never handed to V8, so `gc()`
/// was a name from nowhere. V8-owned flags are now recognised from Node's own
/// option table (`rn_bind_options::is_v8_flag`) and forwarded; see
/// [`record_v8_flag`] and the fallback in [`parse_with_env`].
const IGNORED_WITHOUT_VALUE: &[&str] = &[
    "--disable-proto",
    "--enable-source-maps",
    "--expose-internals",
    "--expose_internals",
    "--experimental-strip-types",
    "--experimental-worker",
    "--frozen-intrinsics",
    "--no-deprecation",
    "--no-warnings",
    "--pending-deprecation",
    "--preserve-symlinks",
    "--preserve-symlinks-main",
    "--throw-deprecation",
    "--trace-deprecation",
    "--trace-warnings",
];

/// Flags whose value is a separate argument (`--flag value`).
const VALUE_SEPARATE: &[&str] = &["--conditions", "--import", "--loader", "--require", "-r"];

/// Flags that select the default trust store.
///
/// Both are read back by `rn-bind-secure-context`'s `addRootCerts`, which is
/// `NewRootCertStore`'s branch order: `--use-openssl-ca` uses OpenSSL's compiled
/// `OPENSSLDIR`, `--use-system-ca` adds the OS store beside the bundled list.
/// `--use-openssl-ca` also has a `NODE_OPTIONS`-visible environment spelling in
/// Node, but the option table is the one place argv is interpreted, so the flag
/// is all that is recorded here.
const ROOT_STORE_FLAGS: &[&str] = &["--use-system-ca", "--use-openssl-ca"];

/// `--abort-on-uncaught-exception` in the spellings Node accepts.
///
/// Both appear in Node's own test headers. `src/node.cc:794` searches its V8
/// argument vector for both, so a runtime that accepts only the dashed form
/// rejects a command line `node` runs.
const ABORT_ON_UNCAUGHT: &[&str] = &[
    "--abort-on-uncaught-exception",
    "--abort_on_uncaught_exception",
];

/// The negations of [`ABORT_ON_UNCAUGHT`], which clear the option.
const ABORT_ON_UNCAUGHT_NEGATED: &[&str] = &[
    "--no-abort-on-uncaught-exception",
    "--no-abort_on_uncaught_exception",
];

/// Flags that are `--flag=value` and may also appear bare.
///
/// The `--allow-*` permission grants are listed here for their `=` form;
/// [`parse`] treats the three that take a path or list (`--allow-env`,
/// `--allow-fs-read`, `--allow-fs-write`) as also accepting a separate argument,
/// because that is a spelling Node's own tests use.
const VALUE_INLINE_PREFIXES: &[&str] = &[
    "--allow-addons=",
    "--allow-child-process=",
    "--allow-env=",
    "--allow-ffi=",
    "--allow-fs-read=",
    "--allow-fs-vfs=",
    "--allow-fs-write=",
    "--allow-inspector=",
    "--allow-net=",
    "--allow-openssl-store=",
    "--allow-wasi=",
    "--allow-worker=",
    "--conditions=",
    "--disable-warning=",
    "--experimental-loader=",
    "--import=",
    "--input-type=",
    "--inspect=",
    "--inspect-brk=",
    "--loader=",
    "--permission=",
    "--title=",
    "--unhandled-rejections=",
];

/// Permission flags that take a value, in either the `=` or the separate form.
///
/// They are the only entries in [`VALUE_INLINE_PREFIXES`] that consume a
/// following argument: `--allow-fs-read /tmp` is how Node's tests spell it, and
/// `--allow-env=A,B` is one occurrence whose value the model splits on commas.
const PERMISSION_VALUE_FLAGS: &[&str] = &["--allow-env", "--allow-fs-read", "--allow-fs-write"];

/// Whether `flag` is one of the permission flags, in any spelling.
///
/// Used to decide whether a flag belongs in the permission model rather than in
/// [`UNIMPLEMENTED`], where it used to be listed. Every one of these is now acted
/// on, so reporting any of them as missing would be a warning that is no longer
/// true.
fn is_permission_flag(flag: &str) -> bool {
    let name = flag.split_once('=').map_or(flag, |(name, _)| name);
    PERMISSION_BOOLEAN_GRANTS.contains(&name)
        || PERMISSION_VALUE_FLAGS.contains(&name)
        || matches!(name, "--permission" | "--permission-audit")
}

/// Permission flags that take no value and turn a scope on.
///
/// Every entry is covered by [`is_permission_flag`]; this list exists so the set
/// of bare grants is stated once, next to the flags that take values. They are
/// not in [`IGNORED_WITHOUT_VALUE`] because they are not ignored:
/// [`Options::permission`] grants the scope when one of these is present, and the
/// enforcement points then allow what they gate.
const PERMISSION_BOOLEAN_GRANTS: &[&str] = &[
    "--allow-addons",
    "--allow-child-process",
    "--allow-ffi",
    "--allow-fs-vfs",
    "--allow-inspector",
    "--allow-net",
    "--allow-openssl-store",
    "--allow-wasi",
    "--allow-worker",
];

/// Flags that enable an experimental surface rustnode has not built yet.
///
/// Accepting them silently would make a test look like it exercised the feature
/// when it did not, so they are recorded in [`Options::unimplemented`].
///
/// A flag belongs here only while the *behaviour* behind it is absent. Three
/// were removed once `rn-bind-options` started publishing their values, because
/// warning about them had become a lie that some tests read:
///
/// * `--experimental-bench` — `node:bench` is now requireable.
/// * `--experimental-stream-iter` — `stream/iter` resolves to the vendored
///   implementation, and the `test-quic-stream-iteration*` files pass.
/// * `--allow-natives-syntax` — forwarded to V8, so `%DebugPrint` and the other
///   natives intrinsics parse instead of throwing `SyntaxError`.
///
/// `--permission` was the fourth, and it has now left the list too. Every scope
/// that is enforced is listed in `crates/rn-permission`'s module documentation;
/// the ones that are not, and the reason each cannot be, are:
///
/// * `wasi` — rustnode has no `internalBinding('wasi')`, so `new WASI()` already
///   throws "the namespace has no Rust implementation yet". A permission check
///   in front of that would report the wrong cause.
/// * `ffi` — no `node:ffi` surface either; `require('node:ffi')` fails on the
///   missing binding for the same reason.
/// * `openssl.store` — the crypto layer has no STORE-loader path to gate.
///
/// The three above are all "no surface exists", so the warning would name a
/// permission gap where the real gap is a missing feature.
///
/// `worker`, `inspector`, `net`, `addon`, `fs` and `child` *are* enforced, so
/// none of them belongs here. `worker` became enforceable with the
/// worker_threads landing; `inspector.open()` checks `inspector`.
///
/// `--permission` itself is deliberately absent: the warning is what told a user
/// the model was not enforced, and for the scopes above the honest signal is the
/// missing-feature error, not a permission one.
const UNIMPLEMENTED: &[&str] = &[
    "--experimental-network-inspection",
    "--experimental-shadow-realm",
    "--experimental-vm-modules",
    "--experimental-web-worker",
    "--js-source-phase-imports",
];

/// Experimental flags whose behaviour *is* implemented.
///
/// They still travel through the generic `--experimental-` branch, but must not
/// be reported as unimplemented, because the feature exists: reporting
/// `--experimental-sqlite` as unimplemented while `require('node:sqlite')`
/// works is a lie the flag prints on every run.
///
/// Being listed here says only that the flag's feature is present. It does not
/// mean the flag is *consumed* by everything that could consult it: the
/// `node:sqlite` gate is now real because the option value reaches
/// `realm.js`'s policy table *and* the `node:` resolution path asks that table.
/// `--no-experimental-sqlite` therefore throws `ERR_UNKNOWN_BUILTIN_MODULE`,
/// the same code Node gives for a builtin it does not expose.
const IMPLEMENTED_EXPERIMENTAL: &[&str] = &[
    "--experimental-bench",
    "--experimental-stream-iter",
    "--experimental-sqlite",
];

/// Parses the `NODE_OPTIONS` environment variable, with Node's rules.
///
/// `src/node.cc:1056` calls `credentials::SafeGetenv("NODE_OPTIONS", ...)` and
/// parses the result before the command line. An unset or empty variable is
/// `None`, and the distinction matters: `NODE_OPTIONS=""` parses to no
/// arguments, so the two behave the same, but keeping `None` makes
/// `Options::env_options` mean "the variable was there".
///
/// # Errors
///
/// Returns the error `StartInternal` would print, already in Node's wording. The
/// caller prints it against `argv[0]` and exits 9.
/// Reads `NODE_OPTIONS` and returns both the flags and the values they set.
///
/// The values are the base [`parse_with_env`] applies the command line to, so a
/// caller that drops them loses the whole point of parsing the variable.
pub fn read_node_options_with_store(
) -> Result<Option<(rn_bind_options::EnvOptions, rn_bind_options::Store)>, rn_bind_options::EnvError>
{
    parse_node_options_value(std::env::var_os("NODE_OPTIONS"))
}

/// The body of [`read_node_options_with_store`], over an explicit value so it is
/// testable.
///
/// The two conversions are deliberately different:
///
/// * `std::env::var` refuses a value that is not valid Unicode, which would let a
///   malformed `NODE_OPTIONS` silently disable the whole variable. Node's
///   `SafeGetenv` copies bytes into a `std::string` and the tokenizer walks
///   them, so the lossy conversion is the closer model — a replacement
///   character is far more likely to produce a visible "not allowed" error than
///   a silent no-op.
/// * An empty value is `None` rather than `Some` with no flags. The observable
///   behaviour is identical (`NODE_OPTIONS=""` sets nothing) and it keeps
///   `Options::env_options` meaning "the variable was present and useful".
fn parse_node_options_value(
    value: Option<std::ffi::OsString>,
) -> Result<Option<(rn_bind_options::EnvOptions, rn_bind_options::Store)>, rn_bind_options::EnvError>
{
    let Some(value) = value else {
        return Ok(None);
    };
    let text = value.to_string_lossy();
    if text.is_empty() {
        return Ok(None);
    }
    let (options, store) = rn_bind_options::parse_env(&text)?;
    Ok(Some((options, store)))
}

/// The program name Node prints a startup-error prefix with.
///
/// `StartInternal` uses `result->args().at(0)`, which is `argv[0]` exactly as the
/// OS supplied it — the full path when a test invokes the binary by path, and a
/// bare name when it is found on `PATH`. Reproducing that rather than printing a
/// fixed `"rustnode"` is what makes `rustnode --version`-style comparisons against
/// Node's stderr possible at all.
pub fn program_name() -> String {
    std::env::args()
        .next()
        .unwrap_or_else(|| "rustnode".to_string())
}

/// Parses `NODE_OPTIONS` and then the command line, in Node's order.
///
/// `src/node.cc:1058` calls `Parse` on the environment's argv and then again on
/// the real one, into the same `PerProcessOptions`. Everything that makes the
/// two compose follows from that single fact, and reproducing it here rather
/// than merging the two `Vec`s by hand is what keeps them composing:
///
/// * a scalar given in both places takes the command line's value, because it
///   is parsed second;
/// * a list (`--require`, `--import`, `--conditions`) keeps both, with the
///   environment's entries first;
/// * `Implies` from either source has already been applied by the time either
///   walk finishes, so `NODE_OPTIONS=--inspect-brk` implies `--inspect` even
///   when the command line says nothing.
///
/// `env` is `None` when the variable was unset or empty. A rejected
/// `NODE_OPTIONS` is [`ParseError::NodeOptions`] and stops the process before
/// the command line is examined at all, which is what Node does: its
/// environment parse returns `kInvalidCommandLineArgument` before reaching the
/// command-line parse below it.
///
/// `stdin` is what libuv reports for the standard input descriptor. It decides
/// only the case Node's dispatch (`src/node.cc:395-405`) reserves for it: no
/// script argument at all, where a terminal means the REPL and anything else
/// means `internal/main/eval_stdin`. Passing it in rather than probing here
/// keeps this function pure, so both branches are testable.
pub fn parse_with_env(
    args: &[String],
    env: Option<(rn_bind_options::EnvOptions, rn_bind_options::Store)>,
    stdin: StdinKind,
) -> Result<Options, ParseError> {
    let mut options = Options::new();

    if let Some((env, env_store)) = env {
        // The inspector and the abort decision are the two pieces of CLI state
        // that are not plain option values: `lib/**` cannot start a listening
        // socket or change how a throw terminates, so the CLI has to read them
        // itself. Every other flag in the variable is already in the store,
        // which is where `getOptionValue` reads it.
        //
        // The flags are re-walked rather than read out of the store because
        // `--inspect-port` and `--inspect-brk` are separate fields that combine,
        // and walking them in order is the only way to get
        // `NODE_OPTIONS="--inspect-port=9339"` plus `--inspect` and the reverse
        // both right.
        for argument in &env.argv {
            if let Err(message) = apply_inspect(argument, &mut options) {
                // Node rejects a bad inspector address while parsing
                // `NODE_OPTIONS`, before the command line is looked at, and
                // prints it like any other rejected value.
                return Err(ParseError::NodeOptions(message));
            }
            apply_abort(argument, &mut options);
        }
        // `--max-old-space-size-percentage` is a per-isolate option, and
        // `PerIsolateOptions::CheckOptions` runs at the end of *each* source's
        // parse (`src/node_options-inl.h:556`). An environment value out of
        // range is therefore rejected even when the command line replaces it:
        // the oracle refuses `NODE_OPTIONS=--max-old-space-size-percentage=0`
        // together with a command-line `=50`. Only the last value in the
        // variable is converted, because `HandleMaxOldSpaceSizePercentage`
        // reads the field the walk left behind.
        //
        // The value is already in `env_store` with the walk's `requires an
        // argument` check applied, so this reads it rather than re-walking. Only
        // the verdict is taken here: the command line's value replaces this one,
        // and the `--max_old_space_size` argument Node appends comes from
        // `finish`.
        let env_percentage = env_store.value_of("--max-old-space-size-percentage");
        if let Some(rn_bind_options::ParsedValue::Text(value)) = env_percentage {
            if !value.is_empty() {
                validate_percentage(&value).map_err(ParseError::NodeOptions)?;
            }
        }
        // The variable's V8 flags come first, which is Node's order: the
        // environment is parsed into the same `v8_args` vector before the
        // command line, so a command-line `--max-old-space-size` overrides the
        // one the variable set. They are handed to V8 in this order too.
        options.v8_args.clone_from(&env.v8_args);
        options.env_argv.clone_from(&env.argv);
        // The environment's values become the base the command line is applied
        // to, which is Node's two-pass order rather than a merge of two lists.
        options.parsed = env_store;
        options.env_options = Some(env);
    }

    let mut unimplemented = BTreeSet::new();
    // The code `-e`/`--eval` named, and whether `-p`/`--print` asked for the
    // result. Node's parser records these as two independent option fields
    // (`eval_string` and `print_eval`), which is why `-p 1+1 -e 'x'` prints the
    // result of `x`: the last `--eval` wins while the print request stands.
    let mut eval_code: Option<String> = None;
    let mut print_eval = false;
    let mut index = 0;

    while index < args.len() {
        let argument = &args[index];

        // An argument of length one — a bare `-` — is not a flag. `ArgsInfo`
        // breaks its loop for `args.first().size() <= 1`, which is exactly what
        // makes `node -` name the stdin script instead of being a bad option.
        if !argument.starts_with('-') || argument.len() == 1 {
            break;
        }

        // `--` ends flag parsing; everything after it is positional. It is not
        // a positional itself, which is why `node -- -` still means stdin.
        if argument == "--" {
            index += 1;
            break;
        }

        // `-e`/`--eval` and its `=value` form. The value must not look like a
        // flag: `node -e -1` is `-e requires an argument` in Node, because
        // `Parse` refuses a separate value that starts with `-`.
        if argument == "-e" || argument == "--eval" {
            let Some(code) = args.get(index + 1).filter(|next| !next.starts_with('-')) else {
                return Err(ParseError::Cli(format!("{argument} requires an argument")));
            };
            // Node records the flag and its source in `process.execArgv`,
            // because a child process re-running the parent has to reproduce
            // the same entry point. Only the leading `node` and the script path
            // are absent.
            options.exec_argv.push(argument.clone());
            options.exec_argv.push(code.clone());
            eval_code = Some(code.clone());
            index += 2;
            continue;
        }

        // `-pe` is `--print --eval`, expanded from the alias table, so it takes
        // the value as the same kind of separate argument `--eval` does.
        if argument == "-pe" {
            let Some(code) = args.get(index + 1).filter(|next| !next.starts_with('-')) else {
                return Err(ParseError::Cli("-pe requires an argument".to_string()));
            };
            options.exec_argv.push(argument.clone());
            options.exec_argv.push(code.clone());
            eval_code = Some(code.clone());
            print_eval = true;
            index += 2;
            continue;
        }

        // `--eval=code`. The `=` form is one argument, so the value cannot look
        // like a flag; an empty value is still an error, and the message keeps
        // the `=` Node prints (`--eval= requires an argument`).
        if let Some(code) = argument.strip_prefix("--eval=") {
            if code.is_empty() {
                return Err(ParseError::Cli("--eval= requires an argument".to_string()));
            }
            options.exec_argv.push(argument.clone());
            eval_code = Some(code.to_string());
            index += 1;
            continue;
        }

        // `-p`/`--print` is a boolean option, and the alias table is what makes
        // it take a following non-flag argument as the source: `--print <arg>`
        // expands to `-pe`, which expands to `--print --eval`. So
        // `node -p 1+1` evaluates `1+1`, while `node -p --no-warnings` leaves
        // the source empty and prints the result of an empty program.
        if argument == "-p" || argument == "--print" {
            options.exec_argv.push(argument.clone());
            print_eval = true;
            match args.get(index + 1).filter(|next| !next.starts_with('-')) {
                Some(code) => {
                    options.exec_argv.push(code.clone());
                    eval_code = Some(code.clone());
                    index += 2;
                }
                None => index += 1,
            }
            continue;
        }

        // `--print=value` sets the boolean and discards the value, because the
        // option's type is `kBoolean` and `Parse` never reads one for it.
        if argument.starts_with("--print=") {
            options.exec_argv.push(argument.clone());
            print_eval = true;
            index += 1;
            continue;
        }

        if UNIMPLEMENTED.contains(&argument.as_str()) {
            unimplemented.insert(argument.clone());
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        if IGNORED_WITHOUT_VALUE.contains(&argument.as_str()) {
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        // `--abort-on-uncaught-exception` is a real option, not an ignored one:
        // it changes how the process dies. It is parsed here rather than left in
        // the ignore list because a flag that is accepted and then not acted on
        // is exactly the failure mode `Options::unimplemented` exists to avoid.
        //
        // Node accepts both spellings — `src/node.cc:794` searches its V8
        // argument vector for the dashed and underscored forms — so both are
        // taken, and `--no-` clears it the way it does for any V8 option
        // (`src/bind-options/src/parsed.rs` already models that negation).
        // `apply_abort` is the same function the environment's flags go
        // through, so a `--no-` here clears what the variable set.
        //
        // It is deliberately **not** forwarded to V8, even though the table
        // marks it `kV8Option`. Node does forward it, but only because it also
        // installs `Isolate::SetAbortOnUncaughtExceptionCallback` and points it
        // at `ShouldAbortOnUncaughtException` (`src/api/environment.cc:65`),
        // which is what makes V8 ask Node and lets the
        // `shouldAbortOnUncaughtToggle[0]` half of the decision — the half
        // `process.setUncaughtExceptionCaptureCallback` clears — override the
        // flag. rustnode has no per-isolate abort callback, so a forwarded flag
        // would make V8 abort on its own and no capture callback could stop it:
        // `--abort-on-uncaught-exception -e
        // 'process.setUncaughtExceptionCaptureCallback(()=>{}); throw 1'` exited
        // 0 before this change and died on SIGTRAP after. The decision stays in
        // `rn-errors`, which reads both halves.
        if ABORT_ON_UNCAUGHT.contains(&argument.as_str())
            || ABORT_ON_UNCAUGHT_NEGATED.contains(&argument.as_str())
        {
            apply_abort(argument, &mut options);
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        // `--use-system-ca` and `--use-openssl-ca` choose where the default
        // trust store comes from, which `SecureContext#addRootCerts` reads back
        // out of the parsed options. They are recorded here rather than listed
        // as ignored, because a flag that is accepted and then not acted on is
        // the failure mode `Options::unimplemented` exists to avoid.
        if ROOT_STORE_FLAGS.contains(&argument.as_str()) {
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        // `--max-old-space-size-percentage` is a Node option rather than a V8
        // one: `src/node_options.cc:237` validates it, converts it against the
        // machine's memory, and hands V8 `--max_old_space_size=<mb>`. It is
        // parsed here, and not left to the V8 fall-through below, because the
        // table declares it `kString` so V8 would never see it.
        //
        // The value is recorded as typed. The conversion needs the machine's
        // memory and must happen once, on the value the *last* source set —
        // `CheckOptions` runs at the end of a source's parse and
        // `HandleMaxOldSpaceSizePercentage` overwrites `max_old_space_size`,
        // which is why `--max-old-space-size-percentage=0` followed by `=50` is
        // accepted. `finish` does that conversion.
        if let Some(value) = percentage_value(argument) {
            let Some(value) = value else {
                // The bare form takes the next argument, and refuses one that
                // looks like a flag: `--max-old-space-size-percentage -1` is
                // "requires an argument" in Node, not "-1 is out of range".
                let Some(next) = args.get(index + 1) else {
                    return Err(ParseError::OptionValue(
                        "--max-old-space-size-percentage requires an argument".to_string(),
                    ));
                };
                if next.is_empty() || next.starts_with('-') {
                    return Err(ParseError::OptionValue(
                        "--max-old-space-size-percentage requires an argument".to_string(),
                    ));
                }
                options
                    .exec_argv
                    .push(format!("--max-old-space-size-percentage={next}"));
                options.max_old_space_size_percentage = Some(next.clone());
                index += 2;
                continue;
            };
            // An empty inline value is `Parse`'s `RequiresArgumentErr`, which
            // names the flag with the `=` the caller typed — and it fires before
            // `CheckOptions` would have said "greater than 0".
            if value.is_empty() {
                return Err(ParseError::OptionValue(
                    "--max-old-space-size-percentage= requires an argument".to_string(),
                ));
            }
            options.exec_argv.push(argument.clone());
            options.max_old_space_size_percentage = Some(value);
            index += 1;
            continue;
        }

        // A permission grant whose value is a separate argument. Node accepts
        // both spellings and its own tests use both, so the value is taken here
        // and recorded in the joined form `exec_argv` uses everywhere else.
        // This is checked before the generic permission branch below, because
        // `--allow-fs-read` alone would otherwise be accepted as a bare boolean
        // and its value treated as the script path.
        if PERMISSION_VALUE_FLAGS.contains(&argument.as_str()) {
            let Some(value) = args.get(index + 1) else {
                return Err(ParseError::Cli(format!("{argument} requires an argument")));
            };
            options.exec_argv.push(format!("{argument}={value}"));
            index += 2;
            continue;
        }

        // Any permission flag: `--permission`, `--permission-audit`, a boolean
        // `--allow-*`, or an `--allow-*=value`. Accepted, recorded for
        // `execArgv`, and acted on — `finish` turns them into the model.
        if is_permission_flag(argument) {
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        if VALUE_SEPARATE.contains(&argument.as_str()) {
            let Some(value) = args.get(index + 1) else {
                return Err(ParseError::Cli(format!("{argument} requires an argument")));
            };
            options.exec_argv.push(format!("{argument}={value}"));
            index += 2;
            continue;
        }

        // `--experimental-` is a namespace, not a promise: the table decides
        // which experimental flags exist. One it declares is accepted and
        // recorded so a script that merely mentions it still boots; one it does
        // not declare is V8's, and falls through to the V8 split below rather
        // than being accepted here and then never reaching V8. That fall-through
        // is what makes `--experimental-fuzzing` work and
        // `--experimental-not-a-real-flag` a `bad option`.
        if (argument.starts_with("--experimental-") || argument.starts_with("--no-experimental-"))
            && rn_bind_options::declares(argument)
        {
            // Most of the surface gates modules that have not landed, so those
            // flags stay in `unimplemented` and say so. `--experimental-bench`
            // is the exception: it is implemented, so reporting it missing
            // would be a lie that some tests read.
            if !IMPLEMENTED_EXPERIMENTAL.contains(&argument.as_str()) {
                unimplemented.insert(argument.clone());
            }
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        // `--inspect`, `--inspect-brk`, `--inspect-port` and their `=value` forms.
        // These are parsed here rather than left in the generic prefix branch because
        // the value decides whether the process opens a socket, and a flag recorded
        // but not acted on would look implemented.
        if is_inspect_flag(argument) {
            if let Err(message) = apply_inspect(argument, &mut options) {
                return Err(ParseError::Cli(message));
            }
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        if VALUE_INLINE_PREFIXES
            .iter()
            .any(|prefix| argument.starts_with(prefix))
        {
            if UNIMPLEMENTED
                .iter()
                .any(|flag| argument.starts_with(&format!("{flag}=")))
            {
                unimplemented.insert(argument.clone());
            }
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        // Everything the table declares is either handled above or is a flag
        // rustnode has not implemented, which is reported rather than forwarded:
        // handing it to V8 would change V8's behaviour behind rustnode's back,
        // and `VALUE_INLINE_PREFIXES` has already covered the ones it accepts.
        // This is the rule `forward_v8_flags` used to state as a comment; it is
        // enforced here now, by asking the table instead of a list.
        if !rn_bind_options::is_v8_flag(argument) {
            return Err(ParseError::Cli(format!("unsupported option '{argument}'")));
        }

        // V8's flag. It is recorded for `execArgv` exactly where Node records
        // it — `Parse` pushes the argument as typed onto `exec_args` before
        // looking it up — and queued for V8, which decides whether it exists.
        // `main` applies the queue before `V8::Initialize`; anything V8 hands
        // back is Node's `bad option`.
        record_v8_flag(&mut options, argument);
        index += 1;
    }

    // The walk is over: what is left is positional. Node's dispatch order
    // (`src/node.cc:365-405`) is what decides which of them is the entry point,
    // and every branch below is one of its cases.
    let positional = &args[index..];
    options.source = if let Some(code) = eval_code {
        // `-e`/`-p` ran: their arguments are `argv.slice(1)`, with an explicit
        // `--` consumed by the flag walk above rather than forwarded.
        options.script_args = positional.to_vec();
        Source::Eval {
            code,
            print: print_eval,
        }
    } else if let Some((script, rest)) = positional.split_first() {
        // A positional is the script path, and `-` is the marker for stdin
        // rather than a file named `-`: `run_main_module` is skipped for it
        // (`src/node.cc:400`) and `eval_stdin` runs instead, with the marker
        // left in `process.argv`.
        if script == "-" {
            options.script_args = rest.to_vec();
            Source::Stdin { marker: true }
        } else {
            options.script_args = rest.to_vec();
            Source::File(script.clone())
        }
    } else if stdin == StdinKind::Redirected {
        // No script, standard input is not a terminal: Node reads it as a
        // CommonJS module. This is the case that used to evaluate `"0"` and
        // exit 0 without printing anything.
        Source::Stdin { marker: false }
    } else {
        // A terminal. Node starts the REPL here; rustnode has none, so the
        // empty program is the honest stand-in.
        Source::Empty
    };

    finish(options, unimplemented)
}


/// Records one V8 flag for `process.execArgv` and for forwarding.
///
/// The argument goes into `exec_argv` as it was typed: the oracle reports
/// `--expose_gc` verbatim in `process.execArgv`, not a normalized form, because
/// Node's `ArgsInfo::pop_first` returns the original string.
///
/// `v8_args` keeps the same shape. V8 would accept `--flag value` as a pair, but
/// Node never gives it one from the command line — `--max-old-space-size 4096`
/// is an error there — so a value that arrived inline stays inline.
fn record_v8_flag(options: &mut Options, argument: &str) {
    options.exec_argv.push(argument.to_string());
    options.v8_args.push(argument.to_string());
}

/// Whether `argument` is `--max-old-space-size-percentage`, in either spelling
/// of the name and either the `=value` or the bare form.
///
/// Returns `Some(Some(value))` for the inline form, `Some(None)` for the bare
/// form (whose value is the next argument), and `None` for anything else.
/// Underscores after the leading dashes are dashes, exactly as `Parse`
/// normalizes them, which is what makes `--max_old_space_size_percentage` work.
fn percentage_value(argument: &str) -> Option<Option<String>> {
    let (name, value) = match argument.split_once('=') {
        Some((name, value)) => (name, Some(value.to_string())),
        None => (argument, None),
    };
    if !argument.starts_with("--") {
        return None;
    }
    let normalized = format!("--{}", name[2..].replace('_', "-"));
    if normalized != "--max-old-space-size-percentage" {
        return None;
    }
    Some(value)
}

/// Converts one `--max-old-space-size-percentage` value the way Node does.
///
/// Returns the `--max_old_space_size=<mb>` argument Node appends to its V8
/// argument vector (`src/node.cc:784-789`), or Node's rejection message.
///
/// That append is what gives the percentage *precedence* over
/// `--max-old-space-size`, and precedence over the flag's position: Node
/// appends after the whole walk, so
/// `--max-old-space-size-percentage=50 --max-old-space-size=1000` still answers
/// 23677 MB on the oracle. V8 lets the last `max_old_space_size` win
/// (`heap.cc:5004`), which is why the appended argument is the decisive one.
fn validate_percentage(value: &str) -> Result<String, String> {
    let mb = rn_core::max_old_space_size_percentage_mb(
        value,
        rn_uv::memory::constrained_memory(),
        rn_uv::memory::total_memory(),
    )?;
    Ok(format!("--max_old_space_size={mb}"))
}

/// Whether `argument` is `--inspect`, `--inspect-port`, `--inspect-brk`,
/// `--inspect-wait` or one of their `=value` forms.
fn is_inspect_flag(argument: &str) -> bool {
    let name = argument.split_once('=').map_or(argument, |(name, _)| name);
    matches!(
        name,
        "--inspect" | "--inspect-port" | "--inspect-brk" | "--inspect-wait"
    )
}

/// Records one `--inspect*` argument's effect on `options`.
///
/// These four flags combine in a way that only walking them in order gets
/// right, which is why this is called once per argument from both sources
/// rather than reducing them to a single value:
///
/// * `--inspect-port` sets the host and port and does **not** open a socket.
///   Node's own `--inspect-port=9339` alone leaves the inspector off while
///   `process.debugPort` still reports 9339.
/// * `--inspect` opens it, at the already-configured port when it carries no
///   value, so `NODE_OPTIONS=--inspect-port=9339` and `--inspect` on the command
///   line listen on 9339.
/// * `--inspect-brk` does the same and also waits for a client.
/// * A later `--inspect-port` still moves the port of an inspector that has
///   already been asked for, which is `NODE_OPTIONS=--inspect` plus
///   `--inspect-port=9338`.
///
/// Verified against the oracle for all four combinations; see
/// `rn-cli/tests/node_options.rs`.
fn apply_inspect(argument: &str, options: &mut Options) -> Result<(), String> {
    let (name, value) = match argument.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (argument, None),
    };
    // The name is checked before the value is read. A `match` alone is not
    // enough: parsing the value first would read `--stack-trace-limit=42` as an
    // inspector port and reject it for being below 1024.
    if !is_inspect_flag(name) {
        return Ok(());
    }
    // A bare `--inspect` (and `--inspect-brk`) means "listen where the port
    // option points", so the previous host and port are inherited rather than
    // reset. `NODE_OPTIONS=--inspect-port=9339` plus `--inspect` listens on
    // 9339 in Node, and that only works if the bare form is a no-op on the
    // address.
    let parsed = if value.is_none() {
        InspectRequest {
            wait: false,
            ..options.debug_port.clone()
        }
    } else {
        InspectRequest::parse_with_host(value, options.debug_port.host.as_str(), false)?
    };
    match name {
        "--inspect-port" => {
            // Only the address changes; whether to listen is a separate flag.
            options.debug_port = parsed;
        }
        "--inspect" | "--inspect-wait" => {
            options.debug_port = parsed;
            options.inspect_enabled = true;
        }
        "--inspect-brk" => {
            options.debug_port = parsed;
            options.inspect_enabled = true;
            options.inspect_wait = true;
        }
        _ => {}
    }
    Ok(())
}

/// Records `--abort-on-uncaught-exception`, in either spelling or its negation.
///
/// Called for both sources so the command line can turn off what
/// `NODE_OPTIONS` turned on, which is what `NODE_OPTIONS=--abort-on-uncaught-exception
/// -- --no-abort-on-uncaught-exception` does in Node.
fn apply_abort(argument: &str, options: &mut Options) {
    if ABORT_ON_UNCAUGHT.contains(&argument) {
        options.abort_on_uncaught_exception = true;
    } else if ABORT_ON_UNCAUGHT_NEGATED.contains(&argument) {
        options.abort_on_uncaught_exception = false;
    }
}

/// The final pass Node runs after the command-line walk: `CheckOptions`.
///
/// Returns a [`ParseError::OptionValue`] for a value the walk accepted but
/// `CheckOptions` rejects. Every value checked here is one whose check must run
/// on the *final* value of its source, which is why it cannot happen earlier in
/// the walk.
fn finish(mut options: Options, unimplemented: BTreeSet<String>) -> Result<Options, ParseError> {
    options.unimplemented = unimplemented.into_iter().collect();
    // `PerIsolateOptions::CheckOptions` converts the percentage before V8 ever
    // sees a flag, and appends its answer as `--max_old_space_size=<mb>`. That
    // append is what gives the percentage precedence over an explicit
    // `--max-old-space-size` regardless of where the two appeared.
    if let Some(value) = options.max_old_space_size_percentage.take() {
        let argument = validate_percentage(&value).map_err(ParseError::OptionValue)?;
        options.v8_args.push(argument);
    }
    // The options binding's own parser, fed the flags this CLI accepted. It is
    // a second pass over the same argv by design: this parser decides *what
    // rustnode does*, and `rn-bind-options` decides *what Node's option layer
    // reports*, so one implementation cannot quietly become the authority for
    // both. The flags only — never the script path or its arguments, which
    // Node's parser stops at too.
    //
    // It starts from the environment's store rather than from the table's
    // defaults, because Node parses `NODE_OPTIONS` and then the command line
    // into one `PerProcessOptions`. That is what makes a scalar given in both
    // places take the command line's value while `--require` keeps both, and it
    // is why the environment's parse has to have happened first.
    options.parsed.apply(&options.exec_argv);
    // `Environment::InitializePermission` clears `allow_native_addons` when
    // `--permission` (not `--permission-audit`) was given without
    // `--allow-addons`, which is what makes `process.dlopen` throw
    // `ERR_DLOPEN_DISABLED` before the permission check runs. The flag is
    // published as `--addons`, so the derived value goes into the same store
    // `getOptionValue('--addons')` reads. Audit mode deliberately keeps addons
    // enabled so the `addon` check can publish the denial instead.
    if config_wants_addons_disabled(&options.exec_argv) {
        options.parsed.force(
            "--addons",
            rn_bind_options::parsed::ParsedValue::Bool(false),
        );
    }
    // The permission model is the one thing this parser builds rather than
    // describes: `PermissionConfig::from_args` already reads these flags in both
    // spellings and owns the 68 tests that pin its grammar, so routing through
    // it keeps one interpretation of `--allow-fs-read=*` rather than two.
    //
    // Both sources are read, in Node's order, because the grants accumulate:
    // `NODE_OPTIONS=--permission --allow-fs-read=/a` plus `--allow-fs-read=/b`
    // allows both paths, which the oracle confirms.
    let mut all_args = options.env_argv.clone();
    all_args.extend(options.exec_argv.iter().cloned());
    let mut config = rn_permission::PermissionConfig::from_args(&all_args);
    // `Environment::InitializePermission` grants the entry point read access
    // implicitly, so `node --permission app.js` can load the script it was told
    // to run without also needing `--allow-fs-read=app.js`. It does *not* do that
    // for `-e` or a REPL, where there is no file to allow, and it skips `-`
    // (stdin) and the `inspect` subcommand. The path is the one from the command
    // line: the model resolves it against the working directory, which is what
    // `PathResolve` does with it too.
    if let Source::File(path) = &options.source {
        if path != "-" && path != "inspect" {
            config.allow_fs_read.push(path.clone());
        }
    }
    // `--require` preloads are granted the same way, because Node cannot load
    // them before `lib/**` runs either. Both sources count: a variable-only
    // preload is denied by `--permission` in Node exactly like a command-line
    // one, which the oracle confirms.
    for entry in &all_args {
        if let Some(preload) = entry.strip_prefix("--require=") {
            config.allow_fs_read.push(preload.to_string());
        }
    }
    options.permission_config = config.clone();
    options.permission = std::sync::Arc::new(rn_permission::PermissionModel::with_cwd(
        current_dir(),
        config,
    ));
    Ok(options)
}

/// Whether `--permission` was given without `--allow-addons` and without audit
/// mode, which is the case `Environment::InitializePermission` turns native
/// addons off for.
///
/// `--permission-audit` is the exception: it leaves `allow_native_addons` alone so
/// the `addon` scope check, not a disabled loader, produces the denial — and that
/// denial is what gets published to `node:permission-model:addon`.
fn config_wants_addons_disabled(argv: &[String]) -> bool {
    let mut enforcing = false;
    let mut audit = false;
    let mut allow_addons = false;
    for argument in argv {
        match argument
            .split_once('=')
            .map_or(argument.as_str(), |(name, _)| name)
        {
            "--permission" => enforcing = true,
            "--permission-audit" => {
                enforcing = true;
                audit = true;
            }
            "--allow-addons" => allow_addons = true,
            _ => {}
        }
    }
    enforcing && !audit && !allow_addons
}

/// The working directory the permission model resolves relative grants against.
///
/// Node's `PathResolve` starts from the process working directory, and a grant
/// written as `--allow-fs-read=data` has to mean the same directory the script
/// sees. A directory that cannot be read is impossible in practice and is not
/// worth failing the run over, so the empty string makes relative grants resolve
/// against `/` rather than panicking.
fn current_dir() -> String {
    std::env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses with no `NODE_OPTIONS`, which is what these tests are about.
    ///
    /// The environment path is pinned separately, in `tests/node_options.rs` and
    /// in this module's own environment tests below.
    fn parse_of(args: &[&str]) -> Result<Options, String> {
        let owned: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
        parse_with_env(&owned, None, StdinKind::Terminal).map_err(|error| match error {
            ParseError::Cli(message)
            | ParseError::NodeOptions(message)
            | ParseError::OptionValue(message) => message,
        })
    }

    #[test]
    fn eval_and_print_are_distinguished() {
        let options = parse_of(&["-e", "1+1"]).expect("parses");
        assert!(matches!(options.source, Source::Eval { print: false, .. }));

        let options = parse_of(&["-p", "1+1"]).expect("parses");
        assert!(matches!(options.source, Source::Eval { print: true, .. }));
    }

    #[test]
    fn a_script_path_takes_everything_after_it() {
        let options = parse_of(&["app.js", "--not-a-runtime-flag", "value"]).expect("parses");
        assert!(matches!(options.source, Source::File(path) if path == "app.js"));
        // The trailing arguments belong to the script, not to the runtime, so
        // an unknown flag among them must not be an error.
        assert_eq!(options.script_args, ["--not-a-runtime-flag", "value"]);
    }

    #[test]
    fn flags_before_a_script_are_accepted() {
        let options = parse_of(&["--no-warnings", "--expose-internals", "app.js"]).expect("parses");
        assert!(options.expose_internals());
        assert!(matches!(options.source, Source::File(_)));
        // These two are acted on, not deferred, so neither is reported missing.
        assert!(options.unimplemented.is_empty());
        assert_eq!(options.exec_argv, ["--no-warnings", "--expose-internals"]);
    }

    #[test]
    fn an_unimplemented_experimental_flag_is_reported_not_hidden() {
        let options = parse_of(&["--experimental-vm-modules", "-e", "1"]).expect("parses");
        assert_eq!(options.unimplemented, ["--experimental-vm-modules"]);
    }

    /// The bug this whole change exists for: `--permission` used to be accepted
    /// and recorded, while the binding it reaches was built from
    /// `PermissionModel::disabled()` and nothing consulted a gate.
    #[test]
    fn permission_flags_build_an_enforcing_model() {
        let options =
            parse_of(&["--permission", "--allow-fs-read=/tmp", "-e", "1"]).expect("parses");
        assert!(options.permission.is_enabled());
        assert!(!options.permission.is_audit());
    }

    #[test]
    fn no_permission_flag_still_builds_a_disabled_model() {
        // The negative direction of the same test: a runtime without the flag
        // must not deny anything, so this is what keeps the check honest rather
        // than denying everything.
        let options = parse_of(&["--allow-fs-read=/tmp", "-e", "1"]).expect("parses");
        assert!(!options.permission.is_enabled());
    }

    #[test]
    fn every_permission_flag_spelling_reaches_the_model() {
        // Both value forms, because Node's own tests use both.
        let joined =
            parse_of(&["--permission", "--allow-fs-read=/tmp/x", "-e", "1"]).expect("parses");
        assert!(joined
            .exec_argv
            .iter()
            .any(|flag| flag == "--allow-fs-read=/tmp/x"));
        assert!(
            joined.permission.check_fs_read("/tmp/x").is_ok(),
            "the joined form must grant the path"
        );

        let separate =
            parse_of(&["--permission", "--allow-fs-read", "/tmp/x", "-e", "1"]).expect("parses");
        // The separate form is recorded joined, so `execArgv` has one shape and
        // the model sees a value rather than treating the path as the script.
        assert!(separate
            .exec_argv
            .iter()
            .any(|flag| flag == "--allow-fs-read=/tmp/x"));
        assert!(
            separate.permission.check_fs_read("/tmp/x").is_ok(),
            "the separate form must grant the path"
        );
        assert!(matches!(separate.source, Source::Eval { .. }));
    }

    #[test]
    fn a_grant_does_not_grant_the_other_scope() {
        // A model built from only a read grant must deny writes, and vice versa:
        // a `--permission` that allowed everything would pass the tests above
        // without enforcing anything.
        let options =
            parse_of(&["--permission", "--allow-fs-read=/tmp/x", "-e", "1"]).expect("parses");
        assert!(options.permission.check_fs_read("/tmp/x").is_ok());
        assert!(options.permission.check_fs_write("/tmp/x").is_err());
        assert!(options.permission.check_child_process().is_err());
    }

    #[test]
    fn permission_audit_is_enabled_but_does_not_deny() {
        let options = parse_of(&["--permission-audit", "-e", "1"]).expect("parses");
        assert!(options.permission.is_enabled());
        assert!(options.permission.is_audit());
    }

    #[test]
    fn the_entry_point_is_granted_read_implicitly() {
        // `Environment::InitializePermission` adds the script path to
        // `allow_fs_read`, so `node --permission app.js` can load what it was
        // told to run.
        let options = parse_of(&["--permission", "/definitely/not/here.js"]).expect("parses");
        assert!(options
            .permission
            .check_fs_read("/definitely/not/here.js")
            .is_ok());
        assert!(options.permission.check_fs_read("/etc/passwd").is_err());
    }

    #[test]
    fn eval_gets_no_implicit_read_grant() {
        // `-e` has no file, so there is nothing to allow; granting the working
        // directory instead would make `--permission -e` silently readable.
        let options = parse_of(&["--permission", "-e", "1"]).expect("parses");
        assert!(options.permission.check_fs_read("probe.js").is_err());
    }

    #[test]
    fn permission_grants_are_not_reported_unimplemented() {
        // Every scope this build has a surface for is now enforced, so
        // `--permission` and its grants must all leave the list empty. A grant
        // in it would be a warning that is no longer true.
        let options = parse_of(&[
            "--permission",
            "--allow-fs-read=/tmp",
            "--allow-fs-write=/tmp",
            "--allow-child-process",
            "--allow-env=A",
            "--allow-net",
            "--allow-addons",
            "-e",
            "1",
        ])
        .expect("parses");
        assert!(
            options.unimplemented.is_empty(),
            "{:?}",
            options.unimplemented
        );
    }

    #[test]
    fn a_missing_permission_value_is_an_error_not_a_script() {
        let error = parse_of(&["--permission", "--allow-fs-read"]).expect_err("rejects");
        assert!(error.contains("--allow-fs-read"), "{error}");
    }

    #[test]
    fn a_valued_flag_consumes_its_value() {
        let options =
            parse_of(&["--disable-warning=ExperimentalWarning", "-e", "1"]).expect("parses");
        assert!(options.unimplemented.is_empty());
        assert!(matches!(options.source, Source::Eval { .. }));
    }

    #[test]
    fn a_separate_value_flag_consumes_two_arguments() {
        let options = parse_of(&["--require", "preload.js", "-e", "1"]).expect("parses");
        // The value is joined into one entry, and the entry point follows it, so
        // `execArgv` reproduces the whole invocation minus the script path.
        assert_eq!(options.exec_argv, ["--require=preload.js", "-e", "1"]);
        assert!(matches!(options.source, Source::Eval { .. }));
    }

    #[test]
    fn an_unknown_flag_is_left_for_v8_to_decide() {
        // Node does not reject an unknown flag itself: `Parse` pushes it onto
        // `v8_args` and `V8::SetFlagsFromCommandLine` is what reports it as
        // `bad option`. The parser therefore accepts it and records it, and
        // `main` is what turns a V8 refusal into exit 9 — see
        // `tests/node_options.rs::a_bogus_flag_is_a_bad_option_with_nodes_message_and_status`.
        let options = parse_of(&["--not-a-real-flag", "-e", "1"]).expect("parses");
        assert_eq!(options.v8_args, ["--not-a-real-flag"]);
        assert_eq!(options.exec_argv, ["--not-a-real-flag", "-e", "1"]);
    }

    #[test]
    fn a_declared_flag_rustnode_does_not_implement_is_rejected_not_forwarded() {
        // The rule the old `forward_v8_flags` comment stated: a flag Node's
        // table declares is Node's, so handing it to V8 would change V8's
        // behaviour behind rustnode's back. `--max-http-header-size` is in the
        // table and the CLI does not act on it, so it stays an error and never
        // reaches `v8_args`.
        let error = parse_of(&["--max-http-header-size=32768", "-e", "1"]).expect_err("rejects");
        assert!(error.contains("--max-http-header-size=32768"), "{error}");
    }

    #[test]
    fn a_v8_option_in_the_table_is_recorded_for_forwarding() {
        // `--expose-gc` is a `kV8Option`, so it needs both records: `execArgv`
        // (what the process reports) and `v8_args` (what reaches V8 before
        // `initialize`). A flag that reached only the first would be accepted
        // and then do nothing.
        let options = parse_of(&["--expose-gc", "-e", "1"]).expect("parses");
        assert_eq!(options.v8_args, ["--expose-gc"]);
        assert!(options.exec_argv.iter().any(|flag| flag == "--expose-gc"));
    }

    #[test]
    fn the_underscore_spelling_of_a_v8_option_is_forwarded_too() {
        // `Parse` normalizes underscores before the lookup, so `--expose_gc`
        // resolves to the same table entry. Both spellings appear in Node's test
        // headers.
        let options = parse_of(&["--expose_gc", "-e", "1"]).expect("parses");
        assert_eq!(options.v8_args, ["--expose_gc"]);
    }

    #[test]
    fn a_v8_flag_queued_from_the_variable_comes_before_the_command_lines() {
        // Node parses the environment into the same `v8_args` vector before the
        // command line, so a later spelling overrides an earlier one. Reversing
        // this would make `NODE_OPTIONS=--max-old-space-size=100` win over a
        // command-line `--max-old-space-size=512`.
        let env = rn_bind_options::parse_env("--max-old-space-size=100").expect("parses");
        let options = parse_with_env(
            &[
                "--max-old-space-size=512".to_string(),
                "-e".to_string(),
                "1".to_string(),
            ],
            Some(env),
            StdinKind::Terminal,
        )
        .expect("parses");
        assert_eq!(
            options.v8_args,
            ["--max-old-space-size=100", "--max-old-space-size=512"]
        );
    }

    #[test]
    fn an_unknown_experimental_flag_is_left_for_v8_rather_than_reported_unimplemented() {
        // `--experimental-` is a namespace, not a promise. Accepting every name
        // in it made `--experimental-regexp-engine` (a V8 flag) work only by
        // accident of never being forwarded, and made `--experimental-nonsense`
        // succeed. The table decides: a declared entry stays unimplemented, an
        // undeclared one is V8's.
        let options = parse_of(&["--experimental-regexp-engine", "-e", "1"]).expect("parses");
        assert_eq!(options.v8_args, ["--experimental-regexp-engine"]);
        assert!(
            options.unimplemented.is_empty(),
            "{:?}",
            options.unimplemented
        );

        let options = parse_of(&["--experimental-vm-modules", "-e", "1"]).expect("parses");
        assert_eq!(options.unimplemented, ["--experimental-vm-modules"]);
        assert!(options.v8_args.is_empty(), "{:?}", options.v8_args);
    }

    #[test]
    fn double_dash_ends_flag_parsing() {
        let options = parse_of(&["--", "--looks-like-a-flag"]).expect("parses");
        assert!(matches!(options.source, Source::File(path) if path == "--looks-like-a-flag"));
    }

    #[test]
    fn no_arguments_means_nothing_to_run() {
        let options = parse_of(&[]).expect("parses");
        assert!(matches!(options.source, Source::Empty));
    }

    #[test]
    fn eval_arguments_become_the_script_arguments() {
        // `node -e 'x' a b` reports `['a', 'b']` after the executable, and an
        // explicit `--` is only a separator, so it must not appear either.
        let options = parse_of(&["-e", "x", "a", "b"]).expect("parses");
        assert_eq!(options.script_args, ["a", "b"]);

        let options = parse_of(&["-e", "x", "--", "a", "b"]).expect("parses");
        assert_eq!(options.script_args, ["a", "b"]);

        let options = parse_of(&["-e", "x", "--"]).expect("parses");
        assert!(options.script_args.is_empty());
    }

    #[test]
    fn eval_keeps_its_flag_and_source_in_exec_argv() {
        // A child process inherits these to reproduce the same entry point, so
        // unlike the script path they belong in `execArgv`.
        let options = parse_of(&["--expose-internals", "-p", "1+1"]).expect("parses");
        assert_eq!(options.exec_argv, ["--expose-internals", "-p", "1+1"]);
        assert!(options.script_args.is_empty());
    }

    /// A bare pipe runs stdin; a terminal does not.
    ///
    /// This is the whole of Node's dispatch at `src/node.cc:400-405`:
    /// `first_argv.empty() && uv_guess_handle(STDIN_FILENO) != UV_TTY` means
    /// `internal/main/eval_stdin`. Before this, both cases fell through to the
    /// empty program, which evaluated `"0"` and exited 0 while printing
    /// nothing — a silent success for a script that never ran.
    #[test]
    fn no_argument_reads_stdin_only_when_it_is_not_a_terminal() {
        let options = parse_with_env(&[], None, StdinKind::Redirected).expect("parses");
        assert!(matches!(options.source, Source::Stdin { marker: false }));
        assert!(options.script_args.is_empty());

        let options = parse_with_env(&[], None, StdinKind::Terminal).expect("parses");
        assert!(matches!(options.source, Source::Empty));
    }

    /// `-` is the stdin marker, and it stays in `process.argv`.
    ///
    /// `src/node.cc:400` skips `run_main_module` when the script is `-`, and the
    /// marker is left in `argv` rather than stripped: `node - x y` reports
    /// `[execPath, '-', 'x', 'y']`.
    #[test]
    fn a_dash_means_stdin_and_keeps_itself_in_argv() {
        let options = parse_of(&["-", "x", "y"]).expect("parses");
        assert!(matches!(options.source, Source::Stdin { marker: true }));
        assert_eq!(options.script_args, ["x", "y"]);

        // `--` does not make `-` a file name: it only ends flag parsing.
        let options = parse_of(&["--", "-"]).expect("parses");
        assert!(matches!(options.source, Source::Stdin { marker: true }));
    }

    /// `--` before a non-dash argument still names a file.
    ///
    /// The reason the distinction matters: `node -- a b` makes `a` the script,
    /// so `--` forwards nothing to a stdin script — the stdin path is only
    /// reached when nothing positional follows.
    #[test]
    fn double_dash_still_names_a_script_file() {
        let options = parse_of(&["--", "a", "b"]).expect("parses");
        assert!(matches!(options.source, Source::File(path) if path == "a"));
        assert_eq!(options.script_args, ["b"]);
    }






    /// The last `--eval` wins while `--print` stands, because Node records them
    /// as two independent option fields (`eval_string`, `print_eval`).
    #[test]
    fn print_and_eval_compose_as_two_option_fields() {
        let options = parse_of(&["-e", "1", "-p", "2"]).expect("parses");
        assert!(matches!(
            &options.source,
            Source::Eval { code, print: true } if code == "2"
        ));

        // `-p` alone has no source, so it falls through to the stdin entry
        // point, which reads `--print` from the option store. That is how
        // `echo 1+1 | node -p` prints `2`.
        let options =
            parse_with_env(&["-p".to_string()], None, StdinKind::Redirected).expect("parses");
        assert!(matches!(options.source, Source::Stdin { marker: false }));
        assert!(
            options.exec_argv.iter().any(|flag| flag == "-p"),
            "{:?}",
            options.exec_argv
        );
        assert_eq!(
            options.parsed.value_of("--print"),
            Some(rn_bind_options::ParsedValue::Bool(true)),
            "the store is what eval_stdin reads --print from"
        );
    }

    /// A value that looks like a flag is not consumed, which is how
    /// `node -e -1` becomes `-e requires an argument`.
    #[test]
    fn an_eval_value_that_looks_like_a_flag_is_missing() {
        let error = parse_of(&["-e", "-1"]).expect_err("rejects");
        assert!(error.contains("-e requires an argument"), "{error}");

        let error = parse_of(&["--eval="]).expect_err("rejects");
        assert!(error.contains("--eval= requires an argument"), "{error}");
    }

    #[test]
    fn a_script_path_is_not_in_exec_argv() {
        let options = parse_of(&["--no-warnings", "app.js", "arg"]).expect("parses");
        assert_eq!(options.exec_argv, ["--no-warnings"]);
        assert_eq!(options.script_args, ["arg"]);
    }

    /// `--inspect-port` records where to listen without asking to listen.
    ///
    /// It used to be conflated with `--inspect`, so `rustnode --inspect-port=9339`
    /// opened a socket Node does not open. The two facts are separate in Node
    /// (`--inspect-port` writes `HostPort`; `--inspect` sets
    /// `inspector_enabled`), which is why they are separate fields here.
    #[test]
    fn inspect_port_records_an_address_without_enabling_the_inspector() {
        let options = parse_of(&["--inspect-port=9339"]).expect("parses");
        assert!(!options.inspect_enabled);
        assert_eq!(options.debug_port.port, 9339);
        assert_eq!(options.debug_port.host, "127.0.0.1");
    }

    #[test]
    fn inspect_enables_the_inspector_at_the_configured_address() {
        let options = parse_of(&["--inspect=0.0.0.0:9339"]).expect("parses");
        assert!(options.inspect_enabled);
        assert!(!options.inspect_wait);
        assert_eq!(options.debug_port.port, 9339);
        assert_eq!(options.debug_port.host, "0.0.0.0");
    }

    #[test]
    fn inspect_brk_also_waits_for_a_client() {
        let options = parse_of(&["--inspect-brk=9339"]).expect("parses");
        assert!(options.inspect_enabled);
        assert!(options.inspect_wait);
        assert_eq!(options.debug_port.port, 9339);
    }

    /// A bare `--inspect` keeps whatever `--inspect-port` already set.
    ///
    /// The oracle listens on 9339 for
    /// `NODE_OPTIONS=--inspect-port=9339 rustnode --inspect`, so the bare form
    /// must not reset the address to the default.
    #[test]
    fn a_bare_inspect_keeps_the_configured_port() {
        let env = rn_bind_options::parse_env("--inspect-port=9339").expect("parses");
        let options = parse_with_env(&["--inspect".to_string()], Some(env), StdinKind::Terminal)
            .expect("parses");
        assert!(options.inspect_enabled);
        assert_eq!(options.debug_port.port, 9339);
    }

    #[test]
    fn a_later_inspect_port_still_moves_the_address() {
        let env = rn_bind_options::parse_env("--inspect").expect("parses");
        let options = parse_with_env(
            &["--inspect-port=9338".to_string()],
            Some(env),
            StdinKind::Terminal,
        )
        .expect("parses");
        assert!(options.inspect_enabled);
        assert_eq!(options.debug_port.port, 9338);
    }

    /// `SplitHostPort` has four branches, and the value is observable through
    /// `process.debugPort` in Node. Each case below is what the oracle reports.
    #[test]
    fn an_inspect_value_follows_node_split_host_port() {
        let cases = [
            ("9339", ("127.0.0.1", 9339)),
            ("myhost", ("myhost", 9229)),
            ("0.0.0.0:9339", ("0.0.0.0", 9339)),
            ("[::1]:9339", ("::1", 9339)),
            ("[::1]", ("::1", 9229)),
            (":9339", ("127.0.0.1", 9339)),
            ("abc:def", ("abc", 0)),
            ("0", ("127.0.0.1", 0)),
        ];
        for (value, (host, port)) in cases {
            let options = parse_of(&[&format!("--inspect={value}")])
                .unwrap_or_else(|error| panic!("--inspect={value}: {error}"));
            assert_eq!(
                (options.debug_port.host.as_str(), options.debug_port.port),
                (host, port),
                "--inspect={value}"
            );
        }
    }

    #[test]
    fn an_out_of_range_inspect_port_is_rejected() {
        // `ParseAndValidatePort` rejects a non-zero port below 1024 and anything
        // above 65535 with one sentence.
        for value in ["80", "1023", "99999"] {
            let error = parse_of(&[&format!("--inspect-port={value}")]).expect_err("rejects");
            assert_eq!(error, "must be 0 or in range 1024 to 65535.", "{value}");
        }
        // 0 asks the OS for a free port and is allowed; 1024 is the floor.
        assert!(parse_of(&["--inspect-port=0"]).is_ok());
        assert!(parse_of(&["--inspect-port=1024"]).is_ok());
    }
}

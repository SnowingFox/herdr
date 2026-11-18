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
/// The three sources all print through `StartInternal`'s loop, which is
/// `"%s: %s\n"` against `argv[0]` verbatim (`src/node.cc`), so the program name
/// is what makes the output byte-identical to the oracle's rather than merely
/// similar. They stay distinct variants because the call sites differ in what
/// they know — a walk-time rejection versus a post-walk `CheckOptions` verdict —
/// not because the rendering differs.
///
/// * a bad command-line flag is `<program>: <message>`, where the message keeps
///   Node's own wording: `bad option: <flag>` for a flag V8 refused and
///   `<flag> requires an argument` for a value the walk did not get;
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
    /// One or more `--env-file` failures, already in Node's wording.
    ///
    /// A list because Node collects every bad file into its error vector and
    /// `StartInternal` prints each one as its own `<program>: <message>` line.
    /// Folding them into one string would put two files' messages on one line and
    /// prefix only the first.
    EnvFile(Vec<String>),
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
    /// `--inspect-brk-node`: break at Node bootstrap after waiting.
    ///
    /// Node distinguishes this from `--inspect-brk`: plain `--inspect-brk`
    /// breaks at user-script start through JavaScript `callAndPauseOnStart`,
    /// while `--inspect-brk-node` additionally asks the native agent to break
    /// on bootstrap (`break_node_first_line`). rustnode's CLI mirrors that
    /// split so `node inspect <file>` does not stop in bootstrap internals.
    pub inspect_break_node: bool,
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
    /// `--version`/`-v`: print the version and run nothing.
    ///
    /// A separate field rather than a [`Source`] because of *when* it takes
    /// effect: `node.cc:1282` answers it in `InitializeOncePerProcess`, before
    /// `V8::Initialize` and before the inspector or the realm exist, but only
    /// after the V8 flag vector has been applied — which is why
    /// `node --version --not-a-real-flag` is a `bad option` and exits 9 rather
    /// than printing.
    pub print_version: bool,
    /// `--help`/`-h`: print the usage text, which [`Source::Help`] then names.
    ///
    /// Kept separate from [`Self::print_version`] because the two answer at
    /// different points: help is a real main script (`internal/main/print_help`)
    /// that runs after the realm is up, so it needs the whole bootstrap, and
    /// Node checks the version first when both are given.
    pub print_help: bool,
    /// `-i`/`--interactive`: enter the REPL even when stdin is not a terminal.
    ///
    /// Node's `force_repl` (`src/node_options.h:300`, set by
    /// `--interactive` at `src/node_options.cc:1496`). It does two things
    /// `StartExecution` depends on: it selects `internal/main/repl` over
    /// `eval_string` when `-e` was also given (`src/node.cc:380` tests
    /// `has_eval_string && !force_repl`), and it selects the REPL over
    /// `eval_stdin` when stdin is a pipe (`src/node.cc:407`).
    ///
    /// `NODE_OPTIONS=--interactive` sets it too, because the option is
    /// `kAllowedInEnvvar` — so it is read from the environment's store rather
    /// than only from the command-line walk.
    pub force_repl: bool,
    /// `--check`/`-c`: parse the entry point instead of running it.
    ///
    /// Read after the walk rather than during it, because it decides the
    /// [`Source`] in the same place Node's `StartExecution` reads
    /// `options()->syntax_check_only`, and because the flag can appear on either
    /// side of the script argument's position.
    pub syntax_check_only: bool,
    /// `--trace-exit`: print a stack when this environment ends.
    ///
    /// Node's `EnvironmentOptions::trace_exit` (`src/node_options.h:282`), read
    /// by `Environment::Exit`. Recorded here *and* in
    /// [`rn_core::hook_slot::set_trace_exit`], because the exit itself happens
    /// in three crates that cannot see this struct: `process.reallyExit` in
    /// `rn-bind-process-methods`, the fatal path in `rn-errors`, and the CLI's
    /// own `terminate`.
    pub trace_exit: bool,
    /// `--trace-uncaught`: show where the `throw` behind an uncaught exception
    /// happened.
    ///
    /// Node's `EnvironmentOptions::trace_uncaught` (`src/node_options.h:285`).
    /// It does two things and both are needed for the flag to be honest:
    /// `Environment::InitializeDiagnostics` turns on V8's capture of the stack
    /// behind an uncaught exception, and `ReportException` prints the
    /// `Thrown at:` block from that capture instead of the
    /// `(Use \`node --trace-uncaught ...\`)` hint.
    pub trace_uncaught: bool,
    /// `--v8-options`: print V8's own option list and run nothing.
    ///
    /// `PerProcessOptions::print_v8_help`, answered at `src/node.cc:1297` —
    /// which is to say immediately after `--version` (`:1282`) and before
    /// `V8::Initialize`, by calling `V8::SetFlagsFromString("--help")`. V8
    /// writes the list itself, so the text is V8's and not a transcription.
    pub print_v8_options: bool,
    /// `--zero-fill-buffers`: zero-fill every newly allocated `Buffer`.
    ///
    /// `PerProcessOptions::zero_fill_all_buffers` (`src/node_options.h:430`).
    /// The decision is made at allocation time in `rn-bind-buffer`, so this is
    /// recorded into the shared hook slot rather than read from here; the field
    /// exists so the walk has somewhere to put the answer and the `--no-`
    /// negation can clear it.
    pub zero_fill_buffers: bool,
    /// `--bench`: run Node's benchmark runner instead of a script.
    ///
    /// `EnvironmentOptions::bench_runner` (`src/node_options.h`), read by
    /// `StartExecution` at `src/node.cc:388`. It selects
    /// [`Source::Bench`], and `CheckOptions` rejects it alongside `--test`,
    /// `--check`, `--eval` and `--interactive`.
    pub bench_runner: bool,
    /// `--env-file` and `--env-file-if-exists`, in the order they were given.
    ///
    /// Node records these as two `kStringList` fields (`env_file` and
    /// `optional_env_file`), but the *file objects* it later walks are one
    /// ordered list — `Dotenv::GetDataFromArgs` scans raw argv and tags each entry
    /// with `is_optional` — so one vector of pairs is the shape the reader needs.
    /// Keeping them apart would let `--env-file=a --env-file-if-exists=b` apply
    /// in the wrong order, and later files win for a duplicated key.
    ///
    /// The values are read, not acted on, at parse time: `InitializeOncePerProcess`
    /// parses the files before V8 is initialised and reports their errors through
    /// the same `<program>: <message>` vector as a bad flag, with the same exit 9.
    pub env_files: Vec<EnvFileRequest>,
    /// The variables those files defined, in `Dotenv`'s sorted order.
    ///
    /// Parsed by [`read_env_files`] and installed by [`install_env_files`] from
    /// `main`, because the two happen at different points: Node parses the files
    /// in `InitializeOncePerProcess` and installs them in `Environment::Initialize`,
    /// *after* `--permission`'s environment scrub. Installing here would let an
    /// inherited value the scrub removed survive under the file's name.
    pub env_file_store: std::collections::BTreeMap<String, String>,
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
            inspect_break_node: false,
            debug_port: InspectRequest::default_endpoint(),
            max_old_space_size_percentage: None,
            print_version: false,
            print_help: false,
            force_repl: false,
            syntax_check_only: false,
            trace_exit: false,
            trace_uncaught: false,
            print_v8_options: false,
            zero_fill_buffers: false,
            bench_runner: false,
            env_files: Vec::new(),
            env_file_store: std::collections::BTreeMap::new(),
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

/// One `--env-file` or `--env-file-if-exists` occurrence.
///
/// The pair is what `Dotenv::GetDataFromArgs` builds: a path and whether a
/// missing file is tolerated. `--env-file-if-exists` is the tolerant spelling and
/// prints `<path> not found. Continuing without it.` to stderr; `--env-file`
/// makes a missing file a startup error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileRequest {
    /// The path exactly as typed, which is what every message quotes.
    pub path: String,
    /// `--env-file-if-exists`: a missing file is not an error.
    pub optional: bool,
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
    /// Reachable only when stdin is a terminal and no `-i` asked for the REPL,
    /// which is a state Node reaches by starting the REPL anyway: `StartExecution`
    /// tests `force_repl || uv_guess_handle(STDIN_FILENO) == UV_TTY`. A terminal
    /// therefore means [`Source::Repl`], so this variant is only the fallback for
    /// a process whose stdin kind was never probed — the parser's own tests, and
    /// a caller that has no descriptor to ask.
    #[default]
    Empty,
    /// `-i`/`--interactive`, or a bare `node` on a terminal:
    /// `internal/main/repl`.
    ///
    /// `StartExecution` reaches this after every other entry point is ruled out
    /// (`src/node.cc:407`), and `internal/main/repl.js` is what builds the REPL
    /// out of the vendored `lib/repl.js`. Nothing is reimplemented here: the
    /// entry point is a `kMainScript` like `eval_stdin`, so it compiles with
    /// `(process, require, internalBinding, primordials)` and calls
    /// `prepareMainThreadExecution()` itself.
    Repl,
    /// `-e`, `-p` or `-pe`: `internal/main/eval_string`.
    ///
    /// A [`Source`] that names a main script rather than a flag, for the same
    /// reason as [`Self::CheckSyntax`]: `eval_string.js` reads the code out of
    /// the option store (`getOptionValue('--eval')`), chooses between
    /// `evalModuleEntryPoint` and `evalScript` from `--input-type`, calls
    /// `addBuiltinLibsToObject` for the builtin globals, and honours `--print`.
    /// Driving the eval from the CLI instead made `module`, `exports`,
    /// `__filename` and `__dirname` undefined and left `--input-type` with no
    /// reader, because the CLI's own `evaluate_script` is a bare
    /// `v8::Script::compile` against the global object.
    ///
    /// The code itself already travelled in `exec_argv` (it is what makes
    /// `process.execArgv` report `['-e', 'code']`), and `finish` feeds that
    /// vector to the option store, so nothing has to be carried here.
    Eval,
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
    /// `--help`/`-h`: `internal/main/print_help` is the entry point.
    ///
    /// A [`Source`] rather than a flag because that is what Node makes it: the
    /// usage text is generated by `lib/internal/main/print_help.js` from the
    /// option table, so it has to run *inside* the realm, after the bootstrap
    /// that builds `internalBinding`. Reproducing the text as a constant would
    /// be a second copy of the table that could silently disagree with it.
    Help,
    /// `inspect`: Node's own debugger client, run from
    /// `internal/main/inspect`.
    ///
    /// This is `StartExecution`'s `first_argv == "inspect"` branch
    /// (`src/node.cc:367`), which is checked before the entry point is treated
    /// as a file. Without it the word became a script path, so every
    /// `test/debugger/*` invocation died with
    /// `Cannot find module '<cwd>/inspect'` before reaching any assertion.
    ///
    /// The arguments after it are the debugger's own (`--port=`, `--probe`, the
    /// script to launch, `host:port`, `-p <pid>`). `internal/main/inspect` reads
    /// them from `process.argv` rather than from the option table — Node's own
    /// parser stops at the first non-flag, so they were never options — which is
    /// why they travel in [`Options::script_args`] and are not interpreted here.
    Inspect,
    /// `--test`: Node's own test-runner entry point,
    /// `internal/main/test_runner`.
    ///
    /// Remaining positional arguments are test globs or file paths, so they
    /// stay untouched in `process.argv`.
    Test,
    /// `--check`/`-c`: parse the entry point and exit without running it, which
    /// is `internal/main/check_syntax`.
    ///
    /// A [`Source`] rather than a flag for the same reason as [`Self::Help`]:
    /// the checking itself is Node's, and `check_syntax.js` decides the module
    /// format, reads the file or stdin, and reports the `SyntaxError` through
    /// `wrapSafe`/`ModuleWrap`. Reimplementing any of that here would be a
    /// second copy of the loader's format rules. The positional argument, when
    /// there is one, stays in `process.argv`, because that is where
    /// `check_syntax.js` reads it from (it resolves `process.argv[1]` itself).
    CheckSyntax,
    /// `--bench`: Node's benchmark runner, `internal/main/bench_runner`.
    ///
    /// `StartExecution` reaches it at `src/node.cc:388`, ahead of `--test`
    /// (`:392`), which is why `CheckOptions` rejects the two together rather
    /// than letting one silently win. The runner itself is entirely
    /// JavaScript — `internal/bench_runner/**` is vendored byte-identical — so
    /// nothing is reimplemented here; the flag only has to select it.
    ///
    /// `OptionParser` rejects `--bench` without `--experimental-bench`
    /// (`CheckBenchOptions`, `src/node_options.cc:375`), and `finish`
    /// reproduces that before a [`Source`] is chosen.
    Bench,
}

impl Source {
    /// Whether the entry point is one of Node's `internal/main/**` scripts,
    /// which run pre-execution themselves.
    ///
    /// `-e`, a file and the empty program are driven by the CLI, so the CLI
    /// calls `prepareMainThreadExecution` for them. The three below are not: the
    /// first line of `print_help.js`, `eval_stdin.js` and `inspect.js` is
    /// `prepareMainThreadExecution()`, and running it twice trips
    /// `initializeModuleLoaders`' assertion that no user module has executed.
    pub fn uses_main_script(&self) -> bool {
        matches!(
            self,
            Self::Stdin { .. }
                | Self::Help
                | Self::Inspect
                | Self::Test
                | Self::Repl
                | Self::CheckSyntax
                | Self::Bench
                | Self::Eval { .. }
        )
    }

    /// The main script id this source runs, when it is one.
    pub fn main_script_id(&self) -> Option<&'static str> {
        match self {
            Self::Stdin { .. } => Some("internal/main/eval_stdin"),
            Self::Help => Some("internal/main/print_help"),
            Self::Inspect => Some("internal/main/inspect"),
            Self::Test => Some("internal/main/test_runner"),
            Self::Repl => Some("internal/main/repl"),
            Self::CheckSyntax => Some("internal/main/check_syntax"),
            Self::Bench => Some("internal/main/bench_runner"),
            Self::Eval { .. } => Some("internal/main/eval_string"),
            _ => None,
        }
    }

    /// The literals in a main script's source that name Node, and what this
    /// binary calls itself instead.
    ///
    /// `internal/main/print_help.js` writes `Usage: node [options] ...` and
    /// `node inspect [options] ...` as string literals, and they are the only
    /// places in the usage text that name the program: everything else is
    /// generated from the option table. The vendored tree is held
    /// byte-identical to Node's by `tools/verify-libjs.sh`, so the substitution
    /// happens on the source as it is compiled rather than in the file.
    ///
    /// The replacement is the fixed word `rustnode` rather than `argv[0]`: the
    /// usage text describes the program, not the path it was invoked from, and
    /// Node's own literal is likewise fixed.
    pub fn program_name_substitutions(&self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Help => &[
                ("Usage: node [options]", "Usage: rustnode [options]"),
                ("node inspect [options]", "rustnode inspect [options]"),
            ],
            _ => &[],
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

/// The bare word that selects Node's debugger client.
///
/// Matched exactly: `./inspect` and `inspect.js` are files, and Node's own
/// `first_argv == "inspect"` comparison is exact too.
pub const INSPECT_SUBCOMMAND: &str = "inspect";

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
    "--cpu-prof",
    "--disable-proto",
    "--enable-source-maps",
    "--heap-prof",
    "--expose-internals",
    "--expose_internals",
    "--experimental-strip-types",
    "--experimental-worker",
    "--frozen-intrinsics",
    "--network-family-autoselection",
    "--no-network-family-autoselection",
    "--node-snapshot",
    "--no-node-snapshot",
    "--no-deprecation",
    "--no-warnings",
    "--pending-deprecation",
    "--preserve-symlinks",
    "--preserve-symlinks-main",
    "--throw-deprecation",
    "--trace-deprecation",
    "--trace-warnings",
    "--strip-types",
    "--no-strip-types",
    "--watch",
    "--watch-preserve-output",
    // The three below are read by code that already exists, so accepting them
    // is not the "silently ignored" failure this list is warned about: the
    // value reaches the store, and the reader acts on it.
    //
    // * `--insecure-http-parser` — `lib/internal/http/common.js:33` reads it
    //   through `getOptionValue` and folds it into `calculateLenientFlags`,
    //   which the parser's `initialize` already honours.
    // * `--no-extra-info-on-fatal-exception` — `ReportException`
    //   (`src/node_errors.cc:590`) prints the trailing `Node.js <version>` line
    //   only when `extra_info_on_fatal_exception` is set. `rn-errors` reads the
    //   same value out of the store.
    // * `--disable-sigusr1` — the inspector agent's SIGUSR1 listener is what it
    //   turns off; rustnode's agent never installs one, so the flag's effect is
    //   already the state of this build and accepting it states the truth.
    "--insecure-http-parser",
    "--no-insecure-http-parser",
    "--extra-info-on-fatal-exception",
    "--no-extra-info-on-fatal-exception",
    "--disable-sigusr1",
    "--no-disable-sigusr1",
    // Read by `rn-napi`'s `CallbackIntoModule` equivalent rather than by the
    // CLI: it decides whether an old addon's throw is fatal or a DEP0168
    // warning. Accepting it here is what puts the value in the store that
    // `rn-napi` asks.
    "--force-node-api-uncaught-exceptions-policy",
    "--no-force-node-api-uncaught-exceptions-policy",
    // `--require-module` and its `--experimental-` legacy alias, whose value
    // `lib/internal/modules/cjs/loader.js` reads twice (`:1897` decides whether
    // a `require()`d file is reparsed for ESM syntax, `:2104` throws
    // `ERR_REQUIRE_ESM` when the format came back `module` and the flag is off).
    // Both spellings reach the store, and `rn-bind-options` keeps the two names
    // on one value because Node binds one `require_module` field to both.
    //
    // The `--no-` forms are listed because the negation is the whole point of
    // the flag and the walk matches names literally rather than deriving them
    // from the option's kind.
    "--require-module",
    "--no-require-module",
    "--experimental-require-module",
    "--no-experimental-require-module",
    // `--experimental-detect-module` and `--experimental-print-required-tla` are
    // the other two thirds of that same reader: `loader.js:1892` gates the
    // entry point's format detection on the first, and
    // `experimental-print-required-tla` travels with `--require-module` in the
    // `--experimental-require-module` implication. Both are `kBoolean`s whose
    // value `lib/**` reads, so the store is the whole mechanism.
    "--experimental-detect-module",
    "--no-experimental-detect-module",
    "--experimental-print-required-tla",
    "--no-experimental-print-required-tla",
    // Three `NoOp{}` entries that rustnode used to reject outright. Node accepts
    // each and does nothing with it, so refusing the command line is a divergence
    // of the same kind the warning was: `--http-parser` is a removed HTTP/1
    // implementation, `--napi-modules` a build-time flag that is now the default,
    // and `--node-memory-debug` a debug build's instrumentation switch. All three
    // are silent on the oracle, and a `node` invocation carrying one must start
    // here too.
    "--http-parser",
    "--napi-modules",
    "--node-memory-debug",
];

/// Test-runner flags that take no value.
///
/// Their semantics live in Node's own `lib/internal/test_runner/**` modules, so
/// the CLI only needs to accept and forward them.
const TEST_FLAGS_WITHOUT_VALUE: &[&str] = &[
    "--test",
    "--test-force-exit",
    "--test-update-snapshots",
    "--experimental-test-coverage",
    "--experimental-test-module-mocks",
    "--test-only",
    "--test-forbid-only",
    "--test-coverage-include-all",
    "--test-randomize",
    "--test-udp-no-try-send",
];

/// Flags whose value is a separate argument (`--flag value`).
const VALUE_SEPARATE: &[&str] = &[
    "--conditions",
    "--cpu-prof-interval",
    "--cpu-prof-dir",
    "--cpu-prof-name",
    "--heap-prof-dir",
    "--heap-prof-name",
    "--heap-prof-interval",
    "--import",
    "--inspect-publish-uid",
    "--loader",
    "--max-http-header-size",
    "--network-family-autoselection-attempt-timeout",
    "--heapsnapshot-near-heap-limit",
    "--report-signal",
    "--watch-kill-signal",
    "--watch-path",
    "--v8-pool-size",
    "--tls-cipher-list",
    "--secure-heap",
    "--secure-heap-min",
    "--use-largepages",
    "--require",
    "--tls-keylog",
    "-r",
];

/// Test-runner flags whose value may be the next argument.
const TEST_VALUE_SEPARATE: &[&str] = &[
    "--test-concurrency",
    "--test-timeout",
    "--test-coverage-branches",
    "--test-coverage-functions",
    "--test-coverage-lines",
    "--test-isolation",
    "--test-name-pattern",
    "--test-reporter",
    "--test-reporter-destination",
    "--test-shard",
    "--test-skip-pattern",
    "--experimental-test-tag-filter",
    "--test-coverage-include",
    "--test-coverage-exclude",
    "--test-global-setup",
    "--test-random-seed",
    "--test-rerun-failures",
];

/// Flags that select the default trust store.
///
/// Both are read back by `rn-bind-secure-context`'s `addRootCerts`, which is
/// `NewRootCertStore`'s branch order: `--use-openssl-ca` uses OpenSSL's compiled
/// `OPENSSLDIR`, `--use-system-ca` adds the OS store beside the bundled list.
/// `--use-openssl-ca` also has a `NODE_OPTIONS`-visible environment spelling in
/// Node, but the option table is the one place argv is interpreted, so the flag
/// is all that is recorded here.
const ROOT_STORE_FLAGS: &[&str] = &[
    "--use-system-ca",
    "--no-use-system-ca",
    "--use-openssl-ca",
    "--no-use-openssl-ca",
    "--use-bundled-ca",
];

/// Flags that select the process-wide TLS protocol defaults.
///
/// `lib/tls.js` reads these through `getOptionValue()` to choose
/// `DEFAULT_MIN_VERSION`/`DEFAULT_MAX_VERSION`.
const TLS_VERSION_FLAGS: &[&str] = &[
    "--tls-min-v1.0",
    "--tls-min-v1.1",
    "--tls-min-v1.2",
    "--tls-min-v1.3",
    "--tls-max-v1.2",
    "--tls-max-v1.3",
];

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
    "--cpu-prof-dir=",
    "--cpu-prof-interval=",
    "--cpu-prof-name=",
    "--disable-warning=",
    "--heap-prof-dir=",
    "--heap-prof-interval=",
    "--heap-prof-name=",
    "--experimental-loader=",
    "--import=",
    "--input-type=",
    "--inspect=",
    "--inspect-brk=",
    "--inspect-publish-uid=",
    "--loader=",
    "--max-http-header-size=",
    "--network-family-autoselection-attempt-timeout=",
    "--heapsnapshot-near-heap-limit=",
    "--report-signal=",
    "--permission=",
    "--watch-kill-signal=",
    "--watch-path=",
    "--v8-pool-size=",
    "--test-concurrency=",
    "--test-timeout=",
    "--test-coverage-branches=",
    "--test-coverage-functions=",
    "--test-coverage-lines=",
    "--test-isolation=",
    "--test-name-pattern=",
    "--test-reporter=",
    "--test-reporter-destination=",
    "--test-shard=",
    "--test-skip-pattern=",
    "--experimental-test-tag-filter=",
    "--test-coverage-include=",
    "--test-coverage-exclude=",
    "--test-global-setup=",
    "--test-random-seed=",
    "--test-rerun-failures=",
    "--title=",
    "--tls-cipher-list=",
    "--tls-keylog=",
    "--secure-heap=",
    "--secure-heap-min=",
    "--use-largepages=",
    "--trace-event-file-pattern=",
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

/// Experimental flags this build is known **not** to honour, named individually.
///
/// [`warns_about`] warns by default, so this list is not what makes a flag warn;
/// it is the evidence for the ones a reader is most likely to ask about, and the
/// place a newly discovered gap gets written down. An entry here that also
/// appeared in [`IMPLEMENTED_EXPERIMENTAL`] would be a contradiction, and the
/// unit tests reject that.
///
/// Everything in this list was measured missing against the pinned oracle:
/// `--experimental-shadow-realm` leaves `globalThis.ShadowRealm` `undefined` where
/// Node reports `function`, `--experimental-web-worker` does the same for
/// `Worker`, `--experimental-network-inspection` reaches a
/// `setupNetworkTracking` this build's inspector does not publish, and
/// `--experimental-eventsource` leaves `globalThis.EventSource` `undefined`.
///
/// The list is documentation, not the rule — that is [`warns_about`], which is
/// driven by the option table so a `NoOp{}` name can never be mis-declared.
const UNIMPLEMENTED: &[&str] = &[
    "--experimental-network-inspection",
    "--experimental-shadow-realm",
    "--experimental-web-worker",
    "--experimental-eventsource",
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
    // `--experimental-vm-modules` is a `BOOL_FIELD` whose value rustnode both
    // stores and honours. `lib/internal/process/pre_execution.js:197` reads it
    // and patches `vm` with `Module`, `SourceTextModule` and `SyntheticModule`,
    // and `lib/internal/vm.js:84` keys the dynamic-import sentinel on it. The
    // observable parity is exact: `typeof require('vm').SourceTextModule` is
    // `"undefined"` without the flag and `"function"` with it, on both runtimes.
    // The store carries the value for the same reason — `getOptionValue` returns
    // `true` here exactly as it does on Node — so the warning this used to print
    // was false.
    "--experimental-vm-modules",
];

/// Whether accepting `argument` should print the not-implemented warning.
///
/// The warning means one thing: **rustnode has no behaviour for this flag, and
/// Node does.** Both halves are required, and they are answered differently.
///
/// The second is a fact about the option table, so it is read from the table.
/// Node has no behaviour for a `NoOp{}` entry — `Parse`'s `kNoOp` arm is a bare
/// `break` — so there is nothing for rustnode to be missing. Warning about
/// `--experimental-fetch` was a lie printed on every run: the feature it names is
/// unconditionally on, and Node keeps the spelling only so old command lines
/// still start. `kV8Option` entries are the same shape but never reach here: they
/// are forwarded to V8, so their behaviour is V8's and rustnode gets it free.
///
/// The first half is a fact about *this build*, which the table cannot know, so
/// it stays an explicit list. [`IMPLEMENTED_EXPERIMENTAL`] names the flags whose
/// value or code path rustnode honours.
///
/// The default is therefore to **warn**: a declared experimental flag nobody has
/// proved this build honours keeps saying so. That direction is deliberate. The
/// opposite default — warn only about names on a list — is what made
/// `--experimental-vm-modules` a false alarm while `--experimental-eventsource`,
/// which really is missing (`typeof globalThis.EventSource` is `"undefined"` here
/// and `"function"` on Node), stayed honest. Silence has to be earned per flag.
fn warns_about(argument: &str) -> bool {
    !rn_bind_options::is_no_op(argument) && !IMPLEMENTED_EXPERIMENTAL.contains(&argument)
}

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

/// Reads every `--env-file` the command line named, without installing anything.
///
/// This is `Dotenv::ParsePath` from `src/node_dotenv.cc`, which
/// `InitializeOncePerProcess` runs before V8 is initialised
/// (`src/node.cc:972`). A bad file is reported there through the same error
/// vector as a rejected flag — `<program>: <path>: not found` — with exit 9, and
/// a missing `--env-file-if-exists` file is not an error at all: it prints
/// `<path> not found. Continuing without it.` and the parse continues.
///
/// The values are *not* installed here. Node installs them later, in
/// `Environment::Initialize` (`src/node.cc:343`), and the position matters for
/// `--permission`: the environment scrub runs first and removes every name
/// `--allow-env` does not grant, so an inherited value for a name the file also
/// defines is gone by the time the file's value is applied. That is what
/// `test-permission-env-file.js` asserts — "an inherited value for the same name
/// was removed at startup" — and installing here would keep it instead.
///
/// The parsing itself is [`rn_util::util::dotenv_parse`], the transliterated
/// `Dotenv::ParseContent` that `process.loadEnvFile()` and `util.parseEnv()`
/// already use. A second parser would be a second interpretation of a `.env`
/// file, and the quoting and comment rules are detailed enough that the two
/// would drift.
///
/// # Errors
///
/// Returns the messages `StartInternal` would print, already in Node's wording
/// and in file order. All of them are reported, not just the first, because Node
/// collects them into its error vector and prints every one.
pub fn read_env_files(
    files: &[EnvFileRequest],
) -> Result<std::collections::BTreeMap<String, String>, Vec<String>> {
    let mut errors = Vec::new();
    // One store for all the files, which is what `per_process::dotenv_file` being
    // a single `Dotenv` means: a key in two files takes the later file's value,
    // and `GetKeys()` reports each name once.
    let mut store = std::collections::BTreeMap::new();
    for request in files {
        match std::fs::read_to_string(&request.path) {
            Ok(contents) => {
                store.extend(rn_util::util::dotenv_parse(&contents));
            }
            Err(_) => {
                if request.optional {
                    eprintln!("{} not found. Continuing without it.", request.path);
                } else {
                    // Node says `not found` for every open failure, because
                    // `ParsePath` maps any `uv_fs_open` error to `FileError`
                    // without inspecting which one it was.
                    errors.push(format!("{}: not found", request.path));
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(store)
    } else {
        Err(errors)
    }
}

/// Installs what [`read_env_files`] parsed, the way `Dotenv::SetEnvironment` does.
///
/// A name the environment already has is skipped: "the real environment wins over
/// the file", which is what makes `FOO=inherited node --env-file=f.env` keep the
/// inherited value, and it is what `process.loadEnvFile()` does too.
///
/// The exception is a name `--permission`'s scrub removed. That pass takes away
/// every variable `--allow-env` does not grant, so by the time this runs the name
/// is absent for a reason the file is allowed to override: Node's comment on the
/// grant is "the environment scrub removed any inherited values they had, so only
/// the files' values are visible" (`src/env.cc:1152`). Without this the file's
/// value for a scrubbed name would be dropped and `process.env` would be missing
/// a variable the file defined.
pub fn install_env_files(store: &std::collections::BTreeMap<String, String>, removed: &[String]) {
    for (key, value) in store {
        let scrubbed = removed.iter().any(|name| name == key);
        if !scrubbed && rn_env::get(key).is_some() {
            continue;
        }
        let _ = rn_env::set(key, value);
    }
}

/// Recognizes one `--env-file`/`--env-file-if-exists` argument.
///
/// Returns `Ok(None)` for anything else, so the caller can fall through to the
/// rest of the walk. `Some((request, consumed_separate))` reports whether the
/// value came from the following argument, which is what tells the caller to
/// advance one or two positions.
///
/// The separate spelling refuses a value that looks like a flag, which is
/// `Parse`'s `missing_argument()`: `--env-file --help` is "requires an argument"
/// rather than an attempt to open a file called `--help`. The message names the
/// flag as typed, including the `--` spelling, which is what Node prints.
///
/// An empty inline value (`--env-file=`) is *not* refused here, because Node
/// does not refuse it: it reaches `ParsePath("")` and reports `: not found`. That
/// is the behaviour the oracle shows, and it is why the empty case is left to the
/// reader.
fn env_file_request(
    argument: &str,
    next: Option<&String>,
) -> Result<Option<(EnvFileRequest, bool)>, String> {
    // Both spellings, and nothing that merely starts with one of them:
    // `--env-file-if-exists` must not be read as `--env-file` with the value
    // `-if-exists`.
    let (name, optional) = if argument == "--env-file" || argument.starts_with("--env-file=") {
        ("--env-file", false)
    } else if argument == "--env-file-if-exists" || argument.starts_with("--env-file-if-exists=") {
        ("--env-file-if-exists", true)
    } else {
        return Ok(None);
    };
    if let Some((_, value)) = argument.split_once('=') {
        return Ok(Some((
            EnvFileRequest {
                path: value.to_string(),
                optional,
            },
            false,
        )));
    }
    match next {
        Some(value) if !value.starts_with('-') => Ok(Some((
            EnvFileRequest {
                path: value.clone(),
                optional,
            },
            true,
        ))),
        _ => Err(format!("{name} requires an argument")),
    }
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
        // `--trace-exit` and `--trace-uncaught` are `kAllowedInEnvvar`, and both
        // are read by the CLI rather than by `lib/**`, so the variable's values
        // have to be taken from the store here — the command-line walk below
        // only ever sees the command line. Reading them before that walk is what
        // gives `NODE_OPTIONS=--trace-exit --no-trace-exit` the command line's
        // answer, which is Node's two-pass order.
        if let Some(rn_bind_options::ParsedValue::Bool(value)) = env_store.value_of("--trace-exit")
        {
            options.trace_exit = value;
        }
        if let Some(rn_bind_options::ParsedValue::Bool(value)) =
            env_store.value_of("--trace-uncaught")
        {
            options.trace_uncaught = value;
        }
        if let Some(rn_bind_options::ParsedValue::Bool(value)) =
            env_store.value_of("--zero-fill-buffers")
        {
            options.zero_fill_buffers = value;
        }
        // The environment's values become the base the command line is applied
        // to, which is Node's two-pass order rather than a merge of two lists.
        options.parsed = env_store;
        options.env_options = Some(env);
    }

    let mut unimplemented = BTreeSet::new();
    // The code `-e`/`--eval` named. Node's parser records that as one option
    // field (`eval_string`) beside `print_eval`, which is why `-p 1+1 -e 'x'`
    // prints the result of `x`: the last `--eval` wins while the print request
    // stands. Both reach `lib/**` through the option store, so only the
    // "was there an eval at all" question is kept here — that is the
    // `has_eval_string` `StartExecution` tests at `src/node.cc:380`.
    let mut eval_code: Option<String> = None;
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
            index += 1;
            continue;
        }

        // `--version`/`-v` and `--help`/`-h`. Node's table declares both as
        // booleans, so the `=value` form is accepted and ignored, and the
        // `--no-` spelling clears one that an earlier argument set.
        if let Some((name, negated)) = flag_name(argument) {
            let sets = !negated;
            match name {
                "--version" | "-v" => {
                    options.print_version = sets;
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                "--help" | "-h" => {
                    options.print_help = sets;
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                _ => {}
            }
        }

        // `-i`/`--interactive`. Both spellings name the same `kBoolean`
        // option, so `-i` is expanded here rather than left to the alias table,
        // which the CLI does not consult while walking. The `=value` form is
        // accepted and ignored like `--print`'s, and `--no-interactive` clears
        // what an earlier `-i` set — which is what makes
        // `NODE_OPTIONS=--interactive` overridable on the command line.
        if argument == "-i" || argument == "--interactive" || argument.starts_with("--interactive=")
        {
            options.force_repl = true;
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--no-interactive" {
            options.force_repl = false;
            options.exec_argv.push(argument.clone());
            index += 1;
            continue;
        }

        // `--check`/`-c` selects `internal/main/check_syntax` instead of running
        // the entry point. Both spellings are in Node's option table as
        // `--check` plus the `-c` alias, and `--no-check` clears it the way any
        // boolean negation does, so all three go through [`flag_name`].
        if let Some((name, negated)) = flag_name(argument) {
            if name == "--check" {
                options.syntax_check_only = !negated;
                options.exec_argv.push(argument.clone());
                index += 1;
                continue;
            }
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

        if TEST_FLAGS_WITHOUT_VALUE.contains(&argument.as_str()) {
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

        // `--trace-exit` and `--trace-uncaught` are the two flags that add
        // diagnostics to a *fatal* path, so accepting them without acting on
        // them would be invisible: the process still exits with the right
        // status, just silently. Both are parsed here rather than left to the
        // generic "declared but not acted on" branch for that reason.
        //
        // They are booleans in Node's table, so the `=value` form is accepted
        // and discarded, and `--no-` clears what an earlier source set. That is
        // the same rule `--trace-warnings` and every other boolean follows;
        // these two differ only in that the CLI itself, not `lib/**`, is what
        // reads them.
        if let Some((name, negated)) = flag_name(argument) {
            let sets = !negated;
            match name {
                "--trace-exit" => {
                    options.trace_exit = sets;
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                "--trace-uncaught" => {
                    options.trace_uncaught = sets;
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                // `--bench` is `kDisallowedInEnvvar`, so it can only arrive
                // here from the command line; `NODE_OPTIONS=--bench` is refused
                // by `rn_bind_options::parse_env` before the walk starts.
                //
                // It is recorded rather than left to the generic "declared but
                // not acted on" branch because `CheckOptions` has four
                // combinations to reject and `StartExecution` dispatches on it.
                "--bench" => {
                    options.bench_runner = sets;
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                // `--v8-options` prints V8's list and exits 0. It is recorded
                // here rather than answered in this walk because V8 is not
                // initialised yet: `main` answers it where `src/node.cc:1297`
                // does, after the V8 flag vector is applied and before
                // `V8::Initialize`.
                //
                // The flag is `kDisallowedInEnvvar`, so `NODE_OPTIONS` is
                // refused by `rn_bind_options::parse_env` before this point;
                // `test-cli-node-options-disallowed.js` asserts exactly that.
                "--v8-options" => {
                    options.print_v8_options = sets;
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                // `--zero-fill-buffers` is `kAllowedInEnvvar`, so its value can
                // also come from the store; `finish` installs whichever source
                // won.
                "--zero-fill-buffers" => {
                    options.zero_fill_buffers = sets;
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                // `--debug` and `--debug-brk` are rejected, not accepted. They
                // are `BOOL_FIELD(deprecated_debug)` in Node's table and
                // `CheckOptions` turns that into DEP0062
                // (`src/node_options.cc:59`) — an error, exit 9, on every run
                // that names either one. Accepting them quietly would claim a
                // debugger endpoint this build does not open.
                //
                // `--debug-brk=` is an alias for `--debug-brk` in Node's table,
                // so the `=value` form is the same rejection; `--no-debug`
                // clears a flag that was never set, which is not an error.
                "--debug" | "--debug-brk" if negated => {
                    // `--no-debug` clears a flag that was never set. Only the
                    // non-negated spellings are the DEP0062 error, so this arm
                    // exists to let the negation through.
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                "--debug" | "--debug-brk" => {
                    return Err(ParseError::OptionValue(
                        "[DEP0062]: `node --debug` and `node --debug-brk` are invalid. \
                         Please use `node --inspect` and `node --inspect-brk` instead."
                            .to_string(),
                    ));
                }
                _ => {}
            }
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

        // `lib/tls.js` reads these protocol toggles from `internal/options`.
        // Accepting them here keeps the CLI aligned with the option table and
        // lets JS set `DEFAULT_MIN_VERSION` / `DEFAULT_MAX_VERSION`.
        if TLS_VERSION_FLAGS.contains(&argument.as_str()) {
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
                options.exec_argv.push(argument.clone());
                options.exec_argv.push(next.clone());
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

        // `--env-file` and `--env-file-if-exists`, in either spelling. They are
        // handled here rather than left to the generic "declared but not acted
        // on" branch below because they *are* acted on, and the reading happens
        // in [`finish`] where the walk's whole result is available.
        match env_file_request(argument, args.get(index + 1)) {
            Ok(Some((request, consumed_value))) => {
                options.exec_argv.push(argument.clone());
                if consumed_value {
                    options.exec_argv.push(request.path.clone());
                }
                options.env_files.push(request);
                index += if consumed_value { 2 } else { 1 };
                continue;
            }
            Ok(None) => {}
            Err(message) => return Err(ParseError::Cli(message)),
        }

        // A permission grant whose value is a separate argument. Node accepts
        // both spellings and its own tests use both, so the value is taken here.
        // This is checked before the generic permission branch below, because
        // `--allow-fs-read` alone would otherwise be accepted as a bare boolean
        // and its value treated as the script path.
        if PERMISSION_VALUE_FLAGS.contains(&argument.as_str()) {
            let Some(value) = args.get(index + 1) else {
                return Err(ParseError::Cli(format!("{argument} requires an argument")));
            };
            options.exec_argv.push(argument.clone());
            options.exec_argv.push(value.clone());
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
            // Both entries, exactly as typed, because that is what
            // `process.execArgv` reports for the separate spelling. Joining them
            // into `--require=x` made `test-dotenv.js`'s own flag check spin
            // forever: `test/common/index.js` re-spawns the file when a
            // `// Flags:` entry is absent from `process.execArgv`, and the joined
            // form never matches the two-entry flag it looks for.
            options.exec_argv.push(argument.clone());
            options.exec_argv.push(value.clone());
            index += 2;
            continue;
        }

        if TEST_VALUE_SEPARATE.contains(&argument.as_str()) {
            let Some(value) = args.get(index + 1) else {
                return Err(ParseError::Cli(format!("{argument} requires an argument")));
            };
            options.exec_argv.push(argument.clone());
            options.exec_argv.push(value.clone());
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
            // Whether this is reported depends on what Node's table says the
            // flag *is*, not on the `--experimental-` prefix: a `NoOp{}` entry
            // has no behaviour in Node either, so there is nothing missing here
            // and the warning would be false. See [`warns_about`].
            if warns_about(argument) {
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

        // A declared option rustnode does not act on still takes its value the
        // way `Parse` does. Without this, `--input-type module` reported
        // `unsupported option '--input-type'` and then treated `module` as the
        // script path — a rejection that named the wrong problem, with a
        // second one hiding behind it.
        //
        // Both arguments are recorded exactly as typed, which is the shape
        // `process.execArgv` reports for each spelling. A separate value may not
        // start with `-`: `Parse` calls `missing_argument()` there. `--run` is
        // the one option whose value is optional, so a following flag is not an
        // error for it; Node lists the package's scripts instead.
        if rn_bind_options::takes_separate_value(argument) {
            // `--stack-trace-limit` is the one option that is both an `kInteger`
            // and forwarded to V8. Node's `Parse` pushes `arg` — the argument
            // *as typed* — onto `v8_args` for it
            // (`src/node_options-inl.h:503`), and that one line produces three
            // different behaviours, all of which the oracle exhibits:
            //
            // * `--stack-trace-limit=42` pushes `--stack-trace-limit=42`, which
            //   V8 accepts, so the limit really changes.
            // * `--stack-trace-limit 42` pushes the *bare* `--stack-trace-limit`,
            //   which V8 rejects with `missing value for flag … of type int` and
            //   exits 9. The separate form is therefore not supported by Node at
            //   all, and reproducing the forwarding reproduces the rejection.
            // * `NODE_OPTIONS=--stack-trace-limit=42` takes `env.rs`'s own
            //   `kInteger` branch, which does the same thing for the variable.
            //
            // Forwarding only the inline form would accept a command line the
            // oracle refuses, which is the divergence this branch is meant to
            // remove, so the argument goes over exactly as typed.
            let also_v8 = rn_bind_options::is_v8_flag(argument);
            if !argument.starts_with("--") || !argument.contains('=') {
                match args.get(index + 1) {
                    Some(value) if !value.starts_with('-') => {
                        options.exec_argv.push(argument.clone());
                        options.exec_argv.push(value.clone());
                        if also_v8 {
                            options.v8_args.push(argument.clone());
                        }
                        if UNIMPLEMENTED.contains(&argument.as_str()) {
                            unimplemented.insert(argument.clone());
                        }
                        index += 2;
                        continue;
                    }
                    _ if argument == "--run" => {
                        options.exec_argv.push(argument.clone());
                        index += 1;
                        continue;
                    }
                    _ => {
                        return Err(ParseError::Cli(format!("{argument} requires an argument")));
                    }
                }
            }
            // The inline form: the value is already attached, so it is recorded
            // as typed and the walk moves past this one argument.
            if UNIMPLEMENTED
                .iter()
                .any(|flag| argument.starts_with(&format!("{flag}=")))
            {
                unimplemented.insert(argument.clone());
            }
            options.exec_argv.push(argument.clone());
            if also_v8 {
                options.v8_args.push(argument.clone());
            }
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
    // and every branch below is one of its cases. `--help` is checked there
    // before `-e` is (`:371` against `:380`), which is why `node -e 1 --help`
    // prints the usage text instead of running the code.
    let positional = &args[index..];
    let run_test = options.exec_argv.iter().any(|flag| flag == "--test")
        || options.env_argv.iter().any(|flag| flag == "--test");
    options.source = if positional.first().map(String::as_str) == Some(INSPECT_SUBCOMMAND) {
        // `StartExecution` checks `first_argv == "inspect"` (`src/node.cc:367`)
        // before it looks at `print_help` (`:371`) or `has_eval_string` (`:384`),
        // and `first_argv` is `argv[1]` *after* the option walk has erased the
        // flags it consumed (`ArgsInfo::pop_first`). That is why
        // `node --help inspect` prints the debugger's usage rather than the
        // runtime's, and why `node -e 'x' inspect` does not evaluate anything.
        // Both are what the oracle does, so the check comes first here too.
        //
        // `--version` is the one thing that beats it, because Node answers that
        // in `ProcessGlobalArgs` before dispatch is reached at all.
        options.script_args = positional[1..].to_vec();
        Source::Inspect
    } else if options.print_help {
        // `internal/main/print_help` is a main script rather than a flag
        // answer, so the realm has to be up before it runs.
        options.script_args = positional.to_vec();
        Source::Help
    } else if run_test {
        options.script_args = positional.to_vec();
        Source::Test
    } else if options.bench_runner {
        // `src/node.cc:388`, after `syntax_check_only` (`:384`) and before
        // `test_runner` (`:392`). The four combinations `CheckOptions` rejects
        // are refused in [`finish`], so reaching here means `--bench` is the
        // only entry point asked for. The glob patterns are `process.argv[1..]`,
        // which is what `bench_runner.js` slices.
        options.script_args = positional.to_vec();
        Source::Bench
    } else if eval_code.is_some() {
        // `-e`/`-p` ran: their arguments are `argv.slice(1)`, with an explicit
        // `--` consumed by the flag walk above rather than forwarded.
        //
        // `-i` beats `-e`: `StartExecution` reaches `eval_string` only when
        // `has_eval_string && !force_repl` (`src/node.cc:380`), so
        // `node -i -e 42` starts the REPL and evaluates `42` inside it. The
        // eval code still travels in `exec_argv`, where `internal/main/repl`
        // reads it back through `getOptionValue('--eval')`.
        //
        // The code is not carried into [`Source::Eval`]: `finish` applies
        // `exec_argv` to the option store, and `eval_string.js` reads it back
        // with `getOptionValue('--eval')`. The `eval_code` binding exists to
        // decide *that* there is an eval at all, which is what
        // `has_eval_string` means to `StartExecution`.
        if options.force_repl {
            options.script_args = positional.to_vec();
            Source::Repl
        } else {
            options.script_args = positional.to_vec();
            Source::Eval
        }
    } else if options.syntax_check_only {
        // `StartExecution` reaches `syntax_check_only` only after
        // `has_eval_string` (`src/node.cc:380` against `:384`), and the pair is
        // already rejected by [`finish`] with Node's own sentence, so reaching
        // here means there is no `-e` to run instead.
        //
        // The positional argument is `process.argv[1]`, which is what
        // `check_syntax.js` resolves and reads; with none, it reads stdin. Both
        // cases keep the original spelling here because the script does the
        // path resolution itself, and doing it here would make its
        // `process.argv[1]` already-absolute in a way Node's is not yet.
        options.script_args = positional.to_vec();
        Source::CheckSyntax
    } else if let Some((script, rest)) = positional.split_first() {
        // A positional is the script path, and `-` is the marker for stdin
        // rather than a file named `-`: `run_main_module` is skipped for it
        // (`src/node.cc:403`) and `eval_stdin` runs instead, with the marker
        // left in `process.argv`.
        //
        // A real path outranks `-i`: `StartExecution` tests the positional at
        // `:403` and `force_repl` only at `:407`, so `node -i file.js` runs the
        // file and never shows a prompt. The `-` marker is the exception,
        // because `:403` excludes it by name — `node -i -` is a REPL session.
        if script == "-" {
            if options.force_repl {
                options.script_args = positional.to_vec();
                Source::Repl
            } else {
                options.script_args = rest.to_vec();
                Source::Stdin { marker: true }
            }
        } else {
            options.script_args = rest.to_vec();
            Source::File(script.clone())
        }
    } else if options.force_repl {
        // `-i` with a pipe on stdin: the REPL is entered even though nothing
        // looks like a terminal (`src/node.cc:407`). This is the case every
        // `spawn(process.execPath, ['--interactive'])` test in the suite drives,
        // and the one `-i -e <code>` reaches after `:380` declines `-e`.
        options.script_args = positional.to_vec();
        Source::Repl
    } else if stdin == StdinKind::Redirected {
        // No script, standard input is not a terminal: Node reads it as a
        // CommonJS module. This is the case that used to evaluate `"0"` and
        // exit 0 without printing anything.
        Source::Stdin { marker: false }
    } else {
        // A terminal with no script and no `-i`. `StartExecution`'s last test
        // is `uv_guess_handle(STDIN_FILENO) == UV_TTY` (`src/node.cc:407`),
        // which this is, so Node starts the REPL here too.
        Source::Repl
    };

    finish(options, unimplemented)
}

/// The canonical option name inside one argument, plus whether it was negated.
///
/// This is the normalization `Parse` applies before its table lookup
/// (`src/node_options-inl.h:365-390`): a `--long` argument is split at `=`, and
/// a `--no-` prefix is removed and reported as a negation. It is why
/// `--no-version` clears what an earlier `--version` set instead of being an
/// unknown option.
///
/// Only the six spellings the caller handles are canonicalized, and they are
/// returned as `'static` strings so the `--no-` prefix can be dropped without an
/// allocation. Returns `None` for anything else, including a short flag with a
/// value glued on (`-v=`): `Parse` only splits on `=` when the argument starts
/// with two dashes, so `-v=` is V8's `bad option`, not `-v`.
///
/// `-c` is the alias table's spelling of `--check`, and `--check` is a boolean,
/// so it takes the `=value` form and the `--no-` negation like the two above.
fn flag_name(argument: &str) -> Option<(&'static str, bool)> {
    // Only a `--long` argument is split at `=`: `Parse` skips the split entirely
    // for a short flag, so `-v=1` is not `-v`.
    let name = if argument.starts_with("--") {
        argument.split_once('=').map_or(argument, |(name, _)| name)
    } else {
        argument
    };
    match name {
        "--version" | "-v" => Some(("--version", false)),
        "--help" | "-h" => Some(("--help", false)),
        "--check" | "-c" => Some(("--check", false)),
        "--trace-exit" => Some(("--trace-exit", false)),
        "--trace-uncaught" => Some(("--trace-uncaught", false)),
        "--bench" => Some(("--bench", false)),
        "--v8-options" => Some(("--v8-options", false)),
        "--zero-fill-buffers" => Some(("--zero-fill-buffers", false)),
        "--debug" | "--debug-brk" => Some(("--debug-brk", false)),
        "--no-debug" | "--no-debug-brk" => Some(("--debug-brk", true)),
        "--no-version" => Some(("--version", true)),
        "--no-help" => Some(("--help", true)),
        "--no-check" => Some(("--check", true)),
        "--no-trace-exit" => Some(("--trace-exit", true)),
        "--no-trace-uncaught" => Some(("--trace-uncaught", true)),
        "--no-bench" => Some(("--bench", true)),
        "--no-v8-options" => Some(("--v8-options", true)),
        "--no-zero-fill-buffers" => Some(("--zero-fill-buffers", true)),
        _ => None,
    }
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

/// One option's value from a raw argument list, in either spelling.
///
/// `--flag=value` and `--flag value` both count, because `Parse` accepts both for
/// every non-boolean non-V8 option and rustnode records the separate form as two
/// entries. Returns the last occurrence, which is the last-write-wins rule
/// `Parse` applies to a scalar.
fn option_value(argv: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let mut found = None;
    let mut index = 0;
    while index < argv.len() {
        let argument = &argv[index];
        if let Some(value) = argument.strip_prefix(&prefix) {
            found = Some(value.to_string());
        } else if argument == name {
            if let Some(value) = argv.get(index + 1) {
                found = Some(value.clone());
            }
            index += 1;
        }
        index += 1;
    }
    found
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
/// `--inspect-brk-node`, `--inspect-wait` or one of their `=value` forms.
fn is_inspect_flag(argument: &str) -> bool {
    let name = argument.split_once('=').map_or(argument, |(name, _)| name);
    matches!(
        name,
        "--inspect"
            | "--inspect-port"
            | "--inspect-brk"
            | "--inspect-brk-node"
            | "--inspect-wait"
            | "--no-inspect"
            | "--no-inspect-brk"
            | "--no-inspect-wait"
            | "--no-inspect-brk-node"
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
/// * `--inspect-brk-node` additionally asks the native agent to break at
///   bootstrap after waiting.
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
        "--inspect" => {
            options.debug_port = parsed;
            options.inspect_enabled = true;
        }
        // `--no-inspect` is the negation of a boolean in Node's table, so it
        // clears what an earlier source set instead of leaving it open. Node
        // options are last-write-wins, and `test-debugger-no-inspect-brk.js`
        // asserts both directions: `--no-inspect --no-inspect-brk --inspect-brk`
        // still breaks, and a lone `--no-inspect` before `probe.js` refuses.
        "--no-inspect" => {
            options.inspect_enabled = false;
            options.inspect_wait = false;
            options.inspect_break_node = false;
        }
        "--no-inspect-brk" => options.inspect_wait = false,
        "--no-inspect-wait" => options.inspect_wait = false,
        "--no-inspect-brk-node" => {
            options.inspect_break_node = false;
        }
        // `--inspect-wait` opens the endpoint and blocks for a client like
        // `--inspect-brk`, but arms no break-on-start: Node's `wait_for_connect()`
        // is true while `break_node_first_line` stays false, so
        // `WaitForConnectByOptions` waits and then runs straight into user code.
        // Treating it as plain `--inspect` made the process never wait at all.
        "--inspect-wait" => {
            options.debug_port = parsed;
            options.inspect_enabled = true;
            options.inspect_wait = true;
        }
        "--inspect-brk" => {
            options.debug_port = parsed;
            options.inspect_enabled = true;
            options.inspect_wait = true;
        }
        "--inspect-brk-node" => {
            options.debug_port = parsed;
            options.inspect_enabled = true;
            options.inspect_wait = true;
            options.inspect_break_node = true;
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
    // `InitializeOncePerProcess` parses the env files before V8 is initialised
    // and before the command line's own errors are reported, which is why
    // `node --env-file=missing --not-a-real-flag` names the file rather than the
    // flag. Applying them here reproduces both facts: the files are read after
    // the walk (so a later `--env-file` still wins), and a bad file stops the
    // process with exit 9.
    //
    // They have to be *read* during parsing rather than later, because
    // `--permission`'s environment scrub happens before the realm exists and the
    // names a file defines have to be known by then to be granted. The values
    // are installed separately, after the scrub — see `main`.
    options.env_file_store = match read_env_files(&options.env_files) {
        Ok(store) => store,
        Err(messages) => return Err(ParseError::EnvFile(messages)),
    };
    // `EnvironmentOptions::CheckOptions` (`src/node_options.cc:318`) rejects this
    // pair by name. Node's dispatch would otherwise reach `--eval` first
    // (`src/node.cc:380` before `:384`), so without the check the command would
    // quietly evaluate the string and never say the two cannot be combined.
    if options.syntax_check_only && matches!(options.source, Source::Eval) {
        return Err(ParseError::OptionValue(
            "either --check or --eval can be used, not both".to_string(),
        ));
    }
    // `CheckBenchOptions` (`src/node_options.cc:375`) needs every option source
    // parsed before it can look at `--experimental-bench`, so it runs here rather
    // than during the walk. Each message is Node's own sentence; the first four
    // are `CheckOptions`' `bench_runner` block and the last is the separate
    // "is the experimental flag present" check.
    //
    // Order matters: Node reports the combination errors from `CheckOptions`
    // before `CheckBenchOptions` runs, which is why `--bench --test` names the
    // pair rather than the missing `--experimental-bench`.
    //
    // The experimental check gates more than `--bench` itself: every
    // `--bench-*` option is in the same `kBenchRunnerNamespace`, and
    // `CheckBenchOptions` asks `has_bench_options` rather than `bench_runner`
    // alone, so `--bench-samples=1` without `--experimental-bench` is rejected
    // exactly like `--bench`. `test-bench-cli.js` walks all seven spellings.
    let has_bench_options = options.bench_runner
        || options
            .exec_argv
            .iter()
            .chain(options.env_argv.iter())
            .any(|flag| {
                let name = flag.split_once('=').map_or(flag.as_str(), |(name, _)| name);
                name.starts_with("--bench-")
            });
    // The four combination errors are inside `if (bench_runner)`, not
    // `if (has_bench_options)`: a bare `--bench-samples=1` alongside `--test`
    // is only the missing-experimental-flag error, never the pairing one.
    if options.bench_runner {
        if options.exec_argv.iter().any(|flag| flag == "--test")
            || options.env_argv.iter().any(|flag| flag == "--test")
        {
            return Err(ParseError::OptionValue(
                "either --bench or --test can be used, not both".to_string(),
            ));
        }
        if options.syntax_check_only {
            return Err(ParseError::OptionValue(
                "either --bench or --check can be used, not both".to_string(),
            ));
        }
        if options
            .exec_argv
            .iter()
            .any(|flag| flag == "-e" || flag == "--eval")
            || options
                .env_argv
                .iter()
                .any(|flag| flag == "-e" || flag == "--eval")
        {
            return Err(ParseError::OptionValue(
                "either --bench or --eval can be used, not both".to_string(),
            ));
        }
        if options.force_repl {
            return Err(ParseError::OptionValue(
                "either --bench or --interactive can be used, not both".to_string(),
            ));
        }
        if options
            .exec_argv
            .iter()
            .chain(options.env_argv.iter())
            .any(|flag| flag == "--watch" || flag.starts_with("--watch-path="))
        {
            return Err(ParseError::OptionValue(
                "either --bench or --watch can be used, not both".to_string(),
            ));
        }
        // `--bench-isolation` accepts only `none` and `process`
        // (`src/node_options.cc:383`). A bare `--bench-isolation` gets the
        // default `process`; anything else is rejected by name.
        if let Some(value) = option_value(&options.exec_argv, "--bench-isolation") {
            if value != "none" && value != "process" {
                return Err(ParseError::OptionValue(
                    "invalid value for --bench-isolation".to_string(),
                ));
            }
        }
        // `has_bench_samples` distinguishes "not given" from "given as 0", so a
        // zero that arrived from the command line is an error while the absent
        // default is not.
        if option_value(&options.exec_argv, "--bench-samples").as_deref() == Some("0") {
            return Err(ParseError::OptionValue(
                "--bench-samples must be greater than 0".to_string(),
            ));
        }
    }
    if has_bench_options {
        // `CheckBenchOptions`: `--experimental-bench` is what makes
        // `node:bench` requireable, and the runner cannot load without it. The
        // message names the flag and is printed with exit 9, like every other
        // rejected option.
        //
        // Read from the raw argv rather than from `options.parsed`, because this
        // check runs before `parsed.apply` below feeds the store — the same
        // reason the `--test` check above scans `exec_argv`. Both sources count:
        // the flag is `kDisallowedInEnvvar`, so only `NODE_OPTIONS` rejection
        // already removed it from `env_argv`, but scanning both keeps this
        // honest if that ever changes.
        let experimental = options
            .exec_argv
            .iter()
            .chain(options.env_argv.iter())
            .any(|flag| flag == "--experimental-bench");
        if !experimental {
            return Err(ParseError::OptionValue(
                "--experimental-bench is required to use --bench or related options".to_string(),
            ));
        }
    }
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
    // `Environment::InitializePermission` adds every name an env file defined to
    // the `env` allow list: "variables defined in env files are allowed"
    // (`src/env.cc:1155`). It is a *second* grant, applied after the scrub, and
    // that order is what `test-permission-env-file.js` asserts: an inherited value
    // for a name the file also defines is removed by the scrub — which only knows
    // about the command line's `--allow-env` — and the file's value then takes
    // effect. Granting these names before the scrub would keep the inherited
    // value, which is the opposite of what Node does.
    //
    // The names come from the files that were successfully read: one that did not
    // exist contributed nothing, and it already stopped the process unless it was
    // the tolerant spelling.
    let env_file_names: Vec<String> = options.env_file_store.keys().cloned().collect();
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
    // The second `env` grant, from the files rather than the command line. It has
    // to be on the model rather than in `permission_config.allow_env` because the
    // scrub reads that one, and a name granted there would survive as the
    // inherited value instead of the file's.
    if !env_file_names.is_empty() {
        options.permission.apply_env_allow(&env_file_names);
    }
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
            // Joined, because these tests assert on the text a user sees and
            // `main` prints one line per message; keeping the vector would make
            // every assertion compare a `Vec` to a `&str`.
            ParseError::EnvFile(messages) => messages.join("\n"),
        })
    }

    /// `-e` and `-p` both select `internal/main/eval_string`; they differ only in
    /// the `--print` option value that script reads.
    ///
    /// The source is deliberately identical for the two: `eval_string.js` is
    /// what branches on `getOptionValue('--print')`, so a second Rust-side
    /// `print` field would be a flag nothing reads. Asserting on the store is
    /// asserting on what the script actually sees.
    #[test]
    fn eval_and_print_are_distinguished_by_the_print_option() {
        let options = parse_of(&["-e", "1+1"]).expect("parses");
        assert!(matches!(options.source, Source::Eval));
        assert_eq!(
            options.parsed.value_of("--print"),
            Some(rn_bind_options::parsed::ParsedValue::Bool(false)),
            "-e must leave --print false"
        );

        let options = parse_of(&["-p", "1+1"]).expect("parses");
        assert!(matches!(options.source, Source::Eval));
        assert_eq!(
            options.parsed.value_of("--print"),
            Some(rn_bind_options::parsed::ParsedValue::Bool(true)),
            "-p must set --print, which eval_string reads"
        );
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
        // A flag Node binds to a real field, whose behaviour rustnode lacks.
        // `experimental_network_inspection` reaches `setupNetworkTracking` in
        // `src/inspector_agent.cc`, and this build publishes no such method.
        let options = parse_of(&["--experimental-network-inspection", "-e", "1"]).expect("parses");
        assert_eq!(options.unimplemented, ["--experimental-network-inspection"]);
    }

    /// The rule the warning has to follow, as a table over Node's own kinds.
    ///
    /// Driven from `rn_bind_options` rather than from a literal list, because the
    /// defect was a literal list drifting from the table: every `NoOp{}` entry was
    /// warned about even though Node does nothing behind it either. A name added
    /// to `src/node_options.cc` as `NoOp` therefore cannot be mis-declared here
    /// without this test failing.
    #[test]
    fn a_no_op_flag_is_never_reported_unimplemented() {
        let no_ops = rn_bind_options::no_op_names();
        // The table has 19 such entries; a generator change that emptied this
        // list would make the loop below assert nothing.
        assert!(no_ops.len() >= 13, "{no_ops:?}");

        for flag in no_ops {
            let options = parse_of(&[flag, "-e", "1"])
                .unwrap_or_else(|error| panic!("{flag} should parse: {error}"));
            assert!(
                options.unimplemented.is_empty(),
                "{flag} is NoOp in Node's table but was reported unimplemented"
            );
        }
    }

    /// The other direction: silencing `NoOp` must not silence a flag whose
    /// behaviour really is missing. Without this, a `warns_about` that returned
    /// `false` unconditionally would pass the test above.
    ///
    /// Every one of these was measured missing against the pinned oracle:
    /// `--experimental-eventsource` leaves `globalThis.EventSource` `undefined`
    /// where Node reports `function`, and the other three are the C++ surfaces
    /// named in [`UNIMPLEMENTED`].
    #[test]
    fn a_flag_with_real_behaviour_is_still_reported() {
        for flag in UNIMPLEMENTED {
            assert!(
                !rn_bind_options::is_no_op(flag),
                "{flag} is a NoOp, so it does not belong in UNIMPLEMENTED"
            );
            let options = parse_of(&[flag, "-e", "1"])
                .unwrap_or_else(|error| panic!("{flag} should parse: {error}"));
            assert_eq!(options.unimplemented, [*flag]);
        }
    }

    /// Silence has to be earned, so the two lists cannot overlap: a flag in both
    /// would be one this build both does and does not honour.
    #[test]
    fn no_flag_is_both_implemented_and_unimplemented() {
        for flag in IMPLEMENTED_EXPERIMENTAL {
            assert!(
                !UNIMPLEMENTED.contains(flag),
                "{flag} is claimed by both lists"
            );
        }
    }

    /// A flag that is neither implemented nor known-missing still warns.
    ///
    /// This is the direction the defect was in: `--experimental-vm-modules` was a
    /// false alarm because nothing proved it worked, and the fix is to prove the
    /// ones that do rather than to assume it. A flag nobody has verified keeps
    /// saying so.
    #[test]
    fn an_unverified_experimental_flag_still_warns() {
        for flag in [
            "--experimental-storage-inspection",
            "--experimental-worker-inspection",
            "--experimental-inspector-network-resource",
            "--experimental-webstorage",
            "--experimental-quic",
        ] {
            assert!(!rn_bind_options::is_no_op(flag), "{flag}");
            assert!(!IMPLEMENTED_EXPERIMENTAL.contains(&flag), "{flag}");
            let options = parse_of(&[flag, "-e", "1"]).expect("parses");
            assert_eq!(options.unimplemented, [flag]);
        }
    }

    /// `--experimental-vm-modules` is a `BOOL_FIELD` whose value rustnode stores
    /// *and* whose reader is in vendored `lib/**`, so the feature is live and the
    /// warning this used to print was false. `typeof
    /// require('vm').SourceTextModule` is `"function"` with the flag on both
    /// runtimes, which is the observable the oracle check pins.
    #[test]
    fn an_experimental_flag_whose_value_is_honoured_is_not_reported() {
        let options = parse_of(&["--experimental-vm-modules", "-e", "1"]).expect("parses");
        assert!(options.unimplemented.is_empty());
        assert_eq!(
            options.parsed.value_of("--experimental-vm-modules"),
            Some(rn_bind_options::ParsedValue::Bool(true))
        );
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
        // The separate form keeps both entries, which is what the oracle reports
        // for `process.execArgv`. The model still sees the value: `from_args`
        // reads the following argument itself.
        assert_eq!(
            separate.exec_argv,
            ["--permission", "--allow-fs-read", "/tmp/x", "-e", "1"]
        );
        assert!(
            separate.permission.check_fs_read("/tmp/x").is_ok(),
            "the separate form must grant the path"
        );
        assert!(matches!(separate.source, Source::Eval));
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
        assert!(matches!(options.source, Source::Eval));
    }

    #[test]
    fn a_separate_value_flag_consumes_two_arguments() {
        let options = parse_of(&["--require", "preload.js", "-e", "1"]).expect("parses");
        // Both entries are kept exactly as typed, because that is what the oracle
        // reports for `process.execArgv` and what `test/common/index.js` matches a
        // `// Flags:` header against. Joining them into `--require=preload.js` made
        // `test-dotenv.js` re-spawn itself forever: its flag check looks for the
        // two-entry form and never found it.
        assert_eq!(options.exec_argv, ["--require", "preload.js", "-e", "1"]);
        assert!(matches!(options.source, Source::Eval));
        // The store still sees the value, because its own walk consumes the
        // separate argument.
        assert_eq!(
            options.parsed.value_of("--require"),
            Some(rn_bind_options::parsed::ParsedValue::List(vec![
                "preload.js".to_string()
            ]))
        );
    }

    /// `--env-file` is read, not merely accepted: a missing file is a startup
    /// error and `--env-file-if-exists` is not.
    ///
    /// The parser is where this is observable without a filesystem, because
    /// [`read_env_files`] runs from [`finish`]: a missing file must surface as a
    /// [`ParseError::EnvFile`] rather than as a `Source` that runs the script
    /// anyway, which is the "accepted and ignored" shape `UNIMPLEMENTED` exists to
    /// prevent.
    #[test]
    fn a_missing_env_file_is_a_startup_error() {
        let error = parse_of(&["--env-file=/nonexistent/rn-test.env", "-e", "1"])
            .expect_err("a missing env file must be rejected");
        assert_eq!(error, "/nonexistent/rn-test.env: not found");
    }

    /// The tolerant spelling continues, and the script still runs.
    #[test]
    fn a_missing_optional_env_file_continues() {
        let options = parse_of(&["--env-file-if-exists=/nonexistent/rn-test.env", "-e", "1"])
            .expect("the tolerant spelling must not fail");
        assert!(matches!(options.source, Source::Eval));
        assert_eq!(options.env_files.len(), 1);
        assert!(options.env_files[0].optional);
    }

    /// Both spellings are recorded in argv order, because later files win for a
    /// duplicated key and `execArgv` has to report what the user typed.
    #[test]
    fn env_files_keep_their_order_and_spelling() {
        // The required file has to exist: `--env-file` is read from `finish`, so a
        // missing one is a startup error rather than a parse success.
        let directory = std::env::temp_dir().join(format!("rn-env-order-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create the scratch directory");
        let present = directory.join("a.env");
        std::fs::write(&present, "RN_ENV_ORDER=a\n").expect("write the env file");
        let present = present.to_string_lossy().into_owned();
        let options = parse_of(&[
            "--env-file",
            &present,
            "--env-file-if-exists",
            "b.env",
            "-e",
            "1",
        ])
        .expect("parses");
        assert_eq!(
            options.env_files,
            [
                EnvFileRequest {
                    path: present.clone(),
                    optional: false
                },
                EnvFileRequest {
                    path: "b.env".to_string(),
                    optional: true
                },
            ]
        );
        assert_eq!(
            options.exec_argv,
            [
                "--env-file",
                present.as_str(),
                "--env-file-if-exists",
                "b.env",
                "-e",
                "1"
            ]
        );
        // The store keeps what the file defined, which is what `main` installs.
        assert_eq!(
            options
                .env_file_store
                .get("RN_ENV_ORDER")
                .map(String::as_str),
            Some("a")
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A value that looks like a flag is refused, naming the flag as typed.
    #[test]
    fn an_env_file_with_no_value_is_rejected() {
        let error =
            parse_of(&["--env-file", "-e", "1"]).expect_err("a missing value must be rejected");
        assert_eq!(error, "--env-file requires an argument");

        let error =
            parse_of(&["--env-file-if-exists"]).expect_err("a missing value must be rejected");
        assert_eq!(error, "--env-file-if-exists requires an argument");
    }

    #[test]
    fn a_short_flag_keeps_its_value_as_a_separate_entry() {
        // `-r=x` is not a spelling Node accepts: an `=` is read only on a
        // two-dash argument, so joining the pair would record `-r=x`, which the
        // alias table has no entry for and the preload would never run.
        // `process.execArgv` under the oracle is `["-r", "/tmp/pre.js", ...]`,
        // which is the shape this pins.
        let options = parse_of(&["-r", "/tmp/pre.js", "-e", "1"]).expect("parses");
        assert_eq!(options.exec_argv, ["-r", "/tmp/pre.js", "-e", "1"]);
        assert!(matches!(options.source, Source::Eval));
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
        // behaviour behind rustnode's back. `--report-compact` is in the
        // table and the CLI does not act on it, so it stays an error and never
        // reaches `v8_args`.
        let error = parse_of(&["--report-compact", "-e", "1"]).expect_err("rejects");
        assert!(error.contains("--report-compact"), "{error}");
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

        let options = parse_of(&["--experimental-shadow-realm", "-e", "1"]).expect("parses");
        assert_eq!(options.unimplemented, ["--experimental-shadow-realm"]);
        assert!(options.v8_args.is_empty(), "{:?}", options.v8_args);
    }

    /// `--require-module` defaults to true, and the `--no-` spellings both clear
    /// it in the same store entry.
    ///
    /// The default is the part that matters most: `loader.js:1897` reads this to
    /// decide whether a `require()`d file is reparsed for ESM syntax, and
    /// `:2104` throws `ERR_REQUIRE_ESM` when it is off. `DEFINE_BOOL_FIELD(
    /// require_module) = true` in `src/node_options.h:216` is where the default
    /// comes from, so a store that started `false` would break `require()` of
    /// ESM everywhere, not only under the flag.
    #[test]
    fn require_module_defaults_to_true_and_each_negation_clears_it() {
        let options = parse_of(&["-e", "1"]).expect("parses");
        assert_eq!(
            options.parsed.value_of("--require-module"),
            Some(rn_bind_options::ParsedValue::Bool(true))
        );

        for flag in ["--no-require-module", "--no-experimental-require-module"] {
            let options = parse_of(&[flag, "-e", "1"])
                .unwrap_or_else(|error| panic!("{flag} should parse: {error}"));
            assert_eq!(
                options.parsed.value_of("--require-module"),
                Some(rn_bind_options::ParsedValue::Bool(false)),
                "{flag} left --require-module set"
            );
        }
    }

    /// The two spellings are one field in Node, so the *last* one wins across
    /// both and each name reports the winner.
    ///
    /// Node binds `--require-module` and `--experimental-require-module` to the
    /// same `BOOL_FIELD(require_module)` (`src/node_options.cc:719` and `:724`),
    /// and `Parse` assigns as it walks. A store that kept the two names apart
    /// would answer `false` for the second command line below, which sends
    /// `loader.js` down the `ERR_REQUIRE_ESM` branch after the user asked for
    /// the opposite.
    #[test]
    fn the_require_module_aliases_share_one_value() {
        let cases = [
            (
                ["--no-require-module", "--experimental-require-module"],
                true,
            ),
            (
                ["--experimental-require-module", "--no-require-module"],
                false,
            ),
            (["--no-require-module", "--require-module"], true),
            (["--require-module", "--no-require-module"], false),
        ];
        for (flags, expected) in cases {
            let options = parse_of(&[flags[0], flags[1], "-e", "1"])
                .unwrap_or_else(|error| panic!("{flags:?} should parse: {error}"));
            for name in ["--require-module", "--experimental-require-module"] {
                assert_eq!(
                    options.parsed.value_of(name),
                    Some(rn_bind_options::ParsedValue::Bool(expected)),
                    "{flags:?} gave the wrong {name}"
                );
            }
        }
    }

    /// `-c` and `--check` are the same option, and both reach `check_syntax`.
    ///
    /// The two spellings matter because Node's own suite uses both: `-c` is the
    /// alias table's form (`src/node_options.cc`'s `AddAlias`), so a parser that
    /// took only `--check` would still reject half the syntax tests. The source
    /// is what the dispatch reads, so asserting on it is asserting on the
    /// routing rather than on a flag bit nothing consumes.
    #[test]
    fn check_selects_the_syntax_check_source_in_both_spellings() {
        for flag in ["-c", "--check"] {
            let options = parse_of(&[flag, "app.js"]).expect("parses");
            assert!(
                matches!(options.source, Source::CheckSyntax),
                "{flag} must select check_syntax, got {:?}",
                options.source
            );
            // The positional stays in `process.argv` because `check_syntax.js`
            // resolves `process.argv[1]` itself; resolving it here would make
            // the script see an already-absolute path Node's does not.
            assert_eq!(options.script_args, ["app.js"]);
            assert!(options.exec_argv.iter().any(|entry| entry == flag));
        }
    }

    /// `--no-check` clears a `--check` given before it, as for any boolean.
    #[test]
    fn no_check_clears_an_earlier_check() {
        let options = parse_of(&["--check", "--no-check", "app.js"]).expect("parses");
        assert!(!options.syntax_check_only);
        assert!(
            !matches!(options.source, Source::CheckSyntax),
            "a cleared flag must not select check_syntax, got {:?}",
            options.source
        );
    }

    /// `--check` with no positional reads stdin, so the source is still
    /// `CheckSyntax` and there is no script argument to hand the script.
    #[test]
    fn check_without_a_script_still_selects_check_syntax() {
        let options = parse_of(&["-c"]).expect("parses");
        assert!(matches!(options.source, Source::CheckSyntax));
        assert!(options.script_args.is_empty(), "{:?}", options.script_args);
    }

    /// `CheckOptions` rejects `--check` with `--eval` by name.
    ///
    /// Without this the dispatch reaches `--eval` first — Node's `StartExecution`
    /// checks `has_eval_string` (`src/node.cc:380`) before `syntax_check_only`
    /// (`:384`) — so the command would quietly evaluate the string instead of
    /// reporting that the two cannot be combined.
    #[test]
    fn check_with_eval_is_rejected_with_nodes_sentence() {
        let error = parse_of(&["-c", "-e", "1"]).expect_err("rejects");
        assert_eq!(error, "either --check or --eval can be used, not both");
    }

    /// The check flag must not swallow the `--check`-shaped V8 flags.
    ///
    /// `flag_name` matches exact spellings, so a longer name that merely starts
    /// with `--check` stays unknown and is left for V8 to accept or refuse. This
    /// pins the boundary rather than the specific flag.
    #[test]
    fn a_flag_merely_prefixed_with_check_is_not_check() {
        assert!(flag_name("--check-not-a-flag").is_none());
        assert_eq!(flag_name("-c"), Some(("--check", false)));
        assert_eq!(flag_name("--no-check"), Some(("--check", true)));
        // A short flag never splits at `=`, so `-c=1` is not `-c`.
        assert!(flag_name("-c=1").is_none());
    }

    #[test]
    fn double_dash_ends_flag_parsing() {
        let options = parse_of(&["--", "--looks-like-a-flag"]).expect("parses");
        assert!(matches!(options.source, Source::File(path) if path == "--looks-like-a-flag"));
    }

    /// No arguments on a terminal is the REPL, which is `StartExecution`'s last
    /// test (`src/node.cc:407`: `force_repl || uv_guess_handle(STDIN_FILENO) ==
    /// UV_TTY`). `parse_of` passes `StdinKind::Terminal`, so this is the branch
    /// a user typing bare `node` reaches.
    #[test]
    fn no_arguments_on_a_terminal_start_the_repl() {
        let options = parse_of(&[]).expect("parses");
        assert!(matches!(options.source, Source::Repl));
        assert!(!options.force_repl, "the REPL here comes from the terminal");
    }

    /// `-i`/`--interactive` selects the REPL when stdin is a pipe.
    ///
    /// This is the flag the whole `test/parallel/test-repl-*` cluster spawns its
    /// children with, and it used to be `unsupported option '--interactive'`
    /// (exit 9). The oracle is `spawn(process.execPath, ['--interactive'])`
    /// printing the banner and evaluating each line on a pipe.
    #[test]
    fn interactive_selects_the_repl_on_a_pipe() {
        for spelling in ["-i", "--interactive"] {
            let options = parse_of(&[spelling]).expect("parses");
            assert!(options.force_repl, "{spelling} sets force_repl");
            assert!(matches!(options.source, Source::Repl), "{spelling}");
            // `internal/main/repl` is a main script and calls
            // `prepareMainThreadExecution()` itself; the CLI must not.
            assert!(options.source.uses_main_script(), "{spelling}");
            assert_eq!(
                options.source.main_script_id(),
                Some("internal/main/repl"),
                "{spelling}"
            );
        }
        // The pipe is what makes this the interesting case: without `-i` it
        // would be `eval_stdin`.
        let options =
            parse_with_env(&["-i".to_string()], None, StdinKind::Redirected).expect("parses");
        assert!(matches!(options.source, Source::Repl));
    }

    /// A real script path outranks `-i`, which `StartExecution` decides by
    /// testing the positional at `src/node.cc:403` before `force_repl` at
    /// `:407`. `node -i file.js` runs the file and never shows a prompt.
    #[test]
    fn interactive_does_not_swallow_a_script_argument() {
        let options = parse_of(&["-i", "app.js"]).expect("parses");
        assert!(options.force_repl);
        assert!(matches!(options.source, Source::File(path) if path == "app.js"));
    }

    /// `-` is the exception to that ordering: `src/node.cc:403` excludes the
    /// marker by name, so `node -i -` is a REPL session whose `argv[1]` is `-`.
    #[test]
    fn interactive_with_the_stdin_marker_still_reaches_the_repl() {
        let options = parse_of(&["-i", "-"]).expect("parses");
        assert!(matches!(options.source, Source::Repl));
    }

    /// `-i` beats `-e`: `src/node.cc:380` is `has_eval_string && !force_repl`.
    /// The REPL then evaluates the code itself from `getOptionValue('--eval')`,
    /// which is why `node -i -e 'x'` prints the banner first and the eval output
    /// after it.
    #[test]
    fn interactive_takes_precedence_over_eval() {
        let options = parse_of(&["-i", "-e", "42"]).expect("parses");
        assert!(matches!(options.source, Source::Repl));
        // The code and its flag stay in `execArgv`, which is what makes
        // `process.execArgv` match the oracle's `["-i", "-e", "42"]` and lets
        // `internal/main/repl` read the code back.
        assert_eq!(options.exec_argv, ["-i", "-e", "42"]);
    }

    /// `--no-interactive` clears what an earlier spelling set, which is what
    /// makes `NODE_OPTIONS=--interactive` overridable on the command line.
    #[test]
    fn no_interactive_clears_the_request() {
        let args = ["--interactive".to_string(), "--no-interactive".to_string()];
        let options = parse_with_env(&args, None, StdinKind::Redirected).expect("parses");
        assert!(!options.force_repl);
        assert!(matches!(options.source, Source::Stdin { marker: false }));
    }

    /// `--interactive` is `kDisallowedInEnvvar` in Node's table
    /// (`src/node_options.cc:1496` passes no `kAllowedInEnvvar`), and the
    /// oracle rejects it with `--interactive is not allowed in NODE_OPTIONS`.
    /// Recording that here keeps the CLI from reading a value the environment
    /// parser already refused.
    #[test]
    fn interactive_is_not_allowed_in_node_options() {
        let error = rn_bind_options::parse_env("--interactive")
            .expect_err("NODE_OPTIONS must refuse --interactive");
        assert!(
            error
                .message()
                .contains("--interactive is not allowed in NODE_OPTIONS"),
            "{}",
            error.message()
        );
    }

    /// `node inspect` selects Node's debugger client, not a file named `inspect`.
    ///
    /// The defect this pins: the word was consumed as a script path, so every
    /// `test/debugger/*` invocation — all of which spell it this way — died with
    /// `Cannot find module '<cwd>/inspect'` before reaching an assertion. Node's
    /// `StartExecution` checks `first_argv == "inspect"` (`src/node.cc:367`)
    /// before it looks at the entry point at all.
    #[test]
    fn the_inspect_word_selects_the_debugger_client() {
        let options = parse_of(&["inspect"]).expect("parses");
        assert!(
            matches!(options.source, Source::Inspect),
            "inspect must select the debugger client, got {:?}",
            options.source
        );
        assert!(
            options.script_args.is_empty(),
            "a bare inspect has no arguments"
        );
        // It is not a flag and not part of `execArgv`: Node reports neither.
        assert!(options.exec_argv.is_empty(), "{:?}", options.exec_argv);
    }

    /// The debugger's own arguments follow `inspect` as script arguments.
    ///
    /// They belong in `process.argv[2..]` because `internal/main/inspect` reads
    /// them from there. Node's parser stops at the first non-flag, so `--port=0`
    /// is never an option of the *runtime*, and treating it as one would reject
    /// every `node inspect --port=0 script.js` with `bad option`.
    #[test]
    fn inspect_arguments_are_not_runtime_options() {
        let options = parse_of(&["inspect", "--port=0", "/tmp/app.js", "a"]).expect("parses");
        assert!(matches!(options.source, Source::Inspect));
        assert_eq!(options.script_args, ["--port=0", "/tmp/app.js", "a"]);
        // `--port` is not a runtime flag, so it must not reach `execArgv` or V8.
        assert!(options.exec_argv.is_empty(), "{:?}", options.exec_argv);
        assert!(options.v8_args.is_empty(), "{:?}", options.v8_args);
        assert!(
            options.unimplemented.is_empty(),
            "{:?}",
            options.unimplemented
        );
    }

    /// Runtime flags before `inspect` are still runtime flags.
    ///
    /// `NODE_DEBUG=inspect node --no-warnings inspect x.js` and the suite's own
    /// `node --expose-internals inspect ...` both rely on this: the option walk
    /// ends at `inspect`, and everything after it belongs to the debugger.
    #[test]
    fn flags_before_inspect_keep_their_meaning() {
        let options = parse_of(&["--no-warnings", "--expose-internals", "inspect", "--help"])
            .expect("parses");
        assert!(matches!(options.source, Source::Inspect));
        assert!(options.expose_internals(), "the flag must still be seen");
        assert_eq!(options.exec_argv, ["--no-warnings", "--expose-internals"]);
        assert_eq!(options.script_args, ["--help"]);
    }

    /// `inspect` wins over `-e`, which is `StartExecution`'s order.
    ///
    /// The oracle prints the debugger's usage for `node -e 'x' inspect` rather
    /// than evaluating anything, because the `inspect` branch comes before the
    /// `has_eval_string` one (`src/node.cc:367` versus `:384`).
    #[test]
    fn inspect_wins_over_eval() {
        let options = parse_of(&["-e", "console.log(1)", "inspect", "--help"]).expect("parses");
        assert!(
            matches!(options.source, Source::Inspect),
            "inspect must win over -e, got {:?}",
            options.source
        );
        assert_eq!(options.script_args, ["--help"]);
        // `-e` and its source stay in `execArgv`; Node records them before the
        // walk reaches `inspect`.
        assert_eq!(options.exec_argv, ["-e", "console.log(1)"]);
    }

    /// A file whose name merely contains `inspect` is a file.
    ///
    /// `StartExecution` compares the whole argument, so `./inspect`,
    /// `inspect.js` and `/path/to/inspect` are all entry points. Matching on a
    /// prefix would have broken the ordinary case of running a script called
    /// `inspect.js`.
    #[test]
    fn only_the_bare_word_is_the_subcommand() {
        for path in ["inspect.js", "./inspect", "/tmp/inspect", "inspect/"] {
            let options =
                parse_of(&[path]).unwrap_or_else(|error| panic!("{path} must parse: {error}"));
            assert!(
                matches!(options.source, Source::File(ref chosen) if chosen == path),
                "{path} must be a file, got {:?}",
                options.source
            );
        }
    }

    /// An explicit `--` still ends flag parsing, and `inspect` after it is
    /// subject to the same rule.
    ///
    /// `node -- inspect` is the debugger client in Node, because `--` ends the
    /// options and the next word is the entry point.
    #[test]
    fn inspect_after_a_terminator_is_the_subcommand() {
        let options = parse_of(&["--", "inspect", "--help"]).expect("parses");
        assert!(
            matches!(options.source, Source::Inspect),
            "{:?}",
            options.source
        );
        assert_eq!(options.script_args, ["--help"]);
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

    /// A bare pipe runs stdin; a terminal starts the REPL.
    ///
    /// This is Node's dispatch at `src/node.cc:403-409`: no positional means
    /// `force_repl || uv_guess_handle(STDIN_FILENO) == UV_TTY` decides between
    /// `internal/main/repl` and `internal/main/eval_stdin`. Before this, both
    /// cases fell through to the empty program, which evaluated `"0"` and
    /// exited 0 while printing nothing — a silent success for a script that
    /// never ran.
    #[test]
    fn no_argument_reads_stdin_only_when_it_is_not_a_terminal() {
        let options = parse_with_env(&[], None, StdinKind::Redirected).expect("parses");
        assert!(matches!(options.source, Source::Stdin { marker: false }));
        assert!(options.script_args.is_empty());

        let options = parse_with_env(&[], None, StdinKind::Terminal).expect("parses");
        assert!(matches!(options.source, Source::Repl));
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

    /// `--version` and `--help` are options, not errors, and every spelling of
    /// them works.
    #[test]
    fn version_and_help_are_accepted() {
        for argument in ["--version", "-v"] {
            let options = parse_of(&[argument]).expect("parses");
            assert!(options.print_version, "{argument}");
            assert!(!options.print_help, "{argument}");
        }
        for argument in ["--help", "-h"] {
            let options = parse_of(&[argument]).expect("parses");
            assert!(options.print_help, "{argument}");
            assert!(!options.print_version, "{argument}");
            assert!(matches!(options.source, Source::Help));
        }
    }

    /// The `=value` form of a boolean flag is accepted and the value ignored.
    #[test]
    fn a_boolean_flag_ignores_an_inline_value() {
        let options = parse_of(&["--version=1"]).expect("parses");
        assert!(options.print_version);
        // A short flag with a value glued on is not `-v`: `Parse` only splits on
        // `=` for an argument starting with two dashes, so `-v=1` stays an
        // ordinary unknown flag and V8 is what rejects it as `bad option`.
        let options = parse_of(&["-v=1"]).expect("reaches the V8 queue");
        assert!(!options.print_version);
        assert_eq!(options.v8_args, ["-v=1"]);
    }

    /// `--no-version` clears what an earlier argument set, and runs nothing.
    #[test]
    fn the_negated_spellings_clear_the_request() {
        let options = parse_of(&["--version", "--no-version"]).expect("parses");
        assert!(!options.print_version);

        let options = parse_of(&["--help", "--no-help"]).expect("parses");
        assert!(!options.print_help);
        // With the request cleared there is no script and no flag left, so a
        // terminal means the REPL.
        assert!(matches!(options.source, Source::Repl));
    }

    /// A rejected flag still wins over `--version`, which is the ordering
    /// `node --version --not-a-real-flag` shows: `bad option` and exit 9.
    #[test]
    fn a_v8_flag_still_reaches_v8_when_version_was_asked_for() {
        let options = parse_of(&["--version", "--not-a-real-flag"]).expect("parses");
        assert!(options.print_version);
        assert_eq!(options.v8_args, ["--not-a-real-flag"]);
    }

    /// `--help` wins over `-e`: Node checks it first at `src/node.cc:371`,
    /// before the `has_eval_string` branch at `:380`.
    #[test]
    fn help_wins_over_an_eval_string() {
        let options = parse_of(&["-e", "console.log(1)", "--help"]).expect("parses");
        assert!(matches!(options.source, Source::Help));
        assert!(!options.print_version);
    }

    /// The last `--eval` wins while `--print` stands, because Node records them
    /// as two independent option fields (`eval_string`, `print_eval`). Both are
    /// read back by `internal/main/eval_string` from the option store, so the
    /// store is where the pair is asserted.
    #[test]
    fn print_and_eval_compose_as_two_option_fields() {
        let options = parse_of(&["-e", "1", "-p", "2"]).expect("parses");
        assert!(matches!(options.source, Source::Eval));
        assert_eq!(
            options.parsed.value_of("--eval"),
            Some(rn_bind_options::parsed::ParsedValue::Text("2".to_string())),
            "the last --eval is the code eval_string runs"
        );
        assert_eq!(
            options.parsed.value_of("--print"),
            Some(rn_bind_options::parsed::ParsedValue::Bool(true)),
            "the earlier -p still asks for the result to be printed"
        );

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
        assert!(!options.inspect_break_node);
        assert_eq!(options.debug_port.port, 9339);
        assert_eq!(options.debug_port.host, "0.0.0.0");
    }

    #[test]
    fn inspect_brk_also_waits_for_a_client() {
        let options = parse_of(&["--inspect-brk=9339"]).expect("parses");
        assert!(options.inspect_enabled);
        assert!(options.inspect_wait);
        assert!(!options.inspect_break_node);
        assert_eq!(options.debug_port.port, 9339);
    }

    #[test]
    fn inspect_brk_node_marks_a_bootstrap_break() {
        let options = parse_of(&["--inspect-brk-node=9339"]).expect("parses");
        assert!(options.inspect_enabled);
        assert!(options.inspect_wait);
        assert!(options.inspect_break_node);
        assert_eq!(options.debug_port.port, 9339);
    }

    /// `--inspect-wait` waits for a client but arms no break-on-start.
    ///
    /// Node's `DebugOptions` sets `wait_for_connect()` for `--inspect-wait` and
    /// leaves `break_node_first_line` false, so `WaitForConnectByOptions` blocks
    /// and then runs user code without pausing. The oracle shows the difference:
    /// `node --inspect-wait=0 -e "..."` prints only the listening banner and never
    /// the script's output until a client connects. Treating the flag as plain
    /// `--inspect` made rustnode run the script immediately.
    #[test]
    fn inspect_wait_waits_without_breaking() {
        let options = parse_of(&["--inspect-wait=9339"]).expect("parses");
        assert!(options.inspect_enabled);
        assert!(options.inspect_wait);
        assert!(!options.inspect_break_node);
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

    #[test]
    fn tls_cli_flags_from_the_node_option_table_are_accepted() {
        let options = parse_of(&[
            "--tls-min-v1.0",
            "--tls-max-v1.2",
            "--tls-keylog=/tmp/keylog.log",
            "--no-use-system-ca",
            "--no-use-openssl-ca",
            "--use-bundled-ca",
        ])
        .expect("parses");

        assert!(options
            .exec_argv
            .iter()
            .any(|flag| flag == "--tls-min-v1.0"));
        assert!(options
            .exec_argv
            .iter()
            .any(|flag| flag == "--tls-max-v1.2"));
        assert!(options
            .exec_argv
            .iter()
            .any(|flag| flag == "--tls-keylog=/tmp/keylog.log"));
        assert!(options
            .exec_argv
            .iter()
            .any(|flag| flag == "--no-use-system-ca"));
        assert!(options
            .exec_argv
            .iter()
            .any(|flag| flag == "--no-use-openssl-ca"));
        assert!(options
            .exec_argv
            .iter()
            .any(|flag| flag == "--use-bundled-ca"));

        assert_eq!(
            options.parsed.value_of("--tls-min-v1.0"),
            Some(rn_bind_options::ParsedValue::Bool(true))
        );
        assert_eq!(
            options.parsed.value_of("--tls-max-v1.2"),
            Some(rn_bind_options::ParsedValue::Bool(true))
        );
        assert_eq!(
            options.parsed.value_of("--tls-keylog"),
            Some(rn_bind_options::ParsedValue::Text(
                "/tmp/keylog.log".to_string()
            ))
        );
        assert_eq!(
            options.parsed.value_of("--use-system-ca"),
            Some(rn_bind_options::ParsedValue::Bool(false))
        );
        assert_eq!(
            options.parsed.value_of("--use-openssl-ca"),
            Some(rn_bind_options::ParsedValue::Bool(false))
        );
        assert_eq!(
            options.parsed.value_of("--use-bundled-ca"),
            Some(rn_bind_options::ParsedValue::Bool(true))
        );
    }
}

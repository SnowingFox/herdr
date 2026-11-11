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

/// What the command line asked for.
#[derive(Debug, Default)]
pub struct Options {
    /// `-e`/`--eval`, `-p`/`--print`, or a script path.
    pub source: Source,
    /// Arguments after the script, exposed as `process.argv`.
    pub script_args: Vec<String>,
    /// Every flag seen, in order, for `process.execArgv`.
    pub exec_argv: Vec<String>,
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
    /// The inspector endpoint `--inspect` asked for, if any.
    ///
    /// `Some` starts the server before user code runs, which is what makes
    /// `node --inspect` print its `ws://` URL and accept a client. `None` leaves the
    /// inspector off, which is the default for the same reason it is in Node: a
    /// listening debug port is an attack surface.
    pub inspect: Option<InspectRequest>,
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
}

impl Options {
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
    /// Parses the value of `--inspect`, `--inspect-brk` or `--inspect-port`.
    ///
    /// Node accepts `[host:]port` in every spelling, and a bare flag with no value
    /// (which the parser turns into `None` here). A host containing a colon is
    /// bracketed, so `--inspect=[::1]:9229` splits on the *last* colon rather than the
    /// first.
    ///
    /// Returns `Err` for a port that is not a number or does not fit in 16 bits,
    /// because Node rejects those at startup rather than silently using 9229.
    pub fn parse(value: Option<&str>, wait: bool) -> Result<Self, String> {
        let Some(value) = value.filter(|value| !value.is_empty()) else {
            return Ok(Self {
                port: 9229,
                host: "127.0.0.1".to_string(),
                wait,
            });
        };
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => (host.trim_start_matches('[').trim_end_matches(']'), port),
            None => ("127.0.0.1", value),
        };
        let port: u16 = port
            .parse()
            .map_err(|_| format!("--inspect: '{value}' is not a valid port"))?;
        Ok(Self {
            port,
            host: if host.is_empty() { "127.0.0.1" } else { host }.to_string(),
            wait,
        })
    }
}

/// Where the code to run comes from.
#[derive(Debug, Default)]
pub enum Source {
    /// Nothing to run: behaves like `-e ''`.
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
}

/// Flags that take no separate value and that rustnode deliberately ignores.
///
/// These change Node's behaviour in ways that do not affect whether a script
/// runs: warning categories, source maps, gc exposure. A script that only needs
/// them accepted should run.
///
/// The `--allow-*` permission grants are deliberately *not* here. They carry
/// values, they change what the runtime permits, and accepting them without
/// acting on them was the bug this list used to hide.
const IGNORED_WITHOUT_VALUE: &[&str] = &[
    "--abort-on-uncaught-exception",
    "--allow-natives-syntax",
    "--disable-proto",
    "--enable-source-maps",
    "--expose-gc",
    "--expose-internals",
    "--expose_internals",
    "--expose_gc",
    "--experimental-shadow-realm",
    "--experimental-strip-types",
    "--experimental-vm-modules",
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
    "--max-old-space-size=",
    "--permission=",
    "--stack-size=",
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
/// `--permission` was the fourth. It has now left the list too: `fs.read`,
/// `fs.write`, `child`, `env`, `net` and `addon` are all enforced, which is the
/// set this build has a surface for. `worker` is still unenforced but gated on
/// the unmerged worker_threads branch, `inspector` has its own change open, and
/// `wasi`, `ffi` and `openssl.store` have no implementation to gate at all —
/// `new WASI()` already fails on the missing `wasi` binding rather than on a
/// permission, so a permission warning over it would name the wrong cause.
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
/// be reported as unimplemented, because `lib/**` now acts on them: each is read
/// back through `internalBinding('options')` by the vendored JavaScript.
const IMPLEMENTED_EXPERIMENTAL: &[&str] = &["--experimental-bench", "--experimental-stream-iter"];

/// Parses the command line, or returns the message to print on a bad flag.
pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut unimplemented = BTreeSet::new();
    let mut index = 0;

    while index < args.len() {
        let argument = &args[index];

        if argument == "-e" || argument == "--eval" || argument == "-p" || argument == "--print" {
            let Some(code) = args.get(index + 1) else {
                return Err(format!("{argument} requires an argument"));
            };
            options.source = Source::Eval {
                code: code.clone(),
                print: argument == "-p" || argument == "--print",
            };
            // Node keeps `-e`/`-p` out of the *flags* it inherits, but it does
            // put the flag and its source in `process.execArgv`, because a child
            // process re-running the parent has to reproduce the same entry
            // point. Only the leading `node` and the script path are absent.
            options.exec_argv.push(argument.clone());
            options.exec_argv.push(code.clone());
            // Arguments after the source belong to the evaluated code, with an
            // explicit `--` acting only as a separator (`node -e 'x' -- a`
            // gives `['a']`, the same as `node -e 'x' a`).
            index += 2;
            if args.get(index).map(String::as_str) == Some("--") {
                index += 1;
            }
            options.script_args = args[index..].to_vec();
            return Ok(finish(options, unimplemented));
        }

        // `--` ends flag parsing; everything after is the script and its args.
        if argument == "--" {
            index += 1;
            if let Some(script) = args.get(index) {
                options.source = Source::File(script.clone());
                options.script_args = args[index + 1..].to_vec();
            }
            return Ok(finish(options, unimplemented));
        }

        // A script path is the first non-flag argument; the rest belong to it.
        if !argument.starts_with('-') {
            options.source = Source::File(argument.clone());
            options.script_args = args[index + 1..].to_vec();
            return Ok(finish(options, unimplemented));
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

        // A permission grant whose value is a separate argument. Node accepts
        // both spellings and its own tests use both, so the value is taken here
        // and recorded in the joined form `exec_argv` uses everywhere else.
        // This is checked before the generic permission branch below, because
        // `--allow-fs-read` alone would otherwise be accepted as a bare boolean
        // and its value treated as the script path.
        if PERMISSION_VALUE_FLAGS.contains(&argument.as_str()) {
            let Some(value) = args.get(index + 1) else {
                return Err(format!("{argument} requires an argument"));
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
                return Err(format!("{argument} requires an argument"));
            };
            options.exec_argv.push(format!("{argument}={value}"));
            index += 2;
            continue;
        }

        if argument.starts_with("--experimental-") || argument.starts_with("--no-experimental-") {
            // The experimental surface is broad and most of it gates modules
            // that have not landed. Record and accept, so a script that merely
            // mentions one still boots.
            //
            // `--experimental-bench` is the exception: it is implemented, so
            // reporting it missing would be a lie that some tests read. The
            // other flags stay in `unimplemented` and say so.
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
        if let Some(request) = parse_inspect_flag(argument) {
            match request {
                Ok(request) => {
                    options.inspect = Some(request);
                    options.exec_argv.push(argument.clone());
                    index += 1;
                    continue;
                }
                Err(message) => return Err(message),
            }
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

        // `-v`, `--version` and `--help` are handled before parsing.
        return Err(format!("unsupported option '{argument}'"));
    }

    Ok(finish(options, unimplemented))
}

/// Parses one `--inspect*` argument, or `None` when it is not one.
///
/// `--inspect-port` sets the port without starting the server in Node, and is
/// accepted here for the same reason: `lib/internal/bench_runner/cli.js` checks
/// `process.debugPort` and passes it on to a child, so a runner that rejects the flag
/// cannot spawn anything.
fn parse_inspect_flag(argument: &str) -> Option<Result<InspectRequest, String>> {
    let (name, value) = match argument.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (argument, None),
    };
    match name {
        "--inspect" | "--inspect-port" => Some(InspectRequest::parse(value, false)),
        "--inspect-brk" => Some(InspectRequest::parse(value, true)),
        _ => None,
    }
}

fn finish(mut options: Options, unimplemented: BTreeSet<String>) -> Options {
    options.unimplemented = unimplemented.into_iter().collect();
    // The options binding's own parser, fed the flags this CLI accepted. It is
    // a second pass over the same argv by design: this parser decides *what
    // rustnode does*, and `rn-bind-options` decides *what Node's option layer
    // reports*, so one implementation cannot quietly become the authority for
    // both. The flags only — never the script path or its arguments, which
    // Node's parser stops at too.
    options.parsed = rn_bind_options::Store::parse(&options.exec_argv);
    // `Environment::InitializePermission` clears `allow_native_addons` when
    // `--permission` (not `--permission-audit`) was given without
    // `--allow-addons`, which is what makes `process.dlopen` throw
    // `ERR_DLOPEN_DISABLED` before the permission check runs. The flag is
    // published as `--addons`, so the derived value goes into the same store
    // `getOptionValue('--addons')` reads. Audit mode deliberately keeps addons
    // enabled so the `addon` check can publish the denial instead.
    if config_wants_addons_disabled(&options.exec_argv) {
        options
            .parsed
            .force("--addons", rn_bind_options::parsed::ParsedValue::Bool(false));
    }
    // The permission model is the one thing this parser builds rather than
    // describes: `PermissionConfig::from_args` already reads these flags in both
    // spellings and owns the 68 tests that pin its grammar, so routing through
    // it keeps one interpretation of `--allow-fs-read=*` rather than two.
    let mut config = rn_permission::PermissionConfig::from_args(&options.exec_argv);
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
    // them before `lib/**` runs either.
    for entry in &options.exec_argv {
        if let Some(preload) = entry.strip_prefix("--require=") {
            config.allow_fs_read.push(preload.to_string());
        }
    }
    options.permission_config = config.clone();
    options.permission = std::sync::Arc::new(rn_permission::PermissionModel::with_cwd(
        current_dir(),
        config,
    ));
    options
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
        match argument.split_once('=').map_or(argument.as_str(), |(name, _)| name) {
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

    fn parse_of(args: &[&str]) -> Result<Options, String> {
        let owned: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
        parse(&owned)
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
        assert!(options.unimplemented.is_empty(), "{:?}", options.unimplemented);
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
    fn an_unknown_flag_is_an_error() {
        // A typo must not silently change nothing.
        assert!(parse_of(&["--not-a-real-flag", "app.js"]).is_err());
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

    #[test]
    fn a_script_path_is_not_in_exec_argv() {
        let options = parse_of(&["--no-warnings", "app.js", "arg"]).expect("parses");
        assert_eq!(options.exec_argv, ["--no-warnings"]);
        assert_eq!(options.script_args, ["arg"]);
    }
}

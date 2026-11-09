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
/// runs: warning categories, source maps, gc exposure, permission grants. A
/// script that only needs them accepted should run.
const IGNORED_WITHOUT_VALUE: &[&str] = &[
    "--abort-on-uncaught-exception",
    "--allow-child-process",
    "--allow-fs-read",
    "--allow-fs-write",
    "--allow-natives-syntax",
    "--allow-worker",
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
const VALUE_INLINE_PREFIXES: &[&str] = &[
    "--allow-child-process=",
    "--allow-env=",
    "--allow-fs-read=",
    "--allow-fs-write=",
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

/// Flags that enable an experimental surface rustnode has not built yet.
///
/// Accepting them silently would make a test look like it exercised the feature
/// when it did not, so they are recorded in [`Options::unimplemented`].
const UNIMPLEMENTED: &[&str] = &[
    "--allow-natives-syntax",
    "--experimental-bench",
    "--experimental-network-inspection",
    "--experimental-shadow-realm",
    "--experimental-stream-iter",
    "--experimental-vm-modules",
    "--experimental-web-worker",
    "--js-source-phase-imports",
    "--permission",
];

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
            // Node keeps `-e`/`-p` out of `process.execArgv`: the flag selects
            // the entry point, it is not part of the runtime configuration a
            // child process would inherit.
            index += 2;
            continue;
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
            unimplemented.insert(argument.clone());
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
                || argument.starts_with("--permission=")
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

fn finish(mut options: Options, unimplemented: BTreeSet<String>) -> Options {
    options.unimplemented = unimplemented.into_iter().collect();
    options
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
        assert_eq!(options.exec_argv, ["--require=preload.js"]);
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
}

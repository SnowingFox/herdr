mod args;

use rn_bindings::install_all;
use rn_core::Env;
use rn_realm as bootstrap;
use rn_v8_sys::v8;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    if let Err(message) = rn_v8_sys::check_linked_v8() {
        eprintln!("rustnode: {message}");
        std::process::exit(1);
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    // Flags that V8 owns are handed to it before initialization, the way Node's
    // `V8::Initialize` path does. `--max-old-space-size` is the one observable
    // through `v8.getHeapStatistics().heap_size_limit`, so ignoring it made that
    // field a fixed 1.5 GB no matter what the command line said.
    forward_v8_flags(&args);

    // The command line is parsed before anything is built, because the
    // permission model it produces has to exist before the binding registry
    // does: `rn_permission::register` installs `internalBinding('permission')`
    // around whatever model is already there, and the `fs`, `child_process` and
    // `worker` checks read the same one. Parsing later would leave the binding
    // holding a disabled model while the CLI held an enforcing one.
    let options = match args::parse(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("rustnode: {message}");
            std::process::exit(9);
        }
    };
    // A flag whose feature has not landed must not pass silently, or a test
    // that needed it looks like it exercised something it did not.
    for flag in &options.unimplemented {
        eprintln!("rustnode: warning: {flag} is accepted but not implemented");
    }
    rn_permission::runtime::install_shared(options.permission.clone());

    // `--allow-env` is enforced by removing everything it does not grant, not by
    // checking a read later: the environment block is read directly by every C
    // library and inherited by every child process, so there is no call to hook.
    // That has to happen before V8 is initialised, because the platform thread
    // pool starts there and the scrub is not synchronised with `getenv()`.
    //
    // A malformed pattern is a startup error, which is what Node's option
    // validation does (`--allow-env must be '*', a variable name, or a variable
    // name prefix followed by '*'`), and it exits with 9 like every other
    // rejected flag.
    let allow_env = rn_permission::env::parse_allow_list(&options.permission_config.allow_env);
    if options.permission_config.enabled {
        if allow_env
            .iter()
            .any(|pattern| !rn_permission::env::is_valid_pattern(pattern))
        {
            eprintln!(
                "rustnode: --allow-env must be '*', a variable name, or a \
                 variable name prefix followed by '*'"
            );
            std::process::exit(9);
        }
        if options.permission_config.audit {
            let denied = rn_permission::env::record_audited(&allow_env);
            options.permission.record_removed_env_vars(denied);
        } else {
            let removed = rn_permission::env::scrub(&allow_env);
            options.permission.record_removed_env_vars(removed);
        }
    }

    let mut env = Env::new();
    let mut registry = rn_core::BindingRegistry::new();
    install_all(&mut registry);
    for namespace in registry.namespaces() {
        env.insert(namespace.clone());
    }
    // A worker thread runs a second isolate and needs a registry of its own: the
    // object each namespace caches is a V8 handle belonging to one isolate, so
    // sharing this one would hand the worker foreign handles. `rn-bindings` is
    // the crate that knows how to assemble a registry and it depends on the
    // worker crate, so the factory is handed over here rather than called from
    // there.
    rn_core::realm::set_registry_factory(|| {
        let mut registry = rn_core::BindingRegistry::new();
        install_all(&mut registry);
        registry
    });
    // `internalBinding` resolves through whatever registry the *thread* has
    // installed, so the main thread's has to be installed rather than leaked:
    // a leaked `&'static` could not be replaced when this thread later ran a
    // worker's own realm.
    // Held for the whole of `main`: dropping the guard would uninstall the
    // registry, and every `internalBinding` call after that would fail.
    let _realm_registry = rn_core::realm::install(registry);

    // `v8.setFlagsFromString()` is a public API — `lib/v8.js` exports it — and
    // V8 refuses to honour it once `PrepareForSnapshotSerialization` has frozen
    // the flag list, which happens during `V8::Initialize`. Node disables the
    // freeze before initializing for exactly this reason, so a flag set from
    // JavaScript keeps working instead of crashing inside V8's `CHECK`.
    v8::V8::set_flags_from_string("--no-freeze-flags-after-init");

    let args: Vec<String> = std::env::args().skip(1).collect();
    // Flags that V8 owns are handed to it before initialization, the way Node's
    // `V8::Initialize` path does. `--max-old-space-size` is the one observable
    // through `v8.getHeapStatistics().heap_size_limit`, so ignoring it made that
    // field a fixed 1.5 GB no matter what the command line said.
    forward_v8_flags(&args);

    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    // `import.meta` and `import()` are dispatched by V8 through isolate-level
    // handlers rather than `internalBinding()`, so they are installed here,
    // where a `&mut Isolate` exists. A binding callback cannot do it: the v8
    // crate documents `FunctionCallbackArguments::get_isolate` as unsound while
    // a callback scope is open, and one always is during a binding call.
    rn_module_wrap::install_isolate_callbacks(&mut isolate);
    // `v8.writeHeapSnapshot` needs `take_heap_snapshot`, an `Isolate` method,
    // and a binding callback cannot obtain a `&mut Isolate` soundly. Recording
    // the isolate here is the same arrangement the ESM handlers use.
    rn_bind_heap_utils::set_snapshot_isolate(&mut isolate);
    // `V8Inspector::create` and V8's client callbacks need `&mut Isolate`, which a
    // binding cannot obtain soundly, so the inspector records the isolate here the
    // same way `heap_utils` does for heap snapshots.
    rn_bind_inspector::set_isolate(&mut isolate);
    // Node runs V8 with an explicit microtask policy: the embedder decides when
    // the queue drains, through `runMicrotasks()` in
    // `lib/internal/process/task_queues.js` and the loop's own checkpoints.
    // V8's default `Auto` policy drains whenever a script's call depth drops to
    // zero, which would run promise callbacks *before* the tick queue and make
    // `process.nextTick` lose to a `.then` — Node guarantees the opposite.
    isolate.set_microtasks_policy(v8::MicrotasksPolicy::Explicit);
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    // `lib/**` reads option values through `internalBinding('options')`, and
    // that binding can only report them if it is told what the command line
    // said. Installing before the realm bootstrap matters: `realm.js` builds
    // the builtin allow-list from `--experimental-bench` during its own load,
    // so a value installed later would arrive after the decision was made.
    // `--strip-types` is recorded with `default: true` because Node 28 ships
    // amaro, and that is the flag `internal/process/execution.js` keys the
    // TypeScript path off. This build vendors no amaro, so leaving the default
    // makes the first `eval` script take a path that throws
    // `ERR_NO_TYPESCRIPT` — which is how a worker's `console.log` turned into a
    // process-killing failure. Reporting the capability this binary has is the
    // same rule `config.hasInspector` follows.
    let mut parsed = options.parsed.clone();
    parsed.set(
        "--strip-types",
        rn_bind_options::parsed::ParsedValue::Bool(false),
    );
    rn_bind_options::parsed::install(parsed);

    // The inspector is created before the console is installed, because V8 puts its
    // own `console` on the per-context extras object during `contextCreated`, and
    // `internal/util/inspector.js`'s `wrapConsole` reads it from the binding at that
    // point. Creating it later leaves the global console unwrapped and a debugger
    // never sees a `console.log`.
    //
    // `process.features.inspector` and `config.hasInspector` are true, so `lib/**`
    // loads `internal/inspector_async_hook` and `internalBinding('profiler')`; both
    // exist, which is what makes those flags honest.
    rn_bind_inspector::ensure_inspector(scope);

    // `--inspect` opens the endpoint before anything else runs, and prints the URL the
    // way Node does. `--inspect-brk` additionally blocks until a client attaches, which
    // is what makes the first line of user code the first line a debugger sees.
    if let Some(request) = options.inspect.as_ref() {
        match rn_bind_inspector::start_server(request.host.as_str(), request.port) {
            Ok(url) => {
                eprintln!("Debugger listening on {url}");
                eprintln!("For help, see: https://nodejs.org/learn/getting-started/debugging");
                if request.wait && !rn_bind_inspector::wait_for_client() {
                    eprintln!("rustnode: --inspect-brk found no client; running without waiting");
                }
            }
            Err(message) => {
                eprintln!("rustnode: {message}");
                std::process::exit(9);
            }
        }
    }

    if let Err(message) = bootstrap::install_globals(scope, &args) {
        eprintln!("rustnode: {message}");
        std::process::exit(1);
    }

    // `process.argv` is `[execPath, scriptPath?, ...scriptArgs]`. Node puts the
    // resolved script path in `argv[1]` and omits that slot for `-e`/`-p`, where
    // the arguments follow the executable directly. Resolving it here, rather
    // than in the parser, keeps `Options` a faithful record of what was typed
    // while `argv` matches what Node reports for the same command line.
    let mut argv_rest: Vec<String> = Vec::new();
    let mut script_path = None;
    if let args::Source::File(path) = &options.source {
        let resolved = std::path::absolute(path)
            .map(|resolved| resolved.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.clone());
        argv_rest.push(resolved.clone());
        script_path = Some(resolved);
    }
    argv_rest.extend(options.script_args.iter().cloned());

    // Node's own bootstrap defines `internalBinding` and `require`. When it fails
    // the CLI still runs, because `-e` on a bare global is useful for debugging
    // the bootstrap itself; the reason is printed so a failure is never silent.
    let mut runtime = None;
    let mut realm_require: Option<v8::Global<v8::Function>> = None;
    match bootstrap::bootstrap_realm(scope, &argv_rest, &options.exec_argv) {
        Ok(mut loaders) => {
            if options.expose_internals() {
                bootstrap::expose_internals(scope, &loaders);
            }
            // The internal loader needs the `node:` scheme stripped before it
            // can resolve a specifier; Node's user-land loader does that, and
            // this stands in for it until `contextify` unblocks the real one.
            bootstrap::wrap_require_with_scheme_support(scope, &loaders);
            bootstrap::install_early_globals(scope, &loaders);
            // The CommonJS loader turns `require` from a builtin lookup into a
            // real module loader, which is what makes `require('./file.js')`
            // work. It is the vendored `lib/internal/modules/cjs/loader.js`,
            // not a Rust reimplementation: resolution order, the cache, the
            // `node_modules` walk and `package.json` `exports` are all already
            // correct there.
            if let Some(require) = loaders.require.as_ref() {
                let require = v8::Local::new(scope, require);
                if let Err(message) = bootstrap::install_cjs_loader(scope, require, &script_path) {
                    // A failure is reported rather than fatal, for the same
                    // reason the bootstrap itself is: a script using only
                    // builtins still runs, and saying why file requires do not
                    // work is more useful than refusing to start.
                    eprintln!("rustnode: commonjs loader unavailable: {message}");
                }
            }
            // The loop's JavaScript half is installed before the script runs,
            // because a script may call `setTimeout` on its first line. A
            // failure here is reported rather than fatal: a synchronous script
            // still runs, and saying why timers will not fire is more useful
            // than refusing to start.
            match loaders.require.as_ref() {
                Some(require) => {
                    let require = v8::Local::new(scope, require);
                    match rn_realm::Runtime::install(scope, require) {
                        Ok(hooks) => {
                            // Worker exits are reported from the check phase, and
                            // the hook is additive because the crate that owns
                            // the handle (`rn-bind-timers`) must not depend on the
                            // worker crate or vice versa.
                            rn_bind_worker::install_check_phase();
                            runtime = Some(hooks);
                        }
                        Err(message) => eprintln!("rustnode: timers unavailable: {message}"),
                    }
                    // Node's `internal/main/run_main_module` runs pre-execution
                    // before it runs anything else, and the ESM loader refuses
                    // to initialize afterwards: `initializeModuleLoaders`
                    // asserts that no user module has been executed yet. Every
                    // `.mjs` entry point therefore failed with
                    // `ERR_INTERNAL_ASSERTION` until this ran first.
                    bootstrap::install_stdio(scope);
                    // After stdio: the real console binds to `process.stdout`
                    // lazily, and it must reach the same write queue rather than
                    // a second descriptor. See `install_console`.
                    bootstrap::install_console(scope, require);
                    bootstrap::prepare_execution(scope, require);
                    // `node -e` exposes builtins as lazy globals; a script file
                    // does not, which is why this is gated on the source. Node's
                    // own `eval_string.js` makes the same distinction.
                    if matches!(options.source, args::Source::Eval { .. }) {
                        if let Err(message) = rn_realm::install_eval_builtins(scope, require) {
                            eprintln!("rustnode: builtin globals unavailable: {message}");
                        }
                    }
                }
                None => {
                    eprintln!("rustnode: timers unavailable: the realm bootstrap left no require")
                }
            }
            let _ = loaders.internal_binding;
            // Taken last: every step above reads `loaders.require`, and taking it
            // first left `install_early_globals` without a loader, which silently
            // dropped the `Buffer` global.
            realm_require = loaders.require.take();
        }
        Err(message) => eprintln!("rustnode: realm bootstrap failed: {message}"),
    }

    // `src/node.cc::StartExecution` opens an `InternalCallbackScope` with
    // `{ 1, 0 }` and `kSkipAsyncHooks` around everything it runs, so the async
    // id every top-level resource inherits as its trigger is 1. Without it the
    // buffers keep the `clear_async_id_stack` seed and every resource reports
    // `triggerAsyncId() === -1`. See `push_top_level_context`.
    rn_bind_async_wrap::push_top_level_context(scope);

    // A file is loaded through Node's own entry-point path
    // (`internal/modules/run_main.js::executeUserEntryPoint`), which picks the
    // CommonJS or ESM loader from the file's format — `.mjs`, `.wasm`, or a
    // `.js` in a `"type": "module"` package take the ESM path. `-e` has no
    // file, so it is compiled as a bare script against the global object.
    //
    // The file's text is deliberately not read here: the loader reads it, and a
    // second read would bypass the loader's source handling (and its cache).
    let mut print_result = false;
    let mut entry_promise: Option<v8::Global<v8::Promise>> = None;
    let (value, caught) = match &options.source {
        args::Source::File(_) => {
            // The resolved absolute path, not the raw argument: the loader
            // treats its request as a specifier, so a relative one would be
            // resolved against the loader's paths instead of the cwd.
            let caught = match (realm_require.as_ref(), script_path.as_ref()) {
                (Some(require), Some(path)) => {
                    let require = v8::Local::new(scope, require);
                    // A top-level await makes the entry point asynchronous: the
                    // call returns the graph's promise and the module body
                    // finishes during the microtask drain below, not before it.
                    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
                    let scope = &mut try_catch.init();
                    let result = bootstrap::run_main(scope, require, path);
                    if scope.has_caught() {
                        scope.exception().map(|exception| {
                            format!("Uncaught {}", exception.to_rust_string_lossy(scope))
                        })
                    } else {
                        if let Some(promise) =
                            result.and_then(|value| v8::Local::<v8::Promise>::try_from(value).ok())
                        {
                            entry_promise = Some(v8::Global::new(scope, promise));
                        }
                        None
                    }
                }
                _ => Some("Uncaught the realm bootstrap left no require".to_string()),
            };
            (None, caught)
        }
        args::Source::Eval { code, print } => {
            print_result = *print;
            evaluate_script(scope, code)
        }
        args::Source::Empty => evaluate_script(scope, "0"),
    };

    if let Some(message) = caught {
        eprintln!("{message}");
        // The status is 1 and `exit` still has to run: Node reports an uncaught
        // throw through `process._fatalException`, which overwrites
        // `process.exitCode` with `kGenericUserError` and emits `exit`. Skipping
        // the emit made `process.on('exit', ...)` fire for every kind of exit
        // except the most common failure a script has.
        let code = event_loop::emit_exit_after_failure(scope);
        std::process::exit(if code == 0 { 1 } else { code });
    }

    if print_result {
        if let Some(value) = value {
            println!("{}", value.to_rust_string_lossy(scope));
        }
    }

    // The script body has run. Everything it queued — timers, immediates, ticks,
    // promise callbacks — is what the loop exists for, so it starts here rather
    // than letting the process exit with that work still pending.
    //
    // The first drain happens before the first phase: Node runs the script and
    // then checks the microtask queue, which is why a `.then` scheduled in the
    // script body runs before the process exits and before any timer.
    //
    // A `.mjs` entry point with a top-level `await` is the one case where the
    // script has *not* finished when the loader returns: it handed back the
    // module graph's promise. Draining the microtask queue is what finishes it,
    // and it must happen before the timers in the loop below so a top-level
    // await resolves before `setTimeout(0)` — the order Node guarantees.
    let mut exit_requested = false;
    if let Some(hooks) = runtime.as_ref() {
        hooks.drain(scope);
        // A rejection here is the module body throwing, which Node reports as an
        // uncaught exception from the entry point. `triggerUncaughtException`
        // already ran if the loader routed it through the fatal path; this
        // catches the case where the promise simply settled rejected.
        if let Some(entry) = entry_promise.take() {
            let entry = v8::Local::new(scope, entry);
            if entry.state() == v8::PromiseState::Rejected {
                let exception = entry.result(scope);
                eprintln!("Uncaught {}", exception.to_rust_string_lossy(scope));
                hooks.drain(scope);
                std::process::exit(1);
            }
        }
        match rn_realm::run_loop(scope, hooks) {
            Ok(rn_io::StopReason::ExitRequested | rn_io::StopReason::TurnLimit) => {
                exit_requested = true;
            }
            Ok(rn_io::StopReason::Idle) => {}
            Err(message) => eprintln!("rustnode: the event loop could not start: {message}"),
        }
        // A microtask queued by the last callback in the last turn still has to
        // run, and Node drains once more before exiting.
        hooks.drain(scope);
    }

    // The loop has settled, so the process is at the point Node calls
    // `EmitProcessExitInternal` from. `beforeExit` has already been offered the
    // final idle by the loop itself, so what is left is `exit` and termination.
    //
    // Nothing ran this before, which is why a natural exit printed nothing from
    // a `process.on('exit', ...)` handler while an explicit `process.exit()`
    // did: that path reaches `per_thread.js`'s wrapper, and this one went
    // straight to `std::process::exit`.
    //
    // A process that is already exiting — an explicit `process.exit()` that
    // returned because user code replaced `reallyExit`, or a fatal path that
    // emitted `exit` itself — is left alone and keeps the status it settled on.
    let code = match runtime.as_ref() {
        Some(_) => event_loop::emit_exit(scope, 0),
        None => bootstrap::read_exit_code(scope).unwrap_or(0),
    };

    // An uncaught exception asks for 1 unless the exit handlers replaced that
    // with a code of their own, which is the order Node applies.
    if exit_requested || rn_core::hook_slot::flag(rn_core::hook_slot::EXIT_REQUESTED) {
        std::process::exit(if code == 0 { 1 } else { code });
    }
    std::process::exit(code);
}

/// Compiles and runs `source` as a bare script and reports the result.
///
/// This is the `-e`/`-p` path, which Node also evaluates as a top-level script
/// rather than as a CommonJS module. The returned pair is the script's completion
/// value (for `-p`) and the `Uncaught ...` message when the script threw.
fn evaluate_script<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &str,
) -> (Option<v8::Local<'s, v8::Value>>, Option<String>) {
    let Some(name) = v8::String::new(scope, "evalmachine.<anonymous>") else {
        eprintln!("rustnode: cannot allocate script name");
        std::process::exit(1);
    };
    let origin = v8::ScriptOrigin::new(
        scope,
        name.into(),
        0,
        0,
        false,
        0,
        None,
        false,
        false,
        false,
        None,
    );
    let Some(code) = v8::String::new(scope, source) else {
        eprintln!("rustnode: input contains invalid UTF-8");
        std::process::exit(1);
    };
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let value =
        v8::Script::compile(scope, code, Some(&origin)).and_then(|script| script.run(scope));
    let caught = if scope.has_caught() {
        scope.exception().map(|exception| {
            let text = exception.to_rust_string_lossy(scope);
            format!("Uncaught {text}")
        })
    } else {
        None
    };
    (value, caught)
}

/// Passes the command-line flags that belong to V8 through to it.
///
/// Node splits its arguments into its own and V8's, and hands the V8 half over
/// before `V8::Initialize`. rustnode accepts the same flags, so the ones that
/// are only meaningful to V8 have to reach it too — otherwise a flag is accepted
/// and silently does nothing, which is the failure mode `Options::unimplemented`
/// exists to avoid but cannot catch for a flag that *is* implemented elsewhere.
///
/// Only the flags listed here are forwarded. Everything else rustnode handles
/// itself, and forwarding it would change V8's behaviour behind rustnode's back.
fn forward_v8_flags(args: &[String]) {
    /// V8 flags that are also Node flags and are implemented by passing them
    /// through. `--max-old-space-size` sizes the old generation, which is what
    /// `v8.getHeapStatistics().heap_size_limit` reports.
    ///
    /// `--expose-gc` is here rather than in JavaScript for the same reason: it
    /// is what makes V8 install the `gc()` global, and a hand-written `gc` would
    /// not be the same function V8's tests call. Node lists it as a `V8Option`
    /// in `node_options.cc`, so this is the faithful place for it.
    const FORWARDED: &[&str] = &["--max-old-space-size=", "--stack-size="];
    /// V8 flags spelled with no value.
    ///
    /// Both spellings appear in Node's test headers — `--expose-gc` and
    /// `--expose_gc` — and V8 accepts either, so both are forwarded. Matching
    /// only the dashed form left `test-abortsignal-drop-settled-signals.mjs`
    /// failing on a flag the harness had already passed through.
    ///
    /// `--allow-natives-syntax` is here for the same reason and is the same kind
    /// of flag: V8 consumes it and Node stores no field for it, so accepting it
    /// without forwarding leaves `%DebugPrint` and friends as a `SyntaxError`.
    /// `lib/internal/test_runner/runner.js` names these two as the examples of
    /// options that must be propagated by hand.
    const FORWARDED_BARE: &[&str] = &[
        "--expose-gc",
        "--expose_gc",
        "--allow-natives-syntax",
        "--allow_natives_syntax",
    ];

    for argument in args {
        if FORWARDED.iter().any(|prefix| argument.starts_with(prefix))
            || FORWARDED_BARE.contains(&argument.as_str())
        {
            // V8 spells its flags with underscores as well as dashes; the dashed
            // form is what the command line takes and V8 accepts both.
            v8::V8::set_flags_from_string(argument);
        }
    }
}

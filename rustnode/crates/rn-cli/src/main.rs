mod args;
mod bootstrap;
mod event_loop;

use rn_bindings::install_all;
use rn_core::Env;
use rn_v8_sys::v8;

const BOOTSTRAP: &str = include_str!("bootstrap.js");

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

    let mut env = Env::new();
    let mut registry = rn_core::BindingRegistry::new();
    install_all(&mut registry);
    for namespace in registry.namespaces() {
        env.insert(namespace.clone());
    }
    // `internalBinding` reaches the registry from a V8 callback, which cannot
    // borrow, so the registry lives for the whole process.
    let registry: &'static rn_core::BindingRegistry = Box::leak(Box::new(registry));

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

    // `lib/**` reads option values through `internalBinding('options')`, and
    // that binding can only report them if it is told what the command line
    // said. Installing before the realm bootstrap matters: `realm.js` builds
    // the builtin allow-list from `--experimental-bench` during its own load,
    // so a value installed later would arrive after the decision was made.
    rn_bind_options::parsed::install(options.parsed.clone());

    if let Err(message) = install_globals(scope, &args) {
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
    match bootstrap::bootstrap_realm(scope, registry, &argv_rest, &options.exec_argv) {
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
                    match event_loop::RuntimeHooks::install(scope, require) {
                        Ok(hooks) => runtime = Some(hooks),
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
                        if let Err(message) = event_loop::install_eval_builtins(scope, require) {
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
        std::process::exit(1);
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
        match event_loop::run_loop(scope, hooks) {
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

    // A script that reports failure through `process.exitCode` rather than a
    // throw is how every one of Node's own tests fails, so the status has to
    // travel out of the interpreter. An explicit `process.exit()` already
    // terminated the process before reaching here.
    if let Some(code) = bootstrap::read_exit_code(scope) {
        std::process::exit(code);
    }
    if exit_requested || rn_core::hook_slot::flag(rn_core::hook_slot::EXIT_REQUESTED) {
        std::process::exit(1);
    }
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

fn install_globals(scope: &mut v8::PinScope, args: &[String]) -> Result<(), String> {
    let global = scope.get_current_context().global(scope);

    let argv = v8::Array::new(scope, args.len() as i32);
    for (index, arg) in args.iter().enumerate() {
        let value = v8::String::new(scope, arg).ok_or("cannot allocate argv entry")?;
        argv.set_index(scope, index as u32, value.into());
    }
    set_global(scope, global, "__argv", argv.into())?;

    let stdout = make_stream_object(scope, StdStream::Stdout)?;
    set_global(scope, global, "__stdout", stdout.into())?;

    let stderr = make_stream_object(scope, StdStream::Stderr)?;
    set_global(scope, global, "__stderr", stderr.into())?;

    let version = v8::String::new(scope, v8::V8::get_version()).ok_or("cannot allocate version")?;
    set_global(scope, global, "__v8Version", version.into())?;

    let source = v8::String::new(scope, BOOTSTRAP).ok_or("cannot allocate bootstrap source")?;
    let script = v8::Script::compile(scope, source, None).ok_or("cannot compile bootstrap")?;
    script.run(scope).ok_or("cannot run bootstrap")?;

    Ok(())
}

fn set_global(
    scope: &mut v8::PinScope,
    global: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate global name")?;
    global.set(scope, key.into(), value);
    Ok(())
}

#[derive(Clone, Copy)]
enum StdStream {
    Stdout,
    Stderr,
}

impl StdStream {
    fn write(self, text: &str) {
        use std::io::Write;
        match self {
            Self::Stdout => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(text.as_bytes());
                let _ = out.flush();
            }
            Self::Stderr => {
                let mut err = std::io::stderr().lock();
                let _ = err.write_all(text.as_bytes());
                let _ = err.flush();
            }
        }
    }
}

fn stream_write_callback(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _rv: v8::ReturnValue,
) {
    let Some(text) = args.get(0).to_string(scope) else {
        return;
    };
    let text = text.to_rust_string_lossy(scope);
    let Some(external) = v8::Local::<v8::External>::try_from(args.data()).ok() else {
        return;
    };
    // SAFETY: the pointer comes from `Box::into_raw` in `make_stream_object` and
    // lives for the whole process, so the read is valid for the callback's life.
    let stream = unsafe { *external.value().cast::<StdStream>() };
    stream.write(&text);
}

fn make_stream_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    stream: StdStream,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let external = v8::External::new(scope, Box::into_raw(Box::new(stream)).cast());
    let template = v8::FunctionTemplate::builder(stream_write_callback)
        .data(external.into())
        .build(scope);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate stream write function")?;
    let object = v8::Object::new(scope);
    let key = v8::String::new(scope, "write").ok_or("cannot allocate key")?;
    object.set(scope, key.into(), function.into());
    Ok(object)
}

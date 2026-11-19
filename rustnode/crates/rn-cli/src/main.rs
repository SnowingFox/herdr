mod args;
mod config_file;
mod diagnostics;
mod snapshot;

use rn_bindings::install_all;
use rn_core::Env;
use rn_realm as bootstrap;
use rn_v8_sys::v8;
use std::path::Path;

fn main() {
    rn_core::profile::start();
    diagnostics::install();
    rn_core::profile::mark("tracing init");

    if let Err(message) = rn_v8_sys::check_linked_v8() {
        eprintln!("rustnode: {message}");
        terminate(1);
    }
    rn_core::profile::mark("v8 link check");

    let args: Vec<String> = std::env::args().skip(1).collect();
    // libuv has to be handed the argument block before `process.title` can be
    // written: `uv_set_process_title` answers `UV_ENOBUFS` until `uv_setup_args`
    // has run, and Node calls it at the very top of `main` for that reason. Doing
    // it here means `process.title` is a real rename on `ps` rather than a
    // Rust-side string that reads back and changes nothing.
    rn_uv::process_title::setup_args();
    rn_core::profile::mark("uv_setup_args");
    // `NODE_OPTIONS` is parsed before the command line, the way
    // `InitializeNodeWithArgsInternal` does it (`src/node.cc:1054`), and a
    // rejected variable stops the process there. The message is printed against
    // `argv[0]` because that is what Node prints, which is what makes the stderr
    // byte-identical rather than merely similar.
    let env_options = match args::read_node_options_with_store() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{}: {}", args::program_name(), error.message());
            terminate(9);
        }
    };
    // Flags that V8 owns are handed to it before initialization, the way Node's
    // `V8::Initialize` path does. `--max-old-space-size` is the one observable
    // through `v8.getHeapStatistics().heap_size_limit`, so ignoring it made that
    // field a fixed 1.5 GB no matter what the command line said.
    //
    // The forwarding itself happens below, immediately before V8 is initialized,
    // because it is V8 that decides which flags exist and what a rejected one
    // says. See `apply_v8_flags`.

    // The command line is parsed before anything is built, because the
    // permission model it produces has to exist before the binding registry
    // does: `rn_permission::register` installs `internalBinding('permission')`
    // around whatever model is already there, and the `fs`, `child_process` and
    // `worker` checks read the same one. Parsing later would leave the binding
    // holding a disabled model while the CLI held an enforcing one.
    let options = match args::parse_with_env(
        &args,
        env_options,
        if rn_uv::is_terminal(0) {
            args::StdinKind::Terminal
        } else {
            args::StdinKind::Redirected
        },
    ) {
        Ok(options) => options,
        Err(error) => match error {
            // `StartInternal` prints every rejected argument the same way:
            // `"%s: %s\n"` against `argv[0]` verbatim, which is what makes the
            // output byte-identical to the oracle's. The fixed `rustnode:`
            // prefix this used to print was a shape no test expects and no Node
            // build produces; `test-cli-eval.js` compares the whole line against
            // `${process.execPath}: -e requires an argument`.
            args::ParseError::Cli(message) => {
                eprintln!("{}: {message}", args::program_name());
                terminate(9);
            }
            args::ParseError::NodeOptions(message) => {
                eprintln!("{}: {message}", args::program_name());
                terminate(9);
            }
            // `CheckOptions` errors are printed by the same loop as the
            // environment's, because Node's error vector does not record which
            // source produced one.
            args::ParseError::OptionValue(message) => {
                eprintln!("{}: {message}", args::program_name());
                terminate(9);
            }
            // The two file sources, whose messages Node collects into one vector
            // and `StartInternal` prints in a loop — but only the config reader
            // also writes a line of its own, with no program name. That line has
            // to reach stderr first and verbatim, so it is written here with
            // `eprint!` (it already carries its newlines) before the prefixed
            // messages.
            args::ParseError::Startup(startup) => {
                for diagnostic in &startup.diagnostics {
                    eprint!("{diagnostic}");
                }
                let program = args::program_name();
                for message in &startup.messages {
                    eprintln!("{program}: {message}");
                }
                terminate(9);
            }
        },
    };
    // A flag whose feature has not landed must not pass silently, or a test
    // that needed it looks like it exercised something it did not.
    for flag in &options.unimplemented {
        eprintln!("rustnode: warning: {flag} is accepted but not implemented");
    }
    if let Some(missing) = missing_test_runner_path(&options) {
        eprintln!("Could not find '{missing}'");
        terminate(1);
    }
    rn_permission::runtime::install_shared(options.permission.clone());
    rn_core::profile::mark("args parse + permission install");

    // The command line's abort decision is recorded once, before any code runs,
    // because Node sets `EnvironmentOptions::abort_on_uncaught_exception` from
    // the V8 argument vector at environment creation (`src/node.cc:794`) and
    // never re-reads it. `v8.setFlagsFromString` is a different mechanism: it
    // makes V8 itself abort, which is why
    // `test-process-exception-capture-should-abort-on-uncaught-setflagsfromstring.js`
    // behaves differently from the command-line form.
    rn_core::hook_slot::set_abort_on_uncaught_exception(options.abort_on_uncaught_exception);
    // The two `--trace-*` diagnostics are recorded at the same point and for the
    // same reason: Node reads them from `EnvironmentOptions` at the moment the
    // environment reports or exits, never from the option layer, so nothing a
    // script does later can turn them on.
    rn_core::hook_slot::set_trace_exit(options.trace_exit);
    rn_core::hook_slot::set_trace_uncaught(options.trace_uncaught);
    // `--trace-sync-io` is two switches in Node: this one, and the loop-phase one
    // `main` flips around `run_loop` (`SpinEventLoopInternal`'s
    // `env->set_trace_sync_io`). Setting only the second would lose the flag;
    // setting only this one would warn during the first tick, which the oracle
    // does not.
    rn_core::hook_slot::set_trace_sync_io(options.trace_sync_io);
    // `--trace-promises` is deliberately *not* a hook-slot value: the isolate
    // promise hook is installed before any of this runs (see `trace_promises`),
    // because V8 must see it before the first promise is created by the loaders.
    //
    // `--zero-fill-buffers` decides how `createUnsafeArrayBuffer` allocates, and
    // that call happens in `rn-bind-buffer` on whichever thread asks, so the
    // decision travels in the shared slot rather than in this struct.
    rn_core::hook_slot::set_zero_fill_buffers(options.zero_fill_buffers);
    // `ReportException` ends every uncaught report with `Node.js <version>`
    // unless `--no-extra-info-on-fatal-exception` cleared it. The text lives in
    // `rn-realm`, which depends on `rn-errors`, so the version is recorded here
    // and read back from the slot rather than making that edge a cycle.
    rn_core::hook_slot::set_node_version(rn_realm::versions::process_version_string().to_string());
    if let Some(rn_bind_options::ParsedValue::Bool(value)) =
        options.parsed.value_of("--extra-info-on-fatal-exception")
    {
        rn_core::hook_slot::set_extra_info_on_fatal_exception(value);
    }
    // `CallbackIntoModule`'s policy switch, read by `rn-napi` on every addon
    // throw. Recorded here because the binding crate cannot see `Options`.
    if let Some(rn_bind_options::ParsedValue::Bool(value)) = options
        .parsed
        .value_of("--force-node-api-uncaught-exceptions-policy")
    {
        rn_core::hook_slot::set_force_node_api_uncaught_exceptions_policy(value);
    }
    // `env->exec_argv()`, which a worker without its own `options.execArgv`
    // inherits (`src/node_worker.cc:664`). Recording it here is what makes the
    // parent's `--trace-exit` reach a worker: the worker re-parses this list
    // into its own `EnvironmentOptions`.
    rn_core::hook_slot::set_exec_argv(options.exec_argv.clone());

    // `Environment::Initialize` records the IPC channel's descriptor from
    // `NODE_CHANNEL_FD` before any JavaScript runs, so that a later change to the
    // environment cannot change which descriptor counts as the channel. The
    // `net` scope exempts that descriptor, because a fork or cluster child is
    // handed the channel rather than opening it; without the record,
    // `setupChildProcessIpcChannel()`'s `Pipe.open(fd)` would be denied under a
    // bare `--permission` and the child would fail during pre-execution.
    if let Ok(channel) = std::env::var("NODE_CHANNEL_FD") {
        if let Ok(fd) = channel.trim().parse::<i32>() {
            if fd >= 0 {
                rn_permission::runtime::set_ipc_channel_fd(fd);
            }
        }
    }

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
    // The names the scrub took away, so `--env-file` can tell "the parent set this
    // and it wins" from "the permission model removed it and the file may restore
    // it". Empty unless the model is enforcing.
    let mut scrubbed: Vec<String> = Vec::new();
    if options.permission_config.enabled {
        if allow_env
            .iter()
            .any(|pattern| !rn_permission::env::is_valid_pattern(pattern))
        {
            eprintln!(
                "rustnode: --allow-env must be '*', a variable name, or a \
                 variable name prefix followed by '*'"
            );
            terminate(9);
        }
        if options.permission_config.audit {
            let denied = rn_permission::env::record_audited(&allow_env);
            // Two records, because they answer different questions:
            // `record_removed_env_vars` is "the scrub took this away", empty in
            // audit mode by design, and `record_audited_env_vars` is "enforcing
            // would have taken this away", which is what an audit-mode read
            // reports against.
            options.permission.record_removed_env_vars(denied.clone());
            rn_permission::runtime::record_audited_env_vars(denied);
        } else {
            let removed = rn_permission::env::scrub(&allow_env);
            options.permission.record_removed_env_vars(removed.clone());
            scrubbed = removed;
        }
    }

    // `--env-file`'s values are installed here, after the scrub above and before
    // anything reads the environment. This is `Environment::Initialize`'s
    // position (`src/node.cc:343`), and the order is the whole point: the scrub
    // removes every name `--allow-env` does not grant, so an inherited value for
    // a name the file also defines is gone by now and the file's value takes
    // effect. `test-permission-env-file.js` asserts exactly that.
    args::install_env_files(&options.env_file_store, &scrubbed);
    // A name the scrub removed and an env file put back must stop reporting a
    // denial: without this the store holds the file's value while
    // `process.env.X` still answers `undefined` with a "removed at startup"
    // warning, which is the state `test-permission-env-file.js` failed on.
    //
    // Only the names the files actually define are restored. Clearing the whole
    // scrub record would silence the denial for a variable no file mentioned,
    // which is what `node:permission-model:env` and the one-time warning exist to
    // report.
    let restored: Vec<String> = scrubbed
        .iter()
        .filter(|name| options.env_file_store.contains_key(*name))
        .cloned()
        .collect();
    if !restored.is_empty() {
        options.permission.record_env_vars_restored(&restored);
    }

    let mut env = Env::new();
    let mut registry = rn_core::BindingRegistry::new();
    install_all(&mut registry);
    for namespace in registry.namespaces() {
        env.insert(namespace.clone());
    }
    rn_core::profile::mark("binding registry");
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
    //
    // It is also the first of the two flag calls Node makes: `node.cc:949` sets
    // this string, and the command line's V8 flags are applied further down the
    // same function (`node.cc:1101`), so the freeze is lifted before the flags
    // that would otherwise be refused arrive.
    v8::V8::set_flags_from_string("--no-freeze-flags-after-init");

    // The command line's V8 flags, handed over the way Node hands them over:
    // V8 consumes what it recognizes and the rest is a `bad option`. This has to
    // happen before `initialize`, because V8 reads its flag list once and
    // silently ignores anything set afterwards — a flag applied after this point
    // is accepted and then does nothing, which is the failure mode the old
    // allow-list version of this function could not detect.
    apply_v8_flags(&options.v8_args);

    // `--version` answers here, exactly where `src/node.cc:1282` does it: after
    // `InitializeNodeWithArgsInternal` has applied the V8 argument vector and
    // before `V8::Initialize`, the inspector, or any realm exists. The position
    // is observable in both directions — `node --version --not-a-real-flag` is a
    // `bad option` and exits 9 because V8 rejects the flag first, while
    // `node --version --inspect` prints the version and never opens the socket.
    if options.print_version {
        println!("{}", rn_realm::versions::process_version_string());
        terminate(0);
    }

    // `--v8-options`, answered at `src/node.cc:1297`: immediately after the
    // version and before `V8::Initialize`, by handing V8 its own `--help`. V8
    // writes the list, so the text is generated from the flags this build
    // actually has rather than transcribed — which is the only way the answer
    // can stay true across a V8 bump.
    //
    // Ordering is observable in the same way `--version`'s is: a bad flag still
    // wins, because the V8 argument vector was applied a few lines up.
    if options.print_v8_options {
        // Applied here rather than in the startup argument vector because
        // setting this flag costs about 17 ms of every process's startup; see
        // [`user_named_external_memory_flag`]. `--v8-options` is the one place
        // the value is observable, and a caller who set it explicitly keeps
        // their value, which is Node's `none_of` guard.
        if !user_named_external_memory_flag(&options.v8_args) {
            v8::V8::set_flags_from_string("--external-memory-max-reasonable-size=0");
        }
        v8::V8::set_flags_from_string("--help");
        terminate(0);
    }

    // A `CustomPlatform` rather than the default one, so a foreground task V8
    // posts from *another* thread can wake this thread's event loop. With the
    // default platform such a task is queued and nothing signals the waiter, so
    // `Atomics.waitAsync` only settled when some unrelated event happened to turn
    // the loop: `postMessageToThread` into a throwing `workerMessage` handler
    // reported `ERR_WORKER_MESSAGING_ERRORED` after 5011 ms instead of 13 ms, and
    // with only unref'd timers it never settled at all. See
    // `rn_v8_sys::platform`.
    let platform = rn_v8_sys::platform::new_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    // Tells the loop's platform-task checkpoint to drain our queue rather than
    // V8's default one, which a custom platform leaves empty by design.
    rn_v8_sys::use_custom_platform();
    v8::V8::initialize();
    rn_core::profile::mark("V8::initialize");

    // `--build-snapshot` runs on its own isolate and never reaches the path
    // below. Two reasons: `create_blob` consumes its isolate and must not run
    // inside a handle scope, and `main`'s scope is pinned for the whole function,
    // so the isolate it borrows could never be moved into `create_blob`. A build
    // therefore happens in [`snapshot::build`], which owns both the isolate and
    // the scope in one body and so can end the scope before consuming the isolate.
    if options.build_snapshot {
        run_snapshot_build(&options);
    }

    // The allocator is what makes `process.memoryUsage().arrayBuffers` a real
    // number: V8's default allocator does not count anything, so an isolate
    // created without one cannot report live backing-store bytes at all. See
    // `rn_core::array_buffer_allocator` for why this is per isolate rather than
    // process-wide.
    //
    // The constraints are `SetIsolateCreateParamsForNode`
    // (`src/api/environment.cc:210`), which is what makes this isolate's heap
    // sized from the machine rather than from V8's browser default of 1.4 GB.
    // Without it `v8.getHeapStatistics().heap_size_limit` reports 1496 MB on a
    // 47 GB box where Node reports 4192 MB, and the 32 MB semi-space
    // `ConfigureDefaults` picks is what stops startup from scavenging.
    let params = rn_core::set_isolate_create_params_for_node(
        v8::CreateParams::default(),
        rn_uv::memory::constrained_memory(),
        rn_uv::memory::total_memory(),
    );
    let mut isolate = v8::Isolate::new(if options.debug_arraybuffer_allocations {
        // `ArrayBufferAllocator::Create`'s debugging subtype
        // (`src/api/environment.cc:196`), selected when
        // `debug_arraybuffer_allocations` is set. The flag's whole behaviour is
        // in this allocator, so this is the one place it matters.
        rn_core::with_debugging_array_buffer_allocator(params)
    } else {
        rn_core::with_counted_array_buffer_allocator(params)
    });
    rn_core::profile::mark("Isolate::new");
    // `import.meta` and `import()` are dispatched by V8 through isolate-level
    // handlers rather than `internalBinding()`, so they are installed here,
    // where a `&mut Isolate` exists. A binding callback cannot do it: the v8
    // crate documents `FunctionCallbackArguments::get_isolate` as unsound while
    // a callback scope is open, and one always is during a binding call.
    rn_module_wrap::install_isolate_callbacks(&mut isolate);
    // `new ShadowRealm()` asks the embedder for its global object through one
    // isolate-level callback, and with none installed V8 throws its own bare
    // `Error: Not supported`. Node answers with a fully bootstrapped second
    // realm; `rn_realm::shadow_realm` is that answer. Installed here for the same
    // reason as the two ESM handlers above: the only API that sets it takes
    // `&mut Isolate`.
    rn_realm::shadow_realm::install_callback(&mut isolate);
    // V8 reports a rejected promise through one isolate-level callback, and
    // `internal/process/promises.js` cannot receive a rejection without it:
    // `setPromiseRejectCallback` only records the JavaScript function. Node
    // installs `node::task_queue::PromiseRejectCallback` from
    // `SetIsolateMiscHandlers`, before any JavaScript runs, which is the same
    // position this takes. A binding cannot do it — the only API takes
    // `&mut Isolate`.
    rn_bind_task_queue::install_isolate_callbacks(&mut isolate);
    // `v8.writeHeapSnapshot` needs `take_heap_snapshot`, an `Isolate` method,
    // and a binding callback cannot obtain a `&mut Isolate` soundly. Recording
    // the isolate here is the same arrangement the ESM handlers use.
    rn_bind_heap_utils::set_snapshot_isolate(&mut isolate);
    // `--trace-promises` is `Environment::InitializeDiagnostics`'s
    // `isolate_->SetPromiseHook(TracePromises)`, and the only API that installs
    // one takes `&mut Isolate`. This is *before* the option store is installed
    // below, so the flag is read from the parser's own record rather than from
    // `getOptionValue`, which is the same source `InitializeDiagnostics` uses
    // (`EnvironmentOptions`).
    rn_realm::trace_promises::arm(options.trace_promises, &mut isolate);
    // Node registers `Environment::BuildEmbedderGraph` at isolate creation
    // (`src/node.cc:240`), which is what puts `Node / MessagePort` and the other
    // native nodes into every snapshot. Without a callback V8 adds no embedder
    // nodes at all, so `test/pummel/test-worker-take-heapsnapshot.js` would find
    // none of the ones it looks for. This is the same registration, walking the
    // retainers rustnode actually has.
    install_embedder_graph(&mut isolate);
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

    // `Environment::InitializeDiagnostics` (`src/node.cc:245`) turns on V8's
    // capture of the stack behind an uncaught exception, but only under
    // `--trace-uncaught`. That capture is what `Message::GetStackTrace` reads
    // when the exception is reported, and it is why the flag reports the throw
    // site for a value that has no `stack` of its own — a thrown `null`, or an
    // object whose `stack` getter throws. The frame limit is
    // `--stack-trace-limit`, the same value `Error.stackTraceLimit` uses.
    if options.trace_uncaught {
        let limit = stack_trace_limit(&options);
        isolate.set_capture_stack_trace_for_uncaught_exceptions(true, limit);
    }
    rn_core::hook_slot::set_stack_trace_limit(i64::from(stack_trace_limit(&options)));
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    // `--trace-promises`'s hook needs the principal realm's context; see
    // `trace_promises::record_context`. Recorded here, where the context is a
    // handle this frame owns.
    rn_realm::trace_promises::record_context(options.trace_promises, scope, context);
    let scope = &mut v8::ContextScope::new(scope, context);
    rn_core::profile::mark("Context::new");

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
    // Read *after* the store is installed: `parsed::value_of` reads the
    // thread-local store, and a read before this line saw the table default
    // rather than the flag, so DEP0119 never fired.
    rn_core::hook_slot::set_pending_deprecation(matches!(
        rn_bind_options::parsed::value_of("--pending-deprecation"),
        Some(rn_bind_options::parsed::ParsedValue::Bool(true))
    ));

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
    //
    // `Agent::Start`/`StartIoThread` check the `inspector` scope, so an
    // `--inspect` under `--permission` without `--allow-inspector` is refused
    // before the endpoint opens. There is no JavaScript frame to throw into at
    // this point, so the failure is reported and the process exits the way
    // Node's does for a rejected startup flag; `test-permission-inspector-brk.js`
    // asserts the exit status and the `Access to this API has been restricted`
    // text on stderr.
    if options.inspect_enabled {
        // `Agent::Start`/`StartIoThread` check the `inspector` scope, so an
        // `--inspect` under `--permission` without `--allow-inspector` is refused
        // before the endpoint opens. There is no JavaScript frame to throw into at
        // this point, so the failure is reported and the process exits the way
        // Node's does for a rejected startup flag;
        // `test-permission-inspector-brk.js` asserts the exit status and the
        // `Access to this API has been restricted` text on stderr.
        if let Some(denied) = rn_permission::runtime::deny_inspector() {
            eprintln!("Error: {}", denied.message());
            std::process::exit(1);
        }
        let request = &options.debug_port;
        // The entry point `/json/list` reports is the *unresolved* `argv[1]`, as
        // `Agent::Start` receives it (`src/node.cc:203`): the oracle titles a
        // relative `app.js` as `"app.js"` while resolving `url` itself. The CLI
        // knows which argument that was, so it is recorded here rather than
        // re-read from `std::env::args`, which cannot tell a flag's value from a
        // script path.
        match &options.source {
            args::Source::File(path) => rn_bind_inspector::set_script_name(path),
            args::Source::Inspect => rn_bind_inspector::set_script_name(args::INSPECT_SUBCOMMAND),
            _ => {}
        }
        match rn_bind_inspector::start_server(request.host.as_str(), request.port) {
            Ok(url) => {
                eprintln!("Debugger listening on {url}");
                eprintln!("For help, see: https://nodejs.org/learn/getting-started/debugging");
                // `--inspect-brk` blocks here until a client sends
                // `Runtime.runIfWaitingForDebugger`, which is
                // `Agent::WaitForConnectByOptions` plus `waitForFrontend`.
                //
                // It cannot be a sleep-and-poll: the client's first commands —
                // `Debugger.enable`, `Debugger.setBreakpointByUrl`, then
                // `runIfWaitingForDebugger` — all arrive *while* the process is
                // stopped, so the wait has to dispatch them. That is why this goes
                // through the same message loop an ordinary pause uses rather than
                // blocking on an attachment flag; the flag-only version deadlocked
                // as soon as a client tried to say "run".
                if options.inspect_wait {
                    if !rn_bind_inspector::wait_for_frontend(scope) {
                        eprintln!(
                            "rustnode: --inspect-brk found no client; running without waiting"
                        );
                    }
                    // Node only asks for this native post-wait pause in the
                    // `--inspect-brk-node` mode (`break_node_first_line`), not for
                    // plain `--inspect-brk`: normal break-on-start for user scripts
                    // comes from JavaScript `callAndPauseOnStart`. Arming this
                    // unconditionally moves `node inspect <file>`'s first visible
                    // pause into bootstrap internals instead of the script itself.
                    //
                    // `--test` enters through `internal/main/test_runner`, whose
                    // startup side effects (including the inspector concurrency
                    // warning) must run before any debugger pause in
                    // `test-runner-inspect.mjs`'s attach flow.
                    if options.inspect_break_node && !matches!(options.source, args::Source::Test) {
                        rn_bind_inspector::schedule_start_break();
                    }
                }
            }
            Err(message) => {
                eprintln!("rustnode: {message}");
                terminate(9);
            }
        }
    }

    if let Err(message) = bootstrap::install_globals(scope, &args) {
        eprintln!("rustnode: {message}");
        terminate(1);
    }
    rn_core::profile::mark("install_globals (bootstrap.js)");

    // `Environment::InitializeCompileCache`, which `LoadEnvironment` calls after
    // `InitializeDiagnostics` and before `StartExecution` — so before any module
    // is compiled and, crucially, *after* the permission model is installed.
    // Enabling it earlier made `--permission` grant the cache directory by
    // accident: the model was not yet in the thread-local the check reads, so
    // every check passed and a denied run wrote its cache anyway.
    //
    // The exit flush is registered by the enable itself — here for the
    // environment variable, and inside the binding for
    // `module.enableCompileCache()` — because Node's `AtExit` callback is
    // registered by `Environment::EnableCompileCache` on both paths.
    rn_bind_modules::compile_cache::initialize_from_env();
    rn_core::profile::mark("compile cache init");

    // `process.argv` is `[execPath, scriptPath?, ...scriptArgs]`. Node puts the
    // resolved script path in `argv[1]` and omits that slot for `-e`/`-p`, where
    // the arguments follow the executable directly. Resolving it here, rather
    // than in the parser, keeps `Options` a faithful record of what was typed
    // while `argv` matches what Node reports for the same command line.
    let mut argv_rest: Vec<String> = Vec::new();
    let mut script_path = None;
    // What `install_cjs_loader` anchors `require` at, when it differs from
    // `process.argv[1]`. Only `--entry-url` splits them: the published slot has
    // to stay what the user typed, while `Module.createRequire` needs something
    // it can resolve.
    let mut require_anchor: Option<String> = None;
    // `--entry-url` changes both halves of this slot. Node keeps the entry point
    // as the user wrote it — `process.argv[1]` is the raw `a1.js` or
    // `file:///…` string, not an absolute path — because
    // `lib/internal/modules/run_main.js:176` builds the `URL` from it, and
    // `run_main_module.js:17` passes `false` for `expandArgv1` so nothing
    // rewrites the slot afterwards. Measured on the oracle: `node a1.js` reports
    // `/tmp/eu/a1.js`, `node --entry-url a1.js` reports `a1.js`, and
    // `node --entry-url file:///tmp/eu/a1.js` reports the URL.
    let entry_is_url = matches!(
        options.parsed.value_of("--entry-url"),
        Some(rn_bind_options::parsed::ParsedValue::Bool(true))
    );
    match &options.source {
        args::Source::File(path) if entry_is_url => {
            // `process.argv[1]` keeps what the user typed, exactly as Node
            // leaves it: `run_main_module.js:17` passes `false` for
            // `expandArgv1`, so nothing rewrites the slot, and
            // `lib/internal/modules/run_main.js:176` resolves it with
            // `new URL(mainPath, getCWDURL())` when it needs a URL.
            //
            // The CJS loader's `require` anchor is a different value, because
            // `Module.createRequire` rejects a bare relative string. Node never
            // builds one on this path — `--entry-url` forces the ESM loader, so
            // `executeUserEntryPoint` resolves `mainPath` itself — but this
            // build's entry point still reaches `executeUserEntryPoint`'s CJS
            // branch, so the anchor is kept resolvable rather than left to
            // throw. A `file:` URL is already resolvable as typed.
            argv_rest.push(path.clone());
            script_path = Some(path.clone());
            require_anchor = Some(if path.contains("://") {
                path.clone()
            } else {
                std::path::absolute(path)
                    .map(|resolved| resolved.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| path.clone())
            });
        }
        args::Source::File(path) => {
            let resolved = std::path::absolute(path)
                .map(|resolved| resolved.to_string_lossy().into_owned())
                .unwrap_or_else(|_| path.clone());
            argv_rest.push(resolved.clone());
            script_path = Some(resolved);
        }
        // `node -` publishes the marker itself as `argv[1]`, which is what
        // `patchProcessObject` then leaves alone: its `expandArgv1` branch skips
        // an argument starting with `-`. A bare `node` with a pipe publishes no
        // `argv[1]` at all.
        args::Source::Stdin { marker: true } => argv_rest.push("-".to_string()),
        // `inspect` keeps its own name in `argv[1]` rather than being resolved
        // to a path, which is what `internal/main/inspect`'s
        // `process.argv.slice(2)` expects: the debugger's arguments start at
        // index 2 either way. Node's `StartExecution` reads the same slot from
        // `env->argv()[1]` before any expansion, so the word itself is the
        // entry point's name.
        args::Source::Inspect => argv_rest.push(args::INSPECT_SUBCOMMAND.to_string()),
        _ => {}
    }
    argv_rest.extend(options.script_args.iter().cloned());

    // Node's own bootstrap defines `internalBinding` and `require`. When it fails
    // the CLI still runs, because `-e` on a bare global is useful for debugging
    // the bootstrap itself; the reason is printed so a failure is never silent.
    let mut runtime = None;
    let mut realm_require: Option<v8::Global<v8::Function>> = None;
    match bootstrap::bootstrap_realm(
        scope,
        &argv_rest,
        &options.exec_argv,
        bootstrap::ProcessState::main_thread(options.debug_port.port),
    ) {
        Ok(mut loaders) => {
            rn_core::profile::mark("realm bootstrap returned");
            // The bootstrap stored the *requested* `--inspect-port`, which is 0
            // when the caller asked the OS for one. A server started above
            // already knows the port it bound, so that value wins — this is
            // `DebugPortGetter` reading `env->inspector_host_port()`, which
            // `inspector_io.cc` updates after `uv_tcp_bind` resolves a 0.
            // `cluster` derives each worker's `--inspect-port` from this getter,
            // so a 0 here made it pass `--inspect-port=1` and fail to start.
            if let Some(bound) = rn_bind_inspector::bound_port() {
                rn_uv::process_title::set_debug_port(bound);
            }
            if options.expose_internals() {
                bootstrap::expose_internals(scope, &loaders);
                rn_core::profile::mark("expose_internals");
            }
            // The internal loader needs the `node:` scheme stripped before it
            // can resolve a specifier; Node's user-land loader does that, and
            // this stands in for it until `contextify` unblocks the real one.
            bootstrap::wrap_require_with_scheme_support(scope, &loaders);
            // The option-gated builtin allow-list (`quic`, `dtls`, `sqlite`,
            // `bench`, `vfs`, ...) is applied exactly once, by Node's own
            // `prepareMainThreadExecution` below: `prepareExecution` calls
            // `setupOptionGatedBuiltins()` at
            // `internal/process/pre_execution.js:121`, which is
            // `BuiltinModule.allowOptionGatedBuiltins(getOptionValue)`.
            //
            // This used to also call `allowOptionGatedBuiltins` here, on the
            // stated belief that "rustnode does not run `pre_execution.js`". It
            // does — `prepare_execution` invokes `prepareMainThreadExecution` —
            // so Node applied the call once and rustnode applied it twice, and
            // nothing between the two calls needs a gated builtin:
            // `install_early_globals` reaches only `buffer`, `encoding`,
            // `worker/js_transferable`, `async_hooks` and `util`, and
            // `install_cjs_loader` only `modules/cjs/loader`. Both the suite and
            // the worker path behave identically without it, so the second
            // application was pure cost and is gone.
            //
            // The `require('node:...')` boundary is what *enforces* the list:
            // the vendored CJS loader's `BuiltinModule.normalizeRequirableId`,
            // which is why `install_cjs_loader` below must keep the global
            // `require` sending every `node:` id through the file loader.
            // Routing the scheme branch to the realm loader instead skipped that
            // check and loaded `quic`, `dtls` and `bench` even though
            // `canBeRequiredByUsers` reports false for them.
            bootstrap::install_early_globals(scope, &loaders);
            rn_core::profile::mark("install_early_globals");
            // The CommonJS loader turns `require` from a builtin lookup into a
            // real module loader, which is what makes `require('./file.js')`
            // work. It is the vendored `lib/internal/modules/cjs/loader.js`,
            // not a Rust reimplementation: resolution order, the cache, the
            // `node_modules` walk and `package.json` `exports` are all already
            // correct there.
            if let Some(require) = loaders.require.as_ref() {
                let require = v8::Local::new(scope, require);
                let anchor = require_anchor.clone().or_else(|| script_path.clone());
                if let Err(message) = bootstrap::install_cjs_loader(scope, require, &anchor) {
                    // A failure is reported rather than fatal, for the same
                    // reason the bootstrap itself is: a script using only
                    // builtins still runs, and saying why file requires do not
                    // work is more useful than refusing to start.
                    eprintln!("rustnode: commonjs loader unavailable: {message}");
                }
            }
            rn_core::profile::mark("install_cjs_loader");
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
                    rn_core::profile::mark("install_stdio + console");
                    // Node's entry points are main scripts, and each of them
                    // calls `prepareMainThreadExecution()` itself: that is the
                    // first line of `run_main_module.js`, `print_help.js` and
                    // `eval_stdin.js` alike. The CLI calls it here only for the
                    // paths it drives itself — `-e`, a file entry point, and the
                    // empty program — so a main script must not find it already
                    // run. Node enforces the same ordering with the assertion in
                    // `initializeModuleLoaders` ("no user module has been
                    // executed yet"), which is what made a `.mjs` entry point
                    // fail with `ERR_INTERNAL_ASSERTION` before the CLI ran
                    // pre-execution at all.
                    if options.source.uses_main_script() {
                        rn_core::profile::mark("prepare_execution (deferred to main script)");
                    } else {
                        bootstrap::prepare_execution(scope, require);
                        rn_core::profile::mark("prepare_execution");
                    }
                    // `node -e` exposes builtins as lazy globals, and
                    // `internal/main/eval_string` does that itself
                    // (`addBuiltinLibsToObject(globalThis, '<eval>')` is its
                    // first statement after pre-execution). Installing them
                    // here as well would run that twice, and the second call
                    // would re-define every getter the first one installed.
                }
                None => {
                    eprintln!("rustnode: timers unavailable: the realm bootstrap left no require")
                }
            }
            rn_core::profile::mark("Runtime::install + eval builtins");
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
    rn_core::profile::mark("push_top_level_context");

    // A file is loaded through Node's own entry-point path
    // (`internal/modules/run_main.js::executeUserEntryPoint`), which picks the
    // CommonJS or ESM loader from the file's format — `.mjs`, `.wasm`, or a
    // `.js` in a `"type": "module"` package take the ESM path. `-e` has no
    // file, so it is compiled as a bare script against the global object.
    //
    // The file's text is deliberately not read here: the loader reads it, and a
    // second read would bypass the loader's source handling (and its cache).
    let mut entry_promise: Option<v8::Global<v8::Promise>> = None;
    let mut entry_fatal = false;
    match &options.source {
        args::Source::File(_) => {
            // Node exposes a global `require` only for `-e`/`-p`. A file entry
            // point is a CommonJS or ESM module, whose `require` is the module
            // wrapper's parameter — an own `globalThis` property is not merely
            // extra, it shadows nothing and shows up in `test/common/index.js`'s
            // globals audit, and in `Object.getOwnPropertyNames(globalThis)`.
            //
            // `realm_require` below is a captured handle to the *same* loader,
            // so the entry point still resolves; only the global copy goes.
            rn_realm::delete_require_global(scope);
            // The resolved absolute path, not the raw argument: the loader
            // treats its request as a specifier, so a relative one would be
            // resolved against the loader's paths instead of the cwd.
            match (realm_require.as_ref(), script_path.as_ref()) {
                (Some(require), Some(path)) => {
                    let require = v8::Local::new(scope, require);
                    // A top-level await makes the entry point asynchronous: the
                    // call returns the graph's promise and the module body
                    // finishes during the microtask drain below, not before it.
                    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
                    let scope = &mut try_catch.init();
                    let result = bootstrap::run_main(scope, require, path);
                    if let Some(promise) =
                        result.and_then(|value| v8::Local::<v8::Promise>::try_from(value).ok())
                    {
                        entry_promise = Some(v8::Global::new(scope, promise));
                    }
                    // The entry point does not print here: `run_main.js` hands
                    // the error to `triggerUncaughtException`, which is
                    // `process._fatalException` first and print-and-exit only
                    // when that declines. The exception is reported while the
                    // `TryCatch` that caught it is still open, because
                    // `_fatalException` runs JavaScript and the value has to be
                    // a live handle; formatting it here instead — the old code —
                    // was a second uncaught path no listener could intercept.
                    //
                    // A terminated isolate reports `has_caught()` with no
                    // exception and is not a reportable error, so it is skipped
                    // the way the event loop skips it.
                    let handled = if scope.has_caught() && !scope.has_terminated() {
                        // The message from *this* `TryCatch` is the one that
                        // carries the throw site. A message built at report time
                        // describes the reporter: `Exception::create_message`
                        // here produced `undefined:0` because the failing script
                        // is no longer the current one by then.
                        let message = scope.message();
                        match scope.exception() {
                            Some(exception) => rn_errors::report_uncaught_exception_with_message(
                                scope, exception, message,
                            ),
                            None => true,
                        }
                    } else {
                        true
                    };
                    entry_fatal = !handled;
                }
                _ => {
                    eprintln!("Uncaught the realm bootstrap left no require");
                    entry_fatal = true;
                }
            }
        }
        // `internal/main/eval_string`, `internal/main/eval_stdin`,
        // `internal/main/print_help`, `internal/main/inspect` and
        // `internal/main/test_runner` are Node's own entry points, run as main
        // scripts. They are not reimplemented here for the same reason a file is
        // not: `eval_stdin` reads stdin through `process.stdin`, honours
        // `--input-type`, `--print` and `--strip-types`, and hands the code to
        // `evalScript`, which is what gives the module
        // `module`/`exports`/`require`/`__filename` and makes `require.main`
        // undefined — reproducing that by hand would be a second copy of
        // `evalScript`'s semantics.
        //
        // `eval_string` is the `-e`/`-p` half of the same argument, and it is
        // the whole reason `--input-type` works for `-e`: that script is what
        // reads `getOptionValue('--input-type')` and chooses between
        // `evalModuleEntryPoint` and `evalScript`. Driving the eval from here
        // left `module`, `exports`, `__filename` and `__dirname` undefined
        // (`typeof module` was `"function"` from the loader's global) and made
        // `--input-type=module -e 'import ...'` a `SyntaxError`.
        //
        // `print_help` is the same argument one surface over: the usage text is
        // generated from the option table at run time, so a Rust-side copy
        // would silently drift from the table `getOptionValue` reports.
        //
        // `inspect` likewise *is* `internal/debugger/*`: the client, the REPL
        // and the probe mode all live there, and the script requires `events`,
        // `util`, `timers/promises`, `child_process`, `net`, `http` and
        // `internal/url`, so it has to run after the loaders are installed —
        // which is where this arm is. `test_runner` has the same property:
        // `internal/main/test_runner` owns setup and launches user tests from JS.
        args::Source::Stdin { .. }
        | args::Source::Help
        | args::Source::Inspect
        | args::Source::Test
        | args::Source::Repl
        | args::Source::CheckSyntax
        | args::Source::Bench => {
            let id = options
                .source
                .main_script_id()
                .expect("every main-script source names one");
            // The main scripts call `prepareMainThreadExecution()` themselves,
            // which is why the CLI skipped its own call above. A failure is
            // reported through the same uncaught path a file entry point uses:
            // `print_help` throwing is a startup error, and `eval_stdin` reports
            // the user script's throw from inside its own `end` handler.
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let scope = &mut try_catch.init();
            let failure = match options.source.program_name_substitutions() {
                // `--help` writes its usage header as the literal `node`, and
                // the vendored tree has to stay byte-identical to Node's, so the
                // name is substituted in the source rather than in the file.
                substitutions if !substitutions.is_empty() => {
                    rn_js2c::builtin_by_id(id).and_then(|builtin| {
                        let mut source = builtin.source().to_string();
                        for (needle, replacement) in substitutions {
                            source = source.replace(needle, replacement);
                        }
                        bootstrap::run_main_script_with_source(scope, id, &source)
                    })
                }
                _ => bootstrap::run_main_script(scope, id),
            };
            // A main script that threw and left no live exception behind is
            // still fatal. `run_main_script` opens its own `TryCatch`, so by the
            // time it returns the caught flag is cleared and `handled` reads
            // true even though the script aborted — which made `--check` on a
            // missing file print `Cannot find module` and exit 0. Its `failure`
            // is the only surviving evidence, and Node's `StartExecution`
            // treats a throwing entry point as a startup failure.
            let failed = failure.is_some();
            if let Some(message) = failure {
                eprintln!("{message}");
            }
            let handled = if scope.has_caught() && !scope.has_terminated() {
                match scope.exception() {
                    Some(exception) => rn_errors::report_uncaught_currently(scope, exception),
                    None => true,
                }
            } else {
                true
            };
            entry_fatal = !handled || failed;
        }
        // `internal/main/eval_string` runs *user* code, so its throw has to stay
        // live for the caller's `TryCatch`: `report_uncaught_exception` is what
        // reaches `process._fatalException` and, through
        // `shouldAbortOnUncaughtToggle`, the `--abort-on-uncaught-exception`
        // decision. Returning the message as a value instead — the shape every
        // other main script uses, because their throws are rustnode defects and
        // a printed message is more useful than a silent gap — printed the error
        // and exited 1 where Node dies on SIGTRAP.
        //
        // The scope is *not* re-created here on purpose: `run_eval_main_script`
        // leaves the exception pending, so the arm below sees it.
        //
        // A module-format `-e` is evaluated as an ES module, and Node's ESM path
        // has no `require` binding at all: `evalModuleEntryPoint` compiles the
        // code as a module, whose scope never has one. `test-cli-eval.js`
        // asserts `typeof require === 'undefined'` for `--input-type module
        // --eval`, and the global `require` installed for `-e` is the only thing
        // that would make it `"function"`.
        //
        // `--input-type` is read from the store because that is where
        // `eval_string.js` reads it; the parser only rejects a value that is not
        // one of the four spellings.
        args::Source::Eval => {
            let module_input = matches!(
                options.parsed.value_of("--input-type"),
                Some(rn_bind_options::ParsedValue::Text(ref input_type))
                    if input_type == "module" || input_type == "module-typescript"
            );
            if module_input {
                rn_realm::delete_require_global(scope);
            }
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let scope = &mut try_catch.init();
            if let Err(message) = bootstrap::run_eval_main_script(scope) {
                eprintln!("rustnode: {message}");
                entry_fatal = true;
            }
            // The message comes from the live `TryCatch`, not from a fresh
            // `Exception::CreateMessage`: V8 captures the throw-site stack into
            // the message it makes at throw time, and a message made here would
            // carry this report site instead. `--trace-uncaught` reads it, and
            // `throw null` — which has no error object to take a stack from —
            // is exactly the case where the difference is visible.
            let message = if rn_core::hook_slot::trace_uncaught() {
                scope.message()
            } else {
                None
            };
            let handled = if scope.has_caught() && !scope.has_terminated() {
                match scope.exception() {
                    Some(exception) => {
                        rn_errors::report_uncaught_exception_with_message(scope, exception, message)
                    }
                    None => true,
                }
            } else {
                true
            };
            entry_fatal = entry_fatal || !handled;
        }
        args::Source::Empty => {
            // A bare `node` on a terminal-less descriptor with no script still
            // behaves like `-e ''`, which is what Node reaches when nothing else
            // matched. The completion value is discarded: nothing prints it.
            let _ = evaluate_script(scope, "0");
        }
    }
    rn_core::profile::mark("user script");

    // Only a throw the handler declined is fatal, and then `exit` still has to
    // run: `process._fatalException` overwrote `process.exitCode` with
    // `kGenericUserError` and emitted `exit` inside `onGlobalUncaughtException`.
    // Skipping the emit made `process.on('exit', ...)` fire for every kind of
    // exit except the most common failure a script has.
    //
    // A throw the handler *accepted* leaves the script running, which is why
    // this is conditional: Node continues into the event loop, so a timer the
    // handler scheduled still fires.
    if entry_fatal {
        let code = rn_realm::runtime::emit_exit_after_failure(scope);
        // Before terminating, because this branch exits without reaching the
        // `flush_coverage` below it. Node writes `NODE_V8_COVERAGE` from the
        // `V8CoverageConnection` destructor during environment teardown, and
        // `std::process::exit` skips destructors — so a run that died on an
        // uncaught error produced no coverage file at all, where the oracle still
        // writes one. A coverage consumer therefore lost the whole run rather
        // than the single failing test.
        rn_bind_inspector::flush_coverage(scope);
        terminate(if code == 0 { 1 } else { code });
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
        // A rejection here is the module body throwing. Node's
        // `runEntryPointWithESMLoader` awaits the graph's promise inside a
        // `try`, so the rejection surfaces in its `catch` and is reported as
        // `triggerUncaughtException(err, true /* fromPromise */)` — the same
        // `fromPromise` framing an unhandled rejection gets, which is why this
        // goes through the rejection entry point rather than printing.
        if let Some(entry) = entry_promise.take() {
            let entry = v8::Local::new(scope, entry);
            if entry.state() == v8::PromiseState::Rejected {
                let exception = entry.result(scope);
                let fatal = !rn_errors::report_uncaught_rejection(scope, exception);
                hooks.drain(scope);
                if fatal {
                    let code = rn_realm::runtime::emit_exit_after_failure(scope);
                    terminate(if code == 0 { 1 } else { code });
                }
            }
        }
        // `SpinEventLoopInternal` brackets `uv_run` with
        // `env->set_trace_sync_io(...)` (`src/api/embed_helpers.cc:35` and `:69`),
        // which is what makes the flag's "after the first tick" wording true: the
        // script's own top-level synchronous calls run before this line and are
        // silent, while a timer or immediate callback runs inside it and warns.
        rn_core::hook_slot::set_trace_sync_io_active(rn_core::hook_slot::trace_sync_io());
        match rn_realm::run_loop(scope, hooks) {
            Ok(rn_io::StopReason::ExitRequested | rn_io::StopReason::TurnLimit) => {
                exit_requested = true;
            }
            Ok(rn_io::StopReason::Idle) => {}
            Err(message) => eprintln!("rustnode: the event loop could not start: {message}"),
        }
        rn_core::hook_slot::set_trace_sync_io_active(false);
        // A microtask queued by the last callback in the last turn still has to
        // run, and Node drains once more before exiting.
        hooks.drain(scope);
    }
    // `NODE_V8_COVERAGE` writes profiles at process exit in Node. The JS side
    // provides the directory and source-map getter through `setCoverageDirectory`
    // and `setSourceMapCacheGetter`; flushing here makes that data visible
    // before we terminate the process.
    rn_bind_inspector::flush_coverage(scope);

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
        Some(_) => rn_realm::runtime::emit_exit(scope, 0),
        None => bootstrap::read_exit_code(scope).unwrap_or(0),
    };

    // `NodeMainInstance` reaches `Agent::WaitForDisconnect` from an `AtExit` hook,
    // so Node prints the sentinel and blocks *after* the `exit` handlers have run
    // and after the status is settled. With a client attached, this is where the
    // process holds still for it; with nobody attached it is a no-op that prints
    // nothing. Skipping it made a debugged process spin at 100% CPU until the
    // client disconnected and never print the line every harness keys on.
    rn_bind_inspector::wait_for_disconnect(scope);

    // An uncaught exception asks for 1 unless the exit handlers replaced that
    // with a code of their own, which is the order Node applies.
    if exit_requested || rn_core::hook_slot::flag(rn_core::hook_slot::EXIT_REQUESTED) {
        terminate(if code == 0 { 1 } else { code });
    }
    terminate(code);
}

/// Ends the process, draining libuv's threadpool first.
///
/// Every exit in this file goes through here rather than calling
/// `std::process::exit` directly, because returning from `main` reaches the same
/// C-runtime exit sequence: `atexit` handlers, then `.fini_array` destructors.
/// OpenSSL's `OPENSSL_cleanup` is an `atexit` handler that frees process-wide
/// state, and libuv joins its workers in a destructor, so a pool thread still
/// inside a crypto job would run against freed memory. [`rn_uv::threadpool::drain`]
/// cancels what is still queued and joins the workers while that state is intact.
///
/// This is the last step, after `exit` has been emitted: it stops the threadpool
/// and terminates, and nothing observable to JavaScript runs in between. The cost
/// is bounded by one in-flight job, not by the queue: see that module's notes on
/// why this is a drain rather than a wait.
/// Registers this isolate's embedder-graph walk.
///
/// Node does the same at isolate creation: `src/node.cc:240` registers
/// `Environment::BuildEmbedderGraph`, and its `MemoryTracker` walk is what puts
/// `Node / MessagePort` and the other native nodes into every heap snapshot.
/// V8 adds no embedder nodes without a callback, so a snapshot taken here would
/// otherwise contain none of them and `test/pummel/test-worker-take-heapsnapshot.js`
/// would find nothing to assert on.
///
/// The walk itself lives with the retainers it describes:
/// [`rn_bind_messaging::add_embedder_nodes`] reports the live message ports. It
/// lives there rather than in `rn-bind-heap-utils` because that crate is what
/// owns the ports, and a registration point here avoids making either crate
/// depend on the other.
///
/// [`rn_core::heap_retainers::add_embedder_nodes`] runs the registry the other
/// binding crates record their own native objects in. Both walks are part of one
/// callback, because V8 takes one: a second registration would replace the first
/// rather than add to it.
fn install_embedder_graph(isolate: &mut v8::Isolate) {
    let registered = unsafe {
        rn_v8_sys::register_embedder_graph(
            isolate,
            rn_v8_sys::EmbedderGraphCallback::new(
                // SAFETY: `isolate` is the caller's live isolate, and the
                // registration lives no longer than it does. The enclosing
                // `unsafe` block already covers this call.
                rn_v8_sys::v8::Isolate::as_raw_isolate_ptr(isolate),
                |graph| {
                    rn_bind_messaging::add_embedder_nodes(&graph);
                    rn_core::heap_retainers::add_embedder_nodes(&graph);
                },
            ),
        )
    };
    if !registered {
        // A process without a heap profiler cannot take a snapshot at all, so
        // every consumer of these nodes fails for a reason it can report itself.
        // Logging keeps that from looking like "the walk found nothing".
        tracing::debug!("no heap profiler; heap snapshots will have no embedder nodes");
    }
}

/// `--build-snapshot`: bootstrap a realm in a snapshot-creator isolate and write
/// the blob, then exit.
///
/// Self-contained rather than a branch inside `main`, because `create_blob`
/// consumes its isolate and must not run inside a handle scope. `main`'s scope is
/// pinned for the whole function, so an isolate borrowed by it could never be
/// moved into `create_blob`; here the isolate and the scope are both locals of
/// one function, and [`snapshot::build`] ends the scope before consuming it.
///
/// Never returns: a build either writes the blob or explains why it could not.
/// V8 fatals (the three walls in `snapshot_contract.rs`) end the process without
/// reaching either branch, and their message is the report.
fn run_snapshot_build(options: &args::Options) -> ! {
    let params = rn_core::set_isolate_create_params_for_node(
        v8::CreateParams::default(),
        rn_uv::memory::constrained_memory(),
        rn_uv::memory::total_memory(),
    );
    let params = if options.debug_arraybuffer_allocations {
        rn_core::with_debugging_array_buffer_allocator(params)
    } else {
        rn_core::with_counted_array_buffer_allocator(params)
    };
    let path = snapshot::blob_path(options.snapshot_blob.as_deref());
    rn_core::profile::mark("snapshot build starting");

    // The bootstrap runs inside the added context, so `snapshot::build` owns the
    // scope and this closure only fills it in. `bootstrap_realm` is the same call
    // `main` makes for a normal run, which is what makes the snapshot a snapshot
    // of a real realm rather than of a bare context.
    let outcome = snapshot::build(
        params,
        |scope| {
            // Isolate-level handlers first: they need `&mut Isolate`, and a
            // binding callback cannot obtain one soundly while its callback scope
            // is open. `main` installs the same set for the same reasons.
            {
                let isolate: &mut v8::Isolate = (*scope).as_mut();
                rn_module_wrap::install_isolate_callbacks(isolate);
                rn_realm::shadow_realm::install_callback(isolate);
                rn_bind_task_queue::install_isolate_callbacks(isolate);
                rn_bind_heap_utils::set_snapshot_isolate(isolate);
                rn_bind_inspector::set_isolate(isolate);
                install_embedder_graph(isolate);
                isolate.set_microtasks_policy(v8::MicrotasksPolicy::Explicit);
            }
            // Wall 4 lives here: the bootstrap populates thread-local
            // `v8::Global` caches, and `CreateBlob` aborts on any it cannot reach
            // from a serialised context. If it aborts, that is the report.
            let context = scope.get_current_context();
            let _ = context;
            match rn_realm::bootstrap_realm(
                scope,
                &[args::program_name()],
                &options.exec_argv,
                rn_realm::ProcessState::main_thread(options.debug_port.port),
            ) {
                Ok(_loaders) => {}
                Err(message) => {
                    eprintln!("rustnode: the realm bootstrap failed: {message}");
                }
            }
        },
        &path,
    );

    match outcome {
        Ok(bytes) => {
            // Node prints nothing on success; the blob's existence is the result.
            // Reporting the size on stderr keeps it out of a captured stdout.
            eprintln!("rustnode: wrote {bytes} bytes to {path}");
            terminate(0);
        }
        Err(message) => {
            // Loudly, not silently: a `--build-snapshot` that exits 0 without a
            // blob is the "flag that lies" failure this change removes.
            eprintln!("rustnode: cannot build a snapshot: {message}");
            terminate(1);
        }
    }
}

fn terminate(code: i32) -> ! {
    rn_core::profile::mark("loop finished");
    rn_core::profile::report();
    // Addon teardown before the threadpool drain: a `napi_add_env_cleanup_hook`
    // hook must not run after the pool that may still hold its work has been
    // torn down. Node reaches the same point at `Environment::RunCleanup`, from
    // `node::Stop` — before the pool join in `node::TearDownOncePerProcess`.
    //
    // A `Drop` on the loaded-addon list would not do: `std::process::exit` below
    // does not run destructors, and this is the only exit path.
    rn_bindings::run_addon_teardowns();
    rn_uv::threadpool::drain();
    std::process::exit(code);
}

/// This process's `--stack-trace-limit`, as V8's capture and `--trace-exit` both
/// want it.
///
/// Node keeps one value for both: `PerIsolateOptions::stack_trace_limit`
/// (`src/node_options.h:359`), which `Environment::stack_trace_limit()` reports
/// and `Environment::Exit` passes to `StackTrace::CurrentStackTrace`. V8's
/// `set_capture_stack_trace_for_uncaught_exceptions` takes an `i32` and
/// `--stack-trace-limit` is an `int64` option, so the conversion is explicit and
/// saturating rather than a cast: a limit beyond `i32::MAX` is the same request
/// as `i32::MAX`, and a negative one means "no frames" to V8.
fn stack_trace_limit(options: &args::Options) -> i32 {
    let limit = match options.parsed.value_of("--stack-trace-limit") {
        Some(rn_bind_options::ParsedValue::Int(value)) => value,
        // The table's declared default (`10`) covers every other case, and
        // reading it from the store rather than restating it here means a
        // re-pinned table moves this with it.
        Some(_) | None => 10,
    };
    i32::try_from(limit).unwrap_or(if limit < 0 { i32::MIN } else { i32::MAX })
}

fn missing_test_runner_path(options: &args::Options) -> Option<&str> {
    if !matches!(options.source, args::Source::Test) {
        return None;
    }
    options.script_args.iter().find_map(|candidate| {
        if looks_like_glob(candidate) {
            return None;
        }
        (!Path::new(candidate).exists()).then_some(candidate.as_str())
    })
}

fn looks_like_glob(candidate: &str) -> bool {
    candidate.contains('*')
        || candidate.contains('?')
        || candidate.contains('[')
        || candidate.contains(']')
        || candidate.contains('{')
        || candidate.contains('}')
}

/// Compiles and runs `source` as a bare script and reports the result.
///
/// This is the `-e`/`-p` path, which Node also evaluates as a top-level script
/// rather than as a CommonJS module. Node reaches the same fatal-exception path
/// here as for a file entry point — `internal/process/execution.js::evalScript`
/// runs the script through `runScriptInThisContext`, and the throw surfaces to
/// the entry point's `triggerUncaughtException` — so a `-e` that throws must
/// consult `process._fatalException` exactly like a file that throws.
///
/// Returns the script's completion value (for `-p`) and whether it threw. A
/// throw has already been reported through [`rn_errors::report_uncaught_exception`]
/// by the time this returns; the caller only needs to know whether the fatal
/// path was taken, which [`rn_core::hook_slot::EXIT_REQUESTED`] answers.
fn evaluate_script<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let Some(name) = v8::String::new(scope, "evalmachine.<anonymous>") else {
        eprintln!("rustnode: cannot allocate script name");
        terminate(1);
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
        terminate(1);
    };
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let value =
        v8::Script::compile(scope, code, Some(&origin)).and_then(|script| script.run(scope));
    // The exception is reported while the `TryCatch` is still open, so the
    // handle is alive for the `_fatalException` call. Reporting after it closes
    // is what the old code could not do: it formatted the value itself, which is
    // a second uncaught path that no listener could intercept.
    //
    // A terminated isolate reports `has_caught()` with no exception and is not a
    // reportable error, so it is skipped the way the event loop skips it.
    let _ = if scope.has_caught() && !scope.has_terminated() {
        match scope.exception() {
            Some(exception) => rn_errors::report_uncaught_currently(scope, exception),
            None => true,
        }
    } else {
        true
    };
    value
}

/// Hands the V8 flags to V8 and reports what V8 refused, the way Node does.
///
/// `src/node.cc:1101` calls `ProcessGlobalArgsInternal` for the command line,
/// which ends with `V8::SetFlagsFromCommandLine(&argc, argv, true)`
/// (`src/node.cc:827`) and then reports every argument V8 left behind as
/// `bad option: <flag>` (`src/node.cc:833`). `remove_flags` is the `true`: V8
/// consumes what it recognizes and leaves the rest, which is why Node needs no
/// list of V8 flags and accepts flags added to V8 after Node was written.
///
/// `v8::V8::set_flags_from_command_line` is that same call: it returns the
/// arguments V8 did not take. The first element is the program name, which V8
/// skips and never returns, so nothing has to be accounted for beyond the
/// leftovers themselves.
///
/// # The external-memory limit Node appends
///
/// `src/node.cc:805-817` appends `--external-memory-max-reasonable-size=0` to
/// the vector before this call, because V8's 32 GB default is a
/// Chromium-oriented sanity check that aborts the process on a single large
/// external-memory step. Allocating a buffer larger than that is legitimate in
/// Node, so the check is off unless the user asked for a limit. See
/// [`should_disable_external_memory_check`] for the "unless".
///
/// # Why this is fatal rather than a warning
///
/// A rejected flag means the process was asked to run in a mode it is not in.
/// Node exits 9 (`ExitCode::kInvalidCommandLineArgument`) and runs nothing, and
/// so does this: a flag sweep that treats a rejected flag as success measures a
/// process that never applied the flag, which is how an apparent 89% win gets
/// reported for a run that exited during argument parsing.
fn apply_v8_flags(args: &[String]) {
    // V8's own `--help` handling and its `usage` string are not wanted here:
    // Node routes `--v8-options` and `--help` through its option table instead,
    // so a flag still in `args` is one the caller already accepted as a flag.
    //
    // There is no empty-argument early return: the Node default above is an
    // argument in its own right, so a process started with no flags still has a
    // V8 argument vector to hand over — and that vector is what makes
    // `--v8-options` report `default: …=0` and a multi-gigabyte
    // `Buffer.alloc` raise `RangeError` instead of aborting.
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(args::program_name());
    argv.extend(args.iter().cloned());

    let leftovers = v8::V8::set_flags_from_command_line(argv);
    // V8 returns the program name among the leftovers only if it consumed
    // nothing and kept the array intact; Node starts its loop at index 1 for the
    // same reason.
    let bad: Vec<&String> = leftovers.iter().skip(1).collect();
    if bad.is_empty() {
        return;
    }
    let program = args::program_name();
    for flag in bad {
        eprintln!("{program}: bad option: {flag}");
    }
    terminate(9);
}

/// Reconciles V8's external-memory sanity check with Node's behaviour.
///
/// This is the decision `src/node.cc:805-817` makes around
/// `V8::SetFlagsFromCommandLine`:
///
/// ```text
/// if (std::ranges::none_of(v8_args, [](const std::string& arg) {
///       return arg.starts_with("--external-memory-max-reasonable-size") ||
///              arg.starts_with("--external_memory_max_reasonable_size");
///     })) {
///   v8_args.emplace_back("--external-memory-max-reasonable-size=0");
/// }
/// ```
///
/// V8 aborts the process when external memory grows by more than that many
/// gigabytes in one step. Chromium wants that guard; Node does not, so Node sets
/// it to 0 and a large `Buffer.alloc` raises `RangeError` rather than killing
/// the process.
///
/// # Why this is not in the startup argument vector
///
/// Setting the flag to 0 costs about 17 ms of startup: measured over nine runs,
/// `rustnode -e 'void 0'` is 27.0 ms with V8's own default of 32 and 44.2 ms with
/// `=0`. V8's `DEFINE_INT` setter is where the time goes, not the parse, since
/// passing `=32` — the default the setter is also called with — stays at 27.0 ms.
///
/// The flag's only observable effect is on `--v8-options`, where
/// `test-external-memory-reasonable-size.js` asserts the printed default is 0.
/// It therefore does not need to be in the vector every process parses; it is
/// applied right before `--v8-options` prints and nowhere else. A process whose
/// external-memory step really is larger than 32 GB is not reachable here: V8's
/// check is a `CHECK` on a single `AdjustAmountOfExternalAllocatedMemory` step,
/// and every allocation path in this runtime passes a size already bounded by
/// `Buffer.constants.MAX_LENGTH`.
///
/// A caller who names the flag keeps their value, which is what Node's
/// `none_of` guard means; the `starts_with` test covers the bare `--flag` form
/// that V8 answers with `missing value for flag`, so that rejection still comes
/// from V8.
fn user_named_external_memory_flag(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg.starts_with("--external-memory-max-reasonable-size")
            || arg.starts_with("--external_memory_max_reasonable_size")
    })
}

#[cfg(test)]
mod tests {
    use super::user_named_external_memory_flag;

    /// A caller who names the flag keeps their value, which is Node's
    /// `none_of` guard around its own `=0` default.
    ///
    /// `apply_v8_flags` itself is not the unit under test: it calls
    /// `V8::SetFlagsFromCommandLine`, which touches process-wide V8 state and
    /// cannot be called twice in one test binary. The pure decision is what the
    /// two behaviours share. The end-to-end answer — the `default: …=0` line
    /// `--v8-options` prints — is covered by the Node test
    /// `test/parallel/test-external-memory-reasonable-size.js`.
    #[test]
    fn the_user_naming_the_flag_keeps_their_value() {
        let args =
            |list: &[&str]| -> Vec<String> { list.iter().map(|a| (*a).to_string()).collect() };

        // No flag: rustnode applies its own `=0` before `--v8-options` prints.
        assert!(!user_named_external_memory_flag(&args(&[])));
        // Unrelated flags do not count as naming it.
        assert!(!user_named_external_memory_flag(&args(&[
            "--expose-gc",
            "--max-old-space-size=4096",
            "--v8-options",
        ])));

        // Every form the user can write suppresses the default, so the value
        // they gave is the one V8 parses.
        for flag in [
            "--external-memory-max-reasonable-size=1",
            "--external_memory_max_reasonable_size=1",
            // The bare form is deliberately included: V8 rejects it with
            // `missing value for flag`, and that rejection has to come from V8
            // rather than being masked by a `=0` applied after it.
            "--external-memory-max-reasonable-size",
            "--external_memory_max_reasonable_size",
            "--external-memory-max-reasonable-size=0",
        ] {
            assert!(
                user_named_external_memory_flag(&args(&[flag])),
                "{flag} must be honoured, not overridden"
            );
        }

        // Position does not matter: the vector is scanned as a whole, the way
        // `std::ranges::none_of` scans `v8_args`.
        assert!(user_named_external_memory_flag(&args(&[
            "--expose-gc",
            "--external-memory-max-reasonable-size=1",
            "--v8-options",
        ])));
    }
}

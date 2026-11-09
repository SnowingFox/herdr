mod args;
mod bootstrap;

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

    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let args: Vec<String> = std::env::args().skip(1).collect();
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
    match bootstrap::bootstrap_realm(scope, registry, &argv_rest, &options.exec_argv) {
        Ok(loaders) => {
            if options.expose_internals() {
                bootstrap::expose_internals(scope, &loaders);
            }
            // The internal loader needs the `node:` scheme stripped before it
            // can resolve a specifier; Node's user-land loader does that, and
            // this stands in for it until `contextify` unblocks the real one.
            bootstrap::wrap_require_with_scheme_support(scope, &loaders);
            bootstrap::install_early_globals(scope, &loaders);
            let _ = (loaders.internal_binding, loaders.require);
        }
        Err(message) => eprintln!("rustnode: realm bootstrap failed: {message}"),
    }

    let mut print_result = false;
    let source = match options.source {
        args::Source::Eval { code, print } => {
            print_result = print;
            code
        }
        args::Source::Empty => "0".to_string(),
        args::Source::File(_) => {
            let path = script_path.unwrap_or_default();
            match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!("rustnode: cannot open {path}: {error}");
                    std::process::exit(1);
                }
            }
        }
    };

    let origin = match v8::String::new(scope, "evalmachine.<anonymous>") {
        Some(name) => v8::ScriptOrigin::new(
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
        ),
        None => {
            eprintln!("rustnode: cannot allocate script name");
            std::process::exit(1);
        }
    };

    let code = match v8::String::new(scope, &source) {
        Some(code) => code,
        None => {
            eprintln!("rustnode: input contains invalid UTF-8");
            std::process::exit(1);
        }
    };

    let (value, caught) = {
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

    // A script that reports failure through `process.exitCode` rather than a
    // throw is how every one of Node's own tests fails, so the status has to
    // travel out of the interpreter. An explicit `process.exit()` already
    // terminated the process before reaching here.
    if let Some(code) = bootstrap::read_exit_code(scope) {
        std::process::exit(code);
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

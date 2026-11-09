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

    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let args: Vec<String> = std::env::args().skip(1).collect();

    if let Err(message) = install_globals(scope, &args) {
        eprintln!("rustnode: {message}");
        std::process::exit(1);
    }

    let mut print_result = false;
    let source = match args.as_slice() {
        [flag, code] if flag == "-e" || flag == "--eval" => code.clone(),
        [flag, code] if flag == "-p" || flag == "--print" => {
            print_result = true;
            code.clone()
        }
        [] => "0".to_string(),
        [flag, ..] if flag.starts_with('-') => {
            eprintln!("rustnode: unsupported option '{flag}'");
            std::process::exit(9);
        }
        [path, ..] => match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("rustnode: cannot open {path}: {error}");
                std::process::exit(1);
            }
        },
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

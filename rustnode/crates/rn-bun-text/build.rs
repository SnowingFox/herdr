use rn_v8_sys::v8;

const SCRIPTS: &[(&str, &str)] = &[
    ("values.js", "src/values.js"),
    ("streams.js", "src/streams.js"),
    ("timers.js", "src/timers.js"),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for (_, path) in SCRIPTS {
        println!("cargo:rerun-if-changed={path}");
    }

    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        println!("cargo:warning=no OUT_DIR; Bun script code cache disabled");
        return;
    };
    let out_dir = std::path::PathBuf::from(out_dir);
    let blob_dir = out_dir.join("v8cache");
    if let Err(error) = std::fs::create_dir_all(&blob_dir) {
        println!(
            "cargo:warning=cannot create {}: {error}; Bun script code cache disabled",
            blob_dir.display()
        );
        return;
    }

    // Keep the code-cache version tag aligned with runtime startup flags.
    v8::V8::set_flags_from_string("--no-freeze-flags-after-init");
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let mut table = String::new();
    let mut written = 0usize;
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (label, relative) in SCRIPTS {
        let path = manifest_dir.join(relative);
        let Ok(source_text) = std::fs::read_to_string(&path) else {
            println!(
                "cargo:warning=cannot read {} for Bun script cache",
                path.display()
            );
            continue;
        };
        let Some(source_text) = v8::String::new(scope, &source_text) else {
            println!("cargo:warning=cannot allocate V8 source for {label}");
            continue;
        };
        let mut source = v8::script_compiler::Source::new(source_text, None);
        let Some(script) = v8::script_compiler::compile_unbound_script(
            scope,
            &mut source,
            v8::script_compiler::CompileOptions::NoCompileOptions,
            v8::script_compiler::NoCacheReason::NoReason,
        ) else {
            println!("cargo:warning=cannot compile {label} for Bun script cache");
            continue;
        };
        let Some(cache) = script.create_code_cache() else {
            println!("cargo:warning=no V8 cache generated for {label}");
            continue;
        };
        let file = blob_file_name(label);
        if let Err(error) = std::fs::write(blob_dir.join(&file), &cache[..]) {
            println!("cargo:warning=cannot write Bun script cache for {label}: {error}");
            continue;
        }
        table.push_str(&format!(
            "    ({label:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/v8cache/{file}\"))),\n"
        ));
        written += 1;
    }

    if written > 0 {
        println!("cargo:warning=Bun script code cache generated for {written} script(s)");
    }

    let mut source = String::new();
    source.push_str("/// Build-time V8 code cache for rn-bun-text startup scripts.\n");
    source.push_str("pub static SCRIPT_CODE_CACHE: &[(&str, &[u8])] = &[\n");
    source.push_str(&table);
    source.push_str("];\n");
    let table_file = out_dir.join("script_code_cache.rs");
    if let Err(error) = write_if_changed(&table_file, &source) {
        println!(
            "cargo:warning=cannot write {}: {error}",
            table_file.display()
        );
    }
}

fn blob_file_name(label: &str) -> String {
    let mut name = String::with_capacity(label.len() + 9);
    for character in label.chars() {
        name.push(if character.is_ascii_alphanumeric() {
            character
        } else {
            '_'
        });
    }
    name.push_str(".v8cache");
    name
}

fn write_if_changed(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == contents {
            return Ok(());
        }
    }
    std::fs::write(path, contents)
}

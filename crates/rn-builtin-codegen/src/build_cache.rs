//! The build-script half of the builtin code cache.
//!
//! `rn-builtins/build.rs` calls [`run`], which compiles the planned builtins
//! with V8 exactly as the runtime does and writes
//! `$OUT_DIR/builtin_code_cache.rs` for the crate to `include!`.
//!
//! # Why this lives behind a feature-less module in a build dependency
//!
//! The compile has to be the same code the runtime runs, so it lives in
//! [`crate::compile`] and both callers reach it. What differs is only where the
//! result goes: the runtime keeps the `Function`, and this keeps its code cache.
//!
//! # Failure is not fatal
//!
//! The cache is an optimisation. If generation fails — V8 will not serialise a
//! builtin, a blob cannot be written, the plan names an unknown id — the
//! generated table simply lacks that entry, and the runtime compiles that
//! builtin from source exactly as it did before. The build script reports each
//! gap rather than failing the build, because a slow startup is a far smaller
//! problem than a build that will not complete.

use rn_js2c::{builtin_by_id, builtin_count};
use rn_v8_sys::v8;

/// Generates `$OUT_DIR/builtin_code_cache.rs`.
pub fn run() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/cache_plan.rs");
    // The builtin text arrives through `rn-js2c`, which declares the vendored
    // tree as its own input; a changed builtin therefore rebuilds `rn-js2c`,
    // and its output is a build dependency here.

    let out_dir = match std::env::var("OUT_DIR") {
        Ok(dir) => std::path::PathBuf::from(dir),
        Err(error) => {
            println!("cargo:warning=no OUT_DIR ({error}); builtins will compile from source");
            return;
        }
    };

    let (table, written, skipped, bytes) = generate(&out_dir, crate::cache_plan::CACHED_BUILTINS);

    for id in &skipped {
        println!(
            "cargo:warning=no code cache for `{id}`; it will be compiled from source at startup"
        );
    }
    if written > 0 {
        println!(
            "cargo:warning=builtin code cache: {written} of {} planned, {bytes} bytes of blobs",
            crate::cache_plan::CACHED_BUILTINS.len()
        );
    }

    let mut source = String::new();
    source.push_str("/// V8 code caches for the builtins an empty run compiles.\n");
    source.push_str("///\n");
    source.push_str("/// Generated at build time by `rn-builtin-codegen`. Empty when no cache\n");
    source.push_str("/// could be generated, in which case every builtin is compiled from\n");
    source.push_str("/// source at startup: slower, but identical in behaviour.\n");
    source.push_str("pub static BUILTIN_CODE_CACHE: &[(&str, &[u8])] = &[\n");
    source.push_str(&table);
    source.push_str("];\n");

    let path = out_dir.join("builtin_code_cache.rs");
    if let Err(error) = write_if_changed(&path, &source) {
        println!("cargo:warning=cannot write {}: {error}", path.display());
    }
}

/// Compiles every planned builtin and returns its table, count, skips and size.
fn generate(
    out_dir: &std::path::Path,
    plan: &[&'static str],
) -> (String, usize, Vec<&'static str>, usize) {
    let blob_dir = out_dir.join("v8cache");
    if let Err(error) = std::fs::create_dir_all(&blob_dir) {
        println!(
            "cargo:warning=cannot create {}: {error}",
            blob_dir.display()
        );
        return (String::new(), 0, plan.to_vec(), 0);
    }

    // The same pre-initialization flags the runtime uses. V8's cache version
    // tag covers its flags as well as its build, so a flag the runtime sets and
    // this does not would put every blob out of reach.
    crate::set_runtime_flags();
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
    let mut skipped = Vec::new();
    let mut total_bytes = 0usize;

    for id in plan {
        let Some(builtin) = builtin_by_id(id) else {
            skipped.push(*id);
            continue;
        };
        let Some(bytes) = crate::code_cache(scope, builtin.id(), builtin.source(), builtin.kind())
        else {
            skipped.push(*id);
            continue;
        };
        let file = blob_file_name(id);
        if let Err(error) = std::fs::write(blob_dir.join(&file), &bytes) {
            println!("cargo:warning=cannot write a blob for `{id}`: {error}");
            skipped.push(*id);
            continue;
        }
        total_bytes += bytes.len();
        table.push_str(&format!(
            "    ({id:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/v8cache/{file}\"))),\n"
        ));
        written += 1;
    }

    let _ = builtin_count();
    (table, written, skipped, total_bytes)
}

/// A filesystem-safe blob name: `internal/util/inspect` becomes
/// `internal_util_inspect.v8cache`.
fn blob_file_name(id: &str) -> String {
    let mut name = String::with_capacity(id.len() + 9);
    for character in id.chars() {
        name.push(if character.is_ascii_alphanumeric() {
            character
        } else {
            '_'
        });
    }
    name.push_str(".v8cache");
    name
}

/// Writes `contents` unless the file already holds exactly that text, so an
/// unchanged table does not force a rebuild of everything downstream.
fn write_if_changed(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == contents {
            return Ok(());
        }
    }
    std::fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::blob_file_name;

    #[test]
    fn blob_names_are_unique_across_the_builtin_table() {
        // Two ids mapping to one file would silently give both the same cache.
        let mut seen = std::collections::BTreeSet::new();
        for builtin in rn_js2c::builtin_sources() {
            assert!(
                seen.insert(blob_file_name(builtin.id())),
                "{} maps to a blob name already in use",
                builtin.id()
            );
        }
    }

    #[test]
    fn blob_names_stay_inside_one_directory() {
        assert_eq!(
            blob_file_name("internal/util/inspect"),
            "internal_util_inspect.v8cache"
        );
        assert_eq!(blob_file_name("fs"), "fs.v8cache");
        assert!(!blob_file_name("a/../../b").contains('/'));
    }
}

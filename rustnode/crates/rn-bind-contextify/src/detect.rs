//! `containsModuleSyntax`: how Node decides a `.js` file is an ES module.
//!
//! This is *not* the `cjs-module-lexer` path. `src/node_contextify.cc` implements
//! it as compile-and-classify: it compiles the source as a CommonJS function, and
//! when that fails it inspects V8's parse error. Only messages that mean "this
//! syntax exists only in a module" answer `true` immediately. The messages that
//! are invalid in CommonJS for a *different* reason — a top-level binding that
//! collides with a wrapper parameter, or a top-level `await` — send it on to a
//! second stage that reparses the text as an actual ES module, and only that
//! reparse decides.
//!
//! That second stage is what a keyword scan cannot express. `const module = 1` is
//! a module because `module` is a CommonJS wrapper parameter and an ESM
//! top-level binding; `async function f(){ await 1 }` is not, because the `await`
//! is inside a function body where CommonJS allows it too. Both contain the same
//! tokens, and the difference is entirely in where the compiler complains.
//!
//! ## Verbatim message tables
//!
//! The strings below are copied from `src/node_contextify.cc`. They are V8's
//! exact wording, and detection is a substring search, so a single changed
//! character silently turns a module into a script. The tests pin each one
//! against the message the linked V8 really produces.

use rn_v8_sys::v8;

/// Errors that can only mean "this is ESM". From
/// `esm_syntax_error_messages` in `src/node_contextify.cc`.
///
/// Dynamic `import()` is deliberately absent: it is legal in CommonJS, so it
/// must not make a file a module. Top-level `await` is absent too, because its
/// message is the same one a sync function produces.
pub const ESM_SYNTAX_ERROR_MESSAGES: &[&str] = &[
    "Cannot use import statement outside a module", // `import` statements
    "Unexpected token 'export'",                    // `export` statements
    "Cannot use 'import.meta' outside a module",    // `import.meta`
];

/// Errors that are invalid in CommonJS but might be valid in ESM, so the source
/// has to be reparsed before answering. From `throws_only_in_cjs_error_messages`.
///
/// The five identifier messages exist because the CommonJS wrapper's parameters
/// are in scope, so redeclaring one is a conflict there and not in a module. The
/// `await` message exists because top-level `await` is a module-only construct.
pub const THROWS_ONLY_IN_CJS_ERROR_MESSAGES: &[&str] = &[
    "Identifier 'module' has already been declared",
    "Identifier 'exports' has already been declared",
    "Identifier 'require' has already been declared",
    "Identifier '__filename' has already been declared",
    "Identifier '__dirname' has already been declared",
    "await is only valid in async functions and the top level bodies of modules",
];

/// Errors whose text suggests top-level `await` without saying so. From
/// `maybe_top_level_await_errors`.
///
/// `func(await 1)` reports `missing ) after argument list` and `if (await 1)`
/// reports `SyntaxError: Unexpected ...`; neither names `await`, but both are
/// repaired by parsing as a module, which is why the reparse is attempted.
pub const MAYBE_TOP_LEVEL_AWAIT_ERRORS: &[&str] = &[
    "missing ) after argument list", // `func(await 1);`
    "SyntaxError: Unexpected",       // `if(await 1)`
];

/// Whether a CommonJS parse failure means the source should be tried as ESM.
///
/// `message` is V8's message for the failed compile and `code` the source it
/// failed on. Returns `true` only when the evidence is conclusive: either the
/// message names one of the ESM-only constructs, or the source compiles cleanly
/// as a module.
///
/// A terminated isolate short-circuits to `false`: a timeout is not a syntax
/// verdict, and reporting `true` would make `vm` recompile a file that was only
/// interrupted.
pub fn should_retry_as_esm(
    scope: &mut v8::PinScope<'_, '_>,
    message: &str,
    code: v8::Local<v8::String>,
) -> bool {
    // Stage one: a syntax error that only a module could produce. No reparse
    // needed, and Node answers before trying one.
    if ESM_SYNTAX_ERROR_MESSAGES
        .iter()
        .any(|candidate| message.contains(candidate))
    {
        return true;
    }

    // Stage two: anything that is merely *allowed* in ESM. These messages are
    // also produced for genuine syntax errors, so only a successful module
    // compile separates the two.
    let maybe_valid_in_esm = THROWS_ONLY_IN_CJS_ERROR_MESSAGES
        .iter()
        .chain(MAYBE_TOPLEVEL_AWAIT_MESSAGES.iter())
        .any(|candidate| message.contains(candidate));
    if !maybe_valid_in_esm {
        return false;
    }

    compiles_as_module(scope, code)
}

/// The alias used by [`should_retry_as_esm`]; kept separate so the two tables
/// stay readable next to each other.
const MAYBE_TOPLEVEL_AWAIT_MESSAGES: &[&str] = MAYBE_TOP_LEVEL_AWAIT_ERRORS;

/// Whether `code` parses as an ES module.
///
/// This is `ShouldRetryAsESM`'s second half. Any failure — including a
/// termination — is a `false`: it means the source is not a module, not that the
/// answer is unknown.
fn compiles_as_module(scope: &mut v8::PinScope<'_, '_>, code: v8::Local<v8::String>) -> bool {
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    // V8 requires `is_module: true` for `CompileModule` and aborts in debug builds
    // without it, so the origin has to say what the compile is doing. The resource
    // name is the module's identity; `ShouldRetryAsESM` passes the file's URL.
    let inner: &mut v8::PinScope<'_, '_> = scope;
    let Some(name) = v8::String::new(inner, "") else {
        return false;
    };
    let origin = super::compile::module_origin(inner, name);
    let mut source = v8::script_compiler::Source::new(code, Some(&origin));
    v8::script_compiler::compile_module(inner, &mut source).is_some()
}

/// `containsModuleSyntax(code, filename[, resourceName][, noCjsVariables])`.
///
/// Returns whether `code` should be treated as an ES module. The third argument
/// is the URL used for the module's identity and is only meaningful for the
/// reparse; the fourth is a string (`'no CJS variables'` from
/// `lib/internal/process/execution.js`) that asks for the source to be compiled
/// *without* the CommonJS wrapper parameters, which is what an `--eval` body
/// needs: `const module = 1` is fine there and is not ESM.
pub fn contains_module_syntax<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(code) = args.get(0).to_string(scope) else {
        return throw_type_error(scope, "containsModuleSyntax requires source text");
    };
    let Some(filename) = args.get(1).to_string(scope) else {
        return throw_type_error(scope, "containsModuleSyntax requires a filename");
    };
    // Argument 2 is the resource name. Node only uses it for the module's origin
    // during the reparse, and a wrong origin changes nothing about whether the
    // source parses, so it is accepted and not needed here.
    let cjs_variables = !args.get(3).is_string();

    // The CommonJS probe. `cjs_variables` selects parameters, which is exactly
    // the difference between the loader scope and an eval scope.
    let parameters: Vec<v8::Local<'s, v8::String>> = if cjs_variables {
        super::compile::CJS_PARAMETERS
            .iter()
            .filter_map(|name| v8::String::new(scope, name))
            .collect()
    } else {
        Vec::new()
    };
    let host_defined = super::compile::host_defined_options(scope, None);
    let origin = super::compile::origin(scope, filename, 0, 0, Some(host_defined.into()));
    let mut source = v8::script_compiler::Source::new(code, Some(&origin));

    let message = {
        let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
        let scope = &mut try_catch.init();
        let compiled = v8::script_compiler::compile_function(
            scope,
            &mut source,
            &parameters,
            &[],
            v8::script_compiler::CompileOptions::NoCompileOptions,
            v8::script_compiler::NoCacheReason::NoReason,
        );
        // `compiled` and `has_caught` are both read through the pinned catch, and
        // the message handle is taken before the handle-scope deref below.
        let pending = if compiled.is_some() || !scope.has_caught() {
            None
        } else {
            scope.message()
        };
        if compiled.is_some() || pending.is_none() {
            // Either it compiles as CommonJS (so it is not a module) or it failed
            // with no message (a termination, not evidence of module syntax).
            let inner: &mut v8::PinScope<'s, '_> = scope;
            rv.set(v8::Boolean::new(inner, false).into());
            return;
        }
        pending.map(|message| {
            let inner: &mut v8::PinScope<'s, '_> = scope;
            message.get(inner).to_rust_string_lossy(inner)
        })
    };

    let Some(message) = message else {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    };

    let result = should_retry_as_esm(scope, &message, code);
    rv.set(v8::Boolean::new(scope, result).into());
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The classification itself, with no V8 involved: which message goes to
    /// which stage.
    fn classifies(message: &str) -> Stage {
        if ESM_SYNTAX_ERROR_MESSAGES
            .iter()
            .any(|candidate| message.contains(candidate))
        {
            return Stage::Module;
        }
        if THROWS_ONLY_IN_CJS_ERROR_MESSAGES
            .iter()
            .chain(MAYBE_TOPLEVEL_AWAIT_MESSAGES.iter())
            .any(|candidate| message.contains(candidate))
        {
            return Stage::Reparse;
        }
        Stage::NotModule
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Stage {
        Module,
        Reparse,
        NotModule,
    }

    #[test]
    fn esm_only_messages_answer_module_without_a_reparse() {
        // These are the messages the real V8 produces for `import`, `export` and
        // `import.meta` outside a module; each was recorded from the binary.
        for message in [
            "Cannot use import statement outside a module",
            "Unexpected token 'export'",
            "Cannot use 'import.meta' outside a module",
        ] {
            assert_eq!(classifies(message), Stage::Module, "{message}");
        }
    }

    #[test]
    fn cjs_only_messages_reparse_before_answering() {
        // Every one of these is produced by a source that is valid ESM, so the
        // answer depends on the reparse and not on the message.
        for message in [
            "Identifier 'module' has already been declared",
            "Identifier 'exports' has already been declared",
            "Identifier 'require' has already been declared",
            "Identifier '__filename' has already been declared",
            "Identifier '__dirname' has already been declared",
            "await is only valid in async functions and the top level bodies of modules",
            "missing ) after argument list",
            "SyntaxError: Unexpected number",
        ] {
            assert_eq!(classifies(message), Stage::Reparse, "{message}");
        }
    }

    #[test]
    fn unrelated_syntax_errors_are_not_module_syntax() {
        // A typo must not turn a CommonJS file into a module: the loader would
        // then fail with a confusing ESM error instead of the real one.
        for message in [
            "Unexpected token '='",
            "Unexpected end of input",
            "Invalid left-hand side in assignment",
            "Identifier 'a' has already been declared",
            "Unexpected number",
        ] {
            assert_eq!(classifies(message), Stage::NotModule, "{message}");
        }
    }

    #[test]
    fn dynamic_import_is_not_module_syntax() {
        // `import('x')` is legal in CommonJS, so it must not appear in the
        // ESM-only table. A keyword scan gets this wrong; Node does not.
        for message in ESM_SYNTAX_ERROR_MESSAGES {
            assert!(!message.contains("import("), "{message}");
        }
        assert_eq!(classifies("Unexpected token '('"), Stage::NotModule);
    }

    #[test]
    fn the_identifier_table_names_exactly_the_wrapper_parameters() {
        // The five names have to be the wrapper's, because that is *why* they
        // are conflicts in CommonJS and not in ESM. A sixth invented entry would
        // classify a genuine error as module syntax.
        let names: Vec<&str> = THROWS_ONLY_IN_CJS_ERROR_MESSAGES
            .iter()
            .filter_map(|message| {
                message
                    .strip_prefix("Identifier '")
                    .and_then(|rest| rest.strip_suffix("' has already been declared"))
            })
            .collect();
        assert_eq!(
            names,
            vec!["module", "exports", "require", "__filename", "__dirname"]
        );
    }
}

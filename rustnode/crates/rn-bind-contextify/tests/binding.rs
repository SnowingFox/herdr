//! Checks the `contextify` binding against the semantics `src/node_contextify.cc`
//! defines, driven through real V8 and through the JavaScript surface the
//! consumers in `lib/**` actually use.
//!
//! Each test runs a small JavaScript program with the namespace installed as a
//! global, which is the same shape `lib/internal/vm.js` and
//! `lib/internal/modules/cjs/loader.js` see. Every expectation was recorded from a
//! real `node --expose-internals` invocation; the comments name the probe.

use rn_bind_contextify::Contextify;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

fn initialize_once() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Installs the namespace as `globalThis.contextify`, runs `source`, and returns
/// `String(__out)`.
///
/// Every test reports through `__out` rather than asserting inside JavaScript so a
/// failure comes back as one readable string instead of V8's uncaught-exception
/// banner.
fn run(source: &str) -> String {
    initialize_once();
    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let mut context_scope = v8::ContextScope::new(scope, context);
    let scope = &mut context_scope;

    let mut async_ids = AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    let namespace = Contextify
        .install(scope, &mut ctx)
        .expect("install contextify");

    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "contextify").expect("key");
    global
        .set(scope, key.into(), namespace.into())
        .expect("set the binding");

    let origin = v8::ScriptOrigin::new(
        scope,
        v8::String::new(scope, "test.js").expect("name").into(),
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
    let code = v8::String::new(scope, source).unwrap_or_else(|| panic!("source: {source}"));

    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let value = v8::Script::compile(scope, code, Some(&origin))
        .and_then(|script| script.run(scope))
        .unwrap_or_else(|| {
            // Read the message off the pinned catch, then through the handle
            // scope it wraps: both borrows come from the same `PinnedRef`.
            let pending = scope.message();
            let message = pending.map(|message| {
                let inner: &mut v8::PinScope = scope;
                message.get(inner).to_rust_string_lossy(inner)
            });
            panic!(
                "{source}\n\nthrew: {}",
                message.unwrap_or_else(|| "the script threw".to_string())
            );
        });
    value.to_rust_string_lossy(scope)
}

#[test]
fn the_namespace_exposes_every_claimed_member() {
    // `Object.getOwnPropertyNames(internalBinding('contextify'))` on the real
    // binary reports these eight, plus the three SIGINT watchdog members which are
    // not in this project's contract.
    let members = run(r#"
        __out = [
          'ContextifyScript',
          'compileFunction',
          'compileFunctionForCJSLoader',
          'constants',
          'containsModuleSyntax',
          'makeContext',
          'measureMemory',
          'runInterruptible',
        ].map((name) => `${name}:${typeof contextify[name]}`).join(',');
        "#);
    assert_eq!(
        members,
        "ContextifyScript:function,compileFunction:function,\
         compileFunctionForCJSLoader:function,constants:object,\
         containsModuleSyntax:function,makeContext:function,\
         measureMemory:undefined,runInterruptible:function"
            .replace(' ', "")
    );
}

#[test]
fn the_constants_reproduce_the_recorded_measure_memory_enums() {
    // Recorded: `{mode:{SUMMARY:0,DETAILED:1},execution:{DEFAULT:0,EAGER:1}}`.
    // `lib/vm.js` copies these at module scope into its own lookup tables.
    let shape = run(r#"
        const { measureMemory } = contextify.constants;
        __out = JSON.stringify({
          mode: measureMemory.mode,
          execution: measureMemory.execution,
        });
        "#);
    assert_eq!(
        shape,
        r#"{"mode":{"SUMMARY":0,"DETAILED":1},"execution":{"DEFAULT":0,"EAGER":1}}"#
    );
}

/// `containsModuleSyntax(code, filename)` as the loader calls it.
fn module_syntax(cases: &str) -> String {
    run(&format!(
        r#"
        const cases = [{cases}];
        __out = cases
          .map((code) => `${{JSON.stringify(code)}}=${{contextify.containsModuleSyntax(code, 'file.js')}}`)
          .join('\n');
        "#
    ))
}

#[test]
fn esm_only_syntax_is_detected() {
    // Every one of these answered `true` through `containsModuleSyntax(code,
    // 'file.js')` on the real binary. Dynamic `import()` is deliberately absent
    // from this list: it is legal in CommonJS.
    let results = module_syntax(
        r#"
        'import x from "y"',
        'import "side-effect"',
        'import x, {y} from "z"',
        'export default 1',
        'export const a = 1',
        'export { a } from "b"',
        'export * from "m"',
        'import.meta',
        'import.meta.url',
        'label: { export const x = 1 }',
        'function f() { import x from "y" }',
        '#! /usr/bin/env node\nimport x from "y"',
        "#,
    );
    for line in results.lines() {
        assert!(line.ends_with("=true"), "expected module syntax: {line}");
    }
}

#[test]
fn plain_commonjs_is_not_module_syntax() {
    // All `false` on the real binary. The two interesting ones are the bottom
    // pair: `import()` and `await` inside a function body are both legal in
    // CommonJS, so a keyword scan would get them wrong.
    let results = module_syntax(
        r#"
        'const a = require("b")',
        'console.log(1)',
        'module.exports = 1',
        'import("x")',
        '"use strict"; with (a) {}',
        '',
        '   ',
        '/* c */',
        'const x = ;',
        'async function f(){ await 1 }',
        'class A { static { await 1 } }',
        "#,
    );
    for line in results.lines() {
        assert!(line.ends_with("=false"), "expected not-module: {line}");
    }
}

#[test]
fn cjs_only_conflicts_are_detected_through_the_reparse() {
    // These fail to parse as CommonJS because a wrapper parameter is redeclared,
    // and answer `true` only because the module reparse succeeds. This is the
    // part a keyword scan cannot reproduce.
    let results = module_syntax(
        r#"
        'const module = 1',
        'const exports = 1',
        'const require = 1',
        'const __filename = 1',
        'const __dirname = 1',
        'await 1',
        'x = await 1',
        'await 1; 2',
        'func(await 1)',
        "#,
    );
    for line in results.lines() {
        assert!(line.ends_with("=true"), "expected module syntax: {line}");
    }
}

#[test]
fn the_reparse_is_what_decides_the_ambiguous_messages() {
    // The four cases here all reach the module reparse, and only the reparse
    // separates them: `func(await 1)` parses as a module and `if(await 1)` does
    // not (it becomes an `if` with no body). A message table alone would answer
    // `true` for both, and a keyword scan would answer `true` for neither.
    let results = module_syntax(
        r#"
        'func(await 1)',
        'if(await 1)',
        'x = await 1',
        'const = 1',
        '"use strict"; with(a) {}',
        'function f(){',
        "#,
    );
    let expected = [
        ("\"func(await 1)\"", true),
        ("\"if(await 1)\"", false),
        ("\"x = await 1\"", true),
        ("\"const = 1\"", false),
        ("\"\\\"use strict\\\"; with(a) {}\"", false),
        ("\"function f(){\"", false),
    ];
    for (line, (label, want)) in results.lines().zip(expected) {
        assert_eq!(
            line,
            format!("{label}={want}"),
            "misclassified a message that depends on the reparse"
        );
    }
}

#[test]
fn the_no_cjs_variables_flag_suppresses_the_reparse() {
    // `lib/internal/process/execution.js` passes `'no CJS variables'` for `--eval`
    // bodies, where the wrapper parameters do not exist, so `const module = 1` is
    // not a module there. `await 1` and `import` still are.
    let results = run(r#"
        const probe = (code) =>
          contextify.containsModuleSyntax(code, 'file.js', null, 'no CJS variables');
        __out = [
          probe('const module = 1'),
          probe('const exports = 1'),
          probe('const require = 1'),
          probe('const __filename = 1'),
          probe('const __dirname = 1'),
          probe('await 1'),
          probe('import x from "y"'),
        ].join(',');
        "#);
    assert_eq!(results, "false,false,false,false,false,true,true");
}

#[test]
fn the_commonjs_compiler_returns_a_five_parameter_wrapper() {
    // Recorded: `r.function.length === 5`, and the five names are visible to the
    // source as `exports`, `require`, `module`, `__filename`, `__dirname`.
    let result = run(r#"
        const r = contextify.compileFunctionForCJSLoader(
          'module.exports = [typeof exports, typeof require, typeof module, ' +
          'typeof __filename, typeof __dirname, __filename, __dirname]',
          '/tmp/probe.js', false, false);
        const module_ = { exports: {} };
        r.function(module_.exports, function require() {}, module_, '/tmp/probe.js', '/tmp');
        __out = JSON.stringify({
          keys: Object.keys(r),
          arity: r.function.length,
          canParseAsESM: r.canParseAsESM,
          sourceURL: r.sourceURL,
          sourceMapURL: r.sourceMapURL,
          exports: module_.exports,
        });
        "#);
    assert_eq!(
        result,
        r#"{"keys":["cachedDataRejected","sourceURL","sourceMapURL","function","canParseAsESM"],"arity":5,"canParseAsESM":false,"sourceURL":"/tmp/probe.js","exports":["object","function","object","string","string","/tmp/probe.js","/tmp"]}"#
    );
}

#[test]
fn the_commonjs_compiler_reports_esm_detectable_source() {
    // Recorded: with `shouldDetectModule` set, `import x from "y"` comes back with
    // `canParseAsESM: true` and `function: undefined` instead of throwing, and the
    // loader retries the file as ESM.
    let result = run(r#"
        const r = contextify.compileFunctionForCJSLoader('import x from "y"', '/tmp/m.js', false, true);
        __out = JSON.stringify({
          canParseAsESM: r.canParseAsESM,
          functionType: typeof r.function,
        });
        "#);
    assert_eq!(
        result,
        r#"{"canParseAsESM":true,"functionType":"undefined"}"#
    );
}

#[test]
fn the_commonjs_compiler_throws_the_original_error_without_the_detect_flag() {
    // Without `shouldDetectModule` the loader must surface V8's own message,
    // because that is the `require(esm)` error users see.
    let result = run(r#"
        try {
          contextify.compileFunctionForCJSLoader('import x from "y"', '/tmp/m.js', false, false);
          __out = 'no throw';
        } catch (error) {
          __out = `${error.name}: ${error.message.split('\n')[0]}`;
        }
        "#);
    assert_eq!(
        result,
        "SyntaxError: Cannot use import statement outside a module"
    );
}

#[test]
fn a_non_module_syntax_error_is_thrown_even_with_the_detect_flag() {
    // Recorded: `const = 1` throws `Unexpected token '='`. Its message is in
    // neither table, so it must not be reported as ESM.
    let result = run(r#"
        try {
          contextify.compileFunctionForCJSLoader('const = 1', '/tmp/broken.js', false, true);
          __out = 'no throw';
        } catch (error) {
          __out = `${error.name}: ${error.message.split('\n')[0]}`;
        }
        "#);
    assert_eq!(result, "SyntaxError: Unexpected token '='");
}

#[test]
fn source_map_magic_comments_are_reported() {
    // Recorded: a `//# sourceURL=` magic comment becomes `sourceURL`, and the same
    // for `sourceMappingURL`. `Module.prototype._compile` reads both to register
    // the source map.
    let result = run(r#"
        const url = contextify.compileFunctionForCJSLoader(
          '//# sourceURL=magic.js\n1', '/tmp/d.js', false, false);
        const map = contextify.compileFunctionForCJSLoader(
          '//# sourceMappingURL=m.map\n1', '/tmp/e.js', false, false);
        __out = JSON.stringify({ sourceURL: url.sourceURL, sourceMapURL: map.sourceMapURL });
        "#);
    assert_eq!(result, r#"{"sourceURL":"magic.js","sourceMapURL":"m.map"}"#);
}

#[test]
fn compile_function_honours_params_and_reports_its_origin() {
    // `vm.compileFunction('return [a, b]', ['a', 'b'])`: the recorded result
    // carries `sourceURL` set to the file name and the function takes the params.
    let result = run(r#"
        const r = contextify.compileFunction(
          'return [a, b]', 'fn.js', 0, 0, undefined, false, undefined, undefined,
          ['a', 'b'], Symbol('host'));
        __out = JSON.stringify({
          keys: Object.keys(r),
          sourceURL: r.sourceURL,
          called: r.function(1, 2),
        });
        "#);
    assert_eq!(
        result,
        r#"{"keys":["function","sourceURL","sourceMapURL"],"sourceURL":"fn.js","called":[1,2]}"#
    );
}

#[test]
fn compile_function_round_trips_cached_data() {
    // Recorded: `{produceCachedData: true}` sets `cachedDataProduced` and fills
    // `cachedData`; feeding that blob back yields `cachedDataRejected: false`.
    let result = run(r#"
        const produce = (cachedData) => contextify.compileFunction(
          'return 41 + 1', 'cached.js', 0, 0, cachedData, cachedData === undefined,
          undefined, undefined, undefined, Symbol('host'));
        const first = produce(undefined);
        const second = produce(first.cachedData);
        __out = JSON.stringify({
          produced: first.cachedDataProduced,
          isView: ArrayBuffer.isView(first.cachedData),
          rejected: second.cachedDataRejected,
          rejectedIsBoolean: typeof second.cachedDataRejected,
          runs: second.function(),
        });
        "#);
    assert_eq!(
        result,
        r#"{"produced":true,"isView":true,"rejected":false,"rejectedIsBoolean":"boolean","runs":42}"#
    );
}

#[test]
fn cached_data_is_only_reported_when_one_was_consumed() {
    // Recorded: `cachedDataRejected` is absent from the result when no cache was
    // passed, which `internalCompileFunction` checks with `typeof`.
    let result = run(r#"
        const r = contextify.compileFunction(
          'return 1', 'fresh.js', 0, 0, undefined, false, undefined, undefined,
          undefined, Symbol('host'));
        __out = typeof r.cachedDataRejected;
        "#);
    assert_eq!(result, "undefined");
}

#[test]
fn a_script_compiles_and_runs_through_its_prototype() {
    // `lib/internal/vm.js` destructures `runInContext` off the prototype and calls
    // it via `FunctionPrototypeCall`, so it must be an own property there.
    let result = run(r#"
        const script = new contextify.ContextifyScript(
          '1 + 1', 's.js', 0, 0, undefined, false, undefined, Symbol('host'));
        const proto = Object.getOwnPropertyNames(contextify.ContextifyScript.prototype);
        __out = JSON.stringify({
          proto: proto.sort(),
          ran: script.runInContext(null, -1, false, false, false),
          // Recorded: `sourceURL` is `undefined` unless a `//# sourceURL=`
          // magic comment names one, which `source_map_magic_comments_are_reported`
          // covers for the function path.
          hasSourceURL: 'sourceURL' in script,
        });
        "#);
    assert_eq!(
        result,
        r#"{"proto":["constructor","createCachedData","runInContext"],"ran":2,"hasSourceURL":true}"#
    );
}

#[test]
fn a_script_round_trips_cached_data() {
    // `vm.Script({produceCachedData})` then `createCachedData()`: both produce a
    // Buffer, and feeding it back reports `false`.
    let result = run(r#"
        const made = new contextify.ContextifyScript(
          '7 * 6', 'cached-script.js', 0, 0, undefined, true, undefined, Symbol('host'));
        const reused = new contextify.ContextifyScript(
          '7 * 6', 'cached-script.js', 0, 0, made.cachedData, false, undefined, Symbol('host'));
        __out = JSON.stringify({
          produced: made.cachedDataProduced,
          isView: ArrayBuffer.isView(made.cachedData),
          rejected: reused.cachedDataRejected,
          created: ArrayBuffer.isView(made.createCachedData()),
          runs: reused.runInContext(null, -1, false, false, false),
        });
        "#);
    assert_eq!(
        result,
        r#"{"produced":true,"isView":true,"rejected":false,"created":true,"runs":42}"#
    );
}

#[test]
fn a_contextified_sandbox_holds_the_realm_s_globals() {
    // `vm.createContext(s)` returns `s`, the mark is invisible to `Object.keys`,
    // a write inside the realm lands on the sandbox, and a sandbox property is
    // readable inside the realm. The last two are what the property interceptors
    // exist for.
    let result = run(r#"
        const sandbox = { seeded: 'from-sandbox' };
        const returned = contextify.makeContext(
          sandbox, 'VM Context 1', undefined, true, true, false, Symbol('host'));
        const script = new contextify.ContextifyScript(
          'sandboxWrite = 7; seeded',
          'inside.js', 0, 0, undefined, false, sandbox, Symbol('host'));
        const read = script.runInContext(sandbox, -1, false, false, false);
        __out = JSON.stringify({
          sameObject: returned === sandbox,
          visibleKeys: Object.keys(sandbox).sort(),
          read,
          sandboxWrite: sandbox.sandboxWrite,
          typeofObject: new contextify.ContextifyScript(
            'typeof Object', 'realm.js', 0, 0, undefined, false, sandbox, Symbol('h')
          ).runInContext(sandbox, -1, false, false, false),
        });
        "#);
    assert_eq!(
        result,
        r#"{"sameObject":true,"visibleKeys":["sandboxWrite","seeded"],"read":"from-sandbox","sandboxWrite":7,"typeofObject":"function"}"#
    );
}

#[test]
fn a_vanilla_context_returns_its_global_object() {
    // `vm.createContext(vm.constants.DONT_CONTEXTIFY)` passes a symbol instead of
    // a sandbox and gets the new realm's global object back. That object must be
    // marked too, so `isContext` answers for it.
    let result = run(r#"
        const vanilla = contextify.makeContext(
          Symbol('dont-contextify'), 'VM Context 2', undefined, true, true, false, Symbol('host'));
        __out = JSON.stringify({
          type: typeof vanilla,
          keysOnGlobal: Object.getOwnPropertyNames(vanilla).includes('globalThis'),
        });
        "#);
    assert_eq!(result, r#"{"type":"object","keysOnGlobal":true}"#);
}

#[test]
fn contextifying_the_same_sandbox_twice_is_refused() {
    // Two realms claiming one object is unrepresentable, so Node asserts and this
    // reports it instead.
    let result = run(r#"
        const sandbox = {};
        contextify.makeContext(sandbox, 'first', undefined, true, true, false, Symbol('h'));
        try {
          contextify.makeContext(sandbox, 'second', undefined, true, true, false, Symbol('h'));
          __out = 'no throw';
        } catch (error) {
          __out = error.message;
        }
        "#);
    assert!(result.contains("multiple times"), "{result}");
}

#[test]
fn run_interruptible_returns_false_for_a_normal_call() {
    // `lib/internal/repl/inspector.js` treats `true` as "the user pressed Ctrl+C",
    // so an ordinary call must report `false`.
    let result = run(r#"
        __out = String(contextify.runInterruptible(() => 1));
        "#);
    assert_eq!(result, "false");
}

#[test]
fn run_interruptible_propagates_a_real_exception() {
    // A throw must not be mistaken for an interrupt, or the REPL would report
    // "interrupted" for an inspector failure.
    let result = run(r#"
        try {
          contextify.runInterruptible(() => { throw new Error('boom'); });
          __out = 'no throw';
        } catch (error) {
          __out = error.message;
        }
        "#);
    assert_eq!(result, "boom");
}

#[test]
fn measure_memory_is_absent_rather_than_faked() {
    // The one member this crate defers: the `v8` crate binds neither
    // `Isolate::MeasureMemory` nor `MeasureMemoryDelegate`. An absent member is
    // honest; a stub returning a resolved promise would look like it worked.
    let result = run(r#"
        __out = JSON.stringify({
          typeof: typeof contextify.measureMemory,
          constantsPresent: typeof contextify.constants.measureMemory === 'object',
        });
        "#);
    assert_eq!(result, r#"{"typeof":"undefined","constantsPresent":true}"#);
}

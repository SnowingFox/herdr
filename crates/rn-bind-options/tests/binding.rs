//! End-to-end checks that drive `internalBinding('options')` through a real V8
//! isolate.
//!
//! The unit tests in the crate prove the table and the value rules; these prove
//! the object those rules end up in. Every JavaScript snippet below is the call
//! `lib/**` actually makes, because a member that exists but returns the wrong
//! shape is worse than a missing one: `internal/process/per_thread.js` would
//! build an empty `process.allowedNodeEnvironmentFlags` without throwing.
//!
//! V8's platform and initialisation are process-global and can only be set up
//! once, so these tests serialize on a mutex rather than each calling
//! `V8::initialize`; a second initialisation panics inside V8.

use rn_bind_options::Options;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Runs `body` with a live isolate that has the namespace installed as the
/// global `options`.
fn with_options<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);

    let binding = Options
        .install(
            scope,
            &mut InstallCtx {
                async_ids: &mut AsyncIds::new(),
            },
        )
        .expect("options binding installs");
    let global = context.global(scope);
    let key = v8::String::new(scope, "options").expect("key");
    global.set(scope, key.into(), binding.into());

    let result = body(scope);
    drop(guard);
    result
}

/// Initializes V8 exactly once for the whole test binary.
fn init_v8() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

/// Evaluates `source` in the current scope and returns the last expression as
/// a string.
fn eval(scope: &mut v8::PinScope<'_, '_>, source: &str) -> String {
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let code = v8::String::new(scope, source).expect("source");
    let script = v8::Script::compile(scope, code, None).expect("compiles");
    let run = script.run(scope);
    if scope.has_caught() {
        let exception = scope
            .exception()
            .map(|value| value.to_rust_string_lossy(scope))
            .unwrap_or_else(|| "unknown exception".to_string());
        panic!("javascript threw: {exception}");
    }
    run.map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_default()
}

/// The members `internal/options.js` destructures at module load.
#[test]
fn every_member_the_js_layer_destructures_exists() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            const names = [
              'getCLIOptionsValues', 'getCLIOptionsInfo', 'getOptionsAsFlags',
              'getEmbedderOptions', 'getEnvOptionsInputType',
              'getNamespaceOptionsInputType', 'parseNodeOptionsEnvVar',
            ];
            const missing = names.filter((name) => typeof options[name] !== 'function');
            JSON.stringify({
              missing,
              types: typeof options.types,
              envSettings: typeof options.envSettings,
            });
            "#,
        );
        assert_eq!(
            actual,
            r#"{"missing":[],"types":"object","envSettings":"object"}"#
        );
    });
}

/// `internal/process/per_thread.js` reads both constant objects by name and
/// compares them against the numbers in each option's metadata.
#[test]
fn constants_have_the_values_the_js_layer_compares_against() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            JSON.stringify({
              types: options.types,
              envSettings: options.envSettings,
              typeKeys: Object.keys(options.types),
              envKeys: Object.keys(options.envSettings),
              // `NODE_DEFINE_CONSTANT` is `READ_ONLY | DONT_DELETE`, which is
              // non-writable, enumerable and non-configurable. Enumeration is
              // what `Object.keys(types)` in print_help.js needs.
              descriptors: Object.keys(options.types).map((key) => {
                const d = Object.getOwnPropertyDescriptor(options.types, key);
                return [key, d.writable, d.enumerable, d.configurable];
              }),
            });
            "#,
        );
        assert_eq!(
            actual,
            concat!(
                r#"{"types":{"kNoOp":0,"kV8Option":1,"kBoolean":2,"kInteger":3,"kUInteger":4,"kString":5,"kHostPort":6,"kStringList":7},"#,
                r#""envSettings":{"kAllowedInEnvvar":0,"kDisallowedInEnvvar":1},"#,
                r#""typeKeys":["kNoOp","kV8Option","kBoolean","kInteger","kUInteger","kString","kHostPort","kStringList"],"#,
                r#""envKeys":["kAllowedInEnvvar","kDisallowedInEnvvar"],"#,
                r#""descriptors":[["kNoOp",false,true,false],["kV8Option",false,true,false],["kBoolean",false,true,false],["kInteger",false,true,false],["kUInteger",false,true,false],["kString",false,true,false],["kHostPort",false,true,false],["kStringList",false,true,false]]}"#
            )
        );
    });
}

/// `getCLIOptionsValues` must be a null-prototype object: `lib/**` reads it
/// with a plain index and expects a missing option to be `undefined` rather
/// than inherited.
#[test]
fn cli_option_values_are_a_null_prototype_object() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            const values = options.getCLIOptionsValues();
            JSON.stringify({
              proto: Object.getPrototypeOf(values),
              title: values['--title'],
              inputType: values['--input-type'],
              conditions: values['--conditions'],
              stackTraceLimit: values['--stack-trace-limit'],
              abortOnUncaught: values['--abort-on-uncaught-exception'],
              maxHttpHeaderSize: values['--max-http-header-size'],
              inspectPort: values['--inspect-port'],
              inspectPortProto: Object.getPrototypeOf(values['--inspect-port']),
              negated: values['--no-zero-fill-buffers'],
              plain: values['--zero-fill-buffers'],
              listIsArray: Array.isArray(values['--conditions']),
            });
            "#,
        );
        assert_eq!(
            actual,
            concat!(
                r#"{"proto":null,"title":"","inputType":"","conditions":[],"stackTraceLimit":10,"#,
                r#""abortOnUncaught":false,"maxHttpHeaderSize":16384,"#,
                r#""inspectPort":{"host":"127.0.0.1","port":9229},"inspectPortProto":null,"#,
                r#""negated":true,"plain":false,"listIsArray":true}"#
            ),
            "a `--no-` boolean reports the inverted value of its positive twin"
        );
    });
}

/// Every option in the table reaches the object, and the boolean negation
/// pairs are adjacent with inverted values, which is the order the C++ loop
/// produces.
#[test]
fn every_option_reaches_the_object_with_its_negation() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            const values = options.getCLIOptionsValues();
            const keys = Object.keys(values);
            const info = options.getCLIOptionsInfo();
            const names = [...info.options.keys()];

            // `internal/process/per_thread.js` walks this and pushes each name
            // whose envVarSettings is kAllowedInEnvvar.
            let allowed = 0;
            for (const [name, entry] of info.options) {
              if (name[0] === '[') continue;
              if (entry.envVarSettings === options.envSettings.kAllowedInEnvvar) allowed++;
            }

            const booleans = names.filter((name) => info.options.get(name).type === 2);
            const bad = [];
            for (const name of booleans) {
              const negated = '--no' + name.slice(1);
              const index = keys.indexOf(name);
              if (keys[index - 1] !== negated) bad.push(name);
              if (values[negated] === values[name]) bad.push(name);
            }

            JSON.stringify({
              values: keys.length,
              table: names.length,
              booleans: booleans.length,
              allowed,
              bad,
            });
            "#,
        );
        assert_eq!(
            actual,
            r#"{"values":385,"table":251,"booleans":134,"allowed":199,"bad":[]}"#
        );
    });
}

/// The shape `GetCLIOptionsInfo` builds, including the alias expansions
/// `buildAllowedFlags` re-validates entry by entry.
#[test]
fn cli_option_info_is_two_maps_with_the_expected_entries() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            const { options: opts, aliases } = options.getCLIOptionsInfo();
            const title = opts.get('--title');
            const help = opts.get('--help');
            JSON.stringify({
              optionsIsMap: opts instanceof Map,
              aliasesIsMap: aliases instanceof Map,
              title,
              titleKeys: Object.keys(title),
              titleProto: Object.getPrototypeOf(title),
              helpEnvSetting: help.envVarSettings,
              alias: aliases.get('-h'),
              groupAlias: aliases.get('--inspect='),
            });
            "#,
        );
        assert_eq!(
            actual,
            concat!(
                r#"{"optionsIsMap":true,"aliasesIsMap":true,"#,
                r#""title":{"helpText":"the process title to use on startup","envVarSettings":0,"type":5,"defaultIsTrue":false},"#,
                r#""titleKeys":["helpText","envVarSettings","type","defaultIsTrue"],"titleProto":null,"#,
                r#""helpEnvSetting":1,"alias":["--help"],"groupAlias":["--inspect-port","--inspect"]}"#
            )
        );
    });
}

/// `getEmbedderOptions` is consulted by `internal/options.js`; a standalone
/// executable reports no embedder.
#[test]
fn embedder_options_are_false_for_a_standalone_executable() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            const embedder = options.getEmbedderOptions();
            JSON.stringify({
              value: embedder,
              proto: Object.getPrototypeOf(embedder),
              keys: Object.keys(embedder),
            });
            "#,
        );
        assert_eq!(
            actual,
            concat!(
                r#"{"value":{"shouldNotRegisterESMLoader":false,"noGlobalSearchPaths":false,"#,
                r#""noBrowserGlobals":false,"hasEmbedderPreload":false},"proto":null,"#,
                r#""keys":["shouldNotRegisterESMLoader","noGlobalSearchPaths","noBrowserGlobals","hasEmbedderPreload"]}"#
            )
        );
    });
}

/// The two schema-facing members, which `generateConfigJsonSchema` walks with
/// `ObjectEntries`.
#[test]
fn config_schema_inputs_are_keyed_objects_and_maps() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            const env = options.getEnvOptionsInputType();
            const namespaces = options.getNamespaceOptionsInputType();
            const title = env['--title'];
            const permission = namespaces.get('permission');
            JSON.stringify({
              envIsObject: typeof env === 'object' && !(env instanceof Map),
              title,
              titleProto: Object.getPrototypeOf(title),
              // `--help` is disallowed in NODE_OPTIONS, so it is absent.
              helpAbsent: env['--help'] === undefined,
              // A bracketed internal target is never a config key.
              internalAbsent: env['[has_eval_string]'] === undefined,
              namespaceIsMap: namespaces instanceof Map,
              namespaceKeys: [...namespaces.keys()],
              permissionIsObject: typeof permission === 'object',
              allowFsRead: permission['--allow-fs-read'],
              titleKeys: Object.keys(title),
            });
            "#,
        );
        assert_eq!(
            actual,
            concat!(
                r#"{"envIsObject":true,"#,
                r#""title":{"type":"string","description":"the process title to use on startup"},"#,
                r#""titleProto":null,"helpAbsent":true,"internalAbsent":true,"#,
                r#""namespaceIsMap":true,"namespaceKeys":["bench","test","watch","permission"],"#,
                r#""permissionIsObject":true,"#,
                r#""allowFsRead":{"type":"array","description":"allow permissions to read the filesystem"},"#,
                r#""titleKeys":["type","description"]}"#
            )
        );
    });
}

/// `getOptionsAsFlags` is an array of strings, which
/// `internal/test_runner/runner.js` filters and appends to execArgv.
#[test]
fn options_as_flags_is_an_array_of_flag_strings() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            const flags = options.getOptionsAsFlags();
            JSON.stringify({
              isArray: Array.isArray(flags),
              allStrings: flags.every((flag) => typeof flag === 'string'),
              hasInspectPort: flags.includes('--inspect-port=127.0.0.1:9229'),
              hasV8Flag: flags.some((flag) => flag.startsWith('--max-old-space-size')),
              hasCipherList: flags.some((flag) => flag.startsWith('--tls-cipher-list=TLS_AES_256_GCM')),
            });
            "#,
        );
        assert_eq!(
            actual,
            r#"{"isArray":true,"allStrings":true,"hasInspectPort":true,"hasV8Flag":false,"hasCipherList":true}"#
        );
    });
}

/// `parseNodeOptionsEnvVar` is what `internal/main/watch_mode.js` splits
/// `NODE_OPTIONS` with before re-quoting each part for the child.
#[test]
fn parse_node_options_env_var_splits_and_throws_like_node() {
    with_options(|scope| {
        let actual = eval(
            scope,
            r#"
            const parsed = options.parseNodeOptionsEnvVar('--a --b=c "./x y"');
            // The catch is the point: Node throws a plain Error with no `code`.
            let error = null;
            try {
              options.parseNodeOptionsEnvVar('--a "unterminated');
            } catch (caught) {
              error = {
                name: caught.name,
                message: caught.message,
                code: caught.code === undefined ? 'absent' : caught.code,
              };
            }
            JSON.stringify({
              parsed,
              isArray: Array.isArray(parsed),
              error,
              empty: options.parseNodeOptionsEnvVar(''),
            });
            "#,
        );
        assert_eq!(
            actual,
            concat!(
                r#"{"parsed":["--a","--b=c","./x y"],"isArray":true,"#,
                r#""error":{"name":"Error","message":"invalid value for NODE_OPTIONS (unterminated string)\n","code":"absent"},"#,
                r#""empty":[]}"#
            )
        );
    });
}

/// The binding object itself has exactly the recorded members, with nothing
/// extra that `lib/**` might accidentally pick up.
#[test]
fn the_namespace_object_has_exactly_the_contract_members() {
    with_options(|scope| {
        let actual = eval(scope, r#"JSON.stringify(Object.keys(options).sort())"#);
        assert_eq!(
            actual,
            r#"["envSettings","getCLIOptionsInfo","getCLIOptionsValues","getEmbedderOptions","getEnvOptionsInputType","getNamespaceOptionsInputType","getOptionsAsFlags","parseNodeOptionsEnvVar","types"]"#
        );
    });
}

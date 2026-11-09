//! Tests for `internalBinding('config')` and `internalBinding('constants')`.
//!
//! The table assertions run without V8; the `v8_object` tests install the real
//! namespace objects into a live isolate and read them back as JavaScript, so
//! property attributes, sub-object prototypes and function values are covered
//! too.

use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

use rn_bind_config::config::{Config, MEMBERS as CONFIG_MEMBERS, VALUES as CONFIG_VALUES};
use rn_bind_config::constants::{
    Constants, CRYPTO_VALUES, DLOPEN_VALUES, ERRNO_VALUES, FS_VALUES, INTERNAL_VALUES, MEMBERS,
    OS_VALUES, PRIORITY_VALUES, SIGNALS_VALUES, TRACE_VALUES, ZLIB_VALUES,
};
use rn_bind_config::Value;

/// Runs `body` with a live isolate, scope and context.
///
/// V8's platform and initialization are process-global and can only be set up
/// once, so these tests serialize on a mutex rather than each calling
/// `V8::initialize`.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static V8_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let guard = V8_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    init_v8();

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
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

/// Installs one namespace and returns the result.
fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    module: &dyn BindingModule,
) -> v8::Local<'s, v8::Object> {
    let mut async_ids = AsyncIds::default();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    module
        .install(scope, &mut ctx)
        .expect("namespace install should not fail")
}

/// Evaluates an expression with `globalThis.__ns` bound to `object`.
fn eval_with<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    source: &str,
) -> String {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "__ns").expect("allocating __ns");
    global.set(scope, key.into(), object.into());

    let source = v8::String::new(scope, source).expect("allocating source");
    let script = v8::Script::compile(scope, source, None).expect("compiling probe script");
    let result = script.run(scope).expect("running probe script");
    result.to_rust_string_lossy(scope)
}

fn lookup(table: &[(&'static str, Value)], name: &str) -> Option<Value> {
    table
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

#[test]
fn config_exposes_every_member_the_js_layer_reads() {
    // Derived from `rg "internalBinding\('config'\)" vendor/libnode-js/lib`.
    let expected = [
        // lib/v8.js, lib/inspector.js, internal/repl/inspector.js,
        // internal/webstorage.js, internal/util/inspector.js,
        // internal/bootstrap/web/exposed-wildcard.js,
        // internal/bootstrap/switches/is_main_thread.js,
        // internal/process/pre_execution.js, internal/console/constructor.js
        "hasInspector",
        // internal/main/eval_string.js,
        // internal/bootstrap/web/exposed-window-or-worker.js, lib/v8.js
        "hasOpenSSL",
        // internal/util/inspect.js, buffer.js, internal/encoding.js
        "hasIntl",
        // internal/main/print_help.js
        "hasSmallICU",
        "hasNodeOptions",
        // trace_events.js
        "hasTracing",
        // internal/process/pre_execution.js
        "noBrowserGlobals",
        // internal/bootstrap/node.js (process.features.debug)
        "isDebugBuild",
        // internal/bootstrap/node.js (process.features.openssl_is_boringssl)
        "openSSLIsBoringSSL",
        // internal/inspector_async_hook.js
        "bits",
        // internal/navigator.js
        "getDefaultLocale",
    ];

    for name in expected {
        assert!(
            CONFIG_MEMBERS.contains(&name),
            "config is missing read member {name}"
        );
    }
    // 9 tabled booleans, plus `bits` (computed from the target) and
    // `getDefaultLocale` (a function), which are installed separately.
    assert_eq!(
        CONFIG_MEMBERS.len(),
        CONFIG_VALUES.len() + 2,
        "members() must account for every tabled value plus bits and getDefaultLocale"
    );
}

#[test]
fn config_member_list_matches_the_recorded_contract() {
    // contracts/config.json is the authority: it records what a real Node
    // publishes, merged from a runtime recording and a static scan of lib/**.
    // A member missing here makes lib/** read `undefined`, which silently
    // disables features: buffer.js branches on hasIntl for transcoding and
    // inspector.js on hasInspector.
    let contract = [
        "bits",
        "getDefaultLocale",
        "hasInspector",
        "hasIntl",
        "hasNodeOptions",
        "hasOpenSSL",
        "hasSmallICU",
        "hasTracing",
        "isDebugBuild",
        "noBrowserGlobals",
        "openSSLIsBoringSSL",
    ];
    let mut declared: Vec<&str> = CONFIG_MEMBERS.to_vec();
    declared.sort_unstable();
    let mut expected = contract;
    expected.sort_unstable();
    assert_eq!(
        declared, expected,
        "config diverged from contracts/config.json"
    );
}

#[test]
fn every_member_config_claims_is_actually_installed() {
    // `members()` is what rn-compat checks against contracts/config.json, so a
    // name listed there but never defined would pass the contract check while
    // `lib/**` still reads `undefined`. Compare against the live object.
    with_context(|scope| {
        let object = install(scope, &Config);
        let names = object
            .get_own_property_names(scope, Default::default())
            .expect("config own property names");
        let actual: std::collections::BTreeSet<String> = (0..names.length())
            .filter_map(|index| names.get_index(scope, index))
            .map(|name| name.to_rust_string_lossy(scope))
            .collect();

        for member in CONFIG_MEMBERS {
            assert!(
                actual.contains(*member),
                "config.members() lists {member} but install() never defines it"
            );
        }
    });
}

#[test]
fn config_member_list_matches_installed_properties() {
    with_context(|scope| {
        let object = install(scope, &Config);
        let names = object
            .get_own_property_names(scope, Default::default())
            .expect("config own property names");
        let mut actual: Vec<String> = (0..names.length())
            .filter_map(|index| names.get_index(scope, index))
            .map(|name| name.to_rust_string_lossy(scope))
            .collect();
        actual.sort();

        let mut declared: Vec<String> = CONFIG_MEMBERS
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        declared.sort();

        assert_eq!(actual, declared, "members() and installed keys diverged");
    });
}

#[test]
fn config_values_match_a_default_linux_release_build() {
    assert_eq!(
        Config::get("isDebugBuild"),
        Some(Value::Bool(false)),
        "release builds define neither DEBUG nor NDEBUG"
    );
    assert_eq!(Config::get("hasOpenSSL"), Some(Value::Bool(true)));
    assert_eq!(
        Config::get("openSSLIsBoringSSL"),
        Some(Value::Bool(false)),
        "node ships upstream OpenSSL, not BoringSSL"
    );
    assert_eq!(Config::get("hasIntl"), Some(Value::Bool(true)));
    assert_eq!(
        Config::get("hasSmallICU"),
        Some(Value::Bool(false)),
        "small-icu is a configure option, not the default"
    );
    assert_eq!(Config::get("hasTracing"), Some(Value::Bool(true)));
    assert_eq!(Config::get("hasNodeOptions"), Some(Value::Bool(true)));
    // The one value here that deliberately differs from a stock Node build.
    // `config.hasInspector` means "this binary was compiled with the
    // inspector", and this one was not: `internalBinding('inspector')` has no
    // implementation. Three call sites make that unavoidable —
    // `internal/process/pre_execution.js` reaches the binding at module scope
    // through `setupInspectorHooks`, `lib/v8.js` reads the flag at module scope
    // to decide whether to load `internalBinding('profiler')`, and
    // `lib/inspector.js` throws when it is false. Reporting a stock build's
    // `true` breaks startup and `require('v8')` alike. The recorded Node value
    // is true; see the note on `config_values_match_a_live_node_recording` for
    // why it is expected to disagree until the inspector lands.
    assert_eq!(
        Config::get("hasInspector"),
        Some(Value::Bool(false)),
        "this build has no inspector, and the flag must say so"
    );
    assert_eq!(
        Config::get("noBrowserGlobals"),
        Some(Value::Bool(false)),
        "--no-browser-globals is opt-in"
    );
    assert_eq!(Config::get("bits"), Some(Value::int(64)));
}

#[test]
fn config_bits_follows_pointer_width() {
    assert_eq!(Config::bits() as usize, std::mem::size_of::<usize>() * 8);
}

#[test]
fn config_get_default_locale_returns_a_bcp47_tag() {
    // Node returns `Isolate::GetDefaultLocale()`, so this is the ICU default as
    // a language tag, not an empty string. `en-US` on a default Linux install,
    // and whatever `LANG` asks for otherwise.
    with_context(|scope| {
        let object = install(scope, &Config);
        let result = eval_with(scope, object, "__ns.getDefaultLocale()");
        assert!(
            !result.is_empty(),
            "getDefaultLocale must return the ICU locale, not an empty string"
        );
        // A BCP 47 language tag: a 2-3 letter primary subtag, then optional
        // subtags. `en-US`, `C`, `POSIX` and `sr-Latn-RS` all satisfy this.
        let primary = result.split(['-', '_']).next().unwrap_or_default();
        assert!(
            primary.len() >= 2
                && primary.len() <= 3
                && primary.chars().all(|c| c.is_ascii_alphabetic()),
            "getDefaultLocale returned {result:?}, which is not a language tag"
        );
    });
}

#[test]
fn config_values_match_a_live_node_recording() {
    // Captured from `node --expose-internals` on Linux:
    //   internalBinding('config')
    // and confirmed against src/node_config.cc. Keeping the captured values
    // here means a change to the table has to be a deliberate edit.
    for (name, expected) in [
        ("isDebugBuild", Value::Bool(false)),
        ("openSSLIsBoringSSL", Value::Bool(false)),
        ("hasOpenSSL", Value::Bool(true)),
        ("hasIntl", Value::Bool(true)),
        ("hasSmallICU", Value::Bool(false)),
        ("hasTracing", Value::Bool(true)),
        ("hasNodeOptions", Value::Bool(true)),
        // Recorded from a stock Node, which has the inspector. This is the only
        // value that is allowed to disagree, and only for this reason: the
        // build genuinely lacks `internalBinding('inspector')`, so reporting
        // `true` would be a claim the binary cannot honour. Drop the exception
        // (and the corresponding assertion above) when the inspector lands.
        ("hasInspector", Value::Bool(false)),
        ("noBrowserGlobals", Value::Bool(false)),
        ("bits", Value::int(64)),
    ] {
        assert_eq!(
            Config::get(name),
            Some(expected),
            "{name} disagrees with Node"
        );
    }

    // Checked separately because its expected value legitimately differs.
    assert_eq!(
        Config::get("hasInspector"),
        Some(Value::Bool(false)),
        "the recording says true, but this build has no inspector binding"
    );
}

#[test]
fn config_installs_readonly_enumerable_booleans() {
    with_context(|scope| {
        let object = install(scope, &Config);
        let result = eval_with(
            scope,
            object,
            "JSON.stringify({
               proto: Object.getPrototypeOf(__ns) === Object.prototype,
               debug: __ns.isDebugBuild,
               intl: __ns.hasIntl,
               bits: __ns.bits,
               bitsType: typeof __ns.bits,
               desc: Object.getOwnPropertyDescriptor(__ns, 'hasOpenSSL'),
               locale: typeof __ns.getDefaultLocale,
               localeLength: __ns.getDefaultLocale.length,
               localeValue: typeof __ns.getDefaultLocale(),
             })",
        );
        // Node's READONLY_PROPERTY passes only `v8::ReadOnly`, so `config`
        // properties are writable:false but still configurable:true. This is
        // the opposite of `constants`, which uses NODE_DEFINE_CONSTANT with
        // `ReadOnly | DontDelete` and is therefore non-configurable.
        assert_eq!(
            result,
            concat!(
                r#"{"proto":true,"debug":false,"intl":true,"bits":64,"bitsType":"number","#,
                r#""desc":{"value":true,"writable":false,"enumerable":true,"configurable":true},"#,
                r#""locale":"function","localeLength":0,"localeValue":"string"}"#
            )
        );
    });
}

#[test]
fn config_rejects_writes_like_node() {
    with_context(|scope| {
        let object = install(scope, &Config);
        let result = eval_with(
            scope,
            object,
            "'use strict';
             try {
               __ns.hasIntl = false;
               'wrote'
             } catch (error) {
               error.name
             }",
        );
        // `v8::ReadOnly` without `DontDelete` makes strict-mode assignment
        // throw a TypeError, which is what Node's READONLY_PROPERTY produces.
        assert_eq!(result, "TypeError");
    });
}

// ---------------------------------------------------------------------------
// constants: shape
// ---------------------------------------------------------------------------

#[test]
fn constants_member_list_is_the_six_node_subtrees() {
    assert_eq!(
        MEMBERS,
        &["os", "fs", "crypto", "zlib", "trace", "internal"]
    );
}

#[test]
fn constants_member_list_matches_installed_properties() {
    with_context(|scope| {
        let object = install(scope, &Constants);
        let names = object
            .get_own_property_names(scope, Default::default())
            .expect("constants own property names");
        let mut actual: Vec<String> = (0..names.length())
            .filter_map(|index| names.get_index(scope, index))
            .map(|name| name.to_rust_string_lossy(scope))
            .collect();
        actual.sort();

        let mut declared: Vec<String> = MEMBERS.iter().map(|name| (*name).to_string()).collect();
        declared.sort();

        assert_eq!(actual, declared, "members() and installed keys diverged");
    });
}

#[test]
fn constants_installs_the_os_tree_with_all_nested_tables() {
    with_context(|scope| {
        let object = install(scope, &Constants);
        let result = eval_with(
            scope,
            object,
            "JSON.stringify({
               nullProto: Object.getPrototypeOf(__ns) === null,
               osNullProto: Object.getPrototypeOf(__ns.os) === null,
               nestedNullProto:
                 Object.getPrototypeOf(__ns.os.signals) === null &&
                 Object.getPrototypeOf(__ns.os.errno) === null &&
                 Object.getPrototypeOf(__ns.os.priority) === null &&
                 Object.getPrototypeOf(__ns.os.dlopen) === null,
               osKeys: Object.keys(__ns.os).sort(),
               udp: __ns.os.UV_UDP_REUSEADDR,
               sigint: __ns.os.signals.SIGINT,
               eperm: __ns.os.errno.EPERM,
               low: __ns.os.priority.PRIORITY_LOW,
               lazy: __ns.os.dlopen.RTLD_LAZY,
             })",
        );
        assert_eq!(
            result,
            concat!(
                r#"{"nullProto":true,"osNullProto":true,"nestedNullProto":true,"#,
                r#""osKeys":["UV_UDP_REUSEADDR","dlopen","errno","priority","signals"],"#,
                r#""udp":4,"sigint":2,"eperm":1,"low":19,"lazy":1}"#
            )
        );
    });
}

#[test]
fn constants_are_readonly_and_non_configurable() {
    with_context(|scope| {
        let object = install(scope, &Constants);
        let result = eval_with(
            scope,
            object,
            "JSON.stringify(Object.getOwnPropertyDescriptor(__ns.fs, 'O_RDONLY'))",
        );
        assert_eq!(
            result,
            r#"{"value":0,"writable":false,"enumerable":true,"configurable":false}"#
        );
    });
}

#[test]
fn constants_do_not_leak_between_namespaces() {
    // `fs` is a sibling of `os`, not a member of it, and `signals` lives only
    // under `os`; a flat object would satisfy neither check.
    with_context(|scope| {
        let object = install(scope, &Constants);
        let result = eval_with(
            scope,
            object,
            "JSON.stringify({
               fsOnRoot: 'O_RDONLY' in __ns.fs,
               fsOnOs: 'O_RDONLY' in __ns.os,
               signalsOnRoot: 'SIGINT' in __ns,
               zOnFs: 'Z_OK' in __ns.fs,
             })",
        );
        assert_eq!(
            result,
            r#"{"fsOnRoot":true,"fsOnOs":false,"signalsOnRoot":false,"zOnFs":false}"#
        );
    });
}

// ---------------------------------------------------------------------------
// constants: values
// ---------------------------------------------------------------------------

#[test]
fn os_udp_reuseaddr_matches_libuv() {
    assert_eq!(lookup(OS_VALUES, "UV_UDP_REUSEADDR"), Some(Value::int(4)));
}

#[test]
fn fs_constants_match_linux_headers() {
    // Representative values from <fcntl.h>, <sys/stat.h> and uv.h on Linux.
    for (name, expected) in [
        ("O_RDONLY", 0),
        ("O_WRONLY", 1),
        ("O_RDWR", 2),
        ("O_CREAT", 64),
        ("O_EXCL", 128),
        ("O_TRUNC", 512),
        ("O_APPEND", 1024),
        ("O_NONBLOCK", 2048),
        ("O_DSYNC", 4096),
        ("O_DIRECTORY", 65536),
        ("O_NOFOLLOW", 131072),
        ("O_DIRECT", 16384),
        ("O_NOATIME", 262144),
        // O_SYNC is O_DSYNC | 0x100000 on Linux.
        ("O_SYNC", 1_052_672),
    ] {
        assert_eq!(
            lookup(FS_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with Linux"
        );
    }
}

#[test]
fn fs_file_type_masks_match_linux() {
    for (name, expected) in [
        ("S_IFMT", 0o170000),
        ("S_IFSOCK", 0o140000),
        ("S_IFLNK", 0o120000),
        ("S_IFREG", 0o100000),
        ("S_IFBLK", 0o060000),
        ("S_IFDIR", 0o040000),
        ("S_IFCHR", 0o020000),
        ("S_IFIFO", 0o010000),
    ] {
        assert_eq!(
            lookup(FS_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with Linux"
        );
    }
}

#[test]
fn fs_access_and_permission_constants_match_linux() {
    for (name, expected) in [
        ("F_OK", 0),
        ("X_OK", 1),
        ("W_OK", 2),
        ("R_OK", 4),
        ("S_IRWXU", 0o700),
        ("S_IRUSR", 0o400),
        ("S_IWUSR", 0o200),
        ("S_IXUSR", 0o100),
        ("S_IRWXG", 0o070),
        ("S_IRWXO", 0o007),
    ] {
        assert_eq!(
            lookup(FS_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with Linux"
        );
    }
}

#[test]
fn fs_windows_only_open_flags_are_zero_on_linux() {
    for name in [
        "UV_FS_O_FILEMAP",
        "UV_FS_O_TEMPORARY",
        "UV_FS_O_SHORT_LIVED",
        "UV_FS_O_SEQUENTIAL",
        "UV_FS_O_RANDOM",
    ] {
        assert_eq!(
            lookup(FS_VALUES, name),
            Some(Value::int(0)),
            "uv/unix.h defines {name} as 0"
        );
    }
}

#[test]
fn fs_copy_modes_alias_their_libuv_spelling() {
    for (uv_name, node_name) in [
        ("UV_FS_COPYFILE_EXCL", "COPYFILE_EXCL"),
        ("UV_FS_COPYFILE_FICLONE", "COPYFILE_FICLONE"),
        ("UV_FS_COPYFILE_FICLONE_FORCE", "COPYFILE_FICLONE_FORCE"),
    ] {
        assert_eq!(lookup(FS_VALUES, uv_name), lookup(FS_VALUES, node_name));
    }
    // `internal/vfs/providers/composable.js` reads COPYFILE_EXCL directly.
    assert_eq!(lookup(FS_VALUES, "COPYFILE_EXCL"), Some(Value::int(1)));
}

#[test]
fn signal_constants_match_linux() {
    for (name, expected) in [
        ("SIGHUP", 1),
        ("SIGINT", 2),
        ("SIGQUIT", 3),
        ("SIGKILL", 9),
        ("SIGUSR1", 10),
        ("SIGSEGV", 11),
        ("SIGPIPE", 13),
        ("SIGTERM", 15),
        ("SIGCHLD", 17),
        ("SIGCONT", 18),
        ("SIGWINCH", 28),
        // SIGPOLL and SIGIO share a number on Linux, as do SIGIOT and SIGABRT.
        ("SIGIO", 29),
        ("SIGPOLL", 29),
        ("SIGABRT", 6),
        ("SIGIOT", 6),
        // Not the Windows-only SIGBREAK, and no SIGLOST/SIGINFO on Linux.
        ("SIGPWR", 30),
        ("SIGSYS", 31),
    ] {
        assert_eq!(
            lookup(SIGNALS_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with Linux"
        );
    }
}

#[test]
fn signals_table_omits_platform_absent_names() {
    for absent in ["SIGBREAK", "SIGLOST", "SIGINFO", "SIGUNUSED"] {
        assert_eq!(
            lookup(SIGNALS_VALUES, absent),
            None,
            "{absent} does not exist on Linux and must not be published"
        );
    }
}

#[test]
fn errno_constants_match_linux() {
    for (name, expected) in [
        ("EPERM", 1),
        ("ENOENT", 2),
        ("EINTR", 4),
        ("EIO", 5),
        ("EAGAIN", 11),
        ("ENOMEM", 12),
        ("EACCES", 13),
        ("EEXIST", 17),
        ("EISDIR", 21),
        ("EINVAL", 22),
        ("EMFILE", 24),
        ("ENOTDIR", 20),
        ("ENOSPC", 28),
        ("EPIPE", 32),
        ("ERANGE", 34),
        ("ENAMETOOLONG", 36),
        ("ENOSYS", 38),
        ("ELOOP", 40),
        ("EADDRINUSE", 98),
        ("ECONNRESET", 104),
        ("ETIMEDOUT", 110),
        // Aliases, exactly as glibc defines them.
        ("EWOULDBLOCK", 11),
        ("EOPNOTSUPP", 95),
        ("ENOTSUP", 95),
    ] {
        assert_eq!(
            lookup(ERRNO_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with Linux"
        );
    }
    // `internal/fs/utils.js` reads EISDIR to build ERR_FS_EISDIR.
    assert_eq!(lookup(ERRNO_VALUES, "EISDIR"), Some(Value::int(21)));
}

#[test]
fn priority_constants_use_the_portable_names() {
    // The libuv macros are UV_PRIORITY_*, but Node publishes them without the
    // prefix so `os.getPriority`/`setPriority` accept them.
    for (name, expected) in [
        ("PRIORITY_LOW", 19),
        ("PRIORITY_BELOW_NORMAL", 10),
        ("PRIORITY_NORMAL", 0),
        ("PRIORITY_ABOVE_NORMAL", -7),
        ("PRIORITY_HIGH", -14),
        ("PRIORITY_HIGHEST", -20),
    ] {
        assert_eq!(lookup(PRIORITY_VALUES, name), Some(Value::int(expected)));
    }
    assert_eq!(lookup(PRIORITY_VALUES, "UV_PRIORITY_LOW"), None);
}

#[test]
fn dlopen_constants_match_linux() {
    for (name, expected) in [
        ("RTLD_LAZY", 1),
        ("RTLD_NOW", 2),
        ("RTLD_LOCAL", 0),
        ("RTLD_GLOBAL", 0x100),
        ("RTLD_DEEPBIND", 8),
    ] {
        assert_eq!(
            lookup(DLOPEN_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with glibc"
        );
    }
}

#[test]
fn crypto_constants_match_openssl() {
    for (name, expected) in [
        // TLS record versions.
        ("TLS1_VERSION", 0x0301),
        ("TLS1_1_VERSION", 0x0302),
        ("TLS1_2_VERSION", 0x0303),
        ("TLS1_3_VERSION", 0x0304),
        // Point conversion forms; `internal/crypto/keys.js` and
        // `diffiehellman.js` read these.
        ("POINT_CONVERSION_COMPRESSED", 2),
        ("POINT_CONVERSION_UNCOMPRESSED", 4),
        ("POINT_CONVERSION_HYBRID", 6),
        // RSA padding; `internal/crypto/cipher.js` reads the first two.
        ("RSA_PKCS1_PADDING", 1),
        ("RSA_SSLV23_PADDING", 2),
        ("RSA_NO_PADDING", 3),
        ("RSA_PKCS1_OAEP_PADDING", 4),
        ("RSA_X931_PADDING", 5),
        ("RSA_PKCS1_PSS_PADDING", 6),
        ("RSA_PSS_SALTLEN_DIGEST", -1),
        ("RSA_PSS_SALTLEN_MAX_SIGN", -2),
        ("RSA_PSS_SALTLEN_AUTO", -2),
        // DH verification failures.
        ("DH_CHECK_P_NOT_PRIME", 0x01),
        ("DH_CHECK_P_NOT_SAFE_PRIME", 0x02),
        ("DH_UNABLE_TO_CHECK_GENERATOR", 0x04),
        ("DH_NOT_SUITABLE_GENERATOR", 0x08),
        // A few SSL_OP bits; the full set is checked for presence below.
        ("SSL_OP_LEGACY_SERVER_CONNECT", 0x4),
        ("SSL_OP_ALLOW_NO_DHE_KEX", 0x400),
        ("SSL_OP_CIPHER_SERVER_PREFERENCE", 0x400000),
    ] {
        assert_eq!(
            lookup(CRYPTO_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with OpenSSL"
        );
    }
}

#[test]
fn crypto_ssl_op_all_includes_its_documented_bits() {
    let all = match lookup(CRYPTO_VALUES, "SSL_OP_ALL") {
        Some(Value::Num(value)) => value as i64,
        other => panic!("SSL_OP_ALL missing or not numeric: {other:?}"),
    };
    // OpenSSL 4.1 defines `SSL_OP_ALL` as exactly the OR of these three
    // "rather harmless bug workaround" bits. Older OpenSSL also folded in
    // mitigations such as SSL_OP_NO_QUERY_MTU and SSL_OP_COOKIE_EXCHANGE, which
    // are still published individually but are no longer part of the mask.
    for bit in [
        "SSL_OP_SAFARI_ECDHE_ECDSA_BUG",
        "SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS",
        "SSL_OP_CRYPTOPRO_TLSEXT_BUG",
    ] {
        let Some(Value::Num(value)) = lookup(CRYPTO_VALUES, bit) else {
            // SSL_OP_SAFARI_ECDHE_ECDSA_BUG is not published by Node, so assert
            // it through the aggregate only.
            if bit == "SSL_OP_SAFARI_ECDHE_ECDSA_BUG" {
                assert_ne!(all & 0x40, 0, "SSL_OP_ALL is missing {bit}");
                continue;
            }
            panic!("{bit} missing or not numeric");
        };
        assert_eq!(
            all & (value as i64),
            value as i64,
            "SSL_OP_ALL is missing {bit}"
        );
    }
    // The three bits above are the whole mask on this OpenSSL version.
    assert_eq!(
        all,
        // SSL_OP_BIT(31) | SSL_OP_BIT(11) | SSL_OP_BIT(6)
        (1i64 << 31) | (1 << 11) | (1 << 6)
    );
}

#[test]
fn crypto_publishes_every_openssl_option_node_defines() {
    // `DefineCryptoConstants` in Node 28 defines exactly these SSL_OP entries.
    let expected = [
        "SSL_OP_ALLOW_NO_DHE_KEX",
        "SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION",
        "SSL_OP_CIPHER_SERVER_PREFERENCE",
        "SSL_OP_CISCO_ANYCONNECT",
        "SSL_OP_COOKIE_EXCHANGE",
        "SSL_OP_CRYPTOPRO_TLSEXT_BUG",
        "SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS",
        "SSL_OP_LEGACY_SERVER_CONNECT",
        "SSL_OP_NO_COMPRESSION",
        "SSL_OP_NO_ENCRYPT_THEN_MAC",
        "SSL_OP_NO_QUERY_MTU",
        "SSL_OP_NO_RENEGOTIATION",
        "SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION",
        "SSL_OP_NO_SSLv2",
        "SSL_OP_NO_SSLv3",
        "SSL_OP_NO_TICKET",
        "SSL_OP_NO_TLSv1",
        "SSL_OP_NO_TLSv1_1",
        "SSL_OP_NO_TLSv1_2",
        "SSL_OP_NO_TLSv1_3",
        "SSL_OP_PRIORITIZE_CHACHA",
        "SSL_OP_TLS_ROLLBACK_BUG",
        "OPENSSL_VERSION_NUMBER",
    ];
    for name in expected {
        assert!(
            lookup(CRYPTO_VALUES, name).is_some(),
            "crypto is missing {name}"
        );
    }
    // `lib/crypto.js` assigns `constants.defaultCipherList` itself from
    // `--tls-cipher-list`, so the binding must not pre-empt it.
    assert_eq!(lookup(CRYPTO_VALUES, "defaultCipherList"), None);
}

#[test]
fn crypto_default_core_cipher_list_matches_node() {
    let Some(Value::Str(list)) = lookup(CRYPTO_VALUES, "defaultCoreCipherList") else {
        panic!("defaultCoreCipherList must be published as a string");
    };
    // Node's DEFAULT_CIPHER_LIST_CORE: three TLS 1.3 suites then the TLS 1.2
    // selection, ending with the exclusion list.
    assert_eq!(
        list.matches(':').count(),
        23,
        "wrong number of cipher entries"
    );
    assert!(list.starts_with("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"));
    assert!(list.ends_with("!PSK:!SRP:!CAMELLIA"));
    assert!(list.contains(":HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:"));
    // `lib/crypto.js` replaces `defaultCipherList` with the --tls-cipher-list
    // option; the core list must be a separate, distinct property.
    assert_eq!(lookup(CRYPTO_VALUES, "defaultCipherList"), None);
}

#[test]
fn zlib_flush_and_error_codes_match_zlib() {
    for (name, expected) in [
        ("Z_NO_FLUSH", 0),
        ("Z_PARTIAL_FLUSH", 1),
        ("Z_SYNC_FLUSH", 2),
        ("Z_FULL_FLUSH", 3),
        ("Z_FINISH", 4),
        ("Z_BLOCK", 5),
        ("Z_OK", 0),
        ("Z_STREAM_END", 1),
        ("Z_NEED_DICT", 2),
        ("Z_ERRNO", -1),
        ("Z_STREAM_ERROR", -2),
        ("Z_DATA_ERROR", -3),
        ("Z_MEM_ERROR", -4),
        ("Z_BUF_ERROR", -5),
        ("Z_VERSION_ERROR", -6),
        ("Z_NO_COMPRESSION", 0),
        ("Z_BEST_SPEED", 1),
        ("Z_BEST_COMPRESSION", 9),
        ("Z_DEFAULT_COMPRESSION", -1),
        ("Z_DEFAULT_STRATEGY", 0),
        ("Z_FIXED", 4),
    ] {
        assert_eq!(
            lookup(ZLIB_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with zlib"
        );
    }
}

#[test]
fn zlib_mode_enum_matches_node_zlib() {
    // `enum node_zlib_mode` in src/node_zlib.cc. Note the declaration order:
    // BROTLI_DECODE precedes BROTLI_ENCODE, but ZSTD_COMPRESS precedes
    // ZSTD_DECOMPRESS.
    for (name, expected) in [
        ("DEFLATE", 1),
        ("INFLATE", 2),
        ("GZIP", 3),
        ("GUNZIP", 4),
        ("DEFLATERAW", 5),
        ("INFLATERAW", 6),
        ("UNZIP", 7),
        ("BROTLI_DECODE", 8),
        ("BROTLI_ENCODE", 9),
        ("ZSTD_COMPRESS", 10),
        ("ZSTD_DECOMPRESS", 11),
    ] {
        assert_eq!(lookup(ZLIB_VALUES, name), Some(Value::int(expected)));
    }
}

#[test]
fn zlib_ranges_match_node_zlib_defines() {
    for (name, expected) in [
        ("Z_MIN_CHUNK", 64),
        ("Z_DEFAULT_CHUNK", 16 * 1024),
        ("Z_MIN_WINDOWBITS", 8),
        ("Z_MAX_WINDOWBITS", 15),
        ("Z_DEFAULT_WINDOWBITS", 15),
        ("Z_MIN_MEMLEVEL", 1),
        ("Z_MAX_MEMLEVEL", 9),
        ("Z_DEFAULT_MEMLEVEL", 8),
        ("Z_MIN_LEVEL", -1),
        ("Z_MAX_LEVEL", 9),
        ("Z_DEFAULT_LEVEL", -1),
    ] {
        assert_eq!(
            lookup(ZLIB_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with src/node_zlib.cc"
        );
    }
}

#[test]
fn zlib_max_chunk_is_infinity() {
    // `Z_MAX_CHUNK` is `std::numeric_limits<double>::infinity()` in Node.
    assert_eq!(
        lookup(ZLIB_VALUES, "Z_MAX_CHUNK"),
        Some(Value::Num(f64::INFINITY))
    );
}

#[test]
fn brotli_constants_match_brotli_headers() {
    for (name, expected) in [
        ("BROTLI_OPERATION_PROCESS", 0),
        ("BROTLI_OPERATION_FLUSH", 1),
        ("BROTLI_OPERATION_FINISH", 2),
        ("BROTLI_OPERATION_EMIT_METADATA", 3),
        ("BROTLI_PARAM_MODE", 0),
        ("BROTLI_PARAM_QUALITY", 1),
        ("BROTLI_PARAM_LGWIN", 2),
        ("BROTLI_PARAM_LGBLOCK", 3),
        ("BROTLI_MAX_QUALITY", 11),
        ("BROTLI_DEFAULT_WINDOW", 22),
        ("BROTLI_LARGE_MAX_WINDOW_BITS", 30),
        // Decoder results, including the "needs more" pair `zlib.js` branches on.
        ("BROTLI_DECODER_RESULT_ERROR", 0),
        ("BROTLI_DECODER_RESULT_SUCCESS", 1),
        ("BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT", 2),
        ("BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT", 3),
        // First and last detailed error codes; the middle is contiguous.
        ("BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_NIBBLE", -1),
        ("BROTLI_DECODER_ERROR_UNREACHABLE", -31),
    ] {
        assert_eq!(
            lookup(ZLIB_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with brotli"
        );
    }
}

#[test]
fn zstd_constants_match_zstd_headers() {
    for (name, expected) in [
        ("ZSTD_e_continue", 0),
        ("ZSTD_e_flush", 1),
        ("ZSTD_e_end", 2),
        ("ZSTD_fast", 1),
        ("ZSTD_btultra2", 9),
        ("ZSTD_c_compressionLevel", 100),
        ("ZSTD_c_nbWorkers", 400),
        ("ZSTD_CLEVEL_DEFAULT", 3),
        ("ZSTD_error_no_error", 0),
        ("ZSTD_error_GENERIC", 1),
        // Stable codes, then the two "no forward progress" pair.
        ("ZSTD_error_dstBuffer_null", 74),
        ("ZSTD_error_noForwardProgress_destFull", 80),
        ("ZSTD_error_noForwardProgress_inputEmpty", 82),
    ] {
        assert_eq!(
            lookup(ZLIB_VALUES, name),
            Some(Value::int(expected)),
            "{name} disagrees with zstd"
        );
    }
}

#[test]
fn trace_phases_are_character_codes() {
    for (name, character) in [
        ("TRACE_EVENT_PHASE_BEGIN", "B"),
        ("TRACE_EVENT_PHASE_END", "E"),
        ("TRACE_EVENT_PHASE_COMPLETE", "X"),
        ("TRACE_EVENT_PHASE_INSTANT", "I"),
        ("TRACE_EVENT_PHASE_COUNTER", "C"),
        ("TRACE_EVENT_PHASE_ASYNC_BEGIN", "S"),
        ("TRACE_EVENT_PHASE_METADATA", "M"),
        ("TRACE_EVENT_PHASE_MEMORY_DUMP", "v"),
    ] {
        let code = character.as_bytes()[0] as i64;
        assert_eq!(
            lookup(TRACE_VALUES, name),
            Some(Value::int(code)),
            "{name} should be the code of {character:?}"
        );
    }
}

#[test]
fn internal_formats_are_ordered_so_wasm_is_one() {
    // `internal/modules/esm/get_format.js` compares a binding result against
    // these instead of a boolean, so the values must stay distinct and ordered.
    assert_eq!(
        lookup(INTERNAL_VALUES, "EXTENSIONLESS_FORMAT_JAVASCRIPT"),
        Some(Value::int(0))
    );
    assert_eq!(
        lookup(INTERNAL_VALUES, "EXTENSIONLESS_FORMAT_WASM"),
        Some(Value::int(1))
    );
}

#[test]
fn register_publishes_both_namespaces_with_their_full_member_lists() {
    // `tools/regen-bindings.sh` calls this, and `rn-compat` checks the result
    // against contracts/config.json and contracts/constants.json. The member
    // list must match what install() actually defines, otherwise the contract
    // check passes while lib/** reads undefined.
    let mut registry = rn_core::BindingRegistry::new();
    rn_bind_config::register(&mut registry);

    assert_eq!(
        registry.names().collect::<Vec<_>>(),
        vec!["config", "constants"]
    );

    let config = registry
        .namespaces()
        .iter()
        .find(|namespace| namespace.name == "config")
        .expect("config must be registered");
    assert_eq!(
        config
            .members
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "bits",
            "getDefaultLocale",
            "hasInspector",
            "hasIntl",
            "hasNodeOptions",
            "hasOpenSSL",
            "hasSmallICU",
            "hasTracing",
            "isDebugBuild",
            "noBrowserGlobals",
            "openSSLIsBoringSSL",
        ],
        "config registration must cover contracts/config.json exactly"
    );

    let constants = registry
        .namespaces()
        .iter()
        .find(|namespace| namespace.name == "constants")
        .expect("constants must be registered");
    assert_eq!(
        constants
            .members
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["crypto", "fs", "internal", "os", "trace", "zlib"],
        "constants registration must cover contracts/constants.json exactly"
    );
}

#[test]
fn no_table_publishes_a_duplicate_member() {
    let tables: [(&str, &[(&'static str, Value)]); 9] = [
        ("os", OS_VALUES),
        ("dlopen", DLOPEN_VALUES),
        ("errno", ERRNO_VALUES),
        ("signals", SIGNALS_VALUES),
        ("priority", PRIORITY_VALUES),
        ("fs", FS_VALUES),
        ("crypto", CRYPTO_VALUES),
        ("zlib", ZLIB_VALUES),
        ("trace", TRACE_VALUES),
    ];
    for (table_name, table) in tables {
        let mut seen = std::collections::BTreeSet::new();
        for (name, _) in table {
            assert!(seen.insert(*name), "{table_name} repeats {name}");
        }
    }
}

/// The exact destructuring statements `lib/**` performs, evaluated against the
/// installed namespaces.
///
/// A missing property would not throw here -- destructuring yields `undefined`
/// -- so each binding is also checked to be a number where the JS layer treats
/// it as one. This is the check that catches a table entry being renamed.
#[test]
fn every_lib_destructure_statement_resolves() {
    with_context(|scope| {
        let config = install(scope, &Config);
        let constants = install(scope, &Constants);

        let global = scope.get_current_context().global(scope);
        for (name, object) in [("__config", config), ("__constants", constants)] {
            let key = v8::String::new(scope, name).expect("allocating binding name");
            global.set(scope, key.into(), object.into());
        }

        // Each entry mirrors one `internalBinding(...)` site in
        // vendor/libnode-js/lib. `typeof` is used so a wrong type fails loudly
        // instead of silently travelling as a truthy object.
        let result = eval_with(
            scope,
            constants,
            "const types = (object, names) =>
               names.map((name) => `${name}:${typeof object[name]}`).join(' ');
             JSON.stringify({
               // lib/fs.js, lib/internal/fs/streams.js. O_SYMLINK is absent on
               // purpose: it is a macOS/FreeBSD flag, and lib/fs.js only
               // exposes lchmod when it is defined.
               fs: types(__constants.fs, [
                 'S_IFIFO', 'S_IFLNK', 'S_IFMT', 'S_IFREG', 'S_IFSOCK',
                 'F_OK', 'O_WRONLY', 'O_RDONLY',
               ]),
               lchmodGatedOnSymlink: __constants.fs.O_SYMLINK !== undefined,
               // lib/internal/fs/utils.js and lib/internal/fs/cp/cp.js
               utils: types(__constants.fs, [
                 'UV_DIRENT_UNKNOWN', 'UV_DIRENT_FILE', 'UV_DIRENT_DIR',
                 'UV_DIRENT_LINK', 'UV_DIRENT_FIFO', 'UV_DIRENT_SOCKET',
                 'UV_DIRENT_CHAR', 'UV_DIRENT_BLOCK',
                 'COPYFILE_EXCL', 'COPYFILE_FICLONE', 'COPYFILE_FICLONE_FORCE',
               ]),
               // lib/internal/fs/utils.js reads os.errno.EISDIR
               errno: types(__constants.os.errno, ['EISDIR']),
               // lib/internal/validators.js, lib/internal/util.js, lib/os.js,
               // lib/internal/process/per_thread.js, lib/internal/process/signal.js
               signals: types(__constants.os.signals, [
                 'SIGHUP', 'SIGINT', 'SIGTERM', 'SIGKILL', 'SIGKILL',
                 'SIGWINCH', 'SIGCHLD',
               ]),
               // lib/dgram.js
               udp: types(__constants.os, ['UV_UDP_REUSEADDR']),
               // lib/constants.js flattens these four plus fs and crypto
               os: types(__constants.os, [
                 'dlopen', 'errno', 'priority', 'signals',
               ]),
               // lib/internal/tls/common.js, lib/internal/tls/secure-context.js
               tls: types(__constants.crypto, [
                 'SSL_OP_CIPHER_SERVER_PREFERENCE',
                 'TLS1_VERSION', 'TLS1_1_VERSION', 'TLS1_2_VERSION',
                 'TLS1_3_VERSION',
               ]),
               // lib/internal/crypto/{keys,ec,diffiehellman,cipher}.js
               crypto: types(__constants.crypto, [
                 'POINT_CONVERSION_COMPRESSED', 'POINT_CONVERSION_UNCOMPRESSED',
                 'POINT_CONVERSION_HYBRID', 'RSA_PKCS1_PADDING',
                 'RSA_PKCS1_OAEP_PADDING', 'RSA_PKCS1_PSS_PADDING',
                 'RSA_PSS_SALTLEN_MAX_SIGN',
               ]),
               // lib/zlib.js and lib/internal/streams/iter/transform.js
               zlib: types(__constants.zlib, [
                 'Z_NO_FLUSH', 'Z_BLOCK', 'Z_PARTIAL_FLUSH', 'Z_SYNC_FLUSH',
                 'Z_FULL_FLUSH', 'Z_FINISH', 'Z_OK', 'Z_STREAM_END',
                 'Z_NEED_DICT', 'Z_ERRNO', 'Z_STREAM_ERROR', 'Z_DATA_ERROR',
                 'Z_MEM_ERROR', 'Z_BUF_ERROR', 'Z_VERSION_ERROR',
                 'Z_MIN_CHUNK', 'Z_MIN_WINDOWBITS', 'Z_MAX_WINDOWBITS',
                 'Z_MIN_LEVEL', 'Z_MAX_LEVEL', 'Z_MIN_MEMLEVEL',
                 'Z_MAX_MEMLEVEL', 'Z_DEFAULT_CHUNK',
                 'Z_DEFAULT_COMPRESSION', 'Z_DEFAULT_STRATEGY',
                 'Z_DEFAULT_WINDOWBITS', 'Z_DEFAULT_MEMLEVEL', 'Z_FIXED',
                 'DEFLATE', 'DEFLATERAW', 'INFLATE', 'INFLATERAW', 'GZIP',
                 'GUNZIP', 'UNZIP', 'BROTLI_DECODE', 'BROTLI_ENCODE',
                 'ZSTD_COMPRESS', 'ZSTD_DECOMPRESS',
                 'BROTLI_OPERATION_PROCESS', 'BROTLI_OPERATION_FLUSH',
                 'BROTLI_OPERATION_FINISH',
                 'BROTLI_OPERATION_EMIT_METADATA',
                 'ZSTD_e_continue', 'ZSTD_e_flush', 'ZSTD_e_end',
               ]),
               // lib/internal/modules/esm/get_format.js, lib/internal/vfs/setup.js
               internal: types(__constants.internal, [
                 'EXTENSIONLESS_FORMAT_JAVASCRIPT',
                 'EXTENSIONLESS_FORMAT_WASM',
               ]),
             })",
        );

        // Every leaf must be a number; no `undefined` and no accidental object.
        assert!(
            !result.contains(":undefined"),
            "a lib destructure resolved to undefined: {result}"
        );
        assert!(result.contains(r#""udp":"UV_UDP_REUSEADDR:number""#));
        assert!(result.contains(r#""internal":"EXTENSIONLESS_FORMAT_JAVASCRIPT:number"#));
        // The only objects are the four os sub-tables lib/constants.js flattens.
        assert_eq!(
            result,
            concat!(
                r#"{"fs":"S_IFIFO:number S_IFLNK:number S_IFMT:number S_IFREG:number "#,
                r#"S_IFSOCK:number F_OK:number O_WRONLY:number O_RDONLY:number","#,
                r#""lchmodGatedOnSymlink":false,"#,
                r#""utils":"UV_DIRENT_UNKNOWN:number UV_DIRENT_FILE:number "#,
                r#"UV_DIRENT_DIR:number UV_DIRENT_LINK:number UV_DIRENT_FIFO:number "#,
                r#"UV_DIRENT_SOCKET:number UV_DIRENT_CHAR:number UV_DIRENT_BLOCK:number "#,
                r#"COPYFILE_EXCL:number COPYFILE_FICLONE:number "#,
                r#"COPYFILE_FICLONE_FORCE:number","#,
                r#""errno":"EISDIR:number","#,
                r#""signals":"SIGHUP:number SIGINT:number SIGTERM:number SIGKILL:number "#,
                r#"SIGKILL:number SIGWINCH:number SIGCHLD:number","#,
                r#""udp":"UV_UDP_REUSEADDR:number","#,
                r#""os":"dlopen:object errno:object priority:object signals:object","#,
                r#""tls":"SSL_OP_CIPHER_SERVER_PREFERENCE:number TLS1_VERSION:number "#,
                r#"TLS1_1_VERSION:number TLS1_2_VERSION:number TLS1_3_VERSION:number","#,
                r#""crypto":"POINT_CONVERSION_COMPRESSED:number "#,
                r#"POINT_CONVERSION_UNCOMPRESSED:number POINT_CONVERSION_HYBRID:number "#,
                r#"RSA_PKCS1_PADDING:number RSA_PKCS1_OAEP_PADDING:number "#,
                r#"RSA_PKCS1_PSS_PADDING:number RSA_PSS_SALTLEN_MAX_SIGN:number","#,
                r#""zlib":"Z_NO_FLUSH:number Z_BLOCK:number Z_PARTIAL_FLUSH:number "#,
                r#"Z_SYNC_FLUSH:number Z_FULL_FLUSH:number Z_FINISH:number Z_OK:number "#,
                r#"Z_STREAM_END:number Z_NEED_DICT:number Z_ERRNO:number "#,
                r#"Z_STREAM_ERROR:number Z_DATA_ERROR:number Z_MEM_ERROR:number "#,
                r#"Z_BUF_ERROR:number Z_VERSION_ERROR:number Z_MIN_CHUNK:number "#,
                r#"Z_MIN_WINDOWBITS:number Z_MAX_WINDOWBITS:number Z_MIN_LEVEL:number "#,
                r#"Z_MAX_LEVEL:number Z_MIN_MEMLEVEL:number Z_MAX_MEMLEVEL:number "#,
                r#"Z_DEFAULT_CHUNK:number Z_DEFAULT_COMPRESSION:number "#,
                r#"Z_DEFAULT_STRATEGY:number Z_DEFAULT_WINDOWBITS:number "#,
                r#"Z_DEFAULT_MEMLEVEL:number Z_FIXED:number DEFLATE:number "#,
                r#"DEFLATERAW:number INFLATE:number INFLATERAW:number GZIP:number "#,
                r#"GUNZIP:number UNZIP:number BROTLI_DECODE:number "#,
                r#"BROTLI_ENCODE:number ZSTD_COMPRESS:number ZSTD_DECOMPRESS:number "#,
                r#"BROTLI_OPERATION_PROCESS:number BROTLI_OPERATION_FLUSH:number "#,
                r#"BROTLI_OPERATION_FINISH:number "#,
                r#"BROTLI_OPERATION_EMIT_METADATA:number ZSTD_e_continue:number "#,
                r#"ZSTD_e_flush:number ZSTD_e_end:number","#,
                r#""internal":"EXTENSIONLESS_FORMAT_JAVASCRIPT:number "#,
                r#"EXTENSIONLESS_FORMAT_WASM:number"}"#
            )
        );
    });
}

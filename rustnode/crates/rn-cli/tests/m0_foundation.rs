//! Milestone M0: the binary links the pinned V8 and evaluates JavaScript.

use std::process::Command;

fn rustnode(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(args)
        .output()
        .expect("rustnode runs")
}

#[test]
fn eval_prints_integer_result() {
    let out = rustnode(&["-p", "1+1"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2");
}

#[test]
fn console_log_writes_stdout() {
    let out = rustnode(&["-e", "console.log(1+1)"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2");
}

#[test]
fn console_error_writes_stderr() {
    let out = rustnode(&["-e", "console.error('bad')"]);
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "bad");
}

#[test]
fn thrown_error_exits_nonzero() {
    let out = rustnode(&["-e", "throw new Error('boom')"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Uncaught Error: boom"));
}

#[test]
fn script_file_runs() {
    let dir = std::env::temp_dir().join("rustnode-m0");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("script.js");
    std::fs::write(&path, "console.log(6*7)").expect("write script");
    let out = rustnode(&[path.to_str().expect("utf8 path")]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "42");
}

#[test]
fn linked_v8_matches_pin() {
    let out = rustnode(&["-p", "process.versions.v8"]);
    let version = String::from_utf8_lossy(&out.stdout);
    assert!(version.trim().starts_with("15.2."), "got {version}");
}

#[test]
fn a_script_path_becomes_the_second_argument() {
    // `process.argv[1]` is the script, which is how a program finds itself, and
    // the arguments after it belong to the script.
    let dir = std::env::temp_dir().join("rustnode-argv-script");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("argv.js");
    std::fs::write(&path, "console.log(JSON.stringify(process.argv))").expect("write script");
    let out = rustnode(&[path.to_str().expect("utf8 path"), "one", "two"]);
    let printed = String::from_utf8_lossy(&out.stdout);
    let printed = printed.trim();
    let expected_path = std::path::absolute(&path)
        .expect("an absolute path")
        .to_string_lossy()
        .into_owned();
    assert!(
        printed.contains(&format!("\"{expected_path}\",\"one\",\"two\"]")),
        "argv must be [execPath, script, args], got {printed}"
    );
}

#[test]
fn eval_arguments_follow_the_executable() {
    // Node reports no script slot for `-e`, so the arguments start at index 1,
    // and an explicit `--` is only a separator.
    let out = rustnode(&[
        "-e",
        "console.log(JSON.stringify(process.argv.slice(1)))",
        "--",
        "a",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), r#"["a"]"#);

    let out = rustnode(&[
        "-e",
        "console.log(JSON.stringify(process.argv.slice(1)))",
        "a",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), r#"["a"]"#);

    let out = rustnode(&["-p", "JSON.stringify(process.argv.length)"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
}

#[test]
fn exec_argv_reproduces_the_entry_point() {
    // A child process inherits these, so they have to exclude the executable and
    // any script path but keep `-e` and its source.
    let out = rustnode(&[
        "--expose-internals",
        "-p",
        "JSON.stringify(process.execArgv)",
    ]);
    let printed = String::from_utf8_lossy(&out.stdout);
    let printed = printed.trim();
    assert!(
        printed.starts_with(r#"["--expose-internals","-p","#),
        "got {printed}"
    );
    assert!(
        !printed.contains("rustnode\""),
        "the executable must not be in execArgv, got {printed}"
    );
}

#[test]
fn a_builtin_can_be_required_with_its_scheme() {
    // `node:path` and `path` name the same module, and user code writes both.
    // The internal loader matches ids verbatim, so the scheme has to be
    // normalized away before the lookup.
    let out = rustnode(&["-e", "console.log(typeof require('node:path').join)"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "function");

    let out = rustnode(&[
        "-e",
        "console.log(require('node:path') === require('path'))",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true");
}

#[test]
fn an_unknown_specifier_still_fails_with_the_scheme_stripped() {
    // The wrapper must not turn a typo into a silent success.
    let out = rustnode(&["-e", "require('node:not-a-real-builtin')"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not-a-real-builtin"),
        "the error must name the specifier"
    );
}

#[test]
fn a_relative_specifier_is_not_treated_as_a_builtin() {
    let out = rustnode(&["-e", "require('./does-not-exist.js')"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("./does-not-exist.js"),
        "the specifier must survive untouched so the loader can report it"
    );
}

#[test]
fn structured_clone_is_a_real_serializer_round_trip() {
    // It comes from the messaging binding, so a cycle has to survive and a
    // copied object has to stop sharing identity with the original.
    let out = rustnode(&[
        "-e",
        "const o = {n: 1}; o.self = o; const c = structuredClone(o);\n\
         console.log(c.self === c, c === o, c.n);",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true false 1");
}

#[test]
fn text_encoder_and_decoder_are_the_node_implementations() {
    // `internal/encoding` is the vendored Node module, so the encoding label and
    // the byte values have to match Node's rather than be plausible.
    let out = rustnode(&[
        "-e",
        "const e = new TextEncoder();\n\
         console.log(e.encoding, JSON.stringify(Array.from(e.encode('héllo'))));\n\
         const d = new TextDecoder();\n\
         console.log(d.encoding, d.decode(new Uint8Array([104, 195, 169, 108, 108, 111])));",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "utf-8 [104,195,169,108,108,111]\nutf-8 héllo"
    );
}

#[test]
fn the_buffer_global_is_the_module_itself() {
    // The global must be the same function `require('buffer')` hands out, not a
    // second copy: `instanceof` across the two has to hold.
    let out = rustnode(&[
        "-e",
        "console.log(Buffer === require('buffer').Buffer,\n\
         Buffer.from('hi').toString('base64'),\n\
         Buffer.byteLength('héllo'));",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true aGk= 6");
}

#[test]
fn btoa_and_atob_round_trip() {
    let out = rustnode(&["-e", "console.log(btoa('hi'), atob('aGk='))"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "aGk= hi");
}

#[test]
fn console_log_formats_the_way_node_does() {
    // `console.log` is `util.format`, so the first argument is a format string
    // and objects are inspected rather than JSON-serialized. Both were wrong
    // and neither shows up in a contract check.
    let out = rustnode(&[
        "-e",
        "console.log([1, 2, 3]);\n\
         console.log({ a: 1, b: { c: 2 } });\n\
         console.log('str', 42, null, undefined);\n\
         console.log(new Map([[1, 2]]));\n\
         console.log('%s-%d', 'v', 42);",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "[ 1, 2, 3 ]\n\
         { a: 1, b: { c: 2 } }\n\
         str 42 null undefined\n\
         Map(1) { 1 => 2 }\n\
         v-42\n"
    );
}

#[test]
fn console_error_also_formats() {
    let out = rustnode(&["-e", "console.error({ a: [1] })"]);
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "{ a: [ 1 ] }");
}

#[test]
fn lazily_defined_properties_resolve_on_first_read() {
    // `defineLazyProperties` is a C++ function in Node and `lib/stream.js`
    // depends on it: a broken version leaves `stream.Transform` present but
    // `undefined`, which makes `zlib` fail with `Class extends value undefined`.
    // Both source shapes that `lib/**` uses are exercised here.
    let out = rustnode(&[
        "--expose-internals",
        "-e",
        "const realm = require('internal/bootstrap/realm');\n\
         const util = realm.internalBinding('util');\n\
         const named = {};\n\
         util.defineLazyProperties(named, 'path', ['join']);\n\
         const whole = {};\n\
         util.defineLazyProperties(whole, { Duplex: 'internal/streams/duplex' }, ['Duplex']);\n\
         console.log(typeof named.join, typeof whole.Duplex);",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "function function"
    );
}

#[test]
fn stream_and_zlib_work_through_lazy_properties() {
    // The end-to-end consequence: `stream`'s lazy exports have to be real, and
    // `zlib` builds `ZlibBase` on `stream.Transform`.
    let out = rustnode(&[
        "-e",
        "const zlib = require('zlib');\n\
         const stream = require('stream');\n\
         const gz = zlib.gzipSync(Buffer.from('hello'));\n\
         console.log(typeof stream.Transform, gz.length, zlib.gunzipSync(gz).toString());",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "function 25 hello"
    );
}

#[test]
fn crypto_reports_the_openssl_it_linked_and_hashes_correctly() {
    // `lib/internal/util.js` decides whether crypto exists by reading
    // `process.versions.openssl` at module scope, so a missing version makes
    // `require('crypto')` throw ERR_NO_CRYPTO even with the binding installed.
    // The digest values are the published SHA-256 and HMAC-SHA256 of "abc".
    let out = rustnode(&[
        "-e",
        "const c = require('crypto');\n\
         console.log(process.versions.openssl.length > 0,\n\
           c.createHash('sha256').update('abc').digest('hex'),\n\
           c.createHmac('sha256', 'key').update('abc').digest('hex'));",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "true ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
         9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab"
    );
}

#[test]
fn process_features_reports_what_the_binary_actually_has() {
    // `lib/internal/crypto/**` destructures `openssl_is_boringssl` at module
    // scope, so the object must exist. The flags must not overstate: TLS is not
    // implemented, so it has to read false.
    let out = rustnode(&[
        "-e",
        "const f = process.features;\n\
         console.log(f.openssl_is_boringssl, f.tls, f.uv, typeof f.inspector);",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "false false true boolean"
    );
}

#[test]
fn a_script_reports_failure_through_the_exit_code() {
    // Node's own tests fail by setting `process.exitCode`, not by throwing, so
    // a runtime that ignores it would report every test as passing.
    let out = rustnode(&["-e", "process.exitCode = 3"]);
    assert_eq!(out.status.code(), Some(3));

    let out = rustnode(&["-e", "process.exitCode = 0"]);
    assert_eq!(out.status.code(), Some(0));

    // Unset means 0, and a throw still wins over an explicit code.
    let out = rustnode(&["-e", "1"]);
    assert_eq!(out.status.code(), Some(0));

    let out = rustnode(&["-e", "process.exitCode = 3; throw new Error('boom')"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_script_file_reports_its_exit_code_too() {
    // The same path has to work for a file, which is how the harness runs a
    // test: `node test/parallel/test-x.js`.
    let dir = std::env::temp_dir().join("rustnode-exit-code");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("fails.js");
    std::fs::write(
        &path,
        "console.log('about to fail');\nprocess.exitCode = 4;\n",
    )
    .expect("write script");
    let out = rustnode(&[path.to_str().expect("utf8 path")]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "about to fail",
        "the script must still run to completion"
    );
}

#[test]
fn process_memory_usage_reports_real_numbers() {
    // `per_thread.js` builds this object from the `Float64Array(5)` the binding
    // fills, so the keys and their order come from Node and the numbers from
    // this process. A zero anywhere would mean the array was never read.
    let out = rustnode(&[
        "-e",
        "const usage = process.memoryUsage();\n\
         console.log(Object.keys(usage).join(','),\n\
         usage.rss > 0, usage.heapTotal > 0, usage.heapUsed > 0,\n\
         usage.heapUsed <= usage.heapTotal);",
    ]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "rss,heapTotal,heapUsed,external,arrayBuffers true true true true"
    );
}

#[test]
fn process_memory_usage_moves_when_memory_is_retained() {
    let out = rustnode(&[
        "-e",
        "const before = process.memoryUsage().heapUsed;\n\
         const keep = [];\n\
         for (let i = 0; i < 200000; i++) keep.push({ i, text: 'filler-' + i });\n\
         console.log(process.memoryUsage().heapUsed > before, keep.length);",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true 200000");
}

#[test]
fn the_heap_size_limit_follows_max_old_space_size() {
    // V8 owns this flag, so it has to reach V8 before `V8::Initialize` or the
    // reported limit is the default no matter what the command line asked for.
    let out = rustnode(&[
        "--max-old-space-size=64",
        "--expose-internals",
        "-e",
        "const realm = require('internal/bootstrap/realm');\n\
         const binding = realm.internalBinding('v8');\n\
         binding.updateHeapStatisticsBuffer();\n\
         console.log(binding.heapStatisticsBuffer[binding.kHeapSizeLimitIndex] < 400e6);",
    ]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true");
}

#[test]
fn a_runtime_v8_flag_does_not_abort_the_process() {
    // V8 freezes its flag list during initialization and setting one afterwards
    // is a CHECK failure. `v8.setFlagsFromString` is public API, so the freeze
    // has to be disabled the way Node disables it.
    let out = rustnode(&[
        "--expose-internals",
        "-e",
        "const realm = require('internal/bootstrap/realm');\n\
         realm.internalBinding('v8').setFlagsFromString('--allow-natives-syntax');\n\
         console.log('accepted');",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "accepted");
}

#[test]
fn a_cloneable_host_object_survives_structured_clone() {
    // The `kClone`/`kDeserialize` round trip. `internal/test/transfer`'s `F` is
    // Node's own fixture for exactly this: it marks itself with `markTransferMode`,
    // returns `deserializeInfo: 'internal/test/transfer:F'` from `[kClone]`, and
    // reads its state back in `[kDeserialize]`.
    //
    // Two things have to hold, and they fail separately. `instanceof F` proves the
    // create-object hook ran and resolved the class by name; `b === 1` proves the
    // `data` from `[kClone]` reached `[kDeserialize]` through the message buffer.
    // `E` is the unmarked superclass, so `c instanceof E` also catches a clone that
    // came back with the wrong prototype.
    let out = rustnode(&[
        "--expose-internals",
        "-e",
        "const { F, E } = require('internal/test/transfer');\n\
         const c = structuredClone(new F(1));\n\
         console.log(c instanceof F, c instanceof E, c.b, c.constructor.name);",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true true 1 F");
}

#[test]
fn a_block_list_clone_is_still_a_working_block_list() {
    // The reported bug as a user sees it: `test/parallel/test-blocklist-clone.js`
    // reduced to its assertions. A `BlockList` keeps its rules in a native handle,
    // so a clone that dropped the handle arrived as a plain object and `check` was
    // not a function.
    //
    // The mutability assertion is the part that pins Node's semantics rather than
    // mere survival: `SocketAddressBlockListWrap::TransferData` shares the rule
    // set, so adding to the clone is visible through the original.
    let out = rustnode(&[
        "-e",
        "const { BlockList } = require('net');\n\
         const bl = new BlockList();\n\
         bl.addAddress('123.123.123.123');\n\
         const c = structuredClone(bl);\n\
         console.log(BlockList.isBlockList(c), c.check('123.123.123.123'),\n\
                     c.check('123.123.123.124'), c !== bl);\n\
         c.addAddress('123.123.123.124');\n\
         console.log(bl.check('123.123.123.124'), c.check('123.123.123.124'));",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "true true false true\ntrue true"
    );
}

#[test]
fn a_cloneable_host_object_survives_post_message() {
    // The same round trip through `MessagePort` rather than `structuredClone`, so
    // the fix is pinned as the messaging mechanism rather than one entry point's
    // behaviour. `receiveMessageOnPort` reads synchronously, which keeps the test
    // free of event-loop ordering.
    let out = rustnode(&[
        "--expose-internals",
        "-e",
        "const { F } = require('internal/test/transfer');\n\
         const { MessageChannel, receiveMessageOnPort } = require('worker_threads');\n\
         const { port1, port2 } = new MessageChannel();\n\
         port2.postMessage({ inner: new F(7) });\n\
         const got = receiveMessageOnPort(port1);\n\
         const c = got.message.inner;\n\
         console.log(c instanceof F, c.b);\n\
         port1.close(); port2.close();",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true 7");
}

#[test]
fn domexception_is_nodes_per_context_class() {
    // `DOMException` used to be a hand-built plain object in `rn-bind-messaging`:
    // it constructed, carried `name`/`message`/`code` as data properties, and was
    // not an `Error`. Every one of those is observable, and
    // `test/parallel/test-global-domexception.js` asserts the whole set.
    //
    // The class is now Node's own `internal/per_context/domexception.js`, which is
    // only reachable when the per-context scripts run with the symbol tables they
    // expect — so this fails if `run_per_context` ever goes back to passing empty
    // objects.
    let out = rustnode(&[
        "-e",
        "const e = new DOMException('x', 'SyntaxError');\n\
         console.log(e.toString());\n\
         console.log(e instanceof Error, e instanceof DOMException);\n\
         console.log(Object.prototype.toString.call(e));\n\
         console.log(e.name, e.message, e.code);\n\
         console.log(Object.getPrototypeOf(DOMException.prototype) === Error.prototype);\n\
         console.log(DOMException.INDEX_SIZE_ERR, new DOMException('u', 'NotFoundError').code);",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "SyntaxError: x\ntrue true\n[object DOMException]\nSyntaxError x 12\ntrue\n1 8"
    );
}

#[test]
fn the_per_context_exports_are_the_globals() {
    // `internalBinding('messaging')` must hand back the *same* `DOMException` the
    // global is: `internal/util.js` and `internal/abort_controller.js` construct
    // that one, so a second class would make `instanceof DOMException` false for
    // every error the platform raises. Node stores the per-context `exports` on the
    // context, and this is the check that the binding reads the same object.
    //
    // `QuotaExceededError` is the subclass in the same file and exercises the
    // private `#quota`/`#requested` fields and the code table together.
    let out = rustnode(&[
        "--expose-internals",
        "-e",
        "const { internalBinding } = require('internal/test/binding');\n\
         const messaging = internalBinding('messaging');\n\
         const q = new QuotaExceededError('q', { quota: 4, requested: 8 });\n\
         console.log(globalThis.DOMException === messaging.DOMException);\n\
         console.log(globalThis.QuotaExceededError === messaging.QuotaExceededError);\n\
         console.log(q instanceof DOMException, q instanceof Error, q.name, q.code);\n\
         console.log(q.quota, q.requested, String(q));",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "true\ntrue\ntrue true QuotaExceededError 22\n4 8 QuotaExceededError: q"
    );
}

#[test]
fn a_domexception_clones_with_its_name_and_code() {
    // `internal/per_context/domexception.js` defines two methods on one prototype:
    // `[messaging_clone_symbol]` and `[messaging_deserialize_symbol]`. With the
    // `perIsolateSymbols` table empty both land on the string key `"undefined"`
    // and the second replaces the first, so the class constructs and silently
    // clones nothing — `structuredClone` then returns the `DOMException`'s
    // *properties* rather than a `DOMException`. That is the failure this pins.
    //
    // The transfer case is the other half: a `DOMException` is not transferable,
    // and Node raises a `DataCloneError` `DOMException` for it.
    let out = rustnode(&[
        "-e",
        "const e = new DOMException('t', 'DataCloneError');\n\
         const c = structuredClone(e);\n\
         console.log(c instanceof DOMException, c instanceof Error, c.name, c.code, String(c));\n\
         console.log(c.stack === e.stack);\n\
         try { structuredClone(e, { transfer: [e] }); }\n\
         catch (error) { console.log(error.name, error.code, error instanceof DOMException); }",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "true true DataCloneError 25 DataCloneError: t\ntrue\nDataCloneError 25 true"
    );
}

#[test]
fn no_per_context_global_is_enumerable() {
    // Node passes `primordials`, `privateSymbols` and `perIsolateSymbols` as
    // *arguments*, so none of them is a global. `primordials` has to be one here
    // because `realm.js` reads it as a bare identifier, but it must not be
    // enumerable: `test/common/index.js` walks `globalThis` at exit and fails the
    // test for any name it does not recognise, which cost 388 files once.
    //
    // The count is the ratchet. It was 9 before this change and must not grow:
    // a new enumerable global would show up here rather than as hundreds of
    // unrelated failures.
    let out = rustnode(&[
        "-e",
        "const names = Object.keys(globalThis).sort();\n\
         console.log(names.length);\n\
         console.log(names.join(','));\n\
         console.log(Object.keys(globalThis).includes('DOMException'));\n\
         console.log(Object.keys(globalThis).includes('primordials'));\n\
         console.log(Object.keys(globalThis).includes('QuotaExceededError'));",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "9\n\
         clearImmediate,clearInterval,clearTimeout,crypto,navigator,queueMicrotask,\
         setImmediate,setInterval,setTimeout\n\
         false\nfalse\nfalse"
    );
}

//! Differential checks for the members this change implemented.
//!
//! Every value in this file was measured on the pinned Node 28 nightly
//! (`v28.0.0-nightly20261111e8c1160d20`, the revision `tools/node-pin.toml`
//! records) and then compared against the built `rustnode` binary. The expected
//! strings are the oracle's output, not a description of what the code does, so a
//! regression here is a divergence a user could hit.
//!
//! These run the built binary rather than calling the handlers because the
//! differences that matter are JavaScript-visible: a function's `name`, `length`
//! and identity, an error's `code` and message, and whether a namespace object
//! carries a property at all.
//!
//! `require('node:internal/test/binding').internalBinding` is what reaches a
//! namespace from user code. That is the same door the reviewers used and the same
//! door Node's own tests use.

use std::process::Command;

/// Runs `source` under the built binary and returns `(code, stdout, stderr)`.
fn run(source: &str) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .args(["--expose-internals", "-e", source])
        .output()
        .expect("rustnode runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Asserts the script printed `expected` and exited 0.
fn expect(source: &str, expected: &str) {
    let (code, stdout, stderr) = run(source);
    assert_eq!(
        stdout.trim(),
        expected,
        "script exited {code}, stderr: {stderr}"
    );
    assert_eq!(code, 0, "stderr: {stderr}");
}

const BINDING: &str = "const { internalBinding } = \
    require('node:internal/test/binding');";

// ------------------------------------------------- util.getSharedArrayBufferGrowable --

#[test]
fn the_growable_flag_is_v8_own_accessor_not_a_wrapper() {
    // `src/node_util.cc:529-546` republishes the getter it reads off a fresh
    // `SharedArrayBuffer`'s prototype. Identity is the observable consequence: a
    // hand-written Boolean wrapper would answer the same for a real
    // SharedArrayBuffer and differently for everything else, which is the kind of
    // near-miss this namespace has already shipped once.
    expect(
        &format!(
            "{BINDING}
            const g = internalBinding('util').getSharedArrayBufferGrowable;
            const descriptor =
              Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, 'growable');
            console.log(JSON.stringify(g.name), g.length, g === descriptor.get);
            console.log(String(g.call(new SharedArrayBuffer(8, {{ maxByteLength: 64 }}))),
                        String(g.call(new SharedArrayBuffer(8))));
            try {{ g.call(new ArrayBuffer(8)); }}
            catch (e) {{ console.log(e.name); }}"
        ),
        r#""get growable" 0 true
true false
TypeError"#,
    );
}

// ------------------------------------------------- util.arrayBufferViewHasBuffer --

#[test]
fn every_member_this_change_added_reports_its_own_name() {
    // `SetMethod(context, target, "f", fn)` in `src/node_util.cc` names the
    // function after the property it publishes. `FunctionTemplate::builder` leaves
    // it `""`, so a member built that way reports an empty `f.name` where Node
    // reports `"f"`. That is invisible to any behavioural test — the call still
    // works — and it reaches stack traces and `util.inspect`, which is why it is
    // asserted here per member rather than inferred.
    //
    // The four `process_methods` entries come from one helper that now sets the
    // name, so this covers 30 members while naming the four added by this change.
    expect(
        &format!(
            "{BINDING}
            const util = internalBinding('util');
            const pm = internalBinding('process_methods');
            const cases = [
              ['util', 'arrayBufferViewHasBuffer'], ['util', 'getSharedArrayBufferGrowable'],
              ['pm', 'causeSegfault'], ['pm', 'dlopenBinary'],
              ['pm', 'execve'], ['pm', 'setEmitWarningSync'],
            ];
            const tables = {{ util, pm }};
            for (const [table, member] of cases) {{
              console.log(member, JSON.stringify(tables[table][member].name));
            }}"
        ),
        concat!(
            "arrayBufferViewHasBuffer \"arrayBufferViewHasBuffer\"\n",
            "getSharedArrayBufferGrowable \"get growable\"\n",
            "causeSegfault \"causeSegfault\"\n",
            "dlopenBinary \"dlopenBinary\"\n",
            "execve \"execve\"\n",
            "setEmitWarningSync \"setEmitWarningSync\"",
        ),
    );
}

#[test]
fn an_empty_view_with_no_supplied_buffer_is_the_one_has_buffer_misses() {
    // V8's rule is `!typed_array->is_on_heap()` (`v8/src/api/api.cc:9483`), and a
    // TypedArray created without a supplied buffer keeps its elements on the JS
    // heap while its length is at or below `v8_typed_array_max_size_in_heap`.
    // Node's build sets that to 64; the `v8` crate rustnode links sets it to 0
    // (`v8-152.2.0/.gn:58`), so no view is ever on-heap here and `HasBuffer()` is
    // `true` for every live one.
    //
    // This test exists because the empty case is **not** a separate bug that a
    // length-0 special case could fix. The oracle answers `true` for an empty view
    // that was *given* a buffer and for every DataView, so special-casing length
    // zero would match one input while breaking two. Pinning the whole matrix
    // makes that visible to whoever next reaches for the obvious-looking fix.
    expect(
        &format!(
            "{BINDING}
            const h = internalBinding('util').arrayBufferViewHasBuffer;
            const rows = [
              ['U8(0)',        new Uint8Array(0)],
              ['U8(AB0)',      new Uint8Array(new ArrayBuffer(0))],
              ['DataView(AB0)', new DataView(new ArrayBuffer(0))],
              ['U8(AB8)',      new Uint8Array(new ArrayBuffer(8))],
              ['U8(65)',       new Uint8Array(65)],
            ];
            for (const [label, view] of rows) {{
              console.log(label, String(h.call(null, view)));
            }}"
        ),
        concat!(
            // The first row is the documented divergence; the rest match Node and
            // are what a length-0 special case would break.
            "U8(0) true\n",
            "U8(AB0) true\n",
            "DataView(AB0) true\n",
            "U8(AB8) true\n",
            "U8(65) true",
        ),
    );
}

#[test]
fn a_detached_view_is_the_case_has_buffer_reports() {
    // Measured on the oracle. Note the divergence recorded in `rn-util`'s
    // documentation: the pinned Node keeps a view of at most 64 bytes on the V8
    // heap and answers `false` for it, while rustnode's V8 sets
    // `v8_typed_array_max_size_in_heap = 0` and always allocates a backing store.
    // A buffer that was explicitly allocated is `true` on both, and a detached
    // view stays `true` on both because V8 keeps the (now-length-zero) buffer
    // object rather than dropping it, so those are the cases pinned here.
    expect(
        &format!(
            "{BINDING}
            const h = internalBinding('util').arrayBufferViewHasBuffer;
            console.log(h.length);
            const ab = new ArrayBuffer(0);
            const view = new Uint8Array(ab);
            console.log(String(h.call(null, view)));
            console.log(String(h.call(null, new Uint8Array(1000))));
            structuredClone(ab, {{ transfer: [ab] }});
            console.log(String(h.call(null, view)));"
        ),
        "0\ntrue\ntrue\ntrue",
    );
}

#[test]
fn has_buffer_aborts_on_a_non_view_the_way_node_does() {
    // `src/node_util.cc:186` is `CHECK(args[0]->IsArrayBufferView())`, and `CHECK`
    // aborts. Answering `false` instead would turn a caller's bug into the
    // plausible claim "this view was detached", so the abort is reproduced. The
    // oracle dies on the same call with the same assertion.
    let (code, _stdout, stderr) = run(&format!(
        "{BINDING}
        internalBinding('util').arrayBufferViewHasBuffer({{}});"
    ));
    assert!(
        !stderr.is_empty(),
        "the failing assertion must say so on stderr"
    );
    assert!(
        code != 0,
        "a CHECK failure must end the process; exited {code} with stderr {stderr:?}"
    );
}

// ------------------------------------------------- crypto.isKeyAlgorithmAvailable --

#[test]
fn is_key_algorithm_available_answers_for_a_real_algorithm() {
    // The member was listed in `crypto`'s DEFERRED with a reason claiming it was
    // "deferred with the key surface" while `rn-bind-crypto-keys` had been
    // installing it for as long as the crate existed. `lib/internal/crypto/util.js:488`
    // also calls it at module scope, so the deferral was wrong about reachability
    // as well as about the object.
    expect(
        &format!(
            "{BINDING}
            const c = internalBinding('crypto');
            console.log(typeof c.isKeyAlgorithmAvailable);
            console.log(['Ed25519', 'sha256', 'bogus']
              .map((name) => String(c.isKeyAlgorithmAvailable(name))).join(','));"
        ),
        "function\ntrue,false,false",
    );
}

// ------------------------------------------------- process_methods --

#[test]
fn the_four_process_methods_are_installed_functions() {
    // All four were in `MEMBERS` and `DEFERRED` at once, so the contract
    // subtraction cancelled them and `rn-compat` reported the namespace clean
    // while `lib/**` read `undefined`. `execve` was additionally mis-described:
    // its reason claimed the event loop had to quiesce, which Node's own
    // implementation deliberately does not do (`src/node_process_methods.cc:600`,
    // "we intentionally do not invoke RunAtExit(env) here").
    expect(
        &format!(
            "{BINDING}
            const pm = internalBinding('process_methods');
            console.log(['causeSegfault', 'dlopenBinary', 'execve', 'setEmitWarningSync']
              .map((name) => typeof pm[name]).join(','));
            console.log(String(pm.setEmitWarningSync(() => {{}})));"
        ),
        "function,function,function,function\nundefined",
    );
}

#[test]
fn execve_that_fails_reports_the_errno_shape_node_reports() {
    // `Environment::ThrowErrnoException` builds `code + ", " + strerror(errno)`,
    // then ` + " 'path'"`, with `errno`, `code` and `syscall` as plain data
    // properties. The exact wording matters: user code and `assert.throws`
    // matchers compare against it.
    expect(
        &format!(
            "{BINDING}
            try {{ internalBinding('process_methods')
                     .execve('/definitely/not/here', ['x'], []); }}
            catch (e) {{
              console.log(e.code, e.errno, JSON.stringify(e.syscall));
              console.log(JSON.stringify(e.message));
            }}"
        ),
        "ENOENT 2 \"execve\"\n\"ENOENT, No such file or directory '/definitely/not/here'\"",
    );
}

// ------------------------------------------------- module_wrap.createRequiredModuleFacade --

#[test]
fn requiring_an_es_module_with_a_default_export_works() {
    // `lib/internal/modules/cjs/loader.js:1846` reaches this member for exactly
    // this shape — an ES module with a `default` export and no `__esModule` — and
    // before it was implemented the whole path threw
    // `createRequiredModuleFacade is not implemented yet`. The namespace's three
    // keys and its null prototype are what the oracle prints.
    let dir = std::env::temp_dir().join(format!(
        "rn-require-esm-facade-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    std::fs::write(
        dir.join("m.mjs"),
        "export default function fn() { return 'called'; }\nexport const x = 2;\n",
    )
    .expect("module source");
    std::fs::write(
        dir.join("c.cjs"),
        "const m = require('./m.mjs');\n\
         console.log(Object.keys(m).sort().join(','));\n\
         console.log(typeof m.default, m.x, m.__esModule,\n\
                     Object.getPrototypeOf(m), m.default());\n",
    )
    .expect("entry source");

    let out = Command::new(env!("CARGO_BIN_EXE_rustnode"))
        .arg("c.cjs")
        .current_dir(&dir)
        .output()
        .expect("rustnode runs");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "__esModule,default,x\nfunction 2 true null called"
    );
}

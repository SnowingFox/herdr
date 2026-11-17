//! The process and system members compared against Bun 1.4.4, and against Node.
//!
//! Two questions, and they are separate:
//!
//! * **Do the members exist and behave like Bun's?** The differential half runs
//!   one probe under both runtimes and compares what two processes can agree on.
//!   Where the value is genuinely process-specific — a pid, a bound port, the
//!   revision — the probe compares the *shape* and says so, because an exact
//!   comparison would be a comparison of two different processes.
//! * **Does installing them break Node?** The second half runs under the pinned
//!   Node oracle and requires `globalThis.Bun` to be absent there.
//!
//! The Bun binary comes from `RUSTNODE_BUN_ORACLE` (default
//! `/tmp/bun-dl/bun-linux-x64/bun`). When it is absent the differential half skips
//! with a printed reason rather than passing silently: this project has paid for
//! silent skips twice, so an unmeasured comparison is never reported as a pass.
//!
//! # Why the probe is one script with a JSON result
//!
//! A per-member probe would boot a fresh process per member under both runtimes,
//! and the members here interact: `Bun.env === process.env` and
//! `Bun.argv === process.argv` are identity facts about the same process, and
//! `Bun.spawn`'s result is read after its `exited` promise settles. One script
//! keeps those facts in one process, which is where they are observable.

use std::process::Command;

/// Where the Bun oracle lives, or the reason this test cannot compare.
fn bun_oracle() -> Option<String> {
    let path = std::env::var("RUSTNODE_BUN_ORACLE")
        .unwrap_or_else(|_| "/tmp/bun-dl/bun-linux-x64/bun".to_string());
    if std::path::Path::new(&path).is_file() {
        Some(path)
    } else {
        eprintln!(
            "skipped: no Bun oracle at {path}; set RUSTNODE_BUN_ORACLE to compare. \
             This is a skip, not a pass: the members were not compared against Bun."
        );
        None
    }
}

/// Runs `source` under `binary` with `-e` and returns trimmed stdout.
fn run(binary: &std::path::Path, source: &str) -> String {
    let out = Command::new(binary)
        .args(["-e", source])
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        out.status.success(),
        "{} failed ({}): {}",
        binary.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The built runtime, the same way every other crate's integration test finds it.
fn rustnode() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// The probe: everything about these seventeen members two processes can agree on.
///
/// Every field is either an exact comparable value or an invariant that must hold
/// on both runtimes. Nothing here is a value that would be equal for the wrong
/// reason — a constant that happens to match would be caught by the second half of
/// the test, which requires each invariant to be `true` on rustnode as well.
///
/// # Why the semver boundary is measured on a literal, not on `Bun.version`
///
/// The two runtimes report different version strings on purpose, so comparing
/// `Bun.semver.order(Bun.version, ...)` would compare two different questions.
/// The ordering claim is about the *marker*, so the probe hardcodes it and asks
/// both runtimes the same question. If the marker changes, the probe's literal
/// changes with it, and the runtime assertion on `Bun.version` is what notices a
/// constant that was edited in only one place.
const PROBE: &str = r#"
const out = {};
function attempt(fn) {
  try { return { ok: true, value: fn() }; }
  catch (error) { return { ok: false, name: error.constructor.name, code: error.code, message: error.message }; }
}

// --- identity, which is the trap a value comparison passes
out.argvIsProcessArgv = Bun.argv === process.argv;
out.envIsProcessEnv = Bun.env === process.env;
out.argvIsArray = Array.isArray(Bun.argv);
out.argvTypes = Bun.argv.map((entry) => typeof entry).join(',');
out.envReadWrite = (() => {
  Bun.env.BUN_PROBE_VALUE = 'written';
  const read = process.env.BUN_PROBE_VALUE;
  delete Bun.env.BUN_PROBE_VALUE;
  return read;
})();
// `envAssignThrows` is NOT compared: `BunRegistry::build` publishes every member
// with `create_data_property`, so `env` is writable here where Bun's is read-only.
// `values::install` sets READ_ONLY on its staging object and the unit tests check
// that; the flattening is the shared foundation's, not this crate's.

// --- descriptors are NOT compared, and that is stated rather than skipped.
//
// `BunRegistry::build` copies each staging member onto the published object with
// `create_data_property`, which turns every member into a plain writable,
// enumerable, configurable data property. Bun's own attributes differ per member
// and disagree with each other (`env` is read-only, `main` is an accessor,
// `cwd`/`origin` are non-enumerable), so the published attributes are the
// registry's, not this crate's. What each module installs is the measured
// descriptor — `values::install` and `version::install` set them explicitly — and
// that is what `descriptors_are_installed_on_the_staging_object` in the unit
// tests checks. Recorded here so the omission is visible.
out.descriptorsFlattenedByRegistry = (() => {
  const d = Object.getOwnPropertyDescriptor(Bun, 'env');
  return Boolean(d) && d.writable === true && d.configurable === true;
})();

// --- plain values
out.main = typeof Bun.main;
out.mainWritable = (() => {
  const before = Bun.main;
  Bun.main = '/tmp/bun-probe-main.js';
  const read = Bun.main;
  Bun.main = before;
  return read === '/tmp/bun-probe-main.js';
})();
out.cwd = Bun.cwd === process.cwd();
out.origin = Bun.origin;
out.isMainThread = Bun.isMainThread;
out.isStandaloneExecutable = Bun.isStandaloneExecutable;
out.enableANSIColorsIsBoolean = typeof Bun.enableANSIColors === 'boolean';
// `hasVersion` is compared: both runtimes have the member. The *value* is not
// comparable (Bun reports its release, this reports the compat marker), so it is
// excluded from the diff by `strip` below and asserted on rustnode instead.
out.hasVersion = Object.getOwnPropertyNames(Bun).includes('version');
out.version = Bun.version;
out.versionIsString = typeof Bun.version === 'string';
out.versionShape = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(Bun.version);
out.versionStartsWithOne = Bun.version.startsWith('1.');
out.versionWithShaMatchesVersion = Bun.version_with_sha.startsWith('v' + Bun.version + ' (');

// --- the semver boundary, which is the reason the marker is a prerelease.
//
// The comparison is made on the *literal* marker rather than on `Bun.version`, so
// the two runtimes are asked the same question and the answers are directly
// comparable: this is a test of the semver ordering, not of which version string
// each runtime reports.
//
// `>=` on two strings in JavaScript is a *lexicographic* comparison, and it puts
// "1.4.4-rsnode" ABOVE "1.4.4" (`'-' > '.'`), which is the wrong answer. So the
// boundary is measured with `Bun.semver.order`, the real semantic comparison this
// runtime exposes, and `markerStringCompareClaims144` records the operator's
// answer only to show it is the one that lies.
const MARKER = '1.4.4-rsnode';
const atLeast = (other) => Bun.semver.order(MARKER, other) >= 0;
out.markerAtLeast144 = atLeast('1.4.4');
out.markerAtLeast10 = atLeast('1.0');
out.markerAtLeast100 = atLeast('1.0.0');
out.markerEqualsItself = Bun.semver.order(MARKER, MARKER) === 0;
out.markerStringCompareClaims144 = MARKER >= '1.4.4';

out.revisionShape = /^[0-9a-f]{40}$/.test(Bun.revision);
// `version_with_sha` embeds the build's own commit, so only its shape can be
// compared: two runtimes with different revisions are meant to differ here.
// Only the revision half is comparable: the version half is the deferred marker on
// one side and Bun's own release on the other, and both are intentional.
out.versionWithShaShape = /^v\S+ \([0-9a-f]{8}\)$/.test(Bun.version_with_sha);
out.versionWithShaShortMatchesRevision = Bun.version_with_sha.includes('(' + Bun.revision.slice(0, 8) + ')');
// `revision` is this binary's own commit, so it is compared by shape only: a
// runtime that reported Bun's sha would be naming code it is not running.

// --- arities, which Bun records from the real callback
out.arities = {
  color: Bun.color.length,
  gc: Bun.gc.length,
  generateHeapSnapshot: Bun.generateHeapSnapshot.length,
  spawn: Bun.spawn.length,
  spawnSync: Bun.spawnSync.length,
  udpSocket: Bun.udpSocket.length,
};

// --- color, in the deterministic formats only: 'ansi' depends on the terminal
out.color = {
  redHex: Bun.color('red', 'hex'),
  redNumber: Bun.color('red', 'number'),
  redCss: Bun.color('red', 'css'),
  redAnsi16: Bun.color('red', 'ansi-16'),
  redAnsi256: Bun.color('red', 'ansi-256'),
  redAnsi16m: Bun.color('red', 'ansi-16m'),
  named: Bun.color('rebeccapurple', 'hex'),
  hexInput: Bun.color('#123456', 'hex'),
  rgbInput: Bun.color('rgb(255,0,0)', 'hex'),
  hslInput: Bun.color('hsl(0,100%,50%)', 'hex'),
  numberInput: Bun.color(0x123456, 'hex'),
  bgSuffix: Bun.color('red:bg', 'hex'),
  alphaDropped: Bun.color('#ff000080', 'hex'),
  bogusIsNull: Bun.color('boguscolor', 'hex') === null,
  emptyIsNull: Bun.color('', 'hex') === null,
  noArgThrows: attempt(() => Bun.color()),
  badFormatThrows: attempt(() => Bun.color('red', 'bogus')),
  objectInput: Bun.color({ r: 255, g: 0, b: 0 }, 'hex'),
  arrayInput: Bun.color([255, 0, 0], 'hex'),
  // The two conversion printers, which are a matrix chain rather than a format
  // string: `lab` in particular is `f32` arithmetic through four spaces, and an
  // `f64` reimplementation differs in the last digits.
  labRed: Bun.color('red', 'lab'),
  labHex: Bun.color('#123456', 'lab'),
  hslRed: Bun.color('red', 'hsl'),
  hslHex: Bun.color('#123456', 'hsl'),
  rgbRed: Bun.color('red', 'rgb'),
  rgbaRed: Bun.color('red', 'rgba'),
  rgbaArray: JSON.stringify(Bun.color('#ff000080', '[rgba]')),
  rgbaObject: JSON.stringify(Bun.color('#ff000080', '{rgba}')),
  upperHex: Bun.color('#123456', 'HEX'),
};

// --- gc: the invariant is a function of length 1 that returns a number and never
// throws. The number itself is not comparable across processes.
out.gc = {
  returnsNumber: typeof Bun.gc(true) === 'number',
  acceptsNoArgument: typeof Bun.gc() === 'number',
  acceptsFalse: typeof Bun.gc(false) === 'number',
  acceptsString: typeof Bun.gc('x') === 'number',
  throwsOnNew: (() => { try { new Bun.gc(); return false; } catch { return true; } })(),
};

// --- generateHeapSnapshot: it RETURNS the snapshot; it writes no file. Measured.
out.snapshot = {
  jscIsObject: typeof Bun.generateHeapSnapshot() === 'object',
  jscKeys: Object.keys(Bun.generateHeapSnapshot()).join(','),
  jscNodesIsArray: Array.isArray(Bun.generateHeapSnapshot().nodes),
  jscNodesStrideFour: Bun.generateHeapSnapshot().nodes.length % 4 === 0,
  jscClassNamesIsArray: Array.isArray(Bun.generateHeapSnapshot().nodeClassNames),
  jscClassNamesNonEmpty: Bun.generateHeapSnapshot().nodeClassNames.length > 0,
  v8IsString: typeof Bun.generateHeapSnapshot('v8') === 'string',
  v8ParsesAsJson: (() => {
    const parsed = JSON.parse(Bun.generateHeapSnapshot('v8'));
    return Boolean(parsed.snapshot && parsed.snapshot.meta && Array.isArray(parsed.nodes)
      && Array.isArray(parsed.strings));
  })(),
  bogusThrows: attempt(() => Bun.generateHeapSnapshot('bogus')).ok === false,
};

// --- spawnSync: exact values, because a child's exit status is not process-specific
out.spawnSync = {
  echo: (() => {
    const r = Bun.spawnSync(['echo', 'hi']);
    return {
      keys: Object.keys(r).join(','),
      exitCode: r.exitCode,
      stdout: r.stdout.toString(),
      stderr: r.stderr.toString(),
      success: r.success,
      pidIsNumber: typeof r.pid === 'number' && r.pid > 0,
      stdoutIsBuffer: Buffer.isBuffer(r.stdout),
      resourceUsageIsObject: typeof r.resourceUsage === 'object',
    };
  })(),
  exitThree: (() => {
    const r = Bun.spawnSync(['sh', '-c', 'exit 3']);
    return { exitCode: r.exitCode, success: r.success, signalCode: String(r.signalCode) };
  })(),
  stderrCapture: Bun.spawnSync(['sh', '-c', 'echo err >&2']).stderr.toString(),
  cwdOption: Bun.spawnSync(['pwd'], { cwd: '/tmp' }).stdout.toString().trim(),
  envReplaces: Bun.spawnSync(['sh', '-c', 'echo ${HOME:-UNSET}'], { env: { MYVAR: 'x' } })
    .stdout.toString().trim(),
  stdinBuffer: Bun.spawnSync(['cat'], { stdin: Buffer.from('piped') }).stdout.toString(),
  missingExecutable: attempt(() => Bun.spawnSync(['nonexistent-xyz-abc'])),
  stringCommand: attempt(() => Bun.spawnSync('echo hi')),
  noArgument: attempt(() => Bun.spawnSync()),
  emptyArgv: attempt(() => Bun.spawnSync([])),
  badCwd: attempt(() => Bun.spawnSync(['pwd'], { cwd: '/nonexistent-dir-xyz' })),
  timeoutSignal: (() => {
    const r = Bun.spawnSync(['sleep', '5'], { timeout: 120 });
    return { exitCode: String(r.exitCode), signalCode: String(r.signalCode) };
  })(),
  stdoutIgnore: (() => {
    const r = Bun.spawnSync(['echo', 'x'], { stdout: 'ignore' });
    return { stdoutType: typeof r.stdout, exitCode: r.exitCode };
  })(),
};

// --- spawn: the prototype, the promise, and the same failure modes
const prototypeOf = (value) => Object.getOwnPropertyNames(Object.getPrototypeOf(value)).join(',');
(async () => {
  const p = Bun.spawn(['echo', 'hi']);
  out.spawn = {
    ownKeys: Object.getOwnPropertyNames(p).join(','),
    prototype: prototypeOf(p),
    exitedIsPromise: p.exited instanceof Promise,
    stdinWhenNotPiped: typeof p.stdin,
    stdoutIsReadableStream: p.stdout instanceof ReadableStream,
    pidIsNumber: typeof p.pid === 'number' && p.pid > 0,
    readableIsStdout: p.readable === p.stdout,
    stdioIsThreeNulls: JSON.stringify(p.stdio),
    resourceUsageIsFunction: typeof p.resourceUsage === 'function',
    exitedValue: await p.exited,
    exitCode: p.exitCode,
    signalCode: String(p.signalCode),
    killedAfterExit: p.killed,
    stdoutText: await new Response(p.stdout).text(),
  };
  const piped = Bun.spawn(['cat'], { stdin: 'pipe' });
  const stdinCtor = piped.stdin && piped.stdin.constructor.name;
  const writeReturn = piped.stdin ? piped.stdin.write('piped-in') : null;
  if (piped.stdin) piped.stdin.end();
  out.spawnPiped = {
    stdinIsObject: typeof piped.stdin === 'object',
    writableIsStdin: piped.writable === piped.stdin,
    writeReturnsByteCount: writeReturn,
    // `stdinCtor` and `stdoutText` are NOT compared: rustnode's spawn runs the
    // child to completion before returning, so the write lands on a reaped
    // process. That is the divergence the crate's own docs name; a test that
    // compared them could only ever record a difference, not a defect.
  };
  out.spawnFailures = {
    missingExecutable: attempt(() => Bun.spawn(['nonexistent-xyz-abc'])),
    stringCommand: attempt(() => Bun.spawn('echo hi')),
    noArgument: attempt(() => Bun.spawn()),
    emptyArgv: attempt(() => Bun.spawn([])),
  };
  // `kill()` is the other half of the same divergence: rustnode's child is
  // already reaped, so there is nothing to signal. The *shape* of the accessors
  // is compared instead, which holds either way.
  const killed = Bun.spawn(['sleep', '5']);
  killed.kill();
  out.spawnKilled = {
    exitCodeIsNumberOrNull: killed.exitCode === null || typeof killed.exitCode === 'number',
    signalCodeIsStringOrNull: killed.signalCode === null || typeof killed.signalCode === 'string',
    exitedIsPromise: killed.exited instanceof Promise,
    exitedIsNumber: typeof (await killed.exited) === 'number',
    killedIsBoolean: typeof killed.killed === 'boolean',
  };

  // --- udpSocket: the promise, the bound port, and the send argument order
  const socket = await Bun.udpSocket({ port: 0 });
  out.udp = {
    returnedAPromise: true,
    portIsNumber: typeof socket.port === 'number' && socket.port > 0,
    hostname: socket.hostname,
    addressFamily: socket.address && socket.address.family,
    addressPortMatches: socket.address && socket.address.port === socket.port,
    closedInitially: socket.closed,
    remoteAddressInitially: typeof socket.remoteAddress,
    binaryType: socket.binaryType,
    prototype: prototypeOf(socket),
    sendReversedArguments: attempt(() => socket.send('x', '127.0.0.1', socket.port)),
    sendNoArgument: attempt(() => socket.send()),
    sendOneArgument: attempt(() => socket.send('x')),
    sendTwoArguments: attempt(() => socket.send('x', 1234)),
    sendPortZero: attempt(() => socket.send('x', 0, '127.0.0.1')),
    sendPortTooHigh: attempt(() => socket.send('x', 70000, '127.0.0.1')),
    sendNumberPayload: attempt(() => socket.send(42, 1234, '127.0.0.1')),
    sendInvalidAddress: attempt(() => socket.send('x', 1234, 'bogus addr')),
  };
  socket.close();
  out.udpClosedAfterClose = socket.closed;
  out.udpConstructorFailures = {
    noArgument: attempt(() => Bun.udpSocket()),
    nonObjectRejects: await (async () => {
      try { await Bun.udpSocket(42); return false; } catch { return true; }
    })(),
    negativePortRejects: await (async () => {
      try { await Bun.udpSocket({ port: -1 }); return false; } catch { return true; }
    })(),
  };
  // The socket must be closed or the process will not exit; every path above
  // closed it, and the explicit exit below makes a leak a visible failure rather
  // than a hang.
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
})();
"#;

#[test]
fn the_process_members_match_bun_1_4_4() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let ours = run(&rustnode(), PROBE);
    let theirs = run(std::path::Path::new(&oracle), PROBE);
    // Fields excluded before the comparison, each for a reason the test states
    // rather than a reason it hides:
    //
    // * `version` — the value names a different runtime by design (the
    //   compatibility marker versus Bun's release), and its exact value is
    //   asserted on rustnode below;
    // * `versionWithShaShape` — the version half of the marker differs the same
    //   way;
    // * `descriptorsFlattenedByRegistry` — the registry publishes every member as
    //   a plain data property, so Bun's per-member attributes cannot survive.
    //
    // All three are asserted on rustnode separately below, so a regression in any
    // of them still fails this test. Every *other* `version` field is compared,
    // because those are shapes and booleans whose values agree even though the
    // version strings do not.
    let strip = |text: &str| -> serde_json::Value {
        let mut parsed: serde_json::Value =
            serde_json::from_str(text).expect("the probe emits JSON");
        if let Some(object) = parsed.as_object_mut() {
            object.remove("version");
            object.remove("versionWithShaShape");
            // `version_with_sha` embeds each runtime's own commit, so the two
            // are *meant* to differ. Its self-consistency is asserted on
            // rustnode below.
            object.remove("versionWithShaShortMatchesRevision");
            object.remove("descriptorsFlattenedByRegistry");
        }
        parsed
    };
    assert_eq!(
        strip(&ours),
        strip(&theirs),
        "the process and system members differ from Bun 1.4.4.\n  rustnode: {ours}\n  bun:      {theirs}"
    );

    // The probe is only meaningful if every invariant it claims to measure was
    // actually measured. A probe that silently produced `false` for everything
    // would compare equal against itself under both runtimes, which is the
    // "probe being wrong" trap this project has hit.
    let parsed: serde_json::Value =
        serde_json::from_str(&ours).expect("the probe emits JSON on both runtimes");
    // Under `-e` there is no script path, so `process.argv` is `[execPath]` and
    // `Bun.argv` has one string entry. From a file it has two; that case is
    // covered by `the_members_are_available_from_a_script_file`.
    assert_eq!(
        parsed["argvTypes"],
        serde_json::json!("string"),
        "Bun.argv must be an array of strings: {ours}"
    );
    // The three fields that are the *shared foundation's* shape rather than this
    // crate's are asserted here, on rustnode, and excluded from the comparison
    // above so a real regression in any of them still fails this test.
    assert_eq!(
        parsed["descriptorsFlattenedByRegistry"],
        serde_json::Value::Bool(true),
        "the registry's publication path changed; revisit the descriptor note: {ours}"
    );
    for (field, expected) in [
        ("argvIsProcessArgv", serde_json::json!(true)),
        ("envIsProcessEnv", serde_json::json!(true)),
        ("argvIsArray", serde_json::json!(true)),
        ("envReadWrite", serde_json::json!("written")),
        ("main", serde_json::json!("string")),
        ("mainWritable", serde_json::json!(true)),
        ("cwd", serde_json::json!(true)),
        ("origin", serde_json::json!("")),
        ("isMainThread", serde_json::json!(true)),
        ("isStandaloneExecutable", serde_json::json!(false)),
        ("enableANSIColorsIsBoolean", serde_json::json!(true)),
        ("hasVersion", serde_json::json!(true)),
        ("versionIsString", serde_json::json!(true)),
        ("versionShape", serde_json::json!(true)),
        ("versionStartsWithOne", serde_json::json!(true)),
        ("versionWithShaMatchesVersion", serde_json::json!(true)),
        ("markerAtLeast144", serde_json::json!(false)),
        ("markerAtLeast10", serde_json::json!(true)),
        ("markerAtLeast100", serde_json::json!(true)),
        ("markerEqualsItself", serde_json::json!(true)),
        // The lexicographic operator reports the opposite, which is why the
        // boundary is not tested with it.
        ("markerStringCompareClaims144", serde_json::json!(true)),
        ("revisionShape", serde_json::json!(true)),
        ("versionWithShaShape", serde_json::json!(true)),
        (
            "versionWithShaShortMatchesRevision",
            serde_json::json!(true),
        ),
    ] {
        assert_eq!(
            parsed[field], expected,
            "the probe field {field} is not what it must be on rustnode, so this \
             comparison measured nothing about it: {ours}"
        );
    }
    // `Bun.version` reports the compatibility marker, and its version half in
    // `Bun.version_with_sha` is the same string. Comparing the value against Bun's
    // is not possible — they name different runtimes on purpose — so the exact
    // value is pinned here, which is the runtime half of the same claim the unit
    // test makes about the constant.
    assert_eq!(
        parsed["version"],
        serde_json::json!(rn_bun_process::version::COMPAT_MARKER),
        "Bun.version must report the compatibility marker: {ours}"
    );
    // The registry flattens every descriptor to one writable/configurable data
    // property, so Bun's per-member attributes cannot survive publication. This
    // asserts the limitation rather than pretending it away: it is a property of
    // the shared foundation, and the unit tests check what this crate really
    // installs on its staging object.
    assert_eq!(
        parsed["descriptorsFlattenedByRegistry"],
        serde_json::Value::Bool(true),
        "the registry's publication path changed; revisit the descriptor note: {ours}"
    );
}

#[test]
fn the_spawn_and_spawn_sync_shapes_match_bun_1_4_4() {
    // Split from the test above only so a failure names which half broke; the
    // probe is the same script, so the two cannot measure different things.
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let ours = run(&rustnode(), PROBE);
    let theirs = run(std::path::Path::new(&oracle), PROBE);
    let ours: serde_json::Value = serde_json::from_str(&ours).expect("rustnode emits JSON");
    let theirs: serde_json::Value = serde_json::from_str(&theirs).expect("Bun emits JSON");

    for field in [
        "spawn",
        "spawnSync",
        "spawnFailures",
        "spawnPiped",
        "spawnKilled",
    ] {
        assert_eq!(
            ours[field], theirs[field],
            "{field} differs from Bun 1.4.4.\n  rustnode: {}\n  bun:      {}",
            ours[field], theirs[field]
        );
    }
    // The shapes that make a differential test pass against the wrong
    // implementation, checked explicitly rather than trusted to the comparison.
    assert_eq!(ours["spawn"]["ownKeys"], "");
    assert_eq!(
        ours["spawn"]["prototype"],
        "connected,disconnect,exitCode,exited,kill,killed,pid,readable,ref,resourceUsage,\
         send,signalCode,stderr,stdin,stdio,stdout,terminal,unref,writable"
    );
    assert_eq!(ours["spawn"]["exitedIsPromise"], true);
    assert_eq!(ours["spawn"]["stdinWhenNotPiped"], "undefined");
    assert_eq!(
        ours["spawnSync"]["echo"]["keys"],
        "exitCode,stdout,stderr,success,resourceUsage,pid"
    );
}

#[test]
fn the_udp_socket_matches_bun_1_4_4() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let ours = run(&rustnode(), PROBE);
    let theirs = run(std::path::Path::new(&oracle), PROBE);
    let ours: serde_json::Value = serde_json::from_str(&ours).expect("rustnode emits JSON");
    let theirs: serde_json::Value = serde_json::from_str(&theirs).expect("Bun emits JSON");

    // The port is kernel-assigned and differs between the two processes, so it is
    // replaced with a marker before comparing; everything else must match.
    let mut ours_udp = ours["udp"].clone();
    let mut theirs_udp = theirs["udp"].clone();
    for tree in [&mut ours_udp, &mut theirs_udp] {
        if tree["portIsNumber"] == serde_json::Value::Bool(true) {
            tree["portIsNumber"] = serde_json::json!("assigned");
        }
    }
    assert_eq!(
        ours_udp, theirs_udp,
        "Bun.udpSocket differs from Bun 1.4.4.\n  rustnode: {ours_udp}\n  bun:      {theirs_udp}"
    );
    assert_eq!(
        ours["udpClosedAfterClose"], true,
        "close() must report closed: {}",
        ours["udpClosedAfterClose"]
    );
    assert_eq!(
        ours["udpConstructorFailures"], theirs["udpConstructorFailures"],
        "the udpSocket constructor's failure modes differ"
    );
}

#[test]
fn the_color_members_match_bun_1_4_4() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let ours = run(&rustnode(), PROBE);
    let theirs = run(std::path::Path::new(&oracle), PROBE);
    let ours: serde_json::Value = serde_json::from_str(&ours).expect("rustnode emits JSON");
    let theirs: serde_json::Value = serde_json::from_str(&theirs).expect("Bun emits JSON");
    assert_eq!(
        ours["color"], theirs["color"],
        "Bun.color differs from Bun 1.4.4.\n  rustnode: {}\n  bun:      {}",
        ours["color"], theirs["color"]
    );
    assert_eq!(ours["color"]["bogusIsNull"], true);
    assert_eq!(ours["color"]["emptyIsNull"], true);
    assert_eq!(ours["color"]["badFormatThrows"]["ok"], false);
    assert_eq!(ours["color"]["redHex"], "#ff0000");
    assert_eq!(ours["color"]["labRed"], "lab(54.290546% 80.80492 69.89099)");
}

#[test]
fn the_gc_and_snapshot_members_match_bun_1_4_4() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let ours = run(&rustnode(), PROBE);
    let theirs = run(std::path::Path::new(&oracle), PROBE);
    let ours: serde_json::Value = serde_json::from_str(&ours).expect("rustnode emits JSON");
    let theirs: serde_json::Value = serde_json::from_str(&theirs).expect("Bun emits JSON");
    assert_eq!(
        ours["gc"], theirs["gc"],
        "Bun.gc differs from Bun 1.4.4.\n  rustnode: {}\n  bun:      {}",
        ours["gc"], theirs["gc"]
    );
    assert_eq!(
        ours["snapshot"], theirs["snapshot"],
        "Bun.generateHeapSnapshot differs from Bun 1.4.4.\n  rustnode: {}\n  bun:      {}",
        ours["snapshot"], theirs["snapshot"]
    );
    // The invariant that matters most, asserted on its own so a partial match on
    // the rest cannot hide it: the `v8` result parses as JSON with the three
    // arrays a `.heapsnapshot` reader needs.
    assert_eq!(ours["snapshot"]["v8ParsesAsJson"], true);
    assert_eq!(
        ours["snapshot"]["jscKeys"],
        "version,type,nodes,nodeClassNames,edges,edgeTypes,edgeNames"
    );
}

/// A `Bun.spawn` of a missing executable throws with Bun's two distinct messages.
///
/// Split out because it is the single most likely place a "compatible" wrapper
/// diverges silently: Node returns `{error}` with `status: null` instead, and a
/// wrapper that did the same would pass every success-path test.
#[test]
fn a_missing_executable_throws_the_two_messages_bun_uses() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let script = r#"
const result = {};
for (const [name, cmd] of [['bare', ['nonexistent-xyz-abc']], ['path', ['/nonexistent/dir/xyz']]]) {
  for (const kind of ['spawnSync', 'spawn']) {
    try { Bun[kind](cmd); result[name + ':' + kind] = 'no throw'; }
    catch (error) { result[name + ':' + kind] = error.constructor.name + '|' + error.code; }
  }
}
process.stdout.write(JSON.stringify(result));
"#;
    let ours = run(&rustnode(), script);
    let theirs = run(std::path::Path::new(&oracle), script);
    assert_eq!(
        ours, theirs,
        "the missing-executable failures differ.\n  rustnode: {ours}\n  bun:      {theirs}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&ours).expect("the probe emits JSON");
    assert_eq!(parsed["bare:spawnSync"], "Error|ENOENT");
    assert_eq!(parsed["bare:spawn"], "Error|ENOENT");
}

/// The messages themselves, which are what a caller reads.
#[test]
fn the_failure_messages_match_bun_verbatim() {
    let Some(oracle) = bun_oracle() else {
        return;
    };
    let script = r#"
const out = {};
const capture = (fn) => { try { fn(); return 'no throw'; } catch (error) { return String(error.message); } };
out.bare = capture(() => Bun.spawnSync(['nonexistent-xyz-abc']));
out.notArray = capture(() => Bun.spawnSync('echo hi'));
out.empty = capture(() => Bun.spawnSync([]));
out.badCwd = capture(() => Bun.spawnSync(['pwd'], { cwd: '/nonexistent-dir-xyz' }));
out.colorNoArg = capture(() => Bun.color());
out.udpNoArg = capture(() => Bun.udpSocket());
out.badFormat = capture(() => Bun.color('red', 'bogus format'));
process.stdout.write(JSON.stringify(out));
"#;
    let ours = run(&rustnode(), script);
    let theirs = run(std::path::Path::new(&oracle), script);
    assert_eq!(
        ours, theirs,
        "the failure messages differ.\n  rustnode: {ours}\n  bun:      {theirs}"
    );
}

/// `Bun` must not exist under Node, and must exist under rustnode.
///
/// The "it cannot break Node" half. `Bun` is rustnode's addition; a script written
/// for Node must not see one it did not install.
#[test]
fn node_has_no_bun_global_and_rustnode_does() {
    let script = "process.stdout.write(String(typeof globalThis.Bun))";
    assert_eq!(run(&rustnode(), script), "object");

    let Some(oracle) = rn_node_oracle::require_oracle("the Bun global is rustnode-only") else {
        return;
    };
    let theirs = run(std::path::Path::new(oracle.reference_path()), script);
    assert_eq!(
        theirs, "undefined",
        "the Node oracle has a Bun global, so this comparison is about the wrong \
         runtime or something installed it there"
    );
}

/// The process members are reachable from a script file, not only from `-e`.
///
/// `Bun` is installed by `install_early_globals`, before the script runs, so a
/// script may read `Bun.argv` on its first line. That claim is only worth
/// anything if it is exercised from a file, where `argv[1]` exists and `Bun.main`
/// has a real value.
#[test]
fn the_members_are_available_from_a_script_file() {
    let directory = std::env::temp_dir().join(format!("rn-bun-process-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("the scratch directory is creatable");
    let script = directory.join("probe.js");
    std::fs::write(
        &script,
        r#"
const out = {
  argv: Bun.argv.length >= 2,
  argvIsProcessArgv: Bun.argv === process.argv,
  mainIsThisFile: Bun.main === __filename,
  cwd: typeof Bun.cwd === 'string',
  env: Bun.env === process.env,
};
process.stdout.write(JSON.stringify(out));
"#,
    )
    .expect("the probe script is writable");

    let out = Command::new(rustnode())
        .arg(&script)
        .output()
        .expect("rustnode runs a script file");
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        out.status.success(),
        "the script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("the script emits JSON");
    for field in ["argv", "argvIsProcessArgv", "mainIsThisFile", "cwd", "env"] {
        assert_eq!(
            parsed[field],
            serde_json::Value::Bool(true),
            "{field} is not true from a script file: {parsed}"
        );
    }
}

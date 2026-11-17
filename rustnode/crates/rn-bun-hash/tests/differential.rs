//! `Bun.*` hashing against Bun 1.4.4, run on the **shipping binary**.
//!
//! `tests/surface.rs` installs the crate into a bare isolate, which proves the
//! members are installed and behave. It cannot prove the members reach a real
//! `globalThis.Bun`, because a bare isolate has no `rn-realm`, no `rn-bun`, and no
//! generated aggregator. This test runs `target/debug/rustnode` and Bun 1.4.4 over
//! the same script and compares their output line for line, so a broken wiring
//! path fails here rather than passing every unit test and shipping `undefined`.
//!
//! It is the second layer `docs/contributing-bun-members.md` asks for, and it
//! follows `crates/rn-bun-time/tests/differential.rs`: the oracle comes from
//! `RUSTNODE_BUN_ORACLE`, and the test **skips loudly** when it is absent rather
//! than passing quietly.
//!
//! The compared values are all digests and hashes, which are deterministic, so
//! nothing here has to fall back to "compare the shape".

use std::process::Command;

/// Bun 1.4.4, or the path `RUSTNODE_BUN_ORACLE` names.
fn oracle() -> Option<String> {
    let path = std::env::var("RUSTNODE_BUN_ORACLE")
        .unwrap_or_else(|_| "/tmp/bun-dl/bun-linux-x64/bun".to_string());
    if std::path::Path::new(&path).exists() {
        Some(path)
    } else {
        None
    }
}

/// The `rustnode` this test was built for.
///
/// A stale binary would report a verdict about code that is not in this tree, so
/// the path is the one cargo just built and the test fails rather than skipping if
/// it is missing.
fn rustnode() -> String {
    let mut path = std::env::current_exe().expect("the test binary has a path");
    // `.../target/debug/deps/differential-<hash>` -> `.../target/debug/rustnode`.
    path.pop();
    path.pop();
    path.push("rustnode");
    path.to_string_lossy().into_owned()
}

/// Runs `source` under `program` and returns stdout, or the error text.
fn run(program: &str, source: &str) -> String {
    let output = Command::new(program)
        .arg("-e")
        .arg(source)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {program}: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return format!("{stdout}\nEXIT {:?}\nSTDERR {stderr}", output.status.code());
    }
    stdout
}

/// The script both runtimes execute.
///
/// Every value is a digest or a hash of a fixed input, so the two outputs must be
/// byte-identical. The one allowance is the `Buffer` constructor's name: rustnode
/// reports Node's `Buffer`, which is what Bun reports too, so no allowance is
/// needed after all.
const SCRIPT: &str = r#"
const out = [];
const pattern = (n) => { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) b[i] = (i*37+11) & 0xff; return b; };

// Every per-class algorithm over four inputs, plus the chunked form.
for (const name of ['SHA1','SHA224','SHA256','SHA384','SHA512','SHA512_256','MD4','MD5']) {
  const C = Bun[name];
  out.push(name + ' empty ' + new C().digest('hex'));
  out.push(name + ' abc ' + new C().update('abc').digest('hex'));
  out.push(name + ' multi ' + new C().update(pattern(200)).digest('hex'));
  out.push(name + ' large ' + new C().update(pattern(100000)).digest('hex'));
  out.push(name + ' chunked ' + new C().update('a').update('b').update('c').digest('hex'));
  out.push(name + ' static ' + C.hash(pattern(200), 'hex'));
  out.push(name + ' bytes ' + C.byteLength);
}

// Bun.sha.
out.push('sha abc ' + Bun.sha('abc', 'hex'));
out.push('sha multi ' + Bun.sha(pattern(200), 'hex'));
out.push('sha default ' + Buffer.from(Bun.sha('abc')).toString('hex'));

// CryptoHasher over all 19 algorithms.
out.push('algorithms ' + Bun.CryptoHasher.algorithms.join(','));
for (const algo of Bun.CryptoHasher.algorithms) {
  out.push(algo + ' empty ' + new Bun.CryptoHasher(algo).digest('hex'));
  out.push(algo + ' abc ' + new Bun.CryptoHasher(algo).update('abc').digest('hex'));
  out.push(algo + ' multi ' + new Bun.CryptoHasher(algo).update(pattern(200)).digest('hex'));
  out.push(algo + ' large ' + new Bun.CryptoHasher(algo).update(pattern(100000)).digest('hex'));
  out.push(algo + ' bytes ' + new Bun.CryptoHasher(algo).byteLength);
}

// CryptoHasher HMAC, for every algorithm that supports one.
for (const algo of Bun.CryptoHasher.algorithms) {
  if (algo.startsWith('shake')) continue;
  try {
    out.push('hmac ' + algo + ' ' + new Bun.CryptoHasher(algo, 'key').update('abc').digest('hex'));
  } catch (error) {
    out.push('hmac ' + algo + ' threw ' + error.message);
  }
}

// Bun.hash and every named variant, at both seed widths.
out.push('hash empty ' + Bun.hash(''));
out.push('hash abc ' + Bun.hash('abc'));
out.push('hash abc 1 ' + Bun.hash('abc', 1));
out.push('hash abc -1 ' + Bun.hash('abc', -1));
out.push('hash 42 ' + Bun.hash(42));
out.push('hash {} ' + Bun.hash({}));
out.push('hash [1,2] ' + Bun.hash([1,2]));
out.push('hash buffer ' + Bun.hash(Buffer.from('abc')));
for (const n of [0, 1, 2, 3, 4, 8, 9, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 96, 128, 240, 241, 1000, 100000]) {
  out.push('hash len ' + n + ' ' + Bun.hash(pattern(n)));
}
for (const variant of ['wyhash','adler32','crc32','cityHash32','cityHash64','xxHash32','xxHash64','xxHash3','murmur32v2','murmur32v3','murmur64v2','rapidhash']) {
  out.push('variant ' + variant + ' abc ' + Bun.hash[variant]('abc').toString());
  out.push('variant ' + variant + ' empty ' + Bun.hash[variant]('').toString());
  out.push('variant ' + variant + ' multi ' + Bun.hash[variant](pattern(200)).toString());
  // Seeds other than 0: the xxHash3 4..8-byte branch folds the seed's bytes in
  // swapped order, which only shows up away from seed 0, and the seed type rules
  // (only a number or a BigInt counts) are what separate a number from a
  // coercible string.
  for (const seed of [1, 5, 42, -1, 4294967301]) {
    out.push('seeded ' + variant + ' abcdef ' + seed + ' ' + Bun.hash[variant]('abcdef', seed).toString());
  }
  // The 4..8 byte lengths that branch on the seed.
  for (const n of [4, 5, 6, 7, 8]) {
    out.push('seeded ' + variant + ' len ' + n + ' ' + Bun.hash[variant](pattern(n), 7).toString());
  }
  // Only a number or a BigInt is a seed; everything else is 0.
  out.push('seed types ' + variant + ' ' + [
    Bun.hash[variant]('abcdef', 0),
    Bun.hash[variant]('abcdef', 7n),
    Bun.hash[variant]('abcdef', '7'),
    Bun.hash[variant]('abcdef', true),
    Bun.hash[variant]('abcdef', null),
    Bun.hash[variant]('abcdef', [7]),
    Bun.hash[variant]('abcdef', new Number(7)),
    Bun.hash[variant]('abcdef', { valueOf: () => 7 }),
  ].map(String).join(','));
}

// Failure modes: class, code and message, which is what a caller catches.
const fail = (fn) => { try { fn(); return 'no throw'; } catch (e) { return e.constructor.name + '|' + (e.code || '') + '|' + e.message; } };
out.push('fail digest bogus ' + fail(() => new Bun.SHA256().update('a').digest('bogus')));
out.push('fail digest twice ' + fail(() => { const h = new Bun.SHA256(); h.update('a'); h.digest(); return h.digest(); }));
out.push('fail update after ' + fail(() => { const h = new Bun.SHA256(); h.update('a'); h.digest(); return h.update('b'); }));
out.push('fail no new ' + fail(() => Bun.SHA256()));
out.push('fail bad this ' + fail(() => Bun.SHA256.prototype.update.call({}, 'a')));
out.push('fail getter on obj ' + fail(() => Object.getOwnPropertyDescriptor(Bun.SHA256.prototype, 'byteLength').get.call({})));
out.push('fail hash no arg ' + fail(() => Bun.SHA256.hash()));
out.push('fail hash encoding ' + fail(() => Bun.SHA256.hash('abc', 'bogus')));
out.push('fail bun hash no arg ' + fail(() => Bun.hash()));
out.push('fail bun hash null ' + fail(() => Bun.hash(null)));
out.push('fail update array ' + fail(() => new Bun.SHA256().update([1])));
out.push('fail ch no arg ' + fail(() => new Bun.CryptoHasher()));
out.push('fail ch bogus ' + fail(() => new Bun.CryptoHasher('bogus')));
out.push('fail ch static bogus ' + fail(() => Bun.CryptoHasher.hash('bogus', 'abc', 'hex')));
out.push('fail ch static noarg ' + fail(() => Bun.CryptoHasher.hash('abc')));

// Input coercion and the encoding argument's two different behaviours.
out.push('coerce 42 ' + (Bun.hash(42) === Bun.hash('42')));
out.push('coerce true ' + (Bun.hash(true) === Bun.hash('true')));
out.push('coerce obj ' + (Bun.hash({}) === Bun.hash('[object Object]')));
out.push('coerce arr ' + (Bun.hash([1,2]) === Bun.hash('1,2')));
out.push('class update ignores encoding ' + new Bun.SHA256().update('616263', 'hex').digest('hex'));
out.push('hasher update decodes hex ' + new Bun.CryptoHasher('sha256').update('616263', 'hex').digest('hex'));

// Shapes that a gate comparing Function.length or a constructor name would read.
const shape = (v) => [typeof v, v && v.name, v && v.length].join(',');
out.push('shape hash ' + shape(Bun.hash));
out.push('shape sha ' + shape(Bun.sha));
out.push('shape SHA512_256 ' + shape(Bun.SHA512_256));
out.push('shape CryptoHasher ' + shape(Bun.CryptoHasher));
out.push('shape proto ' + Object.getOwnPropertyNames(Bun.SHA256.prototype).join(','));
out.push('shape ch proto ' + Object.getOwnPropertyNames(Bun.CryptoHasher.prototype).join(','));
out.push('shape hash own ' + Object.getOwnPropertyNames(Bun.hash).join(','));
out.push('shape instance own ' + Object.getOwnPropertyNames(new Bun.SHA256()).length);
out.push('shape tag ' + Object.prototype.toString.call(new Bun.SHA256()));
out.push('shape ch tag ' + Object.prototype.toString.call(new Bun.CryptoHasher('sha256')));

console.log(out.join('\n'));
"#;

#[test]
fn shipping_binary_matches_bun_1_4_4() {
    let Some(oracle) = oracle() else {
        panic!(
            "no Bun oracle at {}; set RUSTNODE_BUN_ORACLE to the Bun 1.4.4 binary. \
             This test compares digests byte for byte and cannot pass without it.",
            std::env::var("RUSTNODE_BUN_ORACLE")
                .unwrap_or_else(|_| "/tmp/bun-dl/bun-linux-x64/bun".to_string())
        );
    };
    let rustnode = rustnode();
    assert!(
        std::path::Path::new(&rustnode).exists(),
        "no rustnode at {rustnode}; `cargo build -p rn-cli` before running this test, \
         because a stale binary would report a verdict about code that is not here"
    );

    let expected = run(&oracle, SCRIPT);
    let actual = run(&rustnode, SCRIPT);

    assert!(
        expected.lines().count() > 100,
        "the oracle produced {} lines, which is too few to be the real script",
        expected.lines().count()
    );

    // Line-by-line, so a failure names the member and both values rather than
    // dumping two hundred lines.
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    let mut compared = 0usize;
    for (index, want) in expected_lines.iter().enumerate() {
        let Some(found) = actual_lines.get(index) else {
            panic!(
                "rustnode produced {} lines, Bun produced {}; first missing line {index}: {want}",
                actual_lines.len(),
                expected_lines.len()
            );
        };
        assert_eq!(found, want, "line {index}");
        compared += 1;
    }
    assert_eq!(
        actual_lines.len(),
        expected_lines.len(),
        "rustnode produced a different number of lines"
    );
    // A comparison that silently matched nothing is not a pass.
    assert!(compared > 100, "only {compared} lines were compared");
}

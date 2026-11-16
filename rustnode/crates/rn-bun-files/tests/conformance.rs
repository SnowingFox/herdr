//! The `Bun` file and path group, against the built `rustnode` and Bun 1.4.4.
//!
//! # Why the binary and not an in-process realm
//!
//! `Bun.file` returns a real `Blob`, and the point of the implementation is that
//! the `Blob` is *Node's* — `instanceof Blob` and every prototype member come from
//! `lib/internal/blob.js`. Checking that needs the whole realm, and the realm is
//! what `target/debug/rustnode` is. It is also where `Bun` is really assembled:
//! the shared foundation builds it from the generated contribution aggregator, so
//! a test that hand-built the object here would skip the declaration check the
//! registry performs.
//!
//! So every case runs a script under the built binary, exactly as
//! `crates/rn-bun-time/tests/differential.rs` does, and `tools/check.sh` builds
//! `target/debug/rustnode` before the test sweep for this reason.
//!
//! # What is compared
//!
//! Where Bun's own binary is available (`RUSTNODE_BUN_ORACLE`, default
//! `/tmp/bun-dl/bun-linux-x64/bun`), the same script runs under both and the
//! outputs must be identical. Where a value cannot match across processes — a
//! timestamp, a process id — the probe prints a shape rather than the value, and
//! the test says so at the assertion.
//!
//! # Cleanup
//!
//! Every case works in its own temp directory, removed when the guard drops, so
//! a failure cannot leave state in the repository or in `/tmp`.

use std::path::PathBuf;
use std::process::Command;

/// Where the Bun oracle lives, or `None` when the comparison must be skipped.
fn bun_oracle() -> Option<PathBuf> {
    let path = std::env::var("RUSTNODE_BUN_ORACLE")
        .unwrap_or_else(|_| "/tmp/bun-dl/bun-linux-x64/bun".to_string());
    if std::path::Path::new(&path).is_file() {
        Some(PathBuf::from(path))
    } else {
        eprintln!(
            "skipped the Bun comparison: no oracle at {path}; set RUSTNODE_BUN_ORACLE to \
             compare. This is a skip, not a pass: the member was not compared against Bun."
        );
        None
    }
}

/// The built runtime, found the way every other crate's integration test does.
///
/// `CARGO_BIN_EXE_rustnode` is only defined for the crate that declares the
/// binary, so a dependent crate cannot use it; `tools/check.sh` builds
/// `target/debug/rustnode` before the tests run.
fn rustnode() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    assert!(
        path.is_file(),
        "the runtime is missing at {}; `tools/check.sh` builds it before the tests",
        path.display()
    );
    path
}

/// A temp directory removed when the guard drops.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rn-bun-files-{name}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().expect("utf8")
    }

    /// Writes `relative` under this directory, creating its parents.
    fn write(&self, relative: &str, contents: &str) {
        let full = self.0.join(relative);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("parents");
        }
        std::fs::write(full, contents).expect("write");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `script` under `binary` in `directory` and returns trimmed stdout.
fn run_at(binary: &std::path::Path, directory: Option<&str>, script: &str) -> String {
    let mut command = Command::new(binary);
    command.args(["-e", script]);
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let out = command
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        out.status.success(),
        "{} failed ({})\nscript:\n{script}\nstderr:\n{}",
        binary.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Runs `script` under the built runtime.
fn ours(directory: Option<&str>, script: &str) -> String {
    run_at(&rustnode(), directory, script)
}

/// Runs `script` under Bun, failing when there is no oracle.
///
/// Only the cases that genuinely compare call this, so a missing Bun fails rather
/// than skips: a comparison that silently ran one runtime compared nothing.
fn bun(script: &str, directory: Option<&str>) -> String {
    let oracle = bun_oracle().expect(
        "this case compares against Bun 1.4.4, so it needs the oracle at \
         /tmp/bun-dl/bun-linux-x64/bun or RUSTNODE_BUN_ORACLE",
    );
    run_at(&oracle, directory, script)
}

/// The helper prelude every probe uses, so both runtimes print the same shape.
///
/// `JSON.stringify` of a tagged array rather than free text: an exception becomes
/// `["throw", ctor, code, message]` and a value `["value", value]`, so a case that
/// throws cannot pass by printing a string that happens to match a value.
const PROBE: &str = r#"
const show = (label, fn) => {
  let result;
  try {
    result = ["value", fn()];
  } catch (error) {
    result = ["throw", error.constructor.name, error.code ?? null, error.message];
  }
  process.stdout.write(label + " " + JSON.stringify(result) + "\n");
};
"#;

/// `PROBE` plus an async variant, for members whose real work is a promise.
const PROBE_ASYNC: &str = r#"
const show = (label, fn) => {
  let result;
  try {
    result = ["value", fn()];
  } catch (error) {
    result = ["throw", error.constructor.name, error.code ?? null, error.message];
  }
  process.stdout.write(label + " " + JSON.stringify(result) + "\n");
};
const showAsync = (label, fn) => fn().then(
  (value) => process.stdout.write(label + " " + JSON.stringify(["value", value]) + "\n"),
  (error) => process.stdout.write(label + " " + JSON.stringify(["throw", error.constructor.name, error.code ?? null, error.message]) + "\n"),
);
"#;

#[test]
fn bun_file_is_a_real_blob() {
    let dir = TempDir::new("blob");
    dir.write("hello.txt", "hello world");

    let script = format!(
        r#"{PROBE}
const f = Bun.file("hello.txt");
show("ctor", () => f.constructor.name);
show("instanceofBlob", () => f instanceof Blob);
show("instanceofFile", () => f instanceof File);
show("ownKeys", () => Object.getOwnPropertyNames(f));
show("size", () => f.size);
show("type", () => f.type);
show("name", () => f.name);
show("lastModifiedIsNumber", () => typeof f.lastModified === "number");
show("nodeProtoCount", () => Object.getOwnPropertyNames(Blob.prototype).length);
show("plainBlobHasJson", () => typeof new Blob(["x"]).json);
"#
    );
    let out = ours(Some(dir.path()), &script);

    // The core claim: Node's `Blob`, not a lookalike.
    assert!(out.contains(r#"ctor ["value","Blob"]"#), "{out}");
    assert!(out.contains(r#"instanceofBlob ["value",true]"#), "{out}");
    assert!(out.contains(r#"instanceofFile ["value",false]"#), "{out}");
    // An own property would show a wrapper; Bun reports none.
    assert!(out.contains(r#"ownKeys ["value",[]]"#), "{out}");
    assert!(out.contains(r#"size ["value",11]"#), "{out}");
    assert!(
        out.contains(r#"type ["value","text/plain;charset=utf-8"]"#),
        "{out}"
    );
    assert!(out.contains(r#"name ["value","hello.txt"]"#), "{out}");
    assert!(
        out.contains(r#"lastModifiedIsNumber ["value",true]"#),
        "{out}"
    );
    // Node's `Blob` is untouched, which is the property the design protects.
    assert!(out.contains(r#"nodeProtoCount ["value",9]"#), "{out}");
    assert!(
        out.contains(r#"plainBlobHasJson ["value","undefined"]"#),
        "{out}"
    );
}

#[test]
fn bun_file_prototype_carries_buns_ten_extra_members() {
    let dir = TempDir::new("proto");
    dir.write("hello.txt", "hello world");

    // The measured divergence: Bun's prototype for a file *is* `Blob.prototype`.
    // This build puts the members one link deeper so Node's `Blob` stays clean,
    // and this pins both halves so neither can drift silently.
    let script = format!(
        r#"{PROBE}
const f = Bun.file("hello.txt");
show("protoIsBlobPrototype", () => Object.getPrototypeOf(f) === Blob.prototype);
show("chainReachesBlobPrototype", () => Object.getPrototypeOf(Object.getPrototypeOf(f)) === Blob.prototype);
// The ten members Bun adds beyond Node's nine, which is the part this crate
// contributes. The full list also carries Node's own nine.
const BUN_ONLY = ["json","exists","stat","write","unlink","delete","image","formData","writer","name","lastModified"];
show("bunMembers", () => BUN_ONLY.filter((name) => typeof Object.getOwnPropertyDescriptor(Object.getPrototypeOf(f), name) !== "undefined").sort());
"#
    );
    let out = ours(Some(dir.path()), &script);

    assert!(
        out.contains(r#"protoIsBlobPrototype ["value",false]"#),
        "the divergence must be deliberate and visible: {out}"
    );
    assert!(
        out.contains(r#"chainReachesBlobPrototype ["value",true]"#),
        "{out}"
    );
    assert!(
        out.contains(
            r#"bunMembers ["value",["delete","exists","formData","image","json","lastModified","name","stat","unlink","write","writer"]]"#
        ),
        "{out}"
    );

    // And against Bun, which reports the same member set at a different prototype.
    if bun_oracle().is_some() {
        let theirs = bun(&script, Some(dir.path()));
        assert!(
            theirs.contains(r#"bunMembers ["value",["delete","exists","formData","image","json","lastModified","name","stat","unlink","write","writer"]]"#),
            "Bun's member set changed: {theirs}"
        );
        assert!(
            theirs.contains(r#"protoIsBlobPrototype ["value",true]"#),
            "Bun no longer puts a file's prototype at Blob.prototype: {theirs}"
        );
    }
}

#[test]
fn bun_file_read_methods_match_bun() {
    let dir = TempDir::new("read");
    dir.write("hello.txt", "hello world");
    dir.write("data.json", r#"{"a":1}"#);
    dir.write("empty.txt", "");

    let script = format!(
        r#"{PROBE_ASYNC}
(async () => {{
  const f = Bun.file("hello.txt");
  await showAsync("text", () => f.text());
  await showAsync("textRepeatable", () => f.text());
  await showAsync("json", () => Bun.file("data.json").json());
  await showAsync("bytes", async () => Array.from(await f.bytes()));
  await showAsync("arrayBufferLength", async () => (await f.arrayBuffer()).byteLength);
  await showAsync("existsTrue", () => f.exists());
  await showAsync("existsFalse", () => Bun.file("nope.txt").exists());
  await showAsync("stream", async () => f.stream() instanceof ReadableStream);
  await showAsync("slice", () => f.slice(0, 5).text());
  await showAsync("empty", () => Bun.file("empty.txt").text());
}})();
"#
    );
    let out = ours(Some(dir.path()), &script);

    for expected in [
        r#"text ["value","hello world"]"#,
        r#"textRepeatable ["value","hello world"]"#,
        r#"json ["value",{"a":1}]"#,
        r#"bytes ["value",[104,101,108,108,111,32,119,111,114,108,100]]"#,
        r#"arrayBufferLength ["value",11]"#,
        r#"existsTrue ["value",true]"#,
        r#"existsFalse ["value",false]"#,
        r#"stream ["value",true]"#,
        r#"slice ["value","hello"]"#,
        r#"empty ["value",""]"#,
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected} in:\n{out}"
        );
    }

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "reads differ from Bun 1.4.4"
        );
    }
}

#[test]
fn bun_file_failure_modes_are_buns_classes_and_messages() {
    let dir = TempDir::new("fail");
    dir.write("hello.txt", "hello world");

    let script = format!(
        r#"{PROBE_ASYNC}
(async () => {{
  await showAsync("textMissing", () => Bun.file("nope.txt").text());
  await showAsync("bytesMissing", () => Bun.file("nope.txt").bytes());
  await showAsync("statMissing", () => Bun.file("nope.txt").stat());
  await showAsync("directory", () => Bun.file(".").text());
  await showAsync("nonJson", () => Bun.file("hello.txt").json());
  show("sizeMissing", () => Bun.file("nope.txt").size);
  show("noArg", () => Bun.file());
  show("blobArg", () => Bun.file(Bun.file("hello.txt")));
}})();
"#
    );
    let out = ours(Some(dir.path()), &script);

    // A reader names `open`, `stat` names `stat`; both are ENOENT.
    assert!(
        out.contains(
            r#"textMissing ["throw","Error","ENOENT","ENOENT: no such file or directory, open 'nope.txt'"]"#
        ),
        "{out}"
    );
    assert!(
        out.contains(
            r#"statMissing ["throw","Error","ENOENT","ENOENT: no such file or directory, stat 'nope.txt'"]"#
        ),
        "{out}"
    );
    // Bun's own wording, not Node's EISDIR text.
    assert!(
        out.contains(
            r#"directory ["throw","Error","EISDIR","Directories cannot be read like files"]"#
        ),
        "{out}"
    );
    assert!(
        out.contains(
            r#"nonJson ["throw","SyntaxError",null,"JSON Parse error: Unexpected identifier \"hello\""]"#
        ),
        "{out}"
    );
    assert!(out.contains(r#"sizeMissing ["value",0]"#), "{out}");
    assert!(
        out.contains(
            r#"noArg ["throw","TypeError","ERR_INVALID_ARG_TYPE","Expected file path string or file descriptor"]"#
        ),
        "{out}"
    );
    assert!(
        out.contains(
            r#"blobArg ["throw","TypeError","ERR_INVALID_ARG_TYPE","Expected file path string or file descriptor"]"#
        ),
        "{out}"
    );

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "failure modes differ from Bun 1.4.4"
        );
    }
}

#[test]
fn bun_write_matches_bun_including_parent_directories() {
    let dir = TempDir::new("write");

    let script = format!(
        r#"{PROBE_ASYNC}
const fs = require("node:fs");
(async () => {{
  await showAsync("string", async () => {{ const n = await Bun.write("a.txt", "data"); return [n, fs.readFileSync("a.txt", "utf8")]; }});
  await showAsync("bytes", async () => {{ await Bun.write("b.bin", new Uint8Array([1,2,3])); return fs.readFileSync("b.bin").toString("hex"); }});
  await showAsync("blob", async () => {{ await Bun.write("d.txt", new Blob(["blobdata"])); return fs.readFileSync("d.txt", "utf8"); }});
  await showAsync("bunFileDest", async () => {{ await Bun.write(Bun.file("e.txt"), "viafile"); return fs.readFileSync("e.txt", "utf8"); }});
  await showAsync("bunFilePayload", async () => {{ await Bun.write("f.txt", Bun.file("a.txt")); return fs.readFileSync("f.txt", "utf8"); }});
  await showAsync("numberCoerced", async () => {{ const n = await Bun.write("g.txt", 42); return [n, fs.readFileSync("g.txt", "utf8")]; }});
  // Anything non-nullish that is not binary is coerced rather than rejected. An
  // object and a boolean are here because V8's `String()` and JavaScriptCore's
  // agree on them.
  await showAsync("objectCoerced", async () => {{ const n = await Bun.write("h.txt", {{a: 1}}); return [n, fs.readFileSync("h.txt", "utf8")]; }});
  await showAsync("booleanCoerced", async () => {{ const n = await Bun.write("i.txt", true); return [n, fs.readFileSync("i.txt", "utf8")]; }});
  // An array is a list of **parts**, joined with no separator: Bun writes `"12"`
  // for `[1, 2]` where `String([1,2])` is `"1,2"`. This is Bun's own rule, not
  // an engine difference — both V8 and JavaScriptCore report `"1,2"` for
  // `String([1,2])` — so it is pinned rather than excused as one.
  //
  // A nullish element contributes nothing among its neighbours, so `[1, null, 2]`
  // writes `"12"`. A single-element array holding one is the exception: Bun
  // reduces it to that element and coerces the element, so `[null]` is the four
  // bytes `null`. Both measured on 1.4.4.
  //
  // A **function** payload is the one case this test deliberately does not pin:
  // `String(function f(){{}})` is `"function f(){{}}"` on V8 and
  // `"function f() {{}}"` on JavaScriptCore, so the bytes legitimately differ
  // between the runtimes (14 against 15). That is a real engine difference and is
  // documented in `write.rs`; it is not the explanation for the array cases
  // above, whose bytes differ from `String()` on *both* engines.
  await showAsync("arrayParts", async () => {{ const n = await Bun.write("l.txt", [1, 2]); return [n, fs.readFileSync("l.txt", "utf8")]; }});
  await showAsync("arrayNested", async () => {{ const n = await Bun.write("m.txt", [[1], [2]]); return [n, fs.readFileSync("m.txt", "utf8")]; }});
  await showAsync("arrayWithNullGap", async () => {{ const n = await Bun.write("n2.txt", [1, null, 2]); return [n, fs.readFileSync("n2.txt", "utf8")]; }});
  await showAsync("arrayLoneNull", async () => {{ const n = await Bun.write("n3.txt", [null]); return [n, fs.readFileSync("n3.txt", "utf8")]; }});
  show("nullPayload", () => Bun.write("j.txt", null));
  show("undefinedPayload", () => Bun.write("k.txt", undefined));
  // Parent directories are created; Node's `writeFile` throws ENOENT here.
  await showAsync("createsParents", async () => {{ await Bun.write("deep/nested/x.txt", "created"); return fs.readFileSync("deep/nested/x.txt", "utf8"); }});
  await showAsync("fd", async () => {{
    const fd = fs.openSync("fd.txt", "w");
    try {{ const n = await Bun.write(fd, "hello"); return [n, fs.readFileSync("fd.txt", "utf8")]; }} finally {{ fs.closeSync(fd); }}
  }});
  show("noArg", () => Bun.write());
  show("pathOnly", () => Bun.write("only.txt"));
  show("nullData", () => Bun.write("n.txt", null));
  await showAsync("directory", () => Bun.write(".", "x"));
}})();
"#
    );
    let out = ours(Some(dir.path()), &script);

    for expected in [
        r#"string ["value",[4,"data"]]"#,
        r#"bytes ["value","010203"]"#,
        r#"blob ["value","blobdata"]"#,
        r#"bunFileDest ["value","viafile"]"#,
        r#"bunFilePayload ["value","data"]"#,
        r#"numberCoerced ["value",[2,"42"]]"#,
        r#"createsParents ["value","created"]"#,
        r#"fd ["value",[5,"hello"]]"#,
        // Two different messages, one per missing argument.
        r#"noArg ["throw","TypeError","ERR_INVALID_ARG_TYPE","The \"destination\" argument must be of type path, file descriptor, or Blob. Received undefined"]"#,
        r#"pathOnly ["throw","TypeError","ERR_INVALID_ARG_TYPE","Bun.write(pathOrFdOrBlob, blob) expects a Blob-y thing to write"]"#,
        r#"nullData ["throw","TypeError","ERR_INVALID_ARG_TYPE","Bun.write(pathOrFdOrBlob, blob) expects a Blob-y thing to write"]"#,
        r#"directory ["throw","Error","EISDIR","EISDIR: illegal operation on a directory, open '.'"]"#,
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected} in:\n{out}"
        );
    }

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "Bun.write differs from Bun 1.4.4"
        );
    }
}

#[test]
fn bun_mmap_view_is_live_and_private_by_default() {
    let dir = TempDir::new("mmap");
    dir.write("m.txt", "0123456789");
    dir.write("p.txt", "abcdef");
    dir.write("s.txt", "abcdef");
    dir.write("zero.bin", "");

    let script = format!(
        r#"{PROBE}
const fs = require("node:fs");
show("ctor", () => Bun.mmap("m.txt").constructor.name);
show("tag", () => Object.prototype.toString.call(Bun.mmap("m.txt")));
show("contents", () => Array.from(Bun.mmap("m.txt").slice(0, 4)));
show("length", () => Bun.mmap("m.txt").length);
// The view is live, not a copy. Measured on Bun 1.4.4: the DEFAULT is
// `MAP_SHARED` — a write to a plain `Bun.mmap(path)` reaches the file — and
// only an explicit `shared: false` gives a private copy. The recorded spec says
// the opposite; the oracle disagrees and the oracle wins.
show("writeInMemory", () => {{ const b = Bun.mmap("p.txt"); b[0] = 88; return String.fromCharCode(b[0]); }});
show("defaultWriteOnDisk", () => fs.readFileSync("p.txt", "utf8"));
show("privateWriteOnDisk", () => {{ fs.writeFileSync("q.txt", "abcdef"); const b = Bun.mmap("q.txt", {{ shared: false }}); b[0] = 90; return fs.readFileSync("q.txt", "utf8"); }});
show("sharedWriteOnDisk", () => {{ const b = Bun.mmap("s.txt", {{ shared: true }}); b[0] = 89; return fs.readFileSync("s.txt", "utf8"); }});
show("noArg", () => Bun.mmap());
show("numberPath", () => Bun.mmap(42));
show("zeroLength", () => Bun.mmap("zero.bin"));
"#
    );
    let out = ours(Some(dir.path()), &script);

    for expected in [
        r#"ctor ["value","Uint8Array"]"#,
        r#"tag ["value","[object Uint8Array]"]"#,
        r#"contents ["value",[48,49,50,51]]"#,
        r#"length ["value",10]"#,
        r#"writeInMemory ["value","X"]"#,
        // The default writes through; only `shared: false` leaves the file alone.
        r#"defaultWriteOnDisk ["value","Xbcdef"]"#,
        r#"privateWriteOnDisk ["value","abcdef"]"#,
        r#"sharedWriteOnDisk ["value","Ybcdef"]"#,
        // A zero-byte file is EINVAL rather than an empty array.
        r#"zeroLength ["throw","Error","EINVAL","EINVAL: invalid argument, mmap"]"#,
        r#"noArg ["throw","TypeError","ERR_INVALID_ARG_TYPE","path must be a string"]"#,
        r#"numberPath ["throw","TypeError","ERR_INVALID_ARG_TYPE","path must be a string"]"#,
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected} in:\n{out}"
        );
    }

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "Bun.mmap differs from Bun 1.4.4"
        );
    }
}

#[test]
fn bun_mmap_missing_file_is_enoent() {
    let dir = TempDir::new("mmap-missing");
    let script = format!(
        r#"{PROBE}
show("missing", () => Bun.mmap("nope.bin"));
"#
    );
    let out = ours(Some(dir.path()), &script);
    assert!(
        out.contains(
            r#"missing ["throw","Error","ENOENT","ENOENT: no such file or directory, open '"#
        ),
        "{out}"
    );

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "the missing-file message differs from Bun 1.4.4"
        );
    }
}

#[test]
fn a_mmap_view_stays_valid_across_a_collection() {
    let dir = TempDir::new("mmap-gc");
    dir.write("g.bin", &"A".repeat(4096));

    // The lifetime half of the contract. V8 may collect while the view is
    // reachable; reading it afterwards must still see the mapped bytes. A
    // use-after-unmap would crash here or return garbage, and both are failures.
    let script = format!(
        r#"{PROBE_ASYNC}
(async () => {{
  const view = Bun.mmap("g.bin");
  const first = view[0];
  const last = view[view.length - 1];
  if (typeof Bun.gc === "function") {{ Bun.gc(true); Bun.gc(true); }}
  // Yield through the microtask queue, which needs no event loop.
  await Promise.resolve();
  show("stillValid", () => [first, last, view.length]);
  show("bytesUnchanged", () => view.every((byte) => byte === 65));
  show("stillWritable", () => {{ view[0] = 66; return view[0]; }});
}})();
"#
    );
    let out = ours(Some(dir.path()), &script);

    assert!(
        out.contains(r#"stillValid ["value",[65,65,4096]]"#),
        "{out}"
    );
    assert!(out.contains(r#"bytesUnchanged ["value",true]"#), "{out}");
    assert!(out.contains(r#"stillWritable ["value",66]"#), "{out}");
}

#[test]
fn bun_glob_matches_and_scans_like_bun() {
    let dir = TempDir::new("glob");
    dir.write("g/a.js", "x");
    dir.write("g/b.txt", "x");
    dir.write("g/sub/c.js", "x");
    dir.write("g/.hidden.js", "x");

    let script = format!(
        r#"{PROBE}
show("ctorLength", () => Bun.Glob.length);
show("ctorName", () => Bun.Glob.name);
show("proto", () => Object.getOwnPropertyNames(Bun.Glob.prototype));
show("instanceOwnKeys", () => Object.getOwnPropertyNames(new Bun.Glob("x")));
show("star", () => [...new Bun.Glob("*.js").scanSync({{ cwd: "g" }})]);
show("globstar", () => [...new Bun.Glob("**/*.js").scanSync({{ cwd: "g" }})]);
show("dot", () => [...new Bun.Glob("*.js").scanSync({{ cwd: "g", dot: true }})].sort());
show("onlyFilesFalse", () => [...new Bun.Glob("*").scanSync({{ cwd: "g", onlyFiles: false }})].sort());
show("absoluteIsAbsolute", () => [...new Bun.Glob("*.js").scanSync({{ cwd: "g", absolute: true }})].every((path) => path.startsWith("/") && path.endsWith("/g/a.js")));
show("matchBasename", () => new Bun.Glob("*.js").match("a.js"));
show("matchNonMatching", () => new Bun.Glob("*.js").match("a.txt"));
// `match` is basename-only: a slash never matches and no normalisation happens.
show("matchSlash", () => new Bun.Glob("*.js").match("sub/a.js"));
show("matchLeadingDotSlash", () => new Bun.Glob("*.js").match("./a.js"));
show("noArg", () => new Bun.Glob());
show("numberPattern", () => new Bun.Glob(42));
"#
    );
    let out = ours(Some(dir.path()), &script);

    for expected in [
        r#"ctorLength ["value",1]"#,
        r#"ctorName ["value","Glob"]"#,
        r#"proto ["value",["match","scan","scanSync","constructor"]]"#,
        r#"instanceOwnKeys ["value",[]]"#,
        r#"star ["value",["a.js"]]"#,
        r#"globstar ["value",["a.js","sub/c.js"]]"#,
        r#"dot ["value",[".hidden.js","a.js"]]"#,
        r#"onlyFilesFalse ["value",["a.js","b.txt","sub"]]"#,
        r#"absoluteIsAbsolute ["value",true]"#,
        r#"matchBasename ["value",true]"#,
        r#"matchNonMatching ["value",false]"#,
        r#"matchSlash ["value",false]"#,
        r#"matchLeadingDotSlash ["value",false]"#,
        r#"noArg ["throw","TypeError","ERR_INVALID_ARG_TYPE","pattern must be a string"]"#,
        r#"numberPattern ["throw","TypeError","ERR_INVALID_ARG_TYPE","pattern must be a string"]"#,
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected} in:\n{out}"
        );
    }

    if bun_oracle().is_some() {
        // `scan` returns directory order, which the two runtimes share because it
        // is the same directory; the two cases where order is not Bun's contract
        // are sorted in the probe.
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "Bun.Glob differs from Bun 1.4.4"
        );
    }
}

#[test]
fn bun_file_system_router_routes_and_matches_like_bun() {
    let dir = TempDir::new("router");
    dir.write("pages/index.tsx", "");
    dir.write("pages/about.tsx", "");
    dir.write("pages/api/hello.ts", "");
    dir.write("pages/blog/index.tsx", "");
    dir.write("pages/blog/[slug].tsx", "");

    let script = format!(
        r#"{PROBE}
const router = () => new Bun.FileSystemRouter({{ style: "nextjs", dir: "pages" }});
show("ctorLength", () => Bun.FileSystemRouter.length);
show("ctorName", () => Bun.FileSystemRouter.name);
show("proto", () => Object.getOwnPropertyNames(Bun.FileSystemRouter.prototype));
show("routes", () => Object.keys(router().routes).sort());
show("routesPlain", () => Object.getPrototypeOf(router().routes) === Object.prototype);
show("props", () => {{ const r = router(); return [r.origin, r.assetPrefix, r.style]; }});
show("exact", () => {{
  const m = router().match("/about");
  return [m.pathname, m.params, m.query, m.name, m.kind, typeof m.filePath];
}});
// Fields are enumerable getters on a custom prototype: `keys` is empty while
// every field reads, and concluding "empty object" from `keys` would be wrong.
show("ownKeys", () => Object.getOwnPropertyNames(router().match("/about")));
show("keys", () => Object.keys(router().match("/about")));
show("inOperator", () => "filePath" in router().match("/about"));
show("dynamic", () => {{ const m = router().match("/blog/hello-world"); return [m.pathname, m.params, m.name, m.kind]; }});
// Measured: the query is split out AND retained in `pathname`.
show("query", () => {{ const m = router().match("/about?x=1&y=2"); return [m.pathname, m.query]; }});
show("miss", () => router().match("/nope"));
show("empty", () => router().match("").pathname);
show("badStyle", () => new Bun.FileSystemRouter({{ style: "bogus", dir: "pages" }}));
show("noArg", () => new Bun.FileSystemRouter());
"#
    );
    let out = ours(Some(dir.path()), &script);

    for expected in [
        r#"ctorLength ["value",0]"#,
        r#"ctorName ["value","FileSystemRouter"]"#,
        // Bun's prototype order is alphabetical; it is observable and pinned.
        r#"proto ["value",["assetPrefix","match","origin","reload","routes","style","constructor"]]"#,
        r#"routes ["value",["/","/about","/api/hello","/blog","/blog/[slug]"]]"#,
        r#"routesPlain ["value",true]"#,
        r#"props ["value",[null,null,"nextjs"]]"#,
        r#"exact ["value",["/about",{},{},"/about","exact","string"]]"#,
        r#"ownKeys ["value",[]]"#,
        r#"keys ["value",[]]"#,
        r#"inOperator ["value",true]"#,
        r#"dynamic ["value",["/blog/hello-world",{"slug":"hello-world"},"/blog/[slug]","dynamic"]]"#,
        r#"query ["value",["/about?x=1&y=2",{"x":"1","y":"2"}]]"#,
        r#"miss ["value",null]"#,
        r#"empty ["value","/"]"#,
        r#"badStyle ["throw","TypeError","ERR_INVALID_ARG_TYPE","Only 'nextjs' style is currently implemented"]"#,
        r#"noArg ["throw","TypeError","ERR_INVALID_ARG_TYPE","Expected object"]"#,
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected} in:\n{out}"
        );
    }

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "Bun.FileSystemRouter differs from Bun 1.4.4"
        );
    }
}

#[test]
fn bun_which_resolves_and_never_throws() {
    let dir = TempDir::new("which");
    dir.write("bin/mytool", "#!/bin/sh\n");
    dir.write("bin/noexec", "x");
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.0.join("bin/mytool");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }

    let script = format!(
        r#"{PROBE}
show("ls", () => Bun.which("ls"));
show("missing", () => Bun.which("nonexistent-xyz-abc"));
show("absoluteExists", () => Bun.which("/bin/ls"));
show("absoluteMissing", () => Bun.which("/nope/x"));
show("customPath", () => Bun.which("mytool", {{ PATH: {bin:?} }}));
show("skipsNonExecutable", () => Bun.which("noexec", {{ PATH: {bin:?} }}));
// Never throws: a numeric argument and no argument are both `null`.
show("noArg", () => Bun.which());
show("number", () => Bun.which(42));
show("emptyString", () => Bun.which(""));
"#,
        bin = format!("{}/bin", dir.path())
    );
    let out = ours(Some(dir.path()), &script);

    for expected in [
        r#"ls ["value","/usr/bin/ls"]"#,
        r#"missing ["value",null]"#,
        r#"absoluteExists ["value","/bin/ls"]"#,
        r#"absoluteMissing ["value",null]"#,
        r#"skipsNonExecutable ["value",null]"#,
        r#"noArg ["value",null]"#,
        r#"number ["value",null]"#,
        r#"emptyString ["value",null]"#,
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected} in:\n{out}"
        );
    }
    assert!(
        out.contains(&format!(
            r#"customPath ["value","{}/bin/mytool"]"#,
            dir.path()
        )),
        "{out}"
    );

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "Bun.which differs from Bun 1.4.4"
        );
    }
}

#[test]
fn bun_resolve_matches_bun_including_the_builtin_divergence() {
    let dir = TempDir::new("resolve");
    dir.write("hello.txt", "x");
    std::fs::create_dir_all(dir.0.join("sub")).expect("sub");

    let script = format!(
        r#"{PROBE}
const dir = {dir:?};
show("relative", () => Bun.resolveSync("./hello.txt", dir));
show("parentTraversal", () => Bun.resolveSync("../hello.txt", dir + "/sub"));
show("nodePrefixed", () => Bun.resolveSync("node:fs", dir));
// The recorded divergence from Node: Node answers "fs", Bun answers "node:fs".
show("bareBuiltin", () => Bun.resolveSync("fs", dir));
show("bunSpecifier", () => Bun.resolveSync("bun:test", dir));
show("missing", () => Bun.resolveSync("./nope", dir));
show("noArg", () => Bun.resolveSync());
show("oneArg", () => Bun.resolveSync("./hello.txt"));
show("errorShape", () => {{
  try {{ Bun.resolveSync("./nope", dir); }} catch (error) {{
    return [error.constructor.name, error.code, error instanceof Error, Object.keys(error)];
  }}
  return "no throw";
}});
show("isPromise", () => Bun.resolve("./hello.txt", dir) instanceof Promise);
"#,
        dir = dir.path()
    );
    let out = ours(Some(dir.path()), &script);

    for expected in [
        r#"nodePrefixed ["value","node:fs"]"#,
        r#"bareBuiltin ["value","node:fs"]"#,
        r#"bunSpecifier ["value","bun:test"]"#,
        r#"noArg ["throw","TypeError","ERR_INVALID_ARG_TYPE","Expected a specifier and a from path"]"#,
        r#"oneArg ["throw","TypeError","ERR_INVALID_ARG_TYPE","Expected a from path"]"#,
        // No enumerable own properties, still an `Error`.
        r#"errorShape ["value",["ResolveMessage","ERR_MODULE_NOT_FOUND",true,[]]]"#,
        r#"isPromise ["value",true]"#,
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected} in:\n{out}"
        );
    }
    assert!(
        out.contains(&format!(r#"relative ["value","{}/hello.txt"]"#, dir.path())),
        "{out}"
    );
    assert!(
        out.contains(r#"missing ["throw","ResolveMessage","ERR_MODULE_NOT_FOUND""#),
        "{out}"
    );

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, Some(dir.path())),
            "Bun.resolveSync differs from Bun 1.4.4"
        );
    }
}

#[test]
fn the_path_conversions_equal_node_url() {
    let script = format!(
        r#"{PROBE}
const url = require("node:url");
for (const path of ["/tmp/x/a.txt", "/with space/a.txt", "/ünïcode/a.txt", "/a#b?c.txt"]) {{
  show("pathToFileURL " + path, () => Bun.pathToFileURL(path).href === url.pathToFileURL(path).href);
}}
for (const value of ["file:///tmp/x/a.txt", "file:///tmp/with%20space/a.txt", "file:///tmp/%C3%BC.txt", "file://localhost/tmp/a"]) {{
  show("fileURLToPath " + value, () => Bun.fileURLToPath(value) === url.fileURLToPath(value));
}}
// The two cases a hand-rolled encoder gets wrong, pinned by value.
show("escaping", () => Bun.pathToFileURL("/a#b?c.txt").href);
show("localhost", () => Bun.fileURLToPath("file://localhost/tmp/a"));
show("nonFile", () => Bun.fileURLToPath("/tmp/notaurl"));
show("isUrl", () => Bun.pathToFileURL("/tmp/x") instanceof URL);
"#
    );
    let out = ours(None, &script);

    for expected in [
        r#"pathToFileURL /tmp/x/a.txt ["value",true]"#,
        r#"pathToFileURL /with space/a.txt ["value",true]"#,
        r#"pathToFileURL /ünïcode/a.txt ["value",true]"#,
        r#"pathToFileURL /a#b?c.txt ["value",true]"#,
        r#"fileURLToPath file:///tmp/x/a.txt ["value",true]"#,
        r#"fileURLToPath file:///tmp/with%20space/a.txt ["value",true]"#,
        r#"fileURLToPath file:///tmp/%C3%BC.txt ["value",true]"#,
        r#"fileURLToPath file://localhost/tmp/a ["value",true]"#,
        r#"escaping ["value","file:///a%23b%3Fc.txt"]"#,
        r#"localhost ["value","/tmp/a"]"#,
        r#"isUrl ["value",true]"#,
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected} in:\n{out}"
        );
    }
    assert!(
        out.contains(
            r#"nonFile ["throw","TypeError","ERR_INVALID_URL_SCHEME","The URL must be of scheme file"]"#
        ),
        "{out}"
    );

    if bun_oracle().is_some() {
        assert_eq!(
            out,
            bun(&script, None),
            "the path conversions differ from Bun 1.4.4"
        );
    }
}

#[test]
fn the_installed_surface_matches_this_crates_declaration() {
    let script = format!(
        r#"{PROBE}
const names = {members:?};
show("missing", () => names.filter((name) => !(name in Bun)));
show("types", () => names.map((name) => typeof Bun[name]));
// Measured on Bun 1.4.4: 1 for everything but the `FileSystemRouter` class.
show("arities", () => names.map((name) => Bun[name].length));
show("names", () => names.map((name) => Bun[name].name));
"#,
        members = rn_bun_files::MEMBERS
    );
    let out = ours(None, &script);

    assert!(out.contains(r#"missing ["value",[]]"#), "{out}");
    assert!(
        out.contains(r#"types ["value",["function","function","function","function","function","function","function","function","function","function"]]"#),
        "{out}"
    );
    assert!(
        out.contains(r#"arities ["value",[1,1,1,1,0,1,1,1,1,1]]"#),
        "{out}"
    );
    assert!(
        out.contains(r#"names ["value",["file","write","mmap","Glob","FileSystemRouter","which","resolve","resolveSync","fileURLToPath","pathToFileURL"]]"#),
        "{out}"
    );
}

#[test]
fn a_bun_member_is_not_a_constructor() {
    // `SetMethod` gives `new fn()` a `TypeError`; a bare `FunctionTemplate`
    // builder allows it by accident. `Bun.mmap` has real side effects, so a
    // permissive `new` would also map the file.
    let script = format!(
        r#"{PROBE}
for (const name of ["file", "write", "mmap", "which", "resolve", "resolveSync", "fileURLToPath", "pathToFileURL"]) {{
  show(name, () => {{ try {{ new Bun[name](); return "constructed"; }} catch (error) {{ return error.constructor.name; }} }});
}}
"#
    );
    let out = ours(None, &script);

    for name in [
        "file",
        "write",
        "mmap",
        "which",
        "resolve",
        "resolveSync",
        "fileURLToPath",
        "pathToFileURL",
    ] {
        assert!(
            out.contains(&format!(r#"{name} ["value","TypeError"]"#)),
            "{name} accepted `new`: {out}"
        );
    }
}

#[test]
fn node_has_no_bun_global_and_rustnode_does() {
    // The "it cannot break Node" half: `Bun` is rustnode's addition, and a script
    // written for Node must not see one it did not install.
    let script = r#"process.stdout.write(String(typeof globalThis.Bun))"#;
    assert_eq!(ours(None, script), "object");

    let Some(oracle) = rn_node_oracle::require_oracle("the Bun global is rustnode-only") else {
        return;
    };
    let theirs = run_at(std::path::Path::new(oracle.reference_path()), None, script);
    assert_eq!(
        theirs, "undefined",
        "the Node oracle has a Bun global, so this comparison is about the wrong runtime"
    );
}

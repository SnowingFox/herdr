# Adding a `Bun.*` member

`Bun` is one flat property space that several workers fill in parallel, so the way
to add a member is fixed. Follow these three steps and nothing else — in
particular, do not edit `rn-bun`, `rn-bun-members`, or any shared list.

## The three steps

**1. Create a crate (or reuse your group's crate) with one file.**

`crates/rn-bun-<group>/Cargo.toml`:

```toml
[package]
name = "rn-bun-<group>"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
description = "Bun.<members> for rustnode"

[dependencies]
rn-bun-api = { path = "../rn-bun-api" }
rn-core.workspace = true
rn-v8-sys.workspace = true
```

`crates/rn-bun-<group>/src/lib.rs`:

```rust
use rn_bun_api::BunModule;
use rn_v8_sys::v8;

pub const MEMBERS: &[&str] = &["stripANSI"];

pub struct Text;

impl BunModule for Text {
    fn contributor(&self) -> &'static str { "rn-bun-text" }
    fn members(&self) -> &'static [&'static str] { MEMBERS }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        target: v8::Local<'s, v8::Object>,
    ) -> Result<(), String> {
        rn_core::set_method(scope, target, "stripANSI", strip_ansi)?;
        Ok(())
    }
}

pub fn register(registry: &mut rn_bun_api::BunRegistry) -> Result<(), String> {
    registry.register_module(Text)
}
```

**2. Run the generator.**

```bash
cd rustnode && ./tools/regen-bun-contributions.sh
```

It finds every crate that declares `pub fn register(registry: &mut rn_bun_api::BunRegistry)`
and rewrites `crates/rn-bun-members/src/install_all.rs` and `Cargo.toml`. That is
the only wiring there is; `rn-bun` is not involved.

**3. Run the gate.**

```bash
cd rustnode && ./tools/check.sh
```

The `Bun` surface guard fails on:

* a name in your `members()` that `install` never sets;
* a name `install` sets that is not in `members()`;
* a name that is in two crates at once;
* a name that Bun 1.4.4 does not have (a fabricated member — check
  `tools/bun-surface.json`, which records Bun's real surface);
* a deferral with no reason.

Fix the cause. Do not add anything to an allowlist — there isn't one, deliberately:
a `Bun` member is either real and declared or it fails.

## How to publish a member

Use `rn_core::set_method` for a function, `rn_core::set_class` for a constructor,
and a plain `set`/`create_data_property` for a value. `set_method` gives you
`SetMethod`'s semantics exactly: `name` equals the property name, `length` is `0`,
and `new fn()` is a `TypeError`. All three are observable, and Bun's own surface
follows them — `Bun.nanoseconds.name` is `"nanoseconds"`, its `length` is `0`, and
`new Bun.nanoseconds()` throws. A bare `FunctionTemplate::builder` defaults to
`ConstructorBehavior::Allow` and length 0 by accident, so it will let `new`
succeed where Bun throws.

If a member is a getter in Bun (only `Bun.main` is, on 1.4.4), install it as an
accessor and say so in your tests; the guard compares names, so it cannot tell you
you picked the wrong kind.

## If a member is not ready

Declare it deferred, with a reason that names why:

```rust
const DEFERRED: &[(&str, &str)] = &[("file", "needs a lazily-backed handle; tier 1, not started")];

fn deferred(&self) -> &'static [(&'static str, &'static str)] { DEFERRED }
```

Three rules, and the registry enforces all of them: a deferred name must **not**
be in `members()`, must **not** be installed, and must carry a non-empty reason.
A name that is both installed and deferred is refused, because that pair is how
`sqlite.backup` stayed green while `node:sqlite.backup` was `undefined`.

A deferred member is reported by the guard as `declared-deferred` and does not
fail it. That is the correct state for "started, stopped, and here is why" — but
not for "did not get to it". Absent is the honest word for the latter, and absent
needs no declaration at all.

A deferral is a placeholder, not an answer: it makes a gap visible where an
`undefined` would not, and it should be visible for as short a time as possible.
Tier 1 has none today, so the last one to leave — `Bun.version`, in
`rn-bun-process` — is the worked example of the other direction. Its value could
not be measured, because this runtime is not Bun, so the crate installed a
documented compatibility marker instead and the deferral became a declaration.
That is what "started, stopped, and here is why" is for: it bought the time to
decide, and then the decision replaced it.

## Testing a member

Two layers, and both are worth having:

* **Rust unit tests** for the logic, next to the code. No isolate, no globals.
* **A differential test**: run the same script under Bun 1.4.4
  (`/tmp/bun-dl/bun-linux-x64/bun`) and under `target/debug/rustnode`, and compare
  the output. Where the two cannot match exactly — compression levels, UUIDs, the
  exact nanoseconds value — compare the shape and the invariants, and say in the
  test why the exact value is not comparable.

`crates/rn-bun-time/tests/differential.rs` is the reference for the second layer.
It reads the Bun binary from `RUSTNODE_BUN_ORACLE` (default
`/tmp/bun-dl/bun-linux-x64/bun`), skips loudly when it is absent, and compares what
is stable about the member rather than what is not.

## Where `Bun` is installed, and why

`rn-realm::install_early_globals` calls `rn_bun::install` first, before its
`require` early-return. Two consequences you can rely on:

* `Bun` exists in `-e`, in a script file, and in a worker — including a worker
  whose loader failed;
* it exists before your first line runs, so a test may read `Bun.x` at the top of
  a script.

It is installed **non-enumerable**, unlike Bun's own `globalThis.Bun`
(`enumerable: true`). That is deliberate: `vendor/libnode-js/test`'s
`common/index.js` walks `Object.keys(globalThis)` and fails a test for any unknown
name, and one enumerable global cost that audit 388 files once.
`Object.getOwnPropertyNames(globalThis)` still finds `Bun`.
`crates/rn-cli/tests/m0_foundation.rs` pins the enumerable count at 9 and
`crates/rn-cli/tests/process_surface_parity.rs` compares `globalThis` against the
Node oracle, so a leak here fails the gate rather than a thousand unrelated tests.

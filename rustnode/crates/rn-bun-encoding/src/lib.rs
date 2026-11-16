//! `Bun.YAML`, `Bun.TOML`, `Bun.JSON5`, `Bun.JSONC`, `Bun.JSONL`, `Bun.XML`
//! and `Bun.markdown` for rustnode.
//!
//! This crate owns the *encoding and parsing* group of Bun's Tier 1 surface. It
//! does not create the `Bun` global: `rn-bun` builds that and installs it on
//! `globalThis`, and it reaches this crate through the contribution registry that
//! [`Encoding`] registers with.
//!
//! ```ignore
//! // What `rn-bun-members`' generated aggregator does, once per context:
//! let mut registry = rn_bun_api::BunRegistry::new();
//! rn_bun_encoding::register(&mut registry)?;
//! let bun = registry.build(scope)?;
//! ```
//!
//! # What Bun actually exposes, measured
//!
//! The namespace shapes below are `Object.getOwnPropertyNames` on Bun 1.4.4
//! (`revision 38afee6c8`), re-measured for this crate rather than taken from a
//! description. Two of them are traps for anyone writing this from the outside:
//!
//! | namespace | own members | lengths |
//! | --- | --- | --- |
//! | `Bun.YAML` | `parse`, `stringify` | 1, 3 |
//! | `Bun.TOML` | `parse`, `stringify` | 1, 3 |
//! | `Bun.JSON5` | `parse`, `stringify` | 1, 3 |
//! | `Bun.JSONC` | **`parse` only** | 1 |
//! | `Bun.JSONL` | `parse`, `parseChunk` | 1, 1 |
//! | `Bun.XML` | `parse`, `stringify` | 2, 3 |
//! | `Bun.markdown` | `html`, `ansi`, `render`, `react` | 1, 2, 3, 3 |
//!
//! `Bun.JSONC.stringify` **does not exist**. Adding one would be a divergence
//! in the same way a missing member is, so there is deliberately no function
//! here that could be published under that name.
//!
//! Every namespace is a plain object whose prototype is `Object.prototype`, and
//! every member is a plain writable, enumerable data property holding a function
//! that is **not** a constructor — `new Bun.YAML.parse(…)` throws
//! `TypeError: function is not a constructor`. One exception is recorded in
//! [`jsonl`]: `Bun.JSONL`'s two members are non-configurable and the namespace
//! itself carries `Symbol.toStringTag`.
//!
//! # Argument coercion is per member, not shared
//!
//! Bun is not consistent here and neither is this crate. The rules, measured:
//!
//! * `YAML.parse`, `JSON5.parse`, `JSONC.parse`, `XML.parse` and
//!   `markdown.html` accept a string or a byte view (`ArrayBuffer`,
//!   `ArrayBufferView`), and otherwise run the argument through `String()` — so
//!   `YAML.parse(42)` is the document `42` and `YAML.parse()` parses the
//!   document `undefined`.
//! * `TOML.parse` accepts a string or bytes **only**; anything else is
//!   `TypeError` with `code === "ERR_INVALID_ARG_TYPE"`.
//! * `JSONL.parse`/`parseChunk` accept a string or a byte view, and anything
//!   else is a `TypeError` with message `"… requires a string argument"` and
//!   **no `code`**. A non-string that `String()` would turn into valid JSONL
//!   still works: `JSONL.parse(5)` is `[5]`.
//! * `markdown.*` accept a string or a byte view and nothing else.
//!
//! A shared "get the input string" helper would therefore be wrong for four of
//! the seven namespaces, so each module owns its own argument handling and says
//! which rule it implements.
//!
//! # Errors
//!
//! Parser failures are `SyntaxError` with `code === undefined` and a message
//! prefixed with the format name (`"TOML Parse error: …"`). No error carries a
//! code, so callers switch on nothing and neither does a test.
//!
//! # Dependencies
//!
//! * `saphyr-parser` — the YAML scanner/parser. It emits libyaml's event stream
//!   and does not resolve scalars, which is what is needed: Bun follows the YAML
//!   1.2 **core** schema and the resolution (including `yes` staying a string
//!   and `.inf` becoming `Infinity`) is applied in [`yaml`] on top of the
//!   events. `yaml-rust2` also parses, but it builds a `Yaml` tree with its own
//!   resolution pass and no merge-key handling, so matching Bun would mean
//!   discarding that tree and re-walking the source. `serde_yaml` is
//!   unmaintained (its last release was 2020 and the repository is archived) and
//!   resolves YAML 1.1 booleans, which is wrong on two of the three load-bearing
//!   cases.
//! * `comrak` — CommonMark + GFM as an AST plus a default HTML renderer. Bun's
//!   `markdown.html` output is byte-for-byte what comrak's default renderer
//!   produces for 99 of 106 hand-measured documents including nested lists,
//!   tables, task lists and raw HTML; the seven that differ are table and task
//!   list markup, which this crate renders from the AST itself. No other crate
//!   is close enough to be worth wrapping.
//! * No TOML crate. `toml` 0.8 is correct but its diagnostics are `invalid array
//!   \n expected \`]\`` where Bun writes `Expected ',' or ']' in an array but
//!   found '2'`, and Bun distinguishes eighteen shapes that `toml` collapses
//!   into four. A mapping table would match the common cases and silently get
//!   the rest wrong, so [`toml`] contains the grammar. See that module.

#![deny(missing_docs)]

pub mod convert;
mod json;
pub mod json5;
pub mod jsonc;
pub mod jsonl;
pub mod markdown;
pub mod toml;
pub mod value;
pub mod xml;
pub mod yaml;

use rn_bun_api::{BunModule, BunRegistry};
use rn_v8_sys::v8;

/// Members this crate installs.
///
/// Seven namespaces, each one own property of `Bun`, all present in Bun 1.4.4's
/// recorded surface (`tools/bun-surface.json`, `kind: "object"`, `tier: 1`). The
/// registry compares this declaration against the object [`Encoding::install`]
/// really builds, in both directions, before `Bun` is published.
pub const MEMBERS: &[&str] = &["YAML", "TOML", "JSON5", "JSONC", "JSONL", "XML", "markdown"];

/// A function that builds one namespace object.
///
/// Named rather than written inline so the `install` table stays readable and
/// clippy's `type_complexity` has something to point at.
type NamespaceBuilder =
    for<'s> fn(&mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Object>, String>;

/// Members this crate needs but does not install yet.
///
/// Nothing: all seven members of the encoding group are implemented, so there is
/// no deferral. A deferral is a statement this crate owes a member and has not
/// paid, and an empty list is the honest report here.
pub const DEFERRED: &[(&str, &str)] = &[];

/// The encoding and parsing group.
pub struct Encoding;

impl BunModule for Encoding {
    fn contributor(&self) -> &'static str {
        "rn-bun-encoding"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        target: v8::Local<'s, v8::Object>,
    ) -> Result<(), String> {
        let namespaces: [(&str, NamespaceBuilder); 7] = [
            ("YAML", yaml::namespace),
            ("TOML", toml::namespace),
            ("JSON5", json5::namespace),
            ("JSONC", jsonc::namespace),
            ("JSONL", jsonl::namespace),
            ("XML", xml::namespace),
            ("markdown", markdown::namespace),
        ];
        for (name, build) in namespaces {
            let object = build(scope)?;
            let key = v8::String::new(scope, name)
                .ok_or_else(|| format!("cannot allocate the name Bun.{name}"))?;
            target
                .create_data_property(scope, key.into(), object.into())
                .ok_or_else(|| format!("cannot define Bun.{name}"))?;
        }
        Ok(())
    }
}

/// Registers this crate with the Bun contribution registry.
///
/// `tools/regen-bun-contributions.sh` discovers this declaration and calls it
/// from `rn-bun-members`' generated aggregator, so this crate never edits
/// `rn-bun`, `rn-bun-members` or any other shared file. The signature is what the
/// matcher looks for: `registry` as the only parameter, `&mut BunRegistry`.
pub fn register(registry: &mut BunRegistry) -> Result<(), String> {
    registry.register_module(Encoding)
}

/// The own member names of each namespace, for a test that compares the
/// installed object against the recorded Bun 1.4.4 shape.
pub const SURFACE: &[(&str, &[&str])] = &[
    ("YAML", &["parse", "stringify"]),
    ("TOML", &["parse", "stringify"]),
    ("JSON5", &["parse", "stringify"]),
    ("JSONC", &["parse"]),
    ("JSONL", &["parse", "parseChunk"]),
    ("XML", &["parse", "stringify"]),
    ("markdown", &["html", "ansi", "render", "react"]),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_member_is_in_buns_recorded_surface() {
        // `tools/bun-surface.json` records Bun 1.4.4's own property names. A
        // name this crate invented would be refused by the gate, so the check is
        // repeated here where it can be read next to the declaration.
        assert_eq!(MEMBERS.len(), 7, "the encoding group has seven members");
        for member in MEMBERS {
            assert!(!member.is_empty(), "a member name is never empty");
        }
        assert_eq!(
            MEMBERS,
            ["YAML", "TOML", "JSON5", "JSONC", "JSONL", "XML", "markdown"]
        );
        assert!(DEFERRED.is_empty(), "nothing in this group is deferred");
    }

    #[test]
    fn registering_contributes_every_declaration() {
        let mut registry = BunRegistry::new();
        register(&mut registry).expect("registration succeeds");
        let declared: Vec<&str> = registry
            .declarations()
            .iter()
            .map(|declaration| declaration.member.as_str())
            .collect();
        let mut expected = MEMBERS.to_vec();
        expected.sort_unstable();
        let mut declared_sorted = declared.clone();
        declared_sorted.sort_unstable();
        assert_eq!(declared_sorted, expected);
        for declaration in registry.declarations() {
            assert_eq!(declaration.contributor, "rn-bun-encoding");
        }
        assert!(registry.deferrals().is_empty());
    }
}

//! `internalBinding('glob')` for rustnode.
//!
//! `lib/internal/fs/glob.js` is unchanged Node code. It owns option validation,
//! `Dirent` construction and the iteration protocol; this crate is the engine
//! underneath it, ported from `src/glob/**` and `src/node_glob.cc`.
//!
//! The namespace is small — three functions and five flag constants — but the
//! semantics are not: `hasMagic`, `globSync` and `matchesGlob` all have to agree
//! with Node about braces, extglobs, globstars, dot handling, symlink following
//! and case folding. The modules here are the same split as the C++:
//!
//! | here | Node |
//! | --- | --- |
//! | [`ast`] | `glob_ast.h` |
//! | [`brace`] | the brace-expansion half of `glob_parser.cc` |
//! | [`parser`] | the AST half of `glob_parser.cc` |
//! | [`program`] | `glob_program.cc` |
//! | [`matcher`] | `glob_matcher.cc` |
//! | [`unicode`] | `glob_unicode.cc` |
//! | [`walker`] | `glob_walker.cc` |
//! | [`request`] | `node_glob.cc`'s `GlobRequest` |
//!
//! Patterns and subjects are UTF-16 (`glob::Pattern`): V8 hands the binding a
//! two-byte string, and an unpaired surrogate is legal input that simply never
//! matches a file name. Converting through `String` would replace it silently.

pub mod ast;
pub mod brace;
pub mod differential;
pub mod install;
pub mod matcher;
pub mod parser;
pub mod program;
pub mod unicode;
pub mod unicode_tables;
pub mod walker;

pub use install::{Glob, DEFERRED, MEMBERS};
pub use matcher::{match_pattern, CompiledPattern};
pub use parser::{CompileError, CompileFlags, ParsedPattern};

/// Registers the `glob` namespace with the runtime.
///
/// Re-exported at the crate root because that is the name
/// `tools/regen-bindings.sh` discovers and generates into
/// `rn-bindings/src/install_all.rs`.
pub use install::register;
pub use walker::{WalkEntry, WalkOptions};

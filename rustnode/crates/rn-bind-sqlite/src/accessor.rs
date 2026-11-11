//! The concrete accessor-getter type the class builders need.
//!
//! `FunctionTemplate::builder` is generic over `MapFnTo<AccessorNameGetterCallback>`,
//! and a bare Rust `fn` item does not satisfy that bound: the generated callback
//! takes a `ReturnValue` carrying a lifetime that a function pointer cannot
//! name. So every accessor here is a distinct zero-sized type implementing this
//! trait, which is exactly what `MapFnTo`'s blanket impl accepts.
//!
//! The reason this is a module rather than a type alias: an alias would erase the
//! distinction between the three `Database` accessors, and the builder would then
//! have one type for three different bodies.

use rn_v8_sys::v8;

/// One accessor getter body.
pub trait Getter: v8::MapFnTo<v8::AccessorNameGetterCallback> {}

impl<T: v8::MapFnTo<v8::AccessorNameGetterCallback>> Getter for T {}

//! The value model shared by both namespaces.
//!
//! `config` and `constants` publish only numbers, strings and booleans, so a
//! tiny enum keeps the tables readable and lets tests assert on the same data
//! the installer publishes.

/// One property value installed into a namespace object.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    /// A JavaScript `number`.
    ///
    /// Node's `NODE_DEFINE_CONSTANT` always goes through `v8::Number`, so every
    /// numeric constant is a double even when the C macro is integral.
    Num(f64),
    /// A JavaScript `boolean`.
    Bool(bool),
    /// A JavaScript `string`.
    Str(&'static str),
}

impl Value {
    /// Convenience constructor for integer-shaped constants.
    ///
    /// `const` so the value tables can be `const` items.
    #[must_use]
    pub const fn int(value: i64) -> Self {
        Self::Num(value as f64)
    }
}

/// A single `(name, value)` pair of a namespace object.
pub type Member = (&'static str, Value);

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::int(value)
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::Num(f64::from(value))
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<&'static str> for Value {
    fn from(value: &'static str) -> Self {
        Self::Str(value)
    }
}

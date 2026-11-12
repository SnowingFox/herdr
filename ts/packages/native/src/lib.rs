//! napi-rs native layer for the TypeScript port of herdr.
//!
//! Plain-Rust cores (`terminal_core`, `pty`, `events`, `platform`) hold the behavior and are unit
//! tested without Node. The napi modules (`terminal`, `session`, `process`) are thin bindings.
//! OS-specific code stays under `platform/`.

#![deny(clippy::all)]
// napi-derive registers bindings only outside `cargo test`, so they look unused there.
#![cfg_attr(test, allow(dead_code))]

pub mod error;
pub mod events;
pub mod platform;
pub mod pty;
pub mod terminal_core;

mod process;
mod pty_binding;
mod session;
mod terminal;
mod unicode;

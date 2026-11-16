//! Error helpers. Native errors carry a stable `CODE: message` prefix that the TS wrapper parses
//! into a typed error.

use napi::{Error, Status};

pub const PTY_SPAWN: &str = "EPTY_SPAWN";
pub const PTY_IO: &str = "EPTY_IO";
pub const TERMINAL: &str = "ETERMINAL";
pub const TERMINAL_LOCK: &str = "ETERM_LOCK";
pub const INVALID_ARGUMENT: &str = "EINVAL";
pub const CLOSED: &str = "ECLOSED";

pub fn coded(code: &str, message: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, format!("{code}: {message}"))
}

pub fn terminal_error(err: ghostty_vt::Error) -> Error {
    coded(TERMINAL, err)
}

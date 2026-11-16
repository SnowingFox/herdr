//! Platform-specific process inspection. OS code lives in the matching submodule; this file only
//! holds shared types and re-exports. Core modules must not use `#[cfg(target_os)]`.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix_common;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(unix)]
pub use unix_common::*;
#[cfg(windows)]
pub use windows::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundProcess {
    pub pid: u32,
    pub name: String,
    pub argv: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundJob {
    pub process_group_id: u32,
    pub processes: Vec<ForegroundProcess>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Hangup,
    Terminate,
    Kill,
}

impl Signal {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "hangup" => Some(Self::Hangup),
            "terminate" => Some(Self::Terminate),
            "kill" => Some(Self::Kill),
            _ => None,
        }
    }
}

//! Windows process inspection is not ported yet (ToolHelp/NT queries land in the platform
//! milestone). Callers treat `None` as "unknown".

use std::path::PathBuf;

use super::{ForegroundJob, Signal};

pub fn foreground_process_group_id(_child_pid: u32) -> Option<u32> {
    None
}

pub fn foreground_job(_child_pid: u32) -> Option<ForegroundJob> {
    None
}

pub fn process_cwd(_pid: u32) -> Option<PathBuf> {
    None
}

pub fn session_processes(_child_pid: u32) -> Vec<u32> {
    Vec::new()
}

pub fn signal_processes(_pids: &[u32], _signal: Signal) {}

pub fn signal_process_group(_process_group_id: u32, _signal: Signal) -> bool {
    false
}

pub fn process_exists(_pid: u32) -> bool {
    false
}

//! macOS process inspection is not ported yet (libproc-based foreground job/cwd lands in the
//! platform milestone). Callers treat `None` as "unknown".

use std::path::PathBuf;

use super::ForegroundJob;

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

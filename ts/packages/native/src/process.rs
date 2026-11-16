use napi::Result;
use napi_derive::napi;

use crate::error::{coded, INVALID_ARGUMENT};
use crate::platform::{self, Signal};

#[napi(object)]
pub struct ForegroundProcessInfo {
    pub pid: u32,
    pub name: String,
    pub argv: Option<Vec<String>>,
}

#[napi(object)]
pub struct ForegroundJobInfo {
    pub process_group_id: u32,
    pub processes: Vec<ForegroundProcessInfo>,
}

/// Foreground job of the terminal attached to `childPid`, or null when unknown.
#[napi]
pub fn foreground_job(child_pid: u32) -> Option<ForegroundJobInfo> {
    let job = platform::foreground_job(child_pid)?;
    Some(ForegroundJobInfo {
        process_group_id: job.process_group_id,
        processes: job
            .processes
            .into_iter()
            .map(|process| ForegroundProcessInfo {
                pid: process.pid,
                name: process.name,
                argv: process.argv,
            })
            .collect(),
    })
}

#[napi]
pub fn foreground_process_group_id(child_pid: u32) -> Option<u32> {
    platform::foreground_process_group_id(child_pid)
}

#[napi]
pub fn process_cwd(pid: u32) -> Option<String> {
    platform::process_cwd(pid).map(|path| path.to_string_lossy().into_owned())
}

#[napi]
pub fn session_processes(child_pid: u32) -> Vec<u32> {
    platform::session_processes(child_pid)
}

#[napi]
pub fn signal_processes(pids: Vec<u32>, signal: String) -> Result<()> {
    let signal = Signal::parse(&signal)
        .ok_or_else(|| coded(INVALID_ARGUMENT, format!("unknown signal {signal:?}")))?;
    platform::signal_processes(&pids, signal);
    Ok(())
}

#[napi]
pub fn process_exists(pid: u32) -> bool {
    platform::process_exists(pid)
}

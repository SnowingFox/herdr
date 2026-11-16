use super::Signal;

fn raw_signal(signal: Signal) -> libc::c_int {
    match signal {
        Signal::Hangup => libc::SIGHUP,
        Signal::Terminate => libc::SIGTERM,
        Signal::Kill => libc::SIGKILL,
    }
}

pub fn signal_processes(pids: &[u32], signal: Signal) {
    let sig = raw_signal(signal);
    for &pid in pids {
        if pid == 0 {
            continue;
        }
        // SAFETY: kill(2) takes plain integers and has no memory-safety preconditions.
        unsafe {
            libc::kill(pid as i32, sig);
        }
    }
}

/// Signal a whole process group. The pane child is a session leader, so its pid is its group id.
pub fn signal_process_group(process_group_id: u32, signal: Signal) -> bool {
    if process_group_id == 0 {
        return false;
    }
    // SAFETY: killpg/kill take plain integers and have no memory-safety preconditions.
    unsafe { libc::kill(-(process_group_id as i32), raw_signal(signal)) == 0 }
}

pub fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 only performs the existence/permission check.
    let result = unsafe { libc::kill(pid as i32, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

use std::path::PathBuf;

use super::{ForegroundJob, ForegroundProcess};

/// Upper bound on /proc entries inspected per foreground-job probe.
const PROC_SCAN_LIMIT: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
struct StatFields {
    comm: String,
    state: char,
    pgrp: i32,
    session: i32,
    tpgid: i32,
}

fn parse_stat(stat: &str) -> Option<StatFields> {
    // The comm field may contain spaces and parentheses, so anchor on the last ')'.
    let close = stat.rfind(')')?;
    let comm = stat.get(1 + stat.find('(')?..close)?.to_string();
    let rest = stat.get(close + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    Some(StatFields {
        comm,
        state: fields.first()?.chars().next()?,
        pgrp: fields.get(2)?.parse().ok()?,
        session: fields.get(3)?.parse().ok()?,
        tpgid: fields.get(5)?.parse().ok()?,
    })
}

fn read_stat(pid: u32) -> Option<StatFields> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn parse_cmdline(bytes: &[u8]) -> Option<Vec<String>> {
    let parts: Vec<String> = bytes
        .split(|&byte| byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    (!parts.is_empty()).then_some(parts)
}

fn state_allows_cmdline_read(state: char) -> bool {
    // Reading cmdline of a zombie or uninterruptible process can block or return nothing.
    !matches!(state, 'D' | 'Z' | 'X' | 'x')
}

fn numeric_entries() -> impl Iterator<Item = u32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .take(PROC_SCAN_LIMIT)
}

/// Terminal foreground process group of the terminal `child_pid` is attached to.
pub fn foreground_process_group_id(child_pid: u32) -> Option<u32> {
    let tpgid = read_stat(child_pid)?.tpgid;
    (tpgid > 0).then_some(tpgid as u32)
}

pub fn foreground_job(child_pid: u32) -> Option<ForegroundJob> {
    let process_group_id = foreground_process_group_id(child_pid)?;
    let mut processes: Vec<ForegroundProcess> = numeric_entries()
        .filter_map(|pid| {
            let stat = read_stat(pid)?;
            if stat.pgrp <= 0 || stat.pgrp as u32 != process_group_id {
                return None;
            }
            let argv = state_allows_cmdline_read(stat.state)
                .then(|| std::fs::read(format!("/proc/{pid}/cmdline")).ok())
                .flatten()
                .and_then(|bytes| parse_cmdline(&bytes));
            Some(ForegroundProcess {
                pid,
                name: stat.comm,
                argv,
            })
        })
        .collect();
    if processes.is_empty() {
        return None;
    }
    processes.sort_unstable_by_key(|process| process.pid);
    Some(ForegroundJob {
        process_group_id,
        processes,
    })
}

pub fn process_cwd(pid: u32) -> Option<PathBuf> {
    if pid == 0 {
        return None;
    }
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

pub fn session_processes(child_pid: u32) -> Vec<u32> {
    let Some(session_id) = read_stat(child_pid).map(|stat| stat.session) else {
        return Vec::new();
    };
    numeric_entries()
        .filter(|&pid| read_stat(pid).map(|stat| stat.session) == Some(session_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing_handles_spaces_and_parens_in_comm() {
        let stat = "42 (weird (name) x) S 1 42 42 34816 4242 4194304 0 0";
        let fields = parse_stat(stat).expect("stat parses");
        assert_eq!(
            fields,
            StatFields {
                comm: "weird (name) x".into(),
                state: 'S',
                pgrp: 42,
                session: 42,
                tpgid: 4242,
            }
        );
    }

    #[test]
    fn cmdline_splits_on_nul_and_drops_empty_parts() {
        assert_eq!(
            parse_cmdline(b"sh\0-c\0echo hi\0"),
            Some(vec!["sh".into(), "-c".into(), "echo hi".into()])
        );
        assert_eq!(parse_cmdline(b""), None);
    }

    #[test]
    fn current_process_is_inspectable() {
        let pid = std::process::id();
        assert!(read_stat(pid).is_some());
        assert!(process_cwd(pid).is_some());
        assert!(session_processes(pid).contains(&pid));
    }
}

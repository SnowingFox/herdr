//! Plain-Rust PTY process: spawn, reader thread, queued writer, resize, kill, exit coordination.
//!
//! Writes go through a channel so callers (including the JS thread) never block on a full PTY.
//! The exit callback fires after the reader has drained (or after a grace period when a
//! background process keeps the PTY open), so trailing output is never reported after exit.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};

#[cfg(unix)]
use crate::platform;
use crate::platform::Signal;

const READ_BUFFER_BYTES: usize = 64 * 1024;
const READER_DRAIN_GRACE: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    /// Program followed by its arguments.
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: HashMap<String, String>,
    pub env_remove: Vec<String>,
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

pub type Writer = mpsc::Sender<Vec<u8>>;

#[derive(Default)]
struct ReaderState {
    done: bool,
}

pub struct PtyProcess {
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Writer,
    // Only the non-unix kill path uses the killer; unix signals the process group directly.
    #[cfg_attr(unix, allow(dead_code))]
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    pid: u32,
}

impl PtyProcess {
    /// Spawn `options.argv` in a new PTY. `on_chunk` runs on the reader thread for every read and
    /// receives a writer for terminal query responses. `onExit` runs once on the waiter thread.
    pub fn spawn(
        options: &SpawnOptions,
        mut on_chunk: impl FnMut(&[u8], &Writer) + Send + 'static,
        on_exit: impl FnOnce(ExitInfo) + Send + 'static,
    ) -> std::io::Result<Arc<Self>> {
        let (program, args) = options
            .argv
            .split_first()
            .ok_or_else(|| std::io::Error::other("argv must contain a program"))?;
        let mut command = CommandBuilder::new(program);
        command.args(args);
        if let Some(cwd) = &options.cwd {
            command.cwd(cwd);
        }
        for key in &options.env_remove {
            command.env_remove(key);
        }
        for (key, value) in &options.env {
            command.env(key, value);
        }

        let pair = native_pty_system()
            .openpty(PtySize {
                rows: options.rows.max(1),
                cols: options.cols.max(1),
                pixel_width: options.pixel_width,
                pixel_height: options.pixel_height,
            })
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        let mut child = pair
            .slave
            .spawn_command(command)
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        let pid = child.process_id().unwrap_or(0);
        let killer = child.clone_killer();
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        let mut pty_writer = pair
            .master
            .take_writer()
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        // The slave end must not stay open in the parent or the reader never sees EOF.
        drop(pair.slave);

        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>();
        thread::Builder::new()
            .name("herdr-pty-writer".into())
            .spawn(move || {
                while let Ok(bytes) = writer_rx.recv() {
                    if pty_writer.write_all(&bytes).is_err() || pty_writer.flush().is_err() {
                        break;
                    }
                }
            })?;

        let reader_state = Arc::new((Mutex::new(ReaderState::default()), Condvar::new()));
        let reader_signal = Arc::clone(&reader_state);
        let chunk_writer = writer_tx.clone();
        thread::Builder::new()
            .name("herdr-pty-reader".into())
            .spawn(move || {
                let mut buffer = vec![0u8; READ_BUFFER_BYTES];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => on_chunk(&buffer[..read], &chunk_writer),
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                let (lock, condvar) = &*reader_signal;
                if let Ok(mut state) = lock.lock() {
                    state.done = true;
                }
                condvar.notify_all();
            })?;

        thread::Builder::new()
            .name("herdr-pty-waiter".into())
            .spawn(move || {
                let info = match child.wait() {
                    Ok(status) => ExitInfo {
                        code: status.signal().is_none().then(|| status.exit_code() as i32),
                        signal: status.signal().map(str::to_string),
                    },
                    Err(_) => ExitInfo {
                        code: None,
                        signal: None,
                    },
                };
                let (lock, condvar) = &*reader_state;
                if let Ok(state) = lock.lock() {
                    let _ =
                        condvar.wait_timeout_while(state, READER_DRAIN_GRACE, |state| !state.done);
                }
                on_exit(info);
            })?;

        Ok(Arc::new(Self {
            master: Mutex::new(pair.master),
            writer: writer_tx,
            killer: Mutex::new(killer),
            pid,
        }))
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn writer(&self) -> Writer {
        self.writer.clone()
    }

    pub fn write(&self, bytes: Vec<u8>) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.writer
            .send(bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pty writer closed"))
    }

    pub fn resize(
        &self,
        rows: u16,
        cols: u16,
        pixel_width: u16,
        pixel_height: u16,
    ) -> std::io::Result<()> {
        let master = self
            .master
            .lock()
            .map_err(|_| std::io::Error::other("pty master lock poisoned"))?;
        master
            .resize(PtySize {
                rows: rows.max(1),
                cols: cols.max(1),
                pixel_width,
                pixel_height,
            })
            .map_err(|err| std::io::Error::other(err.to_string()))
    }

    /// Terminal foreground process group, when the platform exposes it.
    pub fn foreground_process_group(&self) -> Option<u32> {
        let master = self.master.lock().ok()?;
        #[cfg(unix)]
        {
            let pgid = master.process_group_leader()?;
            (pgid > 0).then_some(pgid as u32)
        }
        #[cfg(not(unix))]
        {
            let _ = master;
            None
        }
    }

    pub fn kill(&self, signal: Signal) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            if platform::signal_process_group(self.pid, signal) {
                return Ok(());
            }
            platform::signal_processes(&[self.pid], signal);
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = signal;
            let mut killer = self
                .killer
                .lock()
                .map_err(|_| std::io::Error::other("killer lock poisoned"))?;
            killer.kill()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    fn options(argv: &[&str]) -> SpawnOptions {
        SpawnOptions {
            argv: argv.iter().map(|part| part.to_string()).collect(),
            rows: 24,
            cols: 80,
            env: HashMap::from([("TERM".to_string(), "xterm-256color".to_string())]),
            ..SpawnOptions::default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn spawn_reads_output_and_reports_exit_after_drain() {
        let (data_tx, data_rx) = channel::<Vec<u8>>();
        let (exit_tx, exit_rx) = channel::<ExitInfo>();
        let _pty = PtyProcess::spawn(
            &options(&["sh", "-c", "printf hello; exit 3"]),
            move |chunk, _| {
                let _ = data_tx.send(chunk.to_vec());
            },
            move |info| {
                let _ = exit_tx.send(info);
            },
        )
        .expect("spawn");
        let exit = exit_rx.recv_timeout(Duration::from_secs(10)).expect("exit");
        assert_eq!(exit.code, Some(3));
        let mut output = Vec::new();
        while let Ok(chunk) = data_rx.try_recv() {
            output.extend(chunk);
        }
        assert!(String::from_utf8_lossy(&output).contains("hello"));
    }

    #[cfg(unix)]
    #[test]
    fn write_reaches_child_and_resize_is_visible_to_it() {
        let (data_tx, data_rx) = channel::<Vec<u8>>();
        let (exit_tx, exit_rx) = channel::<ExitInfo>();
        let pty = PtyProcess::spawn(
            &options(&["sh", "-c", "read line; echo got:$line; stty size"]),
            move |chunk, _| {
                let _ = data_tx.send(chunk.to_vec());
            },
            move |info| {
                let _ = exit_tx.send(info);
            },
        )
        .expect("spawn");
        pty.resize(30, 100, 0, 0).expect("resize");
        pty.write(b"ping\n".to_vec()).expect("write");
        exit_rx.recv_timeout(Duration::from_secs(10)).expect("exit");
        let mut output = Vec::new();
        while let Ok(chunk) = data_rx.try_recv() {
            output.extend(chunk);
        }
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("got:ping"), "{text:?}");
        assert!(text.contains("30 100"), "{text:?}");
    }

    #[cfg(unix)]
    #[test]
    fn kill_terminates_the_child() {
        let (exit_tx, exit_rx) = channel::<ExitInfo>();
        let pty = PtyProcess::spawn(
            &options(&["sh", "-c", "sleep 30"]),
            |_, _| {},
            move |info| {
                let _ = exit_tx.send(info);
            },
        )
        .expect("spawn");
        pty.kill(Signal::Kill).expect("kill");
        let exit = exit_rx.recv_timeout(Duration::from_secs(10)).expect("exit");
        assert!(exit.signal.is_some() || exit.code != Some(0));
    }

    #[test]
    fn spawn_rejects_empty_argv() {
        let result = PtyProcess::spawn(&SpawnOptions::default(), |_, _| {}, |_| {});
        assert!(result.is_err());
    }
}

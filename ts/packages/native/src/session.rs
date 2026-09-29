use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::{Buffer, Function};
use napi::threadsafe_function::ThreadsafeFunctionCallMode;
use napi::{Result, Status};
use napi_derive::napi;

use crate::error::{coded, terminal_error, PTY_IO, PTY_SPAWN};
use crate::events::{Coalesce, EventQueue};
use crate::pty::{ExitInfo, PtyProcess};
use crate::pty_binding::{parse_signal, spawn_options, Callback, PtySpawnOptions};
use crate::terminal::{lock_core, SharedCore, Terminal};
use crate::terminal_core::TerminalCore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Output,
    Bell(u32),
    Pwd(String),
    Clipboard(Vec<u8>),
    Exit(ExitInfo),
}

impl Coalesce for SessionEvent {
    fn supersedes(&self, previous: &Self) -> bool {
        matches!(
            (self, previous),
            (SessionEvent::Output, SessionEvent::Output)
        )
    }
}

#[napi(object)]
pub struct SessionOptions {
    pub pty: PtySpawnOptions,
    pub max_scrollback_bytes: Option<u32>,
}

#[napi(object)]
pub struct SessionEventData {
    /// `output`, `bell`, `pwd`, `clipboard` or `exit`.
    pub kind: String,
    pub count: Option<u32>,
    pub text: Option<String>,
    pub data: Option<Buffer>,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<String>,
}

impl SessionEventData {
    fn bare(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            count: None,
            text: None,
            data: None,
            exit_code: None,
            exit_signal: None,
        }
    }
}

impl From<SessionEvent> for SessionEventData {
    fn from(event: SessionEvent) -> Self {
        match event {
            SessionEvent::Output => Self::bare("output"),
            SessionEvent::Bell(count) => Self {
                count: Some(count),
                ..Self::bare("bell")
            },
            SessionEvent::Pwd(text) => Self {
                text: Some(text),
                ..Self::bare("pwd")
            },
            SessionEvent::Clipboard(data) => Self {
                data: Some(Buffer::from(data)),
                ..Self::bare("clipboard")
            },
            SessionEvent::Exit(info) => Self {
                exit_code: info.code,
                exit_signal: info.signal,
                ..Self::bare("exit")
            },
        }
    }
}

/// A pane runtime: PTY reader thread feeds the terminal emulator and answers terminal queries
/// natively. JS is woken at most once per drain, never per byte.
#[napi]
pub struct TerminalSession {
    process: Arc<PtyProcess>,
    core: SharedCore,
    queue: Arc<EventQueue<SessionEvent>>,
}

#[napi]
impl TerminalSession {
    /// `onWake` takes no arguments; call `takeEvents()` from it.
    #[napi(factory)]
    pub fn spawn(options: SessionOptions, on_wake: Function<'_, (), ()>) -> Result<Self> {
        let pty_options = spawn_options(options.pty)?;
        let core = TerminalCore::new(
            pty_options.cols,
            pty_options.rows,
            options.max_scrollback_bytes.unwrap_or(10 * 1024 * 1024) as usize,
        )
        .map_err(terminal_error)?;
        let core: SharedCore = Arc::new(Mutex::new(core));
        let queue: Arc<EventQueue<SessionEvent>> = Arc::new(EventQueue::new());
        let wake: Arc<Callback<()>> = Arc::new(
            on_wake
                .build_threadsafe_function()
                .callee_handled::<false>()
                .weak::<true>()
                .build()?,
        );

        let chunk_core = Arc::clone(&core);
        let chunk_queue = Arc::clone(&queue);
        let chunk_wake = Arc::clone(&wake);
        let exit_queue = Arc::clone(&queue);
        let exit_wake = Arc::clone(&wake);
        let process = PtyProcess::spawn(
            &pty_options,
            move |chunk, writer| {
                let (responses, events) = {
                    let Ok(mut core) = chunk_core.lock() else {
                        return;
                    };
                    core.write(chunk);
                    (core.drain_responses(), core.take_events())
                };
                for response in responses {
                    let _ = writer.send(response);
                }
                let mut needs_wake = chunk_queue.push(SessionEvent::Output);
                if events.bells > 0 {
                    needs_wake |= chunk_queue.push(SessionEvent::Bell(u32::from(events.bells)));
                }
                for pwd in events.pwd_changes {
                    needs_wake |= chunk_queue.push(SessionEvent::Pwd(
                        String::from_utf8_lossy(&pwd).into_owned(),
                    ));
                }
                for data in events.clipboard_writes {
                    needs_wake |= chunk_queue.push(SessionEvent::Clipboard(data));
                }
                if needs_wake {
                    chunk_wake.call((), ThreadsafeFunctionCallMode::Blocking);
                }
            },
            move |info| {
                if exit_queue.push(SessionEvent::Exit(info)) {
                    exit_wake.call((), ThreadsafeFunctionCallMode::Blocking);
                }
            },
        )
        .map_err(|err| coded(PTY_SPAWN, err))?;

        Ok(Self {
            process,
            core,
            queue,
        })
    }

    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.process.pid()
    }

    /// Shared handle to this session's terminal emulator.
    #[napi]
    pub fn terminal(&self) -> Terminal {
        Terminal::from_core(Arc::clone(&self.core))
    }

    /// Drain pending events. Re-arms the wake callback.
    #[napi]
    pub fn take_events(&self) -> Vec<SessionEventData> {
        self.queue.take().into_iter().map(Into::into).collect()
    }

    /// Send user input to the child.
    #[napi]
    pub fn write(&self, bytes: Buffer) -> Result<()> {
        self.process
            .write(bytes.to_vec())
            .map_err(|err| coded(PTY_IO, err))
    }

    /// Resize the PTY and the emulator together.
    #[napi]
    pub fn resize(
        &self,
        rows: u32,
        cols: u32,
        cell_width_px: Option<u32>,
        cell_height_px: Option<u32>,
    ) -> Result<()> {
        let rows16 = u16::try_from(rows).map_err(|_| coded("EINVAL", "rows out of range"))?;
        let cols16 = u16::try_from(cols).map_err(|_| coded("EINVAL", "cols out of range"))?;
        let cell_width = cell_width_px.unwrap_or(0);
        let cell_height = cell_height_px.unwrap_or(0);
        lock_core(&self.core)?
            .resize(cols16, rows16, cell_width, cell_height)
            .map_err(terminal_error)?;
        self.process
            .resize(
                rows16,
                cols16,
                u16::try_from(u32::from(cols16) * cell_width).unwrap_or(u16::MAX),
                u16::try_from(u32::from(rows16) * cell_height).unwrap_or(u16::MAX),
            )
            .map_err(|err| coded(PTY_IO, err))
    }

    #[napi]
    pub fn foreground_process_group(&self) -> Option<u32> {
        self.process.foreground_process_group()
    }

    /// `hangup` (default), `terminate` or `kill`.
    #[napi]
    pub fn kill(&self, signal: Option<String>) -> Result<()> {
        self.process
            .kill(parse_signal(signal.as_deref())?)
            .map_err(|err| coded(PTY_IO, err))
    }
}

#[allow(dead_code)]
fn _status_marker(_: Status) {}

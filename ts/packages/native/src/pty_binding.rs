use std::sync::Arc;

use napi::bindgen_prelude::{Buffer, Function};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Result, Status};
use napi_derive::napi;

use crate::error::{coded, INVALID_ARGUMENT, PTY_IO, PTY_SPAWN};
use crate::platform::Signal;
use crate::pty::{ExitInfo, PtyProcess, SpawnOptions};

pub(crate) type Callback<T> = ThreadsafeFunction<T, (), T, Status, false, true>;

#[napi(object)]
pub struct PtySpawnOptions {
    /// Program followed by its arguments.
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// Variables to set in the child (added to the inherited environment).
    pub env: Option<std::collections::HashMap<String, String>>,
    /// Inherited variables to remove before applying `env`.
    pub env_remove: Option<Vec<String>>,
    pub rows: u32,
    pub cols: u32,
    pub pixel_width: Option<u32>,
    pub pixel_height: Option<u32>,
}

#[napi(object)]
#[derive(Clone)]
pub struct PtyExit {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

impl From<ExitInfo> for PtyExit {
    fn from(info: ExitInfo) -> Self {
        Self {
            code: info.code,
            signal: info.signal,
        }
    }
}

fn to_u16(value: u32, name: &str) -> Result<u16> {
    u16::try_from(value).map_err(|_| coded(INVALID_ARGUMENT, format!("{name} out of range")))
}

pub(crate) fn spawn_options(options: PtySpawnOptions) -> Result<SpawnOptions> {
    if options.argv.is_empty() {
        return Err(coded(INVALID_ARGUMENT, "argv must contain a program"));
    }
    Ok(SpawnOptions {
        argv: options.argv,
        cwd: options.cwd,
        env: options.env.unwrap_or_default(),
        env_remove: options.env_remove.unwrap_or_default(),
        rows: to_u16(options.rows, "rows")?,
        cols: to_u16(options.cols, "cols")?,
        pixel_width: to_u16(options.pixel_width.unwrap_or(0), "pixelWidth")?,
        pixel_height: to_u16(options.pixel_height.unwrap_or(0), "pixelHeight")?,
    })
}

pub(crate) fn parse_signal(name: Option<&str>) -> Result<Signal> {
    match name {
        None => Ok(Signal::Hangup),
        Some(name) => Signal::parse(name)
            .ok_or_else(|| coded(INVALID_ARGUMENT, format!("unknown signal {name:?}"))),
    }
}

/// Raw PTY: bytes in, bytes out. Terminal parsing lives in `TerminalSession` or `Terminal`.
#[napi]
pub struct Pty {
    process: Arc<PtyProcess>,
}

#[napi]
impl Pty {
    /// Spawn a program in a new PTY. `onData` receives every chunk read; `onExit` fires once
    /// after the reader drained.
    #[napi(factory)]
    pub fn spawn(
        options: PtySpawnOptions,
        on_data: Function<'_, Buffer, ()>,
        on_exit: Function<'_, PtyExit, ()>,
    ) -> Result<Self> {
        let options = spawn_options(options)?;
        let data_callback: Callback<Buffer> = on_data
            .build_threadsafe_function()
            .callee_handled::<false>()
            .weak::<true>()
            .build()?;
        let exit_callback: Callback<PtyExit> = on_exit
            .build_threadsafe_function()
            .callee_handled::<false>()
            .weak::<true>()
            .build()?;
        let process = PtyProcess::spawn(
            &options,
            move |chunk, _| {
                data_callback.call(
                    Buffer::from(chunk.to_vec()),
                    ThreadsafeFunctionCallMode::Blocking,
                );
            },
            move |info| {
                exit_callback.call(info.into(), ThreadsafeFunctionCallMode::Blocking);
            },
        )
        .map_err(|err| coded(PTY_SPAWN, err))?;
        Ok(Self { process })
    }

    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.process.pid()
    }

    /// Queue bytes for the child. Never blocks the JS thread.
    #[napi]
    pub fn write(&self, bytes: Buffer) -> Result<()> {
        self.process
            .write(bytes.to_vec())
            .map_err(|err| coded(PTY_IO, err))
    }

    #[napi]
    pub fn resize(
        &self,
        rows: u32,
        cols: u32,
        pixel_width: Option<u32>,
        pixel_height: Option<u32>,
    ) -> Result<()> {
        self.process
            .resize(
                to_u16(rows, "rows")?,
                to_u16(cols, "cols")?,
                to_u16(pixel_width.unwrap_or(0), "pixelWidth")?,
                to_u16(pixel_height.unwrap_or(0), "pixelHeight")?,
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

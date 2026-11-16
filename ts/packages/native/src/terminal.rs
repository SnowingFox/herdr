use std::sync::{Arc, Mutex, MutexGuard};

use napi::bindgen_prelude::{Buffer, Uint32Array};
use napi::Result;
use napi_derive::napi;

use crate::error::{coded, terminal_error, INVALID_ARGUMENT, TERMINAL_LOCK};
use crate::terminal_core::{ReadSource, TerminalCore, TextRange};

pub type SharedCore = Arc<Mutex<TerminalCore>>;

pub(crate) fn lock_core(core: &SharedCore) -> Result<MutexGuard<'_, TerminalCore>> {
    core.lock()
        .map_err(|_| coded(TERMINAL_LOCK, "terminal lock poisoned"))
}

#[napi(object)]
pub struct TerminalOptions {
    pub cols: u32,
    pub rows: u32,
    pub max_scrollback_bytes: Option<u32>,
}

#[napi(object)]
pub struct TerminalSize {
    pub cols: u32,
    pub rows: u32,
    pub width_px: u32,
    pub height_px: u32,
}

#[napi(object)]
pub struct CursorInfo {
    pub x: u32,
    pub y: u32,
    pub visible: bool,
    pub blinking: bool,
    /// `block`, `underline`, `bar` or `block-hollow`.
    pub style: String,
    /// False when the cursor is scrolled out of the viewport.
    pub in_viewport: bool,
}

#[napi(object)]
pub struct ModeInfo {
    pub alternate_screen: bool,
    pub bracketed_paste: bool,
    pub mouse_tracking: bool,
    pub mouse_sgr: bool,
    pub mouse_sgr_pixels: bool,
    pub focus_event: bool,
    pub application_cursor_keys: bool,
    pub synchronized_output: bool,
    pub kitty_keyboard_flags: u32,
    pub modify_other_keys: bool,
}

#[napi(object)]
pub struct ScrollbarInfo {
    pub total: u32,
    pub offset: u32,
    pub len: u32,
}

#[napi(object)]
pub struct ReadRange {
    pub start_x: u32,
    pub start_y: u32,
    pub end_x: u32,
    pub end_y: u32,
    pub rectangle: Option<bool>,
}

#[napi(object)]
pub struct ReadOptions {
    /// `viewport` (default) or `screen` (includes scrollback).
    pub source: Option<String>,
    /// Defaults to the whole source.
    pub range: Option<ReadRange>,
    /// Join soft-wrapped rows (ANSI screen reads only).
    pub unwrap: Option<bool>,
}

#[napi(object)]
pub struct TerminalEvents {
    pub bells: u32,
    pub pwd_changes: Vec<String>,
    pub clipboard_writes: Vec<Buffer>,
}

#[napi(object)]
pub struct RowSnapshotData {
    pub cols: u32,
    pub start_row: u32,
    pub row_count: u32,
    /// Four words per cell: text, fg, bg, attrs (see `terminal_core::attrs`).
    pub cells: Uint32Array,
    pub text_table: Vec<String>,
    pub dirty_rows: Vec<u32>,
}

pub(crate) fn read_source(options: Option<&ReadOptions>) -> Result<ReadSource> {
    match options.and_then(|options| options.source.as_deref()) {
        None | Some("viewport") => Ok(ReadSource::Viewport),
        Some("screen") => Ok(ReadSource::Screen),
        Some(other) => Err(coded(
            INVALID_ARGUMENT,
            format!("unknown read source {other:?}"),
        )),
    }
}

fn to_u16(value: u32, name: &str) -> Result<u16> {
    u16::try_from(value).map_err(|_| coded(INVALID_ARGUMENT, format!("{name} out of range")))
}

/// Standalone terminal emulator (no PTY). Used for hidden panes, history reads, and tests.
#[napi]
pub struct Terminal {
    pub(crate) core: SharedCore,
}

impl Terminal {
    pub(crate) fn from_core(core: SharedCore) -> Self {
        Self { core }
    }
}

#[napi]
impl Terminal {
    #[napi(constructor)]
    pub fn new(options: TerminalOptions) -> Result<Self> {
        let core = TerminalCore::new(
            to_u16(options.cols, "cols")?,
            to_u16(options.rows, "rows")?,
            options.max_scrollback_bytes.unwrap_or(10 * 1024 * 1024) as usize,
        )
        .map_err(terminal_error)?;
        Ok(Self::from_core(Arc::new(Mutex::new(core))))
    }

    /// Feed bytes as if they came from a program. Query responses are available from
    /// `drainResponses`.
    #[napi]
    pub fn write(&self, bytes: Buffer) -> Result<()> {
        lock_core(&self.core)?.write(&bytes);
        Ok(())
    }

    /// Bytes the terminal wants written back to the program (DA, DSR, XTGETTCAP, ...).
    #[napi]
    pub fn drain_responses(&self) -> Result<Vec<Buffer>> {
        Ok(lock_core(&self.core)?
            .drain_responses()
            .into_iter()
            .map(Buffer::from)
            .collect())
    }

    /// Monotonic counter bumped by every state change; cheap dirty check for the JS side.
    #[napi]
    pub fn generation(&self) -> Result<f64> {
        Ok(lock_core(&self.core)?.generation() as f64)
    }

    #[napi]
    pub fn resize(
        &self,
        cols: u32,
        rows: u32,
        cell_width_px: Option<u32>,
        cell_height_px: Option<u32>,
    ) -> Result<()> {
        lock_core(&self.core)?
            .resize(
                to_u16(cols, "cols")?,
                to_u16(rows, "rows")?,
                cell_width_px.unwrap_or(0),
                cell_height_px.unwrap_or(0),
            )
            .map_err(terminal_error)
    }

    #[napi]
    pub fn size(&self) -> Result<TerminalSize> {
        let (cols, rows, width_px, height_px) =
            lock_core(&self.core)?.size().map_err(terminal_error)?;
        Ok(TerminalSize {
            cols: u32::from(cols),
            rows: u32::from(rows),
            width_px,
            height_px,
        })
    }

    #[napi]
    pub fn cursor(&self) -> Result<CursorInfo> {
        let cursor = lock_core(&self.core)?.cursor().map_err(terminal_error)?;
        Ok(CursorInfo {
            x: u32::from(cursor.x),
            y: u32::from(cursor.y),
            visible: cursor.visible,
            blinking: cursor.blinking,
            style: cursor.style.to_string(),
            in_viewport: cursor.in_viewport,
        })
    }

    #[napi]
    pub fn modes(&self) -> Result<ModeInfo> {
        let modes = lock_core(&self.core)?.modes().map_err(terminal_error)?;
        Ok(ModeInfo {
            alternate_screen: modes.alternate_screen,
            bracketed_paste: modes.bracketed_paste,
            mouse_tracking: modes.mouse_tracking,
            mouse_sgr: modes.mouse_sgr,
            mouse_sgr_pixels: modes.mouse_sgr_pixels,
            focus_event: modes.focus_event,
            application_cursor_keys: modes.application_cursor_keys,
            synchronized_output: modes.synchronized_output,
            kitty_keyboard_flags: u32::from(modes.kitty_keyboard_flags),
            modify_other_keys: modes.modify_other_keys,
        })
    }

    #[napi]
    pub fn scrollbar(&self) -> Result<ScrollbarInfo> {
        let bar = lock_core(&self.core)?.scrollbar().map_err(terminal_error)?;
        Ok(ScrollbarInfo {
            total: bar.total as u32,
            offset: bar.offset as u32,
            len: bar.len as u32,
        })
    }

    #[napi]
    pub fn scroll_viewport(&self, delta: i32) -> Result<()> {
        lock_core(&self.core)?.scroll_viewport_delta(delta as isize);
        Ok(())
    }

    #[napi]
    pub fn scroll_to_bottom(&self) -> Result<()> {
        lock_core(&self.core)?.scroll_viewport_bottom();
        Ok(())
    }

    #[napi]
    pub fn scroll_to_row(&self, row: u32) -> Result<()> {
        lock_core(&self.core)?.scroll_viewport_row(row as usize);
        Ok(())
    }

    #[napi]
    pub fn clear(&self) -> Result<bool> {
        Ok(lock_core(&self.core)?.clear_screen())
    }

    #[napi]
    pub fn read_text(&self, options: Option<ReadOptions>) -> Result<String> {
        let source = read_source(options.as_ref())?;
        let range = read_range(options.as_ref())?;
        lock_core(&self.core)?
            .read_text(source, range)
            .map_err(terminal_error)
    }

    #[napi]
    pub fn read_ansi(&self, options: Option<ReadOptions>) -> Result<String> {
        let source = read_source(options.as_ref())?;
        let range = read_range(options.as_ref())?;
        let unwrap = options
            .as_ref()
            .and_then(|options| options.unwrap)
            .unwrap_or(false);
        lock_core(&self.core)?
            .read_ansi(source, range, unwrap)
            .map_err(terminal_error)
    }

    /// Bells, cwd changes (OSC 7) and clipboard writes (OSC 52) since the previous call.
    #[napi]
    pub fn take_events(&self) -> Result<TerminalEvents> {
        let events = lock_core(&self.core)?.take_events();
        Ok(TerminalEvents {
            bells: u32::from(events.bells),
            pwd_changes: events
                .pwd_changes
                .into_iter()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .collect(),
            clipboard_writes: events
                .clipboard_writes
                .into_iter()
                .map(Buffer::from)
                .collect(),
        })
    }

    /// Packed viewport cells for `count` rows from `start`. One call per pane per frame.
    #[napi]
    pub fn snapshot_rows(
        &self,
        start: u32,
        count: u32,
        clear_dirty: Option<bool>,
    ) -> Result<RowSnapshotData> {
        let snapshot = lock_core(&self.core)?
            .snapshot_rows(
                to_u16(start, "start")?,
                to_u16(count, "count")?,
                clear_dirty.unwrap_or(false),
            )
            .map_err(terminal_error)?;
        Ok(RowSnapshotData {
            cols: u32::from(snapshot.cols),
            start_row: u32::from(snapshot.start_row),
            row_count: u32::from(snapshot.row_count),
            cells: Uint32Array::new(snapshot.cells),
            text_table: snapshot.text_table,
            dirty_rows: snapshot.dirty_rows.into_iter().map(u32::from).collect(),
        })
    }
}

fn read_range(options: Option<&ReadOptions>) -> Result<Option<TextRange>> {
    let Some(range) = options.and_then(|options| options.range.as_ref()) else {
        return Ok(None);
    };
    Ok(Some(TextRange {
        start_x: to_u16(range.start_x, "startX")?,
        start_y: range.start_y,
        end_x: to_u16(range.end_x, "endX")?,
        end_y: range.end_y,
        rectangle: range.rectangle.unwrap_or(false),
    }))
}

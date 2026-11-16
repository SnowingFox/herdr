//! Plain-Rust terminal emulation core over `ghostty-vt`. No napi types here so it can be unit
//! tested and shared between the standalone `Terminal` binding and PTY sessions.

use std::sync::{Arc, Mutex};

use ghostty_vt::{
    ActiveScreen, CellColor, CellWide, CursorVisualStyle, Error, RenderState, RgbColor, RowCells,
    RowIterator, Terminal,
};

pub const MODE_SYNCHRONIZED_OUTPUT: u16 = ghostty_vt::MODE_SYNCHRONIZED_OUTPUT;

/// Cell attribute bits packed into the fourth word of each snapshot cell.
pub mod attrs {
    pub const BOLD: u32 = 1 << 0;
    pub const ITALIC: u32 = 1 << 1;
    pub const FAINT: u32 = 1 << 2;
    pub const BLINK: u32 = 1 << 3;
    pub const INVERSE: u32 = 1 << 4;
    pub const INVISIBLE: u32 = 1 << 5;
    pub const STRIKETHROUGH: u32 = 1 << 6;
    pub const OVERLINE: u32 = 1 << 7;
    pub const UNDERLINE_SHIFT: u32 = 8;
    pub const UNDERLINE_MASK: u32 = 0b111 << UNDERLINE_SHIFT;
    pub const WIDE_SHIFT: u32 = 12;
    pub const WIDE_MASK: u32 = 0b11 << WIDE_SHIFT;
    pub const HYPERLINK: u32 = 1 << 14;
}

/// Set on the first word of a cell when the text lives in the string table.
pub const CELL_TEXT_TABLE_FLAG: u32 = 0x8000_0000;
/// Set on color words that carry an explicit color (`0xFF000000 | 0xRRGGBB`).
pub const COLOR_SET_FLAG: u32 = 0xFF00_0000;
pub const CELL_WORDS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextRange {
    pub start_x: u16,
    pub start_y: u32,
    pub end_x: u16,
    pub end_y: u32,
    pub rectangle: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSource {
    Viewport,
    Screen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorSnapshot {
    pub x: u16,
    pub y: u16,
    pub visible: bool,
    pub blinking: bool,
    pub style: &'static str,
    pub in_viewport: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeSnapshot {
    pub alternate_screen: bool,
    pub bracketed_paste: bool,
    pub mouse_tracking: bool,
    pub mouse_sgr: bool,
    pub mouse_sgr_pixels: bool,
    pub focus_event: bool,
    pub application_cursor_keys: bool,
    pub synchronized_output: bool,
    pub kitty_keyboard_flags: u8,
    pub modify_other_keys: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrollbarSnapshot {
    pub total: usize,
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DrainedEvents {
    pub bells: u16,
    pub pwd_changes: Vec<Vec<u8>>,
    pub clipboard_writes: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct RowSnapshot {
    pub cols: u16,
    pub start_row: u16,
    pub row_count: u16,
    /// `row_count * cols * CELL_WORDS` words: text, fg, bg, attrs.
    pub cells: Vec<u32>,
    pub text_table: Vec<String>,
    pub dirty_rows: Vec<u16>,
}

pub struct TerminalCore {
    terminal: Terminal,
    render: RenderState,
    row_iterator: RowIterator,
    row_cells: RowCells,
    responses: Arc<Mutex<Vec<Vec<u8>>>>,
    generation: u64,
}

impl TerminalCore {
    pub fn new(cols: u16, rows: u16, max_scrollback_bytes: usize) -> Result<Self, Error> {
        let mut terminal = Terminal::new(cols.max(1), rows.max(1), max_scrollback_bytes)?;
        let responses = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&responses);
        terminal.set_write_pty_callback(move |bytes| {
            if let Ok(mut pending) = sink.lock() {
                pending.push(bytes.to_vec());
            }
        })?;
        Ok(Self {
            terminal,
            render: RenderState::new()?,
            row_iterator: RowIterator::new()?,
            row_cells: RowCells::new()?,
            responses,
            generation: 0,
        })
    }

    /// Feed PTY output. Terminal responses (DA, DSR, ...) accumulate for `drain_responses`.
    pub fn write(&mut self, bytes: &[u8]) {
        self.terminal.write(bytes);
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn drain_responses(&self) -> Vec<Vec<u8>> {
        match self.responses.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => Vec::new(),
        }
    }

    pub fn resize(
        &mut self,
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
    ) -> Result<(), Error> {
        self.terminal
            .resize(cols.max(1), rows.max(1), cell_width_px, cell_height_px)?;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    pub fn size(&self) -> Result<(u16, u16, u32, u32), Error> {
        Ok((
            self.terminal.cols()?,
            self.terminal.rows()?,
            self.terminal.width_px()?,
            self.terminal.height_px()?,
        ))
    }

    pub fn cursor(&mut self) -> Result<CursorSnapshot, Error> {
        self.render.update(&self.terminal)?;
        let cursor = self.render.cursor()?;
        let (x, y, in_viewport) = match cursor.viewport {
            Some(viewport) => (viewport.x, viewport.y, true),
            None => (0, 0, false),
        };
        Ok(CursorSnapshot {
            x,
            y,
            visible: cursor.visible,
            blinking: cursor.blinking,
            style: match cursor.visual_style {
                CursorVisualStyle::Block => "block",
                CursorVisualStyle::Underline => "underline",
                CursorVisualStyle::Bar => "bar",
                CursorVisualStyle::BlockHollow => "block-hollow",
            },
            in_viewport,
        })
    }

    pub fn modes(&self) -> Result<ModeSnapshot, Error> {
        Ok(ModeSnapshot {
            alternate_screen: self.terminal.active_screen()? == ActiveScreen::Alternate,
            bracketed_paste: self.terminal.mode_get(ghostty_vt::MODE_BRACKETED_PASTE)?,
            mouse_tracking: self.terminal.mouse_tracking_enabled()?,
            mouse_sgr: self.terminal.mode_get(ghostty_vt::MODE_MOUSE_SGR)?,
            mouse_sgr_pixels: self.terminal.mode_get(ghostty_vt::MODE_MOUSE_SGR_PIXELS)?,
            focus_event: self.terminal.mode_get(ghostty_vt::MODE_FOCUS_EVENT)?,
            application_cursor_keys: self
                .terminal
                .mode_get(ghostty_vt::MODE_APPLICATION_CURSOR_KEYS)?,
            synchronized_output: self.terminal.mode_get(MODE_SYNCHRONIZED_OUTPUT)?,
            kitty_keyboard_flags: self.terminal.kitty_keyboard_flags()?,
            modify_other_keys: self.terminal.modify_other_keys_enabled()?,
        })
    }

    pub fn scrollbar(&self) -> Result<ScrollbarSnapshot, Error> {
        let bar = self.terminal.scrollbar()?;
        Ok(ScrollbarSnapshot {
            total: bar.total,
            offset: bar.offset,
            len: bar.len,
        })
    }

    pub fn scroll_viewport_delta(&mut self, delta: isize) {
        self.terminal.scroll_viewport_delta(delta);
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn scroll_viewport_bottom(&mut self) {
        self.terminal.scroll_viewport_bottom();
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn scroll_viewport_row(&mut self, row: usize) {
        self.terminal.scroll_viewport_row(row);
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn clear_screen(&mut self) -> bool {
        self.generation = self.generation.wrapping_add(1);
        self.terminal.clear_screen()
    }

    pub fn total_rows(&self) -> Result<usize, Error> {
        self.terminal.total_rows()
    }

    fn resolve_range(
        &self,
        source: ReadSource,
        range: Option<TextRange>,
    ) -> Result<TextRange, Error> {
        if let Some(range) = range {
            return Ok(range);
        }
        let cols = self.terminal.cols()?;
        let rows = match source {
            ReadSource::Viewport => self.terminal.rows()? as u32,
            ReadSource::Screen => self.terminal.total_rows()? as u32,
        };
        Ok(TextRange {
            start_x: 0,
            start_y: 0,
            end_x: cols.saturating_sub(1),
            end_y: rows.saturating_sub(1),
            rectangle: false,
        })
    }

    pub fn read_text(&self, source: ReadSource, range: Option<TextRange>) -> Result<String, Error> {
        let range = self.resolve_range(source, range)?;
        let (start, end) = ((range.start_x, range.start_y), (range.end_x, range.end_y));
        match source {
            ReadSource::Viewport => self
                .terminal
                .read_text_viewport(start, end, range.rectangle),
            ReadSource::Screen => self.terminal.read_text_screen(start, end, range.rectangle),
        }
    }

    pub fn read_ansi(
        &self,
        source: ReadSource,
        range: Option<TextRange>,
        unwrap: bool,
    ) -> Result<String, Error> {
        let range = self.resolve_range(source, range)?;
        let (start, end) = ((range.start_x, range.start_y), (range.end_x, range.end_y));
        match source {
            ReadSource::Viewport => self
                .terminal
                .read_ansi_viewport(start, end, range.rectangle),
            ReadSource::Screen => {
                self.terminal
                    .read_ansi_screen(start, end, range.rectangle, unwrap)
            }
        }
    }

    pub fn take_events(&mut self) -> DrainedEvents {
        DrainedEvents {
            bells: self.terminal.take_bell_count(),
            pwd_changes: self.terminal.take_pwd_changes(),
            clipboard_writes: self.terminal.take_clipboard_writes(),
        }
    }

    /// Snapshot `count` viewport rows starting at `start` into packed words. Only non-blank cells
    /// are read from ghostty; blank cells stay zeroed so wide mostly-empty panes stay cheap.
    pub fn snapshot_rows(
        &mut self,
        start: u16,
        count: u16,
        clear_dirty: bool,
    ) -> Result<RowSnapshot, Error> {
        self.render.update(&self.terminal)?;
        let cols = self.render.cols()?;
        let total_rows = self.render.rows()?;
        let start = start.min(total_rows);
        let count = count.min(total_rows - start);
        let mut snapshot = RowSnapshot {
            cols,
            start_row: start,
            row_count: count,
            cells: vec![0; cols as usize * count as usize * CELL_WORDS],
            text_table: Vec::new(),
            dirty_rows: Vec::new(),
        };

        let mut rows = self.render.populate_row_iterator(&mut self.row_iterator)?;
        let mut y: u16 = 0;
        while rows.next() {
            let in_range = y >= start && y < start + count;
            if in_range {
                if rows.dirty()? {
                    snapshot.dirty_rows.push(y - start);
                }
                let row_offset = (y - start) as usize * cols as usize * CELL_WORDS;
                let mut cells = rows.populate_cells(&mut self.row_cells)?;
                let mut x: usize = 0;
                while cells.next() && x < cols as usize {
                    if !cells.is_default_blank()? {
                        let data = cells.basic_data()?;
                        let text = cells.grapheme_text()?;
                        let base = row_offset + x * CELL_WORDS;
                        snapshot.cells[base] = encode_text(&text, &mut snapshot.text_table);
                        snapshot.cells[base + 1] = encode_color(cells.fg_color()?);
                        snapshot.cells[base + 2] = encode_color(cells.bg_color()?);
                        snapshot.cells[base + 3] = encode_attrs(&data);
                    }
                    x += 1;
                }
            }
            if clear_dirty {
                rows.clear_dirty()?;
            }
            y += 1;
            if y >= start + count && !clear_dirty {
                break;
            }
        }
        if clear_dirty {
            self.render.clean()?;
        }
        Ok(snapshot)
    }
}

fn encode_text(text: &str, table: &mut Vec<String>) -> u32 {
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (None, _) => 0,
        (Some(single), None) => single as u32,
        _ => {
            table.push(text.to_string());
            CELL_TEXT_TABLE_FLAG | (table.len() as u32 - 1)
        }
    }
}

fn encode_color(color: Option<RgbColor>) -> u32 {
    match color {
        Some(RgbColor { r, g, b }) => {
            COLOR_SET_FLAG | (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b)
        }
        None => 0,
    }
}

fn encode_attrs(data: &ghostty_vt::CellBasicData) -> u32 {
    let style = &data.style;
    let mut bits = 0;
    let flags = [
        (style.bold, attrs::BOLD),
        (style.italic, attrs::ITALIC),
        (style.faint, attrs::FAINT),
        (style.blink, attrs::BLINK),
        (style.inverse, attrs::INVERSE),
        (style.invisible, attrs::INVISIBLE),
        (style.strikethrough, attrs::STRIKETHROUGH),
        (style.overline, attrs::OVERLINE),
        (data.has_hyperlink, attrs::HYPERLINK),
    ];
    for (enabled, bit) in flags {
        if enabled {
            bits |= bit;
        }
    }
    bits |= (u32::from(style.underline) << attrs::UNDERLINE_SHIFT) & attrs::UNDERLINE_MASK;
    let wide = match data.wide {
        CellWide::Narrow => 0,
        CellWide::Wide => 1,
        CellWide::SpacerTail => 2,
        CellWide::SpacerHead => 3,
    };
    bits | (wide << attrs::WIDE_SHIFT)
}

#[allow(dead_code)]
fn palette_marker(_color: CellColor) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(cols: u16, rows: u16) -> TerminalCore {
        TerminalCore::new(cols, rows, 1024 * 1024).expect("terminal")
    }

    fn cell(snapshot: &RowSnapshot, row: usize, col: usize) -> [u32; CELL_WORDS] {
        let base = (row * snapshot.cols as usize + col) * CELL_WORDS;
        [
            snapshot.cells[base],
            snapshot.cells[base + 1],
            snapshot.cells[base + 2],
            snapshot.cells[base + 3],
        ]
    }

    #[test]
    fn writes_text_and_reads_it_back() {
        let mut term = core(20, 5);
        term.write(b"hello\r\nworld");
        let text = term.read_text(ReadSource::Viewport, None).unwrap();
        assert!(text.starts_with("hello\nworld"), "{text:?}");
        assert_eq!(term.size().unwrap().0, 20);
    }

    #[test]
    fn snapshot_packs_text_and_style() {
        let mut term = core(10, 3);
        term.write(b"\x1b[1;38;2;1;2;3mA\x1b[0mB");
        let snapshot = term.snapshot_rows(0, 3, false).unwrap();
        let a = cell(&snapshot, 0, 0);
        assert_eq!(a[0], 'A' as u32);
        assert_eq!(a[1], COLOR_SET_FLAG | 0x010203);
        assert_ne!(a[3] & attrs::BOLD, 0);
        let b = cell(&snapshot, 0, 1);
        assert_eq!(b[0], 'B' as u32);
        assert_eq!(b[3] & attrs::BOLD, 0);
        assert_eq!(cell(&snapshot, 0, 2), [0, 0, 0, 0]);
    }

    #[test]
    fn snapshot_uses_string_table_for_graphemes() {
        let mut term = core(10, 2);
        term.write("e\u{301}".as_bytes());
        let snapshot = term.snapshot_rows(0, 1, false).unwrap();
        let first = cell(&snapshot, 0, 0)[0];
        assert_ne!(first & CELL_TEXT_TABLE_FLAG, 0);
        assert_eq!(
            snapshot.text_table[(first & !CELL_TEXT_TABLE_FLAG) as usize],
            "e\u{301}"
        );
    }

    #[test]
    fn dirty_rows_clear_after_snapshot_with_clean() {
        let mut term = core(10, 3);
        term.write(b"x");
        let first = term.snapshot_rows(0, 3, true).unwrap();
        assert!(first.dirty_rows.contains(&0));
        let second = term.snapshot_rows(0, 3, true).unwrap();
        assert!(second.dirty_rows.is_empty());
    }

    #[test]
    fn device_attribute_query_produces_a_response() {
        let mut term = core(10, 3);
        term.write(b"\x1b[c");
        let responses = term.drain_responses();
        assert!(!responses.is_empty());
        assert!(responses[0].starts_with(b"\x1b[?"));
        assert!(term.drain_responses().is_empty());
    }

    #[test]
    fn modes_follow_escape_sequences() {
        let mut term = core(10, 3);
        assert!(!term.modes().unwrap().bracketed_paste);
        term.write(b"\x1b[?2004h\x1b[?1049h");
        let modes = term.modes().unwrap();
        assert!(modes.bracketed_paste);
        assert!(modes.alternate_screen);
    }

    #[test]
    fn resize_changes_reported_size() {
        let mut term = core(10, 3);
        term.resize(40, 12, 8, 16).unwrap();
        let (cols, rows, _, _) = term.size().unwrap();
        assert_eq!((cols, rows), (40, 12));
    }

    #[test]
    fn events_drain_once() {
        let mut term = core(10, 3);
        term.write(b"\x07\x1b]7;file:///tmp/x\x1b\\");
        let events = term.take_events();
        assert_eq!(events.bells, 1);
        assert_eq!(events.pwd_changes.len(), 1);
        assert_eq!(term.take_events(), DrainedEvents::default());
    }

    #[test]
    fn cursor_tracks_writes() {
        let mut term = core(10, 3);
        term.write(b"ab");
        let cursor = term.cursor().unwrap();
        assert_eq!((cursor.x, cursor.y), (2, 0));
        assert!(cursor.visible);
    }

    #[test]
    fn scrollback_is_scrollable() {
        let mut term = core(10, 3);
        for i in 0..10 {
            term.write(format!("line{i}\r\n").as_bytes());
        }
        let before = term.scrollbar().unwrap();
        assert!(before.total > before.len);
        term.scroll_viewport_delta(-2);
        assert!(term.scrollbar().unwrap().offset < before.offset);
        term.scroll_viewport_bottom();
        assert_eq!(term.scrollbar().unwrap().offset, before.offset);
    }
}

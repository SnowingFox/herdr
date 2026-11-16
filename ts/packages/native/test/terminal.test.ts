import { describe, expect, it } from "vitest";
import { NativeError, Terminal, unicodeCodepointWidth, unicodeGraphemeWidth, wrapNative } from "../lib/index.js";

function terminal(cols = 20, rows = 5) {
  return new Terminal({ cols, rows, maxScrollbackBytes: 1024 * 1024 });
}

describe("Terminal", () => {
  it("parses output and reads viewport text", () => {
    const term = terminal();
    term.write(Buffer.from("hello\r\nworld"));
    expect(term.readText().startsWith("hello\nworld")).toBe(true);
    expect(term.size()).toMatchObject({ cols: 20, rows: 5 });
  });

  it("reports cursor position and modes", () => {
    const term = terminal();
    term.write(Buffer.from("ab\x1b[?2004h\x1b[?1049h"));
    expect(term.cursor()).toMatchObject({ x: 2, y: 0, visible: true, inViewport: true });
    expect(term.modes()).toMatchObject({ bracketedPaste: true, alternateScreen: true });
  });

  it("packs cell snapshots into a typed array with a string table", () => {
    const term = terminal(10, 2);
    term.write(Buffer.from("\x1b[1;38;2;1;2;3mA\x1b[0me\u0301"));
    const snapshot = term.snapshotRows(0, 2, true);
    expect(snapshot.cols).toBe(10);
    expect(snapshot.rowCount).toBe(2);
    expect(snapshot.cells).toBeInstanceOf(Uint32Array);
    expect(snapshot.cells.length).toBe(10 * 2 * 4);
    const cells = snapshot.cells;
    expect(cells[0]).toBe("A".codePointAt(0));
    expect(cells[1]).toBe((0xff000000 | 0x010203) >>> 0);
    expect((cells[3] ?? 0) & 1).toBe(1);
    const graphemeRef = cells[4] ?? 0;
    expect(graphemeRef >>> 31).toBe(1);
    expect(snapshot.textTable[graphemeRef & 0x7fffffff]).toBe("e\u0301");
    expect(snapshot.dirtyRows).toContain(0);
    expect(term.snapshotRows(0, 2, true).dirtyRows).toEqual([]);
  });

  it("answers terminal queries through drainResponses", () => {
    const term = terminal();
    term.write(Buffer.from("\x1b[c"));
    const responses = term.drainResponses();
    expect(responses.length).toBeGreaterThan(0);
    expect(responses[0]?.toString("latin1").startsWith("\x1b[?")).toBe(true);
    expect(term.drainResponses()).toEqual([]);
  });

  it("resizes and scrolls through scrollback", () => {
    const term = terminal(10, 3);
    for (let i = 0; i < 10; i += 1) {
      term.write(Buffer.from(`line${i}\r\n`));
    }
    const bottom = term.scrollbar();
    term.scrollViewport(-2);
    expect(term.scrollbar().offset).toBeLessThan(bottom.offset);
    term.scrollToBottom();
    expect(term.scrollbar().offset).toBe(bottom.offset);
    term.resize(30, 6, 8, 16);
    expect(term.size()).toMatchObject({ cols: 30, rows: 6 });
    expect(term.readText({ source: "screen" })).toContain("line0");
  });

  it("drains bell, cwd and clipboard events once", () => {
    const term = terminal();
    term.write(Buffer.from("\x07\x1b]7;file:///tmp/x\x1b\\"));
    const events = term.takeEvents();
    expect(events.bells).toBe(1);
    expect(events.pwdChanges).toEqual(["file:///tmp/x"]);
    expect(term.takeEvents()).toEqual({ bells: 0, pwdChanges: [], clipboardWrites: [] });
  });

  it("rejects invalid arguments with a coded error", () => {
    const term = terminal();
    try {
      wrapNative(() => term.readText({ source: "nope" }));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(NativeError);
      expect((error as NativeError).code).toBe("EINVAL");
    }
  });
});

describe("unicode width", () => {
  it("matches terminal cell widths", () => {
    expect(unicodeCodepointWidth("a".codePointAt(0) ?? 0)).toBe(1);
    expect(unicodeCodepointWidth("界".codePointAt(0) ?? 0)).toBe(2);
    expect(unicodeGraphemeWidth([0x65, 0x301])).toEqual({ consumed: 2, width: 1 });
  });
});

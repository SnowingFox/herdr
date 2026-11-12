import { describe, expect, it } from "vitest";
import { foregroundJob, PaneTerminalSession, processCwd, processExists } from "../lib/index.js";
import type { SessionEvent } from "../lib/index.js";
import { isUnix, waitFor } from "./helpers.js";

function spawnSession(argv: string[], rows = 10, cols = 40) {
  const events: SessionEvent[] = [];
  const session = PaneTerminalSession.spawn(
    { pty: { argv, rows, cols, env: { TERM: "xterm-256color" } }, maxScrollbackBytes: 1024 * 1024 },
    (event) => events.push(event),
  );
  return { session, events, exited: () => waitFor(() => session.hasExited, { description: "session exit" }) };
}

describe.skipIf(!isUnix)("PaneTerminalSession", () => {
  it("parses child output into the terminal and reports exit after draining", async () => {
    const { session, events, exited } = spawnSession(["sh", "-c", "printf 'hello\\r\\nworld'"]);
    await exited();
    expect(session.terminal.readText()).toContain("hello\nworld");
    expect(events.at(-1)).toMatchObject({ kind: "exit", code: 0 });
    expect(events.some((event) => event.kind === "output")).toBe(true);
  });

  it("answers terminal queries natively without JS involvement", async () => {
    const script =
      "stty raw -echo; printf '\\033[c'; dd bs=1 count=4 2>/dev/null | od -An -c";
    const { session, exited } = spawnSession(["sh", "-c", script]);
    await exited();
    const text = session.terminal.readText();
    expect(text).toMatch(/033\s+\[\s+\?\s+6/);
  });

  it("forwards user input and resizes the pty and emulator together", async () => {
    const { session, exited } = spawnSession(["sh", "-c", "read line; echo got:$line; stty size"]);
    session.resize(12, 50, 8, 16);
    session.write(Buffer.from("ping\n"));
    await exited();
    const text = session.terminal.readText();
    expect(text).toContain("got:ping");
    expect(text).toContain("12 50");
    expect(session.terminal.size()).toMatchObject({ rows: 12, cols: 50 });
  });

  it("surfaces bell and cwd escape sequences as events", async () => {
    const { events, exited } = spawnSession([
      "sh",
      "-c",
      "printf '\\007\\033]7;file:///tmp/herdr\\033\\\\'",
    ]);
    await exited();
    expect(events).toContainEqual({ kind: "bell", count: 1 });
    expect(events).toContainEqual({ kind: "pwd", path: "file:///tmp/herdr" });
  });

  it("inspects the foreground job and process state on Linux", async () => {
    const { session, exited } = spawnSession(["sh", "-c", "sleep 30"]);
    const pgid = await waitFor(() => session.foregroundProcessGroup(), { description: "pgrp" });
    expect(pgid).toBe(session.pid);
    if (process.platform === "linux") {
      const job = await waitFor(() => foregroundJob(session.pid), { description: "job" });
      expect(job.processGroupId).toBe(session.pid);
      expect(job.processes.length).toBeGreaterThan(0);
      expect(processCwd(session.pid)).toBeTruthy();
    }
    expect(processExists(session.pid)).toBe(true);
    session.kill("kill");
    await exited();
    expect(session.hasExited).toBe(true);
  });
});

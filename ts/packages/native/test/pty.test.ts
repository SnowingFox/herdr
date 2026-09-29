import { describe, expect, it } from "vitest";
import { Pty } from "../lib/index.js";
import type { PtyExit } from "../lib/index.js";
import { isUnix, waitFor } from "./helpers.js";

function spawnPty(argv: string[], rows = 24, cols = 80) {
  const chunks: Buffer[] = [];
  let exit: PtyExit | undefined;
  const pty = Pty.spawn(
    { argv, rows, cols, env: { TERM: "xterm-256color" } },
    (chunk) => chunks.push(chunk),
    (info) => {
      exit = info;
    },
  );
  return {
    pty,
    output: () => Buffer.concat(chunks).toString("utf8"),
    exit: () => waitFor(() => exit, { description: "pty exit" }),
  };
}

describe.skipIf(!isUnix)("Pty", () => {
  it("delivers output then exit with the child's status", async () => {
    const run = spawnPty(["sh", "-c", "printf hello; exit 3"]);
    const exit = await run.exit();
    expect(exit.code).toBe(3);
    expect(run.output()).toContain("hello");
  });

  it("writes to the child and resizes the pty", async () => {
    const run = spawnPty(["sh", "-c", "read line; echo got:$line; stty size"]);
    run.pty.resize(30, 100);
    run.pty.write(Buffer.from("ping\n"));
    await run.exit();
    expect(run.output()).toContain("got:ping");
    expect(run.output()).toContain("30 100");
  });

  it("reports the foreground process group and kills the child", async () => {
    const run = spawnPty(["sh", "-c", "sleep 30"]);
    await waitFor(() => run.pty.foregroundProcessGroup(), { description: "foreground pgrp" });
    expect(run.pty.foregroundProcessGroup()).toBe(run.pty.pid);
    run.pty.kill("kill");
    const exit = await run.exit();
    expect(exit.signal ?? exit.code).toBeDefined();
  });

  it("rejects an empty argv", () => {
    expect(() => Pty.spawn({ argv: [], rows: 24, cols: 80 }, () => {}, () => {})).toThrow(/EINVAL/);
  });
});

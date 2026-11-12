import { TerminalSession as NativeSession } from "../index.js";
import type { SessionEventData, SessionOptions, Terminal } from "../index.js";
import { wrapNative } from "./errors.js";

export type SessionEvent =
  | { kind: "output" }
  | { kind: "bell"; count: number }
  | { kind: "pwd"; path: string }
  | { kind: "clipboard"; data: Buffer }
  | { kind: "exit"; code: number | undefined; signal: string | undefined };

export type SessionListener = (event: SessionEvent) => void;

function decode(event: SessionEventData): SessionEvent | undefined {
  switch (event.kind) {
    case "output":
      return { kind: "output" };
    case "bell":
      return { kind: "bell", count: event.count ?? 1 };
    case "pwd":
      return { kind: "pwd", path: event.text ?? "" };
    case "clipboard":
      return { kind: "clipboard", data: event.data ?? Buffer.alloc(0) };
    case "exit":
      return { kind: "exit", code: event.exitCode, signal: event.exitSignal };
    default:
      return undefined;
  }
}

/** Typed wrapper over the native pane runtime (PTY + terminal emulator). */
export class PaneTerminalSession {
  readonly terminal: Terminal;
  private readonly native: NativeSession;
  private exited = false;

  private constructor(native: NativeSession) {
    this.native = native;
    this.terminal = native.terminal();
  }

  /**
   * The listener runs on the JS thread. The native wake callback can only fire after this call
   * returns (the JS thread is busy until then), so `session` is always assigned when it runs.
   */
  static spawn(options: SessionOptions, listener: SessionListener): PaneTerminalSession {
    let session: PaneTerminalSession | undefined;
    const native = wrapNative(() =>
      NativeSession.spawn(options, () => session?.drain(listener)),
    );
    session = new PaneTerminalSession(native);
    return session;
  }

  private drain(listener: SessionListener): void {
    for (const raw of this.native.takeEvents()) {
      const event = decode(raw);
      if (!event) {
        continue;
      }
      if (event.kind === "exit") {
        this.exited = true;
      }
      listener(event);
    }
  }

  get pid(): number {
    return this.native.pid;
  }

  get hasExited(): boolean {
    return this.exited;
  }

  write(bytes: Uint8Array): void {
    wrapNative(() => this.native.write(Buffer.from(bytes)));
  }

  resize(rows: number, cols: number, cellWidthPx = 0, cellHeightPx = 0): void {
    wrapNative(() => this.native.resize(rows, cols, cellWidthPx, cellHeightPx));
  }

  foregroundProcessGroup(): number | null {
    return this.native.foregroundProcessGroup();
  }

  kill(signal: "hangup" | "terminate" | "kill" = "hangup"): void {
    wrapNative(() => this.native.kill(signal));
  }
}

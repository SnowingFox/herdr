import type { TerminalId } from "./ids.js";

/**
 * Server-owned terminal metadata. This is the minimal identity slice needed by session
 * organization; title/OSC/agent metadata land with the terminal package.
 */
export interface TerminalState {
  readonly id: TerminalId;
  cwd: string;
  launchArgv: readonly string[] | undefined;
}

export function newTerminalState(
  id: TerminalId,
  cwd: string,
  launchArgv?: readonly string[],
): TerminalState {
  return { id, cwd, launchArgv };
}

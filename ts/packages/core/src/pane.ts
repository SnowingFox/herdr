import type { TerminalId } from "./ids.js";

/**
 * Viewport state for a pane. Terminal identity, cwd, labels and agent metadata live in
 * `TerminalState`; runtimes (PTYs) are owned elsewhere so this stays testable without them.
 */
export interface PaneState {
  attachedTerminalId: TerminalId;
  /**
   * Whether the user has seen this pane since its last state change to idle. False means "Done"
   * (an agent finished while the user was in another workspace).
   */
  seen: boolean;
  /** Whether unmodified right-click gestures are forwarded to the pane application. */
  rightClickPassthrough: boolean;
}

export function newPaneState(attachedTerminalId: TerminalId): PaneState {
  return { attachedTerminalId, seen: true, rightClickPassthrough: false };
}

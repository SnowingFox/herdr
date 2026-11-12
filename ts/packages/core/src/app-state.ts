/**
 * Pure session-organization state: terminals, workspaces, focus and selection. No I/O, no
 * runtimes; runtime shutdown is requested through `terminalRuntimeShutdowns` and executed by the
 * server layer. Config-derived presentation fields arrive with the config package.
 */

import { EMPTY_RECT, type Rect } from "./geometry.js";
import type { PaneId, TerminalId } from "./ids.js";
import type { PaneInfo } from "./layout.js";
import type { TerminalState } from "./terminal-state.js";
import type { Workspace } from "./workspace.js";

export type Mode = "navigate" | "terminal";

export interface PaneFocusTarget {
  readonly workspaceId: string;
  readonly paneId: PaneId;
}

export interface ViewState {
  /** Geometry of the most recently computed server pane surface. */
  terminalArea: Rect;
  paneInfos: PaneInfo[];
}

export interface ToastTarget {
  readonly workspaceId: string;
  readonly paneId: PaneId;
}

export interface ToastNotification {
  message: string;
  target: ToastTarget | undefined;
}

export interface PendingAgentNotification {
  readonly paneId: PaneId;
  readonly workspaceId: string;
}

export interface PopupPaneState {
  readonly paneId: PaneId;
  readonly terminalId: TerminalId;
}

export const DEFAULT_HEADLESS_COLS = 120;
export const DEFAULT_HEADLESS_ROWS = 40;

export class AppState {
  readonly terminals = new Map<TerminalId, TerminalState>();
  /** Terminal ids whose size is currently owned by a direct attach client. */
  readonly directAttachResizeLocks = new Set<TerminalId>();
  readonly paneIdAliases = new Map<number, PaneId>();
  readonly publicPaneIdAliases = new Map<string, PaneId>();
  workspaces: Workspace[] = [];
  active: number | undefined = undefined;
  previousPaneFocus: PaneFocusTarget | undefined = undefined;
  selected = 0;
  mode: Mode = "navigate";
  shouldQuit = false;
  worktreeDirectory = "/tmp/herdr-worktrees";
  view: ViewState = { terminalArea: EMPTY_RECT, paneInfos: [] };
  toast: ToastNotification | undefined = undefined;
  readonly pendingAgentNotifications = new Map<PaneId, PendingAgentNotification>();
  /** Virtual terminal size (columns, rows) used when no client is attached. */
  headlessSize: readonly [number, number] = [DEFAULT_HEADLESS_COLS, DEFAULT_HEADLESS_ROWS];
  confirmClose = true;
  /** Session-modal terminal popup, intentionally outside workspace layouts. */
  popupPane: PopupPaneState | undefined = undefined;
  readonly pluginPanes = new Map<PaneId, unknown>();
  /** Set when a persisted session snapshot would change. */
  sessionDirty = false;
  /** Runtimes the server layer must shut down after state detached their terminal metadata. */
  terminalRuntimeShutdowns: TerminalId[] = [];

  markSessionDirty(): void {
    this.sessionDirty = true;
  }

  // --- Focus tracking ---

  currentPaneFocusTarget(): PaneFocusTarget | undefined {
    const workspace = this.active === undefined ? undefined : this.workspaces[this.active];
    const paneId = workspace?.focusedPaneId();
    return workspace && paneId !== undefined ? { workspaceId: workspace.id, paneId } : undefined;
  }

  recordPaneFocusChange(
    previous: PaneFocusTarget | undefined,
    wsIdx: number,
    paneId: PaneId,
  ): void {
    const workspace = this.workspaces[wsIdx];
    if (!workspace) {
      return;
    }
    const target: PaneFocusTarget = { workspaceId: workspace.id, paneId };
    if (!sameFocusTarget(previous, target)) {
      this.previousPaneFocus = previous;
    }
  }

  private recordPaneFocusAfterNavigation(previous: PaneFocusTarget | undefined): void {
    if (!sameFocusTarget(previous, this.currentPaneFocusTarget())) {
      this.previousPaneFocus = previous;
    }
  }

  focusPaneInWorkspace(wsIdx: number, paneId: PaneId): boolean {
    const workspace = this.workspaces[wsIdx];
    const tabIdx = workspace?.findTabIndexForPane(paneId);
    if (!workspace || tabIdx === undefined) {
      return false;
    }
    const previous = this.currentPaneFocusTarget();
    if (sameFocusTarget(previous, { workspaceId: workspace.id, paneId })) {
      return false;
    }
    this.switchWorkspaceTab(wsIdx, tabIdx);
    const tab = workspace.tabs[tabIdx];
    if (!tab) {
      return false;
    }
    tab.layout.focusPane(paneId);
    this.previousPaneFocus = previous;
    this.markSessionDirty();
    return true;
  }

  // --- Workspace operations ---

  switchWorkspace(idx: number): void {
    const workspace = this.workspaces[idx];
    if (!workspace) {
      return;
    }
    const previousFocus = this.currentPaneFocusTarget();
    this.active = idx;
    this.selected = idx;
    this.markSessionDirty();
    workspace.switchTab(workspace.activeTab);
    this.recordPaneFocusAfterNavigation(previousFocus);
  }

  switchWorkspaceTab(wsIdx: number, tabIdx: number): boolean {
    const workspace = this.workspaces[wsIdx];
    if (!workspace || tabIdx >= workspace.tabs.length) {
      return false;
    }
    const previousFocus = this.currentPaneFocusTarget();
    this.active = wsIdx;
    this.selected = wsIdx;
    this.markSessionDirty();
    workspace.switchTab(tabIdx);
    this.recordPaneFocusAfterNavigation(previousFocus);
    return true;
  }

  moveWorkspace(sourceIdx: number, insertIdx: number): boolean {
    if (sourceIdx >= this.workspaces.length || insertIdx > this.workspaces.length) {
      return false;
    }
    const targetIdx = sourceIdx < insertIdx ? insertIdx - 1 : insertIdx;
    if (sourceIdx === targetIdx) {
      return false;
    }
    this.markSessionDirty();
    const activeId = this.active === undefined ? undefined : this.workspaces[this.active]?.id;
    const selectedId = this.workspaces[this.selected]?.id;
    const [workspace] = this.workspaces.splice(sourceIdx, 1);
    if (workspace) {
      this.workspaces.splice(targetIdx, 0, workspace);
    }
    this.restoreSelection(activeId, selectedId);
    return true;
  }

  moveWorkspaceBlock(workspaceIds: readonly string[], beforeWorkspaceId?: string): boolean {
    const moved = new Set(workspaceIds);
    const known = new Set(this.workspaces.map((workspace) => workspace.id));
    if (
      moved.size === 0 ||
      moved.size !== workspaceIds.length ||
      !workspaceIds.every((id) => known.has(id)) ||
      (beforeWorkspaceId !== undefined && (moved.has(beforeWorkspaceId) || !known.has(beforeWorkspaceId)))
    ) {
      return false;
    }
    const desired = this.workspaces.map((w) => w.id).filter((id) => !moved.has(id));
    const found = beforeWorkspaceId === undefined ? -1 : desired.indexOf(beforeWorkspaceId);
    const insertIdx = found >= 0 ? found : desired.length;
    desired.splice(insertIdx, 0, ...workspaceIds);
    if (this.workspaces.every((workspace, i) => workspace.id === desired[i])) {
      return false;
    }
    const activeId = this.active === undefined ? undefined : this.workspaces[this.active]?.id;
    const selectedId = this.workspaces[this.selected]?.id;
    const positions = new Map(desired.map((id, index) => [id, index] as const));
    this.markSessionDirty();
    this.workspaces.sort(
      (a, b) =>
        (positions.get(a.id) ?? Number.MAX_SAFE_INTEGER) -
        (positions.get(b.id) ?? Number.MAX_SAFE_INTEGER),
    );
    this.restoreSelection(activeId, selectedId);
    return true;
  }

  private restoreSelection(activeId: string | undefined, selectedId: string | undefined): void {
    const indexOf = (id: string | undefined): number | undefined => {
      if (id === undefined) {
        return undefined;
      }
      const idx = this.workspaces.findIndex((workspace) => workspace.id === id);
      return idx >= 0 ? idx : undefined;
    };
    this.active = indexOf(activeId);
    this.selected = indexOf(selectedId) ?? 0;
  }

  terminalIdsForWorkspace(wsIdx: number): TerminalId[] {
    return (this.workspaces[wsIdx]?.tabs ?? []).flatMap((tab) =>
      [...tab.panes.values()].map((pane) => pane.attachedTerminalId),
    );
  }

  paneIdsForWorkspace(wsIdx: number): PaneId[] {
    return (this.workspaces[wsIdx]?.tabs ?? []).flatMap((tab) => tab.layout.paneIds());
  }

  terminalIdsForTab(wsIdx: number, tabIdx: number): TerminalId[] {
    const tab = this.workspaces[wsIdx]?.tabs[tabIdx];
    return tab ? [...tab.panes.values()].map((pane) => pane.attachedTerminalId) : [];
  }

  paneIdsForTab(wsIdx: number, tabIdx: number): PaneId[] {
    return this.workspaces[wsIdx]?.tabs[tabIdx]?.layout.paneIds() ?? [];
  }

  terminalIdForPane(wsIdx: number, paneId: PaneId): TerminalId | undefined {
    return this.workspaces[wsIdx]?.paneState(paneId)?.attachedTerminalId;
  }

  /** Drop terminal metadata that no pane references and queue its runtime for shutdown. */
  removeUnattachedTerminalIds(terminalIds: Iterable<TerminalId>): void {
    for (const terminalId of terminalIds) {
      const stillAttached = this.workspaces.some((workspace) =>
        workspace.tabs.some((tab) =>
          [...tab.panes.values()].some((pane) => pane.attachedTerminalId === terminalId),
        ),
      );
      if (
        !stillAttached &&
        this.terminals.delete(terminalId) &&
        !this.terminalRuntimeShutdowns.includes(terminalId)
      ) {
        this.terminalRuntimeShutdowns.push(terminalId);
      }
    }
  }

  removePluginPaneRecords(paneIds: Iterable<PaneId>): void {
    const ids = [...paneIds];
    if (this.previousPaneFocus && ids.includes(this.previousPaneFocus.paneId)) {
      this.previousPaneFocus = undefined;
    }
    for (const paneId of ids) {
      this.pluginPanes.delete(paneId);
    }
  }

  /** Indices closed together with `wsIdx`: the whole worktree group when closing its parent. */
  workspaceCloseIndices(wsIdx: number): number[] {
    const space = this.workspaces[wsIdx]?.worktreeSpace;
    if (space && !space.isLinkedWorktree) {
      const indices = this.workspaces.flatMap((workspace, idx) =>
        workspace.worktreeSpace?.key === space.key ? [idx] : [],
      );
      if (indices.length >= 2) {
        return indices;
      }
    }
    return [wsIdx];
  }

  workspaceCloseWouldCloseWorktreeGroup(wsIdx: number): boolean {
    return this.workspaceCloseIndices(wsIdx).length >= 2;
  }

  closePaneWouldCloseWorkspace(wsIdx: number, paneId: PaneId): boolean {
    const workspace = this.workspaces[wsIdx];
    const tabIdx = workspace?.findTabIndexForPane(paneId);
    if (!workspace || tabIdx === undefined) {
      return false;
    }
    return (workspace.tabs[tabIdx]?.layout.paneCount() ?? 0) <= 1 && workspace.tabs.length <= 1;
  }

  closeSelectedWorkspace(): void {
    if (this.workspaces.length === 0) {
      return;
    }
    this.markSessionDirty();
    const closeIndices = this.workspaceCloseIndices(this.selected);
    const terminalIds: TerminalId[] = [];
    const paneIds: PaneId[] = [];
    for (const idx of closeIndices) {
      terminalIds.push(...this.terminalIdsForWorkspace(idx));
      paneIds.push(...this.paneIdsForWorkspace(idx));
    }
    const activeId = this.active === undefined ? undefined : this.workspaces[this.active]?.id;
    this.removePluginPaneRecords(paneIds);
    for (const idx of [...closeIndices].reverse()) {
      this.workspaces.splice(idx, 1);
    }
    this.removeUnattachedTerminalIds(terminalIds);
    if (this.workspaces.length === 0) {
      this.active = undefined;
      this.selected = 0;
      return;
    }
    if (activeId !== undefined) {
      const idx = this.workspaces.findIndex((workspace) => workspace.id === activeId);
      if (idx >= 0) {
        this.selected = idx;
      }
    }
    if (this.selected >= this.workspaces.length) {
      this.selected = this.workspaces.length - 1;
    }
    this.active = this.selected;
  }
}

function sameFocusTarget(
  a: PaneFocusTarget | undefined,
  b: PaneFocusTarget | undefined,
): boolean {
  return a?.workspaceId === b?.workspaceId && a?.paneId === b?.paneId && (a === undefined) === (b === undefined);
}

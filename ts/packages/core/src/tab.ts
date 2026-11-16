import type { Direction } from "./geometry.js";
import { allocTerminalId, type PaneId } from "./ids.js";
import { paneNode, TileLayout } from "./layout.js";
import { newPaneState, type PaneState } from "./pane.js";
import { newTerminalState, type TerminalState } from "./terminal-state.js";

export interface MovedPane {
  readonly paneId: PaneId;
  readonly paneState: PaneState;
}

export interface NewPane {
  readonly paneId: PaneId;
  readonly terminal: TerminalState;
}

export type DetachedPane = readonly [PaneId, PaneState["attachedTerminalId"]];

/** A split whose pane exists in the layout but has no state yet (its runtime is still spawning). */
export interface PendingSplit {
  readonly paneId: PaneId;
  readonly target: PaneId;
}

export interface CommitSplitOptions {
  readonly focus: boolean;
  readonly cwd: string;
  readonly launchArgv?: readonly string[] | undefined;
}

export class Tab {
  customName: string | undefined;
  number: number;
  /** Identity source for this tab's pane tree. */
  rootPane: PaneId;
  layout: TileLayout;
  /** Pane viewport state; always present, testable without PTYs. */
  readonly panes = new Map<PaneId, PaneState>();
  zoomed = false;

  private constructor(number: number, customName: string | undefined, rootPane: PaneId, layout: TileLayout) {
    this.number = number;
    this.customName = customName;
    this.rootPane = rootPane;
    this.layout = layout;
  }

  /** New tab with one pane. The caller spawns the runtime for the returned terminal. */
  static create(
    number: number,
    cwd: string,
    launchArgv?: readonly string[],
  ): { tab: Tab; paneId: PaneId; terminal: TerminalState } {
    const { layout, rootId } = TileLayout.create();
    const terminal = newTerminalState(allocTerminalId(), cwd, launchArgv);
    const tab = new Tab(number, undefined, rootId, layout);
    tab.panes.set(rootId, newPaneState(terminal.id));
    return { tab, paneId: rootId, terminal };
  }

  static fromExistingPane(number: number, customName: string | undefined, moved: MovedPane): Tab {
    const tab = new Tab(
      number,
      customName,
      moved.paneId,
      TileLayout.fromSaved(paneNode(moved.paneId), moved.paneId),
    );
    tab.panes.set(moved.paneId, moved.paneState);
    return tab;
  }

  isAutoNamed(): boolean {
    return this.customName === undefined;
  }

  setCustomName(name: string): void {
    this.customName = name;
  }

  /**
   * Reserve a pane next to `target` in the layout. Focus and pane state are untouched until
   * `commitSplit`, so a failed runtime spawn can `rollbackSplit` without leaving a trace.
   */
  reserveSplit(target: PaneId, direction: Direction, ratio = 0.5): PendingSplit | undefined {
    const paneId = this.layout.splitPane(target, direction, ratio);
    return paneId === undefined ? undefined : { paneId, target };
  }

  commitSplit(pending: PendingSplit, options: CommitSplitOptions): NewPane {
    const terminal = newTerminalState(allocTerminalId(), options.cwd, options.launchArgv);
    if (options.focus) {
      this.layout.focusPane(pending.paneId);
    }
    this.panes.set(pending.paneId, newPaneState(terminal.id));
    this.zoomed = false;
    return { paneId: pending.paneId, terminal };
  }

  rollbackSplit(pending: PendingSplit): void {
    this.layout.closePane(pending.paneId);
  }

  closeFocused(): DetachedPane | undefined {
    return this.detachPane(this.layout.focused());
  }

  closePane(paneId: PaneId): DetachedPane | undefined {
    return this.detachPane(paneId);
  }

  removePane(paneId: PaneId): DetachedPane | undefined {
    return this.detachPane(paneId);
  }

  takePaneForMove(paneId: PaneId): MovedPane | undefined {
    if (!this.panes.has(paneId)) {
      return undefined;
    }
    if (this.layout.paneCount() > 1) {
      const nextRoot = this.promotedRootIfNeeded(paneId);
      this.layout.closePane(paneId);
      if (nextRoot !== undefined) {
        this.rootPane = nextRoot;
      }
    }
    const paneState = this.panes.get(paneId);
    if (!paneState) {
      return undefined;
    }
    this.panes.delete(paneId);
    this.zoomed = false;
    return { paneId, paneState };
  }

  /** Insert a moved pane; on failure the moved pane is returned for recovery. */
  insertExistingPane(
    target: PaneId,
    moved: MovedPane,
    direction: Direction,
    ratio: number,
    focus: boolean,
  ): { ok: true; paneId: PaneId } | { ok: false; moved: MovedPane } {
    if (!this.layout.insertPaneNear(target, moved.paneId, direction, ratio, focus)) {
      return { ok: false, moved };
    }
    this.panes.set(moved.paneId, moved.paneState);
    this.zoomed = false;
    return { ok: true, paneId: moved.paneId };
  }

  terminalId(paneId: PaneId): PaneState["attachedTerminalId"] | undefined {
    return this.panes.get(paneId)?.attachedTerminalId;
  }

  private detachPane(paneId: PaneId): DetachedPane | undefined {
    if (this.layout.paneCount() <= 1) {
      return undefined;
    }
    const nextRoot = this.promotedRootIfNeeded(paneId);
    this.layout.closePane(paneId);
    const pane = this.panes.get(paneId);
    if (!pane) {
      return undefined;
    }
    this.panes.delete(paneId);
    this.zoomed = false;
    if (nextRoot !== undefined) {
      this.rootPane = nextRoot;
    }
    return [paneId, pane.attachedTerminalId];
  }

  private promotedRootIfNeeded(closing: PaneId): PaneId | undefined {
    if (this.rootPane !== closing) {
      return undefined;
    }
    return this.layout.paneIds().find((id) => id !== closing);
  }
}

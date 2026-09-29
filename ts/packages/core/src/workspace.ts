import type { Direction } from "./geometry.js";
import {
  generateWorkspaceId,
  type PaneId,
  publicPaneIdForNumber,
  publicTabIdForNumber,
  type TerminalId,
} from "./ids.js";
import type { PaneState } from "./pane.js";
import {
  type CommitSplitOptions,
  type MovedPane,
  type NewPane,
  type PendingSplit,
  Tab,
} from "./tab.js";
import type { TerminalState } from "./terminal-state.js";

export interface WorktreeSpaceMembership {
  readonly key: string;
  readonly label: string;
  readonly repoRoot: string;
  readonly checkoutPath: string;
  readonly isLinkedWorktree: boolean;
}

/** Public ids a pane's process should see in its environment. */
export interface PaneLaunchIdentity {
  readonly workspaceId: string;
  readonly tabId: string;
  readonly paneId: string;
}

export interface TakenPane {
  readonly moved: MovedPane;
  readonly removedTabIdx: number | undefined;
  readonly workspaceEmpty: boolean;
}

export interface ReservedTab {
  readonly number: number;
  readonly paneNumber: number;
}

export interface ReservedSplit {
  readonly tabIdx: number;
  readonly pending: PendingSplit;
  readonly paneNumber: number;
}

export interface WorkspaceCreateOptions {
  readonly cwd: string;
  readonly launchArgv?: readonly string[] | undefined;
  readonly customName?: string | undefined;
  /** Home directory used for the `~` label; defaults to `$HOME`. */
  readonly homeDir?: string | undefined;
}

/** Label for a cwd when no repository identity is cached: `~` for home, else the last segment. */
export function fallbackLabelFromCwd(cwd: string, homeDir = process.env.HOME): string {
  if (homeDir !== undefined && homeDir !== "" && cwd === homeDir) {
    return "~";
  }
  const segments = cwd.split(/[\\/]/).filter((segment) => segment !== "");
  return segments.at(-1) ?? cwd;
}

/** A named workspace containing tabs. */
export class Workspace {
  /** Stable public identity, independent of display order. */
  id: string;
  /** User-provided override. If set, auto-derived identity stops updating. */
  customName: string | undefined;
  /** Fallback identity source for tests, old snapshots, or missing runtimes. */
  identityCwd: string;
  /** cwd from which the cached automatic label was derived. */
  cachedIdentityCwd: string;
  /** Automatic label cached outside the render path. */
  cachedAutoLabel: string;
  cachedGitBranch: string | undefined = undefined;
  cachedGitAheadBehind: readonly [number, number] | undefined = undefined;
  /** Explicit Herdr-managed worktree grouping provenance. */
  worktreeSpace: WorktreeSpaceMembership | undefined = undefined;
  /** Public pane numbers within this workspace. Closed pane numbers are not reused. */
  readonly publicPaneNumbers = new Map<PaneId, number>();
  nextPublicPaneNumber: number;
  nextPublicTabNumber: number;
  readonly tabs: Tab[];
  activeTab = 0;

  private constructor(options: {
    id: string;
    customName: string | undefined;
    identityCwd: string;
    autoLabel: string;
    tab: Tab;
    nextPublicPaneNumber: number;
    nextPublicTabNumber: number;
  }) {
    this.id = options.id;
    this.customName = options.customName;
    this.identityCwd = options.identityCwd;
    this.cachedIdentityCwd = options.identityCwd;
    this.cachedAutoLabel = options.autoLabel;
    this.nextPublicPaneNumber = options.nextPublicPaneNumber;
    this.nextPublicTabNumber = options.nextPublicTabNumber;
    this.tabs = [options.tab];
  }

  /** New workspace with one tab and one pane. The caller spawns the runtime. */
  static create(options: WorkspaceCreateOptions): {
    workspace: Workspace;
    paneId: PaneId;
    terminal: TerminalState;
  } {
    const { tab, paneId, terminal } = Tab.create(1, options.cwd, options.launchArgv);
    const workspace = new Workspace({
      id: generateWorkspaceId(),
      customName: options.customName,
      identityCwd: options.cwd,
      autoLabel: fallbackLabelFromCwd(options.cwd, options.homeDir),
      tab,
      nextPublicPaneNumber: 2,
      nextPublicTabNumber: 2,
    });
    workspace.publicPaneNumbers.set(paneId, 1);
    return { workspace, paneId, terminal };
  }

  /** Workspace built around a pane moved out of another workspace. */
  static fromExistingPane(options: {
    label: string | undefined;
    tabLabel: string | undefined;
    identityCwd: string;
    moved: MovedPane;
    homeDir?: string | undefined;
  }): Workspace {
    const tab = Tab.fromExistingPane(1, options.tabLabel, options.moved);
    const workspace = new Workspace({
      id: generateWorkspaceId(),
      customName: options.label,
      identityCwd: options.identityCwd,
      autoLabel: fallbackLabelFromCwd(options.identityCwd, options.homeDir),
      tab,
      nextPublicPaneNumber: 2,
      nextPublicTabNumber: 2,
    });
    workspace.publicPaneNumbers.set(options.moved.paneId, 1);
    return workspace;
  }

  // --- Tabs ---

  getActiveTab(): Tab | undefined {
    return this.tabs[this.activeTab];
  }

  activeTabIndex(): number {
    return this.activeTab;
  }

  tabDisplayName(tabIdx: number): string | undefined {
    const tab = this.tabs[tabIdx];
    return tab ? (tab.customName ?? String(tabIdx + 1)) : undefined;
  }

  switchTab(idx: number): void {
    const tab = this.tabs[idx];
    if (!tab) {
      return;
    }
    this.activeTab = idx;
    for (const pane of tab.panes.values()) {
      pane.seen = true;
    }
  }

  /** Reserve the next public tab number (burned even if the runtime spawn later fails). */
  reserveTab(): ReservedTab {
    const number = this.nextPublicTabNumber;
    this.nextPublicTabNumber += 1;
    return { number, paneNumber: this.nextPublicPaneNumber };
  }

  /** Create the tab state for a reservation; register it with `commitTab` once its runtime lives. */
  createReservedTab(
    reservation: ReservedTab,
    cwd: string,
    launchArgv?: readonly string[],
  ): { tab: Tab; paneId: PaneId; terminal: TerminalState } {
    return Tab.create(reservation.number, cwd, launchArgv);
  }

  commitTab(reservation: ReservedTab, tab: Tab): number {
    this.registerNewPaneWithNumber(tab.rootPane, reservation.paneNumber);
    this.tabs.push(tab);
    return this.tabs.length - 1;
  }

  launchIdentity(tabNumber: number, paneNumber: number): PaneLaunchIdentity {
    return {
      workspaceId: this.id,
      tabId: publicTabIdForNumber(this.id, tabNumber),
      paneId: publicPaneIdForNumber(this.id, paneNumber),
    };
  }

  closeTab(idx: number): boolean {
    if (this.tabs.length <= 1 || idx >= this.tabs.length) {
      return false;
    }
    const [tab] = this.tabs.splice(idx, 1);
    for (const paneId of tab?.panes.keys() ?? []) {
      this.unregisterPane(paneId);
    }
    this.adjustActiveTabAfterRemoval(idx);
    return true;
  }

  moveTab(sourceIdx: number, insertIdx: number): boolean {
    if (sourceIdx >= this.tabs.length || insertIdx > this.tabs.length) {
      return false;
    }
    const targetIdx = Math.min(
      sourceIdx < insertIdx ? Math.max(insertIdx - 1, 0) : insertIdx,
      Math.max(this.tabs.length - 1, 0),
    );
    if (sourceIdx === targetIdx) {
      return false;
    }
    const activeRootPane = this.tabs[this.activeTab]?.rootPane;
    const [tab] = this.tabs.splice(sourceIdx, 1);
    if (!tab) {
      return false;
    }
    this.tabs.splice(targetIdx, 0, tab);
    const activeIdx =
      activeRootPane === undefined
        ? -1
        : this.tabs.findIndex((candidate) => candidate.rootPane === activeRootPane);
    this.activeTab = activeIdx >= 0 ? activeIdx : targetIdx;
    return true;
  }

  closeActiveTab(): boolean {
    return this.closeTab(this.activeTab);
  }

  // --- Panes ---

  /** Reserve a split of `paneId` in its tab. */
  reserveSplit(paneId: PaneId, direction: Direction, ratio = 0.5): ReservedSplit | undefined {
    const tabIdx = this.findTabIndexForPane(paneId);
    const tab = tabIdx === undefined ? undefined : this.tabs[tabIdx];
    if (tabIdx === undefined || !tab) {
      return undefined;
    }
    const pending = tab.reserveSplit(paneId, direction, ratio);
    return pending ? { tabIdx, pending, paneNumber: this.nextPublicPaneNumber } : undefined;
  }

  commitSplit(reservation: ReservedSplit, options: CommitSplitOptions): NewPane | undefined {
    const tab = this.tabs[reservation.tabIdx];
    if (!tab) {
      return undefined;
    }
    const newPane = tab.commitSplit(reservation.pending, options);
    this.registerNewPaneWithNumber(newPane.paneId, reservation.paneNumber);
    return newPane;
  }

  rollbackSplit(reservation: ReservedSplit): void {
    this.tabs[reservation.tabIdx]?.rollbackSplit(reservation.pending);
  }

  /** Close the focused pane. Returns true if the workspace should close. */
  closeFocused(): boolean {
    const tab = this.getActiveTab();
    const paneCount = tab?.layout.paneCount() ?? 0;
    if (paneCount <= 1) {
      return this.tabs.length <= 1 || this.closeActiveTabAndReport();
    }
    const detached = tab?.closeFocused();
    if (detached) {
      this.unregisterPane(detached[0]);
    }
    return false;
  }

  /** Remove a pane without touching its runtime. Returns true if the workspace should close. */
  removePane(paneId: PaneId): boolean {
    return this.detachPaneFromTab(paneId, (tab) => tab.removePane(paneId));
  }

  closePane(paneId: PaneId): boolean {
    return this.detachPaneFromTab(paneId, (tab) => tab.closePane(paneId));
  }

  takePaneForMove(paneId: PaneId): TakenPane | undefined {
    const tabIdx = this.findTabIndexForPane(paneId);
    const tab = tabIdx === undefined ? undefined : this.tabs[tabIdx];
    if (tabIdx === undefined || !tab) {
      return undefined;
    }
    if (tab.layout.paneCount() <= 1) {
      this.tabs.splice(tabIdx, 1);
      const moved = tab.takePaneForMove(paneId);
      if (!moved) {
        return undefined;
      }
      this.adjustActiveTabAfterRemoval(tabIdx);
      return { moved, removedTabIdx: tabIdx, workspaceEmpty: this.tabs.length === 0 };
    }
    const moved = tab.takePaneForMove(paneId);
    return moved ? { moved, removedTabIdx: undefined, workspaceEmpty: false } : undefined;
  }

  /** Insert a moved pane; on failure the moved pane is returned for recovery. */
  insertMovedPaneIntoTab(
    tabIdx: number,
    targetPaneId: PaneId,
    moved: MovedPane,
    direction: Direction,
    ratio: number,
    focus: boolean,
  ): { ok: true; paneId: PaneId } | { ok: false; moved: MovedPane } {
    const tab = this.tabs[tabIdx];
    if (!tab) {
      return { ok: false, moved };
    }
    const result = tab.insertExistingPane(targetPaneId, moved, direction, ratio, focus);
    if (result.ok && !this.publicPaneNumbers.has(moved.paneId)) {
      this.registerNewPaneWithNumber(moved.paneId, this.nextPublicPaneNumber);
    }
    return result;
  }

  createTabFromExistingPane(moved: MovedPane, label: string | undefined): number {
    const number = this.nextPublicTabNumber;
    this.nextPublicTabNumber += 1;
    const tab = Tab.fromExistingPane(number, label, moved);
    if (!this.publicPaneNumbers.has(moved.paneId)) {
      this.registerNewPaneWithNumber(moved.paneId, this.nextPublicPaneNumber);
    }
    this.tabs.push(tab);
    return this.tabs.length - 1;
  }

  unregisterMovedPane(paneId: PaneId): void {
    this.unregisterPane(paneId);
  }

  publicPaneNumber(paneId: PaneId): number | undefined {
    return this.publicPaneNumbers.get(paneId);
  }

  publicTabNumber(tabIdx: number): number | undefined {
    return this.tabs[tabIdx]?.number;
  }

  publicTabNumberForPane(paneId: PaneId): number | undefined {
    const tabIdx = this.findTabIndexForPane(paneId);
    return tabIdx === undefined ? undefined : this.publicTabNumber(tabIdx);
  }

  setCustomName(name: string): void {
    this.customName = name;
  }

  findTabIndexForPane(paneId: PaneId): number | undefined {
    const idx = this.tabs.findIndex((tab) => tab.panes.has(paneId));
    return idx >= 0 ? idx : undefined;
  }

  paneState(paneId: PaneId): PaneState | undefined {
    for (const tab of this.tabs) {
      const state = tab.panes.get(paneId);
      if (state) {
        return state;
      }
    }
    return undefined;
  }

  terminalId(paneId: PaneId): TerminalId | undefined {
    for (const tab of this.tabs) {
      const id = tab.terminalId(paneId);
      if (id !== undefined) {
        return id;
      }
    }
    return undefined;
  }

  focusedPaneId(): PaneId | undefined {
    return this.getActiveTab()?.layout.focused();
  }

  // --- Identity / labels ---

  /** Label from the cached identity cwd; never touches the filesystem. */
  displayName(): string {
    return this.customName ?? this.automaticDisplayNameForCwd(this.identityCwd);
  }

  /** Terminal-aware label: follows the first tab's root pane cwd. */
  displayNameFromTerminals(terminals: ReadonlyMap<TerminalId, TerminalState>): string {
    if (this.customName !== undefined) {
      return this.customName;
    }
    const first = this.tabs[0];
    const terminalId = first?.terminalId(first.rootPane);
    const cwd = (terminalId === undefined ? undefined : terminals.get(terminalId)?.cwd) ?? this.identityCwd;
    return this.automaticDisplayNameForCwd(cwd);
  }

  resolvedIdentityCwdFrom(terminals: ReadonlyMap<TerminalId, TerminalState>): string {
    const first = this.tabs[0];
    const terminalId = first?.terminalId(first.rootPane);
    return (terminalId === undefined ? undefined : terminals.get(terminalId)?.cwd) ?? this.identityCwd;
  }

  private automaticDisplayNameForCwd(cwd: string): string {
    return cwd === this.cachedIdentityCwd ? this.cachedAutoLabel : fallbackLabelFromCwd(cwd);
  }

  // --- Internals ---

  private detachPaneFromTab(
    paneId: PaneId,
    detach: (tab: Tab) => readonly [PaneId, TerminalId] | undefined,
  ): boolean {
    const tabIdx = this.findTabIndexForPane(paneId);
    const tab = tabIdx === undefined ? undefined : this.tabs[tabIdx];
    if (tabIdx === undefined || !tab) {
      return false;
    }
    if (tab.layout.paneCount() <= 1) {
      if (this.tabs.length <= 1) {
        return true;
      }
      this.tabs.splice(tabIdx, 1);
      this.unregisterPane(paneId);
      this.adjustActiveTabAfterRemoval(tabIdx);
      return false;
    }
    const removed = detach(tab);
    if (removed) {
      this.unregisterPane(removed[0]);
    }
    return false;
  }

  private adjustActiveTabAfterRemoval(removedIdx: number): void {
    if (this.tabs.length === 0) {
      this.activeTab = 0;
    } else if (this.activeTab >= this.tabs.length) {
      this.activeTab = this.tabs.length - 1;
    } else if (removedIdx <= this.activeTab && this.activeTab > 0) {
      this.activeTab -= 1;
    }
  }

  private closeActiveTabAndReport(): boolean {
    if (this.tabs.length <= 1) {
      return true;
    }
    this.closeActiveTab();
    return false;
  }

  /** Register a pane created outside the reserve/commit flow (tests and restore paths). */
  registerNewPane(paneId: PaneId): void {
    this.registerNewPaneWithNumber(paneId, this.nextPublicPaneNumber);
  }

  private registerNewPaneWithNumber(paneId: PaneId, number: number): void {
    this.publicPaneNumbers.set(paneId, number);
    this.nextPublicPaneNumber = Math.max(this.nextPublicPaneNumber, number + 1);
  }

  private unregisterPane(paneId: PaneId): void {
    this.publicPaneNumbers.delete(paneId);
  }
}

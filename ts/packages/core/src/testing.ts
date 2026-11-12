/** Test support: state builders and invariant checks (mirrors the Rust `test_*` helpers). */

import { AppState } from "./app-state.js";
import type { Direction } from "./geometry.js";
import { allocPaneId, allocTerminalId, type PaneId, type TerminalId } from "./ids.js";
import { newPaneState } from "./pane.js";
import { newTerminalState } from "./terminal-state.js";
import { Workspace } from "./workspace.js";

export function testWorkspace(name: string, cwd = process.cwd()): Workspace {
  return Workspace.create({ cwd, customName: name }).workspace;
}

export function testSplit(workspace: Workspace, direction: Direction): PaneId {
  const tab = workspace.getActiveTab();
  if (!tab) {
    throw new Error("workspace must have a tab");
  }
  const newId = tab.layout.splitFocused(direction);
  tab.panes.set(newId, newPaneState(allocTerminalId()));
  workspace.registerNewPane(newId);
  return newId;
}

export function testAddTab(workspace: Workspace, name?: string): number {
  const reservation = workspace.reserveTab();
  const { tab } = workspace.createReservedTab(reservation, workspace.identityCwd);
  tab.customName = name;
  return workspace.commitTab(reservation, tab);
}

/**
 * Workspace whose tab positions, public numbers and raw pane ids all diverge, so identity bugs
 * that conflate them are visible.
 */
export function adversarialWorkspace(): Workspace {
  const ws = testWorkspace("adversarial-identity");
  const removedPane = testSplit(ws, "horizontal");
  testSplit(ws, "vertical");
  if (ws.closePane(removedPane)) {
    throw new Error("closing a non-last pane must not close the workspace");
  }
  allocPaneId();
  const laterPane = testSplit(ws, "horizontal");

  const removedTab = testAddTab(ws, "removed");
  const survivorTab = testAddTab(ws);
  const finalTab = testAddTab(ws);
  const survivorRoot = ws.tabs[survivorTab]?.rootPane as PaneId;
  const finalRoot = ws.tabs[finalTab]?.rootPane as PaneId;
  ws.closeTab(removedTab);
  ws.moveTab(0, ws.tabs.length);
  ws.switchTab(ws.findTabIndexForPane(survivorRoot) as number);

  if (ws.activeTab + 1 === ws.tabs[ws.activeTab]?.number) {
    throw new Error("active tab must distinguish position from public number");
  }
  if (laterPane === ws.publicPaneNumber(laterPane)) {
    throw new Error("pane must distinguish raw id from public number");
  }
  if (ws.findTabIndexForPane(finalRoot) !== 1) {
    throw new Error("final tab should sit at index 1");
  }
  return ws;
}

export function assertWorkspaceInvariants(ws: Workspace): void {
  const fail = (message: string): never => {
    throw new Error(`workspace ${ws.id}: ${message}`);
  };
  if (ws.tabs.length === 0) fail("must contain at least one tab");
  if (ws.activeTab >= ws.tabs.length) fail(`active_tab ${ws.activeTab} out of bounds`);

  const tabNumbers = new Set<number>();
  let maxTabNumber = 0;
  const livePanes = new Set<PaneId>();
  const terminalIds = new Set<TerminalId>();
  ws.tabs.forEach((tab, tabIdx) => {
    if (tab.number <= 0) fail(`tab ${tabIdx} has invalid public number 0`);
    if (tabNumbers.has(tab.number)) fail(`duplicate public tab number ${tab.number}`);
    tabNumbers.add(tab.number);
    maxTabNumber = Math.max(maxTabNumber, tab.number);
    if (!tab.panes.has(tab.rootPane)) fail(`tab ${tabIdx} root pane is missing from tab panes`);
    const layoutPanes = tab.layout.paneIds();
    const layoutSet = new Set(layoutPanes);
    if (layoutPanes.length !== layoutSet.size) fail(`tab ${tabIdx} layout has duplicate pane ids`);
    if (!layoutSet.has(tab.layout.focused())) fail(`tab ${tabIdx} focused pane is not in layout`);
    const paneSet = new Set(tab.panes.keys());
    if (layoutSet.size !== paneSet.size || [...layoutSet].some((id) => !paneSet.has(id))) {
      fail(`tab ${tabIdx} layout panes must exactly match pane states`);
    }
    for (const [paneId, pane] of tab.panes) {
      if (livePanes.has(paneId)) fail(`pane ${paneId} appears in more than one tab`);
      livePanes.add(paneId);
      if (!ws.publicPaneNumbers.has(paneId)) fail(`live pane ${paneId} has no public number`);
      if (terminalIds.has(pane.attachedTerminalId)) {
        fail(`terminal ${pane.attachedTerminalId} attached to multiple panes`);
      }
      terminalIds.add(pane.attachedTerminalId);
    }
  });
  if (ws.nextPublicTabNumber <= maxTabNumber) fail("next_public_tab_number must exceed live numbers");

  const publicKeys = new Set(ws.publicPaneNumbers.keys());
  if (publicKeys.size !== livePanes.size || [...publicKeys].some((id) => !livePanes.has(id))) {
    fail("public pane map must exactly match live panes");
  }
  const paneNumbers = new Set<number>();
  let maxPaneNumber = 0;
  for (const [paneId, number] of ws.publicPaneNumbers) {
    if (number <= 0) fail(`pane ${paneId} has invalid public number 0`);
    if (paneNumbers.has(number)) fail(`duplicate public pane number ${number}`);
    paneNumbers.add(number);
    maxPaneNumber = Math.max(maxPaneNumber, number);
  }
  if (ws.nextPublicPaneNumber <= maxPaneNumber) fail("next_public_pane_number must exceed live numbers");
}

/** Populate missing terminal metadata for every pane so tests need not build it by hand. */
export function ensureTestTerminals(state: AppState): void {
  for (const ws of state.workspaces) {
    for (const tab of ws.tabs) {
      for (const pane of tab.panes.values()) {
        if (!state.terminals.has(pane.attachedTerminalId)) {
          state.terminals.set(
            pane.attachedTerminalId,
            newTerminalState(pane.attachedTerminalId, ws.identityCwd),
          );
        }
      }
    }
  }
}

export function appStateWithWorkspaces(names: readonly string[]): AppState {
  const state = new AppState();
  for (const name of names) {
    state.workspaces.push(testWorkspace(name));
  }
  ensureTestTerminals(state);
  if (state.workspaces.length > 0) {
    state.active = 0;
    state.mode = "terminal";
  }
  return state;
}

export function appStateWithAdversarialIdentity(): AppState {
  const state = new AppState();
  state.workspaces = [adversarialWorkspace()];
  state.active = 0;
  state.selected = 0;
  ensureTestTerminals(state);
  return state;
}

export function assertAppStateInvariants(state: AppState): void {
  const fail = (message: string): never => {
    throw new Error(`app state: ${message}`);
  };
  if (state.workspaces.length === 0) {
    if (state.active !== undefined) fail("empty state must not have an active workspace");
    if (state.selected !== 0) fail("empty state should keep selected at 0");
    if (state.paneIdAliases.size > 0 || state.publicPaneIdAliases.size > 0) {
      fail("empty state must not keep pane aliases");
    }
    if (state.previousPaneFocus) fail("empty state must not keep previous pane focus");
    if (state.pluginPanes.size > 0) fail("empty state must not keep plugin pane records");
    if (state.pendingAgentNotifications.size > 0) fail("empty state must not keep notifications");
    if (state.toast?.target) fail("empty state must not keep pane-targeted toast");
    return;
  }
  if (state.selected >= state.workspaces.length) fail("selected workspace out of bounds");
  const active = state.active;
  if (active === undefined) {
    return fail("non-empty state must have an active workspace");
  }
  if (active >= state.workspaces.length) fail("active workspace out of bounds");

  const workspaceIndexById = new Map<string, number>();
  const paneIds = new Set<PaneId>();
  const attachedTerminalIds = new Set<TerminalId>();
  state.workspaces.forEach((ws, wsIdx) => {
    if (workspaceIndexById.has(ws.id)) fail(`duplicate workspace id ${ws.id}`);
    workspaceIndexById.set(ws.id, wsIdx);
    assertWorkspaceInvariants(ws);
    for (const tab of ws.tabs) {
      for (const [paneId, pane] of tab.panes) {
        if (paneIds.has(paneId)) fail(`pane ${paneId} appears in more than one workspace`);
        paneIds.add(paneId);
        if (attachedTerminalIds.has(pane.attachedTerminalId)) {
          fail(`terminal ${pane.attachedTerminalId} attached to more than one pane`);
        }
        attachedTerminalIds.add(pane.attachedTerminalId);
        if (!state.terminals.has(pane.attachedTerminalId)) {
          fail(`pane ${paneId} is attached to a missing terminal`);
        }
      }
    }
  });

  const assertLivePane = (paneId: PaneId, context: string): void => {
    if (!paneIds.has(paneId)) fail(`${context} references missing pane ${paneId}`);
  };
  const assertWorkspacePane = (workspaceId: string, paneId: PaneId, context: string): void => {
    const idx = workspaceIndexById.get(workspaceId);
    if (idx === undefined) return fail(`${context} references missing workspace ${workspaceId}`);
    if (!state.workspaces[idx]?.paneState(paneId)) {
      fail(`${context} references pane ${paneId} outside workspace ${workspaceId}`);
    }
  };
  for (const [raw, paneId] of state.paneIdAliases) assertLivePane(paneId, `raw pane alias ${raw}`);
  for (const [publicId, paneId] of state.publicPaneIdAliases) {
    assertLivePane(paneId, `public pane alias ${publicId}`);
  }
  if (state.previousPaneFocus) {
    assertWorkspacePane(state.previousPaneFocus.workspaceId, state.previousPaneFocus.paneId, "previous pane focus");
  }
  if (state.toast?.target) {
    assertWorkspacePane(state.toast.target.workspaceId, state.toast.target.paneId, "toast target");
  }
  for (const [paneId, notification] of state.pendingAgentNotifications) {
    if (paneId !== notification.paneId) fail("pending notification key must match payload pane id");
    assertWorkspacePane(notification.workspaceId, notification.paneId, "pending agent notification");
  }
  if (state.popupPane) {
    if (!state.terminals.has(state.popupPane.terminalId)) fail("popup references missing terminal");
    if (attachedTerminalIds.has(state.popupPane.terminalId)) {
      fail("popup terminal must not be attached to a tiled pane");
    }
  }
  for (const paneId of state.pluginPanes.keys()) assertLivePane(paneId, "plugin pane record");
}

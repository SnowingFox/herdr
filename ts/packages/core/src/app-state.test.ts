import { describe, expect, it } from "vitest";
import type { AppState } from "./app-state.js";
import type { PaneId } from "./ids.js";
import {
  appStateWithAdversarialIdentity,
  appStateWithWorkspaces,
  assertAppStateInvariants,
  testAddTab,
  testSplit,
} from "./testing.js";

const names = (state: AppState): string[] => state.workspaces.map((ws) => ws.displayName());
const ws = (state: AppState, idx: number) => {
  const workspace = state.workspaces[idx];
  if (!workspace) throw new Error(`missing workspace ${idx}`);
  return workspace;
};

describe("AppState workspace navigation", () => {
  it("switchWorkspace updates active and selected", () => {
    const state = appStateWithWorkspaces(["a", "b", "c"]);
    state.switchWorkspace(2);
    expect(state.active).toBe(2);
    expect(state.selected).toBe(2);
    expect(state.sessionDirty).toBe(true);
  });

  it("switchWorkspace marks panes seen", () => {
    const state = appStateWithWorkspaces(["a", "b"]);
    const pane = [...(ws(state, 1).getActiveTab()?.panes.values() ?? [])][0];
    if (!pane) throw new Error("missing pane");
    pane.seen = false;
    state.switchWorkspace(1);
    expect(pane.seen).toBe(true);
  });

  it("switchWorkspace out of bounds is a no-op", () => {
    const state = appStateWithWorkspaces(["a"]);
    state.switchWorkspace(5);
    expect(state.active).toBe(0);
  });

  it("records the previous pane focus across workspace switches", () => {
    const state = appStateWithWorkspaces(["a", "b"]);
    const before = state.currentPaneFocusTarget();
    state.switchWorkspace(1);
    expect(state.previousPaneFocus).toEqual(before);
    expect(state.currentPaneFocusTarget()?.workspaceId).toBe(ws(state, 1).id);
  });

  it("focusPaneInWorkspace switches tab, focuses the pane, and rejects the current pane", () => {
    const state = appStateWithWorkspaces(["a"]);
    const workspace = ws(state, 0);
    const tabIdx = testAddTab(workspace);
    const target = workspace.tabs[tabIdx]?.rootPane as PaneId;
    expect(state.focusPaneInWorkspace(0, target)).toBe(true);
    expect(workspace.activeTab).toBe(tabIdx);
    expect(state.currentPaneFocusTarget()?.paneId).toBe(target);
    expect(state.focusPaneInWorkspace(0, target)).toBe(false);
    expect(state.focusPaneInWorkspace(0, 9_999_999 as PaneId)).toBe(false);
  });

  it("moveWorkspace reorders without changing logical selection", () => {
    const state = appStateWithWorkspaces(["a", "b", "c"]);
    const activeId = ws(state, 1).id;
    const selectedId = ws(state, 2).id;
    state.active = 1;
    state.selected = 2;

    state.moveWorkspace(1, 0);

    expect(names(state)).toEqual(["b", "a", "c"]);
    expect(state.active).toBe(0);
    expect(state.selected).toBe(2);
    expect(ws(state, state.active ?? -1).id).toBe(activeId);
    expect(ws(state, state.selected).id).toBe(selectedId);
  });

  it("moveWorkspace accepts insert at end and rejects no-ops", () => {
    const state = appStateWithWorkspaces(["a", "b", "c"]);
    expect(state.moveWorkspace(0, state.workspaces.length)).toBe(true);
    expect(names(state)).toEqual(["b", "c", "a"]);
    expect(state.moveWorkspace(1, 1)).toBe(false);
    expect(state.moveWorkspace(9, 0)).toBe(false);
  });

  it("moveWorkspaceBlock collects non-contiguous members", () => {
    const state = appStateWithWorkspaces(["child-one", "normal", "parent", "child-two", "tail"]);
    const [childOne, parent, childTwo, tail] = [0, 2, 3, 4].map((i) => ws(state, i).id);
    state.active = 0;
    state.selected = 4;

    expect(state.moveWorkspaceBlock([parent, childOne, childTwo] as string[], tail)).toBe(true);

    expect(names(state)).toEqual(["normal", "parent", "child-one", "child-two", "tail"]);
    expect(ws(state, state.active ?? -1).id).toBe(childOne);
    expect(ws(state, state.selected).id).toBe(tail);
  });

  it("moveWorkspaceBlock rejects invalid and no-op orders", () => {
    const state = appStateWithWorkspaces(["a", "b", "c"]);
    const ids = state.workspaces.map((workspace) => workspace.id);
    const [a, b] = ids as [string, string, string];
    expect(state.moveWorkspaceBlock([])).toBe(false);
    expect(state.moveWorkspaceBlock([a, a])).toBe(false);
    expect(state.moveWorkspaceBlock(["missing"])).toBe(false);
    expect(state.moveWorkspaceBlock([a], a)).toBe(false);
    expect(state.moveWorkspaceBlock([a], b)).toBe(false);
    expect(names(state)).toEqual(["a", "b", "c"]);
  });
});

describe("AppState close workspace", () => {
  it("adjusts indices", () => {
    const state = appStateWithWorkspaces(["a", "b", "c"]);
    state.selected = 1;
    state.active = 1;
    state.closeSelectedWorkspace();
    expect(state.workspaces).toHaveLength(2);
    expect(state.selected).toBe(1);
    expect(state.active).toBe(1);
    expect(ws(state, 1).customName).toBe("c");
    assertAppStateInvariants(state);
  });

  it("closing a parent worktree workspace closes its group", () => {
    const state = appStateWithWorkspaces(["main", "issue", "notes"]);
    ws(state, 0).worktreeSpace = {
      key: "repo-key",
      label: "herdr",
      repoRoot: "/repo/herdr",
      checkoutPath: "/repo/herdr",
      isLinkedWorktree: false,
    };
    ws(state, 1).worktreeSpace = {
      key: "repo-key",
      label: "herdr",
      repoRoot: "/repo/herdr",
      checkoutPath: "/repo/herdr-issue",
      isLinkedWorktree: true,
    };
    state.selected = 0;
    state.active = 0;
    expect(state.workspaceCloseWouldCloseWorktreeGroup(0)).toBe(true);

    state.closeSelectedWorkspace();

    expect(names(state)).toEqual(["notes"]);
    expect(state.active).toBe(0);
    expect(state.selected).toBe(0);
    assertAppStateInvariants(state);
  });

  it("closing the last workspace clears active", () => {
    const state = appStateWithWorkspaces(["only"]);
    state.selected = 0;
    state.closeSelectedWorkspace();
    expect(state.workspaces).toHaveLength(0);
    expect(state.active).toBeUndefined();
    expect(state.selected).toBe(0);
    expect(state.terminals.size).toBe(0);
    assertAppStateInvariants(state);
  });

  it("closing at the end adjusts selected", () => {
    const state = appStateWithWorkspaces(["a", "b"]);
    state.selected = 1;
    state.active = 1;
    state.closeSelectedWorkspace();
    expect(state.workspaces).toHaveLength(1);
    expect(state.selected).toBe(0);
    expect(state.active).toBe(0);
  });

  it("closing a non-focused workspace keeps focus", () => {
    const state = appStateWithWorkspaces(["a", "b", "c"]);
    state.selected = 1;
    state.active = 0;
    const activeId = ws(state, 0).id;
    state.closeSelectedWorkspace();
    expect(names(state)).toEqual(["a", "c"]);
    expect(ws(state, state.active ?? -1).id).toBe(activeId);
    expect(state.selected).toBe(0);
  });

  it("queues runtime shutdown for terminals that lost their panes", () => {
    const state = appStateWithWorkspaces(["a", "b"]);
    const terminals = state.terminalIdsForWorkspace(1);
    expect(terminals).toHaveLength(1);
    state.selected = 1;
    state.closeSelectedWorkspace();
    expect(state.terminalRuntimeShutdowns).toEqual(terminals);
    for (const id of terminals) {
      expect(state.terminals.has(id)).toBe(false);
    }
  });

  it("keeps terminals still attached to a surviving pane", () => {
    const state = appStateWithWorkspaces(["a", "b"]);
    const survivor = state.terminalIdsForWorkspace(0);
    state.removeUnattachedTerminalIds(survivor);
    expect(state.terminalRuntimeShutdowns).toEqual([]);
    expect(state.terminals.size).toBe(2);
  });

  it("drops plugin pane records and stale previous focus for closed panes", () => {
    const state = appStateWithWorkspaces(["a", "b"]);
    const closingPane = state.paneIdsForWorkspace(1)[0] as PaneId;
    state.pluginPanes.set(closingPane, {});
    state.previousPaneFocus = { workspaceId: ws(state, 1).id, paneId: closingPane };
    state.selected = 1;
    state.closeSelectedWorkspace();
    expect(state.pluginPanes.size).toBe(0);
    expect(state.previousPaneFocus).toBeUndefined();
    assertAppStateInvariants(state);
  });
});

describe("AppState invariants", () => {
  it("holds for adversarial identity state after mutation", () => {
    const state = appStateWithAdversarialIdentity();
    assertAppStateInvariants(state);
    const workspace = ws(state, 0);
    testSplit(workspace, "vertical");
    state.switchWorkspaceTab(0, 0);
    workspace.moveTab(workspace.activeTab, workspace.tabs.length);
    // New panes need terminal metadata before the app-level invariants hold again.
    for (const id of state.terminalIdsForWorkspace(0)) {
      if (!state.terminals.has(id)) {
        state.terminals.set(id, { id, cwd: workspace.identityCwd, launchArgv: undefined });
      }
    }
    assertAppStateInvariants(state);
  });

  it("detects a pane attached to a missing terminal", () => {
    const state = appStateWithWorkspaces(["a"]);
    const [terminalId] = state.terminalIdsForWorkspace(0);
    if (terminalId === undefined) throw new Error("missing terminal");
    state.terminals.delete(terminalId);
    expect(() => assertAppStateInvariants(state)).toThrow(/missing terminal/);
  });

  it("closePaneWouldCloseWorkspace only for the last pane of the last tab", () => {
    const state = appStateWithWorkspaces(["a"]);
    const workspace = ws(state, 0);
    const root = workspace.tabs[0]?.rootPane as PaneId;
    expect(state.closePaneWouldCloseWorkspace(0, root)).toBe(true);
    testSplit(workspace, "horizontal");
    expect(state.closePaneWouldCloseWorkspace(0, root)).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { allocPaneId, type PaneId } from "./ids.js";
import {
  adversarialWorkspace,
  assertWorkspaceInvariants,
  testAddTab,
  testSplit,
  testWorkspace,
} from "./testing.js";
import { newTerminalState } from "./terminal-state.js";
import { fallbackLabelFromCwd } from "./workspace.js";

const at = <T>(items: readonly T[], index: number): T => {
  const item = items[index];
  if (item === undefined) {
    throw new Error(`missing item ${index}`);
  }
  return item;
};

describe("Workspace", () => {
  it("pane public numbers are stable and not reused after close", () => {
    const ws = testWorkspace("test");
    const root = at(ws.tabs, 0).rootPane;
    const second = testSplit(ws, "horizontal");
    const third = testSplit(ws, "vertical");
    expect(ws.publicPaneNumber(root)).toBe(1);
    expect(ws.publicPaneNumber(second)).toBe(2);
    expect(ws.publicPaneNumber(third)).toBe(3);

    expect(ws.closePane(second)).toBe(false);
    expect(ws.publicPaneNumber(root)).toBe(1);
    expect(ws.publicPaneNumber(second)).toBeUndefined();
    expect(ws.publicPaneNumber(third)).toBe(3);

    const fourth = testSplit(ws, "horizontal");
    expect(ws.publicPaneNumber(fourth)).toBe(4);
  });

  it("tab public numbers are stable and not reused after close", () => {
    const ws = testWorkspace("test");
    const firstRoot = at(ws.tabs, 0).rootPane;
    const secondTab = testAddTab(ws);
    const secondRoot = at(ws.tabs, secondTab).rootPane;
    const thirdTab = testAddTab(ws);
    const thirdRoot = at(ws.tabs, thirdTab).rootPane;

    expect(ws.publicTabNumberForPane(firstRoot)).toBe(1);
    expect(ws.publicTabNumberForPane(secondRoot)).toBe(2);
    expect(ws.publicTabNumberForPane(thirdRoot)).toBe(3);

    expect(ws.closeTab(secondTab)).toBe(true);
    expect(ws.publicTabNumberForPane(firstRoot)).toBe(1);
    expect(ws.publicTabNumberForPane(thirdRoot)).toBe(3);

    const fourthTab = testAddTab(ws);
    expect(ws.publicTabNumberForPane(at(ws.tabs, fourthTab).rootPane)).toBe(4);
    assertWorkspaceInvariants(ws);
  });

  it("adversarial identity state satisfies invariants after mutation", () => {
    const ws = adversarialWorkspace();
    assertWorkspaceInvariants(ws);

    const activePublic = at(ws.tabs, ws.activeTab).number;
    expect(ws.activeTab + 1).not.toBe(activePublic);
    const divergent = [...ws.publicPaneNumbers].find(([paneId, number]) => paneId !== number);
    expect(divergent).toBeDefined();

    const newPane = testSplit(ws, "vertical");
    expect(ws.publicPaneNumber(newPane)).toBeDefined();
    expect(ws.moveTab(ws.activeTab, ws.tabs.length)).toBe(true);
    assertWorkspaceInvariants(ws);
  });

  it("a failed moved-pane insert returns the pane for recovery", () => {
    const source = testWorkspace("source");
    const sourcePane = at(source.tabs, 0).rootPane;
    const taken = source.takePaneForMove(sourcePane);
    expect(taken).toBeDefined();
    if (!taken) return;
    const target = testWorkspace("target");
    const missingTarget = allocPaneId();

    const result = target.insertMovedPaneIntoTab(0, missingTarget, taken.moved, "horizontal", 0.5, true);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.moved.paneId).toBe(sourcePane);
    }
    expect(at(target.tabs, 0).panes.has(sourcePane)).toBe(false);
  });

  it("moving a pane between workspaces keeps invariants", () => {
    const source = testWorkspace("source");
    const extra = testSplit(source, "horizontal");
    const target = testWorkspace("target");
    const taken = source.takePaneForMove(extra);
    expect(taken?.removedTabIdx).toBeUndefined();
    if (!taken) return;
    const targetRoot = at(target.tabs, 0).rootPane;
    const inserted = target.insertMovedPaneIntoTab(0, targetRoot, taken.moved, "vertical", 0.5, true);
    expect(inserted.ok).toBe(true);
    source.unregisterMovedPane(extra);
    assertWorkspaceInvariants(source);
    assertWorkspaceInvariants(target);
    expect(target.publicPaneNumber(extra)).toBe(2);
  });

  it("taking the only pane of a tab removes that tab", () => {
    const ws = testWorkspace("multi");
    const secondTab = testAddTab(ws);
    const root = at(ws.tabs, secondTab).rootPane;
    const taken = ws.takePaneForMove(root);
    expect(taken).toMatchObject({ removedTabIdx: secondTab, workspaceEmpty: false });
    expect(ws.tabs).toHaveLength(1);
  });

  it("moving a tab keeps active identity and stable tab numbers", () => {
    const ws = testWorkspace("test");
    const movedRoot = at(ws.tabs, 0).rootPane;
    testAddTab(ws, "foo");
    const finalAutoIdx = testAddTab(ws);
    const activeRoot = at(ws.tabs, finalAutoIdx).rootPane;
    ws.switchTab(finalAutoIdx);

    expect(ws.moveTab(0, ws.tabs.length)).toBe(true);

    const labels = ws.tabs.map((_, idx) => ws.tabDisplayName(idx));
    expect(labels).toEqual(["foo", "2", "3"]);
    expect(at(ws.tabs, 0).customName).toBe("foo");
    expect(at(ws.tabs, 1).customName).toBeUndefined();
    expect(at(ws.tabs, 2).customName).toBeUndefined();
    expect(ws.tabs.map((tab) => tab.number)).toEqual([2, 3, 1]);
    expect(at(ws.tabs, 2).rootPane).toBe(movedRoot);
    expect(at(ws.tabs, ws.activeTab).rootPane).toBe(activeRoot);
    assertWorkspaceInvariants(ws);
  });

  it("split reservations leave no trace when rolled back", () => {
    const ws = testWorkspace("split");
    const tab = at(ws.tabs, 0);
    const root = tab.rootPane;
    const before = tab.layout.paneIds();
    const reservation = ws.reserveSplit(root, "horizontal");
    expect(reservation).toBeDefined();
    if (!reservation) return;
    expect(tab.layout.paneIds()).toHaveLength(2);
    ws.rollbackSplit(reservation);
    expect(tab.layout.paneIds()).toEqual(before);
    expect(ws.nextPublicPaneNumber).toBe(2);
    assertWorkspaceInvariants(ws);
  });

  it("committed splits register the pane, honor focus and clear zoom", () => {
    const ws = testWorkspace("split");
    const tab = at(ws.tabs, 0);
    tab.zoomed = true;
    const reservation = ws.reserveSplit(tab.rootPane, "vertical", 0.4);
    expect(reservation).toBeDefined();
    if (!reservation) return;
    const created = ws.commitSplit(reservation, { focus: true, cwd: "/tmp/x" });
    expect(created).toBeDefined();
    if (!created) return;
    expect(ws.publicPaneNumber(created.paneId)).toBe(2);
    expect(tab.layout.focused()).toBe(created.paneId);
    expect(tab.zoomed).toBe(false);
    expect(created.terminal.cwd).toBe("/tmp/x");
    assertWorkspaceInvariants(ws);
  });

  it("burns the tab number when a reserved tab is never committed", () => {
    const ws = testWorkspace("burn");
    ws.reserveTab();
    const reservation = ws.reserveTab();
    expect(reservation.number).toBe(3);
    const { tab } = ws.createReservedTab(reservation, "/tmp");
    ws.commitTab(reservation, tab);
    expect(ws.publicTabNumber(1)).toBe(3);
    assertWorkspaceInvariants(ws);
  });

  it("closing the focused pane of a single-pane workspace reports close", () => {
    const ws = testWorkspace("solo");
    expect(ws.closeFocused()).toBe(true);
    testAddTab(ws);
    expect(ws.closeFocused()).toBe(false);
    expect(ws.tabs).toHaveLength(1);
  });

  it("closeFocused on a multi-pane tab removes only the focused pane", () => {
    const ws = testWorkspace("multi-pane");
    const second = testSplit(ws, "horizontal");
    expect(ws.closeFocused()).toBe(false);
    expect(ws.publicPaneNumber(second)).toBeUndefined();
    expect(at(ws.tabs, 0).layout.paneCount()).toBe(1);
  });

  it("switching tabs marks its panes seen", () => {
    const ws = testWorkspace("seen");
    const idx = testAddTab(ws);
    const pane = [...at(ws.tabs, idx).panes.values()][0];
    expect(pane).toBeDefined();
    if (!pane) return;
    pane.seen = false;
    ws.switchTab(idx);
    expect(pane.seen).toBe(true);
  });

  it("findTabIndexForPane and terminalId resolve across tabs", () => {
    const ws = testWorkspace("lookup");
    const idx = testAddTab(ws);
    const root = at(ws.tabs, idx).rootPane;
    expect(ws.findTabIndexForPane(root)).toBe(idx);
    expect(ws.terminalId(root)).toBe(at(ws.tabs, idx).terminalId(root));
    expect(ws.findTabIndexForPane(9_999_999 as PaneId)).toBeUndefined();
  });
});

describe("workspace labels", () => {
  it("labels follow cached identity without touching the filesystem", () => {
    const ws = testWorkspace("ignored");
    ws.customName = undefined;
    ws.identityCwd = "/deep/nested";
    ws.cachedIdentityCwd = "/deep/nested";
    ws.cachedAutoLabel = "cached-repo";
    expect(ws.displayName()).toBe("cached-repo");
  });

  it("terminal-aware display name uses the latest admitted identity cache", () => {
    const ws = testWorkspace("ignored");
    const root = at(ws.tabs, 0).rootPane;
    const terminalId = ws.terminalId(root);
    expect(terminalId).toBeDefined();
    if (terminalId === undefined) return;
    ws.customName = undefined;
    ws.identityCwd = "/old/workspace";
    ws.cachedIdentityCwd = "/new/repo/deep";
    ws.cachedAutoLabel = "repo";
    const terminals = new Map([[terminalId, newTerminalState(terminalId, "/new/repo/deep")]]);
    expect(ws.displayNameFromTerminals(terminals)).toBe("repo");
    expect(ws.displayName()).toBe("workspace");
  });

  it("identity follows the first tab root pane cwd", () => {
    const ws = testWorkspace("ignored");
    ws.customName = undefined;
    const terminalId = ws.terminalId(at(ws.tabs, 0).rootPane);
    if (terminalId === undefined) throw new Error("missing terminal");
    const terminals = new Map([[terminalId, newTerminalState(terminalId, "/herdr-test/pion")]]);
    expect(ws.displayNameFromTerminals(terminals)).toBe("pion");
    expect(ws.resolvedIdentityCwdFrom(terminals)).toBe("/herdr-test/pion");
  });

  it("falls back to ~ for home and the last path segment otherwise", () => {
    expect(fallbackLabelFromCwd("/home/me", "/home/me")).toBe("~");
    expect(fallbackLabelFromCwd("/home/me/project", "/home/me")).toBe("project");
    expect(fallbackLabelFromCwd("C:\\work\\repo", "")).toBe("repo");
    expect(fallbackLabelFromCwd("/", "")).toBe("/");
  });
});

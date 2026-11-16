import { describe, expect, it } from "vitest";
import { type Direction, type NavDirection, type Rect, Borders, rect } from "./geometry.js";
import { allocPaneId, type PaneId, paneIdFromRaw } from "./ids.js";
import {
  findInDirection,
  type Node,
  paneNode,
  type PaneInfo,
  splitNode,
  TileLayout,
} from "./layout.js";

const pane = paneIdFromRaw;
const AREA = rect(0, 0, 100, 40);

function sampleLayout(): TileLayout {
  return TileLayout.fromSaved(
    {
      kind: "split",
      direction: "horizontal",
      ratio: Math.fround(0.3),
      first: paneNode(pane(1)),
      second: {
        kind: "split",
        direction: "vertical",
        ratio: Math.fround(0.6),
        first: paneNode(pane(2)),
        second: {
          kind: "split",
          direction: "horizontal",
          ratio: Math.fround(0.4),
          first: paneNode(pane(3)),
          second: paneNode(pane(4)),
        },
      },
    },
    pane(2),
  );
}

function paneRects(layout: TileLayout): Array<[PaneId, Rect]> {
  return layout.panes(AREA).map((info) => [info.id, info.rect]);
}

function paneRect(layout: TileLayout, id: PaneId): Rect {
  const found = paneRects(layout).find(([candidate]) => candidate === id);
  if (!found) {
    throw new Error("pane should exist");
  }
  return found[1];
}

function splitSnapshot(layout: TileLayout): Array<[Direction, number]> {
  const out: Array<[Direction, number]> = [];
  const collect = (node: Node): void => {
    if (node.kind === "split") {
      out.push([node.direction, node.ratio]);
      collect(node.first);
      collect(node.second);
    }
  };
  collect(layout.root());
  return out;
}

function ratioAt(layout: TileLayout, index: number): number {
  return splitSnapshot(layout)[index]?.[1] ?? Number.NaN;
}

function paneInfo(id: number, r: Rect, isFocused = false): PaneInfo {
  return {
    id: pane(id),
    rect: r,
    innerRect: r,
    scrollbarRect: undefined,
    borders: Borders.NONE,
    isFocused,
  };
}

describe("TileLayout", () => {
  it("split paths preserve preorder geometry and resize targets", () => {
    const ids = [allocPaneId(), allocPaneId(), allocPaneId(), allocPaneId()] as [
      PaneId,
      PaneId,
      PaneId,
      PaneId,
    ];
    const layout = TileLayout.fromSaved(
      {
        kind: "split",
        direction: "horizontal",
        ratio: 0.5,
        first: splitNode(ids[0], "vertical", ids[1], 0.5),
        second: splitNode(ids[2], "vertical", ids[3], 0.25),
      },
      ids[0],
    );
    const area = rect(3, 7, 120, 80);
    const splits = layout.splits(area);
    expect(splits).toHaveLength(3);
    const expected: Array<[boolean[], Direction, number, Rect]> = [
      [[], "horizontal", 63, area],
      [[false], "vertical", 47, rect(3, 7, 60, 80)],
      [[true], "vertical", 27, rect(63, 7, 60, 80)],
    ];
    splits.forEach((split, i) => {
      const [path, direction, pos, splitArea] = expected[i] as (typeof expected)[number];
      expect([split.path, split.direction, split.pos, split.area]).toEqual([
        path,
        direction,
        pos,
        splitArea,
      ]);
    });
    expect(layout.setRatioAt(splits[2]?.path ?? [], 0.5)).toBe(true);
    const resized = layout.splits(area);
    expect(resized[1]?.pos).toBe(splits[1]?.pos);
    expect(resized[2]?.pos).toBe(47);
  });

  it("rejected splits and insertions preserve layout and focus history", () => {
    const { layout, rootId: root } = TileLayout.create();
    const second = layout.splitFocused("horizontal");
    const absent = allocPaneId();
    const before = paneRects(layout);
    const splits = splitSnapshot(layout);
    expect(layout.splitPane(absent, "vertical", 0.5)).toBeUndefined();
    for (const [target, moved] of [
      [absent, allocPaneId()],
      [root, second],
      [root, root],
    ] as const) {
      expect(layout.insertPaneNear(target, moved, "vertical", 0.3, true)).toBe(false);
    }
    expect(paneRects(layout)).toEqual(before);
    expect(splitSnapshot(layout)).toEqual(splits);
    expect(layout.focused()).toBe(second);
    expect(layout.previousFocus()).toBe(root);
    expect(layout.closeFocused()).toBe(true);
    expect(layout.focused()).toBe(root);
  });

  it("splitting a deep leaf preserves other branches and focus", () => {
    const { layout, rootId: root } = TileLayout.create();
    const right = layout.splitPane(root, "horizontal", 0.6) as PaneId;
    const bottomLeft = layout.splitPane(root, "vertical", 0.4) as PaneId;
    const rightRect = paneRect(layout, right);
    const focus = layout.focused();
    const created = layout.splitPane(bottomLeft, "horizontal", Number.NaN) as PaneId;
    expect(layout.paneIds()).toEqual([root, bottomLeft, created, right]);
    expect(paneRect(layout, right)).toEqual(rightRect);
    expect(layout.focused()).toBe(focus);
    expect(splitSnapshot(layout)).toEqual([
      ["horizontal", Math.fround(0.6)],
      ["vertical", Math.fround(0.4)],
      ["horizontal", 0.5],
    ]);
  });

  it("swap panes exchanges leaf ids without changing cells", () => {
    const layout = sampleLayout();
    const beforeRects = paneRects(layout);
    const beforeSplits = splitSnapshot(layout);
    expect(layout.swapPanes(pane(2), pane(4))).toBe(true);
    expect(layout.paneCount()).toBe(4);
    expect(splitSnapshot(layout)).toEqual(beforeSplits);
    expect(layout.focused()).toBe(pane(2));
    const afterRects = paneRects(layout);
    expect(afterRects[0]).toEqual(beforeRects[0]);
    expect(afterRects[1]).toEqual([pane(4), beforeRects[1]?.[1]]);
    expect(afterRects[2]).toEqual(beforeRects[2]);
    expect(afterRects[3]).toEqual([pane(2), beforeRects[3]?.[1]]);
  });

  it("swap panes is a no-op for same or missing pane", () => {
    const layout = sampleLayout();
    const beforeRects = paneRects(layout);
    const beforeSplits = splitSnapshot(layout);
    const beforeFocus = layout.focused();
    expect(layout.swapPanes(pane(2), pane(2))).toBe(false);
    expect(layout.swapPanes(pane(2), pane(99))).toBe(false);
    expect(layout.swapPanes(pane(99), pane(2))).toBe(false);
    expect(paneRects(layout)).toEqual(beforeRects);
    expect(splitSnapshot(layout)).toEqual(beforeSplits);
    expect(layout.focused()).toBe(beforeFocus);
  });

  it("inserting an existing pane near a target focuses the moved pane", () => {
    const { layout, rootId: root } = TileLayout.create();
    const moved = pane(99);
    expect(layout.insertPaneNear(root, moved, "horizontal", 0.25, true)).toBe(true);
    expect(layout.paneCount()).toBe(2);
    expect(layout.paneIds()).toEqual([root, moved]);
    expect(layout.focused()).toBe(moved);
    expect(splitSnapshot(layout)).toEqual([["horizontal", 0.25]]);
    expect(paneRect(layout, root)).toEqual(rect(0, 0, 25, 40));
    expect(paneRect(layout, moved)).toEqual(rect(25, 0, 75, 40));
  });

  it("splitFocused with a ratio sets the new split ratio", () => {
    const { layout, rootId: root } = TileLayout.create();
    layout.focusPane(root);
    layout.splitFocused("horizontal", 0.333);
    const splits = splitSnapshot(layout);
    expect(splits).toHaveLength(1);
    expect(splits[0]?.[0]).toBe("horizontal");
    expect(ratioAt(layout, 0)).toBeCloseTo(0.333, 6);
  });

  it("resizePane preserves focus and reports change", () => {
    const layout = sampleLayout();
    const originalFocus = layout.focused();
    expect(layout.resizePane(pane(1), "right", 0.05, AREA)).toBe(true);
    expect(layout.focused()).toBe(originalFocus);
    expect(splitSnapshot(layout)[0]?.[0]).toBe("horizontal");
    expect(ratioAt(layout, 0)).toBeCloseTo(0.35, 6);
  });

  it("resizing the second child toward the split decreases the ratio", () => {
    const { layout, rootId: root } = TileLayout.create();
    const right = layout.splitFocused("horizontal");
    layout.focusPane(root);
    expect(layout.resizePane(right, "left", 0.05, AREA)).toBe(true);
    expect(ratioAt(layout, 0)).toBeCloseTo(0.45, 6);
    expect(layout.focused()).toBe(root);
  });

  it("resizing outer edges shrinks the focused pane", () => {
    const cases: Array<[Direction, NavDirection, boolean, number]> = [
      ["horizontal", "left", true, 0.45],
      ["horizontal", "right", false, 0.55],
      ["vertical", "up", true, 0.45],
      ["vertical", "down", false, 0.55],
    ];
    for (const [direction, nav, firstPane, expected] of cases) {
      const { layout, rootId } = TileLayout.create();
      const second = layout.splitFocused(direction);
      const target = firstPane ? rootId : second;
      expect(layout.resizePane(target, nav, 0.05, AREA)).toBe(true);
      expect(splitSnapshot(layout)[0]?.[0]).toBe(direction);
      expect(ratioAt(layout, 0)).toBeCloseTo(expected, 6);
    }
  });

  it("resize falls back to an ancestor split of the same axis", () => {
    const build = (outer: Direction, inner: Direction, outerRatio: number): TileLayout =>
      TileLayout.fromSaved(
        {
          kind: "split",
          direction: outer,
          ratio: Math.fround(outerRatio),
          first: {
            kind: "split",
            direction: inner,
            ratio: 0.5,
            first: paneNode(pane(1)),
            second: paneNode(pane(2)),
          },
          second: paneNode(pane(3)),
        },
        pane(1),
      );

    const horizontal = build("horizontal", "vertical", 0.6);
    const beforeH = paneRect(horizontal, pane(1));
    expect(horizontal.resizePane(pane(1), "left", 0.05, AREA)).toBe(true);
    const afterH = paneRect(horizontal, pane(1));
    expect(afterH.height).toBe(beforeH.height);
    expect(afterH.width).toBeLessThan(beforeH.width);
    expect(ratioAt(horizontal, 0)).toBeCloseTo(0.55, 6);
    expect(splitSnapshot(horizontal)[1]).toEqual(["vertical", 0.5]);

    const vertical = build("vertical", "horizontal", 0.6);
    const beforeV = paneRect(vertical, pane(1));
    expect(vertical.resizePane(pane(1), "up", 0.05, AREA)).toBe(true);
    const afterV = paneRect(vertical, pane(1));
    expect(afterV.width).toBe(beforeV.width);
    expect(afterV.height).toBeLessThan(beforeV.height);
    expect(ratioAt(vertical, 0)).toBeCloseTo(0.55, 6);
    expect(splitSnapshot(vertical)[1]).toEqual(["horizontal", 0.5]);
  });

  it("resize uses the split in the same branch when borders share a coordinate", () => {
    const layout = TileLayout.fromSaved(
      {
        kind: "split",
        direction: "vertical",
        ratio: 0.5,
        first: {
          kind: "split",
          direction: "horizontal",
          ratio: 0.5,
          first: paneNode(pane(1)),
          second: paneNode(pane(2)),
        },
        second: {
          kind: "split",
          direction: "horizontal",
          ratio: 0.5,
          first: paneNode(pane(3)),
          second: paneNode(pane(4)),
        },
      },
      pane(3),
    );
    expect(layout.resizePane(pane(3), "right", 0.05, AREA)).toBe(true);
    const splits = splitSnapshot(layout);
    expect(splits[0]).toEqual(["vertical", 0.5]);
    expect(splits[1]).toEqual(["horizontal", 0.5]);
    expect(splits[2]?.[0]).toBe("horizontal");
    expect(ratioAt(layout, 2)).toBeCloseTo(0.55, 6);
  });

  it("findInDirection tiebreaks by larger overlap before layout order", () => {
    const focused = paneInfo(1, rect(10, 10, 10, 10), true);
    const smallOverlapFirst = paneInfo(2, rect(0, 10, 10, 2));
    const largerOverlapSecond = paneInfo(3, rect(0, 10, 10, 8));
    expect(
      findInDirection(focused, "left", [focused, smallOverlapFirst, largerOverlapSecond]),
    ).toBe(pane(3));
  });

  describe("focus history", () => {
    it("closeFocused returns to the pane focus came from", () => {
      const layout = sampleLayout();
      layout.focusPane(pane(4));
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(2));
    });

    it("closeFocused returns to the pane that opened a split", () => {
      const { layout, rootId: first } = TileLayout.create();
      const second = layout.splitFocused("horizontal");
      const third = layout.splitFocused("vertical");
      expect(layout.paneIds()).toHaveLength(3);
      layout.focusPane(first);
      const opened = layout.splitFocused("horizontal");
      expect(layout.focused()).toBe(opened);
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(first);
      expect(layout.paneIds()).toContain(second);
      expect(layout.paneIds()).toContain(third);
    });

    it("closing a background pane keeps the focused pane history", () => {
      const layout = sampleLayout();
      layout.focusPane(pane(4));
      expect(layout.closePane(pane(1))).toBe(true);
      expect(layout.focused()).toBe(pane(4));
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(2));
    });

    it("closing the remembered pane drops the focus history", () => {
      const layout = sampleLayout();
      layout.focusPane(pane(4));
      expect(layout.closePane(pane(2))).toBe(true);
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(3));
    });

    it("closeFocused uses tree order without focus history", () => {
      const layout = sampleLayout();
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(3));
    });

    it("closeFocused does not reuse history after it is consumed", () => {
      const layout = sampleLayout();
      layout.focusPane(pane(4));
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(2));
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(3));
    });

    it("resize does not disturb the close focus target", () => {
      const layout = sampleLayout();
      layout.focusPane(pane(4));
      layout.resizePane(pane(1), "right", 0.05, AREA);
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(2));
    });

    it("splitPane leaves focus and history untouched", () => {
      const layout = sampleLayout();
      layout.focusPane(pane(4));
      const created = layout.splitPane(pane(1), "horizontal", 0.5);
      expect(created).toBeDefined();
      expect(layout.paneIds()).toContain(created);
      expect(layout.focused()).toBe(pane(4));
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(2));
    });

    it("splitPane with a missing target changes nothing", () => {
      const layout = sampleLayout();
      const ids = layout.paneIds();
      expect(layout.splitPane(pane(99), "horizontal", 0.5)).toBeUndefined();
      expect(layout.paneIds()).toEqual(ids);
    });

    it("insertPaneNear unfocused keeps focus and history", () => {
      const layout = sampleLayout();
      layout.focusPane(pane(4));
      expect(layout.insertPaneNear(pane(1), pane(9), "horizontal", 0.5, false)).toBe(true);
      expect(layout.focused()).toBe(pane(4));
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(2));
    });

    it("failed split rollback preserves focus history", () => {
      const layout = sampleLayout();
      layout.focusPane(pane(4));
      const created = layout.splitPane(layout.focused(), "horizontal", 0.5) as PaneId;
      expect(layout.closePane(created)).toBe(true);
      expect(layout.focused()).toBe(pane(4));
      expect(layout.closeFocused()).toBe(true);
      expect(layout.focused()).toBe(pane(2));
    });
  });

  it("rounds pane widths from f32 ratios like the Rust layout", () => {
    const { layout, rootId } = TileLayout.create();
    layout.splitPane(rootId, "horizontal", 0.335);
    expect(paneRect(layout, rootId).width).toBe(34);
  });
});

/**
 * BSP tree layout for tiling panes within a tab. Port of `src/layout.rs`.
 *
 * Split ratios are `f32` in the Rust implementation; every ratio and product here goes through
 * `Math.fround` so rounding decisions (pane widths, resize steps) match bit for bit.
 */

import {
  Borders,
  type Direction,
  type NavDirection,
  type Rect,
  rect,
  roundHalfAwayFromZero,
  saturatingSub,
} from "./geometry.js";
import { allocPaneId, type PaneId } from "./ids.js";

const f32 = Math.fround;
const MIN_RATIO = f32(0.1);
const MAX_RATIO = f32(0.9);
const DEFAULT_RATIO = f32(0.5);

export interface PaneInfo {
  readonly id: PaneId;
  /** Outer rect (including borders if present). */
  readonly rect: Rect;
  /** Inner rect (content area, excluding borders). */
  readonly innerRect: Rect;
  readonly scrollbarRect: Rect | undefined;
  /** `Borders` bit flags drawn around this pane after UI chrome is applied. */
  readonly borders: number;
  readonly isFocused: boolean;
}

export interface SplitBorder {
  /** Divider position: x for a horizontal split, y for a vertical one. */
  readonly pos: number;
  readonly direction: Direction;
  /** Ratio assigned to the first child. */
  readonly ratio: number;
  /** Total area of the split node. */
  readonly area: Rect;
  /** Path from the root (false = first child, true = second). */
  readonly path: readonly boolean[];
}

export type Node =
  | { readonly kind: "pane"; readonly id: PaneId }
  | {
      readonly kind: "split";
      readonly direction: Direction;
      readonly ratio: number;
      readonly first: Node;
      readonly second: Node;
    };

export function paneNode(id: PaneId): Node {
  return { kind: "pane", id };
}

export function splitNode(
  target: PaneId,
  direction: Direction,
  newId: PaneId,
  ratio: number,
): Node {
  return {
    kind: "split",
    direction,
    ratio: validSplitRatio(ratio),
    first: paneNode(target),
    second: paneNode(newId),
  };
}

export function validSplitRatio(ratio: number): number {
  if (!Number.isFinite(ratio)) {
    return DEFAULT_RATIO;
  }
  return clampRatio(f32(ratio));
}

function clampRatio(ratio: number): number {
  return Math.min(Math.max(ratio, MIN_RATIO), MAX_RATIO);
}

export class TileLayout {
  private rootNode: Node;
  private focus: PaneId;
  /**
   * Pane focused before `focus`, used by `closeFocused`. Only a real focus move writes it; tree
   * edits go through target-taking primitives so internal focus excursions never corrupt it.
   */
  private prevFocus: PaneId | undefined;

  private constructor(root: Node, focus: PaneId, prevFocus: PaneId | undefined) {
    this.rootNode = root;
    this.focus = focus;
    this.prevFocus = prevFocus;
  }

  /** New layout with one pane (globally unique id). Returns the layout and its root pane id. */
  static create(): { layout: TileLayout; rootId: PaneId } {
    const rootId = allocPaneId();
    return { layout: new TileLayout(paneNode(rootId), rootId, undefined), rootId };
  }

  /** Reconstruct a layout from a saved tree. */
  static fromSaved(root: Node, focus: PaneId): TileLayout {
    return new TileLayout(root, focus, undefined);
  }

  private setFocus(id: PaneId): void {
    if (id !== this.focus) {
      this.prevFocus = this.focus;
      this.focus = id;
    }
  }

  focused(): PaneId {
    return this.focus;
  }

  /** Pane focused before the current one, when it still matters for `closeFocused`. */
  previousFocus(): PaneId | undefined {
    return this.prevFocus;
  }

  paneCount(): number {
    return countPanes(this.rootNode);
  }

  panes(area: Rect): PaneInfo[] {
    const result: PaneInfo[] = [];
    collectPanes(this.rootNode, area, this.focus, result);
    return result;
  }

  splits(area: Rect): SplitBorder[] {
    const result: SplitBorder[] = [];
    collectSplits(this.rootNode, area, [], result);
    return result;
  }

  /** Split the focused pane and focus the new pane. Production splits flow through `Tab`. */
  splitFocused(direction: Direction, ratio = 0.5): PaneId {
    const newId = this.splitPane(this.focus, direction, ratio);
    if (newId === undefined) {
      throw new Error("focused pane is in the layout");
    }
    this.setFocus(newId);
    return newId;
  }

  /** Split `target` without moving focus. Returns the new pane id, or undefined when absent. */
  splitPane(target: PaneId, direction: Direction, ratio: number): PaneId | undefined {
    if (!containsPane(this.rootNode, target)) {
      return undefined;
    }
    const newId = allocPaneId();
    this.rootNode = replacePane(
      this.rootNode,
      target,
      splitNode(target, direction, newId, ratio),
    );
    return newId;
  }

  /**
   * Insert an existing pane id next to a target pane without allocating a pane. When `focus` is
   * false, focus and its history are left untouched.
   */
  insertPaneNear(
    target: PaneId,
    moved: PaneId,
    direction: Direction,
    ratio: number,
    focus: boolean,
  ): boolean {
    if (target === moved) {
      return false;
    }
    if (containsPane(this.rootNode, moved) || !containsPane(this.rootNode, target)) {
      return false;
    }
    this.rootNode = replacePane(this.rootNode, target, splitNode(target, direction, moved, ratio));
    if (focus) {
      this.setFocus(moved);
    }
    return true;
  }

  /**
   * Close the focused pane, returning focus to the pane it came from when that pane is still
   * open. Returns false if it is the last pane.
   */
  closeFocused(): boolean {
    if (this.paneCount() <= 1) {
      return false;
    }
    const target = this.focus;
    const ids = this.paneIds();
    const pos = ids.indexOf(target);
    const next = ids[pos + 1];
    const ordered = next !== undefined ? next : ids[pos - 1];
    if (ordered === undefined) {
      return false;
    }
    const prev = this.prevFocus;
    const newFocus = prev !== undefined && prev !== target && ids.includes(prev) ? prev : ordered;
    const newRoot = removePane(this.rootNode, target);
    if (newRoot === undefined) {
      return false;
    }
    this.rootNode = newRoot;
    this.focus = newFocus;
    this.prevFocus = undefined;
    return true;
  }

  /** Close any pane. Focus and its history are untouched unless the closed pane is focused. */
  closePane(id: PaneId): boolean {
    if (this.focus === id) {
      return this.closeFocused();
    }
    if (this.paneCount() <= 1 || !this.paneIds().includes(id)) {
      return false;
    }
    const newRoot = removePane(this.rootNode, id);
    if (newRoot === undefined) {
      return false;
    }
    this.rootNode = newRoot;
    if (this.prevFocus === id) {
      this.prevFocus = undefined;
    }
    return true;
  }

  focusPane(id: PaneId): void {
    if (this.paneIds().includes(id)) {
      this.setFocus(id);
    }
  }

  /** Swap two pane ids while preserving split shape and ratios. */
  swapPanes(first: PaneId, second: PaneId): boolean {
    if (first === second) {
      return false;
    }
    const ids = this.paneIds();
    if (!ids.includes(first) || !ids.includes(second)) {
      return false;
    }
    this.rootNode = swapPaneIds(this.rootNode, first, second);
    return true;
  }

  /** Set the ratio of the split node at `path`. */
  setRatioAt(path: readonly boolean[], ratio: number): boolean {
    const updated = setRatioAt(this.rootNode, path, clampRatio(f32(ratio)));
    if (updated === undefined) {
      return false;
    }
    this.rootNode = updated;
    return true;
  }

  /** Adjust the nearest split in `nav` direction for the focused pane. */
  resizeFocused(nav: NavDirection, delta: number, area: Rect): void {
    const panes = this.panes(area);
    const focused = panes.find((pane) => pane.isFocused);
    if (!focused) {
      return;
    }
    const focusedRect = focused.rect;
    const splits = this.splits(area);
    const targetDirection: Direction =
      nav === "left" || nav === "right" ? "horizontal" : "vertical";
    const grows = nav === "right" || nav === "down";

    const best =
      nearestResizeSplit(splits, targetDirection, focusedRect, nav) ??
      nearestResizeSplit(splits, targetDirection, focusedRect, oppositeDirection(nav));
    if (!best) {
      return;
    }
    const currentRatio = getRatioAt(this.rootNode, best.path) ?? DEFAULT_RATIO;
    const step = f32(delta);
    const adjustment = grows ? step : -step;
    this.setRatioAt(best.path, f32(currentRatio + adjustment));
  }

  resizePane(paneId: PaneId, nav: NavDirection, delta: number, area: Rect): boolean {
    if (!this.paneIds().includes(paneId)) {
      return false;
    }
    const before = splitRatios(this.rootNode);
    const previousFocus = this.focus;
    this.focus = paneId;
    this.resizeFocused(nav, delta, area);
    this.focus = previousFocus;
    const after = splitRatios(this.rootNode);
    return !sameRatios(before, after);
  }

  paneIds(): PaneId[] {
    const ids: PaneId[] = [];
    collectIds(this.rootNode, ids);
    return ids;
  }

  /** Tree root for serialization. Nodes are immutable. */
  root(): Node {
    return this.rootNode;
  }
}

// --- Directional pane navigation ---

/** Nearest pane in `direction` from `focused`. */
export function findInDirection(
  focused: PaneInfo,
  direction: NavDirection,
  panes: readonly PaneInfo[],
): PaneId | undefined {
  const fr = focused.rect;
  let best: { key: [number, number, number, number]; id: PaneId } | undefined;

  panes.forEach((pane, index) => {
    if (pane.id === focused.id) {
      return;
    }
    const r = pane.rect;
    const candidate = (() => {
      switch (direction) {
        case "left":
          return r.x + r.width <= fr.x && rangesOverlap(r.y, r.height, fr.y, fr.height);
        case "right":
          return r.x >= fr.x + fr.width && rangesOverlap(r.y, r.height, fr.y, fr.height);
        case "up":
          return r.y + r.height <= fr.y && rangesOverlap(r.x, r.width, fr.x, fr.width);
        case "down":
          return r.y >= fr.y + fr.height && rangesOverlap(r.x, r.width, fr.x, fr.width);
      }
    })();
    if (!candidate) {
      return;
    }
    const horizontal = direction === "left" || direction === "right";
    const edgeDistance = (() => {
      switch (direction) {
        case "left":
          return saturatingSub(fr.x, r.x + r.width);
        case "right":
          return saturatingSub(r.x, fr.x + fr.width);
        case "up":
          return saturatingSub(fr.y, r.y + r.height);
        case "down":
          return saturatingSub(r.y, fr.y + fr.height);
      }
    })();
    const overlap = horizontal
      ? rangeOverlapAmount(r.y, r.height, fr.y, fr.height)
      : rangeOverlapAmount(r.x, r.width, fr.x, fr.width);
    const centerDistance = horizontal
      ? rangeCenterDistance(r.y, r.height, fr.y, fr.height)
      : rangeCenterDistance(r.x, r.width, fr.x, fr.width);
    // Larger overlap wins, so it is negated in the ascending key.
    const key: [number, number, number, number] = [edgeDistance, -overlap, centerDistance, index];
    if (!best || compareKeys(key, best.key) < 0) {
      best = { key, id: pane.id };
    }
  });
  return best?.id;
}

function compareKeys(a: readonly number[], b: readonly number[]): number {
  for (let i = 0; i < a.length; i += 1) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
}

function rangesOverlap(aStart: number, aLen: number, bStart: number, bLen: number): boolean {
  return aStart < bStart + bLen && aStart + aLen > bStart;
}

function splitEdgeDistance(split: SplitBorder, focused: Rect, nav: NavDirection): number {
  switch (nav) {
    case "left":
      return Math.abs(split.pos - focused.x);
    case "right":
      return Math.abs(split.pos - (focused.x + focused.width));
    case "up":
      return Math.abs(split.pos - focused.y);
    case "down":
      return Math.abs(split.pos - (focused.y + focused.height));
  }
}

function splitOnRequestedEdge(split: SplitBorder, focused: Rect, nav: NavDirection): boolean {
  return splitEdgeDistance(split, focused, nav) <= 1;
}

function splitAreaOverlapsFocusedPane(
  split: SplitBorder,
  focused: Rect,
  nav: NavDirection,
): boolean {
  if (nav === "left" || nav === "right") {
    return rangesOverlap(split.area.y, split.area.height, focused.y, focused.height);
  }
  return rangesOverlap(split.area.x, split.area.width, focused.x, focused.width);
}

function nearestResizeSplit(
  splits: readonly SplitBorder[],
  targetDirection: Direction,
  focused: Rect,
  nav: NavDirection,
): SplitBorder | undefined {
  let best: SplitBorder | undefined;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const split of splits) {
    if (
      split.direction !== targetDirection ||
      !splitAreaOverlapsFocusedPane(split, focused, nav) ||
      !splitOnRequestedEdge(split, focused, nav)
    ) {
      continue;
    }
    const distance = splitEdgeDistance(split, focused, nav);
    if (distance < bestDistance) {
      best = split;
      bestDistance = distance;
    }
  }
  return best;
}

function oppositeDirection(nav: NavDirection): NavDirection {
  switch (nav) {
    case "left":
      return "right";
    case "right":
      return "left";
    case "up":
      return "down";
    case "down":
      return "up";
  }
}

function rangeOverlapAmount(aStart: number, aLen: number, bStart: number, bLen: number): number {
  const aEnd = aStart + aLen;
  const bEnd = bStart + bLen;
  return saturatingSub(Math.min(aEnd, bEnd), Math.max(aStart, bStart));
}

function rangeCenterDistance(aStart: number, aLen: number, bStart: number, bLen: number): number {
  return Math.abs(aStart * 2 + aLen - (bStart * 2 + bLen));
}

// --- Tree operations ---

function countPanes(node: Node): number {
  return node.kind === "pane" ? 1 : countPanes(node.first) + countPanes(node.second);
}

function containsPane(node: Node, target: PaneId): boolean {
  return node.kind === "pane"
    ? node.id === target
    : containsPane(node.first, target) || containsPane(node.second, target);
}

function collectPanes(node: Node, area: Rect, focus: PaneId, result: PaneInfo[]): void {
  if (node.kind === "pane") {
    result.push({
      id: node.id,
      rect: area,
      // The inner rect is refined during view computation once borders are known.
      innerRect: area,
      scrollbarRect: undefined,
      borders: Borders.NONE,
      isFocused: node.id === focus,
    });
    return;
  }
  const [a, b] = splitRect(area, node.direction, node.ratio);
  collectPanes(node.first, a, focus, result);
  collectPanes(node.second, b, focus, result);
}

function collectSplits(
  node: Node,
  area: Rect,
  path: boolean[],
  result: SplitBorder[],
): void {
  if (node.kind !== "split") {
    return;
  }
  const [a, b] = splitRect(area, node.direction, node.ratio);
  const pos = node.direction === "horizontal" ? a.x + a.width : a.y + a.height;
  result.push({
    pos,
    direction: node.direction,
    ratio: node.ratio,
    area,
    path: [...path],
  });
  path.push(false);
  collectSplits(node.first, a, path, result);
  path.pop();
  path.push(true);
  collectSplits(node.second, b, path, result);
  path.pop();
}

function collectIds(node: Node, ids: PaneId[]): void {
  if (node.kind === "pane") {
    ids.push(node.id);
    return;
  }
  collectIds(node.first, ids);
  collectIds(node.second, ids);
}

function splitRatios(node: Node): Array<{ path: boolean[]; ratio: number }> {
  const out: Array<{ path: boolean[]; ratio: number }> = [];
  const walk = (current: Node, path: boolean[]): void => {
    if (current.kind !== "split") {
      return;
    }
    out.push({ path: [...path], ratio: current.ratio });
    walk(current.first, [...path, false]);
    walk(current.second, [...path, true]);
  };
  walk(node, []);
  return out;
}

function sameRatios(
  a: ReadonlyArray<{ path: boolean[]; ratio: number }>,
  b: ReadonlyArray<{ path: boolean[]; ratio: number }>,
): boolean {
  return (
    a.length === b.length &&
    a.every((entry, i) => {
      const other = b[i];
      return (
        other !== undefined &&
        entry.ratio === other.ratio &&
        entry.path.length === other.path.length &&
        entry.path.every((step, j) => step === other.path[j])
      );
    })
  );
}

function swapPaneIds(node: Node, first: PaneId, second: PaneId): Node {
  if (node.kind === "pane") {
    if (node.id === first) {
      return paneNode(second);
    }
    if (node.id === second) {
      return paneNode(first);
    }
    return node;
  }
  return {
    ...node,
    first: swapPaneIds(node.first, first, second),
    second: swapPaneIds(node.second, first, second),
  };
}

function replacePane(node: Node, target: PaneId, replacement: Node): Node {
  if (node.kind === "pane") {
    return node.id === target ? replacement : node;
  }
  if (containsPane(node.first, target)) {
    return { ...node, first: replacePane(node.first, target, replacement) };
  }
  if (containsPane(node.second, target)) {
    return { ...node, second: replacePane(node.second, target, replacement) };
  }
  return node;
}

function removePane(node: Node, target: PaneId): Node | undefined {
  if (node.kind === "pane") {
    return node.id === target ? undefined : node;
  }
  const first = removePane(node.first, target);
  const second = removePane(node.second, target);
  if (first === undefined) {
    return second;
  }
  if (second === undefined) {
    return first;
  }
  return { ...node, first, second };
}

function setRatioAt(node: Node, path: readonly boolean[], ratio: number): Node | undefined {
  if (node.kind !== "split") {
    return undefined;
  }
  const [head, ...rest] = path;
  if (head === undefined) {
    return { ...node, ratio };
  }
  if (head) {
    const second = setRatioAt(node.second, rest, ratio);
    return second === undefined ? undefined : { ...node, second };
  }
  const first = setRatioAt(node.first, rest, ratio);
  return first === undefined ? undefined : { ...node, first };
}

function getRatioAt(node: Node, path: readonly boolean[]): number | undefined {
  if (node.kind !== "split") {
    return undefined;
  }
  const [head, ...rest] = path;
  if (head === undefined) {
    return node.ratio;
  }
  return getRatioAt(head ? node.second : node.first, rest);
}

function splitRect(area: Rect, direction: Direction, ratio: number): [Rect, Rect] {
  if (direction === "horizontal") {
    const firstWidth = roundHalfAwayFromZero(f32(area.width * ratio));
    const secondWidth = saturatingSub(area.width, firstWidth);
    return [
      rect(area.x, area.y, firstWidth, area.height),
      rect(area.x + firstWidth, area.y, secondWidth, area.height),
    ];
  }
  const firstHeight = roundHalfAwayFromZero(f32(area.height * ratio));
  const secondHeight = saturatingSub(area.height, firstHeight);
  return [
    rect(area.x, area.y, area.width, firstHeight),
    rect(area.x, area.y + firstHeight, area.width, secondHeight),
  ];
}

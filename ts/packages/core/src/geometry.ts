/** Cell-grid rectangle. Mirrors ratatui's `Rect` (u16 coordinates). */
export interface Rect {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export function rect(x: number, y: number, width: number, height: number): Rect {
  return { x, y, width, height };
}

export const EMPTY_RECT: Rect = rect(0, 0, 0, 0);

export type Direction = "horizontal" | "vertical";

export type NavDirection = "left" | "right" | "up" | "down";

/** ratatui `Borders` bit flags. */
export const Borders = {
  NONE: 0,
  TOP: 0b0001,
  RIGHT: 0b0010,
  BOTTOM: 0b0100,
  LEFT: 0b1000,
  ALL: 0b1111,
} as const;

export function saturatingSub(a: number, b: number): number {
  return a > b ? a - b : 0;
}

/** Round-half-away-from-zero like Rust's `f32::round`, for non-negative inputs identical to Math.round. */
export function roundHalfAwayFromZero(value: number): number {
  return value < 0 ? -Math.round(-value) : Math.round(value);
}

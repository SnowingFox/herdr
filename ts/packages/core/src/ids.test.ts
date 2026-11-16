import { describe, expect, it } from "vitest";
import {
  allocPaneId,
  allocTerminalId,
  decodePublicNumber,
  encodePublicNumber,
  generateWorkspaceId,
  publicPaneIdForNumber,
  publicTabIdForNumber,
  publicWorkspaceNumber,
  reserveWorkspaceIds,
} from "./ids.js";

describe("ids", () => {
  it("generated workspace ids are short base32 handles", () => {
    const first = generateWorkspaceId();
    const second = generateWorkspaceId();
    expect(first.startsWith("w")).toBe(true);
    expect(second.startsWith("w")).toBe(true);
    expect(first).not.toBe(second);
    expect(first.length).toBeLessThanOrEqual(3);
    expect(second.length).toBeLessThanOrEqual(3);
  });

  it("public numbers round trip readable base32 handles", () => {
    expect(encodePublicNumber(1)).toBe("1");
    expect(encodePublicNumber(9)).toBe("9");
    expect(encodePublicNumber(10)).toBe("A");
    expect(encodePublicNumber(31)).toBe("Z");
    expect(encodePublicNumber(32)).toBe("0");
    expect(encodePublicNumber(33)).toBe("11");
    for (const value of [1, 9, 10, 31, 32, 33, 1024, 1025]) {
      expect(decodePublicNumber(encodePublicNumber(value))).toBe(value);
    }
    expect(decodePublicNumber("!")).toBeUndefined();
    expect(decodePublicNumber("I")).toBeUndefined();
  });

  it("reserving restored workspace ids prevents reuse", () => {
    reserveWorkspaceIds([{ id: "wZ" }]);
    const generated = generateWorkspaceId();
    expect(generated).not.toBe("wZ");
    expect(publicWorkspaceNumber(generated) ?? 0).toBeGreaterThan(publicWorkspaceNumber("wZ") ?? 0);
  });

  it("builds public pane and tab ids from workspace ids", () => {
    expect(publicPaneIdForNumber("w1", 33)).toBe("w1:p11");
    expect(publicTabIdForNumber("w1", 2)).toBe("w1:t2");
  });

  it("allocates unique pane and terminal ids", () => {
    expect(allocPaneId()).not.toBe(allocPaneId());
    const terminal = allocTerminalId();
    expect(terminal).toMatch(/^term_[0-9a-f]+$/);
    expect(allocTerminalId()).not.toBe(terminal);
  });
});

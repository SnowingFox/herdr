import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      return sourceFiles(path);
    }
    return path.endsWith(".ts") && !path.endsWith(".test.ts") ? [path] : [];
  });
}

describe("package boundaries", () => {
  it("@herdr/core stays pure: no native module, node builtins, or platform branching", () => {
    const forbidden = [
      /from\s+["']@herdr\/native["']/,
      /from\s+["']node:/,
      /process\.platform/,
    ];
    // testing.ts is test support and may read the process cwd.
    const files = sourceFiles(join(import.meta.dirname, "packages/core/src")).filter(
      (file) => !file.endsWith("testing.ts"),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const pattern of forbidden) {
        expect(pattern.test(text), `${file} matches ${pattern}`).toBe(false);
      }
    }
  });
});

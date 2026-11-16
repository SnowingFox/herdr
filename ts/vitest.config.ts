import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["*.test.ts", "packages/*/src/**/*.test.ts", "packages/*/test/**/*.test.ts"],
    testTimeout: 20_000,
  },
});

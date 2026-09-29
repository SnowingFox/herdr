export async function waitFor<T>(
  probe: () => T,
  { timeoutMs = 10_000, intervalMs = 10, description = "condition" } = {},
): Promise<Exclude<T, null | undefined | false | 0 | "">> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = probe();
    if (value) {
      return value as Exclude<T, null | undefined | false | 0 | "">;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${description}`);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

export const isUnix = process.platform !== "win32";

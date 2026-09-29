/** Stable identities. Pane ids are process-global, public numbers are per-workspace handles. */

export type PaneId = number & { readonly __brand: "PaneId" };
export type TerminalId = string & { readonly __brand: "TerminalId" };

export function paneIdFromRaw(raw: number): PaneId {
  return raw as PaneId;
}

let nextPaneId = 1;

/** Allocate a globally unique pane id. */
export function allocPaneId(): PaneId {
  const id = nextPaneId;
  nextPaneId += 1;
  return id as PaneId;
}

let nextTerminalId = 1;

/** Opaque server-owned terminal identity; never derive it from a pane id or layout position. */
export function allocTerminalId(now: () => number = () => Date.now() * 1000): TerminalId {
  const counter = nextTerminalId;
  nextTerminalId += 1;
  return `term_${Math.floor(now()).toString(16)}${counter.toString(16)}` as TerminalId;
}

const PUBLIC_ID_ALPHABET = "123456789ABCDEFGHJKMNPQRSTVWXYZ0";

/** Bijective base-32 with a readable alphabet: 1..9, A.., Z, 0, then 11, 12, ... */
export function encodePublicNumber(value: number): string {
  if (value === 0) {
    return "0";
  }
  let remaining = value;
  let encoded = "";
  while (remaining > 0) {
    const digit = (remaining - 1) % PUBLIC_ID_ALPHABET.length;
    encoded = PUBLIC_ID_ALPHABET.charAt(digit) + encoded;
    remaining = Math.floor((remaining - 1) / PUBLIC_ID_ALPHABET.length);
  }
  return encoded;
}

export function decodePublicNumber(value: string): number | undefined {
  let decoded = 0;
  for (const ch of value) {
    const digit = PUBLIC_ID_ALPHABET.indexOf(ch);
    if (digit < 0) {
      return undefined;
    }
    decoded = decoded * PUBLIC_ID_ALPHABET.length + digit + 1;
    if (!Number.isSafeInteger(decoded)) {
      return undefined;
    }
  }
  return decoded;
}

let nextWorkspaceId = 1;

export function generateWorkspaceId(): string {
  const counter = nextWorkspaceId;
  nextWorkspaceId += 1;
  return `w${encodePublicNumber(counter)}`;
}

export function publicWorkspaceNumber(id: string): number | undefined {
  return id.startsWith("w") ? decodePublicNumber(id.slice(1)) : undefined;
}

/** Ensure freshly generated ids never collide with restored workspace ids. */
export function reserveWorkspaceIds(workspaces: Iterable<{ readonly id: string }>): void {
  let max: number | undefined;
  for (const workspace of workspaces) {
    const number = publicWorkspaceNumber(workspace.id);
    if (number !== undefined && (max === undefined || number > max)) {
      max = number;
    }
  }
  if (max !== undefined && max + 1 > nextWorkspaceId) {
    nextWorkspaceId = max + 1;
  }
}

export function publicPaneIdForNumber(workspaceId: string, paneNumber: number): string {
  return `${workspaceId}:p${encodePublicNumber(paneNumber)}`;
}

export function publicTabIdForNumber(workspaceId: string, tabNumber: number): string {
  return `${workspaceId}:t${encodePublicNumber(tabNumber)}`;
}

export type NativeErrorCode =
  | "EPTY_SPAWN"
  | "EPTY_IO"
  | "ETERMINAL"
  | "ETERM_LOCK"
  | "EINVAL"
  | "ECLOSED"
  | "EUNKNOWN";

const CODE_PATTERN = /^(E[A-Z_]+): (.*)$/s;

export class NativeError extends Error {
  readonly code: NativeErrorCode;

  constructor(code: NativeErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "NativeError";
    this.code = code;
  }

  /** Native errors carry a `CODE: message` prefix; anything else maps to `EUNKNOWN`. */
  static from(error: unknown): NativeError {
    if (error instanceof NativeError) {
      return error;
    }
    const message = error instanceof Error ? error.message : String(error);
    const match = CODE_PATTERN.exec(message);
    if (match?.[1] && match[2] !== undefined) {
      return new NativeError(match[1] as NativeErrorCode, match[2], { cause: error });
    }
    return new NativeError("EUNKNOWN", message, { cause: error });
  }
}

export function wrapNative<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    throw NativeError.from(error);
  }
}

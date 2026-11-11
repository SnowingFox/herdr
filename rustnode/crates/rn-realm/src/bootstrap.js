'use strict';

// Minimal bootstrap used until the vendored Node builtins are initialized in
// the startup snapshot. Anything defined here must eventually come from
// vendor/libnode-js/lib/** instead.
(function bootstrap(globalThis) {
  const process = globalThis.process || {};
  process.version = 'v28.0.0-rustnode';
  process.versions = { rustnode: '0.1.0', v8: globalThis.__v8Version || 'unknown' };
  process.argv = globalThis.__argv || [];
  process.stdout = globalThis.__stdout || { write() {} };
  process.stderr = globalThis.__stderr || { write() {} };
  process.exit = globalThis.__exit || (() => {});
  process.platform = 'linux';

  // The four `__`-prefixed globals above are a hand-off from Rust, not part of
  // Node's global surface, so they are deleted once copied. Leaving them
  // visible is not harmless: `test/common/index.js` enumerates `globalThis` at
  // exit and fails the test on any name it does not recognise, so a leftover
  // shim turns into "Unexpected global(s) found" in every file that uses
  // `common` — which was 388 of them.
  for (const name of ['__argv', '__stdout', '__stderr', '__v8Version', '__exit']) {
    try {
      delete globalThis[name];
    } catch {
      // A non-configurable property would have thrown from the Rust side too;
      // nothing here can make it removable, and the rest of the bootstrap
      // still has to run.
    }
  }

  // `console.log` is `util.format` plus a newline: the first argument is a
  // format string when it contains a `%` directive, and a non-string argument
  // is inspected. Plain space-joining gets both wrong — `console.log('a %s b',
  // 'x')` prints `a x b`, not `a %s b x`.
  let utilFormat = null;
  let inspector = null;
  const util = () => {
    if (utilFormat === null) {
      try {
        const module = globalThis.require('util');
        utilFormat = module.format;
        inspector = module.inspect;
      } catch {
        // The require path is not ready yet. Fall back to a representation that
        // at least never lies about a primitive.
        inspector = (value) => (typeof value === 'string' ? value : String(value));
        utilFormat = (...args) => args.map((value) => inspector(value)).join(' ');
      }
    }
    return utilFormat;
  };

  const format = (value) => {
    util();
    return inspector(value);
  };

  const write = (stream, args) => {
    const line = util()(...args);
    stream.write(line + '\n');
  };

  const console = {
    log(...args) { write(process.stdout, args); },
    info(...args) { write(process.stdout, args); },
    debug(...args) { write(process.stdout, args); },
    error(...args) { write(process.stderr, args); },
    warn(...args) { write(process.stderr, args); },
    dir(value) { write(process.stdout, [value]); },
  };

  Object.defineProperty(globalThis, 'console', { value: console, writable: true, configurable: true });
  Object.defineProperty(globalThis, 'process', { value: process, writable: true, configurable: true });
})(globalThis);

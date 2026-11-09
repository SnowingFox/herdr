'use strict';

// Minimal bootstrap used until the vendored Node builtins are initialized in
// the startup snapshot. Anything defined here must eventually come from
// vendor/libnode-js/lib/** instead.
(function bootstrap(globalThis) {
  const { stringify } = JSON;
  const utilInspect = (value) => (typeof value === 'string' ? value : stringify(value));

  const write = (stream, args) => {
    const text = args.map(utilInspect).join(' ') + '\n';
    stream.write(text);
  };

  const console = {
    log(...args) { write(process.stdout, args); },
    info(...args) { write(process.stdout, args); },
    error(...args) { write(process.stderr, args); },
    warn(...args) { write(process.stderr, args); },
    dir(value) { write(process.stdout, [value]); },
  };

  const process = globalThis.process || {};
  process.version = 'v28.0.0-rustnode';
  process.versions = { rustnode: '0.1.0', v8: globalThis.__v8Version || 'unknown' };
  process.argv = globalThis.__argv || [];
  process.stdout = globalThis.__stdout || { write() {} };
  process.stderr = globalThis.__stderr || { write() {} };
  process.exit = globalThis.__exit || (() => {});
  process.platform = 'linux';

  Object.defineProperty(globalThis, 'console', { value: console, writable: true, configurable: true });
  Object.defineProperty(globalThis, 'process', { value: process, writable: true, configurable: true });
})(globalThis);

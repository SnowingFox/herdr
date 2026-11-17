// Reproduces the `Bun.udpSocket` close-ordering use-after-free on rustnode
// `c47ec53f` (#178's parent): a single socket, `close()`, then exit.
//
//   target/debug/rustnode repro/udp-close-uaf.js
//
// Expected on a fixed build: prints nothing, exits 0.
// Observed on c47ec53f: exits 134 (SIGABRT) after the script has already run,
// with one of
//
//   Assertion `!(handle->flags & UV_HANDLE_CLOSED)' failed.        core.c:315
//   Assertion `handle->flags & UV_HANDLE_CLOSING' failed.          core.c:314
//
// The two different assertions are the tell: `uv__finish_close` reads
// `handle->flags` from a `uv_udp_t` whose `Box` was already freed by `cancel()`
// (which drops it right after `uv_close`). The bits it reads are whatever the
// allocator left there, so which assert fires depends on heap contents.
//
// `close()` starts an asynchronous close; libuv finishes it on the next
// `uv_run` pass, after the script's last statement. That is why the abort lands
// after the output, and why a script that does no further work before exiting
// can appear clean — the process tears down before the closing-handle pass.
const socket = await Bun.udpSocket({ port: 0, hostname: "127.0.0.1" });
socket.close();
process.stdout.write("closed\n");

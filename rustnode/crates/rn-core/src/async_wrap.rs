//! The `AsyncWrap` state a wrapped handle owns.
//!
//! Node builds every handle on `AsyncWrap`, which owns three things: the id of
//! the resource, the id that triggered it, and the provider kind that names it.
//! `AsyncReset` is what re-issues all three, and it is the method
//! `lib/internal/http/agent.js::asyncResetHandle` calls on a pooled socket.
//!
//! # Why the state is here and the behaviour is not
//!
//! The state is plain data, so `rn-uv` can put it in a `StreamState` without
//! depending on a binding crate. The behaviour needs V8 (it emits `init`), so it
//! lives in `rn-bind-async-wrap` and `rn-bind-tcp-wrap` calls it. Keeping the
//! split at "data in the kernel, hooks in the binding" is the same rule the rest
//! of the kernel follows.

/// `AsyncWrap::kInvalidAsyncId`.
pub const INVALID_ASYNC_ID: f64 = -1.0;

/// `PROVIDER_NONE` in `src/async_wrap.h`, which `GetProviderType` reports before
/// it unwraps.
pub const PROVIDER_NONE: u32 = 0;

/// `PROVIDER_TCPSERVERWRAP`: a listening socket.
pub const PROVIDER_TCPSERVERWRAP: u32 = 41;
/// `PROVIDER_TCPWRAP`: a connected socket.
pub const PROVIDER_TCPWRAP: u32 = 42;
/// `PROVIDER_TCPCONNECTWRAP`: one `uv_tcp_connect` request.
///
/// `TCPWrap::Connect` constructs a fresh `ConnectWrap` per attempt with this
/// provider (`src/tcp_wrap.cc:588`), and it is the *request*, not the socket,
/// that carries the type. A connecting socket's `TCPWRAP` comes from the handle
/// itself, so `net.connect` reports both.
pub const PROVIDER_TCPCONNECTWRAP: u32 = 40;
/// `PROVIDER_TTYWRAP`: a terminal.
pub const PROVIDER_TTYWRAP: u32 = 43;
/// `PROVIDER_PIPECONNECTWRAP`: a pipe connect request.
pub const PROVIDER_PIPECONNECTWRAP: u32 = 25;
/// `PROVIDER_PIPESERVERWRAP`: a listening pipe.
pub const PROVIDER_PIPESERVERWRAP: u32 = 26;
/// `PROVIDER_PIPEWRAP`: a connected pipe or an IPC channel.
pub const PROVIDER_PIPEWRAP: u32 = 27;
/// `PROVIDER_HTTP2SESSION`: an HTTP/2 session.
///
/// The value is the position of `V(HTTP2SESSION)` in `NODE_ASYNC_PROVIDER_TYPES`
/// (`src/async_wrap.h`), counted from `NONE`. `PROVIDER_TCPWRAP` above is the
/// check that the counting is right: it is 42 there and 42 here.
pub const PROVIDER_HTTP2SESSION: u32 = 14;
/// `PROVIDER_HTTP2STREAM`: one HTTP/2 stream.
pub const PROVIDER_HTTP2STREAM: u32 = 15;
/// `PROVIDER_TLSWRAP`: a `TLSWrap`, `AsyncWrap::PROVIDER_TLSWRAP`.
///
/// The position of `V(TLSWRAP)` in `NODE_ASYNC_PROVIDER_TYPES`'s crypto half
/// (`src/async_wrap.h`), counted from `NONE`: 55 non-crypto providers, then the
/// thirteen crypto requests before it. `PROVIDER_TCPWRAP` is the check that the
/// counting is right — 42 there and 42 here — and `node --expose-internals`'s
/// `handle.getProviderType()` on a real `tls_wrap.wrap()` reports 68.
pub const PROVIDER_TLSWRAP: u32 = 68;
/// `PROVIDER_STATWATCHER`: the `uv_fs_poll_t` behind `fs.watchFile`.
///
/// Counted from `NONE` in `NODE_ASYNC_NON_CRYPTO_PROVIDER_TYPES`, which is the
/// same table the `TCPWRAP`/`TCPSERVERWRAP` pair above is checked against.
pub const PROVIDER_STATWATCHER: u32 = 38;

/// `PROVIDER_FSREQCALLBACK`: an `FSReqCallback`-based `fs` request.
///
/// Emitted by every callback-form `fs` binding call, by `FileHandle` reads, and
/// by the `ReadFileJob`/`WriteFileJob` classes.
pub const PROVIDER_FSREQCALLBACK: u32 = 8;
/// `PROVIDER_FSREQPROMISE`: the `FSReqPromise` a `kUsePromises` call creates.
pub const PROVIDER_FSREQPROMISE: u32 = 10;
/// `PROVIDER_FILEHANDLE`: the `FileHandle` behind `fs.promises.open`.
pub const PROVIDER_FILEHANDLE: u32 = 4;
/// `PROVIDER_FILEHANDLECLOSEREQ`: the request `FileHandle.prototype.close`
/// schedules.
pub const PROVIDER_FILEHANDLECLOSEREQ: u32 = 5;
/// `PROVIDER_DNSCHANNEL`: the resolver channel `dns.lookup` creates lazily.
pub const PROVIDER_DNSCHANNEL: u32 = 2;
/// `PROVIDER_GETADDRINFOREQWRAP`: one `getaddrinfo` request.
pub const PROVIDER_GETADDRINFOREQWRAP: u32 = 11;
/// `PROVIDER_GETNAMEINFOREQWRAP`: one `getnameinfo` request.
pub const PROVIDER_GETNAMEINFOREQWRAP: u32 = 12;
/// `PROVIDER_QUERYWRAP`: one c-ares DNS query.
pub const PROVIDER_QUERYWRAP: u32 = 30;
/// `PROVIDER_WORKER`: the `Worker` handle behind `new Worker(...)`.
pub const PROVIDER_WORKER: u32 = 47;
/// `PROVIDER_ZLIB`: a `Zlib` stream handle.
pub const PROVIDER_ZLIB: u32 = 54;
/// `PROVIDER_MESSAGEPORT`: a `MessagePort`.
pub const PROVIDER_MESSAGEPORT: u32 = 24;
/// `PROVIDER_PROCESSWRAP`: a child process's `uv_process_t`.
pub const PROVIDER_PROCESSWRAP: u32 = 28;
/// `PROVIDER_SHUTDOWNWRAP`: the request that closes a child's stdio.
pub const PROVIDER_SHUTDOWNWRAP: u32 = 36;
/// `PROVIDER_SIGNALWRAP`: a `uv_signal_t`.
pub const PROVIDER_SIGNALWRAP: u32 = 37;
/// `PROVIDER_RANDOMBYTESREQUEST`: one `crypto.randomBytes` job.
pub const PROVIDER_RANDOMBYTESREQUEST: u32 = 64;
/// `PROVIDER_RANDOMPRIMEREQUEST`: one `crypto.generatePrime` job.
pub const PROVIDER_RANDOMPRIMEREQUEST: u32 = 65;
/// `PROVIDER_CHECKPRIMEREQUEST`: one `crypto.checkPrime` job.
pub const PROVIDER_CHECKPRIMEREQUEST: u32 = 55;
/// `PROVIDER_ARGON2REQUEST`: one `crypto.argon2` job.
pub const PROVIDER_ARGON2REQUEST: u32 = 60;
/// `PROVIDER_PBKDF2REQUEST`: one `crypto.pbkdf2` job.
pub const PROVIDER_PBKDF2REQUEST: u32 = 56;
/// `PROVIDER_SCRYPTREQUEST`: one `crypto.scrypt` job.
pub const PROVIDER_SCRYPTREQUEST: u32 = 66;
/// `PROVIDER_HKDFREQUEST`: one `crypto.hkdf` job.
///
/// Node has no `HKDFREQUEST` provider: `HKDFJob` reports `DERIVEBITSREQUEST`,
/// because `node_hkdf` derives through `DeriveBitsJob`. The constant is named
/// for the JavaScript class so a reader is not misled about which job it is.
pub const PROVIDER_HKDFREQUEST: u32 = 62;
/// `PROVIDER_HTTPCLIENTREQUEST`: the parser behind a client request.
pub const PROVIDER_HTTPCLIENTREQUEST: u32 = 19;
/// `PROVIDER_HTTPINCOMINGMESSAGE`: the connection a server parses.
pub const PROVIDER_HTTPINCOMINGMESSAGE: u32 = 18;

/// The `AsyncWrap` fields of a wrapped handle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AsyncWrapState {
    /// `AsyncWrap::async_id_`, which starts invalid.
    pub async_id: f64,
    /// `AsyncWrap::trigger_async_id_`.
    pub trigger_async_id: f64,
    /// `AsyncWrap::provider_type_`.
    pub provider: u32,
}

impl AsyncWrapState {
    /// An instance that has not been reset yet, matching the
    /// `AsyncWrap(env, object)` constructor `src/async_wrap.h` describes as
    /// "user is responsible to call set_provider_type() and AsyncReset()".
    pub const fn uninitialised(provider: u32) -> Self {
        Self {
            async_id: INVALID_ASYNC_ID,
            trigger_async_id: INVALID_ASYNC_ID,
            provider,
        }
    }

    /// The id `getAsyncId()` reports.
    pub const fn async_id(&self) -> f64 {
        self.async_id
    }

    /// The provider `getProviderType()` reports.
    pub const fn provider(&self) -> u32 {
        self.provider
    }
}

/// Async id space mirroring Node's `AsyncWrap` so `async_hooks` ordering is
/// preserved bit for bit.
#[derive(Default)]
pub struct AsyncIds {
    next: u64,
}

impl AsyncIds {
    pub fn new() -> Self {
        Self { next: 1 }
    }
    pub fn next_id(&mut self) -> u64 {
        let id = self.next;
        self.next += 1;
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_instance_is_invalid_and_keeps_its_provider() {
        // `AsyncWrap(env, object, provider)` assigns the provider *before* the
        // reset, so `getProviderType()` is answerable on an id-less handle. That
        // is what `asyncResetHandle` reads to build its `ReusedHandle`.
        let state = AsyncWrapState::uninitialised(PROVIDER_TCPWRAP);
        assert_eq!(state.async_id(), INVALID_ASYNC_ID);
        assert_eq!(state.trigger_async_id, INVALID_ASYNC_ID);
        assert_eq!(state.provider(), PROVIDER_TCPWRAP);
        assert_eq!(
            AsyncWrapState::uninitialised(PROVIDER_TCPSERVERWRAP).provider(),
            PROVIDER_TCPSERVERWRAP
        );
    }

    #[test]
    fn the_provider_ids_match_the_async_wrap_table() {
        // These are the providers this crate names, and they are the ones
        // `src/tcp_wrap.cc`, `src/node_stat_watcher.cc` and `src/tls_wrap.cc`
        // select. A drift here would label a socket, a stat watcher or a TLS
        // wrap with the wrong kind while still looking like a working id.
        assert_eq!(PROVIDER_TCPSERVERWRAP, 41);
        assert_eq!(PROVIDER_TCPWRAP, 42);
        assert_eq!(PROVIDER_TCPCONNECTWRAP, 40);
        assert_eq!(PROVIDER_STATWATCHER, 38);
        assert_eq!(PROVIDER_TLSWRAP, 68);
        assert_eq!(PROVIDER_NONE, 0);
    }

    #[test]
    fn the_request_and_job_provider_ids_match_the_async_wrap_table() {
        // The providers the resource wrappers this crate does not own name. Each
        // one is a position in `NODE_ASYNC_PROVIDER_TYPES`, and a wrong number
        // makes `async_hooks` label a resource with a *different* valid name,
        // which no test that only checks "an init fired" would notice.
        assert_eq!(PROVIDER_FSREQCALLBACK, 8);
        assert_eq!(PROVIDER_FSREQPROMISE, 10);
        assert_eq!(PROVIDER_FILEHANDLE, 4);
        assert_eq!(PROVIDER_FILEHANDLECLOSEREQ, 5);
        assert_eq!(PROVIDER_DNSCHANNEL, 2);
        assert_eq!(PROVIDER_GETADDRINFOREQWRAP, 11);
        assert_eq!(PROVIDER_GETNAMEINFOREQWRAP, 12);
        assert_eq!(PROVIDER_QUERYWRAP, 30);
        assert_eq!(PROVIDER_ZLIB, 54);
        assert_eq!(PROVIDER_MESSAGEPORT, 24);
        assert_eq!(PROVIDER_PROCESSWRAP, 28);
        assert_eq!(PROVIDER_SHUTDOWNWRAP, 36);
        assert_eq!(PROVIDER_SIGNALWRAP, 37);
        assert_eq!(PROVIDER_RANDOMBYTESREQUEST, 64);
        assert_eq!(PROVIDER_PBKDF2REQUEST, 56);
        assert_eq!(PROVIDER_HTTPCLIENTREQUEST, 19);
        assert_eq!(PROVIDER_HTTPINCOMINGMESSAGE, 18);
    }
}

//! The `HTTPParser` class: `src/node_http_parser.cc`, rewritten against the
//! vendored llhttp.
//!
//! # Shape
//!
//! One JavaScript object per parser, with one internal field holding a
//! `Box<Parser>`. `Parser` owns the llhttp instance through [`crate::ffi`], the
//! accumulated headers through [`Accumulator`], and the JavaScript callbacks as
//! `Global` handles so a parser outlives the `execute` that called back into
//! them.
//!
//! # The callback contract
//!
//! `lib/internal/http/common.js` assigns functions onto the parser object by
//! numeric index, and `lib/internal/http/server.js` reads two more:
//!
//! | index | constant | handler | signature |
//! | --- | --- | --- | --- |
//! | 0 | `kOnMessageBegin` | `on_message_begin` | `()` |
//! | 1 | `kOnHeaders` | `on_headers` | `(headers, url)` |
//! | 2 | `kOnHeadersComplete` | `on_headers_complete` | 9 arguments |
//! | 3 | `kOnBody` | `on_body` | `(buffer)` |
//! | 4 | `kOnMessageComplete` | `on_message_complete` | `()` |
//! | 5 | `kOnExecute` | called by the consumer | `(bytesParsed)` |
//! | 6 | `kOnTimeout` | called by the consumer | `()` |
//!
//! The last two are read by `lib/**`, never by this crate: Node invokes
//! `kOnExecute` from `OnStreamRead`, but only when the parser has taken over the
//! socket through `consume()`, which this runtime does not do. They exist as
//! constants so `HTTPParser.kOnExecute` is defined; nothing here calls them.
//!
//! # Pausing
//!
//! `pause()` goes straight to `llhttp_pause`, exactly as `Parser::Pause<true>`
//! does. llhttp only records the flag, so the run already in progress finishes
//! normally — its callbacks all fire — and the *next* `execute` returns
//! `HPE_PAUSED` before parsing anything. `lib/**` then calls `resume()` before
//! feeding more bytes.
//!
//! `HPE_PAUSED` is reported as an `Error` with `code: 'HPE_PAUSED'`, because
//! `Parser::Execute` treats every non-`HPE_OK` errno that way. Node's
//! `pending_pause_`/`MaybePause` pair looks like a deferred-pause mechanism but
//! nothing ever sets `pending_pause_` in the pinned source, so this crate does
//! not reproduce it.
//!
//! # Exceptions
//!
//! A callback that throws does not unwind through C. The call records
//! [`Parser::got_exception`], the exception stays pending on the isolate, and
//! `execute` returns [`Outcome::CallbackThrew`] without setting a return value —
//! Node's empty `MaybeLocal`.
//!
//! # Re-entrancy
//!
//! A callback runs while `execute` holds a mutable borrow of the parser, and
//! `lib/**` does reach back into the parser from there. Two different cases, and
//! only one of them is a hazard:
//!
//! * `getCurrentBuffer()` is called from `parserOnIncoming`, which runs inside
//!   `kOnHeadersComplete`. `pause()` and `resume()` are called from
//!   `onParserExecuteCommon`, just after `execute` returns, and from
//!   `socketOnDrain` — but also, in principle, from a user callback. Those three
//!   therefore read dedicated fields instead of [`Parser`]: the llhttp instance
//!   (`LLHTTP_FIELD`) and the buffer being walked, both plain pointers copied
//!   into the object at construction. `getCurrentBuffer` additionally takes a
//!   *shared* borrow through [`crate::with_parser_ref`], so it coexists with the
//!   `&mut` held by `execute`.
//! * `close()`, `free()`, `remove()`, `initialize()`, `execute()` and
//!   `finish()` are only ever called outside a parse: `freeParser` runs after
//!   `execute` has returned, and `initialize` runs before the first byte. They
//!   take `&mut Parser` through a plain borrow, which is sound precisely because
//!   no callback can reach them.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

use rn_v8_sys::v8;

use crate::accumulator::{Accumulator, Action};
use crate::connections::{Entry, EntryState};
use crate::ffi;
use crate::js::{self, Slot};
use crate::SharedList;

/// Which llhttp parser to build, i.e. `HTTPParser.REQUEST`/`RESPONSE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Request,
    Response,
}

impl Kind {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            ffi::parser_type::REQUEST => Some(Self::Request),
            ffi::parser_type::RESPONSE => Some(Self::Response),
            _ => None,
        }
    }

    fn llhttp(self) -> c_int {
        match self {
            Self::Request => ffi::parser_type::REQUEST,
            Self::Response => ffi::parser_type::RESPONSE,
        }
    }
}

/// Everything `initialize` can change about a parser.
#[derive(Debug, Clone, Copy, Default)]
pub struct Config {
    /// `0` means "use the process default", resolved by
    /// [`Config::effective_max_header_size`].
    pub max_header_size: u64,
    /// `kLenient*` bits, straight through to llhttp.
    pub lenient_flags: u32,
    /// `maxHeaderPairs`. `0` means no limit.
    pub max_header_pairs: usize,
}

impl Config {
    /// The header size limit in effect, resolving Node's `0` default.
    ///
    /// Node reads `env->options()->max_http_header_size` in that case, which is
    /// `--max-http-header-size`'s default here: rustnode has no option parser
    /// wired into this crate, and the flag's default is what a process started
    /// without it uses.
    pub fn effective_max_header_size(&self) -> u64 {
        if self.max_header_size == 0 {
            DEFAULT_MAX_HTTP_HEADER_SIZE
        } else {
            self.max_header_size
        }
    }
}

/// `--max-http-header-size`'s default, from `src/node_options.h`.
pub const DEFAULT_MAX_HTTP_HEADER_SIZE: u64 = 16 * 1024;

/// `kMaxChunkExtensionsSize`: a chunk extension longer than this is refused so a
/// peer cannot grow the parser's buffers without bound.
pub const MAX_CHUNK_EXTENSIONS_SIZE: usize = 16 * 1024;

/// `kMaxBufferedBodySize`: how much body may accumulate inside one `execute`
/// before it is delivered anyway.
pub const MAX_BUFFERED_BODY_SIZE: usize = 64 * 1024;

/// The result of one `execute` or `finish`.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `execute`: the byte offset llhttp consumed.
    Consumed(usize),
    /// `finish`: Node returns no value at all, not even `undefined`.
    Finished,
    /// A parse error, with the fields the JavaScript error carries.
    Failed(ParseError),
    /// A callback threw. The exception is pending, so the caller must return
    /// without setting a value.
    CallbackThrew,
}

/// The fields `prepareError` and `lib/**` read off a parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub code: String,
    pub reason: String,
    pub bytes_parsed: usize,
}

/// Why a callback stopped the parse, in the shape llhttp takes.
type Stop = c_int;

/// One parser's native state.
pub struct Parser {
    /// The llhttp instance, allocated by the shim.
    ///
    /// In a `Cell` because `pause()` and `resume()` are reachable from inside a
    /// callback, which already holds a `&mut Parser`; going through the cell
    /// means those paths never need a second one. See the module note on
    /// re-entrancy.
    llhttp: std::cell::Cell<*mut ffi::Llhttp>,
    /// The isolate address.
    ///
    /// A callback arrives with no scope and needs one before it can make a
    /// `Local`, and every scope constructor takes `&mut Isolate`. The wrapper is
    /// `Copy` and holds only the address, so it is what gets stored; the
    /// `&mut Isolate` is derived per callback in `js::with_scope` and lives no
    /// longer than that call. Only the isolate's own thread reads this.
    isolate: v8::UnsafeRawIsolatePtr,
    /// The context the callbacks run in, captured when the parser was built.
    ///
    /// `execute` is called from JavaScript, so the isolate is entered with that
    /// context on the stack; this is the same context, kept so a callback can
    /// put it back on the stack before running JavaScript.
    context: Option<v8::Global<v8::Context>>,
    /// The JavaScript object, for `this` and for reading the callbacks off it.
    ///
    /// Weak on purpose: the internal field owns this `Parser` and the wrapper
    /// owns the field, so a strong reference would be a cycle V8 cannot collect.
    object: Option<v8::Weak<v8::Object>>,
    /// The callbacks this crate invokes, cached the first time each is read.
    /// Node caches them in internal fields so a callback closing over the parser
    /// does not keep it alive past `free()`; `free()` clears them here too.
    callbacks: [Option<v8::Global<v8::Function>>; 5],
    accumulator: Accumulator,
    /// `header_nread_`: request line, status line and header bytes for the
    /// current message, measured against `max_header_size`.
    header_nread: u64,
    /// `header_pairs_`: header pairs for the current message, counted in halves
    /// like Node counts them.
    header_pairs: usize,
    /// `chunk_extensions_nread_`: extensions seen for the current chunk.
    chunk_extensions_nread: usize,
    config: Config,
    /// Whether `initialize` has run. `execute` before it is a no-op, matching a
    /// zeroed Node parser whose llhttp error field is 0.
    initialized: bool,
    /// Set when a callback threw.
    got_exception: bool,
    /// Node's `is_being_freed_`: after `remove()`, callbacks stop firing.
    being_freed: bool,
    /// The buffer `execute` is walking, for `getCurrentBuffer`.
    ///
    /// `Cell`s for the same reason as `llhttp`: `getCurrentBuffer()` is called
    /// from `onParserExecuteCommon` while a callback holds a `&mut Parser`.
    current_buffer: std::cell::Cell<*const u8>,
    current_buffer_len: std::cell::Cell<usize>,
    /// Body bytes collected inside the current `execute`.
    body: BodyBuffer,
    /// `last_message_start_`, which connection expiry measures against.
    last_message_start: Option<std::time::Instant>,
    /// `received_data_`, which `ConnectionsList::idle` checks.
    received_data: bool,
    /// Whether `on_headers_complete` has run for the current message, which
    /// connection expiry checks.
    headers_completed: bool,
    /// The list this parser registered with, and its entry in it.
    ///
    /// `None` when `initialize` was given no list. Holds the list strongly so a
    /// parser outliving its JavaScript `ConnectionsList` still unlinks cleanly
    /// instead of pointing at freed memory.
    connections: Option<(SharedList, crate::connections::Entry)>,
}

/// The body bytes collected inside one `execute`.
///
/// Node holds a `pending_body_` pointer into the caller's buffer and copies into
/// `body_buf_` only when two spans are not adjacent, so the common "one
/// contiguous body" case allocates nothing. The same shape is kept here because
/// `kMaxBufferedBodySize` bounds the accumulation and the flush point depends on
/// it.
#[derive(Default)]
struct BodyBuffer {
    /// Start of the first span. Valid while `len > 0` and `copy` is empty.
    start: *const u8,
    len: usize,
    /// Populated only when a later span did not continue the first.
    copy: Vec<u8>,
}

impl BodyBuffer {
    fn clear(&mut self) {
        self.start = std::ptr::null();
        self.len = 0;
        self.copy.clear();
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Records one span, copying only when it does not continue the last.
    fn push(&mut self, at: *const u8, length: usize) {
        if self.len == 0 {
            self.start = at;
            self.len = length;
            return;
        }
        if self.copy.is_empty() {
            // SAFETY: `start` and `at` both point into the buffer llhttp is
            // walking, which outlives this call, and `start..start + len` is
            // live.
            let contiguous = unsafe { self.start.add(self.len) == at };
            if contiguous {
                self.len += length;
                return;
            }
            // SAFETY: `start` covers `len` live bytes, as above.
            self.copy = unsafe { std::slice::from_raw_parts(self.start, self.len) }.to_vec();
        }
        if length == 0 {
            return;
        }
        // SAFETY: `at` covers `length` live bytes, as above.
        self.copy
            .extend_from_slice(unsafe { std::slice::from_raw_parts(at, length) });
        self.len += length;
    }

    fn bytes(&self) -> &[u8] {
        if !self.copy.is_empty() {
            return &self.copy;
        }
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `start` points at `len` live bytes of the buffer being parsed.
        unsafe { std::slice::from_raw_parts(self.start, self.len) }
    }
}

/// The reason `on_body` reports when flushing first failed because JavaScript
/// threw.
const JS_EXCEPTION_REASON: &std::ffi::CStr = c"HPE_JS_EXCEPTION:JS Exception";

impl Parser {
    /// Builds a parser whose JavaScript object is `object`.
    ///
    /// Two phases because llhttp's `user` pointer must outlive the `Box` moving:
    /// the box is allocated and its address taken first, then llhttp is created
    /// with that address. It is also why the object handle is set afterwards.
    ///
    /// # Safety
    ///
    /// `scope` must belong to `object`'s isolate. Release the result with
    /// [`Self::release`].
    pub unsafe fn create(
        scope: &mut v8::PinScope<'_, '_>,
        object: v8::Local<v8::Object>,
    ) -> Option<*mut Self> {
        let raw: *mut Self = Box::into_raw(Box::new(Self {
            // Replaced below, once the box address is known.
            llhttp: std::cell::Cell::new(std::ptr::null_mut()),
            // SAFETY: the scope is live, so its isolate address is valid. The
            // wrapper owns nothing; only `js::with_scope` turns it back into a
            // reference, and only for the duration of one callback.
            isolate: unsafe { scope.as_raw_isolate_ptr() },
            context: Some(v8::Global::new(scope, scope.get_current_context())),
            object: None,
            callbacks: [None, None, None, None, None],
            accumulator: Accumulator::default(),
            header_nread: 0,
            header_pairs: 0,
            chunk_extensions_nread: 0,
            config: Config::default(),
            initialized: false,
            got_exception: false,
            being_freed: false,
            current_buffer: std::cell::Cell::new(std::ptr::null()),
            current_buffer_len: std::cell::Cell::new(0),
            body: BodyBuffer::default(),
            last_message_start: None,
            received_data: false,
            headers_completed: false,
            connections: None,
        }));
        let callbacks = ffi::Callbacks {
            user: raw.cast::<c_void>(),
            on_message_begin: Some(on_message_begin),
            on_url: Some(on_url),
            on_status: Some(on_status),
            on_header_field: Some(on_header_field),
            on_header_value: Some(on_header_value),
            on_headers_complete: Some(on_headers_complete),
            on_body: Some(on_body),
            on_message_complete: Some(on_message_complete),
            on_chunk_header: Some(on_chunk_header),
            on_chunk_complete: Some(on_chunk_complete),
        };
        // SAFETY: the shim copies the table, so the stack value is fine, and
        // `user` is the box address `Box::into_raw` just fixed.
        let llhttp = unsafe { ffi::rn_llhttp_new(ffi::parser_type::REQUEST, &callbacks) };
        if llhttp.is_null() {
            // SAFETY: `raw` came from `Box::into_raw` above and nothing else
            // holds it.
            drop(unsafe { Box::from_raw(raw) });
            return None;
        }
        // SAFETY: `raw` is uniquely ours until the caller takes ownership.
        unsafe { (*raw).llhttp.set(llhttp) };
        // SAFETY: as above.
        unsafe { (*raw).object = Some(v8::Weak::new(scope, object)) };
        Some(raw)
    }

    /// The llhttp instance, so the wrapper can publish it in its own internal
    /// field for the members that are called re-entrantly.
    pub fn llhttp_pointer(&self) -> *mut ffi::Llhttp {
        self.llhttp.get()
    }

    /// Frees a pointer from [`Self::create`].
    ///
    /// # Safety
    ///
    /// `raw` must come from `create` and be released exactly once.
    pub unsafe fn release(raw: *mut Self) {
        if raw.is_null() {
            return;
        }
        // SAFETY: delegated to the caller.
        drop(unsafe { Box::from_raw(raw) });
    }

    pub fn initialized(&self) -> bool {
        self.initialized
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn last_message_start(&self) -> Option<std::time::Instant> {
        self.last_message_start
    }

    pub fn received_data(&self) -> bool {
        self.received_data
    }

    pub fn headers_completed(&self) -> bool {
        self.headers_completed
    }

    /// Resets the message-scoped counters. Used by `initialize`.
    pub fn reset_counters(&mut self) {
        self.header_nread = 0;
        self.header_pairs = 0;
        self.chunk_extensions_nread = 0;
        self.headers_completed = false;
    }

    /// `initialize(type, asyncResource, maxHeaderSize, lenientFlags,
    /// connectionsList, maxHeaderPairs)`.
    ///
    /// `async_resource` is Node's `AsyncResource` and carries no parser state;
    /// it is accepted by the binding but not stored, because `async_hooks`
    /// tracing of the incoming message is not implemented here. Every other
    /// argument is used.
    pub fn initialize(
        &mut self,
        kind: Kind,
        max_header_size: u64,
        lenient_flags: u32,
        max_header_pairs: usize,
        has_connections: bool,
    ) {
        // SAFETY: `llhttp` is the live instance this parser owns.
        unsafe { ffi::rn_llhttp_init(self.llhttp.get(), kind.llhttp()) };
        if lenient_flags != 0 {
            // SAFETY: as above.
            unsafe { ffi::rn_llhttp_set_lenient(self.llhttp.get(), lenient_flags) };
        }
        if has_connections {
            // Node stamps the start here so a connection that never sends a byte
            // can still expire. It also clears `received_data_`, which is what
            // makes the parser report as *idle* rather than active until the
            // first byte of a message arrives — Node 28's `Idle` tests
            // `last_message_start_ == 0 || !received_data_`.
            self.last_message_start = Some(std::time::Instant::now());
            self.received_data = false;
        }
        self.config = Config {
            max_header_size,
            lenient_flags,
            max_header_pairs,
        };
        self.reset_counters();
        self.accumulator.reset_for_message();
        self.body.clear();
        self.got_exception = false;
        self.being_freed = false;
        self.initialized = true;
        self.clear_cached_callbacks();
    }

    /// `execute(buffer)`.
    ///
    /// # Safety
    ///
    /// `data` must point at `len` readable bytes that stay live for the call;
    /// they are the backing store of the JavaScript view the caller passed.
    pub unsafe fn execute(&mut self, data: *const u8, len: usize) -> Outcome {
        if !self.initialized {
            return Outcome::Consumed(0);
        }
        self.current_buffer.set(data);
        self.current_buffer_len.set(len);
        self.got_exception = false;

        // SAFETY: delegated to the caller; the buffer outlives the call.
        let errno =
            unsafe { ffi::rn_llhttp_execute(self.llhttp.get(), data.cast::<c_char>(), len) };

        // Deliver whatever body was collected while `data` is still valid.
        self.flush_body();

        let outcome = self.after_execute(errno, Some(data), len);
        self.current_buffer.set(std::ptr::null());
        self.current_buffer_len.set(0);
        outcome
    }

    /// `finish()`: tells llhttp the peer will send nothing more.
    pub fn finish(&mut self) -> Outcome {
        if !self.initialized {
            return Outcome::Finished;
        }
        self.got_exception = false;
        // SAFETY: `llhttp` is live and this is its only reference.
        let errno = unsafe { ffi::rn_llhttp_finish(self.llhttp.get()) };
        self.flush_body();
        self.after_execute(errno, None, 0)
    }

    /// Shared tail of `execute` and `finish`.
    fn after_execute(&mut self, mut errno: c_int, data: Option<*const u8>, len: usize) -> Outcome {
        let consumed = if errno == ffi::errno::OK {
            len
        } else {
            // SAFETY: `llhttp` is live; `data` is the buffer just parsed, or
            // null for `finish`, which the shim reports as offset 0.
            let offset = unsafe {
                ffi::rn_llhttp_error_offset(
                    self.llhttp.get(),
                    data.unwrap_or(std::ptr::null()).cast::<c_char>(),
                )
            };
            usize::try_from(offset).unwrap_or(0)
        };

        // HPE_PAUSED_UPGRADE is not a pause: it is how llhttp reports that it
        // stopped at an upgrade boundary. Node treats it as success and clears
        // it, leaving the rest of the buffer for whoever takes the connection.
        if errno == ffi::errno::PAUSED_UPGRADE {
            errno = ffi::errno::OK;
            // SAFETY: as above.
            unsafe { ffi::rn_llhttp_resume_after_upgrade(self.llhttp.get()) };
        }

        if self.got_exception {
            return Outcome::CallbackThrew;
        }

        if errno != ffi::errno::OK {
            return Outcome::Failed(self.parse_error(errno, consumed));
        }
        match data {
            Some(_) => Outcome::Consumed(consumed),
            None => Outcome::Finished,
        }
    }

    /// Builds the error object `Parser::Execute` constructs.
    fn parse_error(&self, errno: c_int, bytes_parsed: usize) -> ParseError {
        // SAFETY: `llhttp` is live and the reason is a static string.
        let reason = unsafe { js::c_str(ffi::rn_llhttp_error_reason(self.llhttp.get())) }
            .unwrap_or_default()
            .to_string();
        let (code, detail) = if errno == ffi::errno::USER {
            // A user error's reason is "CODE:reason", so the code is the part
            // before the first colon. Node `CHECK`s that the colon exists; a
            // reason without one would be a bug in this crate, so the whole
            // string is used as the code rather than panicking.
            match reason.split_once(':') {
                Some((code, detail)) => (code.to_string(), detail.to_string()),
                None => ("HPE_USER".to_string(), reason.clone()),
            }
        } else {
            (ffi::errno_name(errno), reason.clone())
        };
        ParseError {
            // Node's `Exception::Error(env->parse_error_string())` uses the bare
            // string "Parse Error"; the reason lives only in `reason`, and
            // `prepareError` is what folds it into the message when the
            // JavaScript layer reports the failure.
            message: "Parse Error".to_string(),
            code,
            reason: detail,
            bytes_parsed,
        }
    }

    /// `close()`: frees the native parser.
    ///
    /// Node deletes the whole `Parser`, so every later call is a no-op returning
    /// `undefined`. The wrapper here cannot be deleted out from under the
    /// JavaScript object, so the state is marked uninitialised instead, which
    /// makes `execute` and `finish` behave identically.
    pub fn close(&mut self) {
        self.initialized = false;
        self.accumulator.reset_for_message();
        self.body.clear();
        self.clear_cached_callbacks();
    }

    /// `free()`: drops the cached callbacks and the accumulated state, which is
    /// Node's `ClearCachedCallbacks` plus what its destructor releases.
    pub fn free(&mut self) {
        self.clear_cached_callbacks();
        self.body.clear();
        self.accumulator.reset_for_message();
    }

    /// `remove()`: stops further callbacks, Node's `is_being_freed_`.
    pub fn remove(&mut self) {
        self.being_freed = true;
    }

    /// The buffer being parsed, for `getCurrentBuffer`.
    pub fn current_buffer(&self) -> &[u8] {
        let data = self.current_buffer.get();
        let len = self.current_buffer_len.get();
        if data.is_null() || len == 0 {
            return &[];
        }
        // SAFETY: `execute` set this to a buffer it holds for the whole call,
        // and only reads it while that call runs.
        unsafe { std::slice::from_raw_parts(data, len) }
    }

    fn clear_cached_callbacks(&mut self) {
        self.callbacks = [None, None, None, None, None];
    }

    fn should_keep_alive(&self) -> bool {
        // SAFETY: `llhttp` is live.
        unsafe { ffi::rn_llhttp_should_keep_alive(self.llhttp.get()) != 0 }
    }

    fn is_request(&self) -> bool {
        // SAFETY: `llhttp` is live; this only reads `type`.
        unsafe { ffi::rn_llhttp_type(self.llhttp.get()) == ffi::parser_type::REQUEST }
    }

    /// `TrackHeader`: enforces `max_http_header_size` across the request line,
    /// status line and headers.
    fn track_header(&mut self, len: usize) -> Option<Stop> {
        self.header_nread += len as u64;
        let limit = self.config.effective_max_header_size();
        if limit != 0 && self.header_nread >= limit {
            // SAFETY: `llhttp` is live and mid-parse.
            unsafe {
                ffi::rn_llhttp_set_error_reason(self.llhttp.get(), ffi::HEADER_OVERFLOW_C.as_ptr())
            };
            return Some(ffi::errno::USER);
        }
        None
    }

    /// `TrackHeaderPair`: enforces `maxHeaderPairs`.
    fn track_header_pair(&mut self) -> Option<Stop> {
        self.header_pairs += 2;
        if self.config.max_header_pairs > 0 && self.header_pairs > self.config.max_header_pairs {
            // SAFETY: `llhttp` is live and mid-parse.
            unsafe {
                ffi::rn_llhttp_set_error_reason(self.llhttp.get(), ffi::HEADER_OVERFLOW_C.as_ptr())
            };
            return Some(ffi::errno::USER);
        }
        None
    }

    // -----------------------------------------------------------------------
    // llhttp callbacks
    // -----------------------------------------------------------------------

    fn on_message_begin(&mut self) {
        self.reset_counters();
        self.received_data = true;
        self.last_message_start = Some(std::time::Instant::now());
        self.accumulator.reset_for_message();
        // Node re-appends to the active list here, which is what keeps it
        // ordered by message start for `expired()`.
        self.push_active();
        self.sync_connections();
        js::call_no_args(self, Slot::MessageBegin);
    }

    fn on_url(&mut self, at: &[u8]) -> Stop {
        if let Some(stop) = self.track_header(at.len()) {
            return stop;
        }
        self.accumulator.url_mut().push(at);
        0
    }

    fn on_status(&mut self, at: &[u8]) -> Stop {
        if let Some(stop) = self.track_header(at.len()) {
            return stop;
        }
        self.accumulator.status_message_mut().push(at);
        0
    }

    fn on_header_field(&mut self, at: &[u8]) -> Stop {
        if let Some(stop) = self.track_header(at.len()) {
            return stop;
        }
        let starting_pair = self.accumulator.field_count() == self.accumulator.value_count();
        if starting_pair {
            if let Some(stop) = self.track_header_pair() {
                return stop;
            }
        }
        if self.accumulator.push_field(at) != Action::Flush {
            return 0;
        }
        // The batch is full: hand it to `kOnHeaders` and keep the name that
        // triggered this as the start of the next one.
        //
        // The URL is read *before* the flush, because `flush_batch` clears it:
        // `Flush()` in the C++ passes `url_` and then calls `url_.Reset()`, so
        // the first call carries it and later ones carry an empty string.
        let url = self.accumulator.url().bytes().to_vec();
        let batch = self.accumulator.flush_batch();
        if js::call_headers(self, &batch, Some(&url)) {
            self.accumulator.mark_flushed();
        }
        0
    }

    fn on_header_value(&mut self, at: &[u8]) -> Stop {
        if let Some(stop) = self.track_header(at.len()) {
            return stop;
        }
        self.accumulator.push_value(at);
        0
    }

    /// `on_headers_complete`: the nine-argument callback.
    ///
    /// Returns llhttp's instruction: 0 to continue, 1 for "no body", 2 for "no
    /// body and stop at the upgrade boundary". A non-integer result or a throw
    /// is reported as [`Self::got_exception`], which stops `execute` without a
    /// value.
    fn on_headers_complete(&mut self) -> Stop {
        self.header_nread = 0;
        self.headers_completed = true;
        self.sync_connections();

        let is_request = self.is_request();

        // `have_flushed_` means `kOnHeaders` already has the batch that was
        // accumulating, so the remaining pairs have to go the same way rather
        // than through this callback's third argument.
        let headers = if self.accumulator.flushed() {
            // The first `kOnHeaders` already carried the URL and `flush_batch`
            // cleared it, so this call sends an empty one — which is what
            // `url_.Reset()` at the end of `Flush()` produces.
            let url = self.accumulator.url().bytes().to_vec();
            let batch = self.accumulator.flush_batch();
            if js::call_headers(self, &batch, Some(&url)) {
                self.accumulator.mark_flushed();
            }
            None
        } else {
            Some(
                self.accumulator
                    .pairs()
                    .into_iter()
                    .map(|(name, value)| (name.to_vec(), value.to_vec()))
                    .collect::<Vec<_>>(),
            )
        };

        // The URL is only passed here on the fast path; after a flush the
        // `kOnHeaders` call above already carried it.
        let url = match (&headers, is_request) {
            (Some(_), true) => Some(self.accumulator.url().bytes().to_vec()),
            _ => None,
        };
        let status_message = if is_request {
            None
        } else {
            Some(self.accumulator.status_message().bytes().to_vec())
        };

        self.header_pairs = 0;
        self.accumulator.clear_pairs();

        // SAFETY: `llhttp` is live and mid-parse, so its fields describe the
        // message being reported.
        let (method, status_code, version_major, version_minor, upgrade) = unsafe {
            (
                ffi::rn_llhttp_method(self.llhttp.get()),
                ffi::rn_llhttp_status_code(self.llhttp.get()),
                ffi::rn_llhttp_http_major(self.llhttp.get()),
                ffi::rn_llhttp_http_minor(self.llhttp.get()),
                ffi::rn_llhttp_upgrade(self.llhttp.get()),
            )
        };
        let keep_alive = self.should_keep_alive();

        let decision = js::call_headers_complete(
            self,
            js::HeadersCompleteArgs {
                version_major,
                version_minor,
                headers: headers.as_deref(),
                method: if is_request { Some(method) } else { None },
                url: url.as_deref(),
                status_code: if is_request { None } else { Some(status_code) },
                status_message: status_message.as_deref(),
                upgrade: upgrade != 0,
                keep_alive,
            },
        );
        match decision {
            js::HeadersComplete::Instruction(instruction) => instruction,
            // No function installed is llhttp's default: carry on.
            js::HeadersComplete::NoCallback => 0,
            js::HeadersComplete::Failed => {
                // Node marks the parser as failed and returns -1, so llhttp
                // stops and `execute` yields no value.
                self.got_exception = true;
                -1
            }
        }
    }

    fn on_body(&mut self, at: *const u8, length: usize) -> Stop {
        if length == 0 {
            return 0;
        }
        // Node checks the limit *before* recording, so the overflowing span is
        // dropped rather than partially retained.
        if self.body.len + length > MAX_BUFFERED_BODY_SIZE && !self.flush_body() {
            // SAFETY: `llhttp` is live and mid-parse.
            unsafe {
                ffi::rn_llhttp_set_error_reason(self.llhttp.get(), JS_EXCEPTION_REASON.as_ptr())
            };
            return ffi::errno::USER;
        }
        self.body.push(at, length);
        0
    }

    /// Delivers the collected body in one `kOnBody` call.
    ///
    /// Returns false when the callback threw.
    fn flush_body(&mut self) -> bool {
        if self.body.is_empty() {
            return true;
        }
        // The bytes are borrowed out of `self`, and `call_body` needs `self`
        // mutably, so they are copied first. Node copies too: `Buffer::Copy`.
        let bytes = self.body.bytes().to_vec();
        let threw = self.got_exception || !js::call_body(self, &bytes);
        self.body.clear();
        if threw {
            self.got_exception = true;
            return false;
        }
        true
    }

    fn on_message_complete(&mut self) -> Stop {
        if !self.flush_body() {
            return -1;
        }
        self.last_message_start = None;

        // Trailing headers go through `kOnHeaders`, as in Node.
        if !self.accumulator.is_empty() {
            let batch = self.accumulator.flush_batch();
            let url = self.accumulator.url().bytes().to_vec();
            if js::call_headers(self, &batch, Some(&url)) {
                self.accumulator.mark_flushed();
            }
        }
        self.header_pairs = 0;

        // Node pops the active list before reporting completion, so a message
        // that completes is never reported as a live connection.
        self.pop_active();
        self.sync_connections();

        if self.being_freed {
            return 0;
        }
        js::call_no_args(self, Slot::MessageComplete);
        0
    }

    fn on_chunk_header(&mut self) -> Stop {
        self.header_nread = 0;
        self.chunk_extensions_nread = 0;
        0
    }

    fn on_chunk_complete(&mut self) -> Stop {
        self.header_nread = 0;
        0
    }

    // -----------------------------------------------------------------------
    // Callback plumbing shared with `js`
    // -----------------------------------------------------------------------

    pub(crate) fn cached_callback(&self, slot: Slot) -> Option<&v8::Global<v8::Function>> {
        self.callbacks[slot.index()].as_ref()
    }

    pub(crate) fn cache_callback(&mut self, slot: Slot, callback: v8::Global<v8::Function>) {
        self.callbacks[slot.index()] = Some(callback);
    }

    pub(crate) fn object(&self) -> Option<&v8::Weak<v8::Object>> {
        self.object.as_ref()
    }

    /// Registers this parser with `list`, which is what `initialize` does when a
    /// `ConnectionsList` is passed.
    ///
    /// Node pushes onto both lists and stamps `last_message_start_`, so a
    /// connection that never sends a byte can still expire.
    pub fn register_connections(&mut self, scope: &mut v8::PinScope<'_, '_>, list: SharedList) {
        let _ = scope;
        let entry: Entry = std::rc::Rc::new(std::cell::RefCell::new(EntryState {
            last_message_start: self.last_message_start,
            received_data: self.received_data,
            headers_completed: self.headers_completed,
            // The list reports parsers as objects, so the entry needs a handle
            // to this one. It is the same weak handle the parser already keeps.
            object: self.object.clone(),
            in_all: false,
            in_active: false,
        }));
        {
            let mut list = list.borrow_mut();
            list.push(&entry);
            list.push_active(&entry);
        }
        // The parser keeps the entry so every message transition can update it
        // without going back through the JavaScript object.
        self.connections = Some((list, entry));
    }

    /// Removes this parser from its list, if it has one. Node does this in
    /// `remove()` and when the active list reports it expired.
    pub fn release_connections(&mut self) {
        if let Some((list, entry)) = self.connections.take() {
            let mut list = list.borrow_mut();
            list.pop(&entry);
            list.pop_active(&entry);
        }
    }

    /// Mirrors the parser's message state into its list entry.
    fn sync_connections(&self) {
        if let Some((_, entry)) = &self.connections {
            let mut state = entry.borrow_mut();
            state.last_message_start = self.last_message_start;
            state.received_data = self.received_data;
            state.headers_completed = self.headers_completed;
        }
    }

    /// Adds this parser to its list's active set, which `on_message_begin` does.
    fn push_active(&self) {
        if let Some((list, entry)) = &self.connections {
            list.borrow_mut().push_active(entry);
        }
    }

    /// Removes this parser from its list's active set, which
    /// `on_message_complete` does.
    fn pop_active(&self) {
        if let Some((list, entry)) = &self.connections {
            list.borrow_mut().pop_active(entry);
        }
    }

    pub(crate) fn isolate_ptr(&self) -> v8::UnsafeRawIsolatePtr {
        self.isolate
    }

    pub(crate) fn context(&self) -> Option<&v8::Global<v8::Context>> {
        self.context.as_ref()
    }

    pub(crate) fn note_exception(&mut self) {
        self.got_exception = true;
    }
}

impl Drop for Parser {
    fn drop(&mut self) {
        if !self.llhttp.get().is_null() {
            // SAFETY: `llhttp` came from `rn_llhttp_new` and is freed here
            // exactly once.
            unsafe { ffi::rn_llhttp_free(self.llhttp.get()) };
            self.llhttp.set(std::ptr::null_mut());
        }
    }
}

// ---------------------------------------------------------------------------
// Trampolines
// ---------------------------------------------------------------------------

/// Recovers the parser from `user` and runs `body`.
///
/// # Safety
///
/// `user` must be the pointer `Parser::create` gave llhttp.
unsafe fn run(user: *mut c_void, body: impl FnOnce(&mut Parser) -> Stop) -> Stop {
    if user.is_null() {
        return 0;
    }
    // SAFETY: `user` is the pointer `Parser::create` stored, and the parser
    // outlives every callback because `Drop` frees llhttp first.
    let parser = unsafe { &mut *user.cast::<Parser>() };
    if parser.being_freed {
        return 0;
    }
    body(parser)
}

/// Borrows an llhttp span as a slice.
///
/// # Safety
///
/// `at` must cover `length` readable bytes.
unsafe fn span<'a>(at: *const c_char, length: usize) -> &'a [u8] {
    if length == 0 || at.is_null() {
        return &[];
    }
    // SAFETY: delegated to the caller.
    unsafe { std::slice::from_raw_parts(at.cast::<u8>(), length) }
}

unsafe extern "C" fn on_message_begin(user: *mut c_void) -> c_int {
    // SAFETY: llhttp passes the `user` pointer from its settings.
    unsafe {
        run(user, |parser| {
            parser.on_message_begin();
            0
        })
    }
}

unsafe extern "C" fn on_url(user: *mut c_void, at: *const c_char, length: usize) -> c_int {
    // SAFETY: as above, plus the span contract llhttp guarantees.
    let at = unsafe { span(at, length) };
    unsafe { run(user, |parser| parser.on_url(at)) }
}

unsafe extern "C" fn on_status(user: *mut c_void, at: *const c_char, length: usize) -> c_int {
    // SAFETY: as above.
    let at = unsafe { span(at, length) };
    unsafe { run(user, |parser| parser.on_status(at)) }
}

unsafe extern "C" fn on_header_field(user: *mut c_void, at: *const c_char, length: usize) -> c_int {
    // SAFETY: as above.
    let at = unsafe { span(at, length) };
    unsafe { run(user, |parser| parser.on_header_field(at)) }
}

unsafe extern "C" fn on_header_value(user: *mut c_void, at: *const c_char, length: usize) -> c_int {
    // SAFETY: as above.
    let at = unsafe { span(at, length) };
    unsafe { run(user, |parser| parser.on_header_value(at)) }
}

unsafe extern "C" fn on_headers_complete(user: *mut c_void) -> c_int {
    // SAFETY: llhttp passes the `user` pointer from its settings.
    unsafe { run(user, |parser| parser.on_headers_complete()) }
}

unsafe extern "C" fn on_body(user: *mut c_void, at: *const c_char, length: usize) -> c_int {
    // SAFETY: llhttp guarantees `at` covers `length` bytes of the buffer being
    // parsed, which outlives this callback.
    unsafe { run(user, |parser| parser.on_body(at.cast::<u8>(), length)) }
}

unsafe extern "C" fn on_message_complete(user: *mut c_void) -> c_int {
    // SAFETY: llhttp passes the `user` pointer from its settings.
    unsafe { run(user, |parser| parser.on_message_complete()) }
}

unsafe extern "C" fn on_chunk_header(user: *mut c_void) -> c_int {
    // SAFETY: as above.
    unsafe { run(user, |parser| parser.on_chunk_header()) }
}

unsafe extern "C" fn on_chunk_complete(user: *mut c_void) -> c_int {
    // SAFETY: as above.
    unsafe { run(user, |parser| parser.on_chunk_complete()) }
}

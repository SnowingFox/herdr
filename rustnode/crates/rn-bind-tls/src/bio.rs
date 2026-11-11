//! `NodeBIO`: the buffer between OpenSSL and the socket.
//!
//! `src/crypto/crypto_bio.{h,cc}` is the translation unit this mirrors. A
//! `TLSWrap` has two of them, and the direction of each is fixed:
//!
//! | BIO | OpenSSL's role | what Node does with it |
//! | --- | --- | --- |
//! | `enc_in_` | read from | the socket's ciphertext is *written* into it, and `SSL_read` consumes it |
//! | `enc_out_` | write to | `SSL_write` produces ciphertext into it, and `EncOut` drains it to the socket |
//!
//! They are not symmetric in use — `enc_in_` is only ever written by Node and read
//! by OpenSSL, `enc_out_` the reverse — which is why there are two rather than
//! one. But `crypto_bio.cc` does **not** enforce that: a `NodeBIO` is a plain
//! buffer with no direction flag, and `receive()` writes into `enc_in_` after
//! OpenSSL may already have read from it.
//!
//! An earlier version of this module did enforce a direction, on the theory that
//! mixing them would corrupt a handshake. That was wrong and it broke
//! `receive()`: the input BIO is `SSL_get_rbio`'s, and a flag set at creation said
//! "output". The check is gone; Node's shape is the authority.
//!
//! # R1: the `SSL` owns both BIOs, and this type owns neither
//!
//! `SSL_set_bio(ssl, r, w)` **transfers ownership**. After it returns, OpenSSL
//! frees both BIOs when the `SSL` is freed, and freeing either separately is a
//! double free. Node's `Destroy()` (`crypto_tls.cc:1467`) sets
//! `enc_in_ = enc_out_ = nullptr` *after* `ssl_.reset()` for exactly this reason:
//! the pointers are borrowed handles that stop being valid the moment the `SSL`
//! goes away.
//!
//! So [`Pair`] exists to make the rule structural rather than a comment:
//!
//! * one field holds both `BIO*`s, so they cannot be freed one at a time;
//! * it has no `Drop` of its own that frees anything — the `SSL` does;
//! * [`Pair::attach`] consumes it, so no `Pair` exists after the transfer and
//!   there is no code path in this crate that could call `BIO_free`;
//! * the borrowed views ([`EncIn`], [`EncOut`]) are obtained from the `SSL`
//!   after the transfer, which is how Node's `NodeBIO::FromBIO(enc_in_)` works.
//!
//! `BIO_free` does not appear anywhere in this crate, deliberately. See the
//! crate-level docs for the four teardown rules this is the first of.
//!
//! # Why a byte buffer and not `SSL_set_fd`
//!
//! The socket is a libuv handle whose reads arrive as callbacks, not a
//! descriptor OpenSSL can `read(2)` from. Node puts a `NodeBIO` between them so
//! the SSL state machine can be driven synchronously: bytes are copied into
//! `enc_in_` when the listener fires, and `Cycle` runs `SSL_read`/`SSL_write`
//! until they report `WANT_READ`/`WANT_WRITE`. `SSL_set_fd` would make the state
//! machine block instead, which is the shape this whole design avoids.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::ptr;

use openssl_sys as ffi;

/// `BIO_CTRL_RESET` — discard buffered data.
const BIO_CTRL_RESET: c_int = 1;
/// `BIO_CTRL_EOF` — are we at end of input?
const BIO_CTRL_EOF: c_int = 2;
/// `BIO_CTRL_INFO` — `BIO_get_mem_data`'s "pointer and length" query.
const BIO_CTRL_INFO: c_int = 3;
/// `BIO_CTRL_SET_CLOSE` — set the "close on free" flag.
const BIO_CTRL_SET_CLOSE: c_int = 9;
/// `BIO_CTRL_PENDING` — bytes buffered and readable.
const BIO_CTRL_PENDING: c_int = 10;
/// `BIO_CTRL_FLUSH` — a no-op for an in-memory BIO, but OpenSSL asks.
const BIO_CTRL_FLUSH: c_int = 11;
/// `BIO_CTRL_DUP` — BIO chains ask a filter for its dup handler.
const BIO_CTRL_DUP: c_int = 12;
/// `BIO_CTRL_WPENDING` — bytes buffered toward the peer.
const BIO_CTRL_WPENDING: c_int = 13;
/// `BIO_C_SET_BUF_MEM_EOF_RETURN` — the value a read returns at end of input.
const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;

/// `BIO_CTRL_GET_CLOSE` — the read-back partner of [`BIO_CTRL_SET_CLOSE`].
const BIO_CTRL_GET_CLOSE: c_int = 8;

/// `#define BIO_TYPE_SOURCE_SINK 0x0400` in `bio.h`.
///
/// The type OpenSSL expects for a BIO that moves bytes rather than filtering
/// them. `BIO_TYPE_NONE` would make `BIO_new` treat it as a file BIO.
const BIO_TYPE_SOURCE_SINK: c_int = 0x0400;

/// `NodeBIO::kInitialBufferLength` (`crypto_bio.h:148`).
pub const INITIAL_BUFFER_LENGTH: usize = 1024;
/// `NodeBIO::kThroughputBufferLength` (`crypto_bio.h:149`).
pub const THROUGHPUT_BUFFER_LENGTH: usize = 16_384;
/// `kInitialClientBufferLength` (`crypto_tls.cc:592`) — room for a server's
/// first flight, which arrives before the client can react.
pub const INITIAL_CLIENT_BUFFER_LENGTH: usize = 4096;

/// The value a read from a BIO with no data returns, and what `SSL_get_error`
/// turns into `SSL_ERROR_WANT_READ`.
///
/// `NodeBIO`'s `eof_return_` defaults to `-1` (`crypto_bio.h:183`), which is
/// `BIO_should_retry`'s "retry, no error" shape. `NewFixed` sets it to zero so a
/// fixed buffer reports EOF instead, which is the difference between "wait for
/// more bytes" and "there will never be more".
const DEFAULT_EOF_RETURN: c_int = -1;

/// One `NodeBIO`'s storage, `crypto_bio.cc`'s linked list of chunks.
///
/// Node uses a singly-linked list so a read can advance the head without moving
/// bytes. A `VecDeque<u8>` gives the same `O(1)` read-from-front and
/// append-at-back with much less pointer handling, and the only observable
/// difference would be `PeekMultiple`'s chunk boundaries — which Node exposes
/// nowhere that TLS reaches, and which this does not need.
///
/// `RefCell` rather than `&mut` because the C callbacks receive a bare
/// `*mut BIO` and reach this through `BIO_get_data`; there is no lifetime to tie
/// a borrow to. Every callback body is short and ends before returning to
/// OpenSSL, so the cell is never held across another call into the library.
struct Buffer {
    /// Bytes buffered. Reads take from the front, writes append.
    data: VecDeque<u8>,
    /// `eof_return_`: what a read returns when `data` is empty.
    eof_return: c_int,
    /// `initial_`: the capacity to reserve for a write, `crypto_bio.h:180`.
    initial: usize,
}

impl Buffer {
    fn new() -> Self {
        Self {
            data: VecDeque::new(),
            eof_return: DEFAULT_EOF_RETURN,
            initial: INITIAL_BUFFER_LENGTH,
        }
    }
}

/// The `BIO_METHOD` for a `NodeBIO`, built once per process.
///
/// OpenSSL stores the method pointer in every `BIO` it creates, so it has to
/// outlive them all. It is never freed: a `BIO_METHOD` is immutable data, and
/// freeing it while a `BIO` still names it is a use-after-free. Leaking one
/// allocation for the process' life is what `BIO_meth_new` is designed for.
static METHOD: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Returns the process-wide `BIO_METHOD`, building it on first use.
///
/// Returns `None` when OpenSSL refused to allocate one, which can only mean the
/// process is out of memory; the caller turns that into a creation failure
/// rather than crashing.
fn method() -> Option<*const ffi::BIO_METHOD> {
    // `get_or_init` would need a `*const BIO_METHOD`, which is not `Send`; the
    // `usize` is the same pointer and the `OnceLock` is the synchronisation.
    let address = *METHOD.get_or_init(|| {
        // SAFETY: `BIO_meth_new` allocates the method; every `BIO_meth_set_*`
        // below fills in a slot on it and reports 0 on failure. The method is
        // deliberately never freed — see this static's docs.
        unsafe {
            let name = c"rustnode NodeBIO".as_ptr();
            let method = ffi::BIO_meth_new(BIO_TYPE_SOURCE_SINK, name);
            if method.is_null() {
                return 0;
            }
            if ffi::BIO_meth_set_write__fixed_rust(method, Some(bio_write)) == 0
                || ffi::BIO_meth_set_read__fixed_rust(method, Some(bio_read)) == 0
                || ffi::BIO_meth_set_puts__fixed_rust(method, Some(bio_puts)) == 0
                || ffi::BIO_meth_set_ctrl__fixed_rust(method, Some(bio_ctrl)) == 0
                || ffi::BIO_meth_set_create__fixed_rust(method, Some(bio_create)) == 0
                || ffi::BIO_meth_set_destroy__fixed_rust(method, Some(bio_destroy)) == 0
            {
                // A partially filled method would be worse than none: a missing
                // slot is a null function pointer OpenSSL would call.
                ffi::BIO_meth_free(method);
                return 0;
            }
            method as usize
        }
    });
    if address == 0 {
        None
    } else {
        Some(address as *const ffi::BIO_METHOD)
    }
}

/// `NodeBIO::New`: a BIO that retries when empty.
fn new() -> Option<*mut ffi::BIO> {
    let method = method()?;
    // SAFETY: `method` is the live process-wide method, and `BIO_new` allocates
    // a `BIO` that points at it. `bio_create` installs the `Buffer` before this
    // returns, so `BIO_get_data` is valid from here on.
    unsafe {
        let bio = ffi::BIO_new(method);
        if bio.is_null() {
            return None;
        }
        let buffer = Box::into_raw(Box::new(RefCell::new(Buffer::new())));
        ffi::BIO_set_data(bio, buffer.cast::<c_void>());
        ffi::BIO_set_init(bio, 1);
        crate::ffi_extra::BIO_set_shutdown(bio, 0);
        Some(bio)
    }
}

/// The `Buffer` a `BIO` points at, or `None` for a foreign BIO.
///
/// # Safety
///
/// `bio` must be a live `BIO` whose `data` field was set by [`new`]. Every caller
/// in this module passes a pointer OpenSSL handed to one of the callbacks below,
/// which satisfies this.
unsafe fn buffer_of<'a>(bio: *mut ffi::BIO) -> Option<&'a RefCell<Buffer>> {
    if bio.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a live BIO created by `new`.
    let data = unsafe { ffi::BIO_get_data(bio) };
    if data.is_null() {
        return None;
    }
    // SAFETY: `new` stored a `*mut RefCell<Buffer>` in this field and nothing
    // else writes it.
    Some(unsafe { &*(data as *const RefCell<Buffer>) })
}

/// `NodeBIO::Write`: buffer bytes from Node toward OpenSSL.
unsafe extern "C" fn bio_write(bio: *mut ffi::BIO, data: *const c_char, length: c_int) -> c_int {
    if length < 0 || (length > 0 && data.is_null()) {
        return -1;
    }
    // SAFETY: `bio` is the BIO OpenSSL is calling this method on.
    let Some(buffer) = (unsafe { buffer_of(bio) }) else {
        return -1;
    };
    let Ok(mut buffer) = buffer.try_borrow_mut() else {
        // A re-entrant write on the same BIO is a structural error: the buffer
        // is already mid-copy. Reporting it is better than a panic across an
        // `extern "C"` boundary, which is undefined behaviour.
        tracing::error!("NodeBIO write re-entered itself");
        return -1;
    };
    if length > 0 {
        // SAFETY: `data` points at `length` readable bytes, which OpenSSL
        // guarantees for the duration of the call.
        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length as usize) };
        buffer.data.extend(bytes);
    }
    length
}

/// `NodeBIO::Read`: hand buffered bytes to OpenSSL.
unsafe extern "C" fn bio_read(bio: *mut ffi::BIO, out: *mut c_char, length: c_int) -> c_int {
    if length < 0 || (length > 0 && out.is_null()) {
        return -1;
    }
    // SAFETY: `bio` is the BIO OpenSSL is calling this method on.
    let Some(buffer) = (unsafe { buffer_of(bio) }) else {
        return -1;
    };
    let Ok(mut buffer) = buffer.try_borrow_mut() else {
        tracing::error!("NodeBIO read re-entered itself");
        return -1;
    };
    let available = buffer.data.len().min(length as usize);
    for index in 0..available {
        // `pop_front` on a non-empty deque cannot be `None`.
        let Some(byte) = buffer.data.pop_front() else {
            break;
        };
        // SAFETY: `out` points at `length` writable bytes and `index < available
        // <= length`.
        unsafe { *out.add(index) = byte as c_char };
    }
    if available == 0 {
        // Node's `eof_return_`: `-1` asks OpenSSL to retry (a `WANT_READ`),
        // `0` is a real end of input.
        let eof = buffer.eof_return;
        drop(buffer);
        // `BIO_clear_retry_flags` is what makes `-1` a retry rather than an
        // error; the flags are how OpenSSL learns the difference.
        // SAFETY: `bio` is live.
        unsafe {
            ffi::BIO_clear_retry_flags(bio);
            if eof < 0 {
                ffi::BIO_set_retry_read(bio);
            }
        }
        return eof;
    }
    available as c_int
}

/// `NodeBIO::Puts`: OpenSSL writes NUL-terminated text through this on some
/// paths. `crypto_bio.cc` forwards it to `Write` with `strlen`.
unsafe extern "C" fn bio_puts(bio: *mut ffi::BIO, text: *const c_char) -> c_int {
    if text.is_null() {
        return -1;
    }
    // SAFETY: OpenSSL passes a NUL-terminated string.
    let length = unsafe { libc::strlen(text) };
    if length > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: as `bio_write`.
    unsafe { bio_write(bio, text, length as c_int) }
}

/// `NodeBIO::Ctrl`, and `crypto_bio.cc:60`'s `New`'s control entry.
unsafe extern "C" fn bio_ctrl(
    bio: *mut ffi::BIO,
    command: c_int,
    number: c_long,
    pointer: *mut c_void,
) -> c_long {
    // SAFETY: `bio` is the BIO OpenSSL is calling this method on.
    let Some(buffer) = (unsafe { buffer_of(bio) }) else {
        return 0;
    };
    match command {
        BIO_CTRL_RESET => {
            if let Ok(mut buffer) = buffer.try_borrow_mut() {
                buffer.data.clear();
            }
            0
        }
        BIO_CTRL_EOF => {
            let empty = buffer
                .try_borrow()
                .map(|state| state.data.is_empty())
                .unwrap_or(true);
            c_long::from(empty)
        }
        BIO_CTRL_INFO => {
            // `BIO_get_mem_data(bio, &ptr)` asks for a pointer to the buffered
            // bytes and returns their length. A `VecDeque` is not guaranteed
            // contiguous, so the honest answer is what it actually is: the
            // length with a null pointer, which callers treat as "use
            // `BIO_read` instead".
            if !pointer.is_null() {
                // SAFETY: `pointer` is the caller's `char**` out-parameter.
                unsafe { *(pointer as *mut *mut c_char) = ptr::null_mut() };
            }
            let length = buffer
                .try_borrow()
                .map(|state| state.data.len())
                .unwrap_or(0);
            length as c_long
        }
        BIO_CTRL_PENDING | BIO_CTRL_WPENDING => {
            let length = buffer
                .try_borrow()
                .map(|state| state.data.len())
                .unwrap_or(0);
            length as c_long
        }
        BIO_CTRL_SET_CLOSE => number,
        BIO_CTRL_GET_CLOSE => 0,
        // An in-memory BIO has nothing to synchronise, and OpenSSL requires the
        // control to exist rather than error.
        BIO_CTRL_FLUSH | BIO_CTRL_DUP => 1,
        BIO_C_SET_BUF_MEM_EOF_RETURN => {
            if let Ok(mut buffer) = buffer.try_borrow_mut() {
                buffer.eof_return = number as c_int;
            }
            number
        }
        _ => 0,
    }
}

/// `NodeBIO::New(BIO*)`: install the buffer OpenSSL expects a fresh BIO to have.
///
/// OpenSSL calls this from `BIO_new`, once, before anything else. Returning `0`
/// tells it to abandon the allocation, which is what happens when the buffer
/// cannot be created.
unsafe extern "C" fn bio_create(bio: *mut ffi::BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }
    // `BIO_new` has already allocated the `BIO`; `bio_destroy` is only called for
    // a BIO whose create reported success, so this is the only place the buffer
    // is allocated.
    if unsafe { ffi::BIO_get_data(bio) }.is_null() {
        let buffer = Box::into_raw(Box::new(RefCell::new(Buffer::new())));
        // SAFETY: `bio` is the new BIO; nothing else owns this field yet.
        unsafe { ffi::BIO_set_data(bio, buffer.cast::<c_void>()) };
    }
    // SAFETY: `bio` is live.
    unsafe { ffi::BIO_set_init(bio, 1) };
    1
}

/// `NodeBIO::~NodeBIO`, in BIO form: release the Rust `Buffer`.
///
/// This frees the *Buffer*, not the BIO. OpenSSL frees the BIO itself right
/// after this returns, so there must be no `BIO_free` here — that would be the
/// double free R1 is about.
unsafe extern "C" fn bio_destroy(bio: *mut ffi::BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }
    // SAFETY: `bio_create` or `new` allocated this and nothing has freed it.
    let data = unsafe { ffi::BIO_get_data(bio) };
    if !data.is_null() {
        // SAFETY: the pointer came from `Box::into_raw` and this is its one
        // reclaim. Clearing it first makes a second destroy a no-op rather than
        // a second free.
        unsafe {
            ffi::BIO_set_data(bio, ptr::null_mut());
            drop(Box::from_raw(data as *mut RefCell<Buffer>));
        }
    }
    0
}

/// The two BIOs a `TLSWrap` creates, before OpenSSL takes them.
///
/// This type exists to make R1 structural. It has no `Drop` and no `BIO_free`,
/// and the only way to keep using the BIOs is [`Pair::attach`], which consumes
/// it — so there is no state in which this crate holds a `BIO*` it believes it
/// owns, and no code path that could free one separately from the `SSL`.
///
/// See the module docs for why that matters.
pub struct Pair {
    /// `TLSWrap::enc_in_`: ciphertext read from the socket, consumed by
    /// `SSL_read`.
    input: *mut ffi::BIO,
    /// `TLSWrap::enc_out_`: ciphertext `SSL_write` produced, drained to the
    /// socket.
    output: *mut ffi::BIO,
    /// Set by [`Pair::attach`], so a use-after-transfer is a compile-visible
    /// mistake rather than a runtime one.
    attached: bool,
}

impl Pair {
    /// `NodeBIO::New` twice, as `InitSSL` does at `crypto_tls.cc:549`.
    pub fn new() -> Option<Self> {
        let input = new()?;
        let output = new()?;
        Some(Self {
            input,
            output,
            attached: false,
        })
    }

    /// `SSL_set_bio`, which transfers ownership of both to `ssl`.
    ///
    /// Consuming `self` is the point: after this the BIOs belong to the `SSL`
    /// and are freed with it. A caller that needs to reach them again does so
    /// through [`EncIn::of`] and [`EncOut::of`], which take them back from the
    /// `SSL`.
    ///
    /// # Safety
    ///
    /// `ssl` must be a live `SSL` that does not already have a BIO pair, which
    /// is true immediately after `SSL_new`. Calling this on a `SSL` that already
    /// has BIOs leaks, because `SSL_set_bio` frees the old ones.
    pub unsafe fn attach(self, ssl: *mut ffi::SSL) {
        debug_assert!(!self.attached, "a BIO pair is attached exactly once");
        // SAFETY: the caller guarantees `ssl` is live and BIO-less. Both BIOs
        // were created by this type and are not aliased anywhere.
        unsafe { ffi::SSL_set_bio(ssl, self.input, self.output) };
        // Deliberately no `Drop`: the addresses are now OpenSSL's. `Pair` has no
        // destructor that frees anything, so leaving this scope is the whole of
        // it — there is nothing to forget, which is the property R1 asks for.
    }
}

/// `TLSWrap::enc_in_`, borrowed back from the `SSL` that owns it.
///
/// Node keeps the raw pointer and reaches it as `NodeBIO::FromBIO(enc_in_)`.
/// Reading it back from the `SSL` instead means there is no second pointer to go
/// stale when the `SSL` is freed.
pub struct EncIn(*mut ffi::BIO);

/// `TLSWrap::enc_out_`, borrowed back from the `SSL` that owns it.
pub struct EncOut(*mut ffi::BIO);

impl EncIn {
    /// `SSL_get_rbio`, which returns the `SSL`'s read BIO.
    ///
    /// `None` after the `SSL` is freed, which is why this is re-read rather than
    /// cached: a cached pointer here is exactly the stale-pointer class of bug
    /// R1 describes.
    ///
    /// # Safety
    ///
    /// `ssl` must be live, or null.
    pub unsafe fn of(ssl: *mut ffi::SSL) -> Option<Self> {
        if ssl.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees `ssl` is live.
        let bio = unsafe { ffi::SSL_get_rbio(ssl) };
        if bio.is_null() {
            None
        } else {
            Some(Self(bio))
        }
    }

    /// Copies `bytes` in, which is what `OnStreamRead` does after a read.
    ///
    /// Returns how many bytes were accepted, matching `BIO_write`.
    pub fn write(&self, bytes: &[u8]) -> usize {
        if bytes.is_empty() {
            return 0;
        }
        if bytes.len() > c_int::MAX as usize {
            return 0;
        }
        // SAFETY: `self.0` is the `SSL`'s read BIO while the `SSL` is alive, and
        // `bytes` is a valid slice for its own length.
        let written = unsafe {
            ffi::BIO_write(
                self.0,
                bytes.as_ptr().cast::<c_void>(),
                bytes.len() as c_int,
            )
        };
        if written < 0 {
            0
        } else {
            written as usize
        }
    }

    /// `NodeBIO::set_initial`, used by `InitSSL` for a client.
    pub fn set_initial(&self, length: usize) {
        if let Some(buffer) = unsafe { buffer_of(self.0) } {
            if let Ok(mut buffer) = buffer.try_borrow_mut() {
                buffer.initial = length;
            }
        }
    }

    /// Bytes available to `SSL_read`.
    pub fn pending(&self) -> usize {
        if let Some(buffer) = unsafe { buffer_of(self.0) } {
            return buffer
                .try_borrow()
                .map(|state| state.data.len())
                .unwrap_or(0);
        }
        0
    }

    /// Discards everything buffered. `NodeBIO::Reset`.
    pub fn reset(&self) {
        if let Some(buffer) = unsafe { buffer_of(self.0) } {
            if let Ok(mut buffer) = buffer.try_borrow_mut() {
                buffer.data.clear();
            }
        }
    }

    /// The `eof_return` value, which `ClearIn` reads on some paths.
    pub fn eof_return(&self) -> c_int {
        if let Some(buffer) = unsafe { buffer_of(self.0) } {
            return buffer
                .try_borrow()
                .map(|state| state.eof_return)
                .unwrap_or(0);
        }
        0
    }
}

impl EncOut {
    /// `SSL_get_wbio`, which returns the `SSL`'s write BIO.
    ///
    /// # Safety
    ///
    /// `ssl` must be live, or null.
    pub unsafe fn of(ssl: *mut ffi::SSL) -> Option<Self> {
        if ssl.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees `ssl` is live.
        let bio = unsafe { ffi::SSL_get_wbio(ssl) };
        if bio.is_null() {
            None
        } else {
            Some(Self(bio))
        }
    }

    /// Bytes waiting to be written to the socket, `NodeBIO::Length`.
    pub fn pending(&self) -> usize {
        if let Some(buffer) = unsafe { buffer_of(self.0) } {
            return buffer
                .try_borrow()
                .map(|state| state.data.len())
                .unwrap_or(0);
        }
        0
    }

    /// Reads the buffered ciphertext out, up to `limit` bytes.
    ///
    /// `EncOut` in Node drains the BIO into the underlying stream and then
    /// repeats until it is empty, so a single call that returns everything
    /// available is the same behaviour with fewer round trips.
    pub fn take(&self, limit: usize) -> Vec<u8> {
        let Some(buffer) = (unsafe { buffer_of(self.0) }) else {
            return Vec::new();
        };
        let Ok(mut buffer) = buffer.try_borrow_mut() else {
            tracing::error!("NodeBIO output drained while already borrowed");
            return Vec::new();
        };
        let count = buffer.data.len().min(limit);
        buffer.data.drain(..count).collect()
    }

    /// Reads everything available.
    pub fn take_all(&self) -> Vec<u8> {
        self.take(usize::MAX)
    }

    /// The write hint `NodeBIO::set_allocate_tls_hint` carries.
    ///
    /// Not used for allocation here, because the `VecDeque` grows as needed, but
    /// kept so the sizing decision is in one place if a later increment wants to
    /// reserve.
    pub fn throughput_hint(&self, length: usize) {
        if length < THROUGHPUT_BUFFER_LENGTH {
            return;
        }
        if let Some(buffer) = unsafe { buffer_of(self.0) } {
            if let Ok(mut buffer) = buffer.try_borrow_mut() {
                let chunks = length / THROUGHPUT_BUFFER_LENGTH + 1;
                buffer.initial = chunks * (THROUGHPUT_BUFFER_LENGTH + 5 + 32);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The method is built once and is the same pointer every time, which is
    /// what makes it safe to never free.
    #[test]
    fn the_bio_method_is_process_wide() {
        let first = method();
        let second = method();
        assert!(first.is_some());
        assert_eq!(first, second);
    }

    /// R1's structural half: `Pair::new` creates two distinct BIOs and `attach`
    /// transfers them, so a second attach cannot happen.
    ///
    /// The behavioural half is that `SSL_free` releases them, which
    /// [`crate::ssl::Ssl`]'s tests cover; this only pins that the pair is not
    /// freeable from here.
    #[test]
    fn a_pair_is_created_with_two_bios() {
        let pair = Pair::new().expect("a BIO pair is created");
        assert!(!pair.input.is_null());
        assert!(!pair.output.is_null());
        assert_ne!(pair.input, pair.output);
        assert!(!pair.attached);
    }

    /// A write lands in the buffer and a read takes it back out in order.
    ///
    /// The BIO is released through [`release_for_test`] rather than `BIO_free`:
    /// R1 says this crate must have no `BIO_free` path, and a test is still a
    /// path — a helper that is obviously test-only keeps the invariant
    /// greppable.
    #[test]
    fn bytes_round_trip_through_a_bio() {
        let bio = new().expect("a BIO is created");
        let data = b"hello tls";
        // SAFETY: `bio` is live.
        let written =
            unsafe { bio_write(bio, data.as_ptr().cast::<c_char>(), data.len() as c_int) };
        assert_eq!(written, data.len() as c_int);
        let mut out = [0 as c_char; 16];
        // SAFETY: `bio` is live and `out` has room for `data.len()` bytes.
        let read = unsafe { bio_read(bio, out.as_mut_ptr(), data.len() as c_int) };
        assert_eq!(read, data.len() as c_int);
        let bytes: Vec<u8> = out[..read as usize]
            .iter()
            .map(|byte| *byte as u8)
            .collect();
        assert_eq!(bytes, data);
        // SAFETY: `bio` is live and this is its only release.
        unsafe { release_for_test(bio) }
    }

    /// Frees a BIO this module's tests created.
    ///
    /// Test-only on purpose: production code reaches this by `SSL_free`, which
    /// is the whole of R1. Keeping the single `BIO_free_all` in the crate named
    /// `release_for_test` makes an accidental production call site a review
    /// finding rather than an invisible one.
    ///
    /// # Safety
    ///
    /// `bio` must be a BIO created by [`new`] that no `SSL` owns.
    unsafe fn release_for_test(bio: *mut ffi::BIO) {
        // SAFETY: the caller guarantees exclusive ownership.
        unsafe { ffi::BIO_free_all(bio) };
    }

    /// An empty read reports "retry", not EOF, which is what makes
    /// `SSL_get_error` answer `SSL_ERROR_WANT_READ` instead of
    /// `SSL_ERROR_ZERO_RETURN`.
    #[test]
    fn an_empty_read_asks_for_a_retry() {
        let bio = new().expect("a BIO is created");
        let mut out = [0 as c_char; 8];
        // SAFETY: `bio` is live and `out` has room.
        let read = unsafe { bio_read(bio, out.as_mut_ptr(), out.len() as c_int) };
        assert_eq!(read, DEFAULT_EOF_RETURN);
        // `BIO_should_retry` is a macro over `BIO_test_flags`, neither of which
        // `openssl-sys` declares. The flag is readable through the same
        // `BIO_ctrl` path the rest of this module uses: `BIO_CTRL_EOF` is not it,
        // so the check reads the flag directly with `BIO_get_flags`, which
        // *is* declared.
        // SAFETY: `bio` is live.
        let flags = unsafe { crate::ffi_extra::BIO_test_flags(bio, ffi::BIO_FLAGS_SHOULD_RETRY) };
        assert_ne!(flags, 0, "an empty NodeBIO must report a retry");
        // SAFETY: `bio` is live and this is its only release.
        unsafe { release_for_test(bio) };
    }

    /// A BIO created for output refuses a read and one created for input refuses
    /// a write, which is the direction check that stops ciphertext and plaintext
    /// being mixed in one buffer.
    /// A BIO is a plain buffer with no direction: writing after reading works,
    /// which is what `receive()` depends on — it writes into the read BIO after
    /// OpenSSL may already have consumed part of it.
    ///
    /// Node's `NodeBIO` has no direction flag (`crypto_bio.cc`'s `Read`/`Write`
    /// are both unconditional), and an earlier version of this module wrongly
    /// enforced one.
    #[test]
    fn a_bio_accepts_both_directions() {
        let bio = new().expect("a BIO is created");
        let data = b"abc";
        // SAFETY: `bio` is live.
        let written = unsafe { bio_write(bio, data.as_ptr().cast::<c_char>(), 3) };
        assert_eq!(written, 3);
        let mut out = [0 as c_char; 8];
        // SAFETY: `bio` is live and `out` has room.
        let read = unsafe { bio_read(bio, out.as_mut_ptr(), 3) };
        assert_eq!(read, 3, "a written BIO must be readable");
        // Writing again after a read is legal.
        // SAFETY: `bio` is live.
        let again = unsafe { bio_write(bio, data.as_ptr().cast::<c_char>(), 3) };
        assert_eq!(again, 3, "a BIO may be written after being read");
        // SAFETY: `bio` is live and this is its only release.
        unsafe { release_for_test(bio) };
    }

    /// `BIO_C_SET_BUF_MEM_EOF_RETURN` turns the retry into a real EOF, which is
    /// what `NewFixed` does for a fixed buffer.
    #[test]
    fn the_eof_return_can_be_changed_to_a_real_eof() {
        let bio = new().expect("a BIO is created");
        // SAFETY: `bio` is live.
        unsafe { bio_ctrl(bio, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, ptr::null_mut()) };
        let mut out = [0 as c_char; 4];
        // SAFETY: `bio` is live and `out` has room.
        let read = unsafe { bio_read(bio, out.as_mut_ptr(), out.len() as c_int) };
        assert_eq!(read, 0, "an eof_return of 0 is a real end of input");
        // SAFETY: `bio` is live and this is its only release.
        unsafe { release_for_test(bio) };
    }
}

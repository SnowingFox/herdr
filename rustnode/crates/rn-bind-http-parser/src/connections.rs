//! `ConnectionsList`: the bookkeeping `lib/internal/http/server.js` uses to
//! find connections that have been open too long.
//!
//! # What it is for
//!
//! A server holds one of these and passes it to every parser's `initialize`.
//! A background interval then asks three questions:
//!
//! * `all()` — every parser sharing this list, for `closeAllConnections()`.
//! * `idle()` — parsers that are between messages, for
//!   `closeIdleConnections()`.
//! * `active()` / `expired(headersTimeout, requestTimeout)` — parsers currently
//!   mid-message, and the subset that has been mid-message too long, for
//!   `headersTimeout`/`requestTimeout`.
//!
//! # Ordering
//!
//! Node keeps two intrusive doubly-linked lists of parsers (`all_node_` and
//! `active_node_`) and relies on insertion order: the active list is appended to
//! every time a message starts, so it is ordered by `last_message_start_` and
//! `expired()` can walk it in order. A `Vec` of shared entries preserves the same
//! order, with removal O(n) instead of O(1). These lists hold live HTTP
//! connections, so that is the right trade: it keeps the intrusive-node
//! bookkeeping out of `Parser`, which is where the aliasing bugs in the C++ live.
//!
//! # Why the entries are shared and the object is weak
//!
//! The list must not keep a closed connection's parser alive. Node's list holds
//! raw `Parser*` and `remove()` unlinks before the object dies; a shared,
//! reference-counted entry makes the parser's own state visible to the list
//! without a pointer back into it, and the weak object handle means a parser that
//! was never `remove()`d can still be collected.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use rn_v8_sys::v8;

use crate::parser::Parser;

/// One parser's connection state, shared with the list that tracks it.
pub type Entry = Rc<RefCell<EntryState>>;

/// The connection state a list asks about.
///
/// These are the `Parser` fields the C++ reads through its pointer, mirrored so
/// the list never has to reach into a parser that may already be gone.
#[derive(Debug, Default)]
pub struct EntryState {
    /// `last_message_start_`. `None` is Node's `0`: not mid-message.
    pub last_message_start: Option<Instant>,
    /// `received_data_`.
    pub received_data: bool,
    /// `headers_completed_`, which the header timeout tests.
    pub headers_completed: bool,
    /// The JavaScript parser object, so `all()`/`idle()`/`active()` can return
    /// it. Weak so the list is not a GC root for closed connections.
    pub object: Option<v8::Weak<v8::Object>>,
    /// Cleared by `remove()`, after which the parser is in neither list.
    pub in_all: bool,
    pub in_active: bool,
}

/// A list of parsers, matching `ConnectionsList` in `src/node_http_parser.cc`.
#[derive(Default)]
pub struct ConnectionsList {
    all: Vec<Entry>,
    active: Vec<Entry>,
}

impl ConnectionsList {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Push`: appends to the all-connections list.
    pub fn push(&mut self, entry: &Entry) {
        if entry.borrow().in_all {
            return;
        }
        entry.borrow_mut().in_all = true;
        self.all.push(Rc::clone(entry));
    }

    /// `Pop`: removes from the all-connections list.
    pub fn pop(&mut self, entry: &Entry) {
        if !entry.borrow().in_all {
            return;
        }
        entry.borrow_mut().in_all = false;
        self.all.retain(|existing| !Rc::ptr_eq(existing, entry));
    }

    /// `PushActive`: appends to the active list, which is therefore ordered by
    /// `last_message_start_`.
    pub fn push_active(&mut self, entry: &Entry) {
        if entry.borrow().in_active {
            return;
        }
        entry.borrow_mut().in_active = true;
        self.active.push(Rc::clone(entry));
    }

    /// `PopActive`: removes from the active list.
    pub fn pop_active(&mut self, entry: &Entry) {
        if !entry.borrow().in_active {
            return;
        }
        entry.borrow_mut().in_active = false;
        self.active.retain(|existing| !Rc::ptr_eq(existing, entry));
    }

    /// `all()`: every parser sharing this list.
    pub fn all(&self) -> Vec<Entry> {
        self.all.clone()
    }

    /// `idle()`: parsers with no message in progress.
    ///
    /// Node's predicate is `last_message_start_ == 0 || !received_data_`. A
    /// parser that has been initialized but not yet started a message has
    /// `last_message_start_` set (Node stamps it in `Initialize` so an idle
    /// connection can still expire) and `received_data_` false, which is what
    /// makes it idle rather than active.
    pub fn idle(&self) -> Vec<Entry> {
        self.all
            .iter()
            .filter(|entry| {
                let state = entry.borrow();
                state.last_message_start.is_none() || !state.received_data
            })
            .cloned()
            .collect()
    }

    /// `active()`: parsers currently mid-message.
    pub fn active(&self) -> Vec<Entry> {
        self.active.clone()
    }

    /// `expired(headers_timeout_ms, request_timeout_ms)`: parsers mid-message
    /// too long, removed from the active list as they are reported.
    pub fn expired(&mut self, headers_timeout_ms: u32, request_timeout_ms: u32) -> Vec<Entry> {
        let (headers_timeout, request_timeout) =
            normalize_timeouts(headers_timeout_ms, request_timeout_ms);
        let now = Instant::now();
        let headers_deadline = deadline(now, headers_timeout);
        let request_deadline = deadline(now, request_timeout);
        if headers_deadline.is_none() && request_deadline.is_none() {
            return Vec::new();
        }

        let mut expired = Vec::new();
        let mut index = 0;
        while index < self.active.len() {
            let entry = self.active[index].clone();
            let did_expire = {
                let state = entry.borrow();
                is_expired(&state, headers_deadline, request_deadline)
            };
            if did_expire {
                entry.borrow_mut().in_active = false;
                expired.push(entry);
                self.active.remove(index);
            } else {
                index += 1;
            }
        }
        expired
    }
}

/// Node's timeout normalisation: zero disables a deadline, and a header timeout
/// larger than the request timeout is swapped so the tighter one is tested first.
fn normalize_timeouts(headers_ms: u32, request_ms: u32) -> (Duration, Duration) {
    let headers = Duration::from_millis(u64::from(headers_ms));
    let request = Duration::from_millis(u64::from(request_ms));
    if !request.is_zero() && headers > request {
        (request, headers)
    } else {
        (headers, request)
    }
}

/// `now - timeout`, or `None` when the clock has not reached `timeout`.
///
/// Node guards this subtraction because `uv_hrtime()` on a freshly booted device
/// can be smaller than a configured timeout, and an unsigned wrap would then make
/// every connection look expired.
fn deadline(now: Instant, timeout: Duration) -> Option<Instant> {
    if timeout.is_zero() {
        return None;
    }
    now.checked_sub(timeout)
}

/// The expiry test from `ConnectionsList::Expired`.
fn is_expired(
    state: &EntryState,
    headers_deadline: Option<Instant>,
    request_deadline: Option<Instant>,
) -> bool {
    // A parser with no start recorded cannot have expired, which is Node's
    // `last_message_start_ < deadline` never being true for a zero start.
    let Some(started) = state.last_message_start else {
        return false;
    };
    let headers_expired =
        !state.headers_completed && headers_deadline.is_some_and(|deadline| started < deadline);
    let request_expired = request_deadline.is_some_and(|deadline| started < deadline);
    headers_expired || request_expired
}

/// Reads a parser's live state into the shared [`EntryState`].
///
/// Called wherever a message begins, progresses or ends, so the list sees what
/// the C++ would read through its pointer.
pub fn sync(entry: &Entry, parser: &Parser) {
    let mut state = entry.borrow_mut();
    state.last_message_start = parser.last_message_start();
    state.received_data = parser.received_data();
    state.headers_completed = parser.headers_completed();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An instant `millis` in the past, for building an expired entry.
    fn ago(millis: u64) -> Option<Instant> {
        Some(
            Instant::now()
                .checked_sub(Duration::from_millis(millis))
                .expect("the test clock is newer than the offsets used here"),
        )
    }

    fn expired(
        entries: &[(Option<Instant>, bool)],
        headers_ms: u32,
        request_ms: u32,
    ) -> Vec<usize> {
        let (headers, request) = normalize_timeouts(headers_ms, request_ms);
        let now = Instant::now();
        let headers_deadline = deadline(now, headers);
        let request_deadline = deadline(now, request);
        if headers_deadline.is_none() && request_deadline.is_none() {
            return Vec::new();
        }
        let mut found = Vec::new();
        for (index, (started, headers_completed)) in entries.iter().enumerate() {
            let state = EntryState {
                last_message_start: *started,
                headers_completed: *headers_completed,
                received_data: true,
                ..EntryState::default()
            };
            if is_expired(&state, headers_deadline, request_deadline) {
                found.push(index);
            }
        }
        found
    }

    #[test]
    fn no_timeouts_means_nothing_expires() {
        assert!(expired(&[(ago(1_000_000), false)], 0, 0).is_empty());
    }

    #[test]
    fn a_message_past_the_request_deadline_expires() {
        assert_eq!(expired(&[(ago(5_000), false)], 0, 1_000), vec![0]);
    }

    #[test]
    fn a_message_inside_the_request_deadline_does_not_expire() {
        assert!(expired(&[(ago(500), false)], 0, 1_000).is_empty());
    }

    #[test]
    fn the_header_deadline_only_applies_before_headers_complete() {
        assert!(
            expired(&[(ago(5_000), true)], 1_000, 0).is_empty(),
            "the headers arrived, so the header budget no longer applies"
        );
        assert_eq!(expired(&[(ago(5_000), false)], 1_000, 0), vec![0]);
    }

    #[test]
    fn a_parser_that_never_started_a_message_does_not_expire() {
        assert!(expired(&[(None, false)], 1_000, 1_000).is_empty());
    }

    #[test]
    fn the_larger_header_timeout_is_swapped_so_the_tighter_one_decides() {
        // A 10s header budget against a 1s request budget becomes 1s and 10s, so
        // the 1s deadline is what fires.
        assert_eq!(expired(&[(ago(5_000), false)], 10_000, 1_000), vec![0]);
        assert!(
            expired(&[(ago(500), true)], 10_000, 1_000).is_empty(),
            "500ms is inside the swapped 1s deadline"
        );
    }

    #[test]
    fn only_the_entries_that_expired_are_reported() {
        assert_eq!(
            expired(
                &[(ago(5_000), false), (ago(100), false), (ago(9_000), false)],
                1_000,
                0
            ),
            vec![0, 2]
        );
    }

    #[test]
    fn an_idle_parser_is_reported_idle() {
        let mut list = ConnectionsList::new();
        let entry: Entry = Rc::new(RefCell::new(EntryState::default()));
        list.push(&entry);
        assert_eq!(list.idle().len(), 1);
        assert!(list.active().is_empty());
    }

    #[test]
    fn a_parser_whose_message_began_but_never_received_data_is_idle() {
        let mut list = ConnectionsList::new();
        let entry: Entry = Rc::new(RefCell::new(EntryState {
            last_message_start: Some(Instant::now()),
            received_data: false,
            ..EntryState::default()
        }));
        list.push(&entry);
        assert_eq!(list.idle().len(), 1);
        assert_eq!(list.all().len(), 1);
    }

    #[test]
    fn pushing_and_popping_keeps_the_lists_in_order() {
        let mut list = ConnectionsList::new();
        let first: Entry = Rc::new(RefCell::new(EntryState::default()));
        let second: Entry = Rc::new(RefCell::new(EntryState::default()));
        list.push(&first);
        list.push(&second);
        list.push_active(&first);
        list.push_active(&second);
        assert_eq!(list.all().len(), 2);
        assert_eq!(list.active().len(), 2);

        list.pop(&first);
        assert_eq!(list.all().len(), 1);
        assert!(Rc::ptr_eq(&list.all()[0], &second));

        list.pop_active(&first);
        assert_eq!(list.active().len(), 1);
        assert!(Rc::ptr_eq(&list.active()[0], &second));
    }

    #[test]
    fn pushing_twice_does_not_duplicate() {
        let mut list = ConnectionsList::new();
        let entry: Entry = Rc::new(RefCell::new(EntryState::default()));
        list.push(&entry);
        list.push(&entry);
        list.push_active(&entry);
        list.push_active(&entry);
        assert_eq!(list.all().len(), 1);
        assert_eq!(list.active().len(), 1);
    }

    #[test]
    fn popping_an_unlisted_entry_is_a_no_op() {
        let mut list = ConnectionsList::new();
        let entry: Entry = Rc::new(RefCell::new(EntryState::default()));
        list.pop(&entry);
        list.pop_active(&entry);
        assert!(list.all().is_empty());
        assert!(list.active().is_empty());
    }

    #[test]
    fn expired_removes_the_entry_from_the_active_list() {
        let mut list = ConnectionsList::new();
        let stale: Entry = Rc::new(RefCell::new(EntryState {
            last_message_start: ago(5_000),
            received_data: true,
            in_active: true,
            in_all: true,
            ..EntryState::default()
        }));
        list.all.push(Rc::clone(&stale));
        list.active.push(Rc::clone(&stale));
        let reported = list.expired(0, 1_000);
        assert_eq!(reported.len(), 1);
        assert!(list.active().is_empty(), "expiry unlinks the parser");
        assert_eq!(list.all().len(), 1, "but it stays in the all list");
    }
}

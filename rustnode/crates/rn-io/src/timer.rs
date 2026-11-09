use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

/// One scheduled wakeup.
///
/// The `id` is opaque to this type: it is handed back by [`TimerHeap::pop_due`]
/// so the caller can tell which deadline came due. Ordering is by due time and
/// then by insertion, which is how Node orders two timers with the same
/// deadline: `compareTimersLists()` in `lib/internal/timers.js` breaks an expiry
/// tie with the list's creation id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    due_ms: u64,
    seq: u64,
    id: u64,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.due_ms
            .cmp(&other.due_ms)
            .then_with(|| self.seq.cmp(&other.seq))
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Wakeups ordered the way Node orders them: by due time, then insertion order.
#[derive(Debug)]
pub struct TimerHeap {
    heap: BinaryHeap<Reverse<Entry>>,
    seq: u64,
}

impl Default for TimerHeap {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerHeap {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            seq: 0,
        }
    }

    /// Schedules a wakeup and returns the sequence number of that insertion.
    ///
    /// The sequence number is the insertion-order tie-break, not the caller's
    /// id; the caller's id is what [`pop_due`](Self::pop_due) hands back.
    pub fn insert(&mut self, due_ms: u64, id: u64) -> u64 {
        let seq = self.seq;
        self.seq += 1;
        self.heap.push(Reverse(Entry { due_ms, seq, id }));
        seq
    }

    /// Removes and returns the `id` of the earliest wakeup if it is due.
    ///
    /// `None` means the earliest wakeup is still in the future, so the caller
    /// has nothing to run yet. The id is the one passed to
    /// [`insert`](Self::insert), which is what lets a caller discard a deadline
    /// that has since been superseded.
    pub fn pop_due(&mut self, now_ms: u64) -> Option<u64> {
        match self.heap.peek() {
            Some(Reverse(entry)) if entry.due_ms <= now_ms => {
                self.heap.pop().map(|Reverse(entry)| entry.id)
            }
            _ => None,
        }
    }

    /// The earliest deadline, whether or not it has passed.
    pub fn peek_due(&self) -> Option<u64> {
        self.heap.peek().map(|Reverse(entry)| entry.due_ms)
    }

    /// The earliest deadline and the id that scheduled it.
    pub fn peek(&self) -> Option<(u64, u64)> {
        self.heap
            .peek()
            .map(|Reverse(entry)| (entry.due_ms, entry.id))
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn clear(&mut self) {
        self.heap.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pop_due_returns_the_id_it_was_given() {
        // The id is the caller's, not this heap's insertion sequence: the loop
        // uses it to recognise which scheduling request a deadline belongs to.
        let mut heap = TimerHeap::new();
        let _ = heap.insert(10, 4242);
        assert_eq!(heap.pop_due(9), None);
        assert_eq!(heap.pop_due(10), Some(4242));
        assert!(heap.is_empty());
    }

    #[test]
    fn equal_deadlines_pop_in_insertion_order() {
        let mut heap = TimerHeap::new();
        let _ = heap.insert(5, 1);
        let _ = heap.insert(5, 2);
        let _ = heap.insert(5, 3);
        assert_eq!(heap.pop_due(5), Some(1));
        assert_eq!(heap.pop_due(5), Some(2));
        assert_eq!(heap.pop_due(5), Some(3));
    }

    #[test]
    fn a_later_deadline_waits_even_when_inserted_first() {
        let mut heap = TimerHeap::new();
        let _ = heap.insert(20, 1);
        let _ = heap.insert(5, 2);
        assert_eq!(heap.peek_due(), Some(5));
        assert_eq!(heap.pop_due(5), Some(2));
        assert_eq!(heap.pop_due(5), None);
        assert_eq!(heap.pop_due(20), Some(1));
    }

    #[test]
    fn peek_reports_the_earliest_deadline_with_its_id() {
        let mut heap = TimerHeap::new();
        let _ = heap.insert(30, 7);
        let _ = heap.insert(10, 8);
        assert_eq!(heap.peek(), Some((10, 8)));
        assert_eq!(heap.len(), 2);
        heap.clear();
        assert_eq!(heap.peek(), None);
        assert!(heap.is_empty());
    }
}

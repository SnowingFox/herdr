use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Timers ordered the way Node orders them: by due time, then insertion order.
pub struct TimerHeap {
    heap: BinaryHeap<Reverse<(u64, u64)>>,
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

    pub fn insert(&mut self, due_ms: u64, id: u64) -> u64 {
        let seq = self.seq;
        self.seq += 1;
        let _ = id;
        self.heap.push(Reverse((due_ms, seq)));
        seq
    }

    pub fn pop_due(&mut self, now_ms: u64) -> Option<u64> {
        match self.heap.peek() {
            Some(Reverse((due, _))) if *due <= now_ms => {
                self.heap.pop().map(|Reverse((_, seq))| seq)
            }
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

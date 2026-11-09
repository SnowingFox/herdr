use std::collections::VecDeque;

/// Per-isolate task queue drained at the end of each event loop turn.
#[derive(Default)]
pub struct TaskQueue<T> {
    items: VecDeque<T>,
}

impl<T> TaskQueue<T> {
    pub fn push(&mut self, item: T) {
        self.items.push_back(item);
    }
    pub fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.items.drain(..)
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

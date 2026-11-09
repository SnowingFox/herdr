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

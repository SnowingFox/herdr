/// Lifecycle state for a native handle wrapper (socket, file, timer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleState {
    Init,
    Active,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy)]
pub struct Handle {
    pub state: HandleState,
}

impl Default for Handle {
    fn default() -> Self {
        Self {
            state: HandleState::Init,
        }
    }
}

impl Handle {
    pub fn close(&mut self) {
        self.state = HandleState::Closed;
    }
}

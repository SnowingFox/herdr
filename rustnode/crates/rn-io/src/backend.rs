/// Which poller a loop is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// FFI into the vendored libuv, matching Node ordering exactly.
    Libuv,
    /// Native Linux io_uring poller.
    IoUring,
}

pub struct LoopHandle {
    backend: Backend,
}

impl LoopHandle {
    pub fn new(backend: Backend) -> Self {
        Self { backend }
    }
    pub fn backend(&self) -> Backend {
        self.backend
    }
}

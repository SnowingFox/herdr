//! CommonJS wrapper compilation and cache, matching Node's `Module._compile`.
pub fn wrapper_parameters() -> [&'static str; 5] {
    ["exports", "require", "module", "__filename", "__dirname"]
}

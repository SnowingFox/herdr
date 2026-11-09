use rn_core::{BindingRegistry, Namespace};

/// Registers every namespace this build implements.
pub fn install_all(registry: &mut BindingRegistry) {
    registry.register(Namespace::new("config", &["isDebugBuild", "hasOpenSSL"]));
    registry.register(Namespace::empty("util"));
    registry.register(Namespace::empty("errors"));
    registry.register(Namespace::empty("constants"));
    registry.register(Namespace::empty("fs"));
    registry.register(Namespace::empty("buffer"));
    registry.register(Namespace::empty("process_methods"));
    registry.register(Namespace::empty("timers"));
}

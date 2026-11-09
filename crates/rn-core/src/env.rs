use std::collections::HashMap;

use crate::binding::Namespace;

/// Per-isolate runtime state shared by all bindings.
#[derive(Default)]
pub struct Env {
    namespaces: HashMap<String, Namespace>,
}

impl Env {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, namespace: Namespace) {
        self.namespaces.insert(namespace.name.clone(), namespace);
    }
    pub fn get(&self, name: &str) -> Option<&Namespace> {
        self.namespaces.get(name)
    }
    pub fn len(&self) -> usize {
        self.namespaces.len()
    }
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }
}

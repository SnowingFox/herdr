use std::collections::BTreeSet;

/// One `internalBinding(name)` namespace exposed to the JavaScript layer.
#[derive(Debug, Clone)]
pub struct Namespace {
    pub name: String,
    pub members: BTreeSet<String>,
}

impl Namespace {
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            members: BTreeSet::new(),
        }
    }

    pub fn new(name: impl Into<String>, members: &[&str]) -> Self {
        Self {
            name: name.into(),
            members: members.iter().map(|m| (*m).to_string()).collect(),
        }
    }
}

/// Registry handed to the isolate bootstrap.
#[derive(Default)]
pub struct BindingRegistry {
    namespaces: Vec<Namespace>,
}

impl BindingRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, namespace: Namespace) {
        self.namespaces.push(namespace);
    }
    pub fn namespaces(&self) -> &[Namespace] {
        &self.namespaces
    }
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.namespaces.iter().map(|n| n.name.as_str())
    }
}

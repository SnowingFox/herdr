use std::collections::{BTreeMap, BTreeSet};

/// One `internalBinding(name)` namespace exposed to the JavaScript layer.
#[derive(Debug, Clone)]
pub struct Namespace {
    pub name: String,
    /// Members this crate actually installs.
    pub members: BTreeSet<String>,
    /// Members the namespace is known to require but this crate does not
    /// install yet, each with the reason it is deferred.
    ///
    /// This exists because a namespace lands in pieces: `fs` shipped 44 of its
    /// 60 members before the async half existed. Declaring a deferral keeps a
    /// partial landing honest, while a member that is neither installed nor
    /// declared still fails the contract check.
    pub deferred: BTreeMap<String, String>,
}

impl Namespace {
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            members: BTreeSet::new(),
            deferred: BTreeMap::new(),
        }
    }

    pub fn new(name: impl Into<String>, members: &[&str]) -> Self {
        Self {
            name: name.into(),
            members: members.iter().map(|member| (*member).to_string()).collect(),
            deferred: BTreeMap::new(),
        }
    }

    /// Declares members this crate does not install yet.
    pub fn with_deferred(mut self, deferred: &[(&str, &str)]) -> Self {
        for (member, reason) in deferred {
            self.deferred
                .insert((*member).to_string(), (*reason).to_string());
        }
        self
    }

    /// Builds a namespace from a binding module's own declarations, so a crate
    /// cannot register a member list that disagrees with what it installs.
    pub fn from_module<M: crate::BindingModule>(module: &M) -> Self {
        Self {
            name: module.namespace().to_string(),
            members: module
                .members()
                .iter()
                .map(|member| (*member).to_string())
                .collect(),
            deferred: module
                .deferred()
                .iter()
                .map(|(member, reason)| ((*member).to_string(), (*reason).to_string()))
                .collect(),
        }
    }

    /// Members neither installed nor declared as deferred.
    pub fn undeclared<'a, I>(&self, required: I) -> Vec<&'a str>
    where
        I: IntoIterator<Item = &'a str>,
    {
        required
            .into_iter()
            .filter(|member| {
                !self.members.contains(*member) && !self.deferred.contains_key(*member)
            })
            .collect()
    }
}

impl From<&str> for Namespace {
    fn from(name: &str) -> Self {
        Self::empty(name)
    }
}

impl From<String> for Namespace {
    fn from(name: String) -> Self {
        Self::empty(name)
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
        self.namespaces
            .iter()
            .map(|namespace| namespace.name.as_str())
    }

    pub fn get(&self, name: &str) -> Option<&Namespace> {
        self.namespaces
            .iter()
            .find(|namespace| namespace.name == name)
    }
}

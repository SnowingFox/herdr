use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use rn_v8_sys::v8;

use crate::{AsyncIds, BindingModule, InstallCtx};

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

/// A binding module erased behind one object-safe interface.
///
/// `install` takes its lifetimes late-bound, so a `Box<dyn Installer>` can hold
/// any crate's module without the registry knowing its concrete type. That is
/// what lets `register_module` be the only thing a new binding crate writes.
pub trait Installer {
    /// Builds the object `internalBinding(namespace)` returns.
    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String>;
}

impl<M: BindingModule> Installer for M {
    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        BindingModule::install(self, scope, ctx)
    }
}

/// Registry handed to the isolate bootstrap.
#[derive(Default)]
pub struct BindingRegistry {
    namespaces: Vec<Namespace>,
    /// Installers keyed by namespace name, so `internalBinding(name)` resolves
    /// through this one table instead of a hand-written match in the CLI. A
    /// namespace can be registered without one: that is how a contract-only
    /// placeholder stays visible to `rn-compat` without pretending to work.
    installers: BTreeMap<String, Box<dyn Installer>>,
    /// Namespaces installed by this runtime, so a second `internalBinding` call
    /// for the same name returns the same object.
    installed: RefCell<BTreeMap<String, v8::Global<v8::Object>>>,
}

impl BindingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, namespace: Namespace) {
        self.namespaces.push(namespace);
    }

    /// Registers a namespace together with the module that builds it.
    ///
    /// This is the whole wiring a binding crate needs: declare the trait impl,
    /// call this from its `register`, and `internalBinding` finds it.
    pub fn register_module<M: BindingModule + 'static>(&mut self, module: M) {
        self.register(Namespace::from_module(&module));
        self.installers
            .insert(module.namespace().to_string(), Box::new(module));
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

    /// Whether `internalBinding(name)` can build an object.
    pub fn can_install(&self, name: &str) -> bool {
        self.installers.contains_key(name)
    }

    /// Builds one namespace, reusing the object from an earlier call.
    ///
    /// Node caches bindings per isolate, and so must rustnode: `lib/**` relies
    /// on `internalBinding('util')` returning the identical object twice, and
    /// several namespaces hold state (zlib streams, the fs request table) that
    /// would silently split if the second call rebuilt it.
    pub fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        name: &str,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        if let Some(existing) = self.installed.borrow().get(name) {
            return Ok(v8::Local::new(scope, existing));
        }

        let installer = self.installers.get(name).ok_or_else(|| {
            format!("internalBinding('{name}'): the namespace has no Rust implementation yet")
        })?;
        let mut async_ids = AsyncIds::new();
        let mut ctx = InstallCtx {
            async_ids: &mut async_ids,
        };
        let object = installer.install(scope, &mut ctx)?;
        self.installed
            .borrow_mut()
            .insert(name.to_string(), v8::Global::new(scope, object));
        Ok(object)
    }
}

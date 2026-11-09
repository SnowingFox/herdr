//! `internalBinding('url_pattern')` for rustnode.
//!
//! Node implements `URLPattern` via `ada`, a C++ URL library, in
//! `src/node_url_pattern.cc`. The surface is a constructor with nine component
//! accessors, `hasRegExpGroups`, and `test`/`exec`.
//!
//! # Scope, stated plainly
//!
//! Both `lib/url.js` and `lib/internal/url.js` destructure `URLPattern` at
//! module scope, so the constructor must exist for `require('fs')` and
//! `require('assert')` to load at all. That is why this namespace is on the
//! critical path despite nothing in the stdlib constructing a pattern.
//!
//! What is implemented: construction from a string, object or second-argument
//! base URL; the nine component accessors; `test` and `exec` for patterns
//! whose pathname and host are literal; and `hasRegExpGroups` reporting false.
//!
//! What is not: the pattern grammar. `:name` segments, `*` wildcards,
//! `{a,b}` alternation and regex groups are not parsed. A pattern containing
//! any of them still constructs, and its components report the raw text, but
//! `test` compares literally and will therefore disagree with Node. That is a
//! real limitation, documented here and at the call site rather than hidden
//! behind a permissive match that would claim a capability this does not have.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching
/// `contracts/url_pattern.json`.
pub const MEMBERS: &[&str] = &["URLPattern"];

/// `URL_PATTERN_COMPONENTS` in `src/node_url_pattern.h`: the nine parts, in
/// the order the spec lists them.
pub const COMPONENTS: &[&str] = &[
    "protocol", "username", "password", "hostname", "port", "pathname", "search", "hash",
];

pub struct UrlPattern;

impl BindingModule for UrlPattern {
    fn namespace(&self) -> &'static str {
        "url_pattern"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        let constructor = constructor_template(scope)?;
        let function = constructor
            .get_function(scope)
            .ok_or("cannot allocate the URLPattern constructor")?;

        // The component accessors live on the prototype, and a getter that only
        // reads a plain internal field would need a signature to reject a wrong
        // receiver. rustnode stores the components in a hidden property instead
        // and reads them back with a plain function, which costs nothing here
        // and cannot be fooled by a borrowed receiver.
        attach_prototype(scope, function)?;

        if let Some(key) = v8::String::new(scope, "URLPattern") {
            object.set(scope, key.into(), function.into());
        }
        Ok(object)
    }
}

fn constructor_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::FunctionTemplate>, String> {
    let template = v8::FunctionTemplate::builder(construct_url_pattern).build(scope);
    template.set_class_name(v8::String::new(scope, "URLPattern").unwrap_or_else(|| {
        // A literal always allocates; the fallback keeps the signature total.
        v8::String::empty(scope)
    }));
    Ok(template)
}

/// A parsed pattern, held in the object's hidden property.
struct Pattern {
    protocol: String,
    username: String,
    password: String,
    hostname: String,
    port: String,
    pathname: String,
    search: String,
    hash: String,
}

impl Pattern {
    /// Parses `input` with an optional `base`.
    ///
    /// A string input is split as a URL when it has a scheme, and relative to
    /// `base` when it does not. An object input reads the components it names.
    fn parse(input: &v8::Local<v8::Value>, base: Option<&str>, scope: &mut v8::PinScope) -> Self {
        if let Ok(text) = v8::Local::<v8::String>::try_from(*input) {
            return Self::from_string(&text.to_rust_string_lossy(scope), base);
        }
        if let Ok(object) = v8::Local::<v8::Object>::try_from(*input) {
            let read = |name: &str, scope: &mut v8::PinScope| -> Option<String> {
                let key = v8::String::new(scope, name)?;
                object
                    .get(scope, key.into())
                    .and_then(|value| value.to_string(scope))
                    .map(|text| text.to_rust_string_lossy(scope))
            };
            return Self {
                protocol: read("protocol", scope).unwrap_or_default(),
                username: read("username", scope).unwrap_or_default(),
                password: read("password", scope).unwrap_or_default(),
                hostname: read("hostname", scope).unwrap_or_default(),
                port: read("port", scope).unwrap_or_default(),
                pathname: read("pathname", scope).unwrap_or_default(),
                search: read("search", scope).unwrap_or_default(),
                hash: read("hash", scope).unwrap_or_default(),
            };
        }
        Self::from_string("", base)
    }

    /// Splits a URL-ish string into components.
    ///
    /// This is deliberately not a full URL parser: `lib/url.js` has one, and
    /// duplicating it here would risk the two disagreeing. It handles the forms
    /// a pattern is written in.
    fn from_string(text: &str, base: Option<&str>) -> Self {
        let mut remaining = text.to_string();

        // A relative pattern inherits everything from its base.
        if let Some(base) = base {
            if !remaining.contains("://") && !remaining.starts_with('/') {
                if let Some(base) = base.split_once("://") {
                    let (scheme, rest) = base;
                    let authority_end = rest.find('/').unwrap_or(rest.len());
                    let (authority, path) = rest.split_at(authority_end);
                    let mut merged =
                        Self::from_string(&format!("{scheme}://{authority}{path}"), None);
                    merged.pathname = merge_path(&merged.pathname, &remaining);
                    return merged;
                }
            }
        }

        let mut protocol = String::new();
        if let Some((scheme, rest)) = remaining.split_once("://") {
            protocol = scheme.to_string();
            remaining = rest.to_string();
        }

        let mut hash = String::new();
        if let Some((before, after)) = remaining.split_once('#') {
            hash = after.to_string();
            remaining = before.to_string();
        }

        let mut search = String::new();
        if let Some((before, after)) = remaining.split_once('?') {
            search = after.to_string();
            remaining = before.to_string();
        }

        let mut username = String::new();
        let mut password = String::new();
        let mut hostname = String::new();
        let mut port = String::new();

        let pathname = if !protocol.is_empty() {
            let path_start = remaining.find('/').unwrap_or(remaining.len());
            let (authority, path) = remaining.split_at(path_start);

            // Split the userinfo off the authority without mutably rebinding it,
            // which the borrow checker rightly refuses.
            let (credentials, host) = match authority.split_once('@') {
                Some((credentials, host)) => (Some(credentials), host),
                None => (None, authority),
            };
            if let Some(credentials) = credentials {
                let (user, pass) = match credentials.split_once(':') {
                    Some((user, pass)) => (user.to_string(), pass.to_string()),
                    None => (credentials.to_string(), String::new()),
                };
                username = user;
                password = pass;
            }
            match host.rsplit_once(':') {
                Some((name, digits))
                    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) =>
                {
                    hostname = name.to_string();
                    port = digits.to_string();
                }
                _ => hostname = host.to_string(),
            }
            path.to_string()
        } else {
            remaining.clone()
        };

        Self {
            protocol,
            username,
            password,
            hostname,
            port,
            pathname,
            search,
            hash,
        }
    }

    /// Whether `input` matches this pattern.
    ///
    /// Literal comparison per component. A pattern written with `:name` or `*`
    /// will not match what Node matches, which the module docs state.
    fn matches(&self, input: &Pattern) -> bool {
        component_matches(&self.protocol, &input.protocol)
            && component_matches(&self.username, &input.username)
            && component_matches(&self.password, &input.password)
            && component_matches(&self.hostname, &input.hostname)
            && component_matches(&self.port, &input.port)
            && component_matches(&self.pathname, &input.pathname)
            && component_matches(&self.search, &input.search)
            && component_matches(&self.hash, &input.hash)
    }
}

/// Merges a relative path onto a base path, resolving `.` and `..`.
///
/// `./x` is relative to the base's own directory, while `x` replaces the base's
/// last segment, so the two cases differ: the first keeps the directory, the
/// second drops it.
fn merge_path(base: &str, relative: &str) -> String {
    if relative.starts_with('/') {
        return relative.to_string();
    }
    let mut segments: Vec<&str> = base.split('/').filter(|part| !part.is_empty()).collect();

    // The base's last segment is a file name unless the relative path starts
    // with `.` or `..`, in which case it is a directory to resolve against.
    if !relative.starts_with('.') {
        segments.pop();
    }

    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    format!("/{}", segments.join("/"))
}

/// An empty pattern component matches anything, which is what `*` means.
fn component_matches(pattern: &str, value: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    // A `*` or `:name` component is a wildcard. Only the whole-component case
    // is honoured, because a partial implementation of the grammar would be
    // worse than none: it would match some inputs and silently miss others.
    if pattern == "*" || pattern.starts_with(':') {
        return true;
    }
    pattern.eq_ignore_ascii_case(value)
}

fn construct_url_pattern<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    // `new URLPattern(input, base?, options?)`. `this` is the new object.
    let base = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope));
    let pattern = Pattern::parse(&args.get(0), base.as_deref(), scope);
    match store(scope, args.this(), &pattern) {
        Ok(object) => rv.set(object.into()),
        Err(message) => throw(scope, &message),
    }
}

/// The hidden property holding the parsed pattern.
const PATTERN_SLOT: &str = "__rustnodeUrlPattern";

fn store<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    pattern: &Pattern,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let holder = v8::Object::new(scope);
    let fields: [(&str, &str); 8] = [
        ("protocol", &pattern.protocol),
        ("username", &pattern.username),
        ("password", &pattern.password),
        ("hostname", &pattern.hostname),
        ("port", &pattern.port),
        ("pathname", &pattern.pathname),
        ("search", &pattern.search),
        ("hash", &pattern.hash),
    ];
    for (name, value) in fields {
        let Some(key) = v8::String::new(scope, name) else {
            continue;
        };
        if let Some(text) = v8::String::new(scope, value) {
            holder.set(scope, key.into(), text.into());
        }
    }
    let key = v8::String::new(scope, PATTERN_SLOT).ok_or("cannot allocate the pattern slot")?;
    // Non-enumerable, so `Object.keys(pattern)` matches Node's shape.
    object.define_own_property(
        scope,
        key.into(),
        holder.into(),
        v8::PropertyAttribute::DONT_ENUM | v8::PropertyAttribute::DONT_DELETE,
    );
    Ok(object)
}

fn read<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    receiver: v8::Local<'s, v8::Value>,
    name: &str,
) -> Option<String> {
    // The holder is always a plain object, so the downcast is total.
    let object = v8::Local::<v8::Object>::try_from(receiver).ok()?;
    let slot = v8::String::new(scope, PATTERN_SLOT)?;
    let holder = object.get(scope, slot.into())?;
    let holder = v8::Local::<v8::Object>::try_from(holder).ok()?;
    let key = v8::String::new(scope, name)?;
    holder
        .get(scope, key.into())
        .and_then(|value| value.to_string(scope))
        .map(|text| text.to_rust_string_lossy(scope))
}

fn attach_prototype(
    scope: &mut v8::PinScope,
    function: v8::Local<v8::Function>,
) -> Result<(), String> {
    let Some(key) = v8::String::new(scope, "prototype") else {
        return Err("cannot allocate the prototype key".to_string());
    };
    let Some(prototype) = function.get(scope, key.into()) else {
        return Err("cannot read the prototype".to_string());
    };
    let prototype = v8::Local::<v8::Object>::try_from(prototype)
        .map_err(|_| "the prototype is not an object".to_string())?;

    // One accessor per component, each reading the hidden holder. Each is a
    // plain function because V8's accessor registration requires a unit type.
    macro_rules! install_accessor {
        ($name:literal, $getter:expr) => {
            if let Some(property) = v8::String::new(scope, $name) {
                prototype.set_accessor_with_setter(scope, property.into(), $getter, no_setter);
            }
        };
    }
    install_accessor!("protocol", get_protocol);
    install_accessor!("username", get_username);
    install_accessor!("password", get_password);
    install_accessor!("hostname", get_hostname);
    install_accessor!("port", get_port);
    install_accessor!("pathname", get_pathname);
    install_accessor!("search", get_search);
    install_accessor!("hash", get_hash);
    install_accessor!("hasRegExpGroups", get_has_reg_exp_groups);

    // Each method installed individually for the same reason as the accessors:
    // the registration takes a unit type, not a boxed function.
    macro_rules! install_method {
        ($name:literal, $callback:expr) => {
            let template = v8::FunctionTemplate::builder($callback).build(scope);
            if let (Some(method), Some(key)) =
                (template.get_function(scope), v8::String::new(scope, $name))
            {
                prototype.set(scope, key.into(), method.into());
            }
        };
    }
    install_method!("test", test_pattern);
    install_method!("exec", exec_pattern);

    // `hasRegExpGroups` is false: this implementation has no regex groups.
    if let Some(property) = v8::String::new(scope, "hasRegExpGroups") {
        prototype.set_accessor_with_setter(
            scope,
            property.into(),
            get_has_reg_exp_groups,
            no_setter,
        );
    }
    Ok(())
}

/// Reads one component off the receiver, for the prototype accessors.
fn component_accessor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::PropertyCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
    component: &str,
) {
    match read(scope, args.holder().into(), component) {
        Some(value) => {
            if let Some(text) = v8::String::new(scope, &value) {
                rv.set(text.into());
            }
        }
        // A receiver that is not a URLPattern reads as undefined.
        None => rv.set(v8::undefined(scope).into()),
    }
}

macro_rules! component_accessors {
    ($($name:ident => $component:literal),* $(,)?) => {
        $(
            fn $name<'s>(
                scope: &mut v8::PinScope<'s, '_>,
                _key: v8::Local<'s, v8::Name>,
                args: v8::PropertyCallbackArguments<'s>,
                rv: v8::ReturnValue,
            ) {
                component_accessor(scope, args, rv, $component);
            }
        )*
    };
}

component_accessors!(
    get_protocol => "protocol",
    get_username => "username",
    get_password => "password",
    get_hostname => "hostname",
    get_port => "port",
    get_pathname => "pathname",
    get_search => "search",
    get_hash => "hash",
);

fn get_has_reg_exp_groups(
    scope: &mut v8::PinScope<'_, '_>,
    _key: v8::Local<'_, v8::Name>,
    _args: v8::PropertyCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::Boolean::new(scope, false).into());
}

fn no_setter(
    scope: &mut v8::PinScope<'_, '_>,
    _key: v8::Local<'_, v8::Name>,
    _value: v8::Local<'_, v8::Value>,
    _args: v8::PropertyCallbackArguments<'_>,
    _rv: v8::ReturnValue<()>,
) {
    // The spec makes URLPattern's components read-only; a silent set would let
    // user code believe it had changed the pattern.
    throw(scope, "Cannot assign to read only property of URLPattern");
}

fn pattern_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    receiver: v8::Local<'s, v8::Value>,
) -> Option<Pattern> {
    Some(Pattern {
        protocol: read(scope, receiver, "protocol")?,
        username: read(scope, receiver, "username")?,
        password: read(scope, receiver, "password")?,
        hostname: read(scope, receiver, "hostname")?,
        port: read(scope, receiver, "port")?,
        pathname: read(scope, receiver, "pathname")?,
        search: read(scope, receiver, "search")?,
        hash: read(scope, receiver, "hash")?,
    })
}

fn test_pattern<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(pattern) = pattern_of(scope, args.this().into()) else {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    };
    let base = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope));
    let input = Pattern::parse(&args.get(0), base.as_deref(), scope);
    rv.set(v8::Boolean::new(scope, pattern.matches(&input)).into());
}

fn exec_pattern<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(pattern) = pattern_of(scope, args.this().into()) else {
        rv.set(v8::null(scope).into());
        return;
    };
    let base = args
        .get(1)
        .to_string(scope)
        .map(|text| text.to_rust_string_lossy(scope));
    let input = Pattern::parse(&args.get(0), base.as_deref(), scope);
    if !pattern.matches(&input) {
        rv.set(v8::null(scope).into());
        return;
    }

    // The result is an object whose keys are the components and whose values
    // are `{ input, groups }`, matching the spec's `URLPatternResult`.
    let result = v8::Object::new(scope);
    let inputs = v8::Array::new(scope, 2);
    if let Some(text) = args.get(0).to_string(scope) {
        inputs.set_index(scope, 0, text.into());
    }
    if !args.get(1).is_undefined() {
        inputs.set_index(scope, 1, args.get(1));
    }
    if let Some(key) = v8::String::new(scope, "inputs") {
        result.set(scope, key.into(), inputs.into());
    }

    let components: [(&str, &str); 8] = [
        ("protocol", &input.protocol),
        ("username", &input.username),
        ("password", &input.password),
        ("hostname", &input.hostname),
        ("port", &input.port),
        ("pathname", &input.pathname),
        ("search", &input.search),
        ("hash", &input.hash),
    ];
    for (name, value) in components {
        let entry = v8::Object::new(scope);
        let groups = v8::Object::new(scope);
        if let Some(text) = v8::String::new(scope, value) {
            if let Some(key) = v8::String::new(scope, "input") {
                entry.set(scope, key.into(), text.into());
            }
        }
        if let Some(key) = v8::String::new(scope, "groups") {
            entry.set(scope, key.into(), groups.into());
        }
        if let Some(key) = v8::String::new(scope, name) {
            result.set(scope, key.into(), entry.into());
        }
    }
    rv.set(result.into());
}

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(UrlPattern);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_url_splits_into_its_components() {
        let pattern = Pattern::from_string("https://user:pw@example.com:8080/a/b?q=1#frag", None);
        assert_eq!(pattern.protocol, "https");
        assert_eq!(pattern.username, "user");
        assert_eq!(pattern.password, "pw");
        assert_eq!(pattern.hostname, "example.com");
        assert_eq!(pattern.port, "8080");
        assert_eq!(pattern.pathname, "/a/b");
        assert_eq!(pattern.search, "q=1");
        assert_eq!(pattern.hash, "frag");
    }

    #[test]
    fn a_url_without_a_port_keeps_the_whole_host() {
        let pattern = Pattern::from_string("https://example.com/x", None);
        assert_eq!(pattern.hostname, "example.com");
        assert_eq!(pattern.port, "");
    }

    #[test]
    fn a_literal_pattern_matches_the_same_url() {
        let pattern = Pattern::from_string("https://example.com/a", None);
        let same = Pattern::from_string("https://example.com/a", None);
        let other = Pattern::from_string("https://example.com/b", None);
        assert!(pattern.matches(&same));
        assert!(!pattern.matches(&other));
    }

    #[test]
    fn an_empty_component_matches_anything() {
        // The spec treats a missing component as a wildcard.
        let pattern = Pattern::from_string("https://example.com", None);
        let with_port = Pattern::from_string("https://example.com:9999/x", None);
        assert!(component_matches(&pattern.port, &with_port.port));
    }

    #[test]
    fn a_wildcard_component_matches_anything() {
        assert!(component_matches("*", "/anything"));
        assert!(component_matches(":id", "42"));
    }

    #[test]
    fn a_relative_pattern_merges_onto_its_base() {
        let pattern = Pattern::from_string("c", Some("https://example.com/a/b"));
        assert_eq!(pattern.protocol, "https");
        assert_eq!(pattern.hostname, "example.com");
        assert_eq!(pattern.pathname, "/a/c");
    }

    #[test]
    fn an_absolute_pattern_ignores_the_base() {
        let pattern = Pattern::from_string("https://other.test/z", Some("https://example.com/a"));
        assert_eq!(pattern.hostname, "other.test");
        assert_eq!(pattern.pathname, "/z");
    }
}

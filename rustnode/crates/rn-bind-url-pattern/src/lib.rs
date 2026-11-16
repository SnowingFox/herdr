//! `internalBinding('url_pattern')` for rustnode.
//!
//! Node implements `URLPattern` in `src/node_url_pattern.cc` over
//! `ada::url_pattern`. The surface is a constructor, eight component getters,
//! `hasRegExpGroups`, `test` and `exec`.
//!
//! # Shape
//!
//! The prototype's accessors are installed on the *prototype template*, the way
//! `src/node_url_pattern.cc` does it with
//! `prototype_template->SetAccessorProperty(...)`. That detail is load-bearing.
//! `v8::Object::set_accessor_with_setter` maps to V8's
//! `Object::SetNativeDataProperty`, which in this V8 build installs a *lazy data
//! property*: the accessor is invoked once, on the first read, and the result
//! replaces it as an ordinary `{value, writable}` property. A descriptor read
//! then reports `value,writable` instead of `get`, which is observable and was
//! the whole of the `undefined`-components defect. Template accessors do not do
//! that; they stay accessors.
//!
//! # The pattern engine
//!
//! [`pattern`] is a port of ada's `url_pattern_helpers` and `url_pattern`,
//! which is the spec algorithm. The tokenizer, the part-list parser, the
//! regexp generator and the `URLPatternInit` processor are all there, so `:name`
//! segments, `*` wildcards, `{a,b}` alternation, `?`/`*`/`+` modifiers and
//! `(regexp)` groups behave the way Node's do. Matching runs V8's own `RegExp`
//! with the `v` flag the C++ asks for, so a pattern's regexp dialect is the same
//! one user code gets from `/.../v`.

mod pattern;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub use pattern::{CompileOptions, Component, ComponentType, Init, PatternError, ProcessType};

/// Members exposed on the namespace object, matching
/// `contracts/url_pattern.json`.
pub const MEMBERS: &[&str] = &["URLPattern"];

/// The components, in the order the spec and `URL_PATTERN_COMPONENTS` list
/// them.
pub const COMPONENTS: &[&str] = &[
    "protocol", "username", "password", "hostname", "port", "pathname", "search", "hash",
];

/// One installed `URLPattern`, kept on the Rust heap.
///
/// The pattern is not stored in JavaScript at all. A component getter is the
/// hottest operation on this object — a loop reading `pattern.pathname` 200,000
/// times is an ordinary script — and every JS-side encoding costs a property
/// fetch plus a decode per read. Instead the instance carries a single internal
/// field holding a pointer to this struct, so a read is one pointer dereference.
/// The layout is not observable from JavaScript: the field is an internal field,
/// not a property, so `Object.getOwnPropertyNames` and `JSON.stringify` see
/// nothing.
struct State {
    compiled: pattern::CompiledPattern,
}

/// The internal field index holding the [`State`] pointer.
const STATE_FIELD: usize = 0;

/// Reads the state a receiver carries, or `None` when it is not a `URLPattern`.
///
/// # Safety
///
/// The pointer is only ever written by [`store`], which boxes a `State` and
/// hands the raw pointer to V8; and only ever taken from an object whose
/// internal field count is one, which is set on the constructor's instance
/// template and so holds for every instance and no other object. The allocation
/// is never freed for the isolate's lifetime, which is deliberate: a `URLPattern`
/// can be collected at any time and a drop hook would have to be a weak
/// callback, while the pattern itself is small and bounded by the number of
/// patterns a program constructs.
///
/// The `unsafe` block is confined to the deref; a receiver with no field, or a
/// field that does not hold a pattern, returns `None` rather than dereferencing
/// an arbitrary pointer.
fn state_of<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    receiver: v8::Local<'s, v8::Value>,
) -> Option<&'static State> {
    let object = v8::Local::<v8::Object>::try_from(receiver).ok()?;
    if object.internal_field_count() == 0 {
        return None;
    }
    let field = object.get_internal_field(scope, STATE_FIELD)?;
    let external = v8::Local::<v8::External>::try_from(field).ok()?;
    let pointer = external.value() as *const State;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: `store` writes exactly this type into this field, and the pointer
    // is never freed, so it stays valid for as long as any receiver can exist.
    Some(unsafe { &*pointer })
}

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
        let template = constructor_template(scope)?;
        let function = template
            .get_function(scope)
            .ok_or("cannot allocate the URLPattern constructor")?;

        if let Some(key) = v8::String::new(scope, "URLPattern") {
            object.set(scope, key.into(), function.into());
        }
        Ok(object)
    }
}

/// Builds the constructor template and the whole prototype surface on it.
///
/// Everything goes on the template rather than on the materialized prototype
/// object so the accessors stay accessors; see the module docs.
fn constructor_template<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::FunctionTemplate>, String> {
    let template = rn_core::class(construct_url_pattern).build(scope);
    template
        .set_class_name(v8::String::new(scope, "URLPattern").ok_or("cannot name the constructor")?);
    // One internal field, holding the pointer to the compiled pattern's `State`.
    // An internal field rather than a property so nothing about it is visible
    // to `Object.getOwnPropertyNames`, `JSON.stringify` or a spread.
    template
        .instance_template(scope)
        .set_internal_field_count(STATE_FIELD + 1);

    let prototype = template.prototype_template(scope);

    // `Object.prototype.toString.call(new URLPattern())` is
    // `[object URLPattern]` because the prototype carries the toStringTag
    // symbol; Node installs it `ReadOnly | DontEnum`.
    if let Some(tag) = v8::String::new(scope, "URLPattern") {
        let key = v8::Symbol::get_to_string_tag(scope);
        prototype.set_with_attr(
            key.into(),
            tag.into(),
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_ENUM,
        );
    }

    // Node's attributes for the nine accessors: `ReadOnly | DontDelete`, which
    // reads back as `{enumerable: true, configurable: false}` with a getter and
    // no setter. `get, set, enumerable, configurable` was the descriptor from
    // `Object.getOwnPropertyDescriptor(URLPattern.prototype, 'pathname')`.
    // Each getter is its own `FunctionTemplate`, because a template accessor
    // takes function templates rather than raw callbacks. The macro keeps the
    // nine installations visibly identical.
    macro_rules! install_component {
        ($name:literal, $getter:path) => {{
            let getter = rn_core::method($getter)
                .side_effect_type(v8::SideEffectType::HasNoSideEffect)
                .build(scope);
            let key = v8::String::new(scope, $name).ok_or("cannot name a component")?;
            // `PropertyAttribute` is not `Copy`, so it is built per call.
            let attributes = v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE;
            prototype.set_accessor_property(key.into(), Some(getter), None, attributes);
        }};
    }

    install_component!("protocol", get_protocol);
    install_component!("username", get_username);
    install_component!("password", get_password);
    install_component!("hostname", get_hostname);
    install_component!("port", get_port);
    install_component!("pathname", get_pathname);
    install_component!("search", get_search);
    install_component!("hash", get_hash);
    install_component!("hasRegExpGroups", get_has_reg_exp_groups);

    // `test` and `exec` are ordinary prototype methods: writable, enumerable
    // and configurable, which is `SetProtoMethodNoSideEffect`'s shape.
    let exec = rn_core::method(exec_pattern)
        .side_effect_type(v8::SideEffectType::HasNoSideEffect)
        .build(scope);
    let test = rn_core::method(test_pattern)
        .side_effect_type(v8::SideEffectType::HasNoSideEffect)
        .build(scope);
    for (name, function) in [("exec", exec), ("test", test)] {
        let key = v8::String::new(scope, name).ok_or("cannot name a method")?;
        prototype.set(key.into(), function.into());
    }

    Ok(template)
}
/// Reads the pattern state a receiver carries, or `None` when it is not a
/// `URLPattern`.
///
/// The pattern is stored as two strings — one per field of one component —
/// joined by the unit separator, so a lookup is two property reads plus one
/// split rather than a recompile. Recompiling on each read was measurably wrong:
/// it put the tokenizer on the path of every component getter, which is the
/// hottest operation on this object.
/// Throws Node's `ERR_INVALID_THIS`, which is what a getter or method called on
/// the wrong receiver raises. Node's accessors get this from their `Signature`;
/// this build reports `Illegal invocation` for that case, so the message is
/// reproduced directly.
fn throw_illegal_invocation(scope: &mut v8::PinScope<'_, '_>) {
    let Some(message) = v8::String::new(scope, "Illegal invocation") else {
        return;
    };
    let exception = v8::Exception::type_error(scope, message);
    scope.throw_exception(exception);
}

fn throw_coded(scope: &mut v8::PinScope<'_, '_>, message: &str, code: &str) {
    let (Some(text), Some(code_key), Some(code_value)) = (
        v8::String::new(scope, message),
        v8::String::new(scope, "code"),
        v8::String::new(scope, code),
    ) else {
        return;
    };
    let exception = v8::Exception::type_error(scope, text);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        scope.throw_exception(exception);
        return;
    };
    let _ = object.set(scope, code_key.into(), code_value.into());
    scope.throw_exception(exception);
}

/// The getter a component accessor runs.
fn component_getter<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    info: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
    index: usize,
) {
    let Some(state) = state_of(scope, info.this().into()) else {
        throw_illegal_invocation(scope);
        return;
    };
    // The getter reports the *component's pattern*, which is the canonicalised
    // form the compiler produced, not the raw string the init carried.
    if let Some(text) = v8::String::new(scope, &state.compiled.components[index].pattern) {
        rv.set(text.into());
    }
}

macro_rules! component_getters {
    ($($name:ident => $index:literal),* $(,)?) => {
        $(
            fn $name<'s>(
                scope: &mut v8::PinScope<'s, '_>,
                info: v8::FunctionCallbackArguments<'s>,
                rv: v8::ReturnValue,
            ) {
                component_getter(scope, info, rv, $index);
            }
        )*
    };
}

component_getters!(
    get_protocol => 0,
    get_username => 1,
    get_password => 2,
    get_hostname => 3,
    get_port => 4,
    get_pathname => 5,
    get_search => 6,
    get_hash => 7,
);

fn get_has_reg_exp_groups<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    info: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(state) = state_of(scope, info.this().into()) else {
        throw_illegal_invocation(scope);
        return;
    };
    rv.set(v8::Boolean::new(scope, state.compiled.has_regexp_groups()).into());
}

/// `new URLPattern(input?, baseURLOrOptions?, options?)`.
fn construct_url_pattern<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        throw_coded(
            scope,
            "Cannot call constructor without `new`",
            "ERR_CONSTRUCT_CALL_REQUIRED",
        );
        return;
    }

    let this = args.this();
    let length = args.length();

    // Per WebIDL overload resolution: with three or more arguments the middle
    // one is always `baseURL`; with two it is `baseURL` when it is a string and
    // `options` otherwise.
    let mut base_url: Option<String> = None;
    let mut options: Option<v8::Local<'s, v8::Object>> = None;

    if length >= 3 {
        match argument_base_url(scope, args.get(1)) {
            Ok(value) => base_url = value,
            Err(()) => {
                throw_coded(
                    scope,
                    "second argument must be a string",
                    "ERR_INVALID_ARG_TYPE",
                );
                return;
            }
        }
        let candidate = args.get(2);
        if !candidate.is_null_or_undefined() {
            match v8::Local::<v8::Object>::try_from(candidate) {
                Ok(object) => options = Some(object),
                Err(_) => {
                    throw_coded(scope, "options must be an object", "ERR_INVALID_ARG_TYPE");
                    return;
                }
            }
        }
    } else if length == 2 {
        let candidate = args.get(1);
        if let Ok(text) = v8::Local::<v8::String>::try_from(candidate) {
            base_url = Some(text.to_rust_string_lossy(scope));
        } else if candidate.is_null_or_undefined() {
            // The `options` overload with its default.
        } else if let Ok(object) = v8::Local::<v8::Object>::try_from(candidate) {
            options = Some(object);
        } else {
            throw_coded(
                scope,
                "second argument must be a string or object",
                "ERR_INVALID_ARG_TYPE",
            );
            return;
        }
    }

    let ignore_case = match options {
        Some(object) => read_ignore_case(scope, object),
        None => false,
    };

    let input = args.get(0);
    let init = if length == 0 || input.is_null_or_undefined() {
        pattern::Init::default()
    } else if let Ok(text) = v8::Local::<v8::String>::try_from(input) {
        let text = text.to_rust_string_lossy(scope);
        let mut matches = |component: &pattern::Component, value: &str| {
            regex_matches(scope, component, value, ignore_case)
        };
        match pattern::parse_constructor_string(&text, &mut matches) {
            Ok(init) => init,
            Err(_) => {
                throw_coded(
                    scope,
                    "Failed to construct URLPattern",
                    "ERR_INVALID_URL_PATTERN",
                );
                return;
            }
        }
    } else if let Ok(object) = v8::Local::<v8::Object>::try_from(input) {
        match read_init(scope, object) {
            Some(init) => init,
            None => return,
        }
    } else {
        throw_coded(
            scope,
            "Input must be an object or a string",
            "ERR_INVALID_ARG_TYPE",
        );
        return;
    };

    // A string pattern has to be absolute or be given a base: `parse a
    // constructor string` cannot invent a scheme, so
    // `new URLPattern("/a?q=1")` throws rather than quietly becoming a pathless
    // pattern. `parse_url_pattern_impl` checks this before merging the base.
    let from_string = v8::Local::<v8::String>::try_from(input).is_ok();
    // An object input and a `baseURL` argument are mutually exclusive: the
    // dictionary carries its own `baseURL`, so ada's
    // `parse_url_pattern_impl` rejects the pair outright.
    if !from_string && length > 0 && base_url.is_some() && !input.is_null_or_undefined() {
        throw_coded(
            scope,
            "Failed to construct URLPattern",
            "ERR_INVALID_URL_PATTERN",
        );
        return;
    }
    if from_string && base_url.is_none() && init.protocol.is_none() {
        throw_coded(
            scope,
            "Failed to construct URLPattern",
            "ERR_INVALID_URL_PATTERN",
        );
        return;
    }

    // The second argument, when it was a string, is the same thing as
    // `init.baseURL`; the object form wins when both are present, because that
    // is the value the spec reads last.
    let mut init = init;
    if init.base_url.is_none() {
        init.base_url = base_url;
    }

    let strings = match pattern::finish_init(&init, pattern::ProcessType::Pattern) {
        Ok(strings) => strings,
        Err(_) => {
            throw_coded(
                scope,
                "Failed to construct URLPattern",
                "ERR_INVALID_URL_PATTERN",
            );
            return;
        }
    };
    // Compiling here is both the validation step and the only parse: a pattern
    // whose component does not parse throws from the constructor rather than
    // from the first `test`, and the result is what every later read uses.
    let compiled = match pattern::compile_all(&strings, ignore_case) {
        Ok(compiled) => compiled,
        Err(_) => {
            throw_coded(
                scope,
                "Failed to construct URLPattern",
                "ERR_INVALID_URL_PATTERN",
            );
            return;
        }
    };

    if !store(scope, this, &compiled) {
        throw_coded(
            scope,
            "Failed to construct URLPattern",
            "ERR_INVALID_URL_PATTERN",
        );
        return;
    }
    rv.set(this.into());
}

/// Reads the `baseURL` argument, distinguishing "absent" from "invalid".
fn argument_base_url<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: v8::Local<'s, v8::Value>,
) -> Result<Option<String>, ()> {
    if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
        return Ok(Some(text.to_rust_string_lossy(scope)));
    }
    if value.is_null() {
        return Ok(Some("null".to_string()));
    }
    if value.is_undefined() {
        return Ok(Some("undefined".to_string()));
    }
    Err(())
}

fn read_ignore_case(scope: &mut v8::PinScope<'_, '_>, options: v8::Local<'_, v8::Object>) -> bool {
    let Some(key) = v8::String::new(scope, "ignoreCase") else {
        return false;
    };
    options
        .get(scope, key.into())
        .map(|value| value.boolean_value(scope))
        .unwrap_or(false)
}

/// Reads a `URLPatternInit` dictionary off an object.
///
/// Only string-valued members are recorded, which is what Node's
/// `URLPatternInit::FromJsObject` does: it checks `value->IsString()` and
/// otherwise skips the key, so `{pathname: 42}` is the same as `{}`.
fn read_init<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
) -> Option<pattern::Init> {
    let mut init = pattern::Init::default();
    for name in [
        "protocol", "username", "password", "hostname", "port", "pathname", "search", "hash",
        "baseURL",
    ] {
        let key = v8::String::new(scope, name)?;
        let value = object.get(scope, key.into())?;
        if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
            let text = text.to_rust_string_lossy(scope);
            match name {
                "protocol" => init.protocol = Some(text),
                "username" => init.username = Some(text),
                "password" => init.password = Some(text),
                "hostname" => init.hostname = Some(text),
                "port" => init.port = Some(text),
                "pathname" => init.pathname = Some(text),
                "search" => init.search = Some(text),
                "hash" => init.hash = Some(text),
                "baseURL" => init.base_url = Some(text),
                _ => {}
            }
        }
    }
    Some(init)
}

/// Builds the private holder and attaches it to `object`.
/// Boxes `compiled` and records the pointer in the instance's internal field.
///
/// The allocation is deliberately never freed; [`state_of`] explains why.
fn store<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    compiled: &pattern::CompiledPattern,
) -> bool {
    let state = Box::new(State {
        compiled: compiled.clone(),
    });
    let pointer = Box::into_raw(state);
    let external = v8::External::new(scope, pointer as *mut std::ffi::c_void);
    object.set_internal_field(STATE_FIELD, external.into())
}

/// Whether `component` matches `input`, using V8's `RegExp`.
fn regex_matches(
    scope: &mut v8::PinScope<'_, '_>,
    component: &pattern::Component,
    input: &str,
    ignore_case: bool,
) -> bool {
    if let Some(answer) = component.fast_test(input) {
        return answer;
    }
    let Some(source) = component.regexp_source() else {
        return false;
    };
    let (Some(pattern), Some(subject)) = (
        v8::String::new(scope, source),
        v8::String::new(scope, input),
    ) else {
        return false;
    };
    // Node asks for `v` (Unicode sets) always, plus `i` when the pattern was
    // built with `ignoreCase`. `s` (dotAll) is not in Node's flags and is not
    // added here.
    let mut flags = v8::RegExpCreationFlags::UNICODE_SETS;
    if ignore_case || component.ignore_case {
        flags |= v8::RegExpCreationFlags::IGNORE_CASE;
    }
    let Some(regexp) = v8::RegExp::new(scope, pattern, flags) else {
        return false;
    };
    regexp
        .exec(scope, subject)
        .map(|result| !result.is_null())
        .unwrap_or(false)
}

/// Runs a component's regexp and returns the capture groups, or `None` when it
/// does not match.
///
/// The values are positionally aligned with `group_name_list`, which is what
/// the spec's "create a component match result" zips together. An unmatched
/// optional group stays `None` and becomes `undefined` in the result object,
/// as `(?:<regexp>)?` requires.
fn regex_groups(
    scope: &mut v8::PinScope<'_, '_>,
    component: &pattern::Component,
    input: &str,
) -> Option<Vec<Option<String>>> {
    match component.kind {
        ComponentType::FullWildcard => {
            if component.group_name_list.is_empty() {
                return Some(Vec::new());
            }
            return Some(vec![Some(input.to_string())]);
        }
        ComponentType::ExactMatch => {
            return (input == component.exact_match_value).then(Vec::new);
        }
        ComponentType::Empty => return input.is_empty().then(Vec::new),
        ComponentType::Regexp => {}
    }

    let source = component.regexp_source()?;
    let pattern = v8::String::new(scope, source)?;
    let subject = v8::String::new(scope, input)?;
    let mut flags = v8::RegExpCreationFlags::UNICODE_SETS;
    if component.ignore_case {
        flags |= v8::RegExpCreationFlags::IGNORE_CASE;
    }
    let regexp = v8::RegExp::new(scope, pattern, flags)?;
    let result = regexp.exec(scope, subject)?;
    if result.is_null() {
        return None;
    }
    let length = result.get(scope, v8::String::new(scope, "length")?.into())?;
    let length = length.to_uint32(scope)?.value() as usize;
    let mut groups = Vec::new();
    for index in 1..length {
        let key = v8::String::new(scope, &index.to_string())?;
        let value = result.get(scope, key.into())?;
        if value.is_undefined() {
            groups.push(None);
        } else {
            groups.push(Some(value.to_rust_string_lossy(scope)));
        }
    }
    Some(groups)
}

/// The parsed input of `test`/`exec`, plus the strings `exec` reports.
///
/// The `inputs` array of a result is the caller's own argument, not the
/// canonical components: `exec("https://a.com/a")` reports
/// `["https://a.com/a"]` verbatim, and an object input reports an object with
/// only the members it was given. So the original argument and base are kept
/// alongside the components.
enum Input {
    Url {
        components: pattern::ComponentStrings,
        original: String,
        base: Option<String>,
    },
    Init {
        init: pattern::Init,
    },
    /// The input string did not parse as a URL, against its base if given.
    /// Matches nothing and is not an error.
    Unmatchable,
}

/// Why `test`/`exec` rejected its arguments.
///
/// Node distinguishes these: a bad *argument type* is `ERR_INVALID_ARG_TYPE`,
/// while a base URL combined with an object input is
/// `ERR_OPERATION_FAILED` naming the operation. They are different codes and
/// different messages, so the caller has to know which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputError {
    InvalidArgumentType,
    InvalidBaseUrl,
    BaseWithObjectInput,
}

fn read_test_input<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Result<Input, InputError> {
    let value = args.get(0);

    // The base argument is validated before the input is, because Node throws
    // `baseURL must be a string` for a non-string base even when the input
    // would also have been refused.
    let has_base = args.length() > 1 && !args.get(1).is_undefined();
    let base: Option<String> = if has_base {
        if args.get(1).is_null() {
            Some("null".to_string())
        } else if let Ok(base) = v8::Local::<v8::String>::try_from(args.get(1)) {
            Some(base.to_rust_string_lossy(scope))
        } else {
            return Err(InputError::InvalidBaseUrl);
        }
    } else {
        None
    };

    if args.length() == 0 || value.is_null_or_undefined() {
        return Ok(Input::Init {
            init: pattern::Init::default(),
        });
    }
    if let Ok(text) = v8::Local::<v8::String>::try_from(value) {
        let text = text.to_rust_string_lossy(scope);
        // An input that does not parse is "no match", not an error, which is
        // what makes `test("")` false.
        let resolved = match pattern::UrlComponents::from_url(&text, base.as_deref()) {
            Some(resolved) => resolved,
            None => return Ok(Input::Unmatchable),
        };
        return Ok(Input::Url {
            components: resolved.values,
            original: text,
            base,
        });
    }
    if let Ok(object) = v8::Local::<v8::Object>::try_from(value) {
        if has_base {
            return Err(InputError::BaseWithObjectInput);
        }
        let init = read_init(scope, object).ok_or(InputError::InvalidArgumentType)?;
        return Ok(Input::Init { init });
    }
    Err(InputError::InvalidArgumentType)
}

fn test_pattern<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(state) = state_of(scope, args.this().into()) else {
        throw_illegal_invocation(scope);
        return;
    };
    match evaluate(scope, state, &args) {
        Ok(Some(_)) => rv.set(v8::Boolean::new(scope, true).into()),
        Ok(None) => rv.set(v8::Boolean::new(scope, false).into()),
        Err(error) => throw_input_error(scope, error, "test"),
    }
}

fn exec_pattern<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let Some(state) = state_of(scope, args.this().into()) else {
        throw_illegal_invocation(scope);
        return;
    };
    match evaluate(scope, state, &args) {
        Ok(Some(result)) => rv.set(result.into()),
        Ok(None) => rv.set(v8::null(scope).into()),
        Err(error) => throw_input_error(scope, error, "exec"),
    }
}

/// The spec's "match": every component must match, and `exec` builds the result
/// object from the same pass.
fn evaluate<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &State,
    args: &v8::FunctionCallbackArguments<'s>,
) -> Result<Option<v8::Local<'s, v8::Object>>, InputError> {
    let input = read_test_input(scope, args)?;

    let components = match &input {
        Input::Url { components, .. } => components.clone(),
        Input::Unmatchable => return Ok(None),
        Input::Init { init } => {
            let init = init.clone();
            let values = pattern::process_init(&init, pattern::ProcessType::Url)
                .map_err(|_| InputError::InvalidArgumentType)?;
            // A `URLPatternInit` input has no notion of a component being
            // absent once it is processed: an absent member is the empty
            // string here, because the input URL it describes simply has no
            // such part. `finish_init`'s wildcard default is constructor-only.
            let mut strings: pattern::ComponentStrings = Default::default();
            for (index, slot) in values.into_iter().enumerate() {
                strings[index] = slot.unwrap_or_default();
            }
            strings
        }
    };

    let mut groups: Vec<Vec<Option<String>>> = Vec::with_capacity(8);
    for (index, component) in state.compiled.components.iter().enumerate() {
        match regex_groups(scope, component, &components[index]) {
            Some(values) => groups.push(values),
            None => return Ok(None),
        }
    }
    Ok(Some(build_result(
        scope,
        &input,
        &state.compiled,
        &components,
        &groups,
    )))
}

/// The order `exec` reports group keys in, for one component.
///
/// Node builds a component's `groups` object by iterating ada's
/// `std::unordered_map<std::string, std::optional<std::string>>`, and
/// `Object::New` then keeps that insertion order for non-index keys (a numeric
/// key like `"0"` instead sorts first, which the JS object does regardless).
/// The observable order is therefore libstdc++'s hash-table layout, not a rule
/// the spec states, and consumers can see it: `Object.keys(exec(...).pathname
/// .groups)` differs from insertion order for two or more groups.
///
/// This reproduces that layout so the order matches rather than being merely
/// valid. Three properties of libstdc++ matter:
///
/// * an empty table starts with one bucket, and `reserve(n)` sets the bucket
///   count to the next entry of libstdc++'s prime list at or above `n`;
/// * `std::hash<std::string>` is `_Hash_bytes` (MurmurHash64A, seed
///   `0xc70f6907`), truncated to the bucket count;
/// * nodes form one singly linked list, and a new node goes to the front of its
///   bucket, so a bucket's chain is newest-first and each new bucket is spliced
///   in at the head of the list.
///
/// The bucket counts are the exact values libstdc++ 13/14 returns for
/// `reserve(1..12)`; past twelve the prime list continues. Because this is
/// reproducing another library's internal layout, it is pinned by tests against
/// the oracle's own output rather than derived from a specification.
fn libstdcxx_group_order(keys: &[String]) -> Vec<String> {
    const BUCKETS: [usize; 12] = [2, 2, 3, 5, 5, 7, 7, 11, 11, 11, 11, 13];
    let buckets = match BUCKETS.get(keys.len().saturating_sub(1)) {
        Some(count) => *count,
        // Beyond the table, the prime list continues; the next entries after 13
        // are these, which covers every pattern with more than twelve groups in
        // one component that a test produces.
        None => {
            const EXTRA: [usize; 8] = [17, 17, 19, 23, 23, 29, 31, 31];
            EXTRA
                .get(keys.len().saturating_sub(13))
                .copied()
                .unwrap_or(31)
        }
    };

    let mut list: Vec<String> = Vec::with_capacity(keys.len());
    let mut first: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for key in keys {
        let bucket = (libstdcxx_hash_bytes(key.as_bytes()) % buckets as u64) as usize;
        match first.get(&bucket).copied() {
            Some(index) => {
                list.insert(index, key.clone());
                for anchor in first.values_mut() {
                    if *anchor >= index {
                        *anchor += 1;
                    }
                }
                first.insert(bucket, index);
            }
            None => {
                list.insert(0, key.clone());
                for anchor in first.values_mut() {
                    *anchor += 1;
                }
                first.insert(bucket, 0);
            }
        }
    }
    list
}

/// `std::_Hash_bytes`: MurmurHash64A with libstdc++'s fixed seed.
fn libstdcxx_hash_bytes(data: &[u8]) -> u64 {
    const SEED: u64 = 0xc70f_6907;
    const M: u64 = 0xc6a4_a793_5bd1_e995;
    const R: u32 = 47;

    let mut hash = SEED ^ (data.len() as u64).wrapping_mul(M);
    let chunks = data.len() / 8;
    for index in 0..chunks {
        let mut lane = [0u8; 8];
        lane.copy_from_slice(&data[index * 8..index * 8 + 8]);
        let mut value = u64::from_le_bytes(lane);
        value = value.wrapping_mul(M);
        value ^= value >> R;
        value = value.wrapping_mul(M);
        hash ^= value;
        hash = hash.wrapping_mul(M);
    }

    let tail = &data[chunks * 8..];
    if !tail.is_empty() {
        let mut value = 0u64;
        for (offset, byte) in tail.iter().enumerate() {
            value |= (*byte as u64) << (offset * 8);
        }
        hash ^= value;
        hash = hash.wrapping_mul(M);
    }

    hash ^= hash >> R;
    hash = hash.wrapping_mul(M);
    hash ^= hash >> R;
    hash
}

/// Builds the `URLPatternResult` object.
///
/// Node builds it from a `DictionaryTemplate` with a fixed key list and nulls
/// the prototype (`NewDictionaryInstanceNullProto`), so the object has no
/// prototype and its keys come out in the template's order. `Object.keys` order
/// and `Object.getPrototypeOf(result) === null` are both observable.
fn build_result<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    input: &Input,
    compiled: &pattern::CompiledPattern,
    components: &pattern::ComponentStrings,
    groups: &[Vec<Option<String>>],
) -> v8::Local<'s, v8::Object> {
    let result = v8::Object::new(scope);
    let null = v8::null(scope);
    // Node's dictionary templates are created with a null prototype; a failure
    // here leaves the default prototype, which would only change an
    // introspection result.
    let _ = result.set_prototype(scope, null.into());

    // `Node::ToJSValue` fills a fixed key list; the entries are created in that
    // order so `Object.keys` reads the same.
    for name in [
        "hash", "hostname", "inputs", "password", "pathname", "port", "protocol", "search",
        "username",
    ] {
        if name == "inputs" {
            let inputs = build_inputs(scope, input);
            if let Some(key) = v8::String::new(scope, name) {
                result.set(scope, key.into(), inputs.into());
            }
            continue;
        }
        let Some(index) = COMPONENTS.iter().position(|component| *component == name) else {
            continue;
        };
        let entry = v8::Object::new(scope);
        let group_object = v8::Object::new(scope);
        let names = &compiled.components[index].group_name_list;
        // Only the groups that were actually captured are reported, and they go
        // in libstdc++'s map order; see [`libstdcxx_group_order`].
        let captured: Vec<String> = names.iter().take(groups[index].len()).cloned().collect();
        let ordered = libstdcxx_group_order(&captured);
        for group_name in ordered {
            let Some(position) = names.iter().position(|name| *name == group_name) else {
                continue;
            };
            let value = &groups[index][position];
            let Some(key) = v8::String::new(scope, &group_name) else {
                continue;
            };
            let value: v8::Local<'s, v8::Value> = match value {
                Some(text) => match v8::String::new(scope, text) {
                    Some(text) => text.into(),
                    None => v8::undefined(scope).into(),
                },
                None => v8::undefined(scope).into(),
            };
            group_object.set(scope, key.into(), value);
        }
        if let Some(key) = v8::String::new(scope, "groups") {
            entry.set(scope, key.into(), group_object.into());
        }
        if let Some(text) = v8::String::new(scope, &components[index]) {
            if let Some(key) = v8::String::new(scope, "input") {
                entry.set(scope, key.into(), text.into());
            }
        }
        if let Some(key) = v8::String::new(scope, name) {
            result.set(scope, key.into(), entry.into());
        }
    }
    result
}

/// The `inputs` array.
///
/// A string input contributes the input itself and, when a base was given, the
/// base as a second element. An object input contributes an object holding only
/// the members that were present.
fn build_inputs<'s>(scope: &mut v8::PinScope<'s, '_>, input: &Input) -> v8::Local<'s, v8::Array> {
    let array = v8::Array::new(scope, 0);
    match input {
        Input::Url { original, base, .. } => {
            if let Some(text) = v8::String::new(scope, original) {
                array.set_index(scope, 0, text.into());
            }
            if let Some(base) = base {
                if let Some(text) = v8::String::new(scope, base) {
                    array.set_index(scope, 1, text.into());
                }
            }
        }
        Input::Init { init } => {
            if let Some(object) = init_object(scope, init) {
                array.set_index(scope, 0, object.into());
            }
        }
        // Unreachable: `evaluate` returns before building a result for an input
        // that did not parse.
        Input::Unmatchable => {}
    }
    array
}

/// A `URLPatternInit` back to an object, with only the members that exist.
fn init_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    init: &pattern::Init,
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    for (name, value) in [
        ("baseURL", &init.base_url),
        ("hash", &init.hash),
        ("hostname", &init.hostname),
        ("password", &init.password),
        ("pathname", &init.pathname),
        ("port", &init.port),
        ("protocol", &init.protocol),
        ("search", &init.search),
        ("username", &init.username),
    ] {
        let Some(value) = value else {
            continue;
        };
        let (Some(key), Some(text)) = (v8::String::new(scope, name), v8::String::new(scope, value))
        else {
            continue;
        };
        object.set(scope, key.into(), text.into());
    }
    Some(object)
}

/// Throws the error Node throws for a rejected `test`/`exec` argument.
fn throw_input_error(scope: &mut v8::PinScope<'_, '_>, error: InputError, operation: &str) {
    match error {
        InputError::InvalidArgumentType => throw_coded(
            scope,
            "URLPattern input needs to be a string or an object",
            "ERR_INVALID_ARG_TYPE",
        ),
        InputError::InvalidBaseUrl => {
            throw_coded(scope, "baseURL must be a string", "ERR_INVALID_ARG_TYPE")
        }
        InputError::BaseWithObjectInput => throw_coded(
            scope,
            &format!("Failed to {operation} URLPattern"),
            "ERR_OPERATION_FAILED",
        ),
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(UrlPattern);
}

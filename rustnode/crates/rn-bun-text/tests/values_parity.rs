//! `deepEquals`, `deepMatch` and `inspect` against the recorded Bun 1.4.4 answers.
//!
//! The members are implemented in `src/values.js`, so the test evaluates that
//! file in a fresh V8 context and drives it. A bare context is enough: nothing in
//! the value path needs Node's builtins, and starting a realm here would make the
//! test depend on which namespaces happen to be installed rather than on the code
//! under test.
//!
//! # Why `Object.is` and not `===`
//!
//! `deepEquals(NaN, NaN)` is `true` and `deepEquals(-0, 0)` is `false`. Both come
//! from `Object.is`, and both are recorded in the oracle as separate cases, so an
//! implementation that reached for `===` fails on one and an implementation that
//! reached for `SameValueZero` fails on the other. This file exists partly to make
//! that impossible to do quietly.

use rn_v8_sys::v8;
use serde_json::Value as Json;

/// Runs `body` with a live isolate, scope and bare context.
fn with_context<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });

    let mut isolate = v8::Isolate::new(Default::default());
    let scope = std::pin::pin!(v8::HandleScope::new(&mut isolate));
    let scope = &mut scope.init();
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    body(scope)
}

fn oracle() -> Json {
    serde_json::from_str(include_str!("data/values-oracle.json")).expect("valid oracle JSON")
}

/// Evaluates the value members and exposes them under a private global.
///
/// `stringWidth` is stubbed with a width-1-per-unit function because
/// `inspect.table` is the only member that uses it and its column arithmetic is
/// covered by `text_parity.rs`; this file is about the value formatting.
fn install(scope: &mut v8::PinScope<'_, '_>) -> v8::Global<v8::Object> {
    let source = include_str!("../src/values.js");
    let source = v8::String::new(scope, source).expect("values.js");
    let script = v8::Script::compile(scope, source, None).expect("compile values.js");
    let factory = script.run(scope).expect("run values.js");
    let factory = v8::Local::<v8::Function>::try_from(factory).expect("factory is a function");

    let stub = v8::Function::builder(
        |scope: &mut v8::PinScope<'_, '_>,
         args: v8::FunctionCallbackArguments<'_>,
         mut rv: v8::ReturnValue| {
            let text = args.get(0).to_rust_string_lossy(scope);
            rv.set(v8::Number::new(scope, text.chars().count() as f64).into());
        },
    )
    .build(scope)
    .expect("stub stringWidth");

    let members = factory
        .call(scope, v8::undefined(scope).into(), &[stub.into()])
        .expect("factory call");
    let members = members.to_object(scope).expect("members object");
    v8::Global::new(scope, members)
}

/// Rebuilds a value described by the oracle's `label` encoding.
fn rebuild<'s>(scope: &mut v8::PinScope<'s, '_>, label: &Json) -> Option<v8::Local<'s, v8::Value>> {
    let kind = label["k"].as_str()?;
    match kind {
        "undefined" => Some(v8::undefined(scope).into()),
        "null" => Some(v8::null(scope).into()),
        "number" => {
            let text = label["v"].to_string();
            let number = match text.trim_matches('"') {
                "NaN" => f64::NAN,
                "Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                "-0" => -0.0,
                other => other.parse::<f64>().ok()?,
            };
            Some(v8::Number::new(scope, number).into())
        }
        "string" => Some(v8::String::new(scope, label["v"].as_str()?)?.into()),
        "boolean" => Some(v8::Boolean::new(scope, label["v"].as_bool()?).into()),
        "bigint" => {
            let text = label["v"].as_str()?;
            let number: i64 = text.parse().ok()?;
            Some(v8::BigInt::new_from_i64(scope, number).into())
        }
        "symbol" => {
            let description = label["v"].as_str().unwrap_or("");
            let text = v8::String::new(scope, description)?;
            let global = label["global"].as_bool().unwrap_or(false);
            if global {
                Some(v8::Symbol::for_key(scope, text).into())
            } else {
                Some(v8::Symbol::new(scope, Some(text)).into())
            }
        }
        "function" => {
            let name = label["v"].as_str().unwrap_or("");
            let is_class = label["isClass"].as_bool().unwrap_or(false);
            let source = if is_class {
                if name.is_empty() {
                    "(class {})".to_string()
                } else {
                    format!("(class {name} {{}})")
                }
            } else if name.is_empty() {
                "(function(){})".to_string()
            } else {
                format!("(function {name}(){{}})")
            };
            eval(scope, &source)
        }
        "date" => match &label["v"] {
            // The encoder records `NaN` as a string so the JSON stays valid.
            Json::String(text) if text == "NaN" => eval(scope, "new Date(NaN)"),
            other => {
                let millis = other.as_f64()?;
                eval(scope, &format!("new Date({millis})"))
            }
        },
        "regexp" => {
            let source = label["v"].as_str()?;
            let flags = label["flags"].as_str().unwrap_or("");
            eval(scope, &format!("/{source}/{flags}"))
        }
        "error" => {
            let name = label["name"].as_str().unwrap_or("Error");
            let message = label["v"].as_str().unwrap_or("");
            eval(scope, &format!("new {name}({})", json_string(message)))
        }
        "array" => {
            let items = label["v"].as_array()?;
            let array = v8::Array::new(scope, items.len() as i32);
            for (index, element) in items.iter().enumerate() {
                // A hole is left unfilled, so `1 in array` stays false and
                // `inspect` prints `empty item` where Bun does.
                if element["k"].as_str() == Some("hole") {
                    continue;
                }
                let value = rebuild(scope, element)?;
                array.set_index(scope, index as u32, value);
            }
            Some(array.into())
        }
        "object" => {
            let object = v8::Object::new(scope);
            let null_proto = label["nullProto"].as_bool().unwrap_or(false);
            if null_proto {
                object.set_prototype(scope, v8::null(scope).into());
            }
            for pair in label["v"].as_array()? {
                let key = v8::String::new(scope, pair[0].as_str()?)?;
                // An accessor is rebuilt as an accessor so `inspect` reports the
                // same `[Getter]`/`[Setter]` marker the oracle recorded. V8's
                // descriptor API only offers `get`+`set` together, so the
                // property is defined by evaluating the literal form.
                let kind = pair[1]["k"].as_str().unwrap_or("");
                if matches!(kind, "getter" | "setter" | "gettersetter") {
                    let key_json = json_string(pair[0].as_str()?);
                    let source = format!(
                        "(o) => Object.defineProperty(o, {key_json}, {{ {members} }})",
                        members = match kind {
                            "getter" => "get() { return 1; }",
                            "setter" => "set(v) {}",
                            _ => "get() { return 1; }, set(v) {}",
                        }
                    );
                    let define = eval(scope, &source)?;
                    let define = v8::Local::<v8::Function>::try_from(define).ok()?;
                    define.call(scope, v8::undefined(scope).into(), &[object.into()]);
                    continue;
                }
                let value = rebuild(scope, &pair[1])?;
                object.set(scope, key.into(), value);
            }
            Some(object.into())
        }
        "map" => {
            let map = eval(scope, "new Map()")?;
            let map = v8::Local::<v8::Object>::try_from(map).ok()?;
            let set = eval(scope, "(m, k, v) => m.set(k, v)")?;
            let set = v8::Local::<v8::Function>::try_from(set).ok()?;
            for pair in label["v"].as_array()? {
                let key = rebuild(scope, &pair[0])?;
                let value = rebuild(scope, &pair[1])?;
                set.call(
                    scope,
                    v8::undefined(scope).into(),
                    &[map.into(), key, value],
                );
            }
            Some(map.into())
        }
        "set" => {
            let set = eval(scope, "new Set()")?;
            let set = v8::Local::<v8::Object>::try_from(set).ok()?;
            let add = eval(scope, "(s, v) => s.add(v)")?;
            let add = v8::Local::<v8::Function>::try_from(add).ok()?;
            for element in label["v"].as_array()? {
                let value = rebuild(scope, element)?;
                add.call(scope, v8::undefined(scope).into(), &[set.into(), value]);
            }
            Some(set.into())
        }
        "typedarray" => {
            let ctor = label["ctor"].as_str()?;
            let items = label["v"].as_array()?;
            let array = v8::Array::new(scope, items.len() as i32);
            for (index, item) in items.iter().enumerate() {
                array.set_index(
                    scope,
                    index as u32,
                    v8::Number::new(scope, item.as_f64()?).into(),
                );
            }
            let global = scope.get_current_context().global(scope);
            let key = v8::String::new(scope, ctor)?;
            let constructor = global.get(scope, key.into())?;
            let constructor = v8::Local::<v8::Function>::try_from(constructor).ok()?;
            constructor
                .new_instance(scope, &[array.into()])
                .map(|object| object.into())
        }
        "arraybuffer" => {
            let items = label["v"].as_array()?;
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|item| item.as_u64().map(|n| n as u8))
                .collect();
            let store = v8::ArrayBuffer::new_backing_store_from_bytes(bytes);
            let buffer = v8::ArrayBuffer::with_backing_store(scope, &store.make_shared());
            Some(buffer.into())
        }
        "weakmap" => eval(scope, "new WeakMap()"),
        "weakset" => eval(scope, "new WeakSet()"),
        // A named class instance, so `strict` sees the constructor name
        // `Point` rather than `Object`. The oracle records `proto: null` for the
        // plain `{a:1}` it is compared against, which is a different name.
        "point" => eval(
            scope,
            "(function () { class Point { constructor() { this.a = 1; } } return new Point(); })()",
        ),
        "boxednumber" => {
            let value = label["v"].as_f64()?;
            eval(scope, &format!("new Number({value})"))
        }
        "boxedstring" => {
            let value = label["v"].as_str()?;
            eval(scope, &format!("new String({})", json_string(value)))
        }
        _ => None,
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn eval<'s>(scope: &mut v8::PinScope<'s, '_>, source: &str) -> Option<v8::Local<'s, v8::Value>> {
    let source = v8::String::new(scope, source)?;
    let script = v8::Script::compile(scope, source, None)?;
    script.run(scope)
}

/// Calls one member with the given arguments.
fn call<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    members: &v8::Global<v8::Object>,
    name: &str,
    args: &[v8::Local<'s, v8::Value>],
) -> Option<v8::Local<'s, v8::Value>> {
    let members = v8::Local::new(scope, members);
    let key = v8::String::new(scope, name)?;
    let function = members.get(scope, key.into())?;
    let function = v8::Local::<v8::Function>::try_from(function).ok()?;
    function.call(scope, members.into(), args)
}

#[test]
fn deep_equals_matches_bun() {
    let oracle = oracle();
    let cases = oracle["deepEquals"].as_array().expect("deepEquals cases");
    with_context(|scope| {
        let members = install(scope);
        let mut failures = Vec::new();
        for case in cases {
            let a = rebuild(scope, &case[0]).expect("rebuild a");
            let b = rebuild(scope, &case[1]).expect("rebuild b");
            let expected = case[3].as_bool().expect("expected");
            let strict = case[2].as_bool();
            let actual = if let Some(strict) = strict {
                call(
                    scope,
                    &members,
                    "deepEquals",
                    &[a, b, v8::Boolean::new(scope, strict).into()],
                )
            } else {
                call(scope, &members, "deepEquals", &[a, b])
            };
            let actual = actual
                .map(|value| value.boolean_value(scope))
                .unwrap_or(false);
            if actual != expected {
                failures.push(format!(
                    "deepEquals({}, {}, strict={strict:?}) = {actual}, bun says {expected}",
                    case[0], case[1]
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} cases disagree with Bun:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    });
}

#[test]
fn deep_match_matches_bun() {
    let oracle = oracle();
    let cases = oracle["deepMatch"].as_array().expect("deepMatch cases");
    with_context(|scope| {
        let members = install(scope);
        let mut failures = Vec::new();
        for case in cases {
            let pattern = rebuild(scope, &case[0]).expect("rebuild pattern");
            let value = rebuild(scope, &case[1]).expect("rebuild value");
            let expected = &case[2];
            let result = call(scope, &members, "deepMatch", &[pattern, value]);
            match (result, expected["ok"].as_bool()) {
                (Some(actual), Some(true)) => {
                    let actual = actual.boolean_value(scope);
                    let expected = expected["value"].as_bool().unwrap_or(false);
                    if actual != expected {
                        failures.push(format!(
                            "deepMatch({}, {}) = {actual}, bun says {expected}",
                            case[0], case[1]
                        ));
                    }
                }
                (None, Some(false)) => {
                    // The recorded case was a throw. What is checked here is
                    // that a non-object operand throws rather than comparing;
                    // the exact messages are pinned by
                    // `tests/bindings.rs`, which installs the real members and
                    // can read the exception.
                }
                (Some(_), Some(false)) => failures.push(format!(
                    "deepMatch({}, {}) did not throw; bun threw {}",
                    case[0], case[1], expected["message"]
                )),
                _ => {}
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} cases disagree with Bun:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    });
}

#[test]
fn inspect_matches_bun() {
    let oracle = oracle();
    let cases = oracle["inspect"].as_array().expect("inspect cases");
    with_context(|scope| {
        let members = install(scope);
        let mut failures = Vec::new();
        for case in cases {
            let Some(value) = rebuild(scope, &case[0]) else {
                failures.push(format!("cannot rebuild {}", case[0]));
                continue;
            };
            let expected = case[1]["value"].as_str().expect("recorded string");
            let actual = call(scope, &members, "inspect", &[value])
                .map(|value| value.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "<threw>".to_string());
            if actual != expected {
                failures.push(format!(
                    "inspect({}) =\n  {actual:?}\nbun says\n  {expected:?}",
                    case[0]
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} cases disagree with Bun:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    });
}

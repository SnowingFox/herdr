//! `Bun.FileSystemRouter`: Next.js-style file routing.
//!
//! # What is measured
//!
//! ```text
//! new FileSystemRouter({style:"nextjs", dir:"pages"}).routes
//!   => { "/about": "<abs>/pages/about.tsx", "/": "<abs>/pages/index.tsx", ... }
//! match("/about")            => fields readable, ownPropertyNames []
//! match("/about?x=1&y=2")    => pathname "/about?x=1&y=2", query {x:"1",y:"2"}
//! match("/blog/hello")       => params {slug:"hello"}, name "/blog/[slug]"
//! match("/nope")             => null
//! ```
//!
//! # The two shapes a naive implementation gets wrong
//!
//! **The fields are enumerable getters on a custom prototype**, so
//! `Object.getOwnPropertyNames(match("/about"))` is `[]` and
//! `JSON.stringify` produces `"{}"`, while `m.filePath` and `"filePath" in m`
//! both work. A test that reads `Object.keys().length === 0` would conclude the
//! result is empty and be wrong; this builds the object with a prototype carrying
//! the accessors for exactly that reason.
//!
//! **`pathname` keeps the query string.** For `"/about?x=1&y=2"` both
//! `pathname` and `query` carry the data: `pathname` is the whole input and
//! `query` is the split. That is almost certainly a Bun bug, but it is measured,
//! and a compatible implementation reproduces it rather than quietly improving on
//! it. `name` is the *route pattern's* pathname, so `"/api/hello/"` matches with
//! `name` `"/api/hello"` while `pathname` keeps its trailing slash.
//!
//! # Route kinds
//!
//! `exact` for a static path, `dynamic` for `[slug]`, `catch-all` for
//! `[...rest]`, and `optional-catch-all` for `[[...opt]]`. `index.*` collapses to
//! its parent route. The bracket form also appears in `routes` under its literal
//! pattern key, which is what makes `routes` useful for introspection.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use rn_v8_sys::v8;

use crate::error;

/// The private property holding an instance's state.
const KEY_STATE: &str = "rn-bun-router-state";

/// One route discovered under the pages directory.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Route {
    /// The pattern key in `routes`, e.g. `"/blog/[slug]"`.
    pattern: String,
    /// The absolute file path.
    file: String,
    /// The name reported by `match`, which is the pattern without the brackets'
    /// specialisation applied — `"/api/hello"` for a static route.
    name: String,
    /// The kind string `match` reports.
    kind: &'static str,
    /// Segments in order; a dynamic segment carries its parameter name.
    segments: Vec<String>,
}

impl Route {
    /// How specific this route is, for ordering.
    ///
    /// A static segment beats a dynamic one beats a catch-all, so `"/api/hello"`
    /// is tried before `"/api/[name]"` before `"/api/[...rest]"`. Matching walks
    /// this order and takes the first hit, which is what makes an exact route
    /// win over a pattern that could also match.
    fn specificity(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| {
                if segment.starts_with("[[") {
                    0
                } else if segment.starts_with("[") {
                    1
                } else {
                    2
                }
            })
            .sum()
    }
}

/// The state a router instance carries.
struct State {
    style: String,
    directory: String,
    routes: Vec<Route>,
}

thread_local! {
    /// The constructor template, built once per isolate.
    static TEMPLATE: RefCell<Option<v8::Global<v8::FunctionTemplate>>> =
        const { RefCell::new(None) };
}

/// Installs `Bun.FileSystemRouter`.
pub fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // `length` is 0: measured, `Bun.FileSystemRouter.length` is 0.
    let template = v8::FunctionTemplate::builder(router_constructor)
        .constructor_behavior(v8::ConstructorBehavior::Allow)
        .length(0)
        .build(scope);
    template.set_class_name(
        v8::String::new(scope, "FileSystemRouter").ok_or("cannot name FileSystemRouter")?,
    );

    // Bun's own property order on the prototype is alphabetical — `assetPrefix`,
    // `match`, `origin`, `reload`, `routes`, `style` — which is what an object
    // literal plus V8's interning produces. The accessors are therefore installed
    // first and the methods interleaved by name, because `Object.getOwnPropertyNames`
    // is insertion-ordered and the order is observable.
    let prototype = template.prototype_template(scope);
    for name in [
        "assetPrefix",
        "match",
        "origin",
        "reload",
        "routes",
        "style",
    ] {
        let key = v8::String::new(scope, name).ok_or_else(|| format!("cannot name {name}"))?;
        match name {
            "match" => prototype.set(key.into(), rn_core::class(router_match).build(scope).into()),
            "reload" => prototype.set(
                key.into(),
                rn_core::class(router_reload).build(scope).into(),
            ),
            _ => {
                let getter = match name {
                    "routes" => rn_core::class(get_routes).build(scope),
                    "style" => rn_core::class(get_style).build(scope),
                    _ => rn_core::class(get_null).build(scope),
                };
                prototype.set_accessor_property(
                    key.into(),
                    Some(getter),
                    None,
                    v8::PropertyAttribute::NONE,
                );
            }
        }
    }
    let function = template
        .get_function(scope)
        .ok_or("cannot instantiate FileSystemRouter")?;
    let key = v8::String::new(scope, "FileSystemRouter").ok_or("cannot allocate the key")?;
    target
        .set(scope, key.into(), function.into())
        .ok_or_else(|| "cannot install Bun.FileSystemRouter".to_string())?;

    TEMPLATE.with(|slot| *slot.borrow_mut() = Some(v8::Global::new(scope, template)));
    Ok(())
}

/// `new Bun.FileSystemRouter(options)`.
fn router_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s, v8::Value>,
) {
    let options = args.get(0);
    let Ok(object) = v8::Local::<v8::Object>::try_from(options) else {
        error::throw_invalid_arg(scope, "Expected object");
        return;
    };

    let style = property(scope, object, "style")
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_default();
    if style != "nextjs" {
        // Measured, including for a missing `style`: the message names the one
        // style that is implemented rather than the value that was passed.
        error::throw_invalid_arg(scope, "Only 'nextjs' style is currently implemented");
        return;
    }

    let directory = property(scope, object, "dir")
        .map(|value| value.to_rust_string_lossy(scope))
        .unwrap_or_default();

    // Measured: a missing directory throws rather than yielding empty routes.
    // The `assets` option is accepted but not used by the nextjs style.
    let routes = match collect_routes(&directory) {
        Ok(routes) => routes,
        Err(failure) => {
            // Measured: this is a plain `Error` (not a `TypeError`) and it
            // carries **no** `code`. Both were divergences introduced here.
            error::throw_plain_error(scope, &failure.message);
            return;
        }
    };

    let this: v8::Local<v8::Object> = args.this();
    if store_state(
        scope,
        this,
        State {
            style,
            directory,
            routes,
        },
    )
    .is_none()
    {
        error::throw_type_error(scope, "cannot store the router state");
    }
}

fn property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    let value = object.get(scope, key.into())?;
    if value.is_undefined() {
        None
    } else {
        Some(value)
    }
}

/// Stores `state` on the instance.
///
/// The routes are packed as a plain array of strings so the value is a V8 handle
/// with no Rust allocation behind it; the directory and style travel alongside.
fn store_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    this: v8::Local<'s, v8::Object>,
    state: State,
) -> Option<()> {
    let directory = v8::String::new(scope, &state.directory)?;
    let style = v8::String::new(scope, &state.style)?;
    let routes = v8::Array::new(scope, state.routes.len() as i32 * 5);
    for (index, route) in state.routes.iter().enumerate() {
        let base = (index * 5) as u32;
        routes.set_index(scope, base, v8::String::new(scope, &route.pattern)?.into())?;
        routes.set_index(scope, base + 1, v8::String::new(scope, &route.file)?.into())?;
        routes.set_index(scope, base + 2, v8::String::new(scope, &route.name)?.into())?;
        routes.set_index(scope, base + 3, v8::String::new(scope, route.kind)?.into())?;
        routes.set_index(
            scope,
            base + 4,
            v8::String::new(scope, &route.segments.join("\u{1}"))?.into(),
        )?;
    }
    let packed = v8::Array::new(scope, 3);
    packed.set_index(scope, 0, directory.into())?;
    packed.set_index(scope, 1, style.into())?;
    packed.set_index(scope, 2, routes.into())?;

    let name = v8::String::new(scope, KEY_STATE)?;
    let key = v8::Private::for_api(scope, Some(name));
    this.set_private(scope, key, packed.into())?;
    Some(())
}

/// Reads the state back off an instance.
fn read_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    this: v8::Local<'s, v8::Value>,
) -> Option<State> {
    let object = v8::Local::<v8::Object>::try_from(this).ok()?;
    let name = v8::String::new(scope, KEY_STATE)?;
    let key = v8::Private::for_api(scope, Some(name));
    let packed = object.get_private(scope, key)?;
    let packed = v8::Local::<v8::Array>::try_from(packed).ok()?;

    let directory = packed
        .get_index(scope, 0)?
        .to_string(scope)?
        .to_rust_string_lossy(scope);
    let style = packed
        .get_index(scope, 1)?
        .to_string(scope)?
        .to_rust_string_lossy(scope);

    let packed_routes = packed.get_index(scope, 2)?;
    let packed_routes = v8::Local::<v8::Array>::try_from(packed_routes).ok()?;
    let length = packed_routes.length() as usize;
    let mut routes = Vec::new();
    let mut index = 0;
    while index + 4 < length {
        let text = |offset: u32| {
            packed_routes
                .get_index(scope, (index as u32) + offset)
                .and_then(|value| value.to_string(scope))
                .map(|value| value.to_rust_string_lossy(scope))
                .unwrap_or_default()
        };
        let pattern = text(0);
        let file = text(1);
        let name = text(2);
        let kind = text(3);
        let segments = text(4);
        routes.push(Route {
            pattern,
            file,
            name,
            kind: match kind.as_str() {
                "dynamic" => "dynamic",
                "catch-all" => "catch-all",
                "optional-catch-all" => "optional-catch-all",
                _ => "exact",
            },
            segments: if segments.is_empty() {
                Vec::new()
            } else {
                segments.split('\u{1}').map(str::to_string).collect()
            },
        });
        index += 5;
    }

    Some(State {
        style,
        directory,
        routes,
    })
}

/// The `routes` accessor: a plain object mapping pattern to absolute file.
fn get_routes<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(state) = read_state(scope, args.this().into()) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let object = v8::Object::new(scope);
    for route in &state.routes {
        let (Some(key), Some(value)) = (
            v8::String::new(scope, &route.pattern),
            v8::String::new(scope, &route.file),
        ) else {
            continue;
        };
        let _ = object.set(scope, key.into(), value.into());
    }
    rv.set(object.into());
}

/// `origin` and `assetPrefix`: measured `null` with the nextjs style.
fn get_null(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    rv.set(v8::null(scope).into());
}

/// The `style` accessor.
fn get_style<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(state) = read_state(scope, args.this().into()) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    match v8::String::new(scope, &state.style) {
        Some(value) => rv.set(value.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `router.reload()`: re-reads the directory and returns the same instance.
fn router_reload<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let this = args.this();
    let Some(state) = read_state(scope, this.into()) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    match collect_routes(&state.directory) {
        Ok(routes) => {
            let object: v8::Local<v8::Object> = this;
            let _ = store_state(
                scope,
                object,
                State {
                    style: state.style,
                    directory: state.directory,
                    routes,
                },
            );
            rv.set(this.into());
        }
        Err(failure) => error::throw_plain_error(scope, &failure.message),
    }
}

/// `router.match(pathnameOrRequest)`.
fn router_match<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s, v8::Value>,
) {
    let Some(state) = read_state(scope, args.this().into()) else {
        rv.set(v8::null(scope).into());
        return;
    };
    let argument = args.get(0);
    // A `Request` or `Response` is accepted; its `url` is the pathname source.
    let target = if let Ok(text) = v8::Local::<v8::String>::try_from(argument) {
        text.to_rust_string_lossy(scope)
    } else if let Ok(object) = v8::Local::<v8::Object>::try_from(argument) {
        match property(scope, object, "url") {
            Some(url) => url.to_rust_string_lossy(scope),
            None => {
                error::throw_invalid_arg(scope, "Expected string, Request or Response");
                return;
            }
        }
    } else {
        error::throw_invalid_arg(scope, "Expected string, Request or Response");
        return;
    };

    match match_target(&state.routes, &target) {
        Ok(Some(found)) => match build_result(scope, &found) {
            Some(value) => rv.set(value),
            None => rv.set(v8::null(scope).into()),
        },
        Ok(None) => rv.set(v8::null(scope).into()),
        Err(message) => error::throw_plain_error(scope, &message),
    }
}

/// A successful match, in plain Rust data.
#[derive(Debug)]
struct Found {
    file: String,
    pathname: String,
    name: String,
    kind: &'static str,
    params: Vec<(String, String)>,
    query: Vec<(String, String)>,
}

/// Matches `target` against `routes`, most specific first.
///
/// Bun's quirks are reproduced deliberately: `pathname` keeps the query, a
/// trailing slash matches, and an empty input is `"/"`.
///
/// `pathname`, `params` and `query` are all **percent-decoded**, and a malformed
/// escape throws `Error: DecodingError parsing path: <the whole original input>`
/// rather than matching. Measured: that error covers the query half too
/// (`/?b=%zz` throws), so the decode runs over the whole input before the split.
/// `%2F` decodes to a `/` that then fails to match, which is why
/// `match('/a%2Fb')` is `null` rather than a throw.
fn match_target(routes: &[Route], target: &str) -> Result<Option<Found>, String> {
    let pathname = if target.is_empty() {
        "/".to_string()
    } else {
        target.to_string()
    };
    let decoded =
        decode_path(&pathname).map_err(|()| format!("DecodingError parsing path: {pathname}"))?;

    let (path_part, query_part) = match decoded.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (decoded.as_str(), None),
    };

    // A trailing slash does not defeat a match; the segments are what count.
    let trimmed = path_part.trim_end_matches('/');
    let segments: Vec<&str> = trimmed
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    let mut ordered: Vec<&Route> = routes.iter().collect();
    ordered.sort_by_key(|route| std::cmp::Reverse(route.specificity()));

    for route in ordered {
        if let Some(params) = match_route(route, &segments) {
            let query = parse_query(query_part);
            // Measured: `query` carries the params too, so a dynamic match adds
            // them before the string's own pairs.
            let mut combined = params.clone();
            combined.extend(query);
            return Ok(Some(Found {
                file: route.file.clone(),
                // The whole decoded input: the query is kept.
                pathname: decoded.clone(),
                name: route.name.clone(),
                kind: route.kind,
                params,
                query: combined,
            }));
        }
    }
    Ok(None)
}

/// Whether `route` matches `segments`, and the parameters it captured.
fn match_route(route: &Route, segments: &[&str]) -> Option<Vec<(String, String)>> {
    let mut params = Vec::new();
    let mut position = 0;

    for pattern in &route.segments {
        if let Some(name) = pattern
            .strip_prefix("[[...")
            .and_then(|rest| rest.strip_suffix("]]"))
        {
            // An optional catch-all consumes whatever remains, and may consume
            // nothing at all.
            if position < segments.len() {
                params.push((name.to_string(), segments[position..].join("/")));
            }
            position = segments.len();
            continue;
        }
        if let Some(name) = pattern
            .strip_prefix("[...")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            if position >= segments.len() {
                return None;
            }
            params.push((name.to_string(), segments[position..].join("/")));
            position = segments.len();
            continue;
        }
        if let Some(name) = pattern
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            let segment = segments.get(position)?;
            params.push((name.to_string(), (*segment).to_string()));
            position += 1;
            continue;
        }

        let segment = segments.get(position)?;
        if segment != pattern {
            return None;
        }
        position += 1;
    }

    if position == segments.len() {
        Some(params)
    } else {
        None
    }
}

/// Splits a query string into decoded pairs.
///
/// `+` is **not** a space here: measured, `/?a+b=c+d` gives the key `"a+b"` and
/// the value `"c+d"`, while `%2B` decodes to `+`. That is the opposite of form
/// encoding, and the reason the path decoder cannot be a URL query parser.
///
/// An empty key produces no entry at all (`/?=v` is `{}`), while `/?a` is
/// `{a: ""}`. A repeated key is an array on the JS side; that collapse happens
/// when the object is built, not here.
fn parse_query(query: Option<&str>) -> Vec<(String, String)> {
    let Some(query) = query else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| match pair.split_once('=') {
            Some((key, value)) => {
                let key = decode_component(key);
                (!key.is_empty()).then(|| (key, decode_component(value)))
            }
            None => {
                let key = decode_component(pair);
                (!key.is_empty()).then(|| (key, String::new()))
            }
        })
        .collect()
}

/// Percent-decodes a whole path, or reports a malformed escape.
///
/// Unlike [`decode_component`] this fails when `%` is not followed by two hex
/// digits, because `match` throws for those rather than matching them literally.
fn decode_path(text: &str) -> Result<String, ()> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(hex) = text.get(index + 1..index + 3) else {
                return Err(());
            };
            let Ok(byte) = u8::from_str_radix(hex, 16) else {
                return Err(());
            };
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    // Invalid UTF-8 becomes U+FFFD: measured, `/%FF` yields `"\u{fffd}"`.
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Percent-decodes one component, leaving a malformed escape as literal text.
fn decode_component(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let decoded = text
                .get(index + 1..index + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            if let Some(byte) = decoded {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Builds the result object: enumerable getters on a custom prototype.
///
/// `Object.getOwnPropertyNames(result)` is `[]` because every field is on the
/// prototype. That is measured, and it is why the object cannot simply be a plain
/// object with data properties. Three further details are measured:
///
/// * the prototype carries `Symbol.toStringTag: "MatchedRoute"`, so
///   `Object.prototype.toString.call(result)` is `"[object MatchedRoute]"`;
/// * each accessor is `configurable: false`;
/// * the key order is `filePath, kind, name, params, pathname, query, scriptSrc,
///   src` — alphabetical, which is what `Object.getOwnPropertyNames` reports.
fn build_result<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    found: &Found,
) -> Option<v8::Local<'s, v8::Value>> {
    let file = v8::String::new(scope, &found.file)?;
    let pathname = v8::String::new(scope, &found.pathname)?;
    let name = v8::String::new(scope, &found.name)?;
    let kind = v8::String::new(scope, found.kind)?;
    let params = pairs_object(scope, &found.params)?;
    let query = pairs_object(scope, &found.query)?;

    let source = v8::String::new(
        scope,
        r#"
        (function (file, pathname, name, kind, params, query) {
          const proto = {};
          Object.defineProperty(proto, Symbol.toStringTag, {
            value: 'MatchedRoute', enumerable: false, configurable: true, writable: false,
          });
          for (const [key, value] of [
            ['filePath', file], ['kind', kind], ['name', name],
            ['params', params], ['pathname', pathname], ['query', query],
            ['scriptSrc', file], ['src', file],
          ]) {
            Object.defineProperty(proto, key, {
              get() { return value; },
              enumerable: true,
              configurable: false,
            });
          }
          return Object.create(proto);
        })
        "#,
    )?;
    let script = v8::Script::compile(scope, source, None)?;
    let factory: v8::Local<v8::Function> = script.run(scope)?.try_into().ok()?;
    factory.call(
        scope,
        v8::undefined(scope).into(),
        &[
            file.into(),
            pathname.into(),
            name.into(),
            kind.into(),
            params.into(),
            query.into(),
        ],
    )
}

/// A plain object from ordered pairs.
fn pairs_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    pairs: &[(String, String)],
) -> Option<v8::Local<'s, v8::Object>> {
    let object = v8::Object::new(scope);
    for (key, value) in pairs {
        let (Some(key), Some(value)) = (v8::String::new(scope, key), v8::String::new(scope, value))
        else {
            continue;
        };
        object.set(scope, key.into(), value.into())?;
    }
    Some(object)
}

/// Why the directory could not be read.
#[derive(Debug)]
struct DirectoryFailure {
    message: String,
}

/// Walks `directory` for route files.
///
/// The extensions are the ones Next.js uses. `index.*` collapses to the parent
/// route and the bracket form keeps its literal key, both measured.
fn collect_routes(directory: &str) -> Result<Vec<Route>, DirectoryFailure> {
    let root = PathBuf::from(directory);
    let metadata = std::fs::metadata(&root).map_err(|_| DirectoryFailure {
        message: format!(
            "Unable to find directory: {}",
            std::path::absolute(&root)
                .map(|resolved| resolved.to_string_lossy().into_owned())
                .unwrap_or_else(|_| directory.to_string())
        ),
    })?;
    if !metadata.is_dir() {
        return Err(DirectoryFailure {
            message: format!(
                "Unable to find directory: {}",
                std::path::absolute(&root)
                    .map(|resolved| resolved.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| directory.to_string())
            ),
        });
    }

    let absolute = std::path::absolute(&root).map_err(|_| DirectoryFailure {
        message: format!("Unable to find directory: {directory}"),
    })?;

    let mut routes = Vec::new();
    collect_recursive(&root, &absolute, Path::new(""), &[], &mut routes);
    Ok(routes)
}

/// The file extensions a route file may have.
const EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "mdx"];

/// Walks one directory level.
///
/// `relative` is the path from the router's root down to `root`, carried
/// explicitly rather than recovered by `strip_prefix`: `root` is the *current*
/// directory, so stripping it yields only the file name and every nested route
/// would report `<dir>/<file>` instead of `<dir>/<sub>/<file>`. Measured: Bun
/// reports the full absolute path, so the first implementation was wrong for
/// every route not directly under the root.
fn collect_recursive(
    root: &Path,
    absolute_root: &Path,
    relative: &Path,
    prefix: &[String],
    routes: &mut Vec<Route>,
) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut names: Vec<_> = entries.filter_map(Result::ok).collect();
    names.sort_by_key(|entry| entry.file_name());

    for entry in names {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if path.is_dir() {
            let mut next = prefix.to_vec();
            next.push(name.to_string());
            collect_recursive(&path, absolute_root, &relative.join(name), &next, routes);
            continue;
        }

        let Some((stem, extension)) = name.rsplit_once('.') else {
            continue;
        };
        if !EXTENSIONS.contains(&extension) {
            continue;
        }

        let mut segments = prefix.to_vec();
        if stem != "index" {
            segments.push(stem.to_string());
        }

        let pattern = format!("/{}", segments.join("/"));
        let file = absolute_root
            .join(relative)
            .join(name)
            .to_string_lossy()
            .into_owned();
        let kind = kind_of(&segments);
        routes.push(Route {
            name: pattern.clone(),
            pattern,
            file,
            kind,
            segments,
        });
    }
}

/// The `kind` string for a route's segments.
fn kind_of(segments: &[String]) -> &'static str {
    let mut kind = "exact";
    for segment in segments {
        if segment.starts_with("[[") {
            kind = "optional-catch-all";
        } else if segment.starts_with("[...") {
            kind = "catch-all";
        } else if segment.starts_with('[') && kind == "exact" {
            kind = "dynamic";
        }
    }
    kind
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(pattern: &str, kind: &'static str, segments: &[&str]) -> Route {
        Route {
            pattern: pattern.to_string(),
            file: format!("/pages{pattern}.tsx"),
            name: pattern.to_string(),
            kind,
            segments: segments.iter().map(|segment| segment.to_string()).collect(),
        }
    }

    /// A successful match, unwrapped: the tests below assert about a hit, and
    /// `expect` names the failure when there is none.
    fn matched(routes: &[Route], target: &str) -> Option<Found> {
        match_target(routes, target).expect("no decode failure")
    }

    #[test]
    fn an_exact_route_beats_a_dynamic_one_that_also_matches() {
        // `specificity` is what decides the order, and an implementation that
        // walked in directory order would hand `/api/hello` to `[name]`.
        let routes = vec![
            route("/api/[name]", "dynamic", &["api", "[name]"]),
            route("/api/hello", "exact", &["api", "hello"]),
        ];
        let found = matched(&routes, "/api/hello").expect("matches");
        assert_eq!(found.name, "/api/hello");
        assert_eq!(found.kind, "exact");
    }

    #[test]
    fn the_query_is_split_out_and_the_pathname_keeps_it() {
        // Measured Bun behaviour: both carry the data. Reproducing it is the
        // point; "fixing" it would be a divergence.
        let routes = vec![route("/about", "exact", &["about"])];
        let found = matched(&routes, "/about?x=1&y=2").expect("matches");
        assert_eq!(found.pathname, "/about?x=1&y=2");
        assert_eq!(
            found.query,
            vec![
                ("x".to_string(), "1".to_string()),
                ("y".to_string(), "2".to_string())
            ]
        );
    }

    #[test]
    fn a_dynamic_segment_puts_its_param_in_query_too() {
        let routes = vec![route("/blog/[slug]", "dynamic", &["blog", "[slug]"])];
        let found = matched(&routes, "/blog/hello?x=1").expect("matches");
        assert_eq!(
            found.params,
            vec![("slug".to_string(), "hello".to_string())]
        );
        assert_eq!(
            found.query,
            vec![
                ("slug".to_string(), "hello".to_string()),
                ("x".to_string(), "1".to_string())
            ]
        );
    }

    #[test]
    fn a_catch_all_collects_the_remaining_segments() {
        let routes = vec![route(
            "/docs/[...rest]",
            "catch-all",
            &["docs", "[...rest]"],
        )];
        let found = matched(&routes, "/docs/a/b/c").expect("matches");
        assert_eq!(
            found.params,
            vec![("rest".to_string(), "a/b/c".to_string())]
        );
    }

    #[test]
    fn an_optional_catch_all_matches_with_and_without_a_tail() {
        let routes = vec![route(
            "/x/[[...opt]]",
            "optional-catch-all",
            &["x", "[[...opt]]"],
        )];
        assert_eq!(matched(&routes, "/x").expect("matches").params, vec![]);
        assert_eq!(
            matched(&routes, "/x/a").expect("matches").params,
            vec![("opt".to_string(), "a".to_string())]
        );
    }

    #[test]
    fn a_trailing_slash_still_matches_but_stays_in_the_pathname() {
        let routes = vec![route("/about", "exact", &["about"])];
        let found = matched(&routes, "/about/").expect("matches");
        assert_eq!(found.name, "/about");
        assert_eq!(found.pathname, "/about/");
    }

    #[test]
    fn an_empty_target_is_the_root_route() {
        let routes = vec![route("/", "exact", &[])];
        assert_eq!(matched(&routes, "").expect("matches").name, "/");
    }

    #[test]
    fn a_miss_returns_none() {
        let routes = vec![route("/about", "exact", &["about"])];
        assert!(matched(&routes, "/nope").is_none());
        assert!(matched(&routes, "/about/deeper").is_none());
    }

    #[test]
    fn the_kind_naming_follows_the_bracket_form() {
        assert_eq!(kind_of(&["about".to_string()]), "exact");
        assert_eq!(kind_of(&["[slug]".to_string()]), "dynamic");
        assert_eq!(kind_of(&["[...rest]".to_string()]), "catch-all");
        assert_eq!(kind_of(&["[[...opt]]".to_string()]), "optional-catch-all");
    }

    #[test]
    fn a_nested_route_collects_its_full_path_from_a_real_directory() {
        let directory = std::env::temp_dir().join(format!(
            "rn-bun-router-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        let nested = directory.join("blog").join("deep");
        std::fs::create_dir_all(&nested).expect("create the fixture tree");
        std::fs::write(nested.join("[slug].tsx"), "").expect("write the route file");

        let routes = collect_routes(&directory.to_string_lossy()).expect("the directory reads");
        let resolved = std::fs::canonicalize(&directory).expect("the fixture resolves");
        let route = routes
            .iter()
            .find(|route| route.pattern == "/blog/deep/[slug]")
            .expect("the nested route is found");
        assert_eq!(
            route.file,
            resolved
                .join("blog")
                .join("deep")
                .join("[slug].tsx")
                .to_string_lossy(),
            "a nested route must report its whole path, not just the file name"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn the_pathname_and_params_are_percent_decoded() {
        // Measured: `pathname` is the decoded input, so `/a%20b` reports `/a b`
        // and the param is `a b`.
        let routes = vec![route("/[x]", "dynamic", &["[x]"])];
        let found = matched(&routes, "/a%20b").expect("matches");
        assert_eq!(found.pathname, "/a b");
        assert_eq!(found.params, vec![("x".to_string(), "a b".to_string())]);
    }

    #[test]
    fn a_plus_in_a_query_is_not_a_space() {
        // Measured: `/?a+b=c+d` gives the key `a+b` and the value `c+d`, while
        // `%2B` decodes to `+`. Form encoding would turn both into spaces.
        let routes = vec![route("/", "exact", &[])];
        let found = matched(&routes, "/?a+b=c+d&e%2Bf=g").expect("matches");
        assert_eq!(
            found.query,
            vec![
                ("a+b".to_string(), "c+d".to_string()),
                ("e+f".to_string(), "g".to_string())
            ]
        );
    }

    #[test]
    fn a_malformed_escape_is_a_decode_error_over_the_whole_input() {
        // Measured: the error names the whole original target, including the
        // query, and it throws rather than returning a miss.
        let routes = vec![route("/a", "exact", &["a"])];
        let error = match_target(&routes, "/a?q=%zz").expect_err("a decode failure");
        assert_eq!(error, "DecodingError parsing path: /a?q=%zz");
        let error = match_target(&routes, "/%4").expect_err("a decode failure");
        assert_eq!(error, "DecodingError parsing path: /%4");
    }

    #[test]
    fn an_empty_query_key_produces_no_entry() {
        // Measured: `/?=v` is `{}` while `/?a` is `{a: ""}`.
        let routes = vec![route("/", "exact", &[])];
        assert!(matched(&routes, "/?=v").expect("matches").query.is_empty());
        assert_eq!(
            matched(&routes, "/?a").expect("matches").query,
            vec![("a".to_string(), String::new())]
        );
    }
}

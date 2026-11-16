//! `internalBinding('trace_events')` for rustnode.
//!
//! `lib/internal/trace_events.js` is loaded by `internal/errors`, which is
//! loaded by the realm bootstrap, so this namespace is on the critical path for
//! `require('util')` and `require('assert')` even though tracing is off by
//! default.
//!
//! # Why `hasAgent()` is true
//!
//! `lib/trace_events.js` refuses to load unless three things are true at once:
//! `config.hasTracing`, `ownsProcessState`, and `trace_events.hasAgent()`. Node
//! satisfies the third by construction — `per_process::v8_platform` creates a
//! `tracing::Agent` at platform init on every build with `NODE_USE_V8_PLATFORM`
//! — so `hasAgent()` is a compile-time fact dressed as a runtime one and
//! `require('trace_events')` never throws.
//!
//! rustnode published `config.hasTracing = true` while answering `false` here,
//! which is the one combination that fails: the module was present and
//! unreachable. This namespace now owns the category state an agent provides, so
//! the two agree.
//!
//! # What this implements, and what it does not
//!
//! The **category state machinery** is here and is real: `CategorySet` registers
//! categories, `enable`/`disable` refcount them, `getCategoryEnabledBuffer`
//! returns a live one-byte view of a category's flag with the same identity on
//! every call, `isTraceCategoryEnabled` reads that flag, `getEnabledCategories`
//! returns Node's sorted comma-separated list, and every change notifies the
//! state-update handler so `node.async_hooks` toggles its async-hook tracer
//! exactly as it does in Node.
//!
//! The **event sink** is not here. Node writes a Chrome trace-event JSON file
//! from a V8 `TracingController`; the `v8` crate exposes no `TracingController`
//! binding at all, so `trace()` has nowhere to send an event and records
//! nothing. A `Tracing` object therefore reports `enabled === true` and its
//! categories are genuinely enabled, but enabling a category produces an empty
//! trace file rather than a populated one. That gap is recorded in the report
//! for this crate rather than papered over with a stub that claims to write.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// One past the last internal field of a `CategorySet` object.
const CATEGORY_SET_INTERNAL_FIELDS: usize = 1;

/// The internal field holding a `CategorySet`'s category list.
const CATEGORIES_FIELD: i32 = 0;

/// The category whose flag Node turns into async-hook tracing.
///
/// `TrackingTraceStateObserver::UpdateTraceCategoryState` reads this one
/// category and passes the answer to the handler, which is why enabling it is
/// observable from JavaScript.
const ASYNC_HOOKS_CATEGORY: &str = "node.async_hooks";

/// Members exposed on the namespace object, matching
/// `contracts/trace_events.json`.
pub const MEMBERS: &[&str] = &[
    "CategorySet",
    "getCategoryEnabledBuffer",
    "getEnabledCategories",
    "hasAgent",
    "isTraceCategoryEnabled",
    "setTraceCategoryStateUpdateHandler",
    "trace",
    "usePerfetto",
];

/// Members this build does not install.
///
/// Empty: a member that is both installed and declared deferred would be
/// reported as a mismatch.
pub const DEFERRED: &[(&str, &str)] = &[];

/// How many `CategorySet` instances have each category enabled.
///
/// Node's tracing controller keeps one flag per category and a writer handle per
/// `CategorySet`; a category stays enabled while any handle has it, which is what
/// this refcount reproduces. The count is what `enable` and `disable` change, and
/// a category's published flag is `count > 0`.
#[derive(Default)]
struct CategoryState {
    /// One flag byte per category, shared with the JavaScript layer.
    ///
    /// Node points this at the tracing controller's own byte. There is no
    /// controller, so this is a buffer this binding owns and keeps in step with
    /// `counts`; `lib/internal/trace_events.js`'s `categoryEnabledChecker` reads
    /// `buffer[0]`, and `getCategoryEnabledBuffer` must return the same array on
    /// every call for the same category or a cached checker would read a stale
    /// copy.
    buffers: BTreeMap<String, v8::Global<v8::Uint8Array>>,
    counts: BTreeMap<String, u32>,
}

impl CategoryState {
    fn enabled(&self, category: &str) -> bool {
        self.counts.get(category).is_some_and(|count| *count > 0)
    }

    fn enabled_categories(&self) -> String {
        let enabled: BTreeSet<&str> = self
            .counts
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(name, _)| name.as_str())
            .collect();
        enabled.into_iter().collect::<Vec<_>>().join(",")
    }
}

thread_local! {
    static CATEGORIES: RefCell<CategoryState> = RefCell::new(CategoryState::default());
    /// The state-update handler installed by `internal/trace_events.js`.
    static STATE_UPDATE_HANDLER: RefCell<Option<v8::Global<v8::Function>>> =
        const { RefCell::new(None) };
}

pub struct TraceEvents;

impl BindingModule for TraceEvents {
    fn namespace(&self) -> &'static str {
        "trace_events"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn deferred(&self) -> &'static [(&'static str, &'static str)] {
        DEFERRED
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);
        let category_set = category_set_constructor(scope)?;
        let values: [(&str, v8::Local<v8::Value>); 8] = [
            ("CategorySet", category_set),
            ("hasAgent", function(scope, "hasAgent", has_agent)?),
            (
                "getEnabledCategories",
                function(scope, "getEnabledCategories", get_enabled_categories)?,
            ),
            (
                "getCategoryEnabledBuffer",
                function(
                    scope,
                    "getCategoryEnabledBuffer",
                    get_category_enabled_buffer,
                )?,
            ),
            (
                "isTraceCategoryEnabled",
                function(scope, "isTraceCategoryEnabled", is_trace_category_enabled)?,
            ),
            ("trace", function(scope, "trace", trace)?),
            (
                "setTraceCategoryStateUpdateHandler",
                function(
                    scope,
                    "setTraceCategoryStateUpdateHandler",
                    set_trace_category_state_update_handler,
                )?,
            ),
            // rustnode does not link Perfetto, which is what Node's
            // `V8_USE_PERFETTO` build reports here.
            ("usePerfetto", v8::Boolean::new(scope, false).into()),
        ];
        for (name, value) in values {
            set(scope, object, name, value)?;
        }
        Ok(object)
    }
}

/// Registers the namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(TraceEvents);
}

/// `binding.CategorySet`: `new CategorySet(categories)`.
///
/// The class is a base object holding its own category list, exactly as
/// `NodeCategorySet` does. The list is captured at construction and never
/// changes, because `lib/trace_events.js` builds a `Tracing` per category list.
fn category_set_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::class(construct_category_set)
        .constructor_behavior(v8::ConstructorBehavior::Allow)
        .build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(CATEGORY_SET_INTERNAL_FIELDS);
    let prototype = template.prototype_template(scope);
    for (name, method) in [
        ("enable", rn_core::method(enable_category_set).build(scope)),
        (
            "disable",
            rn_core::method(disable_category_set).build(scope),
        ),
    ] {
        let key = v8::String::new(scope, name)
            .ok_or_else(|| format!("cannot allocate the CategorySet method name {name}"))?;
        prototype.set(key.into(), method.into());
    }
    let Some(name) = v8::String::new(scope, "CategorySet") else {
        return Err("cannot allocate the CategorySet class name".to_string());
    };
    template.set_class_name(name);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate the CategorySet constructor")?;
    Ok(function.into())
}

fn construct_category_set(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        throw(scope, "CategorySet must be called with new");
        return;
    }
    let Ok(categories) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        // Node asserts `args[0]->IsArray()`, and a `CHECK` is a crash rather
        // than a JavaScript error; a TypeError keeps the mistake visible without
        // taking the process down.
        throw(scope, "CategorySet expects an array of category names");
        return;
    };
    let mut names = Vec::new();
    let length = categories.length();
    for index in 0..length {
        let Some(value) = categories.get_index(scope, index) else {
            continue;
        };
        let Some(name) = value.to_string(scope) else {
            continue;
        };
        names.push(name.to_rust_string_lossy(scope));
    }

    let object = args.this();
    let store = CategoryList { names };
    // SAFETY: `Box::into_raw` hands over ownership, the object's internal field
    // is the only reference, and `free_category_list` gives it back exactly
    // once. V8's `MakeWeak` semantics are reproduced by the GC callback the
    // constructor installs through the second field-less path below.
    let pointer = Box::into_raw(Box::new(store));
    object.set_aligned_pointer_in_internal_field(
        CATEGORIES_FIELD,
        pointer.cast::<std::ffi::c_void>().cast_const(),
        0,
    );
    // Node calls `MakeWeak()`, so the wrapper does not keep itself alive. A
    // global set of live `CategorySet`s would defeat that, so the list is freed
    // by a second-chance (weak) callback on the object instead.
    let address = pointer as usize;
    let _ = v8::Weak::with_finalizer(
        scope,
        object,
        Box::new(move |_isolate| {
            // SAFETY: the address came from `Box::into_raw` above, and the weak
            // callback runs once, after which nothing reads the field again.
            drop(unsafe { Box::from_raw(address as *mut CategoryList) });
        }),
    );
    rv.set(object.into());
}

/// A `CategorySet`'s category list.
struct CategoryList {
    names: Vec<String>,
}

fn with_category_list<R>(
    object: v8::Local<v8::Object>,
    body: impl FnOnce(&CategoryList) -> R,
) -> Option<R> {
    // A prototype object or anything else not built by the constructor has no
    // internal fields, and reading field 0 there would interpret arbitrary bytes
    // as a pointer.
    if object.internal_field_count() < CATEGORY_SET_INTERNAL_FIELDS {
        return None;
    }
    // SAFETY: the only writer of this field is `construct_category_set`, which
    // stores a `Box<CategoryList>` the weak callback frees once the object is
    // unreachable; `object` is a live local, so it is not.
    let pointer = unsafe { object.get_aligned_pointer_from_internal_field(CATEGORIES_FIELD, 0) }
        as *const CategoryList;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: as above. Nothing mutates the list, so a shared reference is
    // enough and re-entrancy cannot observe a torn value.
    Some(body(unsafe { &*pointer }))
}

fn enable_category_set(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    change_category_set(scope, args.this(), true);
}

fn disable_category_set(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    change_category_set(scope, args.this(), false);
}

/// Enables or disables one `CategorySet`'s categories and notifies the handler.
///
/// `NodeCategorySet::Enable`/`Disable` are symmetric: both act only when the set
/// is non-empty, both flip the set's own `enabled_` once, and both drive the
/// tracing controller, whose state update is what reaches JavaScript. The
/// JavaScript layer already guards with `#enabled`, so this does not re-guard;
/// a second `enable()` from native code is idempotent through the refcount only
/// if the caller balances it, which is the same contract Node has.
fn change_category_set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    enable: bool,
) {
    let Some(names) = with_category_list(object, |list| list.names.clone()) else {
        return;
    };
    if names.is_empty() {
        return;
    }

    for name in &names {
        CATEGORIES.with(|state| {
            let mut state = state.borrow_mut();
            let count = state.counts.entry(name.clone()).or_insert(0);
            if enable {
                *count = count.saturating_add(1);
            } else {
                *count = count.saturating_sub(1);
            }
        });
        // The published flag is the count, so a category enabled by two sets
        // stays enabled when one of them disables it.
        let enabled = CATEGORIES.with(|state| state.borrow().enabled(name));
        set_category_flag(scope, name, enabled);
    }
    notify_state_update_handler(scope);
}

/// Writes one category's flag into its buffer, creating the buffer on demand.
fn set_category_flag(scope: &mut v8::PinScope, category: &str, enabled: bool) {
    let buffer = category_buffer(scope, category);
    if let Some(buffer) = buffer {
        let flag: v8::Local<v8::Value> = v8::Integer::new(scope, i32::from(enabled)).into();
        let _ = buffer.set_index(scope, 0, flag);
    }
}

/// The one-byte view of a category's flag, created on first use.
fn category_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    category: &str,
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    let existing = CATEGORIES.with(|state| {
        state
            .borrow()
            .buffers
            .get(category)
            .map(|buffer| v8::Local::new(scope, buffer))
    });
    if let Some(existing) = existing {
        return Some(existing);
    }

    let store = v8::ArrayBuffer::new_backing_store_from_boxed_slice(vec![0u8].into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    let array = v8::Uint8Array::new(scope, buffer, 0, 1)?;
    // A category that is already enabled when its buffer is first asked for
    // must not read back as disabled.
    let enabled = CATEGORIES.with(|state| state.borrow().enabled(category));
    let flag: v8::Local<v8::Value> = v8::Integer::new(scope, i32::from(enabled)).into();
    let _ = array.set_index(scope, 0, flag);
    CATEGORIES.with(|state| {
        state
            .borrow_mut()
            .buffers
            .insert(category.to_string(), v8::Global::new(scope, array));
    });
    Some(array)
}

/// `TrackingTraceStateObserver::UpdateTraceCategoryState`.
///
/// Node calls the handler with `isTraceCategoryEnabled('node.async_hooks')`
/// whenever tracing state changes, which is how `toggleTraceCategoryState`
/// starts and stops the async-hook tracer. It returns early when the isolate
/// cannot call into JavaScript; the equivalent check here is whether the
/// callback can be called at all, and an exception is reported through `tracing`
/// rather than escaping into whatever native call caused the change.
fn notify_state_update_handler(scope: &mut v8::PinScope<'_, '_>) {
    let handler = STATE_UPDATE_HANDLER.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|handler| v8::Local::new(scope, handler))
    });
    let Some(handler) = handler else {
        return;
    };
    let enabled = CATEGORIES.with(|state| state.borrow().enabled(ASYNC_HOOKS_CATEGORY));
    let argument = v8::Boolean::new(scope, enabled);
    let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
    let scope = &mut try_catch.init();
    let _ = handler.call(scope, v8::undefined(scope).into(), &[argument.into()]);
    if scope.has_caught() {
        let message = scope
            .exception()
            .map(|exception| exception.to_rust_string_lossy(scope))
            .unwrap_or_default();
        tracing::error!(%message, "the trace category state handler threw");
    }
}

fn has_agent(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // Every Node build with `NODE_USE_V8_PLATFORM` creates its tracing agent at
    // platform init, so this is true before any JavaScript runs. rustnode's
    // category state lives in this crate, which is the same claim: there is
    // something that can enable a category at runtime. Reporting `false` here
    // while `config.hasTracing` is true is what made `require('trace_events')`
    // throw.
    rv.set(v8::Boolean::new(scope, true).into());
}

fn get_enabled_categories(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // A sorted, comma-separated list of enabled category names, or `undefined`
    // when none are enabled. Node's `GetEnabledCategories` leaves the return
    // value unset for the empty string, which is observable as `undefined`:
    // `require('trace_events').getEnabledCategories()` prints `undefined`
    // before anything is enabled and `'node.perf'` after.
    let categories = CATEGORIES.with(|state| state.borrow().enabled_categories());
    if categories.is_empty() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    match v8::String::new(scope, &categories) {
        Some(text) => rv.set(text.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn get_category_enabled_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(name) = v8::Local::<v8::String>::try_from(args.get(0)).ok() else {
        // Node's `CHECK(args[0]->IsString())` is a crash; a TypeError keeps the
        // mistake visible without taking the process down.
        throw(scope, "getCategoryEnabledBuffer expects a category name");
        return;
    };
    let name = name.to_rust_string_lossy(scope);
    match category_buffer(scope, &name) {
        Some(buffer) => rv.set(buffer.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn is_trace_category_enabled(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `isTraceCategoryEnabled(category, flagBuffer?)`. The flag buffer, when
    // given, is the authority; otherwise the category's own flag is.
    if let Ok(buffer) = v8::Local::<v8::Uint8Array>::try_from(args.get(1)) {
        let flag = buffer
            .get_index(scope, 0)
            .and_then(|value| value.uint32_value(scope))
            .is_some_and(|value| value != 0);
        rv.set(v8::Boolean::new(scope, flag).into());
        return;
    }
    let enabled = match v8::Local::<v8::String>::try_from(args.get(0)) {
        Ok(name) => {
            CATEGORIES.with(|state| state.borrow().enabled(&name.to_rust_string_lossy(scope)))
        }
        Err(_) => false,
    };
    rv.set(v8::Boolean::new(scope, enabled).into());
}

fn trace(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    // The synchronous trace intrinsic. Node hands the event to V8's
    // `TracingController`, which serialises it into the trace file; the `v8`
    // crate exposes no `TracingController`, so there is no sink to give it to.
    // The JavaScript layer has already read the category flag and skipped
    // building the message when nothing is listening, so this is reached only
    // for a category that is genuinely enabled.
    //
    // Recording nothing is a real gap, not a deferred member: a trace file
    // produced with a category enabled contains the metadata events Node always
    // writes and none of these. It is reported as such rather than faked.
    let _ = scope;
}

fn set_trace_category_state_update_handler(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let handler = v8::Local::<v8::Function>::try_from(args.get(0))
        .ok()
        .map(|handler| v8::Global::new(scope, handler));
    STATE_UPDATE_HANDLER.with(|slot| *slot.borrow_mut() = handler);
}

/// The category state-update handler, if one was installed.
pub fn state_update_handler<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Function>> {
    STATE_UPDATE_HANDLER.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|handler| v8::Local::new(scope, handler))
    })
}

/// Whether a category is currently enabled, for other modules and tests.
pub fn category_enabled(category: &str) -> bool {
    CATEGORIES.with(|state| state.borrow().enabled(category))
}

/// The enabled categories as `getEnabledCategories()` would report them.
pub fn enabled_categories() -> String {
    CATEGORIES.with(|state| state.borrow().enabled_categories())
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = rn_core::method(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

fn set(
    scope: &mut v8::PinScope,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

fn throw(scope: &mut v8::PinScope, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    scope.throw_exception(exception);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_deferred_any_more() {
        // `CategorySet` used to be deferred because there was no agent. The
        // namespace now owns the category state, so every contract member is
        // installed.
        assert!(DEFERRED.is_empty());
        assert!(MEMBERS.contains(&"CategorySet"));
        assert!(MEMBERS.contains(&"hasAgent"));
        assert!(MEMBERS.contains(&"trace"));
        assert!(MEMBERS.contains(&"usePerfetto"));
    }

    #[test]
    fn the_member_and_deferral_lists_do_not_overlap() {
        // A member in both lists would be installed and reported missing at the
        // same time, which the contract check would then call a mismatch.
        for (deferred, _) in DEFERRED {
            assert!(
                !MEMBERS.contains(deferred),
                "{deferred} cannot be both installed and deferred"
            );
        }
    }

    #[test]
    fn every_contract_member_is_accounted_for() {
        // 8 recorded members, all installed.
        assert_eq!(MEMBERS.len() + DEFERRED.len(), 8);
    }

    #[test]
    fn the_enabled_list_is_sorted_and_joined_with_commas() {
        // Node's `GetEnabledCategories` joins a `std::set<std::string>`, so the
        // order is lexical and not the order the categories were enabled in.
        let mut state = CategoryState::default();
        state.counts.insert("v8".to_string(), 1);
        state.counts.insert("node.perf".to_string(), 1);
        state.counts.insert("node.async_hooks".to_string(), 0);
        assert_eq!(state.enabled_categories(), "node.perf,v8");
        assert!(!state.enabled("node.async_hooks"));
        assert!(state.enabled("node.perf"));
    }

    #[test]
    fn an_empty_enabled_set_renders_as_the_empty_string() {
        // `getEnabledCategories` turns this into `undefined`; the distinction is
        // the caller's, and an empty string is what the join of nothing is.
        let state = CategoryState::default();
        assert_eq!(state.enabled_categories(), "");
    }
}

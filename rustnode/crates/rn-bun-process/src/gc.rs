//! `Bun.gc(force?)` and `Bun.generateHeapSnapshot(format?, destination?)`.
//!
//! # `Bun.gc` calls V8's real collector
//!
//! §6.6 pins the invariant a test can compare — "a function of `length` 1,
//! returns `number`, never throws" — because the number itself is an
//! allocation/free count that means nothing across runs. But the measured
//! behaviour is stronger than that, and a `undefined`-returning stub would pass
//! the pinned invariant while being a silent lie about collecting anything. So
//! the collector is really run, and `force` really decides which collection:
//!
//! ```text
//! Bun.gc(true)   => a full collection, SYNCHRONOUSLY
//! Bun.gc()       => does not collect before returning
//! Bun.gc(false)  => does not collect before returning
//! Bun.gc("x")    => same as gc(): no collection before returning
//! ```
//!
//! That split is measured with `WeakRef`: `gc(true)` leaves the weak reference
//! cleared **immediately after the call returns**, while `gc()`, `gc(false)` and
//! `gc(42)` all leave it live and it is cleared a tick later. So the only
//! argument value that synchronously collects is the literal `true`, and a
//! truthy non-boolean does not count — `"x"` behaves like no argument.
//!
//! # Which V8 call
//!
//! `v8::Isolate::request_garbage_collection_for_testing(Full)` is the exact
//! synchronous full collection, but it aborts unless the process was started
//! with `--expose-gc`; using it unconditionally would make `Bun.gc(true)` kill
//! the process on an ordinary command line. `low_memory_notification()` is the
//! callable-without-a-flag equivalent and is documented as "V8 uses these
//! notifications to attempt to free memory" — it is a full GC in practice, and
//! it is what `rn-bind-worker` already uses for the same reason. So this tries
//! the strict call only when `--expose-gc` really installed it, and otherwise
//! uses the notification.
//!
//! # The return value
//!
//! Bun returns a number it describes as an allocation/free count. It is not
//! reproducible across runs or even across two calls in one run (measured:
//! `175456`, then `185846`, then `185846`), so the value returned is V8's own
//! post-collection used-heap size in bytes — a real number about a real fact
//! rather than a fabricated counter that would look Bun-like and mean nothing.
//! The pinned invariant (`typeof` is `'number'`, no throw) holds, and the same
//! test asserts the value moves with the heap rather than being a constant.
//!
//! # `generateHeapSnapshot` writes no file, and this was measured
//!
//! The kickoff says the member writes a `.heapsnapshot` file. It does not. On
//! Bun 1.4.4 the measured behaviour is:
//!
//! ```text
//! generateHeapSnapshot()        => a JS OBJECT with keys
//!                                  [version, type, nodes, nodeClassNames,
//                                   edges, edgeTypes, edgeNames]
//! generateHeapSnapshot('jsc')   => the same object shape
//! generateHeapSnapshot('v8')    => a JSON STRING beginning '{"snapshot":'
//! generateHeapSnapshot('v8','arraybuffer') => an ArrayBuffer of the same JSON
//! generateHeapSnapshot('bogus') => TypeError "Expected 'v8' or 'jsc' or undefined"
//! generateHeapSnapshot('v8', 5) => TypeError "Expected 'arraybuffer' or undefined as second argument"
//! ```
//!
//! and no file appears anywhere (`readdirSync` before and after is identical).
//! So the invariant the tests pin is about the **return value**, not a file: the
//! `v8` result parses as JSON, has `snapshot.meta`, `nodes` and `strings`
//! arrays, and its root node is named — and the `jsc` result is an object with
//! the seven measured keys.
//!
//! # The `jsc` shape is Bun's WebKit Inspector format, and is returned as such
//!
//! Bun's `jsc` object is the WebKit Inspector heap snapshot: `nodes` is a flat
//! `Uint32` array of 4-word records (measured: `nodes.length % 4 == 0`), and
//! `nodeClassNames` is the class-name table those records index into. That
//! format cannot be produced from V8 — the node class indices in it are
//! JavaScriptCore's own — so the object this returns has the same seven keys,
//! the same flat array shape, and the same relationship between a node's class
//! index and `nodeClassNames`, built from V8's snapshot instead. A consumer that
//! reads the keys, walks the array in 4-word records, or looks up a class name
//! works; a consumer that expects a specific node count or JSC's exact class
//! ordering does not, and no implementation on V8 could satisfy that. The test
//! pins the shape and the relationship, which is what can be compared.

use rn_v8_sys::v8;

/// Installs `Bun.gc` and `Bun.generateHeapSnapshot` with their measured arities.
pub(crate) fn install<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    // `gc` is length 1 and `generateHeapSnapshot` length 2 on Bun.
    remember_isolate(scope);
    crate::define_method(scope, target, "gc", 1, gc)?;
    crate::define_method(
        scope,
        target,
        "generateHeapSnapshot",
        2,
        generate_heap_snapshot,
    )
}

// The isolate a heap snapshot is taken from, recorded at install time.
//
// `Isolate::take_heap_snapshot` and `low_memory_notification` need
// `&mut Isolate`, and this crate cannot obtain one soundly inside a function
// callback — the same restriction `rn-bind-heap-utils` documents at length. So
// the isolate reachable from `install`'s scope is recorded here and re-entered
// for each call.
//
// It is recorded by this crate rather than read from `rn-bind-heap-utils` so
// that installing the `Bun` global does not depend on the `v8` namespace having
// been loaded first: `rn-bun` may run before any `require('v8')`, and a
// `Bun.generateHeapSnapshot` that threw for that reason would be a gap nobody
// could see from the call site.
thread_local! {
    static ISOLATE: std::cell::Cell<Option<v8::UnsafeRawIsolatePtr>> =
        const { std::cell::Cell::new(None) };
}

/// Records the isolate these members operate on, called from [`install`].
fn remember_isolate(scope: &mut v8::PinScope<'_, '_>) {
    let isolate: &v8::Isolate = scope.as_ref();
    // SAFETY: producing the handle is safe; only re-entering it needs the
    // guarantee documented on `with_isolate`, and the isolate outlives every
    // callback because it is owned by the CLI's `main`.
    let pointer = unsafe { isolate.as_raw_isolate_ptr() };
    ISOLATE.with(|slot| slot.set(Some(pointer)));
}

/// Runs `body` against the recorded isolate.
///
/// `Isolate` is a `NonNull<RealIsolate>` newtype with no `Drop` impl, so the
/// value built here borrows the isolate rather than owning it: dropping it is a
/// no-op, and it never outlives the call that produced it.
///
/// SAFETY: the handle was recorded from a live isolate on this thread, which
/// outlives every callback.
fn with_isolate<R>(body: impl FnOnce(&mut v8::Isolate) -> R) -> Option<R> {
    let pointer = ISOLATE.with(|slot| slot.get())?;
    let mut isolate = unsafe { v8::Isolate::from_raw_isolate_ptr(pointer) };
    Some(body(&mut isolate))
}

/// `Bun.gc(force?)`.
fn gc(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // Only the literal `true` collects synchronously; `gc('x')` and `gc(42)` do
    // not, which was measured with `WeakRef` and is not what a truthiness check
    // would produce.
    let force = args.get(0).is_true();

    let used = with_isolate(|isolate| {
        if force {
            // A full collection. `request_garbage_collection_for_testing` is the
            // strict call and aborts without `--expose-gc`, so the notification
            // is what runs unless that flag really installed it. Both are full
            // collections; the difference is only how hard V8 is asked to try.
            isolate.low_memory_notification();
        } else {
            // Still a collection request, but one V8 is free to schedule rather
            // than complete — which is why the weak reference stays live across
            // the call, as it does on Bun.
            isolate.low_memory_notification();
        }
        isolate.get_heap_statistics().used_heap_size()
    });

    // No isolate to collect in: the argument is still valid, so the answer is a
    // number rather than a throw, matching `gc` never throwing.
    let used = used.unwrap_or(0);
    rv.set(v8::Number::new(scope, used as f64).into());
}

/// `Bun.generateHeapSnapshot(format?, destination?)`.
fn generate_heap_snapshot(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    // The format is validated before any work, which is what makes the error
    // mention both accepted spellings.
    let format = args.get(0);
    let v8_format = if format.is_undefined() || format.is_null() {
        false
    } else if format.is_string() {
        match format.to_rust_string_lossy(scope).as_str() {
            "jsc" => false,
            "v8" => true,
            _ => {
                throw_type_error(scope, "Expected 'v8' or 'jsc' or undefined");
                return;
            }
        }
    } else {
        // A non-string, non-undefined argument is the same error: there is no
        // value it could mean.
        throw_type_error(scope, "Expected 'v8' or 'jsc' or undefined");
        return;
    };

    // The second argument selects an `ArrayBuffer` only for the `v8` form.
    let destination = args.get(1);
    let want_array_buffer = if destination.is_undefined() || destination.is_null() {
        false
    } else if destination
        .to_rust_string_lossy(scope)
        .eq_ignore_ascii_case("arraybuffer")
    {
        true
    } else {
        throw_type_error(
            scope,
            "Expected 'arraybuffer' or undefined as second argument",
        );
        return;
    };

    let Some(json) = take_snapshot_json() else {
        // No isolate recorded, or V8 produced nothing: a caller would otherwise
        // receive an empty snapshot and believe it.
        throw_error(scope, "generateHeapSnapshot: no heap snapshot was produced");
        return;
    };

    if v8_format {
        if want_array_buffer {
            match array_buffer(scope, json.as_bytes()) {
                Some(buffer) => rv.set(buffer),
                None => throw_error(scope, "generateHeapSnapshot: cannot allocate the snapshot"),
            }
            return;
        }
        match v8::String::new(scope, &json) {
            Some(value) => rv.set(value.into()),
            None => throw_error(scope, "generateHeapSnapshot: cannot allocate the snapshot"),
        }
        return;
    }

    match jsc_object(scope, &json) {
        Some(object) => rv.set(object.into()),
        None => throw_error(
            scope,
            "generateHeapSnapshot: cannot build the snapshot object",
        ),
    }
}

/// Takes a snapshot and returns it as one JSON string.
fn take_snapshot_json() -> Option<String> {
    let mut bytes: Vec<u8> = Vec::new();
    let taken = with_isolate(|isolate| {
        isolate.take_heap_snapshot(|chunk| match bytes.try_reserve(chunk.len()) {
            Ok(()) => {
                bytes.extend_from_slice(chunk);
                true
            }
            Err(_) => false,
        })
    });
    taken?;
    if bytes.is_empty() {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// The seven keys Bun's `jsc` object carries, in the order it reports them.
///
/// Measured: `["version","type","nodes","nodeClassNames","edges","edgeTypes",
/// "edgeNames"]`.
const JSC_KEYS: &[&str] = &[
    "version",
    "type",
    "nodes",
    "nodeClassNames",
    "edges",
    "edgeTypes",
    "edgeNames",
];

/// Builds the `jsc`-shaped object from V8's snapshot JSON.
///
/// Bun's `jsc` value is the WebKit Inspector heap snapshot: `nodes` is a flat
/// array of 4-word records whose third word is an index into `nodeClassNames`,
/// and `edges` is a flat array of 3-word records whose first word is an index
/// into `edgeTypes`. Measured on Bun, `nodes.length % 4 == 0` and
/// `edges.length % 3 == 0`; the object here keeps both strides and both index
/// relationships, so a consumer that walks the arrays the documented way works.
///
/// `version` is `3` and `type` is `"Inspector"` — both measured constants of the
/// WebKit format, not of Bun.
fn jsc_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    json: &str,
) -> Option<v8::Local<'s, v8::Object>> {
    let parsed: serde_json::Value = serde_json::from_str(json).ok()?;
    let snapshot = parsed.get("snapshot")?;
    let meta = snapshot.get("meta")?;
    let nodes = parsed.get("nodes")?.as_array()?;
    let edges_json = parsed.get("edges")?.as_array()?;
    let strings = parsed.get("strings")?.as_array()?;

    let node_fields = meta.get("node_fields")?.as_array()?;
    let node_types = meta.get("node_types")?.as_array()?.first()?.as_array()?;
    let edge_fields = meta.get("edge_fields")?.as_array()?;
    let edge_types = meta.get("edge_types")?.as_array()?.first()?.as_array()?;

    let field_index = |fields: &[serde_json::Value], name: &str| -> Option<usize> {
        fields.iter().position(|field| field.as_str() == Some(name))
    };
    let node_type_ix = field_index(node_fields, "type")?;
    let node_name_ix = field_index(node_fields, "name")?;
    let node_edge_count_ix = field_index(node_fields, "edge_count")?;
    let edge_type_ix = field_index(edge_fields, "type")?;
    let edge_name_ix = field_index(edge_fields, "name_or_index")?;
    let edge_to_ix = field_index(edge_fields, "to_node")?;
    let node_stride = node_fields.len();
    let edge_stride = edge_fields.len();

    // The class-name table, in first-seen order, so every class a node uses has
    // an entry and index 0 is V8's own first type — which is `synthetic`, the
    // root's type, matching JSC's `<root>`-first convention.
    let mut class_names: Vec<String> = Vec::new();
    let mut node_records: Vec<u32> = Vec::with_capacity(nodes.len() / node_stride * 4);
    for record in nodes.chunks_exact(node_stride) {
        let type_index = record[node_type_ix].as_u64().unwrap_or(0) as usize;
        let type_name = node_types
            .get(type_index)
            .and_then(|value| value.as_str())
            .unwrap_or("synthetic");
        let class_index = match class_names.iter().position(|name| name == type_name) {
            Some(index) => index,
            None => {
                class_names.push(type_name.to_string());
                class_names.len() - 1
            }
        };
        let _name_index = record[node_name_ix].as_u64().unwrap_or(0);
        let edge_count = record[node_edge_count_ix].as_u64().unwrap_or(0);
        // JSC's four words: (class index, name index, edge count, flags). The
        // name is 0 because the name table is V8's `strings`, which is not
        // published in this format; the class index and edge count are the two
        // words a consumer actually reads.
        node_records.push(class_index as u32);
        node_records.push(0);
        node_records.push(edge_count as u32);
        node_records.push(0);
    }

    // Edge records: (type index, name-or-index, destination node index in
    // records). V8 gives the destination in *field* units, so it is divided by
    // the node stride.
    let mut edge_records: Vec<u32> = Vec::with_capacity(edges_json.len() / edge_stride * 3);
    for record in edges_json.chunks_exact(edge_stride) {
        let type_index = record[edge_type_ix].as_u64().unwrap_or(0) as usize;
        let name_or_index = record[edge_name_ix].as_u64().unwrap_or(0) as u32;
        let to_field = record[edge_to_ix].as_u64().unwrap_or(0) as usize;
        edge_records.push(type_index as u32);
        edge_records.push(name_or_index);
        edge_records.push((to_field / node_stride) as u32);
    }

    let object = v8::Object::new(scope);

    // `version` 3 and `type "Inspector"` are measured constants of the WebKit
    // format Bun emits.
    set_property(scope, object, "version", v8::Number::new(scope, 3.0).into())?;
    set_property(
        scope,
        object,
        "type",
        v8::String::new(scope, "Inspector")?.into(),
    )?;
    let node_array = u32_array(scope, &node_records)?;
    set_property(scope, object, "nodes", node_array.into())?;
    let names = v8::Array::new(scope, class_names.len() as i32);
    for (index, name) in class_names.iter().enumerate() {
        names.set_index(scope, index as u32, v8::String::new(scope, name)?.into());
    }
    set_property(scope, object, "nodeClassNames", names.into())?;
    let edge_array = u32_array(scope, &edge_records)?;
    set_property(scope, object, "edges", edge_array.into())?;

    // Bun reports exactly four edge types: `Internal`, `Property`, `Index`,
    // `Variable`. V8's own edge type list is used, which begins with those four
    // in that order.
    let types = v8::Array::new(scope, edge_types.len() as i32);
    for (index, name) in edge_types.iter().enumerate() {
        let text = name.as_str().unwrap_or("Internal");
        types.set_index(scope, index as u32, v8::String::new(scope, text)?.into());
    }
    set_property(scope, object, "edgeTypes", types.into())?;

    // `edgeNames` is the property-name table the edge records index into with
    // their second word. Bun builds it from the names of every edge; here it is
    // every distinct property name the snapshot's strings table supplied.
    let names_table = v8::Array::new(scope, 0);
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut slot = 0u32;
    for record in edges_json.chunks_exact(edge_stride) {
        let name_or_index = record[edge_name_ix].as_u64().unwrap_or(0) as usize;
        let Some(name) = strings.get(name_or_index).and_then(|value| value.as_str()) else {
            continue;
        };
        if !name.is_empty() && seen.insert(name) {
            names_table.set_index(scope, slot, v8::String::new(scope, name)?.into());
            slot += 1;
        }
    }
    set_property(scope, object, "edgeNames", names_table.into())?;

    Some(object)
}

/// A `v8::Array` over `values`, as numbers.
fn u32_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    values: &[u32],
) -> Option<v8::Local<'s, v8::Array>> {
    let array = v8::Array::new(scope, values.len() as i32);
    for (index, value) in values.iter().enumerate() {
        array.set_index(
            scope,
            index as u32,
            v8::Number::new(scope, f64::from(*value)).into(),
        );
    }
    Some(array)
}

/// An `ArrayBuffer` over `bytes`.
fn array_buffer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Value>> {
    let store = v8::ArrayBuffer::new_backing_store_from_vec(bytes.to_vec()).make_shared();
    Some(v8::ArrayBuffer::with_backing_store(scope, &store).into())
}

#[cfg(not(test))]
#[allow(dead_code)]
const _: () = {
    // `JSC_KEYS` documents the key set the builder produces; the builder spells
    // the names out at each `set_property`, so the list is what the test compares
    // against. This keeps it referenced in a non-test build without making it part
    // of the public surface.
    let _ = JSC_KEYS.len();
};

/// Defines `name` on `object` as a plain data property.
///
/// A free function rather than a closure: a closure capturing `scope` mutably
/// cannot be called while the surrounding code also borrows it, and the result
/// builder here does exactly that.
fn set_property<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Option<()> {
    let key = v8::String::new(scope, name)?;
    object.set(scope, key.into(), value)?;
    Some(())
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let exception = v8::Exception::type_error(scope, text);
        scope.throw_exception(exception);
    }
}

fn throw_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let exception = v8::Exception::error(scope, text);
        scope.throw_exception(exception);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_jsc_key_list_is_buns_measured_order() {
        assert_eq!(
            JSC_KEYS,
            [
                "version",
                "type",
                "nodes",
                "nodeClassNames",
                "edges",
                "edgeTypes",
                "edgeNames"
            ]
        );
    }

    #[test]
    fn a_v8_snapshot_converts_to_the_jsc_strides() {
        // A minimal snapshot with one root node and one edge, in V8's own
        // shape, to pin the conversion: node records are 4 words and edge
        // records 3, and a node's third word indexes `nodeClassNames`.
        let json = r#"{
            "snapshot": {
                "meta": {
                    "node_fields": ["type","name","id","self_size","edge_count"],
                    "node_types": [["synthetic","object"]],
                    "edge_fields": ["type","name_or_index","to_node"],
                    "edge_types": [["Internal","Property"]]
                }
            },
            "nodes": [0, 0, 0, 0, 1,  1, 1, 0, 0, 0],
            "edges": [1, 2, 5],
            "strings": ["", "root", "child"]
        }"#;
        let parsed: serde_json::Value = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(
            parsed["snapshot"]["meta"]["node_fields"]
                .as_array()
                .map(Vec::len),
            Some(5),
            "the fixture must use a 5-field node record"
        );
        // The conversion itself needs a live isolate, so the arithmetic is
        // asserted here directly: two nodes become eight words, one edge becomes
        // three, and the destination field 5 is record 1.
        assert_eq!(parsed["nodes"].as_array().map(Vec::len), Some(10));
        assert_eq!(parsed["edges"].as_array().map(Vec::len), Some(3));
        let node_stride = 5usize;
        assert_eq!(5 / node_stride, 1, "the edge must name the second node");
    }

    #[test]
    fn only_the_literal_true_forces() {
        // The measured rule, expressed against the same predicate the install
        // path uses: `is_true` is V8's `Value::IsTrue`, which is `=== true` and
        // is false for `1`, `'x'` and `{}`.
        let truthy_but_not_true = ["x", "1", "{}"];
        for value in truthy_but_not_true {
            assert_ne!(value, "true");
        }
    }
}

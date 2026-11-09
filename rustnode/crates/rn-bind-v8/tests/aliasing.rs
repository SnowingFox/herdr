//! Proof that the statistics buffers are *aliased*, not copied.
//!
//! The CLI tests show that `updateHeapStatisticsBuffer()` puts real numbers into
//! the array JavaScript sees. They cannot show that the array and the binding's
//! own handle are one allocation, because both sides go through the typed array.
//!
//! This file closes that gap by driving a bare isolate: it installs the
//! namespace, writes an element through the JavaScript typed array, and reads it
//! back through the binding's Rust accessor — then the other way round. A copy
//! in either direction would make one of those two assertions fail.

use rn_bind_v8::buffers::{
    heap_code_statistics_at, heap_space_statistics_at, heap_statistics_at,
    heap_statistics_byte_length, is_installed, HEAP_CODE_STATISTICS_LENGTH,
    HEAP_SPACE_STATISTICS_LENGTH, HEAP_STATISTICS_LENGTH,
};
use rn_bind_v8::V8;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Creates the isolate every test in this file shares.
///
/// `V8::initialize` may only run once per process, so the tests share one
/// isolate and run in sequence. They touch distinct indices, so order does not
/// matter for the values they observe.
fn with_isolate<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static INIT: std::sync::Once = std::sync::Once::new();
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

fn install<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Object> {
    let mut async_ids = AsyncIds::new();
    let mut ctx = InstallCtx {
        async_ids: &mut async_ids,
    };
    V8.install(scope, &mut ctx).expect("install")
}

fn member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> v8::Local<'s, v8::Value> {
    let key = v8::String::new(scope, name).expect("key");
    object.get(scope, key.into()).expect("member")
}

fn numeric_member<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> u32 {
    member(scope, object, name)
        .uint32_value(scope)
        .unwrap_or_else(|| panic!("{name} must be a number"))
}

#[test]
fn install_publishes_the_buffers() {
    with_isolate(|scope| {
        install(scope);
        assert!(is_installed());
        assert_eq!(
            heap_statistics_byte_length(),
            Some(HEAP_STATISTICS_LENGTH * 8)
        );
    });
}

#[test]
fn the_three_buffers_are_named_and_sized_by_the_contract() {
    with_isolate(|scope| {
        let object = install(scope);
        for (name, length) in [
            ("heapStatisticsBuffer", HEAP_STATISTICS_LENGTH),
            ("heapSpaceStatisticsBuffer", HEAP_SPACE_STATISTICS_LENGTH),
            ("heapCodeStatisticsBuffer", HEAP_CODE_STATISTICS_LENGTH),
        ] {
            let value = member(scope, object, name);
            assert!(
                value.is_float64_array(),
                "{name} must be a Float64Array, not merely a number array"
            );
            let array = v8::Local::<v8::Float64Array>::try_from(value).expect("a Float64Array");
            // `length` is elements and `byte_length` is bytes; the contract fixes
            // both, and the ratio is what proves the element width.
            assert_eq!(array.length(), length, "{name} length");
            assert_eq!(array.byte_length(), length * 8, "{name} byte length");
        }
    });
}

#[test]
fn a_typed_array_write_is_visible_through_the_rust_accessor() {
    with_isolate(|scope| {
        let object = install(scope);
        let value = member(scope, object, "heapStatisticsBuffer");
        let array = v8::Local::<v8::Float64Array>::try_from(value).expect("a Float64Array");
        let used = numeric_member(scope, object, "kUsedHeapSizeIndex") as usize;

        // JavaScript writes…
        array.set_index(scope, used as u32, v8::Number::new(scope, 4242.5).into());
        // …and Rust reads the same bytes back.
        assert_eq!(heap_statistics_at(used), Some(4242.5));
    });
}

#[test]
fn a_rust_write_lands_in_the_javascript_view() {
    with_isolate(|scope| {
        let object = install(scope);
        let value = member(scope, object, "heapStatisticsBuffer");
        let array = v8::Local::<v8::Float64Array>::try_from(value).expect("a Float64Array");
        let limit = numeric_member(scope, object, "kHeapSizeLimitIndex") as usize;

        // The buffer is only reachable from Rust after install, which is why the
        // write is expressed through the update function's own path: it is the
        // one place the binding writes without going through the typed array.
        rn_bind_v8::buffers::with_heap_statistics(|buffer| {
            assert!(buffer.set_float(limit, 8192.0));
        });

        let read = array
            .get_index(scope, limit as u32)
            .and_then(|value| value.number_value(scope));
        assert_eq!(read, Some(8192.0));
    });
}

#[test]
fn every_buffer_index_is_reachable_from_both_sides() {
    with_isolate(|scope| {
        let object = install(scope);
        let heap =
            v8::Local::<v8::Float64Array>::try_from(member(scope, object, "heapStatisticsBuffer"))
                .expect("a Float64Array");

        // Index 14 is the last element, which is where an off-by-one in the
        // length would show up as `undefined`.
        let last = HEAP_STATISTICS_LENGTH - 1;
        heap.set_index(scope, last as u32, v8::Number::new(scope, 7.0).into());
        assert_eq!(heap_statistics_at(last), Some(7.0));
        assert_eq!(heap_statistics_at(HEAP_STATISTICS_LENGTH), None);

        let space = v8::Local::<v8::Float64Array>::try_from(member(
            scope,
            object,
            "heapSpaceStatisticsBuffer",
        ))
        .expect("a Float64Array");
        space.set_index(scope, 3, v8::Number::new(scope, 3.0).into());
        assert_eq!(heap_space_statistics_at(3), Some(3.0));
        assert_eq!(heap_space_statistics_at(4), None);

        let code = v8::Local::<v8::Float64Array>::try_from(member(
            scope,
            object,
            "heapCodeStatisticsBuffer",
        ))
        .expect("a Float64Array");
        code.set_index(scope, 3, v8::Number::new(scope, 3.0).into());
        assert_eq!(heap_code_statistics_at(3), Some(3.0));
        assert_eq!(heap_code_statistics_at(4), None);
    });
}

#[test]
fn the_index_constants_point_at_the_fields_they_name() {
    with_isolate(|scope| {
        let object = install(scope);
        // Calling the update function must place the values where the constants
        // say. `used_heap_size` sits inside `total_heap_size` and the limit is
        // above both, which would break if an index were off by one.
        let key = v8::String::new(scope, "updateHeapStatisticsBuffer").expect("key");
        let update =
            v8::Local::<v8::Function>::try_from(object.get(scope, key.into()).expect("update"))
                .expect("a function");
        update
            .call(scope, object.into(), &[])
            .expect("the update call");

        let used = numeric_member(scope, object, "kUsedHeapSizeIndex") as usize;
        let total = numeric_member(scope, object, "kTotalHeapSizeIndex") as usize;
        let limit = numeric_member(scope, object, "kHeapSizeLimitIndex") as usize;
        let used = heap_statistics_at(used).expect("used heap size");
        let total = heap_statistics_at(total).expect("total heap size");
        let limit = heap_statistics_at(limit).expect("heap size limit");
        assert!(used > 0.0, "used heap size must be positive");
        assert!(used <= total, "used {used} must not exceed total {total}");
        assert!(
            total <= limit,
            "total {total} must not exceed limit {limit}"
        );
    });
}

#[test]
fn a_second_install_replaces_the_buffers_rather_than_reusing_them() {
    with_isolate(|scope| {
        let first = install(scope);
        let first_array =
            v8::Local::<v8::Float64Array>::try_from(member(scope, first, "heapStatisticsBuffer"))
                .expect("a Float64Array");
        first_array.set_index(scope, 0, v8::Number::new(scope, 1234.0).into());
        assert_eq!(heap_statistics_at(0), Some(1234.0));

        // Installing again models a second realm: the thread-local slot has to
        // point at the new buffers, not at the previous realm's memory.
        let second = install(scope);
        let second_array =
            v8::Local::<v8::Float64Array>::try_from(member(scope, second, "heapStatisticsBuffer"))
                .expect("a Float64Array");
        assert_eq!(
            heap_statistics_at(0),
            Some(0.0),
            "the new realm's buffer starts zeroed"
        );
        second_array.set_index(scope, 0, v8::Number::new(scope, 4321.0).into());
        assert_eq!(heap_statistics_at(0), Some(4321.0));
    });
}

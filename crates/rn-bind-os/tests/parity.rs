//! Checks the raw `os` binding against the values this machine really reports.
//!
//! `lib/os.js` is what turns these into `os.cpus()` and friends, but the raw
//! values are what a mismatch would show up in first, and they can be checked
//! without the JavaScript layer (which needs `options` to boot).

use rn_bind_os::Os;
use rn_core::{AsyncIds, BindingModule, InstallCtx};
use rn_v8_sys::v8;

fn with_isolate<T>(body: impl FnOnce(&mut v8::PinScope<'_, '_>) -> T) -> T {
    static INIT: std::sync::Once = std::sync::Once::new();
    let create = || {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    };
    INIT.call_once(create);

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
    Os.install(scope, &mut ctx).expect("install")
}

fn call<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> v8::Local<'s, v8::Value> {
    let key = v8::String::new(scope, name).expect("key");
    let function = v8::Local::<v8::Function>::try_from(object.get(scope, key.into()).expect("fn"))
        .expect("a function");
    function
        .call(scope, object.into(), &[])
        .expect("the call to succeed")
}

#[test]
fn hostname_matches_the_operating_system() {
    with_isolate(|scope| {
        let object = install(scope);
        let value = call(scope, object, "getHostname");
        let reported = value.to_rust_string_lossy(scope);
        let expected = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .expect("hostname file")
            .trim()
            .to_string();
        assert_eq!(reported, expected);
    });
}

#[test]
fn total_memory_matches_proc_meminfo() {
    with_isolate(|scope| {
        let object = install(scope);
        let value = call(scope, object, "getTotalMem");
        let reported = value.number_value(scope).expect("a number");
        let kib: u64 = std::fs::read_to_string("/proc/meminfo")
            .expect("meminfo")
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("MemTotal:")?;
                rest.split_whitespace().next()?.parse().ok()
            })
            .expect("MemTotal");
        assert_eq!(reported, (kib * 1024) as f64);
    });
}

#[test]
fn cpu_count_matches_the_cores_in_proc_stat() {
    with_isolate(|scope| {
        let object = install(scope);
        let value = call(scope, object, "getCPUs");
        let array = v8::Local::<v8::Array>::try_from(value).expect("an array");
        let cores = std::fs::read_to_string("/proc/stat")
            .expect("stat")
            .lines()
            .filter(|line| {
                line.strip_prefix("cpu")
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
            })
            .count();
        // Seven entries per core: model, speed, then the five time fields.
        assert_eq!(array.length() as usize, cores * 7);
    });
}

#[test]
fn load_average_fills_the_caller_array() {
    with_isolate(|scope| {
        let object = install(scope);
        let buffer = v8::ArrayBuffer::new(scope, 24);
        let array = v8::Float64Array::new(scope, buffer, 0, 3).expect("a Float64Array");
        let key = v8::String::new(scope, "getLoadAvg").expect("key");
        let function =
            v8::Local::<v8::Function>::try_from(object.get(scope, key.into()).expect("fn"))
                .expect("a function");
        function
            .call(scope, object.into(), &[array.into()])
            .expect("the call to succeed");

        // The values are written in place, so reading them back out of the
        // array is the assertion: a return value would leave them zero.
        let mut read = [0f64; 3];
        for (index, slot) in read.iter_mut().enumerate() {
            let value = array.get_index(scope, index as u32).expect("value");
            *slot = value.number_value(scope).expect("a number");
        }
        assert!(
            read.iter().any(|value| *value > 0.0),
            "load average should not be all zeroes on a running machine"
        );
    });
}

#[test]
fn user_info_reports_the_current_uid() {
    with_isolate(|scope| {
        let object = install(scope);
        let value = call(scope, object, "getUserInfo");
        let info = v8::Local::<v8::Object>::try_from(value).expect("an object");
        let key = v8::String::new(scope, "uid").expect("key");
        let uid = info
            .get(scope, key.into())
            .expect("uid")
            .number_value(scope)
            .expect("a number");
        // SAFETY: no arguments, cannot fail.
        assert_eq!(uid, unsafe { libc::getuid() } as f64);
    });
}

#[test]
fn a_failed_call_fills_the_error_context_and_returns_undefined() {
    // `lib/os.js` wraps these calls in `getCheckedFunction`, which passes a
    // fresh object and throws `ERR_SYSTEM_ERROR` when the call returns
    // undefined. Returning an error instead of filling the object would bypass
    // that and lose the errno, so the contract has to be checked directly.
    with_isolate(|scope| {
        let object = install(scope);
        let key = v8::String::new(scope, "getPriority").expect("key");
        let function =
            v8::Local::<v8::Function>::try_from(object.get(scope, key.into()).expect("fn"))
                .expect("a function");

        // A pid that cannot exist, with the context object the caller passes.
        let context = v8::Object::new(scope);
        let pid = v8::Integer::new(scope, i32::MAX);
        let result = function
            .call(scope, object.into(), &[pid.into(), context.into()])
            .expect("the call to return");

        assert!(
            result.is_undefined(),
            "a failed call must return undefined, not throw"
        );

        let read = |name: &str| {
            let key = v8::String::new(scope, name).expect("key");
            context.get(scope, key.into())
        };
        // `errno`, `code`, `message` and `syscall` are what
        // `CollectUVExceptionInfo` writes.
        let errno = read("errno").expect("errno");
        assert!(
            errno.number_value(scope).is_some(),
            "the context must carry the errno"
        );
        assert!(read("code").expect("code").is_string());
        assert!(read("syscall").expect("syscall").is_string());
        assert_eq!(
            read("syscall")
                .expect("syscall")
                .to_rust_string_lossy(scope),
            "uv_os_getpriority"
        );
    });
}

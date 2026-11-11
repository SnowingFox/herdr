//! The C ABI Node-API addons are compiled against.
//!
//! Every type here is `#[repr(C)]` and matches a typedef in Node's
//! `src/js_native_api_types.h` at the pinned revision. An addon is compiled
//! against that header, so getting one of these layouts wrong is not a Rust
//! type error — it is a misinterpreted pointer inside an addon's own stack
//! frame, which is why the layouts are asserted by tests in `abi_tests.rs`
//! rather than trusted.
//!
//! The header is the authority; this module names it. Where Node's header uses
//! a typedef the comment quotes the declaration so a later change can be
//! checked against the real thing.

use std::ffi::{c_void, CStr};

/// `typedef struct napi_env__* napi_env;`
#[repr(C)]
pub struct NapiEnv {
    _private: [u8; 0],
}

/// `typedef struct napi_value__* napi_value;`
///
/// Node stores a `v8::Local<v8::Value>` in this pointer slot: `napi_value` is
/// the address of the handle, which is exactly what V8's `Local` is (rusty_v8
/// models it as a `#[repr(C)]` newtype over `NonNull<T>`). So a `napi_value`
/// crosses the boundary as the `Local`'s pointer and no translation table is
/// needed — see `values.rs`.
#[repr(C)]
pub struct NapiValue {
    _private: [u8; 0],
}

/// `typedef struct napi_ref__* napi_ref;`
#[repr(C)]
pub struct NapiRef {
    _private: [u8; 0],
}

/// `typedef struct napi_callback_info__* napi_callback_info;`
///
/// Node's `napi_callback_info` is a `v8impl::FunctionCallbackWrapper*`, a
/// stack object V8 points at for the duration of the callback. rustnode passes
/// a pointer to its own `CallbackFrame` in that role.
#[repr(C)]
pub struct NapiCallbackInfo {
    _private: [u8; 0],
}

/// `typedef struct napi_deferred__* napi_deferred;`
#[repr(C)]
pub struct NapiDeferred {
    _private: [u8; 0],
}

/// `typedef struct napi_handle_scope__* napi_handle_scope;`
#[repr(C)]
pub struct NapiHandleScope {
    _private: [u8; 0],
}

/// `typedef struct napi_escapable_handle_scope__* napi_escapable_handle_scope;`
#[repr(C)]
pub struct NapiEscapableHandleScope {
    _private: [u8; 0],
}

/// `napi_typedarray_type`, in declaration order.
///
/// The integers are ABI: an addon passes the literal, so a reordering silently
/// changes which element size it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum NapiTypedarrayType {
    Int8 = 0,
    Uint8 = 1,
    Uint8Clamped = 2,
    Int16 = 3,
    Uint16 = 4,
    Int32 = 5,
    Uint32 = 6,
    Float32 = 7,
    Float64 = 8,
    BigInt64 = 9,
    BigUint64 = 10,
    Float16 = 11,
}

/// `typedef struct napi_async_work__* napi_async_work;`
#[repr(C)]
pub struct NapiAsyncWork {
    _private: [u8; 0],
}

/// `typedef struct napi_threadsafe_function__* napi_threadsafe_function;`
#[repr(C)]
pub struct NapiThreadsafeFunction {
    _private: [u8; 0],
}

/// `napi_threadsafe_function_release_mode`, in declaration order.
///
/// The integers are ABI: `napi_tsfn_release` is 0 and `napi_tsfn_abort` is 1, and
/// an addon passes the literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum NapiThreadsafeFunctionReleaseMode {
    Release = 0,
    Abort = 1,
}

/// `napi_threadsafe_function_call_mode`, in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum NapiThreadsafeFunctionCallMode {
    Nonblocking = 0,
    Blocking = 1,
}

/// `typedef napi_value (NAPI_CDECL* napi_callback)(napi_env, napi_callback_info)`
pub type NapiCallback =
    Option<unsafe extern "C" fn(env: *mut NapiEnv, info: *mut NapiCallbackInfo) -> *mut NapiValue>;

/// `typedef void (NAPI_CDECL* napi_cleanup_hook)(void* arg)`
///
/// Unlike a finalizer this takes no environment: it runs when the environment is
/// already being torn down, so there is nothing left to call into.
pub type NapiCleanupHook = Option<unsafe extern "C" fn(arg: *mut c_void)>;

/// `typedef void (NAPI_CDECL* napi_async_execute_callback)(napi_env, void*)`
///
/// Runs on a thread-pool thread, so it must not touch JavaScript.
pub type NapiAsyncExecuteCallback =
    Option<unsafe extern "C" fn(env: *mut NapiEnv, data: *mut c_void)>;

/// `typedef void (NAPI_CDECL* napi_async_complete_callback)(napi_env, napi_status, void*)`
///
/// Runs on the loop's thread, after `napi_async_execute_callback`.
pub type NapiAsyncCompleteCallback =
    Option<unsafe extern "C" fn(env: *mut NapiEnv, status: NapiStatus, data: *mut c_void)>;

/// `typedef void (NAPI_CDECL* napi_threadsafe_function_call_js)(napi_env, napi_value, void*, void*)`
///
/// May receive a null env and a null callback when the queue is drained during
/// teardown, which is how an addon learns its values will never reach JavaScript.
pub type NapiThreadsafeFunctionCallJs = Option<
    unsafe extern "C" fn(
        env: *mut NapiEnv,
        js_callback: *mut NapiValue,
        context: *mut c_void,
        data: *mut c_void,
    ),
>;

/// `typedef void (NAPI_CDECL* napi_finalize)(napi_env, void*, void*)`
pub type NapiFinalize =
    Option<unsafe extern "C" fn(env: *mut NapiEnv, data: *mut c_void, hint: *mut c_void)>;

/// `napi_status`, in declaration order.
///
/// The integer values are the ABI: an addon compares against `napi_ok` and
/// `napi_pending_exception` itself. `abi_tests.rs` pins every discriminant and
/// the total count so a reordering cannot slip through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum NapiStatus {
    Ok = 0,
    InvalidArg = 1,
    ObjectExpected = 2,
    StringExpected = 3,
    NameExpected = 4,
    FunctionExpected = 5,
    NumberExpected = 6,
    BooleanExpected = 7,
    ArrayExpected = 8,
    GenericFailure = 9,
    PendingException = 10,
    Cancelled = 11,
    EscapeCalledTwice = 12,
    HandleScopeMismatch = 13,
    CallbackScopeMismatch = 14,
    QueueFull = 15,
    Closing = 16,
    BigintExpected = 17,
    DateExpected = 18,
    ArrayBufferExpected = 19,
    DetachableArraybufferExpected = 20,
    WouldDeadlock = 21,
    NoExternalBuffersAllowed = 22,
    /// Added after `WouldDeadlock`; `src/js_native_api_types.h` ends with it.
    CannotRunJs = 23,
}

impl NapiStatus {
    /// The message Node pairs with each status in `napi_get_last_error_info`.
    ///
    /// Copied from the `error_messages` table in `src/js_native_api_v8.cc`
    /// because `napi_get_last_error_info` is how an addon turns a failed call into
    /// the text it throws, and Node's own tests assert on that text.
    pub fn message(self) -> &'static str {
        // SAFETY: the string is owned by `CStr`'s `to_str`, which is `'static`
        // because the literal is.
        self.message_cstr().to_str().unwrap_or("")
    }

    /// The same text as a NUL-terminated `'static` C string.
    ///
    /// This is what `napi_extended_error_info.error_message` must point at. Node's
    /// table is `static const char* error_messages[]`, so an addon's
    /// `GET_AND_THROW_LAST_ERROR` can save the pointer, make another Node-API call
    /// (which clears the last error), and still read the text. A heap `CString`
    /// freed by that clear would dangle, and the addon would throw garbage — which
    /// is exactly what happened before this became a static.
    pub fn message_cstr(self) -> &'static CStr {
        match self {
            Self::Ok => c"",
            Self::InvalidArg => c"Invalid argument",
            Self::ObjectExpected => c"An object was expected",
            Self::StringExpected => c"A string was expected",
            Self::NameExpected => c"A string or symbol was expected",
            Self::FunctionExpected => c"A function was expected",
            Self::NumberExpected => c"A number was expected",
            Self::BooleanExpected => c"A boolean was expected",
            Self::ArrayExpected => c"An array was expected",
            Self::GenericFailure => c"Unknown failure",
            Self::PendingException => c"An exception is pending",
            Self::Cancelled => c"The async work item was cancelled",
            Self::EscapeCalledTwice => c"napi_escape_handle already called on scope",
            Self::HandleScopeMismatch => c"Invalid handle scope usage",
            Self::CallbackScopeMismatch => c"Invalid callback scope usage",
            Self::QueueFull => c"Thread-safe function queue is full",
            Self::Closing => c"Thread-safe function handle is closing",
            Self::BigintExpected => c"A bigint was expected",
            Self::DateExpected => c"A date was expected",
            Self::ArrayBufferExpected => c"An arraybuffer was expected",
            Self::DetachableArraybufferExpected => c"A detachable arraybuffer was expected",
            Self::WouldDeadlock => c"Main thread would deadlock",
            Self::NoExternalBuffersAllowed => c"External buffers are not allowed",
            Self::CannotRunJs => c"Cannot run JavaScript",
        }
    }
}

/// `napi_valuetype`, the `typeof`-shaped classification `napi_typeof` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum NapiValueType {
    Undefined = 0,
    Null = 1,
    Boolean = 2,
    Number = 3,
    String = 4,
    Symbol = 5,
    Object = 6,
    Function = 7,
    External = 8,
    Bigint = 9,
}

/// `napi_property_attributes`.
///
/// Values are bit flags an addon ORs together, so the repr is `u32` and not an
/// enum: an addon may legitimately pass a combination this crate has no name
/// for.
pub mod property_attributes {
    pub const DEFAULT: u32 = 0;
    pub const WRITABLE: u32 = 1 << 0;
    pub const ENUMERABLE: u32 = 1 << 1;
    pub const CONFIGURABLE: u32 = 1 << 2;
    /// Marks a `napi_define_class` property as static rather than instance.
    pub const STATIC: u32 = 1 << 10;
    /// `napi_writable | napi_configurable`, the default for class methods.
    pub const DEFAULT_METHOD: u32 = WRITABLE | CONFIGURABLE;
    /// `napi_writable | napi_enumerable | napi_configurable`.
    pub const DEFAULT_JSPROPERTY: u32 = WRITABLE | ENUMERABLE | CONFIGURABLE;
}

/// `napi_property_descriptor`.
///
/// One of `utf8name` and `name` is null; exactly one of `method`, `getter`,
/// `setter` and `value` is set. The struct is passed by pointer into
/// `napi_define_properties`, so its field order and size are ABI.
#[repr(C)]
pub struct NapiPropertyDescriptor {
    pub utf8name: *const std::os::raw::c_char,
    pub name: *mut NapiValue,
    pub method: NapiCallback,
    pub getter: NapiCallback,
    pub setter: NapiCallback,
    pub value: *mut NapiValue,
    pub attributes: u32,
    pub data: *mut c_void,
}

/// `napi_extended_error_info`, returned by `napi_get_last_error_info`.
///
/// An addon casts the returned pointer and reads `error_message` and
/// `error_code`; both must be populated for the same lifetime V8 keeps the
/// environment alive, which is why `Env` owns one of these.
#[repr(C)]
pub struct NapiExtendedErrorInfo {
    pub error_message: *const std::os::raw::c_char,
    pub engine_reserved: *mut c_void,
    pub engine_error_code: u32,
    pub error_code: NapiStatus,
}

/// `napi_node_version`, returned by `napi_get_node_version`.
#[repr(C)]
pub struct NapiNodeVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub release: *const std::os::raw::c_char,
}

/// The `napi_addon_register_func` an addon exports as
/// `napi_register_module_v1`.
pub type NapiAddonRegisterFunc =
    Option<unsafe extern "C" fn(env: *mut NapiEnv, exports: *mut NapiValue) -> *mut NapiValue>;

/// `node_api_addon_get_api_version_func`, the optional
/// `node_api_module_get_api_version_v1` companion export.
pub type NapiAddonGetApiVersionFunc = Option<unsafe extern "C" fn() -> i32>;

/// The `NAPI_MODULE_VERSION` that forms the entry-point symbol name.
pub const NAPI_MODULE_VERSION: i32 = 1;

/// The symbol every `NAPI_MODULE_INIT()` addon exports.
///
/// `NAPI_MODULE_INITIALIZER` expands to `napi_register_module_v` ##
/// `NAPI_MODULE_VERSION`, so the literal name is `napi_register_module_v1`.
pub const REGISTER_MODULE_SYMBOL: &str = "napi_register_module_v1";

/// The optional companion symbol an addon exports to declare the Node-API
/// version it was built for (`NODE_API_MODULE_GET_API_VERSION`).
pub const GET_API_VERSION_SYMBOL: &str = "node_api_module_get_api_version_v1";

/// The legacy self-registration entry point, from `node.h`:
/// `node_register_module_v<NODE_MODULE_VERSION>`.
///
/// `NODE_MODULE_VERSION` at the pin is 153. An addon built for any other ABI
/// version exports a different symbol, which is how Node distinguishes "did not
/// self-register" from "compiled against a different runtime".
pub const LEGACY_MODULE_VERSION: i32 = 153;

/// `NODE_API_SUPPORTED_VERSION_MAX` at the pin, from `src/node_version.h`.
pub const NAPI_SUPPORTED_VERSION_MAX: i32 = 10;

/// `NODE_API_SUPPORTED_VERSION_MIN` at the pin.
pub const NAPI_SUPPORTED_VERSION_MIN: i32 = 1;

/// `NODE_API_DEFAULT_MODULE_API_VERSION`: what an addon gets when it does not
/// export `node_api_module_get_api_version_v1`.
pub const NAPI_DEFAULT_MODULE_API_VERSION: i32 = 8;

/// The Node major/minor/patch this runtime reports through
/// `napi_get_node_version`, matching `src/node_version.h` at the pin and
/// `process.version`.
pub const NODE_MAJOR_VERSION: u32 = 28;
pub const NODE_MINOR_VERSION: u32 = 0;
pub const NODE_PATCH_VERSION: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_discriminants_match_the_header() {
        // Pinned against `src/js_native_api_types.h` at the pin. An addon
        // compares these integers, so a reordering is an ABI break that
        // compiles cleanly.
        let expected = [
            (NapiStatus::Ok, 0),
            (NapiStatus::InvalidArg, 1),
            (NapiStatus::ObjectExpected, 2),
            (NapiStatus::StringExpected, 3),
            (NapiStatus::NameExpected, 4),
            (NapiStatus::FunctionExpected, 5),
            (NapiStatus::NumberExpected, 6),
            (NapiStatus::BooleanExpected, 7),
            (NapiStatus::ArrayExpected, 8),
            (NapiStatus::GenericFailure, 9),
            (NapiStatus::PendingException, 10),
            (NapiStatus::Cancelled, 11),
            (NapiStatus::EscapeCalledTwice, 12),
            (NapiStatus::HandleScopeMismatch, 13),
            (NapiStatus::CallbackScopeMismatch, 14),
            (NapiStatus::QueueFull, 15),
            (NapiStatus::Closing, 16),
            (NapiStatus::BigintExpected, 17),
            (NapiStatus::DateExpected, 18),
            (NapiStatus::ArrayBufferExpected, 19),
            (NapiStatus::DetachableArraybufferExpected, 20),
            (NapiStatus::WouldDeadlock, 21),
            (NapiStatus::NoExternalBuffersAllowed, 22),
            (NapiStatus::CannotRunJs, 23),
        ];
        for (status, value) in expected {
            assert_eq!(status as i32, value, "{status:?}");
        }
    }

    #[test]
    fn every_status_has_a_message_except_ok() {
        // `napi_get_last_error_info` hands the message to the addon, and
        // Node's `GET_AND_THROW_LAST_ERROR` throws it. An empty message for a
        // real failure would produce `Error: ` with no text.
        for status in [
            NapiStatus::InvalidArg,
            NapiStatus::ObjectExpected,
            NapiStatus::StringExpected,
            NapiStatus::NameExpected,
            NapiStatus::FunctionExpected,
            NapiStatus::NumberExpected,
            NapiStatus::BooleanExpected,
            NapiStatus::ArrayExpected,
            NapiStatus::GenericFailure,
            NapiStatus::PendingException,
            NapiStatus::Cancelled,
            NapiStatus::EscapeCalledTwice,
            NapiStatus::HandleScopeMismatch,
            NapiStatus::CallbackScopeMismatch,
            NapiStatus::QueueFull,
            NapiStatus::Closing,
            NapiStatus::BigintExpected,
            NapiStatus::DateExpected,
            NapiStatus::ArrayBufferExpected,
            NapiStatus::DetachableArraybufferExpected,
            NapiStatus::WouldDeadlock,
            NapiStatus::NoExternalBuffersAllowed,
            NapiStatus::CannotRunJs,
        ] {
            assert!(!status.message().is_empty(), "{status:?} has no message");
        }
    }

    #[test]
    fn thread_safe_function_mode_discriminants_match_the_header() {
        // `napi_threadsafe_function_release_mode` is `{release, abort}` and
        // `napi_threadsafe_function_call_mode` is `{nonblocking, blocking}`. An
        // addon passes these as plain integers, so the order is the ABI.
        assert_eq!(NapiThreadsafeFunctionReleaseMode::Release as i32, 0);
        assert_eq!(NapiThreadsafeFunctionReleaseMode::Abort as i32, 1);
        assert_eq!(NapiThreadsafeFunctionCallMode::Nonblocking as i32, 0);
        assert_eq!(NapiThreadsafeFunctionCallMode::Blocking as i32, 1);
    }

    #[test]
    fn the_async_callback_types_have_the_headers_shapes() {
        // `napi_async_complete_callback` carries a `napi_status` by value, which
        // is a C enum and therefore an `int`. A Rust enum with a narrower
        // discriminant would shift every later argument.
        assert_eq!(
            std::mem::size_of::<NapiStatus>(),
            std::mem::size_of::<std::os::raw::c_int>(),
            "napi_status is passed by value into complete callbacks"
        );
        // The mode enums are likewise passed by value.
        assert_eq!(
            std::mem::size_of::<NapiThreadsafeFunctionCallMode>(),
            std::mem::size_of::<std::os::raw::c_int>(),
        );
        assert_eq!(
            std::mem::size_of::<NapiThreadsafeFunctionReleaseMode>(),
            std::mem::size_of::<std::os::raw::c_int>(),
        );
    }

    #[test]
    fn value_type_discriminants_match_the_header() {
        // `napi_typeof` results are compared by addons against these names.
        assert_eq!(NapiValueType::Undefined as i32, 0);
        assert_eq!(NapiValueType::Null as i32, 1);
        assert_eq!(NapiValueType::Boolean as i32, 2);
        assert_eq!(NapiValueType::Number as i32, 3);
        assert_eq!(NapiValueType::String as i32, 4);
        assert_eq!(NapiValueType::Symbol as i32, 5);
        assert_eq!(NapiValueType::Object as i32, 6);
        assert_eq!(NapiValueType::Function as i32, 7);
        assert_eq!(NapiValueType::External as i32, 8);
        assert_eq!(NapiValueType::Bigint as i32, 9);
    }

    #[test]
    fn property_descriptor_layout_matches_the_header() {
        // The real check: compile a C translation unit against the pinned header and
        // ask it for the size, then compare. Arithmetic on the field list is what got
        // this wrong the first time (the `attributes` u32 is followed by four bytes of
        // padding before the `data` pointer).
        let expected = c_sizeof("napi_property_descriptor");
        assert_eq!(
            std::mem::size_of::<NapiPropertyDescriptor>(),
            expected,
            "napi_property_descriptor must be the header's size"
        );
        let expected = c_sizeof("napi_extended_error_info");
        assert_eq!(
            std::mem::size_of::<NapiExtendedErrorInfo>(),
            expected,
            "napi_extended_error_info must be the header's size"
        );
        let expected = c_sizeof("napi_node_version");
        assert_eq!(
            std::mem::size_of::<NapiNodeVersion>(),
            expected,
            "napi_node_version must be the header's size"
        );
    }

    /// `sizeof(type)` as the C compiler computes it, from the pinned header.
    ///
    /// Compiling a probe rather than hardcoding a number is what makes this a check of
    /// the layout instead of a restatement of it.
    fn c_sizeof(type_name: &str) -> usize {
        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/addon");
        let source = format!(
            "#define NAPI_VERSION 9\n\
             #include <node_api.h>\n\
             #include <stdio.h>\n\
             int main(void) {{ printf(\"%zu\", sizeof({type_name})); return 0; }}\n"
        );
        let scratch = std::env::temp_dir().join(format!(
            "rn-napi-sizeof-{}-{:?}-{type_name}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&scratch).expect("mkdir");
        let source_path = scratch.join("probe.c");
        std::fs::write(&source_path, source).expect("write probe");
        let binary = scratch.join("probe");
        let compiled = std::process::Command::new("cc")
            .arg("-I")
            .arg(&directory)
            .arg("-o")
            .arg(&binary)
            .arg(&source_path)
            .output()
            .expect("cc must run");
        assert!(
            compiled.status.success(),
            "the probe must compile for {type_name}: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let output = std::process::Command::new(&binary)
            .output()
            .expect("the probe must run");
        let _ = std::fs::remove_dir_all(&scratch);
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("sizeof prints a number")
    }

    #[test]
    fn node_version_matches_process_version() {
        // `napi_get_node_version` must agree with `process.version`, which the
        // CLI reports from this same constant through the pinned tree.
        assert_eq!(
            format!("v{NODE_MAJOR_VERSION}.{NODE_MINOR_VERSION}.{NODE_PATCH_VERSION}"),
            "v28.0.0"
        );
    }

    #[test]
    fn entry_point_symbol_names_are_the_macro_expansions() {
        // `NAPI_MODULE_INITIALIZER_BASE` is `napi_register_module_v`, and
        // `NAPI_MODULE_INITIALIZER` appends `NAPI_MODULE_VERSION` (1).
        assert_eq!(REGISTER_MODULE_SYMBOL, "napi_register_module_v1");
        assert_eq!(NAPI_MODULE_VERSION, 1);
        assert_eq!(GET_API_VERSION_SYMBOL, "node_api_module_get_api_version_v1");
        assert_eq!(LEGACY_MODULE_VERSION, 153);
    }
}

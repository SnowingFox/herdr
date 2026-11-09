/// Node-API entry points exported from the binary for addon linkage.
pub const EXPORTED_SYMBOLS: &[&str] = &[
    "napi_module_register",
    "napi_get_last_error_info",
    "napi_throw",
    "napi_create_object",
    "napi_get_undefined",
    "napi_get_null",
    "napi_get_boolean",
    "napi_create_number",
    "napi_create_string_utf8",
];

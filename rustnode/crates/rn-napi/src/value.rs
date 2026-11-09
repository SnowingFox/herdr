/// Opaque handle shape addons see. Real handles wrap V8 values once the
/// isolate integration lands.
#[repr(C)]
pub struct NapiValue {
    pub raw: *mut std::ffi::c_void,
}

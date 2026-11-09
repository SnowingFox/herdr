//! Node-API. Symbol names and signatures are dictated by the headers in the
//! pinned Node checkout, so `require()` of a prebuilt `.node` addon works.

pub mod symbols;
pub mod value;

/// napi_status codes, from `deps/v8`-adjacent `node_api_types.h`.
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
}

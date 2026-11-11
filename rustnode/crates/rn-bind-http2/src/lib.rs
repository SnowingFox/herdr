//! `internalBinding('http2')` for rustnode.
//!
//! `vendor/libnode-js/lib/internal/http2/core.js` is unchanged Node code and it
//! is the specification for this crate's shape. At module scope it does three
//! things, and all three have to work for `require('node:http2')` to load at all:
//!
//! ```text
//! const binding = internalBinding('http2');
//! const { constants, nameForErrorCode } = binding;
//! const { kBitfield, kSessionPriorityListenerCount, ... } = binding;
//! ...
//! binding.setCallbackFunctions(fn, fn, ... eleven functions);
//! ```
//!
//! `lib/internal/http2/util.js` adds a fourth: it destructures `settingsBuffer`,
//! `optionsBuffer`, `sessionState` and `streamState` at module scope, and
//! `getDefaultSettings` calls `binding.refreshDefaultSettings()` on demand.
//!
//! # The surface is bigger than the contract
//!
//! `contracts/http2.json` records 24 members, and the recorded `constants`
//! property list is 254 entries. That file is the floor. `Initialize` in
//! `src/node_http2.cc` also installs five prototype-bearing classes
//! (`Http2Session`, `Http2Stream`, plus the `Http2Ping`/`Http2Settings` templates
//! `lib/**` never constructs directly), and the methods on those prototypes are
//! the real work: `origin`, `altsvc`, `ping`, `consume`, `receive`, `destroy`,
//! `goaway`, `hasPendingData`, `settings`, `request`, `setNextStreamID`,
//! `setLocalWindowSize`, `updateChunksSent`, `refreshState`, `localSettings`,
//! `remoteSettings`, `setGracefulClose`.
//!
//! # Increment 1: everything except the two classes
//!
//! This commit installs every member of the namespace that does not require a
//! live nghttp2 session: the complete `constants` table, `nameForErrorCode`, the
//! six shared typed arrays, the ten `k*` field indices, `nghttp2ErrorString`,
//! `packSettings`, `refreshDefaultSettings` and `setCallbackFunctions`. That is
//! enough for `require('node:http2')` to load and for
//! `http2.constants`/`http2.getDefaultSettings`/`http2.getPackedSettings` to
//! answer correctly, which converts the whole `test-http2*` family from a load
//! failure into behaviour that can be measured.
//!
//! [`DEFERRED`] names the two members still missing and why. They are absent
//! rather than stubbed, so the contract check reports a known gap instead of a
//! member that exists and lies.
//!
//! # nghttp2 linkage
//!
//! `vendor/nghttp2` is nghttp2 1.70.0 copied byte-identical from `deps/nghttp2`
//! at the pin, compiled by `build.rs` with the flags `nghttp2.gyp` uses.
//! `vendor/nghttp2/README.md` records the reasoning and `tools/verify-nghttp2.sh`
//! holds the tree to the pinned revision. `process.versions.nghttp2` is read from
//! the linked library rather than copied from the pin, so the published version is
//! always the code the binary actually runs.

pub mod callbacks;
pub mod constants;
pub mod errors;
pub mod ffi;
pub mod headers;
pub mod options;
pub mod session;
pub mod session_handle;
pub mod settings;
pub mod state;
pub mod stream;

use std::cell::RefCell;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/http2.json`
/// except for the two declared in [`DEFERRED`].
pub const MEMBERS: &[&str] = &[
    "Http2Session",
    "Http2Stream",
    "constants",
    "kBitfield",
    "kSessionFrameErrorListenerCount",
    "kSessionHasAltsvcListeners",
    "kSessionHasPingListeners",
    "kSessionHasRemoteSettingsListeners",
    "kSessionMaxInvalidFrames",
    "kSessionMaxRejectedStreams",
    "kSessionPriorityListenerCount",
    "kSessionRemoteSettingsIsUpToDate",
    "kSessionUint8FieldCount",
    "nameForErrorCode",
    "nghttp2ErrorString",
    "optionsBuffer",
    "packSettings",
    "refreshDefaultSettings",
    "sessionState",
    "sessionStats",
    "setCallbackFunctions",
    "settingsBuffer",
    "streamState",
    "streamStats",
];

/// Members this namespace needs but cannot install yet.
///
/// Empty: every member `contracts/http2.json` records is installed. The two
/// classes this list used to hold are real constructors now, so a declared deferral
/// here would be a lie of the kind `rn-compat` cannot catch.
pub const DEFERRED: &[(&str, &str)] = &[];

/// Known gaps that are not contract members, so `rn-compat` cannot express them.
///
/// `DEFERRED` is for a *member* that is absent. These are behaviours inside
/// members that are present, which is why they are recorded separately rather than
/// smuggled into the member list.
pub const KNOWN_GAPS: &[(&str, &str)] = &[
    (
        "the readable side never emits 'end'",
        "`on_stream_close` is the only thing that can end a stream's readable \
         side, and nghttp2 does not deliver it while the outbound side still has \
         an open DATA provider — so on a client stream the response body arrives \
         and `'end'` never does. `core.js` gates every cleanup path on \
         `_readableState.ended`, so the session is never destroyed, its socket \
         stays ref'd and the process cannot exit. This is the 90 timeouts and it \
         is *one* bug, not a family: it needs the provider to report EOF through \
         `StreamBase` rather than from the pending queue, which is where the \
         pull/pause protocol has to come from",
    ),
    (
        "socket teardown on destroy()",
        "`Http2Session.destroy()` calls `this.ondone` (finishSessionClose) and the \
         nghttp2 session is freed, but the consumed socket's libuv handle is not \
         closed, so a process that destroys a session with a live connection does \
         not drain its loop. Closing another binding's handle from here would \
         free state its owner still holds, so this waits for the same provider \
         work as the entry above",
    ),
];

/// `SessionUint8Fields` from `node_http2.h`, as the offsets of `SessionJSFields`.
///
/// `lib/internal/http2/core.js` uses them to index a `Uint8Array(12)` it keeps as
/// `kNativeFields`, and reads `kSessionMaxInvalidFrames` and
/// `kSessionMaxRejectedStreams` back out through a `Uint32Array` over the same
/// buffer. The numbers are `offsetof`, so `bitfield` is 0 while
/// `max_invalid_frames` is 4 and `max_rejected_streams` is 8.
pub const K_BITFIELD: i32 = 0;
/// `kSessionPriorityListenerCount`, `offsetof(.., priority_listener_count)`.
pub const K_SESSION_PRIORITY_LISTENER_COUNT: i32 = 1;
/// `kSessionFrameErrorListenerCount`, `offsetof(.., frame_error_listener_count)`.
pub const K_SESSION_FRAME_ERROR_LISTENER_COUNT: i32 = 2;
/// `kSessionMaxInvalidFrames`, `offsetof(.., max_invalid_frames)`.
pub const K_SESSION_MAX_INVALID_FRAMES: i32 = 4;
/// `kSessionMaxRejectedStreams`, `offsetof(.., max_rejected_streams)`.
pub const K_SESSION_MAX_REJECTED_STREAMS: i32 = 8;
/// `kSessionUint8FieldCount`, `sizeof(SessionJSFields)`.
///
/// 12 rather than 11: `max_rejected_streams` ends at byte 12 and the `uint8_t`
/// fields before it only fill three bytes, so the `uint32_t` alignment pads
/// `max_invalid_frames` to offset 4.
pub const K_SESSION_UINT8_FIELD_COUNT: i32 = 12;

/// `internalBinding('http2')`.
pub struct Http2;

impl BindingModule for Http2 {
    fn namespace(&self) -> &'static str {
        "http2"
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

        // The shared typed arrays first, then the field indices into
        // `kNativeFields`. `Initialize` installs them in this order and the order
        // is not observable, but keeping it means a diff against `node_http2.cc`
        // lines up.
        state::Http2State::ensure(scope)?;
        let arrays = state::Http2State::with(|state| state.arrays(scope))?;
        for (name, value) in arrays {
            set(scope, object, name, value)?;
        }

        let indices = [
            ("kBitfield", K_BITFIELD),
            (
                "kSessionPriorityListenerCount",
                K_SESSION_PRIORITY_LISTENER_COUNT,
            ),
            (
                "kSessionFrameErrorListenerCount",
                K_SESSION_FRAME_ERROR_LISTENER_COUNT,
            ),
            ("kSessionMaxInvalidFrames", K_SESSION_MAX_INVALID_FRAMES),
            ("kSessionMaxRejectedStreams", K_SESSION_MAX_REJECTED_STREAMS),
            ("kSessionUint8FieldCount", K_SESSION_UINT8_FIELD_COUNT),
            (
                "kSessionHasRemoteSettingsListeners",
                constants::HAS_REMOTE_SETTINGS_LISTENERS,
            ),
            (
                "kSessionRemoteSettingsIsUpToDate",
                constants::REMOTE_SETTINGS_IS_UP_TO_DATE,
            ),
            ("kSessionHasPingListeners", constants::HAS_PING_LISTENERS),
            (
                "kSessionHasAltsvcListeners",
                constants::HAS_ALTSVC_LISTENERS,
            ),
        ];
        for (name, value) in indices {
            set(scope, object, name, v8::Integer::new(scope, value).into())?;
        }

        // `nameForErrorCode` is a plain `Array`, and `core.js` reads it by
        // numeric index only.
        let names: Vec<v8::Local<'_, v8::Value>> = constants::ERROR_CODE_NAMES
            .iter()
            .map(|name| {
                v8::String::new(scope, name)
                    .map(|value| value.into())
                    .unwrap_or_else(|| v8::undefined(scope).into())
            })
            .collect();
        let name_for_error_code = v8::Array::new_with_elements(scope, &names);
        set(
            scope,
            object,
            "nameForErrorCode",
            name_for_error_code.into(),
        )?;

        let functions: [(&str, v8::Local<'_, v8::Function>); 4] = [
            (
                "nghttp2ErrorString",
                function(scope, "nghttp2ErrorString", nghttp2_error_string)?,
            ),
            (
                "refreshDefaultSettings",
                function(scope, "refreshDefaultSettings", refresh_default_settings)?,
            ),
            (
                "packSettings",
                function(scope, "packSettings", pack_settings)?,
            ),
            (
                "setCallbackFunctions",
                function(scope, "setCallbackFunctions", set_callback_functions)?,
            ),
        ];
        for (name, value) in functions {
            set(scope, object, name, value.into())?;
        }

        // The two classes. `Http2Session` is constructed by `core.js`; the
        // `Http2Stream` constructor is installed because `Initialize` installs it,
        // and `core.js` receives stream handles rather than making them.
        let session = session_handle::constructor(scope)?;
        set(scope, object, "Http2Session", session)?;
        let stream = stream::constructor(scope)?;
        set(scope, object, "Http2Stream", stream)?;

        // `target->Set(context, env->constants_string(), constants)`, which is a
        // normal (writable) property holding an object whose own properties are
        // read-only.
        let constants = constants_object(scope)?;
        set(scope, object, "constants", constants.into())?;

        Ok(object)
    }
}

/// `STREAM_OPTION_EMPTY_PAYLOAD` from `node_http2.h`.
pub const STREAM_OPTION_EMPTY_PAYLOAD: i32 = 0x1;
/// `STREAM_OPTION_GET_TRAILERS`.
pub const STREAM_OPTION_GET_TRAILERS: i32 = 0x2;
/// `STREAM_OPTION_AUTO_EMPTY_TRAILERS`.
pub const STREAM_OPTION_AUTO_EMPTY_TRAILERS: i32 = 0x4;

/// `kSessionMaxInvalidFrames`'s default from `SessionJSFields`.
///
/// `core.js` copies this into `kNativeFields` so a caller can raise it per
/// session; the value here is what an untouched field contains.
pub const MAX_INVALID_FRAMES: u32 = 1000;
/// `kSessionMaxRejectedStreams`'s default.
pub const MAX_REJECTED_STREAMS: u32 = 100;

/// The live nghttp2 session behind a session state.
pub(crate) fn session_ptr(state: &session::SessionState) -> Option<*mut ffi::nghttp2_session> {
    session::raw(state)
}

/// The `Http2Session` JS object a callback reports to, which is `this` in
/// `core.js`'s handlers.
pub(crate) fn session_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    state: &session::SessionState,
) -> Option<v8::Local<'s, v8::Object>> {
    state
        .object
        .borrow()
        .as_ref()
        .map(|object| v8::Local::new(scope, object))
}

/// Reads the eleven installed callbacks.
pub(crate) fn with_callbacks<R>(body: impl FnOnce(&SessionCallbacks) -> R) -> R {
    CALLBACKS.with(|callbacks| body(&callbacks.borrow()))
}

/// Registers the `http2` namespace with the runtime.
///
/// `tools/regen-bindings.sh` discovers this function, so nothing else has to be
/// edited for `internalBinding('http2')` to resolve.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Http2);
}

/// The nghttp2 version this binary links, from `nghttp2_version`.
///
/// `process.versions.nghttp2` is built from this. Reporting the pin's number
/// without checking the library would be a claim about code that may not be
/// there; this reads the version out of the linked object file, so a re-pin that
/// forgot to refresh the vendored tree reports the tree it actually compiled.
pub fn version() -> Option<String> {
    // SAFETY: `nghttp2_version(0)` always returns a pointer to a static struct.
    let info = unsafe { ffi::nghttp2_version(0) };
    if info.is_null() {
        return None;
    }
    // SAFETY: the pointer is non-null and its `version_str` is static text.
    let text = unsafe { (*info).version_str };
    if text.is_null() {
        return None;
    }
    // SAFETY: static NUL-terminated text.
    let text = unsafe { std::ffi::CStr::from_ptr(text) };
    text.to_str().ok().map(str::to_string)
}

/// Builds the `constants` object with `Initialize`'s three attribute classes.
fn constants_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    // `PropertyAttribute` is not `Copy`, so each use below reads `enumerable()`
    // rather than moving a binding.
    let enumerable = || v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE;
    // `DontEnum` on top of the above, for `HTTP2_HIDDEN_CONSTANTS`.
    let hidden = || enumerable() | v8::PropertyAttribute::DONT_ENUM;

    for (name, value) in constants::HIDDEN {
        define(
            scope,
            object,
            name,
            v8::Number::new(scope, *value).into(),
            hidden(),
        )?;
    }
    for (name, value) in constants::NUMBERS {
        define(
            scope,
            object,
            name,
            v8::Number::new(scope, *value).into(),
            enumerable(),
        )?;
    }
    for (name, value) in constants::HEADERS {
        let value = v8::String::new(scope, value)
            .ok_or_else(|| format!("cannot allocate the value of {name}"))?;
        define(scope, object, name, value.into(), enumerable())?;
    }
    for (name, value) in constants::METHODS {
        let value = v8::String::new(scope, value)
            .ok_or_else(|| format!("cannot allocate the value of {name}"))?;
        define(scope, object, name, value.into(), enumerable())?;
    }
    for (name, value) in constants::STATUS_CODES {
        define(
            scope,
            object,
            name,
            v8::Number::new(scope, *value).into(),
            enumerable(),
        )?;
    }
    Ok(object)
}

/// `HttpErrorString`: `nghttp2_strerror` on the argument read as a `uint32`.
fn nghttp2_error_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(code) = args.get(0).uint32_value(scope) else {
        // `node_http2.cc` returns undefined when `Uint32Value` fails, which
        // `lib/internal/http2/util.js` then puts in an error message.
        return;
    };
    rv.set(errors::error_string(scope, code));
}

/// `RefreshDefaultSettings`: write every default into `settingsBuffer`.
fn refresh_default_settings(
    _scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    // The buffers exist by the time this can be called: `install` created them,
    // and the function is only reachable from the object `install` returned.
    let _ = state::Http2State::with(settings::refresh_defaults);
}

/// `PackSettings`: the serialized SETTINGS payload as a `Buffer`.
fn pack_settings(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let packed = state::Http2State::with(|state| settings::pack(scope, state));
    match packed {
        Ok(Some(value)) => rv.set(value),
        // `Pack` returns `Undefined` when `nghttp2_pack_settings_payload` fails,
        // and `getPackedSettings` hands that straight back to the caller.
        Ok(None) | Err(_) => rv.set(v8::undefined(scope).into()),
    }
}

/// The eleven callbacks `core.js` installs, kept for the session half.
///
/// `SetCallbackFunctions` in `src/node_http2.cc` stores them on the `Environment`,
/// where the nghttp2 callbacks read them. There is no session yet, so they are
/// held here: this makes `setCallbackFunctions` a real function that can be called
/// and re-called, which is what `core.js` does at module scope, rather than a
/// member that accepts eleven arguments and discards them.
#[derive(Default)]
pub struct SessionCallbacks {
    pub error: Option<v8::Global<v8::Function>>,
    pub priority: Option<v8::Global<v8::Function>>,
    pub settings: Option<v8::Global<v8::Function>>,
    pub ping: Option<v8::Global<v8::Function>>,
    pub headers: Option<v8::Global<v8::Function>>,
    pub frame_error: Option<v8::Global<v8::Function>>,
    pub goaway_data: Option<v8::Global<v8::Function>>,
    pub altsvc: Option<v8::Global<v8::Function>>,
    pub origin: Option<v8::Global<v8::Function>>,
    pub stream_trailers: Option<v8::Global<v8::Function>>,
    pub stream_close: Option<v8::Global<v8::Function>>,
}

thread_local! {
    /// The callbacks `core.js` installed, in the order `SET_FUNCTION` uses.
    static CALLBACKS: RefCell<SessionCallbacks> = RefCell::new(SessionCallbacks::default());
}

/// `SetCallbackFunctions`.
///
/// `CHECK_EQ(args.Length(), 11)` and `CHECK(args[n]->IsFunction())` in the C++, so
/// a wrong arity or a non-function is a hard failure there. Here it throws a
/// `TypeError`, which is the same signal without aborting the process: `core.js`
/// passes eleven real functions, so anything else means the caller is not the
/// module this binding was written for.
fn set_callback_functions(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    if args.length() != 11 {
        throw_type_error(
            scope,
            &format!(
                "setCallbackFunctions expects 11 functions, received {}",
                args.length()
            ),
        );
        return;
    }
    let mut functions = Vec::with_capacity(11);
    for index in 0..11 {
        match v8::Local::<v8::Function>::try_from(args.get(index)) {
            Ok(function) => functions.push(v8::Global::new(scope, function)),
            Err(_) => {
                throw_type_error(
                    scope,
                    &format!("setCallbackFunctions argument {index} is not a function"),
                );
                return;
            }
        }
    }
    CALLBACKS.with(|callbacks| {
        let mut callbacks = callbacks.borrow_mut();
        let mut next = functions.into_iter();
        // `SET_FUNCTION`'s order, which is the order `core.js` passes them in.
        callbacks.error = next.next();
        callbacks.priority = next.next();
        callbacks.settings = next.next();
        callbacks.ping = next.next();
        callbacks.headers = next.next();
        callbacks.frame_error = next.next();
        callbacks.goaway_data = next.next();
        callbacks.altsvc = next.next();
        callbacks.origin = next.next();
        callbacks.stream_trailers = next.next();
        callbacks.stream_close = next.next();
    });
}

/// How many of the eleven callbacks are currently installed.
///
/// The session half calls this to decide whether it can call into JavaScript at
/// all: `core.js` installs them while loading, so a session constructed before
/// that would have no `onSessionHeaders` to call. Exposed for the integration
/// test rather than for `lib/**`.
#[doc(hidden)]
pub fn installed_callback_count() -> usize {
    CALLBACKS.with(|callbacks| {
        let callbacks = callbacks.borrow();
        [
            callbacks.error.is_some(),
            callbacks.priority.is_some(),
            callbacks.settings.is_some(),
            callbacks.ping.is_some(),
            callbacks.headers.is_some(),
            callbacks.frame_error.is_some(),
            callbacks.goaway_data.is_some(),
            callbacks.altsvc.is_some(),
            callbacks.origin.is_some(),
            callbacks.stream_trailers.is_some(),
            callbacks.stream_close.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
    })
}

/// Builds a function with `callback` behind it.
fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Function>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))
}

/// Sets a normal property.
fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    name: &str,
    value: v8::Local<'_, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    if object.set(scope, key.into(), value).is_none() {
        return Err(format!("cannot define {name}"));
    }
    Ok(())
}

/// Sets a property with explicit attributes, which is what `NODE_DEFINE_CONSTANT`
/// and its hidden variant do.
fn define(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<'_, v8::Object>,
    name: &str,
    value: v8::Local<'_, v8::Value>,
    attributes: v8::PropertyAttribute,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .define_own_property(scope, key.into(), value, attributes)
        .ok_or_else(|| format!("cannot define {name}"))?;
    Ok(())
}

/// Throws a `TypeError` with `message`.
fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    let Some(message) = v8::String::new(scope, message) else {
        return;
    };
    let error = v8::Exception::type_error(scope, message);
    scope.throw_exception(error);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `members` keys of `contracts/http2.json`, read with `serde_json`.
    ///
    /// Parsed rather than scanned: the file has nested objects whose keys look
    /// like member names, and a line-based scan has to guess at indentation to
    /// tell them apart. The contract is the artifact `rn-compat` reads, so reading
    /// it the same way it does is what makes this test mean anything.
    fn contract_members() -> Vec<String> {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/http2.json"
        ))
        .expect("contracts/http2.json is readable");
        let contract: serde_json::Value = serde_json::from_str(&raw).expect("the contract parses");
        contract["members"]
            .as_object()
            .expect("the contract has a members object")
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn every_contract_member_is_installed_or_declared_deferred() {
        // `rn-compat` reports a declared deferral as a pass, so a member in
        // neither list is an undeclared gap and one in both is a lie. This is the
        // same comparison without needing a built binary.
        let recorded = contract_members();
        let installed: std::collections::BTreeSet<&str> = MEMBERS.iter().copied().collect();
        let deferred: std::collections::BTreeSet<&str> =
            DEFERRED.iter().map(|(name, _)| *name).collect();

        // A member in both lists would make the deferral decorative.
        let both: Vec<&&str> = installed.intersection(&deferred).collect();
        assert!(
            both.is_empty(),
            "declared both installed and deferred: {both:?}"
        );

        let missing: Vec<&String> = recorded
            .iter()
            .filter(|name| !installed.contains(name.as_str()) && !deferred.contains(name.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "contract members not accounted for: {missing:?}"
        );

        // And the other direction: a member this crate claims that the contract
        // does not record means the name is wrong, which `rn-compat` would report
        // as the recorded one missing.
        let unknown: Vec<&&str> = installed
            .iter()
            .chain(deferred.iter())
            .filter(|name| !recorded.iter().any(|recorded| recorded == *name))
            .collect();
        assert!(
            unknown.is_empty(),
            "claimed but not in the contract: {unknown:?}"
        );
    }

    #[test]
    fn nothing_is_deferred() {
        // Both classes are real constructors now, so an empty `DEFERRED` is the
        // honest state. This test exists to make a future deferral a deliberate
        // edit: `rn-compat` reports a declared deferral as a pass, which is right
        // for a real gap and wrong for a member somebody simply forgot.
        assert!(
            DEFERRED.is_empty(),
            "a declaration here needs a test update alongside it: {DEFERRED:?}"
        );
    }

    #[test]
    fn the_field_indices_are_the_struct_offsets() {
        // `core.js` builds a `Uint32Array` over `kNativeFields.buffer` at
        // `kSessionMaxInvalidFrames` and `kSessionMaxRejectedStreams`, so these
        // two have to be 4 and 8 rather than 3 and 7: `SessionJSFields` pads to
        // `uint32_t` alignment after its three `uint8_t` members.
        assert_eq!(K_BITFIELD, 0);
        assert_eq!(K_SESSION_PRIORITY_LISTENER_COUNT, 1);
        assert_eq!(K_SESSION_FRAME_ERROR_LISTENER_COUNT, 2);
        assert_eq!(K_SESSION_MAX_INVALID_FRAMES, 4);
        assert_eq!(K_SESSION_MAX_REJECTED_STREAMS, 8);
        assert_eq!(K_SESSION_UINT8_FIELD_COUNT, 12);
    }

    #[test]
    fn the_bitfield_flags_are_bit_positions_in_order() {
        // `core.js` sets `1 << kSessionHasPingListeners` and so on, and
        // `SessionBitfieldFlags` in `node_http2.h` fixes the order.
        assert_eq!(constants::HAS_REMOTE_SETTINGS_LISTENERS, 0);
        assert_eq!(constants::REMOTE_SETTINGS_IS_UP_TO_DATE, 1);
        assert_eq!(constants::HAS_PING_LISTENERS, 2);
        assert_eq!(constants::HAS_ALTSVC_LISTENERS, 3);
    }

    #[test]
    fn the_linked_version_is_published() {
        // `process.versions.nghttp2` and the contract's constants both describe
        // the same library, so a failure here means the vendored tree and the
        // linked object file disagree.
        assert_eq!(version().as_deref(), Some("1.70.0"));
    }
}

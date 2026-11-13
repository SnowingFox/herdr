//! `constants`, the object `lib/internal/http2/util.js` re-exports as
//! `require('node:http2').constants`.
//!
//! `Initialize` in `src/node_http2.cc` builds this in four macro expansions, and
//! the split between them is observable:
//!
//! * `HTTP2_HIDDEN_CONSTANTS` uses `NODE_DEFINE_HIDDEN_CONSTANT`, which adds
//!   `DontEnum` on top of `ReadOnly | DontDelete`, so `NGHTTP2_HCAT_REQUEST` and
//!   the thirteen others with it do not appear in `Object.keys(constants)` but are
//!   still readable. `test-http2-binding.js` iterates `Object.keys(constants)`
//!   and would silently stop checking those fourteen if they were enumerable, so
//!   [`HIDDEN`] is a separate table rather than a flag on each row.
//! * `HTTP2_CONSTANTS` uses `NODE_DEFINE_CONSTANT`: `ReadOnly | DontDelete`,
//!   enumerable.
//! * `HTTP_KNOWN_HEADERS` and `HTTP_KNOWN_METHODS` use
//!   `NODE_DEFINE_STRING_CONSTANT` with a prefixed name.
//! * `HTTP_STATUS_CODES` is the plain enumerable form again.
//!
//! Every value here is the pin's, not a copy chosen here: the three string and
//! status tables come from `src/node_http_common.h`, and the numeric table from
//! `src/node_http2.h` together with the vendored nghttp2 headers. Tests in this
//! module re-derive the version-dependent ones from the linked library, so a
//! stale table cannot survive a re-pin.

/// The fourteen `DontEnum` constants.
///
/// `f64` for the same reason as [`NUMBERS`].
///
/// `Object.keys(constants)` must not see these, but
/// `constants.STREAM_OPTION_GET_TRAILERS` must work: that split is what
/// `NODE_DEFINE_HIDDEN_CONSTANT` produces, and `test-http2-binding.js` depends on
/// it in both directions.
pub const HIDDEN: &[(&str, f64)] = &[
    // `HTTP2_HIDDEN_CONSTANTS` in `node_http2.h`.
    ("NGHTTP2_HCAT_REQUEST", 0.0),
    ("NGHTTP2_HCAT_RESPONSE", 1.0),
    ("NGHTTP2_HCAT_PUSH_RESPONSE", 2.0),
    ("NGHTTP2_HCAT_HEADERS", 3.0),
    ("NGHTTP2_NV_FLAG_NONE", 0.0),
    ("NGHTTP2_NV_FLAG_NO_INDEX", 1.0),
    ("NGHTTP2_ERR_DEFERRED", -508.0),
    ("NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE", -509.0),
    ("NGHTTP2_ERR_INVALID_ARGUMENT", -501.0),
    ("NGHTTP2_ERR_STREAM_CLOSED", -510.0),
    ("NGHTTP2_ERR_NOMEM", -901.0),
    ("STREAM_OPTION_EMPTY_PAYLOAD", 0x1 as f64),
    ("STREAM_OPTION_GET_TRAILERS", 0x2 as f64),
    ("STREAM_OPTION_AUTO_EMPTY_TRAILERS", 0x4 as f64),
];

/// The names `nameForErrorCode` publishes, in `HTTP2_ERROR_CODES` order.
///
/// `Initialize` builds this array from the same macro that defines the error
/// constants, so index `n` is `NGHTTP2_<n>`'s name. `lib/internal/http2/core.js`
/// reads `nameForErrorCode[code]` to build `ERR_HTTP2_STREAM_ERROR` messages, so
/// a short array turns a real error code into `undefined` in a user-visible
/// message.
pub const ERROR_CODE_NAMES: &[&str] = &[
    "NGHTTP2_NO_ERROR",
    "NGHTTP2_PROTOCOL_ERROR",
    "NGHTTP2_INTERNAL_ERROR",
    "NGHTTP2_FLOW_CONTROL_ERROR",
    "NGHTTP2_SETTINGS_TIMEOUT",
    "NGHTTP2_STREAM_CLOSED",
    "NGHTTP2_FRAME_SIZE_ERROR",
    "NGHTTP2_REFUSED_STREAM",
    "NGHTTP2_CANCEL",
    "NGHTTP2_COMPRESSION_ERROR",
    "NGHTTP2_CONNECT_ERROR",
    "NGHTTP2_ENHANCE_YOUR_CALM",
    "NGHTTP2_INADEQUATE_SECURITY",
    "NGHTTP2_HTTP_1_1_REQUIRED",
];

/// The `SessionBitfieldFlags` indices `lib/internal/http2/core.js` uses to set
/// bits in `kNativeFields[kBitfield]`.
///
/// These are not on `constants`; they are separate top-level members of the
/// binding, and `core.js` names each one. Their values are the bit positions in
/// `SessionJSFields::bitfield`, so they have to stay `0..4` in this order.
pub const HAS_REMOTE_SETTINGS_LISTENERS: i32 = 0;
/// `kSessionRemoteSettingsIsUpToDate`.
pub const REMOTE_SETTINGS_IS_UP_TO_DATE: i32 = 1;
/// `kSessionHasPingListeners`.
pub const HAS_PING_LISTENERS: i32 = 2;
/// `kSessionHasAltsvcListeners`.
pub const HAS_ALTSVC_LISTENERS: i32 = 3;

/// The `HTTP2_HEADER_*` entries of `HTTP_KNOWN_HEADERS`.
///
/// Values are the lower-case field names a caller passes in a header object,
/// from `HTTP_SPECIAL_HEADERS`, `HTTP_REGULAR_HEADERS` and
/// `HTTP_ADDITIONAL_HEADERS` in `src/node_http_common.h`, concatenated in
/// that order as `HTTP_KNOWN_HEADERS` does.
pub const HEADERS: &[(&str, &str)] = &[
    ("HTTP2_HEADER_STATUS", ":status"),
    ("HTTP2_HEADER_METHOD", ":method"),
    ("HTTP2_HEADER_AUTHORITY", ":authority"),
    ("HTTP2_HEADER_SCHEME", ":scheme"),
    ("HTTP2_HEADER_PATH", ":path"),
    ("HTTP2_HEADER_PROTOCOL", ":protocol"),
    ("HTTP2_HEADER_ACCEPT_ENCODING", "accept-encoding"),
    ("HTTP2_HEADER_ACCEPT_LANGUAGE", "accept-language"),
    ("HTTP2_HEADER_ACCEPT_RANGES", "accept-ranges"),
    ("HTTP2_HEADER_ACCEPT", "accept"),
    (
        "HTTP2_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS",
        "access-control-allow-credentials",
    ),
    (
        "HTTP2_HEADER_ACCESS_CONTROL_ALLOW_HEADERS",
        "access-control-allow-headers",
    ),
    (
        "HTTP2_HEADER_ACCESS_CONTROL_ALLOW_METHODS",
        "access-control-allow-methods",
    ),
    (
        "HTTP2_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN",
        "access-control-allow-origin",
    ),
    (
        "HTTP2_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS",
        "access-control-expose-headers",
    ),
    (
        "HTTP2_HEADER_ACCESS_CONTROL_REQUEST_HEADERS",
        "access-control-request-headers",
    ),
    (
        "HTTP2_HEADER_ACCESS_CONTROL_REQUEST_METHOD",
        "access-control-request-method",
    ),
    ("HTTP2_HEADER_AGE", "age"),
    ("HTTP2_HEADER_AUTHORIZATION", "authorization"),
    ("HTTP2_HEADER_CACHE_CONTROL", "cache-control"),
    ("HTTP2_HEADER_CONNECTION", "connection"),
    ("HTTP2_HEADER_CONTENT_DISPOSITION", "content-disposition"),
    ("HTTP2_HEADER_CONTENT_ENCODING", "content-encoding"),
    ("HTTP2_HEADER_CONTENT_LENGTH", "content-length"),
    ("HTTP2_HEADER_CONTENT_TYPE", "content-type"),
    ("HTTP2_HEADER_COOKIE", "cookie"),
    ("HTTP2_HEADER_DATE", "date"),
    ("HTTP2_HEADER_ETAG", "etag"),
    ("HTTP2_HEADER_FORWARDED", "forwarded"),
    ("HTTP2_HEADER_HOST", "host"),
    ("HTTP2_HEADER_IF_MODIFIED_SINCE", "if-modified-since"),
    ("HTTP2_HEADER_IF_NONE_MATCH", "if-none-match"),
    ("HTTP2_HEADER_IF_RANGE", "if-range"),
    ("HTTP2_HEADER_LAST_MODIFIED", "last-modified"),
    ("HTTP2_HEADER_LINK", "link"),
    ("HTTP2_HEADER_LOCATION", "location"),
    ("HTTP2_HEADER_RANGE", "range"),
    ("HTTP2_HEADER_REFERER", "referer"),
    ("HTTP2_HEADER_SERVER", "server"),
    ("HTTP2_HEADER_SET_COOKIE", "set-cookie"),
    (
        "HTTP2_HEADER_STRICT_TRANSPORT_SECURITY",
        "strict-transport-security",
    ),
    ("HTTP2_HEADER_TRANSFER_ENCODING", "transfer-encoding"),
    ("HTTP2_HEADER_TE", "te"),
    (
        "HTTP2_HEADER_UPGRADE_INSECURE_REQUESTS",
        "upgrade-insecure-requests",
    ),
    ("HTTP2_HEADER_UPGRADE", "upgrade"),
    ("HTTP2_HEADER_USER_AGENT", "user-agent"),
    ("HTTP2_HEADER_VARY", "vary"),
    (
        "HTTP2_HEADER_X_CONTENT_TYPE_OPTIONS",
        "x-content-type-options",
    ),
    ("HTTP2_HEADER_X_FRAME_OPTIONS", "x-frame-options"),
    ("HTTP2_HEADER_KEEP_ALIVE", "keep-alive"),
    ("HTTP2_HEADER_PROXY_CONNECTION", "proxy-connection"),
    ("HTTP2_HEADER_X_XSS_PROTECTION", "x-xss-protection"),
    ("HTTP2_HEADER_ALT_SVC", "alt-svc"),
    (
        "HTTP2_HEADER_CONTENT_SECURITY_POLICY",
        "content-security-policy",
    ),
    ("HTTP2_HEADER_EARLY_DATA", "early-data"),
    ("HTTP2_HEADER_EXPECT_CT", "expect-ct"),
    ("HTTP2_HEADER_ORIGIN", "origin"),
    ("HTTP2_HEADER_PURPOSE", "purpose"),
    ("HTTP2_HEADER_TIMING_ALLOW_ORIGIN", "timing-allow-origin"),
    ("HTTP2_HEADER_X_FORWARDED_FOR", "x-forwarded-for"),
    ("HTTP2_HEADER_PRIORITY", "priority"),
    ("HTTP2_HEADER_ACCEPT_CHARSET", "accept-charset"),
    (
        "HTTP2_HEADER_ACCESS_CONTROL_MAX_AGE",
        "access-control-max-age",
    ),
    ("HTTP2_HEADER_ALLOW", "allow"),
    ("HTTP2_HEADER_CONTENT_LANGUAGE", "content-language"),
    ("HTTP2_HEADER_CONTENT_LOCATION", "content-location"),
    ("HTTP2_HEADER_CONTENT_MD5", "content-md5"),
    ("HTTP2_HEADER_CONTENT_RANGE", "content-range"),
    ("HTTP2_HEADER_DNT", "dnt"),
    ("HTTP2_HEADER_EXPECT", "expect"),
    ("HTTP2_HEADER_EXPIRES", "expires"),
    ("HTTP2_HEADER_FROM", "from"),
    ("HTTP2_HEADER_IF_MATCH", "if-match"),
    ("HTTP2_HEADER_IF_UNMODIFIED_SINCE", "if-unmodified-since"),
    ("HTTP2_HEADER_MAX_FORWARDS", "max-forwards"),
    ("HTTP2_HEADER_PREFER", "prefer"),
    ("HTTP2_HEADER_PROXY_AUTHENTICATE", "proxy-authenticate"),
    ("HTTP2_HEADER_PROXY_AUTHORIZATION", "proxy-authorization"),
    ("HTTP2_HEADER_REFRESH", "refresh"),
    ("HTTP2_HEADER_RETRY_AFTER", "retry-after"),
    ("HTTP2_HEADER_TRAILER", "trailer"),
    ("HTTP2_HEADER_TK", "tk"),
    ("HTTP2_HEADER_VIA", "via"),
    ("HTTP2_HEADER_WARNING", "warning"),
    ("HTTP2_HEADER_WWW_AUTHENTICATE", "www-authenticate"),
    ("HTTP2_HEADER_HTTP2_SETTINGS", "http2-settings"),
];

/// The `HTTP2_METHOD_*` entries of `HTTP_KNOWN_METHODS`.
///
/// Convenience values, not a supported-method list: HTTP/2 puts no limit on
/// the method token, which is why they are constants rather than a gate.
pub const METHODS: &[(&str, &str)] = &[
    ("HTTP2_METHOD_ACL", "ACL"),
    ("HTTP2_METHOD_BASELINE_CONTROL", "BASELINE-CONTROL"),
    ("HTTP2_METHOD_BIND", "BIND"),
    ("HTTP2_METHOD_CHECKIN", "CHECKIN"),
    ("HTTP2_METHOD_CHECKOUT", "CHECKOUT"),
    ("HTTP2_METHOD_CONNECT", "CONNECT"),
    ("HTTP2_METHOD_COPY", "COPY"),
    ("HTTP2_METHOD_DELETE", "DELETE"),
    ("HTTP2_METHOD_GET", "GET"),
    ("HTTP2_METHOD_HEAD", "HEAD"),
    ("HTTP2_METHOD_LABEL", "LABEL"),
    ("HTTP2_METHOD_LINK", "LINK"),
    ("HTTP2_METHOD_LOCK", "LOCK"),
    ("HTTP2_METHOD_MERGE", "MERGE"),
    ("HTTP2_METHOD_MKACTIVITY", "MKACTIVITY"),
    ("HTTP2_METHOD_MKCALENDAR", "MKCALENDAR"),
    ("HTTP2_METHOD_MKCOL", "MKCOL"),
    ("HTTP2_METHOD_MKREDIRECTREF", "MKREDIRECTREF"),
    ("HTTP2_METHOD_MKWORKSPACE", "MKWORKSPACE"),
    ("HTTP2_METHOD_MOVE", "MOVE"),
    ("HTTP2_METHOD_OPTIONS", "OPTIONS"),
    ("HTTP2_METHOD_ORDERPATCH", "ORDERPATCH"),
    ("HTTP2_METHOD_PATCH", "PATCH"),
    ("HTTP2_METHOD_POST", "POST"),
    ("HTTP2_METHOD_PRI", "PRI"),
    ("HTTP2_METHOD_PROPFIND", "PROPFIND"),
    ("HTTP2_METHOD_PROPPATCH", "PROPPATCH"),
    ("HTTP2_METHOD_PUT", "PUT"),
    ("HTTP2_METHOD_REBIND", "REBIND"),
    ("HTTP2_METHOD_REPORT", "REPORT"),
    ("HTTP2_METHOD_SEARCH", "SEARCH"),
    ("HTTP2_METHOD_TRACE", "TRACE"),
    ("HTTP2_METHOD_UNBIND", "UNBIND"),
    ("HTTP2_METHOD_UNCHECKOUT", "UNCHECKOUT"),
    ("HTTP2_METHOD_UNLINK", "UNLINK"),
    ("HTTP2_METHOD_UNLOCK", "UNLOCK"),
    ("HTTP2_METHOD_UPDATE", "UPDATE"),
    ("HTTP2_METHOD_UPDATEREDIRECTREF", "UPDATEREDIRECTREF"),
    ("HTTP2_METHOD_VERSION_CONTROL", "VERSION-CONTROL"),
];

/// The `HTTP_STATUS_*` entries of `HTTP_STATUS_CODES`.
///
/// `f64` for the same reason as [`NUMBERS`]: every constant on the object is a
/// `v8::Number`.
pub const STATUS_CODES: &[(&str, f64)] = &[
    ("HTTP_STATUS_CONTINUE", 100.0),
    ("HTTP_STATUS_SWITCHING_PROTOCOLS", 101.0),
    ("HTTP_STATUS_PROCESSING", 102.0),
    ("HTTP_STATUS_EARLY_HINTS", 103.0),
    ("HTTP_STATUS_OK", 200.0),
    ("HTTP_STATUS_CREATED", 201.0),
    ("HTTP_STATUS_ACCEPTED", 202.0),
    ("HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION", 203.0),
    ("HTTP_STATUS_NO_CONTENT", 204.0),
    ("HTTP_STATUS_RESET_CONTENT", 205.0),
    ("HTTP_STATUS_PARTIAL_CONTENT", 206.0),
    ("HTTP_STATUS_MULTI_STATUS", 207.0),
    ("HTTP_STATUS_ALREADY_REPORTED", 208.0),
    ("HTTP_STATUS_IM_USED", 226.0),
    ("HTTP_STATUS_MULTIPLE_CHOICES", 300.0),
    ("HTTP_STATUS_MOVED_PERMANENTLY", 301.0),
    ("HTTP_STATUS_FOUND", 302.0),
    ("HTTP_STATUS_SEE_OTHER", 303.0),
    ("HTTP_STATUS_NOT_MODIFIED", 304.0),
    ("HTTP_STATUS_USE_PROXY", 305.0),
    ("HTTP_STATUS_TEMPORARY_REDIRECT", 307.0),
    ("HTTP_STATUS_PERMANENT_REDIRECT", 308.0),
    ("HTTP_STATUS_BAD_REQUEST", 400.0),
    ("HTTP_STATUS_UNAUTHORIZED", 401.0),
    ("HTTP_STATUS_PAYMENT_REQUIRED", 402.0),
    ("HTTP_STATUS_FORBIDDEN", 403.0),
    ("HTTP_STATUS_NOT_FOUND", 404.0),
    ("HTTP_STATUS_METHOD_NOT_ALLOWED", 405.0),
    ("HTTP_STATUS_NOT_ACCEPTABLE", 406.0),
    ("HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED", 407.0),
    ("HTTP_STATUS_REQUEST_TIMEOUT", 408.0),
    ("HTTP_STATUS_CONFLICT", 409.0),
    ("HTTP_STATUS_GONE", 410.0),
    ("HTTP_STATUS_LENGTH_REQUIRED", 411.0),
    ("HTTP_STATUS_PRECONDITION_FAILED", 412.0),
    ("HTTP_STATUS_PAYLOAD_TOO_LARGE", 413.0),
    ("HTTP_STATUS_URI_TOO_LONG", 414.0),
    ("HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE", 415.0),
    ("HTTP_STATUS_RANGE_NOT_SATISFIABLE", 416.0),
    ("HTTP_STATUS_EXPECTATION_FAILED", 417.0),
    ("HTTP_STATUS_TEAPOT", 418.0),
    ("HTTP_STATUS_MISDIRECTED_REQUEST", 421.0),
    ("HTTP_STATUS_UNPROCESSABLE_ENTITY", 422.0),
    ("HTTP_STATUS_LOCKED", 423.0),
    ("HTTP_STATUS_FAILED_DEPENDENCY", 424.0),
    ("HTTP_STATUS_TOO_EARLY", 425.0),
    ("HTTP_STATUS_UPGRADE_REQUIRED", 426.0),
    ("HTTP_STATUS_PRECONDITION_REQUIRED", 428.0),
    ("HTTP_STATUS_TOO_MANY_REQUESTS", 429.0),
    ("HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE", 431.0),
    ("HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS", 451.0),
    ("HTTP_STATUS_INTERNAL_SERVER_ERROR", 500.0),
    ("HTTP_STATUS_NOT_IMPLEMENTED", 501.0),
    ("HTTP_STATUS_BAD_GATEWAY", 502.0),
    ("HTTP_STATUS_SERVICE_UNAVAILABLE", 503.0),
    ("HTTP_STATUS_GATEWAY_TIMEOUT", 504.0),
    ("HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED", 505.0),
    ("HTTP_STATUS_VARIANT_ALSO_NEGOTIATES", 506.0),
    ("HTTP_STATUS_INSUFFICIENT_STORAGE", 507.0),
    ("HTTP_STATUS_LOOP_DETECTED", 508.0),
    ("HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED", 509.0),
    ("HTTP_STATUS_NOT_EXTENDED", 510.0),
    ("HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED", 511.0),
];

/// Every `NODE_DEFINE_CONSTANT` numeric, in `node_http2.h` order.
///
/// `f64` rather than an integer type because `NODE_DEFINE_CONSTANT` publishes
/// `v8::Number::New(isolate, static_cast<double>(constant))`, so
/// `DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS` arrives as `4294967295` rather than
/// as `-1`. A signed integer type here would either not hold that value or would
/// carry the wrong sign for it.
///
/// `NGHTTP2_DEFAULT_WEIGHT` is here because `node_http2.cc` defines it
/// separately: it is a macro, so it cannot be in a `V(name)` list that also
/// has to name it as a string.
pub const NUMBERS: &[(&str, f64)] = &[
    ("MAX_MAX_FRAME_SIZE", 16777215.0),
    ("MIN_MAX_FRAME_SIZE", 16384.0),
    ("MAX_INITIAL_WINDOW_SIZE", 2147483647.0),
    ("DEFAULT_SETTINGS_HEADER_TABLE_SIZE", 4096.0),
    ("DEFAULT_SETTINGS_ENABLE_PUSH", 1.0),
    ("DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS", 4294967295.0),
    ("DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE", 4194304.0),
    ("DEFAULT_SETTINGS_MAX_FRAME_SIZE", 16384.0),
    ("DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE", 65535.0),
    ("DEFAULT_SETTINGS_ENABLE_CONNECT_PROTOCOL", 0.0),
    ("PADDING_STRATEGY_NONE", 0.0),
    ("PADDING_STRATEGY_ALIGNED", 1.0),
    ("PADDING_STRATEGY_MAX", 2.0),
    ("PADDING_STRATEGY_CALLBACK", 1.0),
    ("NGHTTP2_ERR_FRAME_SIZE_ERROR", -522.0),
    ("NGHTTP2_SESSION_SERVER", 0.0),
    ("NGHTTP2_SESSION_CLIENT", 1.0),
    ("NGHTTP2_STREAM_STATE_IDLE", 1.0),
    ("NGHTTP2_STREAM_STATE_OPEN", 2.0),
    ("NGHTTP2_STREAM_STATE_RESERVED_LOCAL", 3.0),
    ("NGHTTP2_STREAM_STATE_RESERVED_REMOTE", 4.0),
    ("NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL", 5.0),
    ("NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE", 6.0),
    ("NGHTTP2_STREAM_STATE_CLOSED", 7.0),
    ("NGHTTP2_FLAG_NONE", 0.0),
    ("NGHTTP2_FLAG_END_STREAM", 1.0),
    ("NGHTTP2_FLAG_END_HEADERS", 4.0),
    ("NGHTTP2_FLAG_ACK", 1.0),
    ("NGHTTP2_FLAG_PADDED", 8.0),
    ("NGHTTP2_FLAG_PRIORITY", 32.0),
    ("NGHTTP2_SETTINGS_HEADER_TABLE_SIZE", 1.0),
    ("NGHTTP2_SETTINGS_ENABLE_PUSH", 2.0),
    ("NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS", 3.0),
    ("NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE", 4.0),
    ("NGHTTP2_SETTINGS_MAX_FRAME_SIZE", 5.0),
    ("NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE", 6.0),
    ("NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL", 8.0),
    ("NGHTTP2_NO_ERROR", 0.0),
    ("NGHTTP2_PROTOCOL_ERROR", 1.0),
    ("NGHTTP2_INTERNAL_ERROR", 2.0),
    ("NGHTTP2_FLOW_CONTROL_ERROR", 3.0),
    ("NGHTTP2_SETTINGS_TIMEOUT", 4.0),
    ("NGHTTP2_STREAM_CLOSED", 5.0),
    ("NGHTTP2_FRAME_SIZE_ERROR", 6.0),
    ("NGHTTP2_REFUSED_STREAM", 7.0),
    ("NGHTTP2_CANCEL", 8.0),
    ("NGHTTP2_COMPRESSION_ERROR", 9.0),
    ("NGHTTP2_CONNECT_ERROR", 10.0),
    ("NGHTTP2_ENHANCE_YOUR_CALM", 11.0),
    ("NGHTTP2_INADEQUATE_SECURITY", 12.0),
    ("NGHTTP2_HTTP_1_1_REQUIRED", 13.0),
    ("NGHTTP2_DEFAULT_WEIGHT", 16.0),
];

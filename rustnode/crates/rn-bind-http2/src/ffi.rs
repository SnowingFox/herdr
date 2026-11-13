//! The nghttp2 C API, in the shape this crate needs.
//!
//! `vendor/nghttp2/lib/includes/nghttp2/nghttp2.h` is the authority; this module
//! mirrors only the declarations the binding calls, because the library is
//! compiled by `build.rs` and its symbols are linked into this crate. Writing
//! them out by hand rather than generating bindings keeps the surface auditable:
//! every function here is one `src/node_http2.cc` also calls.
//!
//! # Why the type aliases
//!
//! nghttp2's handles are opaque. Keeping them as raw pointers with distinct type
//! aliases documents intent at each call site without pretending the lifetimes
//! are checked, which they are not: nghttp2 owns its session, stream and option
//! objects, and the crate frees them exactly where `Nghttp2SessionPointer` and
//! friends do in `node_http2.h`.
//!
//! # Why `nghttp2_nv` is declared rather than inferred
//!
//! `nghttp2_submit_request` takes an array of `nghttp2_nv`, and the layout of
//! that struct is part of the ABI: four fields in a fixed order, with `flags` an
//! `uint8_t`. Node builds the same array in `Http2Headers` over
//! `nghttp2_nv`. A wrong field order here would not fail to compile — it would
//! send mangled header names — so the struct is written out with the header's own
//! field order and a test pins the size against the compiled C library.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_void};

/// `nghttp2_session` — one HTTP/2 connection state machine.
pub type nghttp2_session = c_void;
/// `nghttp2_session_callbacks` — the callback table a session is built with.
pub type nghttp2_session_callbacks = c_void;
/// `nghttp2_option` — the configuration object a session is built with.
pub type nghttp2_option = c_void;
/// `nghttp2_stream` — one stream inside a session.
pub type nghttp2_stream = c_void;
/// `nghttp2_rcbuf` — a reference-counted header buffer.
pub type nghttp2_rcbuf = c_void;

/// `nghttp2_ssize`, which is `ptrdiff_t` unless nghttp2 was configured otherwise.
pub type nghttp2_ssize = isize;

/// `nghttp2_error.NGHTTP2_NO_ERROR`.
pub const NGHTTP2_NO_ERROR: c_int = 0;
/// `NGHTTP2_ERR_NOMEM`.
pub const NGHTTP2_ERR_NOMEM: c_int = -901;
/// `NGHTTP2_ERR_CALLBACK_FAILURE`.
pub const NGHTTP2_ERR_CALLBACK_FAILURE: c_int = -902;
/// `NGHTTP2_ERR_DEFERRED`.
pub const NGHTTP2_ERR_DEFERRED: c_int = -508;
/// `NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.
pub const NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE: c_int = -521;
/// `NGHTTP2_ERR_PAUSE`.
pub const NGHTTP2_ERR_PAUSE: c_int = -526;

/// `NGHTTP2_FLAG_NONE`.
pub const NGHTTP2_FLAG_NONE: u8 = 0;
/// `NGHTTP2_FLAG_END_STREAM`.
pub const NGHTTP2_FLAG_END_STREAM: u8 = 0x01;
/// `NGHTTP2_FLAG_END_HEADERS`.
pub const NGHTTP2_FLAG_END_HEADERS: u8 = 0x04;
/// `NGHTTP2_FLAG_ACK`.
pub const NGHTTP2_FLAG_ACK: u8 = 0x01;

/// `NGHTTP2_REFUSED_STREAM`, the RST_STREAM code for a refused stream.
pub const NGHTTP2_REFUSED_STREAM_CODE: u32 = 7;
/// `NGHTTP2_CANCEL`, the RST_STREAM code `destroy()` uses.
pub const NGHTTP2_CANCEL_CODE: u32 = 8;
/// `NGHTTP2_ERR_INVALID_ARGUMENT`.
pub const NGHTTP2_ERR_INVALID_ARGUMENT: i32 = -501;
/// `NGHTTP2_ERR_PROTO`, reported for a client-side `pushPromise`.
pub const NGHTTP2_ERR_PROTO: i32 = -505;

/// `NGHTTP2_HCAT_REQUEST`.
pub const NGHTTP2_HCAT_REQUEST: c_int = 0;
/// `NGHTTP2_HCAT_RESPONSE`.
pub const NGHTTP2_HCAT_RESPONSE: c_int = 1;
/// `NGHTTP2_HCAT_PUSH_RESPONSE`.
pub const NGHTTP2_HCAT_PUSH_RESPONSE: c_int = 2;
/// `NGHTTP2_HCAT_HEADERS`.
pub const NGHTTP2_HCAT_HEADERS: c_int = 3;

/// `NGHTTP2_NV_FLAG_NONE`.
pub const NGHTTP2_NV_FLAG_NONE: u8 = 0;
/// `NGHTTP2_NV_FLAG_NO_INDEX`.
pub const NGHTTP2_NV_FLAG_NO_INDEX: u8 = 0x01;

/// `NGHTTP2_ALTSVC`, the extension frame type nghttp2 can decode itself.
pub const NGHTTP2_ALTSVC: u8 = 0x0a;
/// `NGHTTP2_ORIGIN`, the second built-in extension frame type.
pub const NGHTTP2_ORIGIN: u8 = 0x0c;

/// `NGHTTP2_SETTINGS_HEADER_TABLE_SIZE`.
pub const NGHTTP2_SETTINGS_HEADER_TABLE_SIZE: c_int = 0x01;
/// `NGHTTP2_SETTINGS_ENABLE_PUSH`.
pub const NGHTTP2_SETTINGS_ENABLE_PUSH: c_int = 0x02;
/// `NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS`.
pub const NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: c_int = 0x03;
/// `NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE`.
pub const NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE: c_int = 0x04;
/// `NGHTTP2_SETTINGS_MAX_FRAME_SIZE`.
pub const NGHTTP2_SETTINGS_MAX_FRAME_SIZE: c_int = 0x05;
/// `NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE`.
pub const NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE: c_int = 0x06;
/// `NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL`.
pub const NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL: c_int = 0x08;

/// `nghttp2_nv`: one header name/value pair as nghttp2 takes it.
///
/// `namelen`/`valuelen` exclude the NUL terminators, and `flags` is one byte, so
/// the struct is padded to pointer alignment. This is the layout
/// `vendor/nghttp2/lib/includes/nghttp2/nghttp2.h` declares and the one
/// `nghttp2_submit_request` reads.
#[repr(C)]
pub struct nghttp2_nv {
    pub name: *mut u8,
    pub value: *mut u8,
    pub namelen: usize,
    pub valuelen: usize,
    pub flags: u8,
}

/// `nghttp2_priority_spec`: a priority tree edge.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nghttp2_priority_spec {
    pub stream_id: i32,
    pub weight: i32,
    pub exclusive: c_int,
}

/// `nghttp2_settings_entry`: one settings id/value pair.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nghttp2_settings_entry {
    pub settings_id: i32,
    pub value: u32,
}

/// `nghttp2_frame_hd`: the nine-byte frame header every frame starts with.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nghttp2_frame_hd {
    pub length: usize,
    pub stream_id: i32,
    pub type_: u8,
    pub flags: u8,
    pub reserved: u8,
}

/// `nghttp2_data_source`: the `source.ptr` nghttp2 hands back to a read callback.
///
/// No `Debug` derive, for the same reason as [`nghttp2_frame`]: a union has no
/// single active member to print.
#[repr(C)]
#[derive(Clone, Copy)]
pub union nghttp2_data_source {
    pub fd: c_int,
    pub ptr: *mut c_void,
}

/// `nghttp2_data`: a DATA frame, as delivered to `on_frame_recv_callback`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nghttp2_data {
    pub hd: nghttp2_frame_hd,
    pub padlen: usize,
}

/// `nghttp2_headers`: a HEADERS frame, as delivered to `on_frame_recv_callback`.
///
/// Every field up to `cat` is declared, including the deprecated `pri_spec`, and
/// that is not optional: `cat` is the field the JavaScript side needs for
/// `onSessionHeaders`, and it sits *after* `pri_spec` in the C struct. Omitting
/// the middle field would put `cat` eight bytes early and read padding. The
/// struct's trailing fields end at `cat`, so this mirror is the whole thing.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nghttp2_headers {
    pub hd: nghttp2_frame_hd,
    pub padlen: usize,
    pub pri_spec: nghttp2_priority_spec,
    pub nva: *mut nghttp2_nv,
    pub nvlen: usize,
    pub cat: c_int,
}

/// `nghttp2_frame`: the union every frame callback receives.
///
/// A `#[repr(C)]` union of the frame variants this crate reads. Reading
/// `hd`/`headers`/`data` is valid only for the frame type that was delivered,
/// which is what `nghttp2_frame_hd.type_` says; every accessor in
/// [`crate::session`] checks it first.
///
/// No `Debug` derive: `#[derive(Debug)]` is not defined for unions, and a manual
/// one would have to decide which variant is live, which is exactly the question
/// the frame type answers and this type cannot.
#[repr(C)]
#[derive(Clone, Copy)]
pub union nghttp2_frame {
    pub hd: nghttp2_frame_hd,
    pub headers: nghttp2_headers,
    pub data: nghttp2_data,
    pub ping: nghttp2_ping,
    pub goaway: nghttp2_goaway,
}

/// `nghttp2_ping`: a PING frame.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nghttp2_ping {
    pub hd: nghttp2_frame_hd,
    /// The eight opaque bytes a peer must echo back in its ACK.
    pub opaque_data: [u8; 8],
}

/// `nghttp2_goaway`: a GOAWAY frame.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nghttp2_goaway {
    pub hd: nghttp2_frame_hd,
    pub last_stream_id: i32,
    pub error_code: u32,
    pub opaque_data: *mut u8,
    pub opaque_data_len: usize,
    pub ignored: usize,
}

/// `nghttp2_frame_type.NGHTTP2_HEADERS`.
pub const NGHTTP2_HEADERS: u8 = 0x01;
/// `nghttp2_frame_type.NGHTTP2_DATA`.
pub const NGHTTP2_DATA: u8 = 0x00;
/// `nghttp2_frame_type.NGHTTP2_SETTINGS`.
pub const NGHTTP2_SETTINGS: u8 = 0x04;
/// `nghttp2_frame_type.NGHTTP2_PING`.
pub const NGHTTP2_PING: u8 = 0x06;
/// `nghttp2_frame_type.NGHTTP2_GOAWAY`.
pub const NGHTTP2_GOAWAY: u8 = 0x07;
/// `nghttp2_frame_type.NGHTTP2_PRIORITY`.
pub const NGHTTP2_PRIORITY: u8 = 0x02;
/// `nghttp2_frame_type.NGHTTP2_RST_STREAM`.
pub const NGHTTP2_RST_STREAM: u8 = 0x03;

/// `nghttp2_session_callbacks_set_on_frame_recv_callback`.
pub type on_frame_recv_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *const nghttp2_frame,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_on_header_callback`: one header pair within a HEADERS frame.
pub type on_header_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *const nghttp2_frame,
        name: *const u8,
        namelen: usize,
        value: *const u8,
        valuelen: usize,
        flags: u8,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_on_data_chunk_recv_callback`.
pub type on_data_chunk_recv_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        data: *const u8,
        len: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_on_stream_close_callback`.
pub type on_stream_close_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        stream_id: i32,
        error_code: u32,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_on_begin_headers_callback`.
pub type on_begin_headers_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *const nghttp2_frame,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_on_frame_send_callback`.
pub type on_frame_send_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *const nghttp2_frame,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_send_callback`: writes bytes to the transport.
pub type send_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        data: *const u8,
        length: usize,
        flags: c_int,
        user_data: *mut c_void,
    ) -> nghttp2_ssize,
>;

/// `nghttp2_data_source_read_callback2`, the callback a DATA provider reads from.
pub type data_source_read_callback2 = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        stream_id: i32,
        buf: *mut u8,
        length: usize,
        data_flags: *mut u32,
        source: *mut nghttp2_data_source,
        user_data: *mut c_void,
    ) -> nghttp2_ssize,
>;

/// `nghttp2_data_provider2`, the provider `nghttp2_submit_data2` takes.
#[repr(C)]
pub struct nghttp2_data_provider2 {
    pub source: nghttp2_data_source,
    pub read_callback: data_source_read_callback2,
}

/// `nghttp2_select_padding_callback`.
pub type select_padding_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *const nghttp2_frame,
        max_payloadlen: usize,
        user_data: *mut c_void,
    ) -> usize,
>;

extern "C" {
    /// `nghttp2_version`, used to report `process.versions.nghttp2`.
    pub fn nghttp2_version(least_version: c_int) -> *const Nghttp2Info;
    /// `nghttp2_strerror`.
    pub fn nghttp2_strerror(lib_error_code: c_int) -> *const c_char;
    /// `nghttp2_pack_settings_payload`.
    pub fn nghttp2_pack_settings_payload(
        buf: *mut u8,
        buflen: usize,
        iv: *const nghttp2_settings_entry,
        niv: usize,
    ) -> isize;

    /// `nghttp2_option_new`.
    pub fn nghttp2_option_new(option_ptr: *mut *mut nghttp2_option) -> c_int;
    /// `nghttp2_option_del`.
    pub fn nghttp2_option_del(option: *mut nghttp2_option);
    /// `nghttp2_option_set_no_closed_streams`.
    pub fn nghttp2_option_set_no_closed_streams(option: *mut nghttp2_option, val: c_int);
    /// `nghttp2_option_set_no_auto_window_update`.
    pub fn nghttp2_option_set_no_auto_window_update(option: *mut nghttp2_option, val: c_int);
    /// `nghttp2_option_set_builtin_recv_extension_type`.
    pub fn nghttp2_option_set_builtin_recv_extension_type(option: *mut nghttp2_option, type_: u8);
    /// `nghttp2_option_set_max_deflate_dynamic_table_size`.
    pub fn nghttp2_option_set_max_deflate_dynamic_table_size(
        option: *mut nghttp2_option,
        val: usize,
    );
    /// `nghttp2_option_set_max_reserved_remote_streams`.
    pub fn nghttp2_option_set_max_reserved_remote_streams(option: *mut nghttp2_option, val: usize);
    /// `nghttp2_option_set_max_send_header_block_length`.
    pub fn nghttp2_option_set_max_send_header_block_length(option: *mut nghttp2_option, val: usize);
    /// `nghttp2_option_set_peer_max_concurrent_streams`.
    pub fn nghttp2_option_set_peer_max_concurrent_streams(option: *mut nghttp2_option, val: u32);
    /// `nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation`.
    pub fn nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(
        option: *mut nghttp2_option,
        val: c_int,
    );
    /// `nghttp2_option_set_max_settings`.
    pub fn nghttp2_option_set_max_settings(option: *mut nghttp2_option, val: usize);
    /// `nghttp2_option_set_stream_reset_rate_limit`.
    pub fn nghttp2_option_set_stream_reset_rate_limit(
        option: *mut nghttp2_option,
        burst: u64,
        rate: u64,
    );

    /// `nghttp2_session_callbacks_new`.
    pub fn nghttp2_session_callbacks_new(
        callbacks_ptr: *mut *mut nghttp2_session_callbacks,
    ) -> c_int;
    /// `nghttp2_session_callbacks_del`.
    pub fn nghttp2_session_callbacks_del(callbacks: *mut nghttp2_session_callbacks);
    /// `nghttp2_session_callbacks_set_on_frame_recv_callback`.
    pub fn nghttp2_session_callbacks_set_on_frame_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_frame_recv_callback: on_frame_recv_callback,
    );
    /// `nghttp2_session_callbacks_set_on_header_callback`.
    pub fn nghttp2_session_callbacks_set_on_header_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_header_callback: on_header_callback,
    );
    /// `nghttp2_session_callbacks_set_on_data_chunk_recv_callback`.
    pub fn nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_data_chunk_recv_callback: on_data_chunk_recv_callback,
    );
    /// `nghttp2_session_callbacks_set_on_stream_close_callback`.
    pub fn nghttp2_session_callbacks_set_on_stream_close_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_stream_close_callback: on_stream_close_callback,
    );
    /// `nghttp2_session_callbacks_set_on_begin_headers_callback`.
    pub fn nghttp2_session_callbacks_set_on_begin_headers_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_begin_headers_callback: on_begin_headers_callback,
    );
    /// `nghttp2_session_callbacks_set_on_frame_send_callback`.
    pub fn nghttp2_session_callbacks_set_on_frame_send_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_frame_send_callback: on_frame_send_callback,
    );
    /// `nghttp2_session_callbacks_set_send_callback`.
    pub fn nghttp2_session_callbacks_set_send_callback(
        cbs: *mut nghttp2_session_callbacks,
        send_callback: send_callback,
    );
    /// `nghttp2_session_callbacks_set_select_padding_callback`.
    pub fn nghttp2_session_callbacks_set_select_padding_callback(
        cbs: *mut nghttp2_session_callbacks,
        select_padding_callback: select_padding_callback,
    );

    /// `nghttp2_session_client_new`.
    pub fn nghttp2_session_client_new(
        session_ptr: *mut *mut nghttp2_session,
        callbacks: *const nghttp2_session_callbacks,
        user_data: *mut c_void,
    ) -> c_int;
    /// `nghttp2_session_server_new2`.
    pub fn nghttp2_session_server_new2(
        session_ptr: *mut *mut nghttp2_session,
        callbacks: *const nghttp2_session_callbacks,
        user_data: *mut c_void,
        option: *const nghttp2_option,
    ) -> c_int;
    /// `nghttp2_session_client_new2`.
    pub fn nghttp2_session_client_new2(
        session_ptr: *mut *mut nghttp2_session,
        callbacks: *const nghttp2_session_callbacks,
        user_data: *mut c_void,
        option: *const nghttp2_option,
    ) -> c_int;
    /// `nghttp2_session_del`.
    pub fn nghttp2_session_del(session: *mut nghttp2_session);
    /// `nghttp2_session_want_read`.
    pub fn nghttp2_session_want_read(session: *mut nghttp2_session) -> c_int;
    /// `nghttp2_session_want_write`.
    pub fn nghttp2_session_want_write(session: *mut nghttp2_session) -> c_int;
    /// `nghttp2_session_mem_recv`.
    pub fn nghttp2_session_mem_recv(
        session: *mut nghttp2_session,
        in_: *const u8,
        inlen: usize,
    ) -> nghttp2_ssize;
    /// `nghttp2_session_mem_send`.
    pub fn nghttp2_session_mem_send(
        session: *mut nghttp2_session,
        data_ptr: *mut *const u8,
    ) -> nghttp2_ssize;
    /// `nghttp2_session_consume`.
    pub fn nghttp2_session_consume(
        session: *mut nghttp2_session,
        stream_id: i32,
        size: usize,
    ) -> c_int;
    /// `nghttp2_session_get_next_stream_id`.
    pub fn nghttp2_session_get_next_stream_id(session: *mut nghttp2_session) -> i32;
    /// `nghttp2_session_get_last_proc_stream_id`.
    pub fn nghttp2_session_get_last_proc_stream_id(session: *mut nghttp2_session) -> i32;
    /// `nghttp2_session_get_outbound_queue_size`.
    pub fn nghttp2_session_get_outbound_queue_size(session: *mut nghttp2_session) -> usize;
    /// `nghttp2_session_get_hd_deflate_dynamic_table_size`.
    pub fn nghttp2_session_get_hd_deflate_dynamic_table_size(
        session: *mut nghttp2_session,
    ) -> usize;
    /// `nghttp2_session_get_hd_inflate_dynamic_table_size`.
    pub fn nghttp2_session_get_hd_inflate_dynamic_table_size(
        session: *mut nghttp2_session,
    ) -> usize;
    /// `nghttp2_session_get_effective_local_window_size`.
    pub fn nghttp2_session_get_effective_local_window_size(session: *mut nghttp2_session) -> i32;
    /// `nghttp2_session_get_effective_recv_data_length`.
    pub fn nghttp2_session_get_effective_recv_data_length(session: *mut nghttp2_session) -> i32;
    /// `nghttp2_session_get_local_window_size`.
    pub fn nghttp2_session_get_local_window_size(session: *mut nghttp2_session) -> i32;
    /// `nghttp2_session_get_remote_window_size`.
    pub fn nghttp2_session_get_remote_window_size(session: *mut nghttp2_session) -> i32;
    /// `nghttp2_session_get_local_settings`.
    pub fn nghttp2_session_get_local_settings(session: *mut nghttp2_session, id: c_int) -> u32;
    /// `nghttp2_session_get_remote_settings`.
    pub fn nghttp2_session_get_remote_settings(session: *mut nghttp2_session, id: c_int) -> u32;
    /// `nghttp2_session_set_next_stream_id`.
    pub fn nghttp2_session_set_next_stream_id(
        session: *mut nghttp2_session,
        stream_id: i32,
    ) -> c_int;
    /// `nghttp2_session_set_local_window_size`.
    pub fn nghttp2_session_set_local_window_size(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        window_size: i32,
    ) -> c_int;
    /// `nghttp2_session_set_stream_user_data`.
    pub fn nghttp2_session_set_stream_user_data(
        session: *mut nghttp2_session,
        stream_id: i32,
        stream_user_data: *mut c_void,
    ) -> c_int;
    /// `nghttp2_session_get_stream_user_data`.
    pub fn nghttp2_session_get_stream_user_data(
        session: *mut nghttp2_session,
        stream_id: i32,
    ) -> *mut c_void;
    /// `nghttp2_session_terminate_session`.
    pub fn nghttp2_session_terminate_session(
        session: *mut nghttp2_session,
        error_code: u32,
    ) -> c_int;
    /// `nghttp2_session_terminate_session2`.
    pub fn nghttp2_session_terminate_session2(
        session: *mut nghttp2_session,
        last_stream_id: i32,
        error_code: u32,
    ) -> c_int;
    /// `nghttp2_session_upgrade2`.
    pub fn nghttp2_session_upgrade2(
        session: *mut nghttp2_session,
        settings_payload: *const u8,
        settings_payloadlen: usize,
        head_request: c_int,
        stream_user_data: *mut c_void,
    ) -> c_int;
    /// `nghttp2_session_check_request_allowed`.
    pub fn nghttp2_session_check_request_allowed(session: *mut nghttp2_session) -> c_int;

    /// `nghttp2_submit_settings`.
    pub fn nghttp2_submit_settings(
        session: *mut nghttp2_session,
        flags: u8,
        iv: *const nghttp2_settings_entry,
        niv: usize,
    ) -> c_int;
    /// `nghttp2_submit_request`.
    pub fn nghttp2_submit_request(
        session: *mut nghttp2_session,
        pri_spec: *const nghttp2_priority_spec,
        nva: *const nghttp2_nv,
        nvlen: usize,
        data_prd: *const nghttp2_data_provider2,
        stream_user_data: *mut c_void,
    ) -> i32;
    /// `nghttp2_submit_response`.
    pub fn nghttp2_submit_response(
        session: *mut nghttp2_session,
        stream_id: i32,
        nva: *const nghttp2_nv,
        nvlen: usize,
        data_prd: *const nghttp2_data_provider2,
    ) -> c_int;
    /// `nghttp2_submit_headers`.
    pub fn nghttp2_submit_headers(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        pri_spec: *const nghttp2_priority_spec,
        nva: *const nghttp2_nv,
        nvlen: usize,
        stream_user_data: *mut c_void,
    ) -> i32;
    /// `nghttp2_submit_data2`.
    pub fn nghttp2_submit_data2(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        data_prd: *const nghttp2_data_provider2,
    ) -> c_int;
    /// `nghttp2_submit_trailer`.
    pub fn nghttp2_submit_trailer(
        session: *mut nghttp2_session,
        stream_id: i32,
        nva: *const nghttp2_nv,
        nvlen: usize,
    ) -> c_int;
    /// `nghttp2_submit_priority`.
    pub fn nghttp2_submit_priority(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        pri_spec: *const nghttp2_priority_spec,
    ) -> c_int;
    /// `nghttp2_submit_ping`.
    pub fn nghttp2_submit_ping(
        session: *mut nghttp2_session,
        flags: u8,
        opaque_data: *const u8,
    ) -> c_int;
    /// `nghttp2_submit_goaway`.
    pub fn nghttp2_submit_goaway(
        session: *mut nghttp2_session,
        flags: u8,
        last_stream_id: i32,
        error_code: u32,
        opaque_data: *const u8,
        opaque_data_len: usize,
    ) -> c_int;
    /// `nghttp2_submit_rst_stream`.
    pub fn nghttp2_submit_rst_stream(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        error_code: u32,
    ) -> c_int;
    /// `nghttp2_submit_altsvc`.
    pub fn nghttp2_submit_altsvc(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        origin: *const u8,
        origin_len: usize,
        field_value: *const u8,
        field_value_len: usize,
    ) -> c_int;
    /// `nghttp2_submit_origin`.
    pub fn nghttp2_submit_origin(
        session: *mut nghttp2_session,
        flags: u8,
        origins: *const Nghttp2OriginEntry,
        nvlen: usize,
    ) -> c_int;

    /// `nghttp2_stream_get_weight`.
    pub fn nghttp2_stream_get_weight(stream: *mut nghttp2_stream) -> i32;
    /// `nghttp2_stream_get_sum_dependency_weight`.
    pub fn nghttp2_stream_get_sum_dependency_weight(stream: *mut nghttp2_stream) -> i32;
    /// `nghttp2_stream_get_state`.
    pub fn nghttp2_stream_get_state(stream: *mut nghttp2_stream) -> c_int;
    /// `nghttp2_session_resume_data`.
    pub fn nghttp2_session_resume_data(session: *mut nghttp2_session, stream_id: i32) -> c_int;
    /// `nghttp2_session_set_user_data`.
    pub fn nghttp2_session_set_user_data(session: *mut nghttp2_session, user_data: *mut c_void);
    /// `nghttp2_session_get_stream`.
    pub fn nghttp2_session_get_stream(
        session: *mut nghttp2_session,
        stream_id: i32,
    ) -> *mut nghttp2_stream;
    /// `nghttp2_session_get_stream_local_close`.
    pub fn nghttp2_session_get_stream_local_close(
        session: *mut nghttp2_session,
        stream_id: i32,
    ) -> c_int;
    /// `nghttp2_session_get_stream_remote_close`.
    pub fn nghttp2_session_get_stream_remote_close(
        session: *mut nghttp2_session,
        stream_id: i32,
    ) -> c_int;
    /// `nghttp2_session_get_stream_local_window_size`.
    pub fn nghttp2_session_get_stream_local_window_size(
        session: *mut nghttp2_session,
        stream_id: i32,
    ) -> i32;
}

/// `nghttp2_info`, what `nghttp2_version` returns.
#[repr(C)]
pub struct Nghttp2Info {
    pub age: c_int,
    pub version_num: c_int,
    pub version_str: *const c_char,
    pub proto_str: *const c_char,
}

/// `nghttp2_origin_entry`.
#[repr(C)]
pub struct Nghttp2OriginEntry {
    pub origin: *mut u8,
    pub origin_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reported_version_is_the_vendored_one() {
        // `process.versions.nghttp2` is built from this, and `lib/**` and the
        // test suite both key off the number. The vendored header says 1.70.0
        // (`NGHTTP2_VERSION` in `nghttp2ver.h`), so the linked library has to
        // agree: reporting a version the binary does not contain would be worse
        // than reporting none.
        let info = unsafe { nghttp2_version(0) };
        assert!(!info.is_null(), "nghttp2_version returned null");
        let info = unsafe { &*info };
        assert_eq!(info.version_num, 0x01_46_00, "1.70.0 is 0x014600");
        let version = unsafe { std::ffi::CStr::from_ptr(info.version_str) };
        assert_eq!(version.to_str().expect("ASCII"), "1.70.0");
    }

    #[test]
    fn strerror_matches_the_documented_text() {
        // `test-http2-binding.js` asserts this exact string for -517, so the
        // linked library is what decides it, not this crate.
        let text = unsafe { std::ffi::CStr::from_ptr(nghttp2_strerror(-517)) };
        assert_eq!(
            text.to_str().expect("ASCII"),
            "GOAWAY has already been sent"
        );
    }

    #[test]
    fn the_frame_header_layout_is_the_compiled_one() {
        // A `#[repr(C)]` struct with the wrong field order still compiles and
        // still links; what it does instead is misread every frame. The C
        // library and this crate have to agree on the header size, and the
        // header is length(8) + stream_id(4) + type(1) + flags(1) + reserved(1)
        // padded to 16 on a 64-bit target.
        assert_eq!(std::mem::size_of::<nghttp2_frame_hd>(), 16);
        assert_eq!(std::mem::align_of::<nghttp2_frame_hd>(), 8);
    }

    #[test]
    fn the_settings_entry_layout_is_the_compiled_one() {
        // `nghttp2_pack_settings_payload` walks an array of these and packs six
        // bytes per entry, so a size or field order difference corrupts every
        // packed SETTINGS frame.
        assert_eq!(std::mem::size_of::<nghttp2_settings_entry>(), 8);
        let entry = nghttp2_settings_entry {
            settings_id: NGHTTP2_SETTINGS_ENABLE_PUSH,
            value: 1,
        };
        let mut packed = [0u8; 6];
        let written =
            unsafe { nghttp2_pack_settings_payload(packed.as_mut_ptr(), packed.len(), &entry, 1) };
        assert_eq!(written, 6);
        assert_eq!(packed, [0x00, 0x02, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn the_nv_layout_puts_flags_after_the_lengths() {
        // `flags` is one byte in `nghttp2.h`; making it `c_int` here would shift
        // no field but would widen the struct, and nghttp2 would read the array
        // with the wrong stride.
        assert_eq!(std::mem::size_of::<nghttp2_nv>(), 40);
        assert_eq!(std::mem::align_of::<nghttp2_nv>(), 8);
    }
}

// Additional declarations the session and stream halves need. Kept as a second
// `extern` block so the increment-1 surface above stays readable; the two are the
// same library.
extern "C" {
    /// `nghttp2_session_callbacks_set_on_header_callback2`.
    pub fn nghttp2_session_callbacks_set_on_header_callback2(
        cbs: *mut nghttp2_session_callbacks,
        on_header_callback2: on_header_callback2,
    );
    /// `nghttp2_session_callbacks_set_on_invalid_frame_recv_callback`.
    pub fn nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_invalid_frame_recv_callback: on_invalid_frame_recv_callback,
    );
    /// `nghttp2_session_callbacks_set_on_frame_not_send_callback`.
    pub fn nghttp2_session_callbacks_set_on_frame_not_send_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_frame_not_send_callback: on_frame_not_send_callback,
    );
    /// `nghttp2_session_callbacks_set_error_callback2`.
    pub fn nghttp2_session_callbacks_set_error_callback2(
        cbs: *mut nghttp2_session_callbacks,
        error_callback2: error_callback2,
    );
    /// `nghttp2_session_callbacks_set_send_data_callback`.
    pub fn nghttp2_session_callbacks_set_send_data_callback(
        cbs: *mut nghttp2_session_callbacks,
        send_data_callback: send_data_callback,
    );

    /// `nghttp2_submit_response2`.
    pub fn nghttp2_submit_response2(
        session: *mut nghttp2_session,
        stream_id: i32,
        nva: *const nghttp2_nv,
        nvlen: usize,
        data_prd: *const nghttp2_data_provider2,
    ) -> c_int;
    /// `nghttp2_submit_request2`.
    pub fn nghttp2_submit_request2(
        session: *mut nghttp2_session,
        pri_spec: *const nghttp2_priority_spec,
        nva: *const nghttp2_nv,
        nvlen: usize,
        data_prd: *const nghttp2_data_provider2,
        stream_user_data: *mut c_void,
    ) -> i32;
    /// `nghttp2_submit_push_promise`.
    pub fn nghttp2_submit_push_promise(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        nva: *const nghttp2_nv,
        nvlen: usize,
        promised_stream_user_data: *mut c_void,
    ) -> i32;
    /// `nghttp2_submit_shutdown_notice`.
    pub fn nghttp2_submit_shutdown_notice(session: *mut nghttp2_session) -> c_int;
    /// `nghttp2_submit_priority_update`.
    pub fn nghttp2_submit_priority_update(
        session: *mut nghttp2_session,
        flags: u8,
        stream_id: i32,
        field_value: *const u8,
        field_value_len: usize,
    ) -> c_int;
    /// `nghttp2_session_get_stream_effective_recv_data_length`.
    pub fn nghttp2_session_get_stream_effective_recv_data_length(
        session: *mut nghttp2_session,
        stream_id: i32,
    ) -> i32;
    /// `nghttp2_rcbuf_get_buf`.
    pub fn nghttp2_rcbuf_get_buf(rcbuf: *mut nghttp2_rcbuf) -> nghttp2_vec;
    /// `nghttp2_rcbuf_incref`.
    pub fn nghttp2_rcbuf_incref(rcbuf: *mut nghttp2_rcbuf);
    /// `nghttp2_rcbuf_decref`.
    pub fn nghttp2_rcbuf_decref(rcbuf: *mut nghttp2_rcbuf);
}

/// `nghttp2_on_header_callback2`: the `rcbuf` form of the header callback.
pub type on_header_callback2 = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *const nghttp2_frame,
        name: *mut nghttp2_rcbuf,
        value: *mut nghttp2_rcbuf,
        flags: u8,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_on_invalid_frame_recv_callback`.
pub type on_invalid_frame_recv_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *const nghttp2_frame,
        lib_error_code: c_int,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_on_frame_not_send_callback`.
pub type on_frame_not_send_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *const nghttp2_frame,
        lib_error_code: c_int,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_error_callback2`.
///
/// Five parameters, and `lib_error_code` is **second** — not last, and not
/// absent. Getting this wrong is not a compile error at the boundary: nghttp2
/// reads the trampoline's declared arity from the call site, so a missing
/// parameter shifts `user_data` onto a frame field and the deref crashes with a
/// misaligned pointer. That is exactly how this was found.
pub type error_callback2 = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        lib_error_code: c_int,
        msg: *const c_char,
        len: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_send_data_callback`.
pub type send_data_callback = Option<
    unsafe extern "C" fn(
        session: *mut nghttp2_session,
        frame: *mut nghttp2_frame,
        frame_data: *const u8,
        frame_len: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;

/// `nghttp2_vec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct nghttp2_vec {
    pub base: *mut u8,
    pub len: usize,
}

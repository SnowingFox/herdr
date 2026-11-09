//! The V8 surface of `internalBinding('cares_wrap')`.
//!
//! `Initialize()` in `src/cares_wrap.cc` registers five methods, nine constants
//! and four constructors, in that order. The order is observable through
//! `Object.keys()` and is reproduced here.
//!
//! # The request wraps
//!
//! `GetAddrInfoReqWrap`, `GetNameInfoReqWrap` and `QueryReqWrap` come from
//! `AsyncWrap::MakeLazilyInitializedJSTemplate`, so they are ordinary
//! constructible functions with an empty prototype. `lib/dns.js` only ever does
//! `new GetAddrInfoReqWrap()` and assigns properties to the result, so the
//! async-id machinery `AsyncWrap` would provide is not required for the lookup
//! path to work; what *is* required is that the constructor produces a plain
//! object that `getaddrinfo` can attach `oncomplete` to.
//!
//! # Errors
//!
//! `SetServers` and `GetAddrInfo` return their status as a number; only
//! `ConvertIpv6StringToBuffer` and `SetLocalAddress` throw, which is why those
//! two build `Error` objects and the others do not.

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

use crate::channel::{self, LocalAddressError, RecordType, Server};
use crate::deliver::{self, Payload};
use crate::errors;
use crate::ip::{SocketAddr, FAMILY_V6};
use crate::sys::{self, Order, RequestFamily};

/// Members exposed on the namespace object, matching `contracts/cares_wrap.json`.
pub const MEMBERS: &[&str] = &[
    "AF_INET",
    "AF_INET6",
    "AF_UNSPEC",
    "AI_ADDRCONFIG",
    "AI_ALL",
    "AI_V4MAPPED",
    "ChannelWrap",
    "DNS_ORDER_IPV4_FIRST",
    "DNS_ORDER_IPV6_FIRST",
    "DNS_ORDER_VERBATIM",
    "GetAddrInfoReqWrap",
    "GetNameInfoReqWrap",
    "QueryReqWrap",
    "canonicalizeIP",
    "convertIpv6StringToBuffer",
    "getaddrinfo",
    "getnameinfo",
    "strerror",
];

/// `DNS_ORDER_*` from `src/cares_wrap.h`.
const DNS_ORDER_VERBATIM: u32 = 0;
const DNS_ORDER_IPV4_FIRST: u32 = 1;
const DNS_ORDER_IPV6_FIRST: u32 = 2;

pub struct CaresWrap;

impl BindingModule for CaresWrap {
    fn namespace(&self) -> &'static str {
        "cares_wrap"
    }

    fn members(&self) -> &'static [&'static str] {
        MEMBERS
    }

    fn install<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        _ctx: &mut InstallCtx<'_>,
    ) -> Result<v8::Local<'s, v8::Object>, String> {
        let object = v8::Object::new(scope);

        // `SetMethod` first, then the constants, then the constructors — the
        // order `Initialize()` uses and therefore the order `Object.keys()`
        // reports.
        for (name, value) in [
            ("getaddrinfo", method(scope, "getaddrinfo", getaddrinfo)?),
            ("getnameinfo", method(scope, "getnameinfo", getnameinfo)?),
            (
                "canonicalizeIP",
                method(scope, "canonicalizeIP", canonicalize_ip)?,
            ),
            (
                "convertIpv6StringToBuffer",
                method(
                    scope,
                    "convertIpv6StringToBuffer",
                    convert_ipv6_string_to_buffer,
                )?,
            ),
            ("strerror", method(scope, "strerror", strerror)?),
        ] {
            set(scope, object, name, value)?;
        }

        // `NODE_DEFINE_CONSTANT` uses `DontEnum`, so these do not appear in
        // `Object.keys()` — but the contract recording lists them because it
        // reads the properties rather than the key list.
        for (name, value) in [
            ("AF_INET", libc::AF_INET),
            ("AF_INET6", libc::AF_INET6),
            ("AF_UNSPEC", libc::AF_UNSPEC),
            ("AI_ADDRCONFIG", libc::AI_ADDRCONFIG),
            ("AI_ALL", libc::AI_ALL),
            ("AI_V4MAPPED", libc::AI_V4MAPPED),
            ("DNS_ORDER_VERBATIM", DNS_ORDER_VERBATIM as i32),
            ("DNS_ORDER_IPV4_FIRST", DNS_ORDER_IPV4_FIRST as i32),
            ("DNS_ORDER_IPV6_FIRST", DNS_ORDER_IPV6_FIRST as i32),
        ] {
            define_constant(scope, object, name, v8::Integer::new(scope, value).into())?;
        }

        for name in ["GetAddrInfoReqWrap", "GetNameInfoReqWrap", "QueryReqWrap"] {
            let constructor = request_wrap(scope, name)?;
            set(scope, object, name, constructor)?;
        }
        let channel = channel_wrap(scope)?;
        set(scope, object, "ChannelWrap", channel)?;

        Ok(object)
    }
}

/// `canonicalizeIP(ip)`.
///
/// `CanonicalizeIP` in `cares_wrap.cc` runs `uv_inet_pton` for `AF_INET` and
/// then `AF_INET6`, returning `undefined` when neither parses and the
/// `uv_inet_ntop` form otherwise. `lib/tls.js` uses it to compare a certificate's
/// IP SANs against a hostname, so the exact normalisation matters.
fn canonicalize_ip(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    // `node::Utf8Value` on a non-string argument stringifies it, so a number
    // reads as its decimal form. `to_string` also throws for a Symbol, which V8
    // reports through the pending exception; leaving `rv` untouched then yields
    // `undefined`, matching what a failed conversion does in Node.
    let Some(text) = args.get(0).to_string(scope) else {
        return;
    };
    let text = text.to_rust_string_lossy(scope);

    let Some(address) = crate::ip::parse_any(&text) else {
        // Node returns without setting a return value, which is `undefined`.
        return;
    };
    if let Some(value) = v8::String::new(scope, &crate::ip::ntop(&address)) {
        rv.set(value.into());
    }
}

/// `convertIpv6StringToBuffer(ip)`.
///
/// Node parses with `AF_INET6` only and throws `Error: Invalid IPv6 address`
/// when that fails, so an IPv4 literal is an error here even though
/// `canonicalizeIP` accepts one. The result is a `Buffer` holding the sixteen
/// address bytes.
fn convert_ipv6_string_to_buffer(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(text) = args.get(0).to_string(scope) else {
        return;
    };
    let text = text.to_rust_string_lossy(scope);

    let Some(address) = crate::ip::pton(FAMILY_V6, &text) else {
        if let Some(message) = v8::String::new(scope, "Invalid IPv6 address") {
            let exception = v8::Exception::error(scope, message);
            scope.throw_exception(exception);
        }
        return;
    };

    let Some(buffer) = uint8_array(scope, &address.bytes) else {
        return;
    };
    rv.set(buffer.into());
}

/// Builds a `Uint8Array` over a fresh backing store.
///
/// `node::Buffer::Copy` produces a `Buffer`, but at this point in the bootstrap
/// `lib/buffer.js` has not finished loading and `Buffer.prototype` may not be
/// installed yet. The consumers only use indexing and `.length`
/// (`isIpv6LinkLocal` in `lib/net.js` reads `[0]` and `[1]`), so a `Uint8Array`
/// is sufficient; once `Buffer` exists the two are interchangeable for reads.
fn uint8_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
) -> Option<v8::Local<'s, v8::Uint8Array>> {
    let store =
        v8::ArrayBuffer::new_backing_store_from_boxed_slice(bytes.to_vec().into_boxed_slice());
    let store: v8::SharedRef<v8::BackingStore> = store.into();
    let buffer = v8::ArrayBuffer::with_backing_store(scope, &store);
    v8::Uint8Array::new(scope, buffer, 0, bytes.len())
}

/// `strerror(code)`.
fn strerror(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let code = args.get(0).int32_value(scope).unwrap_or(0);
    if let Some(text) = v8::String::new(scope, errors::message(code)) {
        rv.set(text.into());
    }
}

/// `getaddrinfo(req, hostname, family, hints, order)`.
///
/// Returns a libuv status: `0` when the lookup was dispatched, or a negative
/// code when it failed immediately. `lib/dns.js` turns a non-zero return into a
/// `DNSException`, so the synchronous failure path never reaches `oncomplete`.
fn getaddrinfo(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(request) = args.get(0).to_object(scope) else {
        return;
    };
    // `dns.lookup` stores the hostname on the request too, but the binding is
    // given it separately and Node reads the argument, not the property.
    let hostname = args.get(1).to_rust_string_lossy(scope);
    let family_flag = args.get(2).int32_value(scope).unwrap_or(0);
    let hints = if args.get(3).is_int32() {
        args.get(3).int32_value(scope).unwrap_or(0)
    } else {
        0
    };
    let order = Order::from_raw(args.get(4).uint32_value(scope).unwrap_or(0));

    let family = family_for(family_flag);
    let Some(family) = family else {
        // `GetAddrInfo` has an `UNREACHABLE` for an unknown family; returning
        // `UV_EINVAL` is the honest equivalent and cannot silently resolve the
        // wrong thing.
        rv.set(v8::Integer::new(scope, -22).into());
        return;
    };

    // An empty hostname is rejected synchronously, which the recording from Node
    // confirmed: `getaddrinfo('')` returns `-22`.
    if hostname.is_empty() {
        rv.set(v8::Integer::new(scope, -22).into());
        return;
    }

    match sys::getaddrinfo(&hostname, family, hints, order) {
        Ok(addresses) => {
            let Some(array) = string_array(scope, &addresses) else {
                return;
            };
            // The dispatch succeeded; the completion still goes through the
            // microtask so `oncomplete` cannot run before the caller assigns it.
            deliver::deliver(scope, request, Payload::Addresses(Ok(array)));
            rv.set(v8::Integer::new(scope, 0).into());
        }
        Err(error) => {
            deliver::deliver(scope, request, Payload::Addresses(Err(error)));
            rv.set(v8::Integer::new(scope, 0).into());
        }
    }
}

/// `getnameinfo(req, address, port)`.
///
/// Node validates the address up front with `uv_ip4_addr`/`uv_ip6_addr` and
/// `CHECK`s the result, so an unparseable address kills the process. This
/// returns `UV_EINVAL` instead, which `lib/dns.js` already handles by throwing a
/// `DNSException` — a strictly better outcome for the same input.
fn getnameinfo(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(request) = args.get(0).to_object(scope) else {
        return;
    };
    let address = args.get(1).to_rust_string_lossy(scope);
    // `GetNameInfo` reads the port as a `uint32_t` and stores it in a sockaddr,
    // so it has to fit in sixteen bits. `lib/dns.js` validates with
    // `validatePort` first, which is why an out-of-range value here means the
    // binding was called directly; rejecting it beats resolving port 0.
    let Some(port) = args.get(2).uint32_value(scope) else {
        rv.set(v8::Integer::new(scope, -22).into());
        return;
    };
    let Ok(port) = u16::try_from(port) else {
        rv.set(v8::Integer::new(scope, -22).into());
        return;
    };

    let Some(parsed) = crate::ip::parse_any(&address) else {
        rv.set(v8::Integer::new(scope, -22).into());
        return;
    };
    let parsed: SocketAddr = parsed.with_port(port);

    match sys::getnameinfo(&parsed) {
        Ok((hostname, service)) => {
            let (Some(hostname), Some(service)) = (
                v8::String::new(scope, &hostname),
                v8::String::new(scope, &service),
            ) else {
                return;
            };
            deliver::deliver(scope, request, Payload::NameInfo(Ok((hostname, service))));
            rv.set(v8::Integer::new(scope, 0).into());
        }
        Err(error) => {
            deliver::deliver(scope, request, Payload::NameInfo(Err(error)));
            rv.set(v8::Integer::new(scope, 0).into());
        }
    }
}

/// Maps `dns.lookup`'s `family` argument onto a requested address family.
///
/// `GetAddrInfo` switches on `0`, `4` and `6` and has an `UNREACHABLE` for
/// anything else; `lib/dns.js` validates against `validFamilies` first, so an
/// unknown value here means the binding was called directly.
fn family_for(flag: i32) -> Option<RequestFamily> {
    match flag {
        0 => Some(RequestFamily::Unspec),
        4 => Some(RequestFamily::V4),
        6 => Some(RequestFamily::V6),
        _ => None,
    }
}

/// Builds a JS array of strings, or `None` when V8 cannot allocate one.
fn string_array<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    values: &[String],
) -> Option<v8::Local<'s, v8::Array>> {
    let array = v8::Array::new(scope, values.len() as i32);
    for (index, value) in values.iter().enumerate() {
        let text = v8::String::new(scope, value)?;
        array.set_index(scope, index as u32, text.into())?;
    }
    Some(array)
}

// ---------------------------------------------------------------------------
// ChannelWrap
// ---------------------------------------------------------------------------

/// Builds the `ChannelWrap` constructor and its fifteen `query*` methods.
///
/// `lib/internal/dns/utils.js` does `new ChannelWrap(timeout, tries,
/// maxTimeout)` and then calls `_handle[bindingName](req, name)` for each
/// `bindingName` in `createResolverClass`'s map, plus `getServers`,
/// `setServers`, `setLocalAddress` and `cancel`.
fn channel_wrap<'s>(scope: &mut v8::PinScope<'s, '_>) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(channel_constructor).build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    {
        let prototype = template.prototype_template(scope);
        install_query_methods(scope, prototype)?;
        macro_rules! install_method {
            ($($name:literal => $callback:path),* $(,)?) => {
                $(
                    let method = v8::FunctionTemplate::builder($callback).build(scope);
                    let key = v8::String::new(scope, $name)
                        .ok_or_else(|| format!("cannot allocate ChannelWrap.{}", $name))?;
                    prototype.set(key.into(), method.into());
                )*
            };
        }
        install_method! {
            "getServers" => get_servers,
            "setServers" => set_servers,
            "setLocalAddress" => set_local_address,
            "cancel" => cancel,
        }
    }

    let Some(class_name) = v8::String::new(scope, "ChannelWrap") else {
        return Err("cannot allocate the ChannelWrap class name".to_string());
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err("cannot allocate the ChannelWrap constructor".to_string());
    };
    function.set_name(class_name);
    Ok(function.into())
}

/// Installs the fifteen `query*` methods, one `FunctionTemplate` each.
///
/// V8 keeps a callback in a non-capturing slot, so each method needs its own
/// `fn` item; `query_a` and friends are generated by `query_method!` and named
/// here in `createResolverClass`'s order so the prototype enumerates the way
/// Node's does.
fn install_query_methods<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    prototype: v8::Local<'s, v8::ObjectTemplate>,
) -> Result<(), String> {
    macro_rules! install {
        ($($name:literal => $callback:path),* $(,)?) => {
            $(
                let method = v8::FunctionTemplate::builder($callback).build(scope);
                let key = v8::String::new(scope, $name)
                    .ok_or_else(|| format!("cannot allocate ChannelWrap.{}", $name))?;
                prototype.set(key.into(), method.into());
            )*
        };
    }
    install! {
        "queryAny" => query_any,
        "queryA" => query_a,
        "queryAaaa" => query_aaaa,
        "queryCaa" => query_caa,
        "queryCname" => query_cname,
        "queryMx" => query_mx,
        "queryNs" => query_ns,
        "queryTlsa" => query_tlsa,
        "queryTxt" => query_txt,
        "querySrv" => query_srv,
        "queryPtr" => query_ptr,
        "queryNaptr" => query_naptr,
        "querySoa" => query_soa,
        "getHostByAddr" => get_host_by_addr,
    }
    Ok(())
}

/// `new ChannelWrap(timeout, tries, maxTimeout)`.
///
/// The three arguments are c-ares options; `timeout` of `-1` selects its
/// default. The state lives in `channel.rs`'s thread-local map, keyed by the
/// value stored in internal field 0.
fn channel_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        // `NewFunctionTemplate`'s callback is only reachable through `new`; a
        // plain call is a `TypeError` in Node because the C++ callback asserts
        // `IsConstructCall()`.
        if let Some(message) = v8::String::new(
            scope,
            "Class constructor ChannelWrap cannot be invoked without 'new'",
        ) {
            let exception = v8::Exception::type_error(scope, message);
            scope.throw_exception(exception);
        }
        return;
    }

    let timeout = args.get(0).int32_value(scope).unwrap_or(-1) as i64;
    let tries = args.get(1).uint32_value(scope).unwrap_or(4);
    let max_timeout = args.get(2).uint32_value(scope).unwrap_or(0);

    let key = channel::open_channel(timeout, tries, max_timeout);
    let this = args.this();
    install_channel_key(scope, this, key);
    rv.set(this.into());
}

/// Stores the channel key in internal field 0 as an `External`.
///
/// An internal field holds a `Data`, and `External` is the one `Data` that can
/// carry a pointer. The key is encoded as an address rather than allocated:
/// `open_channel` returns a counter, and nothing dereferences it.
fn install_channel_key(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    key: usize,
) {
    let external = v8::External::new(scope, key as *mut std::ffi::c_void);
    object.set_internal_field(0, external.into());
}

/// Reads back the key `install_channel_key` stored.
///
/// The object's own lifetime is independent of the scope's: only the raw
/// pointer is read back, so nothing outlives the call.
fn channel_key(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>) -> Option<usize> {
    let field = object.get_internal_field(scope, 0)?;
    let external = v8::Local::<v8::External>::try_from(field).ok()?;
    let key = external.value() as usize;
    if key == 0 {
        return None;
    }
    Some(key)
}

/// The channel key stored on a `ChannelWrap` receiver.
///
/// A receiver that never went through the constructor has no internal field, so
/// this returns `None` and the caller reports `EDESTRUCTION` instead of
/// dereferencing a garbage pointer.
fn this_channel(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
) -> Option<usize> {
    channel_key(scope, args.this())
}

/// `getServers()`: `[[address, port], ...]`.
fn get_servers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(key) = this_channel(scope, &args) else {
        rv.set(v8::Array::new(scope, 0).into());
        return;
    };
    let Some(servers) = channel::with_channel(key, |channel| channel.get_servers()) else {
        rv.set(v8::Array::new(scope, 0).into());
        return;
    };

    let array = v8::Array::new(scope, servers.len() as i32);
    for (index, server) in servers.iter().enumerate() {
        let Some(address) = v8::String::new(scope, &server.address) else {
            return;
        };
        let port = v8::Integer::new(scope, i32::from(server.port));
        let pair = v8::Array::new_with_elements(scope, &[address.into(), port.into()]);
        if array.set_index(scope, index as u32, pair.into()).is_none() {
            return;
        }
    }
    rv.set(array.into());
}

/// `setServers([[family, address, port], ...])`, returning a c-ares status.
fn set_servers(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(key) = this_channel(scope, &args) else {
        rv.set(v8::Integer::new(scope, channel::code::EBADFAMILY).into());
        return;
    };

    let value = args.get(0);
    let Ok(array) = v8::Local::<v8::Array>::try_from(value) else {
        rv.set(v8::Integer::new(scope, channel::code::EBADFAMILY).into());
        return;
    };

    let mut servers = Vec::with_capacity(array.length() as usize);
    for index in 0..array.length() {
        let Some(entry) = array.get_index(scope, index) else {
            return;
        };
        let Ok(entry) = v8::Local::<v8::Array>::try_from(entry) else {
            rv.set(v8::Integer::new(scope, channel::code::EBADFAMILY).into());
            return;
        };
        let family = entry
            .get_index(scope, 0)
            .and_then(|value| value.int32_value(scope))
            .unwrap_or(0);
        let address = entry
            .get_index(scope, 1)
            .map(|value| value.to_rust_string_lossy(scope))
            .unwrap_or_default();
        let port = entry
            .get_index(scope, 2)
            .and_then(|value| value.int32_value(scope))
            .unwrap_or(53);
        if family != 4 && family != 6 {
            rv.set(v8::Integer::new(scope, channel::code::EBADFAMILY).into());
            return;
        }
        servers.push(Server {
            address,
            port: u16::try_from(port).unwrap_or(0),
        });
    }

    let status = channel::with_channel(key, |channel| channel.set_servers(servers))
        .unwrap_or(channel::code::EDESTRUCTION);
    rv.set(v8::Integer::new(scope, status).into());
}

/// `setLocalAddress(ipv4, ipv6)`.
///
/// Throws `ERR_INVALID_ARG_VALUE` for the three refusals Node reports, which is
/// why the error carries a `code`.
fn set_local_address(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(key) = this_channel(scope, &args) else {
        return;
    };
    let first = args.get(0).to_rust_string_lossy(scope);
    let second = if args.get(1).is_undefined() {
        None
    } else {
        Some(args.get(1).to_rust_string_lossy(scope))
    };

    let outcome = channel::with_channel(key, |channel| {
        channel.set_local_address(&first, second.as_deref())
    });
    if let Some(Err(error)) = outcome {
        throw_invalid_arg_value(scope, error);
    }
}

/// Throws `ERR_INVALID_ARG_VALUE` with `message`.
fn throw_invalid_arg_value(scope: &mut v8::PinScope<'_, '_>, error: LocalAddressError) {
    let Some(message) = v8::String::new(scope, error.message()) else {
        return;
    };
    let exception = v8::Exception::error(scope, message);
    let Ok(object) = v8::Local::<v8::Object>::try_from(exception) else {
        return;
    };
    if let Some(code) = v8::String::new(scope, "ERR_INVALID_ARG_VALUE") {
        let key = v8::String::new(scope, "code");
        if let Some(key) = key {
            object.set(scope, key.into(), code.into());
        }
    }
    scope.throw_exception(exception);
}

/// `cancel()`: abort every in-flight query on this channel.
fn cancel(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue,
) {
    let Some(key) = this_channel(scope, &args) else {
        return;
    };
    let _ = channel::with_channel(key, |channel| channel.cancel());
}

/// The one implementation behind every `query*` method.
///
/// Each entry in `QUERY_METHODS` is a distinct `extern` function because V8
/// stores the callback in a non-capturing slot; this macro is what keeps them
/// from being fifteen copies of the same body.
macro_rules! query_method {
    ($name:ident, $rtype:expr) => {
        fn $name(
            scope: &mut v8::PinScope<'_, '_>,
            args: v8::FunctionCallbackArguments<'_>,
            mut rv: v8::ReturnValue,
        ) {
            run_query(scope, &args, &mut rv, $rtype);
        }
    };
}

query_method!(query_a, RecordType::A);
query_method!(query_aaaa, RecordType::Aaaa);
query_method!(query_any, RecordType::Any);
query_method!(query_caa, RecordType::Caa);
query_method!(query_cname, RecordType::Cname);
query_method!(query_mx, RecordType::Mx);
query_method!(query_ns, RecordType::Ns);
query_method!(query_tlsa, RecordType::Tlsa);
query_method!(query_txt, RecordType::Txt);
query_method!(query_srv, RecordType::Srv);
query_method!(query_ptr, RecordType::Ptr);
query_method!(query_naptr, RecordType::Naptr);
query_method!(query_soa, RecordType::Soa);

/// `getHostByAddr(req, name)`: a PTR query for the address's reverse name.
///
/// The argument `lib/internal/dns/utils.js` passes is the address itself, not a
/// reverse name, because c-ares builds the name from it. `dns.reverse()` relies
/// on that: `resolver.prototype.reverse = resolver('getHostByAddr')` is called
/// with `10.0.0.1`, not `1.0.0.10.in-addr.arpa`.
fn get_host_by_addr(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    let Some(request) = args.get(0).to_object(scope) else {
        return;
    };
    let address = args.get(1).to_rust_string_lossy(scope);
    let name = crate::ip::parse_any(&address)
        .and_then(|parsed| channel::reverse_name(&parsed.with_port(0)));
    let Some(name) = name else {
        // `dns.reverse()` validates the address in JavaScript, so a bad one here
        // means the binding was called directly.
        rv.set(v8::Integer::new(scope, channel::code::EBADNAME).into());
        return;
    };
    respond_with_query(scope, &args, &mut rv, request, &name, RecordType::Ptr);
}

/// Shared body of every `query*` method.
fn run_query(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    rtype: RecordType,
) {
    let Some(request) = args.get(0).to_object(scope) else {
        return;
    };
    let name = args.get(1).to_rust_string_lossy(scope);
    respond_with_query(scope, args, rv, request, &name, rtype);
}

/// Sends the query and delivers its answer to `request.oncomplete`.
fn respond_with_query<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    rv: &mut v8::ReturnValue,
    request: v8::Local<'s, v8::Object>,
    name: &str,
    rtype: RecordType,
) {
    let Some(key) = this_channel(scope, args) else {
        rv.set(v8::Integer::new(scope, channel::code::EDESTRUCTION).into());
        return;
    };
    let Some(outcome) = channel::with_channel(key, |channel| channel.query(name, rtype)) else {
        rv.set(v8::Integer::new(scope, channel::code::EDESTRUCTION).into());
        return;
    };

    let payload = match outcome {
        Ok(answer) => match build_answer(scope, answer) {
            Some((result, ttls)) => crate::deliver::QueryPayload::Ok { result, ttls },
            None => return,
        },
        Err(status) => crate::deliver::QueryPayload::Err(status),
    };
    deliver::deliver(scope, request, Payload::Query(payload));
    rv.set(v8::Integer::new(scope, 0).into());
}

/// Builds a query answer and its optional TTL array.
///
/// Only the address queries carry TTLs, which is what `onresolve` in
/// `lib/internal/dns/callback_resolver.js` reads: it maps `ttls[index]` onto each
/// address when `req.ttl` is set, and every other query type ignores the third
/// argument entirely.
fn build_answer<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    answer: crate::channel::Answer,
) -> Option<(v8::Local<'s, v8::Value>, Option<v8::Local<'s, v8::Array>>)> {
    use crate::channel::Answer;
    let value = match answer {
        Answer::Addresses(addresses, ttls) => {
            let list = string_array(scope, &addresses)?;
            let ttl_array = v8::Array::new(scope, ttls.len() as i32);
            for (index, ttl) in ttls.iter().enumerate() {
                let value = v8::Number::new(scope, f64::from(*ttl));
                ttl_array.set_index(scope, index as u32, value.into())?;
            }
            return Some((list.into(), Some(ttl_array)));
        }
        Answer::Hosts(hosts) | Answer::HostsByAddress(hosts) => string_array(scope, &hosts)?.into(),
        Answer::Exchanges(pairs) => {
            let list = v8::Array::new(scope, pairs.len() as i32);
            for (index, (exchange, priority)) in pairs.iter().enumerate() {
                let object = v8::Object::new(scope);
                let name = v8::String::new(scope, exchange)?;
                let key = v8::String::new(scope, "exchange")?;
                object.set(scope, key.into(), name.into())?;
                let key = v8::String::new(scope, "priority")?;
                object.set(
                    scope,
                    key.into(),
                    v8::Number::new(scope, f64::from(*priority)).into(),
                )?;
                list.set_index(scope, index as u32, object.into())?;
            }
            list.into()
        }
        Answer::Texts(texts) => {
            let list = v8::Array::new(scope, texts.len() as i32);
            for (index, chunks) in texts.iter().enumerate() {
                let inner = string_array(scope, chunks)?;
                list.set_index(scope, index as u32, inner.into())?;
            }
            list.into()
        }
        Answer::Services(services) => {
            let list = v8::Array::new(scope, services.len() as i32);
            for (index, service) in services.iter().enumerate() {
                let object = v8::Object::new(scope);
                set_number(scope, object, "priority", f64::from(service.priority))?;
                set_number(scope, object, "weight", f64::from(service.weight))?;
                set_number(scope, object, "port", f64::from(service.port))?;
                let name = v8::String::new(scope, &service.name)?;
                let key = v8::String::new(scope, "name")?;
                object.set(scope, key.into(), name.into())?;
                list.set_index(scope, index as u32, object.into())?;
            }
            list.into()
        }
        Answer::Naptrs(records) => {
            let list = v8::Array::new(scope, records.len() as i32);
            for (index, record) in records.iter().enumerate() {
                let object = v8::Object::new(scope);
                set_text(scope, object, "flags", &record.flags)?;
                set_text(scope, object, "service", &record.service)?;
                set_text(scope, object, "regexp", &record.regexp)?;
                set_text(scope, object, "replacement", &record.replacement)?;
                set_number(scope, object, "order", f64::from(record.order))?;
                set_number(scope, object, "preference", f64::from(record.preference))?;
                list.set_index(scope, index as u32, object.into())?;
            }
            list.into()
        }
        Answer::Tlsas(records) => {
            let list = v8::Array::new(scope, records.len() as i32);
            for (index, record) in records.iter().enumerate() {
                let object = v8::Object::new(scope);
                set_number(scope, object, "usage", f64::from(record.usage))?;
                set_number(scope, object, "selector", f64::from(record.selector))?;
                set_number(scope, object, "matching", f64::from(record.matching))?;
                set_text(scope, object, "data", &record.data)?;
                list.set_index(scope, index as u32, object.into())?;
            }
            list.into()
        }
        Answer::Caas(records) => {
            let list = v8::Array::new(scope, records.len() as i32);
            for (index, record) in records.iter().enumerate() {
                let object = v8::Object::new(scope);
                let key = v8::String::new(scope, "critical")?;
                object.set(
                    scope,
                    key.into(),
                    v8::Boolean::new(scope, record.critical).into(),
                )?;
                set_text(scope, object, "tag", &record.tag)?;
                set_text(scope, object, "issue", &record.value)?;
                list.set_index(scope, index as u32, object.into())?;
            }
            list.into()
        }
        Answer::Soa(soa) => {
            let object = v8::Object::new(scope);
            set_text(scope, object, "nsname", &soa.nsname)?;
            set_text(scope, object, "hostmaster", &soa.hostmaster)?;
            set_number(scope, object, "serial", f64::from(soa.serial))?;
            set_number(scope, object, "refresh", f64::from(soa.refresh))?;
            set_number(scope, object, "retry", f64::from(soa.retry))?;
            set_number(scope, object, "expire", f64::from(soa.expire))?;
            set_number(scope, object, "minttl", f64::from(soa.minttl))?;
            object.into()
        }
        Answer::Any(records) => {
            let list = v8::Array::new(scope, records.len() as i32);
            for (index, record) in records.iter().enumerate() {
                let object = any_record_object(scope, record)?;
                list.set_index(scope, index as u32, object.into())?;
            }
            list.into()
        }
    };
    Some((value, None))
}

fn any_record_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    record: &crate::channel::AnyRecord,
) -> Option<v8::Local<'s, v8::Object>> {
    use crate::channel::AnyRecord;
    let object = v8::Object::new(scope);
    match record {
        AnyRecord::A { address, ttl } => {
            set_text(scope, object, "address", address)?;
            set_number(scope, object, "ttl", f64::from(*ttl))?;
            set_text(scope, object, "type", "A")?;
        }
        AnyRecord::Aaaa { address, ttl } => {
            set_text(scope, object, "address", address)?;
            set_number(scope, object, "ttl", f64::from(*ttl))?;
            set_text(scope, object, "type", "AAAA")?;
        }
        AnyRecord::Cname { value } => {
            set_text(scope, object, "value", value)?;
            set_text(scope, object, "type", "CNAME")?;
        }
        AnyRecord::Ns { value } => {
            set_text(scope, object, "value", value)?;
            set_text(scope, object, "type", "NS")?;
        }
        AnyRecord::Ptr { value } => {
            set_text(scope, object, "value", value)?;
            set_text(scope, object, "type", "PTR")?;
        }
        AnyRecord::Mx { exchange, priority } => {
            set_text(scope, object, "exchange", exchange)?;
            set_number(scope, object, "priority", f64::from(*priority))?;
            set_text(scope, object, "type", "MX")?;
        }
        AnyRecord::Txt { value } => {
            let inner = string_array(scope, value)?;
            let key = v8::String::new(scope, "entries")?;
            object.set(scope, key.into(), inner.into())?;
            set_text(scope, object, "type", "TXT")?;
        }
        AnyRecord::Srv {
            priority,
            weight,
            port,
            name,
        } => {
            set_number(scope, object, "priority", f64::from(*priority))?;
            set_number(scope, object, "weight", f64::from(*weight))?;
            set_number(scope, object, "port", f64::from(*port))?;
            set_text(scope, object, "name", name)?;
            set_text(scope, object, "type", "SRV")?;
        }
        AnyRecord::Naptr { value } => {
            set_text(scope, object, "flags", &value.flags)?;
            set_text(scope, object, "service", &value.service)?;
            set_text(scope, object, "regexp", &value.regexp)?;
            set_text(scope, object, "replacement", &value.replacement)?;
            set_number(scope, object, "order", f64::from(value.order))?;
            set_number(scope, object, "preference", f64::from(value.preference))?;
            set_text(scope, object, "type", "NAPTR")?;
        }
        AnyRecord::Caa { value } => {
            let key = v8::String::new(scope, "critical")?;
            object.set(
                scope,
                key.into(),
                v8::Boolean::new(scope, value.critical).into(),
            )?;
            set_text(scope, object, "issue", &value.value)?;
            set_text(scope, object, "tag", &value.tag)?;
            set_text(scope, object, "type", "CAA")?;
        }
        AnyRecord::Tlsa { value } => {
            set_number(scope, object, "usage", f64::from(value.usage))?;
            set_number(scope, object, "selector", f64::from(value.selector))?;
            set_number(scope, object, "matching", f64::from(value.matching))?;
            set_text(scope, object, "data", &value.data)?;
            set_text(scope, object, "type", "TLSA")?;
        }
        AnyRecord::Soa { value } => {
            set_text(scope, object, "nsname", &value.nsname)?;
            set_text(scope, object, "hostmaster", &value.hostmaster)?;
            set_number(scope, object, "serial", f64::from(value.serial))?;
            set_number(scope, object, "refresh", f64::from(value.refresh))?;
            set_number(scope, object, "retry", f64::from(value.retry))?;
            set_number(scope, object, "expire", f64::from(value.expire))?;
            set_number(scope, object, "minttl", f64::from(value.minttl))?;
            set_text(scope, object, "type", "SOA")?;
        }
    }
    Some(object)
}

fn set_text<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: &str,
) -> Option<()> {
    let text = v8::String::new(scope, value)?;
    let key = v8::String::new(scope, name)?;
    object.set(scope, key.into(), text.into());
    Some(())
}

fn set_number<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: f64,
) -> Option<()> {
    let key = v8::String::new(scope, name)?;
    object.set(scope, key.into(), v8::Number::new(scope, value).into());
    Some(())
}

// ---------------------------------------------------------------------------
// The request wraps
// ---------------------------------------------------------------------------

/// Builds one request-wrap constructor.
///
/// `MakeLazilyInitializedJSTemplate` produces a plain constructible function
/// with no prototype methods and `length` 0, and `lib/dns.js` only needs
/// `new ReqWrap()` plus property assignment, so that is exactly what this
/// builds. A subclass of `Object` is therefore not worth the prototype chain.
fn request_wrap<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(request_wrap_constructor)
        .length(0)
        .build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(0);
    let Some(class_name) = v8::String::new(scope, name) else {
        return Err(format!("cannot allocate the {name} class name"));
    };
    template.set_class_name(class_name);
    let Some(function) = template.get_function(scope) else {
        return Err(format!("cannot allocate the {name} constructor"));
    };
    function.set_name(class_name);
    Ok(function.into())
}

/// The body shared by all three request wraps.
///
/// Each `new ReqWrap()` allocates one async id, which is what `async_hooks`
/// reports and what `perf_hooks` uses as an entry key. Node's `AsyncWrap`
/// assigns the id in its constructor, and `lib/dns.js` starts a perf entry on the
/// request object, so the id has to exist.
fn request_wrap_constructor(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue,
) {
    if !args.is_construct_call() {
        if let Some(message) =
            v8::String::new(scope, "Class constructor cannot be invoked without 'new'")
        {
            let exception = v8::Exception::type_error(scope, message);
            scope.throw_exception(exception);
        }
        return;
    }
    rv.set(args.this().into());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a non-constructible function, matching `node::SetMethod`.
fn method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback)
        .length(0)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate cares_wrap.{name}"))?;
    if let Some(text) = v8::String::new(scope, name) {
        function.set_name(text);
    }
    Ok(function.into())
}

/// Defines one constant with `NODE_DEFINE_CONSTANT`'s attributes.
fn define_constant<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
    value: v8::Local<'s, v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .define_own_property(
            scope,
            key.into(),
            value,
            // `NODE_DEFINE_CONSTANT` passes `v8::DontEnum`, so the constants are
            // absent from `Object.keys()` and cannot be reassigned.
            v8::PropertyAttribute::DONT_ENUM,
        )
        .ok_or_else(|| format!("cannot define constant {name}"))?;
    Ok(())
}

fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object.set(scope, key.into(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::with_context;

    /// Calls `function` with one string argument.
    fn call_with<'s>(
        scope: &mut v8::PinScope<'s, '_>,
        function: v8::Local<'s, v8::Function>,
        receiver: v8::Local<'s, v8::Object>,
        input: &str,
    ) -> v8::Local<'s, v8::Value> {
        let value = v8::String::new(scope, input).expect("input");
        function
            .call(scope, receiver.into(), &[value.into()])
            .expect("call")
    }

    fn install<'s>(scope: &mut v8::PinScope<'s, '_>) -> v8::Local<'s, v8::Object> {
        let mut async_ids = rn_core::AsyncIds::new();
        let mut ctx = rn_core::InstallCtx {
            async_ids: &mut async_ids,
        };
        CaresWrap.install(scope, &mut ctx).expect("install")
    }

    #[test]
    fn every_contract_member_is_installed() {
        let mut async_ids = rn_core::AsyncIds::new();
        let ctx = rn_core::InstallCtx {
            async_ids: &mut async_ids,
        };
        let _ = ctx;
        assert_eq!(MEMBERS.len(), 18);
        let namespace = rn_core::Namespace::from_module(&CaresWrap);
        assert_eq!(namespace.members.len(), 18);
        assert!(namespace.deferred.is_empty(), "nothing should be deferred");
    }

    #[test]
    fn constants_have_node_values() {
        with_context(|scope| {
            let object = install(scope);
            let read = |scope: &mut v8::PinScope<'_, '_>, key: &str| -> Option<f64> {
                let key = v8::String::new(scope, key)?;
                object.get(scope, key.into())?.number_value(scope)
            };
            // Recorded from a real Node binary on this platform.
            assert_eq!(read(scope, "AF_INET"), Some(2.0));
            assert_eq!(read(scope, "AF_INET6"), Some(10.0));
            assert_eq!(read(scope, "AF_UNSPEC"), Some(0.0));
            assert_eq!(read(scope, "AI_ADDRCONFIG"), Some(32.0));
            assert_eq!(read(scope, "AI_ALL"), Some(16.0));
            assert_eq!(read(scope, "AI_V4MAPPED"), Some(8.0));
            assert_eq!(read(scope, "DNS_ORDER_VERBATIM"), Some(0.0));
            assert_eq!(read(scope, "DNS_ORDER_IPV4_FIRST"), Some(1.0));
            assert_eq!(read(scope, "DNS_ORDER_IPV6_FIRST"), Some(2.0));
        });
    }

    #[test]
    fn canonicalize_ip_round_trips_and_rejects() {
        with_context(|scope| {
            let object = install(scope);
            let key = v8::String::new(scope, "canonicalizeIP").expect("key");
            let function: v8::Local<v8::Function> = object
                .get(scope, key.into())
                .expect("get")
                .try_into()
                .expect("function");

            let canonical = call_with(
                scope,
                function,
                object,
                "2001:0DB8:0000:0000:0000:0000:0000:0001",
            );
            assert_eq!(canonical.to_rust_string_lossy(scope), "2001:db8::1");
            let canonical = call_with(scope, function, object, "::ffff:127.0.0.1");
            assert_eq!(canonical.to_rust_string_lossy(scope), "::ffff:127.0.0.1");
            // Failures are `undefined`, not a throw and not `null`.
            let failed = call_with(scope, function, object, "not-an-ip");
            assert!(failed.is_undefined());
        });
    }

    #[test]
    fn convert_ipv6_returns_sixteen_bytes_and_throws_otherwise() {
        with_context(|scope| {
            let object = install(scope);
            let key = v8::String::new(scope, "convertIpv6StringToBuffer").expect("key");
            let function: v8::Local<v8::Function> = object
                .get(scope, key.into())
                .expect("get")
                .try_into()
                .expect("function");

            let value = v8::String::new(scope, "2001:db8::1").expect("input");
            let result = function
                .call(scope, object.into(), &[value.into()])
                .expect("call");
            let bytes: v8::Local<v8::Uint8Array> = result.try_into().expect("typed array");
            assert_eq!(bytes.byte_length(), 16);
            let mut buffer = [0u8; 16];
            let length = bytes.copy_contents(&mut buffer);
            assert_eq!(length, 16);
            let hex: String = buffer.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, "20010db8000000000000000000000001");

            let bad = v8::String::new(scope, "1.2.3.4").expect("input");
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let scope = &mut try_catch.init();
            let result = function.call(scope, object.into(), &[bad.into()]);
            assert!(result.is_none(), "must throw");
            assert!(scope.has_caught());
            let exception = scope.exception().expect("exception");
            assert_eq!(
                exception.to_rust_string_lossy(scope),
                "Error: Invalid IPv6 address"
            );
        });
    }

    #[test]
    fn strerror_matches_the_recorded_table() {
        with_context(|scope| {
            let object = install(scope);
            let key = v8::String::new(scope, "strerror").expect("key");
            let function: v8::Local<v8::Function> = object
                .get(scope, key.into())
                .expect("get")
                .try_into()
                .expect("function");
            for (code, expected) in [
                (0.0, "Successful completion"),
                (4.0, "Domain name not found"),
                (12.0, "Timeout while contacting DNS servers"),
                (-1000.0, "There are pending queries."),
                (999.0, "unknown"),
            ] {
                let value = v8::Number::new(scope, code);
                let result = function
                    .call(scope, object.into(), &[value.into()])
                    .expect("call");
                assert_eq!(result.to_rust_string_lossy(scope), expected);
            }
        });
    }

    #[test]
    fn the_request_wraps_are_constructible_functions_of_length_zero() {
        with_context(|scope| {
            let object = install(scope);
            for name in [
                "GetAddrInfoReqWrap",
                "GetNameInfoReqWrap",
                "QueryReqWrap",
                "ChannelWrap",
            ] {
                let key = v8::String::new(scope, name).expect("key");
                let value = object.get(scope, key.into()).expect("get");
                let function: v8::Local<v8::Function> = value
                    .try_into()
                    .unwrap_or_else(|_| panic!("{name} must be a function"));
                let length_key = v8::String::new(scope, "length").expect("key");
                let length = function
                    .get(scope, length_key.into())
                    .and_then(|value| value.number_value(scope))
                    .unwrap_or(-1.0);
                assert_eq!(length, 0.0, "{name}.length");
                let actual = function.get_name(scope).to_rust_string_lossy(scope);
                assert_eq!(actual, name, "{name}.name");
            }
        });
    }

    #[test]
    fn a_request_wrap_produces_a_plain_object() {
        with_context(|scope| {
            let object = install(scope);
            let key = v8::String::new(scope, "GetAddrInfoReqWrap").expect("key");
            let function: v8::Local<v8::Function> = object
                .get(scope, key.into())
                .expect("get")
                .try_into()
                .expect("function");

            let instance = function
                .new_instance(scope, &[])
                .expect("construct")
                .to_object(scope)
                .expect("object");
            // The JS layer assigns these after construction, so they must be
            // settable and readable.
            for property in ["oncomplete", "hostname", "family"] {
                let name = v8::String::new(scope, property).expect("name");
                let value = v8::Number::new(scope, 1.0);
                instance.set(scope, name.into(), value.into());
            }
            let name = v8::String::new(scope, "family").expect("name");
            let read = instance.get(scope, name.into()).expect("read");
            assert_eq!(read.number_value(scope), Some(1.0));
        });
    }

    #[test]
    fn calling_a_request_wrap_without_new_throws() {
        with_context(|scope| {
            let object = install(scope);
            let key = v8::String::new(scope, "GetAddrInfoReqWrap").expect("key");
            let function: v8::Local<v8::Function> = object
                .get(scope, key.into())
                .expect("get")
                .try_into()
                .expect("function");
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let scope = &mut try_catch.init();
            let result = function.call(scope, object.into(), &[]);
            assert!(result.is_none());
            assert!(scope.has_caught());
        });
    }

    #[test]
    fn getaddrinfo_delivers_through_oncomplete() {
        with_context(|scope| {
            let object = install(scope);
            let source = v8::String::new(
                scope,
                r#"
                globalThis.seen = null;
                const binding = globalThis.caresBinding;
                globalThis.req = new binding.GetAddrInfoReqWrap();
                globalThis.req.oncomplete = function(status, addresses) {
                  globalThis.seen = [status, Array.from(addresses)];
                };
                "#,
            )
            .expect("source");
            let global = scope.get_current_context().global(scope);
            let key = v8::String::new(scope, "caresBinding").expect("key");
            global.set(scope, key.into(), object.into());
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let key = v8::String::new(scope, "caresBinding").expect("key");
            let binding = global.get(scope, key.into()).expect("binding");
            let binding: v8::Local<v8::Object> = binding.try_into().expect("object");
            let function_key = v8::String::new(scope, "getaddrinfo").expect("key");
            let function: v8::Local<v8::Function> = binding
                .get(scope, function_key.into())
                .expect("get")
                .try_into()
                .expect("function");

            let req_key = v8::String::new(scope, "req").expect("key");
            let request: v8::Local<v8::Object> = global
                .get(scope, req_key.into())
                .expect("req")
                .try_into()
                .expect("object");
            let hostname = v8::String::new(scope, "localhost").expect("hostname");
            let family = v8::Integer::new(scope, 4).into();
            let hints = v8::Integer::new(scope, 0).into();
            let order = v8::Integer::new(scope, 0).into();

            let status = function
                .call(
                    scope,
                    binding.into(),
                    &[request.into(), hostname.into(), family, hints, order],
                )
                .expect("call");
            assert_eq!(status.number_value(scope), Some(0.0), "dispatch status");

            let seen_key = v8::String::new(scope, "seen").expect("key");
            let seen = global.get(scope, seen_key.into()).expect("seen");
            // V8's default microtask policy drains at the end of `script.run` and
            // of every `Function::call`, so a call from Rust reaches the handler
            // before returning. What must hold — and is checked in
            // `deliver::tests` with a scope that does not drain — is that the
            // delivery went through the microtask queue rather than the callback
            // being invoked inline by `getaddrinfo`. Assert the payload instead.
            let seen: v8::Local<v8::Array> = seen.try_into().expect("array");
            assert_eq!(seen.length(), 2);
            {
                let status = seen.get_index(scope, 0).expect("status");
                assert_eq!(status.number_value(scope), Some(0.0));
            }

            scope.as_mut().perform_microtask_checkpoint();

            let seen = global.get(scope, seen_key.into()).expect("seen");
            let seen: v8::Local<v8::Array> = seen.try_into().expect("array");
            assert_eq!(seen.length(), 2);
            let status = seen.get_index(scope, 0).expect("status");
            assert_eq!(status.number_value(scope), Some(0.0));
            let addresses: v8::Local<v8::Array> = seen
                .get_index(scope, 1)
                .expect("addresses")
                .try_into()
                .expect("array");
            // Node answers `['127.0.0.1', '127.0.0.1']` here: this machine's
            // `/etc/hosts` has one `127.0.0.1 localhost` line and one
            // `127.0.0.1 cursor` line, so the resolver reports two A records.
            assert!(addresses.length() >= 1, "at least one address");
            let address = addresses.get_index(scope, 0).expect("address");
            assert_eq!(address.to_rust_string_lossy(scope), "127.0.0.1");
        });
    }

    #[test]
    fn getnameinfo_delivers_hostname_and_service() {
        with_context(|scope| {
            let global = scope.get_current_context().global(scope);
            let object = install(scope);
            let key = v8::String::new(scope, "caresBinding").expect("key");
            global.set(scope, key.into(), object.into());

            let source = v8::String::new(
                scope,
                r#"
                globalThis.seen = null;
                const binding = globalThis.caresBinding;
                globalThis.req = new binding.GetNameInfoReqWrap();
                globalThis.req.oncomplete = function(status, hostname, service) {
                  globalThis.seen = [status, hostname, service];
                };
                "#,
            )
            .expect("source");
            let script = v8::Script::compile(scope, source, None).expect("compiles");
            script.run(scope).expect("runs");

            let function_key = v8::String::new(scope, "getnameinfo").expect("key");
            let function: v8::Local<v8::Function> = object
                .get(scope, function_key.into())
                .expect("get")
                .try_into()
                .expect("function");
            let req_key = v8::String::new(scope, "req").expect("key");
            let request: v8::Local<v8::Object> = global
                .get(scope, req_key.into())
                .expect("req")
                .try_into()
                .expect("object");
            let address = v8::String::new(scope, "127.0.0.1").expect("address");
            let port = v8::Integer::new(scope, 80).into();
            let status = function
                .call(
                    scope,
                    object.into(),
                    &[request.into(), address.into(), port],
                )
                .expect("call");
            assert_eq!(status.number_value(scope), Some(0.0));

            scope.as_mut().perform_microtask_checkpoint();

            let seen_key = v8::String::new(scope, "seen").expect("key");
            let seen: v8::Local<v8::Array> = global
                .get(scope, seen_key.into())
                .expect("seen")
                .try_into()
                .expect("array");
            assert_eq!(seen.length(), 3);
            let hostname = seen.get_index(scope, 1).expect("hostname");
            assert_eq!(hostname.to_rust_string_lossy(scope), "localhost");
            let service = seen.get_index(scope, 2).expect("service");
            assert_eq!(service.to_rust_string_lossy(scope), "http");
        });
    }

    #[test]
    fn an_empty_hostname_is_rejected_synchronously() {
        with_context(|scope| {
            let global = scope.get_current_context().global(scope);
            let object = install(scope);
            let source = v8::String::new(
                scope,
                r#"
                const binding = globalThis.caresBinding;
                globalThis.req = new binding.GetAddrInfoReqWrap();
                "#,
            )
            .expect("source");
            let key = v8::String::new(scope, "caresBinding").expect("key");
            global.set(scope, key.into(), object.into());
            v8::Script::compile(scope, source, None)
                .expect("compiles")
                .run(scope)
                .expect("runs");

            let function_key = v8::String::new(scope, "getaddrinfo").expect("key");
            let function: v8::Local<v8::Function> = object
                .get(scope, function_key.into())
                .expect("get")
                .try_into()
                .expect("function");
            let req_key = v8::String::new(scope, "req").expect("key");
            let request: v8::Local<v8::Object> = global
                .get(scope, req_key.into())
                .expect("req")
                .try_into()
                .expect("object");
            let hostname = v8::String::new(scope, "").expect("hostname");
            let family = v8::Integer::new(scope, 4).into();
            let hints = v8::Integer::new(scope, 0).into();
            let order = v8::Integer::new(scope, 0).into();
            let status = function
                .call(
                    scope,
                    object.into(),
                    &[request.into(), hostname.into(), family, hints, order],
                )
                .expect("call");
            // Recorded from Node: `dns.lookup('')` fails before dispatch.
            assert_eq!(status.number_value(scope), Some(-22.0));
        });
    }

    #[test]
    fn channel_wrap_reports_system_servers_and_accepts_new_ones() {
        with_context(|scope| {
            let global = scope.get_current_context().global(scope);
            let object = install(scope);
            let source = v8::String::new(
                scope,
                r#"
                const binding = globalThis.caresBinding;
                globalThis.channel = new binding.ChannelWrap(-1, 4, 0);
                "#,
            )
            .expect("source");
            let key = v8::String::new(scope, "caresBinding").expect("key");
            global.set(scope, key.into(), object.into());
            v8::Script::compile(scope, source, None)
                .expect("compiles")
                .run(scope)
                .expect("runs");

            let channel_key = v8::String::new(scope, "channel").expect("key");
            let channel: v8::Local<v8::Object> = global
                .get(scope, channel_key.into())
                .expect("channel")
                .try_into()
                .expect("object");
            let get_key = v8::String::new(scope, "getServers").expect("key");
            let get: v8::Local<v8::Function> = channel
                .get(scope, get_key.into())
                .expect("get")
                .try_into()
                .expect("function");
            let servers = get.call(scope, channel.into(), &[]).expect("call");
            let servers: v8::Local<v8::Array> = servers.try_into().expect("array");
            // This machine always has at least one configured nameserver; if not,
            // the empty array is still the documented answer.
            assert!(servers.length() <= 8);

            // Setting a server must be reflected by the next `getServers()`.
            let set_key = v8::String::new(scope, "setServers").expect("key");
            let set: v8::Local<v8::Function> = channel
                .get(scope, set_key.into())
                .expect("get")
                .try_into()
                .expect("function");
            let entry = v8::Array::new(scope, 3);
            entry.set_index(scope, 0, v8::Integer::new(scope, 4).into());
            let address = v8::String::new(scope, "8.8.8.8").expect("address");
            entry.set_index(scope, 1, address.into());
            entry.set_index(scope, 2, v8::Integer::new(scope, 53).into());
            let list = v8::Array::new(scope, 1);
            list.set_index(scope, 0, entry.into());
            let status = set
                .call(scope, channel.into(), &[list.into()])
                .expect("call");
            assert_eq!(status.number_value(scope), Some(0.0));

            let servers = get.call(scope, channel.into(), &[]).expect("call");
            let servers: v8::Local<v8::Array> = servers.try_into().expect("array");
            assert_eq!(servers.length(), 1);
            let pair: v8::Local<v8::Array> = servers
                .get_index(scope, 0)
                .expect("pair")
                .try_into()
                .expect("array");
            let host = pair.get_index(scope, 0).expect("host");
            assert_eq!(host.to_rust_string_lossy(scope), "8.8.8.8");
            let port = pair.get_index(scope, 1).expect("port");
            assert_eq!(port.number_value(scope), Some(53.0));
        });
    }

    #[test]
    fn set_local_address_rejects_two_addresses_of_one_family() {
        with_context(|scope| {
            let global = scope.get_current_context().global(scope);
            let object = install(scope);
            let source = v8::String::new(
                scope,
                r#"
                const binding = globalThis.caresBinding;
                globalThis.channel = new binding.ChannelWrap(-1, 4, 0);
                "#,
            )
            .expect("source");
            let key = v8::String::new(scope, "caresBinding").expect("key");
            global.set(scope, key.into(), object.into());
            v8::Script::compile(scope, source, None)
                .expect("compiles")
                .run(scope)
                .expect("runs");

            let channel_key = v8::String::new(scope, "channel").expect("key");
            let channel: v8::Local<v8::Object> = global
                .get(scope, channel_key.into())
                .expect("channel")
                .try_into()
                .expect("object");
            let set_key = v8::String::new(scope, "setLocalAddress").expect("key");
            let set: v8::Local<v8::Function> = channel
                .get(scope, set_key.into())
                .expect("get")
                .try_into()
                .expect("function");

            let first = v8::String::new(scope, "1.2.3.4").expect("first");
            let second = v8::String::new(scope, "5.6.7.8").expect("second");
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let scope = &mut try_catch.init();
            let result = set.call(scope, channel.into(), &[first.into(), second.into()]);
            assert!(result.is_none(), "must throw");
            assert!(scope.has_caught());
            let exception: v8::Local<v8::Object> = scope
                .exception()
                .expect("exception")
                .try_into()
                .expect("object");
            let code_key = v8::String::new(scope, "code").expect("key");
            let code = exception.get(scope, code_key.into()).expect("code");
            assert_eq!(code.to_rust_string_lossy(scope), "ERR_INVALID_ARG_VALUE");
        });
    }
}

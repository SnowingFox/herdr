//! `internalBinding('block_list')` for rustnode.
//!
//! The JavaScript half is `lib/internal/blocklist.js` and
//! `lib/internal/socketaddress.js`, both unchanged Node code, so the contract is
//! `src/node_sockaddr.cc`'s. Four members:
//!
//! * `BlockList` — a constructor whose instances hold the rules. The JavaScript
//!   wrapper keeps it in a private symbol and exposes `addAddress`, `check`,
//!   `rules`, `size` and the rest on top of it.
//! * `SocketAddress` — `new SocketAddress(address, port, family, flowlabel)`,
//!   the value type rules are written in. `lib/internal/socketaddress.js`
//!   validates the arguments in JavaScript and this only sees the coerced four.
//! * `AF_INET` and `AF_INET6` — the constants both modules pass back in.
//!
//! # Why the methods are type-strict
//!
//! Node's C++ guards every argument with `CHECK(args[0]->IsString())` and
//! friends. A binding that instead *coerces* hides a caller's bug: an object
//! would arrive as `[object Object]`. So a wrong type throws a `TypeError`,
//! which is the only thing a `CHECK` can become from Rust.
//!
//! # Where the state lives
//!
//! Each instance owns one boxed allocation whose pointer sits in internal field
//! zero, the same arrangement `rn-bind-http-parser` and the tty wrap use. The
//! finalizer drops the box, and `rules` is the only place the allocation is
//! read back out. There is no lock: `Environment`'s isolate is single-threaded
//! and every entry point here runs on it.

mod address;
mod blocklist;

use std::ffi::c_void;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub use address::{Family, SocketAddress, AF_INET, AF_INET6};
pub use blocklist::{BlockList, Rule};

use blocklist::family_from_af;

/// Members exposed on the namespace object, matching `contracts/block_list.json`.
pub const MEMBERS: &[&str] = &["AF_INET", "AF_INET6", "BlockList", "SocketAddress"];

/// Members this namespace needs but cannot install yet, each with the reason.
///
/// Empty: all four recorded members are installed, and the prototypes carry
/// every method the JavaScript layer calls.
pub const DEFERRED: &[(&str, &str)] = &[];

/// The internal field holding an instance's boxed state.
const STATE_FIELD: i32 = 0;

/// `internalBinding('block_list')`.
pub struct BlockListBinding;

impl BindingModule for BlockListBinding {
    fn namespace(&self) -> &'static str {
        "block_list"
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

        // `Initialize` registers the constructor first, then the socket
        // address constructor, then the two constants.
        let block_list = block_list_constructor(scope)?;
        set(scope, object, "BlockList", block_list)?;
        let socket_address = socket_address_constructor(scope)?;
        set(scope, object, "SocketAddress", socket_address)?;

        for (name, value) in [("AF_INET", AF_INET), ("AF_INET6", AF_INET6)] {
            let value = v8::Integer::new(scope, value);
            define_constant(scope, object, name, value.into())?;
        }

        Ok(object)
    }
}

/// Registers the `block_list` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(BlockListBinding);
}

fn define_constant(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> Result<(), String> {
    let key = v8::String::new(scope, name).ok_or("cannot allocate a property name")?;
    object
        .define_own_property(
            scope,
            key.into(),
            value,
            v8::PropertyAttribute::READ_ONLY | v8::PropertyAttribute::DONT_DELETE,
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

fn key<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
) -> Result<v8::Local<'s, v8::String>, String> {
    v8::String::new(scope, name).ok_or_else(|| format!("cannot allocate {name}"))
}

fn throw_type_error(scope: &mut v8::PinScope<'_, '_>, message: &str) {
    if let Some(text) = v8::String::new(scope, message) {
        let error = v8::Exception::type_error(scope, text);
        scope.throw_exception(error);
    }
}

/// Throws an `Error` carrying `code`, the shape `ERR_INVALID_ADDRESS` has.
fn throw_coded_error(scope: &mut v8::PinScope<'_, '_>, code: &str, message: &str) {
    let Some(text) = v8::String::new(scope, message) else {
        return;
    };
    let exception = v8::Exception::error(scope, text);
    if let Ok(object) = v8::Local::<v8::Object>::try_from(exception) {
        if let Some(name) = v8::String::new(scope, "code") {
            if let Some(value) = v8::String::new(scope, code) {
                object.set(scope, name.into(), value.into());
            }
        }
    }
    scope.throw_exception(exception);
}

/// Boxes `state` onto `object` and registers the finalizer that frees it.
fn install_state<T>(scope: &mut v8::PinScope<'_, '_>, object: v8::Local<v8::Object>, state: T) {
    let pointer = Box::into_raw(Box::new(state));
    object.set_aligned_pointer_in_internal_field(
        STATE_FIELD,
        pointer.cast::<c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let weak = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            // SAFETY: the pointer came from `Box::into_raw` in this function
            // and no other owner exists; the finalizer runs exactly once.
            drop(unsafe { Box::from_raw(address as *mut T) });
        }),
    );
    // The `Weak` only has to stay registered, and forgetting it transfers the
    // registration to V8 rather than cancelling it.
    std::mem::forget(weak);
}

/// Borrows the state installed by [`install_state`].
///
/// SAFETY: the caller must only use the reference inside `body`, and must not
/// re-enter JavaScript, because that could run the finalizer and free the box.
fn with_state<T, R>(object: v8::Local<v8::Object>, body: impl FnOnce(&mut T) -> R) -> Option<R> {
    // SAFETY: the field only ever holds a pointer produced by `install_state`
    // for this object's own template, and `object` is a live local.
    let pointer =
        unsafe { object.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) } as *mut T;
    if pointer.is_null() {
        return None;
    }
    // SAFETY: `pointer` is the live allocation `install_state` made, and
    // `body` cannot re-enter JavaScript while this borrow is held.
    Some(body(unsafe { &mut *pointer }))
}

/// One of the `AF_INET`/`AF_INET6` arguments, read as a family.
fn family_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
) -> Option<Family> {
    let af = args.get(index).int32_value(scope)?;
    match family_from_af(af) {
        Some(family) => Some(family),
        None => {
            throw_type_error(scope, "expected AF_INET or AF_INET6");
            None
        }
    }
}

/// Builds the `SocketAddress` constructor.
fn socket_address_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(socket_address_new)
        .length(4)
        .build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    let methods: [(&str, v8::Local<v8::FunctionTemplate>); 3] = [
        ("detail", method(scope, 1, socket_address_detail)),
        (
            "legacyDetail",
            method(scope, 0, socket_address_legacy_detail),
        ),
        ("flowlabel", method(scope, 0, socket_address_flow_label)),
    ];
    for (name, template) in methods {
        prototype.set(key(scope, name)?.into(), template.into());
    }

    let Some(name) = v8::String::new(scope, "SocketAddress") else {
        return Err("cannot allocate the SocketAddress class name".to_string());
    };
    template.set_class_name(name);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate SocketAddress")?;
    function.set_name(name);
    Ok(function.into())
}

/// Builds one non-constructible method, matching `SetProtoMethod`.
///
/// The callback is a generic parameter rather than a stored function pointer
/// because `MapFnTo` needs the concrete zero-sized function item to select its
/// impl; a `fn` pointer would satisfy no impl at all.
fn method<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    length: i32,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> v8::Local<'s, v8::FunctionTemplate> {
    v8::FunctionTemplate::builder(callback)
        .length(length)
        .constructor_behavior(v8::ConstructorBehavior::Throw)
        .build(scope)
}

/// `new SocketAddress(address, port, family, flowlabel)`.
fn socket_address_new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "SocketAddress cannot be invoked without 'new'");
        return;
    }
    let Ok(text) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        throw_type_error(scope, "SocketAddress requires a string address");
        return;
    };
    let host = text.to_rust_string_lossy(scope);
    let Some(port) = args.get(1).int32_value(scope) else {
        throw_type_error(scope, "SocketAddress requires an integer port");
        return;
    };
    let Some(family) = family_argument(scope, &args, 2) else {
        return;
    };
    let flow_label = args.get(3).uint32_value(scope).unwrap_or(0);

    // Node's `CHECK(args[1]->IsInt32())` accepts the whole int32 range and
    // truncates to the sixteen bits a port holds.
    let port = (port & 0xffff) as u16;
    let Some(mut address) = SocketAddress::parse(family, &host, port) else {
        throw_coded_error(scope, "ERR_INVALID_ADDRESS", "Invalid socket address");
        return;
    };
    address.set_flow_label(flow_label);

    let object = args.this();
    install_state(scope, object, address);
    rv.set(object.into());
}

/// `detail(target)`: fills `target` with `address`, `port`, `family` and
/// `flowlabel`, then returns it.
fn socket_address_detail(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Ok(detail) = v8::Local::<v8::Object>::try_from(args.get(0)) else {
        throw_type_error(scope, "detail requires an object");
        return;
    };
    let fields = with_state::<SocketAddress, _>(args.this(), |address| {
        let text = address.display_text();
        let family = address.family().af();
        let port = address.port();
        let flow_label = address.flow_label();
        (text, family, port, flow_label)
    });
    let Some((text, family, port, flow_label)) = fields else {
        return;
    };

    let Some(address) = v8::String::new(scope, &text) else {
        return;
    };
    let values: [(&str, v8::Local<v8::Value>); 4] = [
        ("address", address.into()),
        ("port", v8::Integer::new(scope, i32::from(port)).into()),
        ("family", v8::Integer::new(scope, family).into()),
        (
            "flowlabel",
            v8::Integer::new_from_unsigned(scope, flow_label).into(),
        ),
    ];
    for (name, value) in values {
        if let Some(key) = v8::String::new(scope, name) {
            detail.set(scope, key.into(), value);
        }
    }
    rv.set(detail.into());
}

/// `legacyDetail()`: the `AddressToJS` shape `{ address, family, port }` with
/// `family` spelled out.
fn socket_address_legacy_detail(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let fields = with_state::<SocketAddress, _>(args.this(), |address| {
        let text = address.display_text();
        let family = address.family().label();
        let port = address.port();
        (text, family, port)
    });
    let Some((text, family, port)) = fields else {
        return;
    };
    let object = v8::Object::new(scope);
    if let Some(value) = v8::String::new(scope, &text) {
        set(scope, object, "address", value.into()).ok();
    }
    if let Some(value) = v8::String::new(scope, family) {
        set(scope, object, "family", value.into()).ok();
    }
    let port = v8::Integer::new(scope, i32::from(port));
    set(scope, object, "port", port.into()).ok();
    rv.set(object.into());
}

/// `flowlabel()`.
fn socket_address_flow_label(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let label =
        with_state::<SocketAddress, _>(args.this(), |address| address.flow_label()).unwrap_or(0);
    rv.set(v8::Integer::new_from_unsigned(scope, label).into());
}

/// Builds the `BlockList` constructor.
fn block_list_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(block_list_new)
        .length(0)
        .build(scope);
    template
        .instance_template(scope)
        .set_internal_field_count(1);

    let prototype = template.prototype_template(scope);
    let methods: [(&str, v8::Local<v8::FunctionTemplate>); 12] = [
        ("addAddress", method(scope, 1, add_address)),
        ("addAddresses", method(scope, 1, add_addresses)),
        ("addRange", method(scope, 2, add_range)),
        ("addSubnet", method(scope, 2, add_subnet)),
        ("removeAddress", method(scope, 1, remove_address)),
        ("removeRange", method(scope, 2, remove_range)),
        ("removeSubnet", method(scope, 2, remove_subnet)),
        ("check", method(scope, 1, check)),
        ("checkString", method(scope, 2, check_string)),
        ("getRules", method(scope, 0, get_rules)),
        ("clear", method(scope, 0, clear)),
        ("getSize", method(scope, 0, get_size)),
    ];
    for (name, template) in methods {
        prototype.set(key(scope, name)?.into(), template.into());
    }
    let Some(name) = v8::String::new(scope, "BlockList") else {
        return Err("cannot allocate the BlockList class name".to_string());
    };
    template.set_class_name(name);
    let function = template
        .get_function(scope)
        .ok_or("cannot allocate BlockList")?;
    function.set_name(name);
    Ok(function.into())
}

/// `new BlockList()`.
fn block_list_new(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    if !args.is_construct_call() {
        throw_type_error(scope, "BlockList cannot be invoked without 'new'");
        return;
    }
    let object = args.this();
    install_state(scope, object, BlockList::new());
    rv.set(object.into());
}

/// Reads argument `index` as a `SocketAddress` handle.
fn socket_address_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    index: i32,
    name: &str,
) -> Option<SocketAddress> {
    let Ok(object) = v8::Local::<v8::Object>::try_from(args.get(index)) else {
        throw_type_error(scope, &format!("{name} must be a SocketAddress"));
        return None;
    };
    match with_state::<SocketAddress, _>(object, |address| *address) {
        Some(address) => Some(address),
        None => {
            throw_type_error(scope, &format!("{name} must be a SocketAddress"));
            None
        }
    }
}

/// `addAddress(address)`.
fn add_address(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(address) = socket_address_argument(scope, &args, 0, "address") else {
        return;
    };
    with_state::<BlockList, _>(args.this(), |list| list.add_address(address));
    rv.set(v8::Boolean::new(scope, true).into());
}

/// `addAddresses(addresses)`.
fn add_addresses(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Ok(array) = v8::Local::<v8::Array>::try_from(args.get(0)) else {
        throw_type_error(scope, "addAddresses requires an array");
        return;
    };
    let mut addresses = Vec::with_capacity(array.length() as usize);
    for index in 0..array.length() {
        let Some(value) = array.get_index(scope, index) else {
            return;
        };
        let Ok(object) = v8::Local::<v8::Object>::try_from(value) else {
            throw_type_error(scope, "addAddresses requires SocketAddress entries");
            return;
        };
        let Some(address) = with_state::<SocketAddress, _>(object, |address| *address) else {
            throw_type_error(scope, "addAddresses requires SocketAddress entries");
            return;
        };
        addresses.push(address);
    }
    with_state::<BlockList, _>(args.this(), |list| {
        for address in addresses {
            list.add_address(address);
        }
    });
    rv.set(v8::Boolean::new(scope, true).into());
}

/// `addRange(start, end)`, answering `false` when `start` is after `end`.
///
/// The comparison is `SocketAddress::operator>`, so a cross-family pair that is
/// unordered counts as *not* greater and the range is accepted, exactly as
/// Node's `if (*start > *end)` lets it through.
fn add_range(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(start) = socket_address_argument(scope, &args, 0, "start") else {
        return;
    };
    let Some(end) = socket_address_argument(scope, &args, 1, "end") else {
        return;
    };
    if start.compare(&end) == Some(std::cmp::Ordering::Greater) {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    }
    with_state::<BlockList, _>(args.this(), |list| list.add_range(start, end));
    rv.set(v8::Boolean::new(scope, true).into());
}

/// `addSubnet(network, prefix)`.
fn add_subnet(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(network) = socket_address_argument(scope, &args, 0, "network") else {
        return;
    };
    let Some(prefix) = prefix_argument(scope, &args, &network) else {
        return;
    };
    with_state::<BlockList, _>(args.this(), |list| list.add_subnet(network, prefix));
    rv.set(v8::Boolean::new(scope, true).into());
}

/// Reads the prefix length, which the JavaScript layer has already range
/// checked per family.
fn prefix_argument(
    scope: &mut v8::PinScope<'_, '_>,
    args: &v8::FunctionCallbackArguments<'_>,
    network: &SocketAddress,
) -> Option<u8> {
    let Some(prefix) = args.get(1).int32_value(scope) else {
        throw_type_error(scope, "prefix must be an integer");
        return None;
    };
    let maximum = i32::try_from(network.family().bits()).unwrap_or(32);
    if prefix < 0 || prefix > maximum {
        throw_type_error(scope, "prefix is out of range for the address family");
        return None;
    }
    u8::try_from(prefix).ok()
}

/// `removeAddress(address)`.
fn remove_address(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(address) = socket_address_argument(scope, &args, 0, "address") else {
        return;
    };
    with_state::<BlockList, _>(args.this(), |list| list.remove_address(address));
}

/// `removeRange(start, end)`.
fn remove_range(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(start) = socket_address_argument(scope, &args, 0, "start") else {
        return;
    };
    let Some(end) = socket_address_argument(scope, &args, 1, "end") else {
        return;
    };
    with_state::<BlockList, _>(args.this(), |list| list.remove_range(start, end));
}

/// `removeSubnet(network, prefix)`.
fn remove_subnet(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    let Some(network) = socket_address_argument(scope, &args, 0, "network") else {
        return;
    };
    let Some(prefix) = prefix_argument(scope, &args, &network) else {
        return;
    };
    with_state::<BlockList, _>(args.this(), |list| list.remove_subnet(network, prefix));
}

/// `check(address)` where `address` is a `SocketAddress`.
fn check(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Some(address) = socket_address_argument(scope, &args, 0, "address") else {
        return;
    };
    let blocked =
        with_state::<BlockList, _>(args.this(), |list| list.apply(&address)).unwrap_or(false);
    rv.set(v8::Boolean::new(scope, blocked).into());
}

/// `checkString(address, family)`.
///
/// This is the fast path `lib/internal/blocklist.js` takes for a string
/// argument. A malformed literal answers `false` rather than throwing, which is
/// what `CheckString` does when `SocketAddress::New` fails.
fn check_string(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let Ok(text) = v8::Local::<v8::String>::try_from(args.get(0)) else {
        throw_type_error(scope, "checkString requires a string address");
        return;
    };
    let host = text.to_rust_string_lossy(scope);
    let Some(family) = family_argument(scope, &args, 1) else {
        return;
    };
    let Some(address) = SocketAddress::parse(family, &host, 0) else {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    };
    let blocked =
        with_state::<BlockList, _>(args.this(), |list| list.apply(&address)).unwrap_or(false);
    rv.set(v8::Boolean::new(scope, blocked).into());
}

/// `getRules()`.
fn get_rules(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let rules =
        with_state::<BlockList, _>(args.this(), |list| list.list_rules()).unwrap_or_default();
    let array = v8::Array::new(scope, rules.len() as i32);
    for (index, rule) in rules.iter().enumerate() {
        if let Some(value) = v8::String::new(scope, rule) {
            array.set_index(scope, index as u32, value.into());
        }
    }
    rv.set(array.into());
}

/// `getSize()`.
fn get_size(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_>,
) {
    let size = with_state::<BlockList, _>(args.this(), |list| list.size()).unwrap_or(0);
    rv.set(v8::Number::new(scope, size as f64).into());
}

/// `clear()`.
fn clear(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    _rv: v8::ReturnValue<'_>,
) {
    with_state::<BlockList, _>(args.this(), |list| list.clear());
    let _ = scope;
}

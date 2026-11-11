//! The `statement.iterate()` iterator.
//!
//! `StatementIterator` in `src/node_sqlite.cc` is a `BaseObject` prototype whose
//! `__proto__` is set to the global `Iterator.prototype`, so it is a real
//! iterator with `next()` and `return()` and works in `for...of`. Its `return()`
//! marks the statement's reset generation used up so a second `next()` after
//! `break` throws `ERR_INVALID_STATE` rather than silently restarting.
//!
//! The generation counter is the part that matters: a `for...of` loop stopped
//! early leaves the statement mid-scan, and re-entering `next()` would step from
//! where it stopped rather than from the beginning. Node records the statement's
//! `reset_generation_` in the iterator and compares it on every `next()`.

use std::os::raw::c_void;

use rn_v8_sys::v8;

use crate::errors;
use crate::stmt::{self, StatementState};

/// The internal field holding an iterator's boxed state.
pub const STATE_FIELD: i32 = 0;
/// How many internal fields an iterator instance has.
pub const INTERNAL_FIELDS: usize = 2;
/// The second field holds the rooted `Statement` object, which is
/// `BaseObjectPtr<Statement>` in the C++: an iterator cannot outlive the
/// statement it walks.
pub const STATEMENT_FIELD: i32 = 1;

/// Everything one iterator owns.
pub struct IteratorState {
    /// The statement state, kept valid by [`Self::statement_object`].
    pub statement: *mut StatementState,
    /// The rooted `Statement` object.
    pub statement_object: v8::Global<v8::Object>,
    /// Whether the iterator has reported completion.
    pub done: bool,
    /// The statement's reset generation when this iterator was created.
    ///
    /// `StatementIterator` records `stmt_->reset_generation_` in its
    /// constructor and `Next` refuses once the two disagree, so a stale iterator
    /// cannot step a statement another caller has since reset and bound.
    pub generation: u64,
}

/// Creates and installs an iterator over `statement`.
///
/// Not `unsafe fn`: the caller has just reset and bound that statement through
/// its own live state, and rooting the statement object below is what keeps the
/// pointer valid afterwards.
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the statement was just reset and bound by the caller and is rooted here"
)]
///
/// The caller has already reset and bound the statement, which is what
/// `Iterate` relies on: `Next` steps without resetting first.
pub fn create<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    statement: *mut StatementState,
    statement_object: v8::Local<'s, v8::Object>,
) -> Option<v8::Local<'s, v8::Value>> {
    let object = allocate(scope)?;
    // SAFETY: the caller reset and bound this statement, and the rooted object
    // below keeps it alive.
    let generation = unsafe { (*statement).reset_generation };
    let state = IteratorState {
        statement,
        statement_object: v8::Global::new(scope, statement_object),
        done: false,
        generation,
    };
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
            // SAFETY: the pointer came from `Box::into_raw` here, and this
            // finalizer runs exactly once, so it is the only owner.
            drop(unsafe { Box::from_raw(address as *mut IteratorState) });
        }),
    );
    std::mem::forget(weak);

    Some(object.into())
}

/// The global `Iterator.prototype`, when the runtime has one.
fn global_iterator_prototype<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Option<v8::Local<'s, v8::Value>> {
    let global = scope.get_current_context().global(scope);
    let key = v8::String::new(scope, "Iterator")?;
    let iterator = global.get(scope, key.into())?;
    let Ok(iterator) = v8::Local::<v8::Object>::try_from(iterator) else {
        return None;
    };
    let key = v8::String::new(scope, "prototype")?;
    iterator.get(scope, key.into())
}

/// Allocates an iterator instance from the class's object template.
///
/// `StatementIterator::Create` in the C++ uses
/// `GetConstructorTemplate(env)->InstanceTemplate()->NewInstance(...)`, which
/// never runs the constructor body — that is why `new StatementIterator()`
/// throws while `iterate()` works.
fn allocate<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Object>> {
    let template = v8::FunctionTemplate::builder(illegal_constructor)
        .length(0)
        .build(scope);
    let instance = template.instance_template(scope);
    instance.set_internal_field_count(INTERNAL_FIELDS);
    let instance = instance.new_instance(scope)?;
    let prototype = template.prototype_template(scope);
    for (name, method) in [
        ("next", crate::database::method(scope, 0, next)),
        ("return", crate::database::method(scope, 0, ret)),
    ] {
        let key = v8::String::new(scope, name)?;
        prototype.set(key.into(), method.into());
    }
    // `Iterate` sets the instance's prototype to the *global*
    // `Iterator.prototype`, and `Iterator.prototype` is what supplies
    // `map`/`filter`/`take`. Our `next` and `return` have to sit between the
    // instance and that: a prototype whose own prototype is the global one.
    let prototype = prototype.new_instance(scope)?;
    if let Some(iterator_prototype) = global_iterator_prototype(scope) {
        prototype.set_prototype(scope, iterator_prototype);
    }
    instance.set_prototype(scope, prototype.into())?;
    Some(instance)
}

fn illegal_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    _args: v8::FunctionCallbackArguments<'s>,
    _rv: v8::ReturnValue<'s>,
) {
    errors::throw_coded(scope, "ERR_ILLEGAL_CONSTRUCTOR", "Illegal constructor");
}

/// The iterator state behind `this`, or a thrown `ERR_INVALID_THIS`.
fn state_of(
    scope: &mut v8::PinScope<'_, '_>,
    this: v8::Local<'_, v8::Object>,
) -> Option<*mut IteratorState> {
    // SAFETY: the field was installed by `create` for this object's template.
    let pointer = unsafe { this.get_aligned_pointer_from_internal_field(STATE_FIELD, 0) }
        as *mut IteratorState;
    if pointer.is_null() {
        errors::throw_coded(
            scope,
            "ERR_INVALID_THIS",
            "Value of \"this\" must be of type StatementIterator",
        );
        return None;
    }
    Some(pointer)
}

/// The result object `{ done, value }`, built with the null-prototype template
/// `getLazyIterTemplate` uses.
fn iteration_result<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    done: bool,
    value: v8::Local<'s, v8::Value>,
) -> Option<v8::Local<'s, v8::Object>> {
    let keys = ["done", "value"];
    let values = [v8::Boolean::new(scope, done).into(), value];
    let mut key_locals = Vec::with_capacity(keys.len());
    for key in keys {
        key_locals.push(v8::String::new(scope, key)?.into());
    }
    Some(v8::Object::with_prototype_and_properties(
        scope,
        v8::null(scope).into(),
        &key_locals,
        &values,
    ))
}

/// `iterator.next()`.
fn next<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = state_of(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`, whose rooted
    // statement object keeps the statement state alive.
    let state = unsafe { &mut *pointer };
    // A drained iterator touches no SQLite state, so it stays usable from a
    // callback and is checked before the guards below.
    if state.done {
        if let Some(result) = iteration_result(scope, true, v8::null(scope).into()) {
            rv.set(result.into());
        }
        return;
    }
    let statement = state.statement;
    if statement.is_null() {
        errors::throw_coded(scope, "ERR_INVALID_STATE", "statement has been finalized");
        return;
    }
    // SAFETY: `statement_object` roots the `Statement` object, whose boxed state
    // this pointer is, so it is alive.
    let statement = unsafe { &mut *statement };
    if !stmt::require_live(scope, statement) {
        return;
    }
    if state.generation != statement.reset_generation {
        errors::throw_coded(scope, "ERR_INVALID_STATE", "iterator was invalidated");
        return;
    }
    match stmt::step_for_iterator(scope, statement) {
        Some(Some(row)) => {
            if let Some(result) = iteration_result(scope, false, row) {
                rv.set(result.into());
            }
        }
        Some(None) => {
            state.done = true;
            let code = statement.reset();
            if code != crate::ffi::SQLITE_OK {
                let connection = statement.connection();
                errors::throw_sqlite(scope, connection);
                return;
            }
            if let Some(result) = iteration_result(scope, true, v8::null(scope).into()) {
                rv.set(result.into());
            }
        }
        None => {}
    }
}

/// `iterator.return()`.
///
/// Runs the statement's reset so a generator's `finally` blocks still run when
/// the loop is abandoned, then reports completion.
fn ret<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue<'s>,
) {
    let Some(pointer) = state_of(scope, args.this()) else {
        return;
    };
    // SAFETY: `state_of` returned a live pointer for `this`.
    let state = unsafe { &mut *pointer };
    if !state.done {
        state.done = true;
        if !state.statement.is_null() {
            // SAFETY: `statement_object` roots the statement state.
            let statement = unsafe { &mut *state.statement };
            statement.reset();
        }
    }
    if let Some(result) = iteration_result(scope, true, v8::null(scope).into()) {
        rv.set(result.into());
    }
}

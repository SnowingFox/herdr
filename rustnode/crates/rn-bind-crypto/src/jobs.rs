//! Installing the three random job classes onto the `crypto` namespace.
//!
//! Each class is a constructor plus a `run` on its prototype, which is
//! `CryptoJob::Initialize`'s shape: `NewFunctionTemplate(isolate, New)` with
//! `SetProtoMethod(isolate, job, "run", Run)` and
//! `SetConstructorFunction(context, target, traits.JobName, job)`.
//!
//! # Why `run` is on the prototype here and on the instance elsewhere
//!
//! It is the same observable thing — `job.run()` works either way — but a
//! prototype method is what Node installs and what `typeof Job.prototype.run`
//! reports, and `rn-bind-crypto-cipher`'s `AESCipherJob` does the same for the
//! same reason. A class with no prototype `run` would also let `job.run` be
//! shadowed by an own property without anything noticing.
//!
//! # The mode is stored, not re-read
//!
//! `run()` needs the mode to decide between the tuple and the completion, and
//! the constructor's arguments are gone by then. It is captured into the job
//! state at construction, which is what `CryptoJob`'s `mode_` member is: a value
//! read once, not a property of the JavaScript object (which `lib/**` could set).

use rn_crypto_job::{dispatch, Completion, CryptoJobError, JobMode, Runnable};
use rn_v8_sys::v8;

use crate::argon2_job::Argon2Job;
use crate::random_jobs::{self, CheckPrimeJob, RandomBytesJob, RandomPrimeJob};

/// Installs `RandomBytesJob`, `RandomPrimeJob` and `CheckPrimeJob`.
pub fn install_random_jobs<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
) -> Result<(), String> {
    install_class(scope, target, "RandomBytesJob", random_bytes_constructor)?;
    install_class(scope, target, "RandomPrimeJob", random_prime_constructor)?;
    install_class(scope, target, "CheckPrimeJob", check_prime_constructor)?;
    // `Argon2Job` shares this `run` because it shares the protocol: a mode, a
    // work step and a completion. The variant below is what picks the compute.
    install_class(scope, target, "Argon2Job", argon2_constructor)
}

/// Installs one job class: the constructor, `run` on its prototype, its name.
fn install_class<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    target: v8::Local<'s, v8::Object>,
    name: &str,
    constructor: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<(), String> {
    // `rn_core::class`: these four (`RandomBytesJob`, `RandomPrimeJob`,
    // `CheckPrimeJob`, `Argon2Job`) are `CryptoJob` subclasses that `lib/**`
    // writes `new` against, so they keep `[[Construct]]` — Node publishes them
    // through `SetConstructorFunction`.
    let template = rn_core::class(constructor).build(scope);
    // One internal field, holding the mode and the job, exactly as
    // `CryptoJob::kInternalFieldCount` is 1.
    template
        .instance_template(scope)
        .set_internal_field_count(1);
    let prototype = template.prototype_template(scope);
    let Some(key) = v8::String::new(scope, "run") else {
        return Err(format!("cannot allocate {name}.run"));
    };
    // `run` is a prototype method, so `rn_core::method` and not `class`:
    // `SetProtoMethod` is `ConstructorBehavior::kThrow`, and Node makes
    // `new job.run()` a `TypeError` even though `new RandomBytesJob(...)` is
    // fine. Using `class` here would leave `run` constructible, which is a
    // different defect in the other direction.
    prototype.set(key.into(), rn_core::method(run).build(scope).into());
    // `rn_core::set_class` is `SetConstructorFunction(…, SET_CLASS_NAME)`: the
    // class name is what V8 reports as `f.name`, so it has to be the property
    // name Node passes in rather than left to the bare builder.
    rn_core::set_class(scope, target, name, template)?;
    Ok(())
}

/// Reports a call without `new` as a catchable `TypeError`.
///
/// Returns `true` when the call is a construct call and the constructor should
/// continue. The message matches `ERR_INVALID_THIS`'s shape rather than
/// inventing a code: `Class constructor X cannot be invoked without 'new'` is
/// what a JavaScript `class` throws, and `internal/errors` has no dedicated
/// template for a native constructor's misuse.
fn require_new(scope: &mut v8::PinScope<'_, '_>, args: &v8::FunctionCallbackArguments<'_>) -> bool {
    if args.is_construct_call() {
        return true;
    }
    crate::install::throw_type_error(scope, "Class constructor cannot be invoked without 'new'");
    false
}

/// `new RandomBytesJob(mode, buffer, offset, size)`.
fn random_bytes_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    // A plain call must not reach `set_aligned_pointer_in_internal_field`: for a
    // call without `new` V8's `This()` is an ordinary object with no internal
    // fields, and the write is `v8::Object::SetAlignedPointerInInternalField:
    // Internal field out of bounds`, which *aborts the process* rather than
    // throwing. Node aborts here too (`CryptoJob`'s constructor is reached
    // through `CHECK(args.IsConstructCall())`), but the tree's policy after #98
    // is that a misuse is a catchable `TypeError` instead of a crash, and
    // `tools/no-new-audit.py` enforces it — this constructor was the single
    // remaining abort in the whole registry when it landed.
    if !require_new(scope, &args) {
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = random_jobs::mode_argument(scope, &args) else {
        return;
    };
    // `AdditionalConfig` CHECKs both of these are `Uint32`, because `random.js`
    // computes them with `>>> 0` from already-validated values.
    let offset = args.get(2).uint32_value(scope).unwrap_or(0) as usize;
    let size = args.get(3).uint32_value(scope).unwrap_or(0) as usize;
    let Some(job) = RandomBytesJob::from_arguments(scope, args.get(1), offset, size) else {
        return;
    };
    install_state(scope, this, mode, JobKind::Bytes(job));
    rv.set(this.into());
}

/// `new RandomPrimeJob(mode, size, safe, add, rem)`.
fn random_prime_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    // A plain call must not reach `set_aligned_pointer_in_internal_field`: for a
    // call without `new` V8's `This()` is an ordinary object with no internal
    // fields, and the write is `v8::Object::SetAlignedPointerInInternalField:
    // Internal field out of bounds`, which *aborts the process* rather than
    // throwing. Node aborts here too (`CryptoJob`'s constructor is reached
    // through `CHECK(args.IsConstructCall())`), but the tree's policy after #98
    // is that a misuse is a catchable `TypeError` instead of a crash, and
    // `tools/no-new-audit.py` enforces it — this constructor was the single
    // remaining abort in the whole registry when it landed.
    if !require_new(scope, &args) {
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = random_jobs::mode_argument(scope, &args) else {
        return;
    };
    let Some(job) = RandomPrimeJob::from_arguments(scope, &args) else {
        return;
    };
    install_state(scope, this, mode, JobKind::Prime(job));
    rv.set(this.into());
}

/// `new CheckPrimeJob(mode, candidate, checks)`.
fn check_prime_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    // A plain call must not reach `set_aligned_pointer_in_internal_field`: for a
    // call without `new` V8's `This()` is an ordinary object with no internal
    // fields, and the write is `v8::Object::SetAlignedPointerInInternalField:
    // Internal field out of bounds`, which *aborts the process* rather than
    // throwing. Node aborts here too (`CryptoJob`'s constructor is reached
    // through `CHECK(args.IsConstructCall())`), but the tree's policy after #98
    // is that a misuse is a catchable `TypeError` instead of a crash, and
    // `tools/no-new-audit.py` enforces it — this constructor was the single
    // remaining abort in the whole registry when it landed.
    if !require_new(scope, &args) {
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = random_jobs::mode_argument(scope, &args) else {
        return;
    };
    let Some(job) = CheckPrimeJob::from_arguments(scope, &args) else {
        return;
    };
    install_state(scope, this, mode, JobKind::Check(job));
    rv.set(this.into());
}

/// `job.run()`, shared by the three prototypes.
fn run<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    let this: v8::Local<v8::Object> = args.this();
    let Some((mode, job)) = take_state(this) else {
        // `ASSIGN_OR_RETURN_UNWRAP` in Node's `Run`: a receiver this class did
        // not build has no state, and the job reports that rather than panicking.
        random_jobs::throw_type(scope, "Value of \"this\" must be of type CryptoJob");
        return;
    };
    // `job.run()` may only be called once: the work is taken out of the object.
    // A second call in Node would re-run the work, which for a prime generation
    // means generating a different prime for the same job, so the state is gone
    // and this reports it.
    let Some(job) = job else {
        random_jobs::throw_type(scope, "The job has already run");
        return;
    };
    // `Completion::Callback` is the shape every `random.js` caller uses: it
    // assigns `job.ondone` before calling `run()`. The sync mode ignores it.
    match dispatch(scope, mode, job, this, Completion::Callback) {
        Some(value) => rv.set(value),
        // A queued `Async` job returns `undefined` and delivers through
        // `ondone`; `random.js` ignores `run()`'s return value on that path.
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `new Argon2Job(mode, pass, salt, lanes, keylen, memcost, iter, secret, ad,
/// type)`.
fn argon2_constructor<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    args: v8::FunctionCallbackArguments<'s>,
    mut rv: v8::ReturnValue,
) {
    // A plain call must not reach `set_aligned_pointer_in_internal_field`: for a
    // call without `new` V8's `This()` is an ordinary object with no internal
    // fields, and the write is `v8::Object::SetAlignedPointerInInternalField:
    // Internal field out of bounds`, which *aborts the process* rather than
    // throwing. Node aborts here too (`CryptoJob`'s constructor is reached
    // through `CHECK(args.IsConstructCall())`), but the tree's policy after #98
    // is that a misuse is a catchable `TypeError` instead of a crash, and
    // `tools/no-new-audit.py` enforces it — this constructor was the single
    // remaining abort in the whole registry when it landed.
    if !require_new(scope, &args) {
        return;
    }
    let this: v8::Local<v8::Object> = args.this();
    let Some(mode) = random_jobs::mode_argument(scope, &args) else {
        return;
    };
    let Some(job) = Argon2Job::from_arguments(scope, &args, mode) else {
        return;
    };
    install_state(scope, this, mode, JobKind::Argon2(job));
    rv.set(this.into());
}

/// The state a job instance carries.
///
/// One enum rather than a generic parameter per class because `run` is a single
/// function shared by all three prototypes; the variant is what picks the
/// compute step. Each class installs its own variant, so the pairing between a
/// variant and its output is fixed at construction.
enum JobKind {
    Bytes(RandomBytesJob),
    Prime(RandomPrimeJob),
    Check(CheckPrimeJob),
    Argon2(Argon2Job),
}

/// The computed result of one of the three jobs.
///
/// Three named variants rather than one type: a `RandomBytesJob` produces
/// nothing (it filled the caller's buffer), a prime job produces bytes and a
/// check produces a boolean. Erasing them behind `Box<dyn Any>` would trade this
/// match for a downcast that can fail.
enum JobOutput {
    Filled,
    Prime(Vec<u8>),
    PrimeCheck(bool),
    Derived(Vec<u8>),
}

impl Runnable for JobKind {
    type Output = JobOutput;

    fn run(&mut self) -> Result<Self::Output, CryptoJobError> {
        match self {
            Self::Bytes(job) => job.run().map(|()| JobOutput::Filled),
            Self::Prime(job) => job.run().map(JobOutput::Prime),
            Self::Check(job) => job.run().map(JobOutput::PrimeCheck),
            Self::Argon2(job) => job.run().map(JobOutput::Derived),
        }
    }

    fn finish<'s>(
        &self,
        scope: &mut v8::PinScope<'s, '_>,
        output: Self::Output,
    ) -> Option<v8::Local<'s, v8::Value>> {
        match (self, output) {
            (Self::Bytes(job), JobOutput::Filled) => job.finish(scope, ()),
            (Self::Prime(job), JobOutput::Prime(bytes)) => job.finish(scope, bytes),
            (Self::Check(job), JobOutput::PrimeCheck(prime)) => job.finish(scope, prime),
            (Self::Argon2(job), JobOutput::Derived(bytes)) => job.finish(scope, bytes),
            // Unreachable: `run` pairs a variant with its own output, and it is
            // the only producer. Reporting `undefined` keeps this total without
            // an assertion that would abort inside a libuv completion.
            _ => Some(v8::undefined(scope).into()),
        }
    }
}

/// Allocates the state and installs it on the new object with a finalizer.
fn install_state<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<'s, v8::Object>,
    mode: JobMode,
    job: JobKind,
) {
    let pointer = Box::into_raw(Box::new((
        mode,
        std::cell::RefCell::new(Option::<JobKind>::Some(job)),
    )));
    object.set_aligned_pointer_in_internal_field(
        random_jobs::JOB_FIELD,
        pointer.cast::<std::os::raw::c_void>().cast_const(),
        0,
    );
    let address = pointer as usize;
    let _ = v8::Weak::with_guaranteed_finalizer(
        scope,
        object,
        Box::new(move || {
            let pointer = address as *mut (JobMode, std::cell::RefCell<Option<JobKind>>);
            // SAFETY: allocated by `install_state` for this object alone, and
            // this finalizer is the only thing that frees it.
            drop(unsafe { Box::from_raw(pointer) });
        }),
    );
}

/// Reads the mode and takes the job out, or `None` for a foreign receiver.
///
/// The alignment check guards the case `ASSIGN_OR_RETURN_UNWRAP` guards in Node:
/// `run` is installed on three prototypes, so V8 will call it with a receiver of
/// any of those classes, or with an object whose constructor returned before
/// installing state. In those cases field 0 holds whatever V8 put there, and
/// reading it as a pointer would be a misaligned dereference rather than a
/// catchable error.
fn take_state(object: v8::Local<'_, v8::Object>) -> Option<(JobMode, Option<JobKind>)> {
    // SAFETY: the field is read as a plain address; the dereference below is
    // guarded by the null and alignment checks.
    let raw = unsafe { object.get_aligned_pointer_from_internal_field(random_jobs::JOB_FIELD, 0) };
    if raw.is_null() {
        return None;
    }
    let pointer = raw as *mut (JobMode, std::cell::RefCell<Option<JobKind>>);
    if !(pointer as usize).is_multiple_of(std::mem::align_of::<(
        JobMode,
        std::cell::RefCell<Option<JobKind>>,
    )>()) {
        return None;
    }
    // SAFETY: `install_state` is the only writer of this field for a job object,
    // it always stores a box this crate allocated, and the finalizer cannot run
    // while `object` is a live local.
    let (mode, cell) = unsafe { &*pointer };
    let job = match cell.try_borrow_mut() {
        Ok(mut slot) => slot.take(),
        // A re-entrant borrow cannot happen: nothing in this crate calls back
        // into V8 while the borrow is held.
        Err(_) => return None,
    };
    Some((*mode, job))
}

//! `internalBinding('contextify')` for rustnode.
//!
//! This is the namespace that turns source text into executable code. Three
//! separate consumers in `lib/**` depend on it, and each one pins a different
//! part of the contract:
//!
//! * `lib/internal/modules/cjs/loader.js` calls `compileFunctionForCJSLoader`
//!   for every CommonJS file it loads. The returned function is then called
//!   with the five wrapper arguments, so the parameter list is not cosmetic.
//! * `lib/vm.js` and `lib/internal/vm.js` call `ContextifyScript` and
//!   `compileFunction` to implement `vm.Script` and `vm.compileFunction`.
//! * `lib/internal/modules/esm/get_format.js`, `lib/internal/main/check_syntax.js`
//!   and `lib/internal/process/execution.js` call `containsModuleSyntax`, which
//!   is how Node decides a `.js` file is an ES module. It does *not* use
//!   `cjs-module-lexer`; detection is compile-and-inspect-the-error, and the
//!   error text is the interface.
//!
//! ## Why `containsModuleSyntax` is a compile, not a scan
//!
//! The obvious implementation is a lexer looking for `import` and `export`.
//! Node does something better and subtler: it compiles the source as a
//! CommonJS function, and if that fails, it inspects the parse error. Only
//! certain messages mean "this could be ESM" (`Cannot use import statement
//! outside a module`, `Unexpected token 'export'`, ...). For the messages that
//! are ESM-valid-but-CJS-invalid for a *different* reason — a top-level
//! `const module = ...` shadowing a wrapper parameter, or top-level `await` — it
//! reparses the source as an actual ES module and only then answers yes.
//!
//! That second step is what makes `const module = 1` a module and
//! `async function f(){ await 1 }` not one, which a keyword scan cannot express.
//! [`detect`] reproduces the two-stage decision, including the exact message
//! table.
//!
//! ## The compile cache
//!
//! `NODE_COMPILE_CACHE` is honoured on the CommonJS path only, through
//! [`rn_bind_modules::compile_cache`], which owns the on-disk format. V8's own
//! code cache is a byte blob this crate produces and consumes but never
//! inspects.

pub mod compile;
pub mod constants;
pub mod detect;
pub mod script;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/contextify.json`.
///
/// This lists what the object actually installs. `measureMemory` is deliberately
/// absent and declared in [`DEFERRED`] instead, because `rn-compat` only checks a
/// deferral that `members` omits: listing a member in both places would make the
/// contract check pass without ever noticing the gap.
pub const MEMBERS: &[&str] = &[
    "ContextifyScript",
    "compileFunction",
    "compileFunctionForCJSLoader",
    "constants",
    "containsModuleSyntax",
    "makeContext",
    "runInterruptible",
];

/// Members the namespace needs but this crate does not install yet.
///
/// `measureMemory` is the only recorded member this crate cannot provide. It
/// needs `v8::Isolate::MeasureMemory` plus `v8::MeasureMemoryDelegate::Default`,
/// and the `v8` crate linked here exposes neither: a search of
/// `v8-152.2.0/src` for `MeasureMemory` finds no binding at all, so there is no
/// way to ask V8 for a heap measurement. `lib/vm.js` reads the function at module
/// scope (`measureMemory: _measureMemory`), which is a destructuring bind and
/// therefore harmless, and only calls it from inside `vm.measureMemory()`, which
/// is behind an experimental flag.
pub const DEFERRED: &[(&str, &str)] = &[(
    "measureMemory",
    "needs v8::Isolate::MeasureMemory and v8::MeasureMemoryDelegate::Default, neither of which the v8 crate binds; only callable through the flagged vm.measureMemory()",
)];

/// `internalBinding('contextify')`.
pub struct Contextify;

impl BindingModule for Contextify {
    fn namespace(&self) -> &'static str {
        "contextify"
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

        let values: [(&str, v8::Local<v8::Value>); 7] = [
            ("ContextifyScript", script::constructor(scope)?),
            (
                "compileFunction",
                function(scope, "compileFunction", compile::compile_function)?,
            ),
            (
                "compileFunctionForCJSLoader",
                function(
                    scope,
                    "compileFunctionForCJSLoader",
                    compile::compile_function_for_cjs_loader,
                )?,
            ),
            ("constants", constants::value(scope)),
            (
                "containsModuleSyntax",
                function(
                    scope,
                    "containsModuleSyntax",
                    detect::contains_module_syntax,
                )?,
            ),
            (
                "makeContext",
                function(scope, "makeContext", script::make_context)?,
            ),
            (
                "runInterruptible",
                function(scope, "runInterruptible", compile::run_interruptible)?,
            ),
        ];
        for (name, value) in values {
            let key = v8::String::new(scope, name).ok_or("cannot allocate a member name")?;
            object.set(scope, key.into(), value);
        }
        Ok(object)
    }
}

/// Registers the `contextify` namespace with the runtime.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Contextify);
}

fn function<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    name: &str,
    callback: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Result<v8::Local<'s, v8::Value>, String> {
    let template = v8::FunctionTemplate::builder(callback).build(scope);
    let function = template
        .get_function(scope)
        .ok_or_else(|| format!("cannot allocate {name}"))?;
    Ok(function.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_list_covers_the_recorded_contract() {
        // `contracts/contextify.json` lists eight members. This crate installs
        // seven and declares `measureMemory` deferred, so `rn-compat` requires
        // this crate to claim exactly the other seven.
        assert_eq!(MEMBERS.len(), 7);
        let mut sorted = MEMBERS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec![
                "ContextifyScript",
                "compileFunction",
                "compileFunctionForCJSLoader",
                "constants",
                "containsModuleSyntax",
                "makeContext",
                "runInterruptible",
            ]
        );
    }

    #[test]
    fn measure_memory_is_declared_and_not_claimed() {
        // Listing a deferral in `members` too would let the contract check pass
        // without ever noticing the gap.
        assert!(!MEMBERS.contains(&"measureMemory"));
        assert_eq!(DEFERRED.len(), 1);
        assert_eq!(DEFERRED[0].0, "measureMemory");
        assert!(!DEFERRED[0].1.is_empty());
    }
}

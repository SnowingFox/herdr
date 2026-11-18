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
pub mod memory;
pub mod script;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

/// Members exposed on the namespace object, matching `contracts/contextify.json`.
pub const MEMBERS: &[&str] = &[
    "ContextifyScript",
    "compileFunction",
    "compileFunctionForCJSLoader",
    "constants",
    "containsModuleSyntax",
    "makeContext",
    "measureMemory",
    "runInterruptible",
];

/// Members still deferred in this namespace.
pub const DEFERRED: &[(&str, &str)] = &[];

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

        // Publish the sandbox-to-realm lookup this crate owns, so a namespace that
        // needs a `vm` context but cannot depend on this one can ask for it.
        // `moveMessagePortToContext` is the caller; Node reaches the same table
        // through the static `ContextFromContextifiedSandbox`.
        rn_core::hook_slot::set_sandbox_context_lookup(script::context_of);

        let values: [(&str, v8::Local<v8::Value>); 8] = [
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
                "measureMemory",
                function(scope, "measureMemory", memory::measure_memory)?,
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
    Ok(rn_core::named_method(scope, name, callback)?.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_member_list_covers_the_recorded_contract() {
        // `contracts/contextify.json` lists eight members and this crate now
        // installs all eight.
        assert_eq!(MEMBERS.len(), 8);
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
                "measureMemory",
                "runInterruptible",
            ]
        );
    }

    #[test]
    fn no_contextify_members_remain_deferred() {
        assert!(MEMBERS.contains(&"measureMemory"));
        assert!(DEFERRED.is_empty());
    }
}

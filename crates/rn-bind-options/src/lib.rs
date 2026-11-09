//! `internalBinding('options')` for rustnode.
//!
//! `src/node_options.cc` is the specification. Its namespace is almost
//! entirely data: every `AddOption` call describes one command-line option,
//! and the members either publish that table or read values out of a parsed
//! `PerProcessOptions`. rustnode has no option parser yet, so the members that
//! would read parsed values report the defaults from `src/node_options.h`
//! instead; that is what a Node process started with no arguments reports too.
//!
//! What `lib/**` does with this namespace, and why each member matters:
//!
//! * `internal/options.js` wraps every member and is loaded by
//!   `internal/bootstrap/realm`, so nothing above the bootstrap can load while
//!   this namespace is missing.
//! * `internal/process/per_thread.js` builds `process.allowedNodeEnvironmentFlags`
//!   from `getCLIOptionsInfo()` plus the `envSettings` and `types` constants.
//! * `internal/main/print_help.js` uses `types` to name an option's type in
//!   `--help` output.
//! * `internal/test_runner/runner.js` and `internal/bench_runner/cli.js` call
//!   `getOptionsAsFlags` to rebuild the parent's flags for a child process.
//!
//! `getCLIOptionsInfo` returns Maps whose prototype Node replaces with the
//! primordial `SafeMap.prototype`. `lib/**` only reads through them, and the
//! distinction is invisible to every current caller, so this crate returns
//! ordinary Maps and says so here rather than pretending otherwise.

pub mod install;
pub mod option;
pub mod table;
pub mod values;

use rn_core::{BindingModule, InstallCtx};
use rn_v8_sys::v8;

pub use option::{DefaultValue, OptionInfo, OptionNamespace};
pub use values::{
    cli_info, cli_values, env_options_input_types, namespace_options_input_types, options_as_flags,
    parse_node_options, CliValue, EmbedderOptions, InputType, NodeOptionsError, OptionMetadata,
};

/// Members of the `options` namespace, matching `contracts/options.json`.
pub const MEMBERS: &[&str] = &[
    "envSettings",
    "getCLIOptionsInfo",
    "getCLIOptionsValues",
    "getEmbedderOptions",
    "getEnvOptionsInputType",
    "getNamespaceOptionsInputType",
    "getOptionsAsFlags",
    "parseNodeOptionsEnvVar",
    "types",
];

/// The `options` namespace.
#[derive(Debug, Default, Clone, Copy)]
pub struct Options;

impl BindingModule for Options {
    fn namespace(&self) -> &'static str {
        "options"
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

        install::define_method(scope, object, "getCLIOptionsValues", get_cli_options_values)?;
        install::define_method(scope, object, "getCLIOptionsInfo", get_cli_options_info)?;
        install::define_method(scope, object, "getOptionsAsFlags", get_options_as_flags)?;
        install::define_method(scope, object, "getEmbedderOptions", get_embedder_options)?;
        install::define_method(
            scope,
            object,
            "getEnvOptionsInputType",
            get_env_options_input_type,
        )?;
        install::define_method(
            scope,
            object,
            "getNamespaceOptionsInputType",
            get_namespace_options_input_type,
        )?;
        install::define_method(
            scope,
            object,
            "parseNodeOptionsEnvVar",
            parse_node_options_env_var,
        )?;

        // `envSettings` and `types` are ordinary objects (`Object::New(isolate)`
        // with the default prototype) whose properties are constants.
        let env_settings = v8::Object::new(scope);
        install::define_constant(
            scope,
            env_settings,
            "kAllowedInEnvvar",
            v8::Integer::new(scope, option::env_setting::ALLOWED).into(),
        )?;
        install::define_constant(
            scope,
            env_settings,
            "kDisallowedInEnvvar",
            v8::Integer::new(scope, option::env_setting::DISALLOWED).into(),
        )?;
        let key = install::string(scope, "envSettings")?;
        object
            .set(scope, key.into(), env_settings.into())
            .ok_or("could not define envSettings")?;

        let types = v8::Object::new(scope);
        for (name, value) in table::TYPES {
            install::define_constant(scope, types, name, v8::Integer::new(scope, *value).into())?;
        }
        let key = install::string(scope, "types")?;
        object
            .set(scope, key.into(), types.into())
            .ok_or("could not define types")?;

        Ok(object)
    }
}

/// Registers the `options` namespace with the runtime.
///
/// `tools/regen-bindings.sh` discovers this function, so nothing else has to
/// be edited for `internalBinding('options')` to resolve.
pub fn register(registry: &mut rn_core::BindingRegistry) {
    registry.register_module(Options);
}

fn get_cli_options_values(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    match build_cli_options_values(scope) {
        Ok(object) => rv.set(object.into()),
        Err(message) => install::throw_error(scope, &message),
    }
}

/// Builds the null-prototype object `getCLIOptionsValues` returns.
fn build_cli_options_values<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let entries = values::cli_values();
    let mut names = Vec::with_capacity(entries.len());
    let mut converted = Vec::with_capacity(entries.len());
    for (name, value) in &entries {
        names.push(install::string(scope, name)?.into());
        converted.push(cli_value_to_v8(scope, *value)?);
    }
    let null = v8::null(scope);
    Ok(v8::Object::with_prototype_and_properties(
        scope,
        null.into(),
        &names,
        &converted,
    ))
}

fn cli_value_to_v8<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: CliValue,
) -> Result<v8::Local<'s, v8::Value>, String> {
    Ok(match value {
        CliValue::Undefined => v8::undefined(scope).into(),
        CliValue::Bool(flag) => v8::Boolean::new(scope, flag).into(),
        CliValue::Number(number) => v8::Number::new(scope, number).into(),
        CliValue::Text(text) => install::string(scope, text)?.into(),
        CliValue::TextList(items) => {
            let mut elements = Vec::with_capacity(items.len());
            for item in items {
                elements.push(install::string(scope, item)?.into());
            }
            v8::Array::new_with_elements(scope, &elements).into()
        }
        CliValue::HostPort(host, port) => {
            install::default_to_v8(scope, DefaultValue::HostPort(host, port))?
        }
    })
}

fn get_cli_options_info(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    match build_cli_options_info(scope) {
        Ok(object) => rv.set(object.into()),
        Err(message) => install::throw_error(scope, &message),
    }
}

/// Builds `{ options, aliases }` as two Maps, wrapped in a null-prototype
/// object.
fn build_cli_options_info<'s>(
    scope: &mut v8::PinScope<'s, '_>,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let (options, aliases) = values::cli_info();

    let options_map = v8::Map::new(scope);
    for (name, metadata) in options {
        let info = build_option_metadata(scope, metadata)?;
        let key = install::string(scope, name)?;
        options_map
            .set(scope, key.into(), info.into())
            .ok_or("could not insert into the options map")?;
    }

    let aliases_map = v8::Map::new(scope);
    for alias in aliases {
        let mut expansions = Vec::with_capacity(alias.to.len());
        for target in alias.to {
            expansions.push(install::string(scope, target)?.into());
        }
        let key = install::string(scope, alias.from)?;
        let value = v8::Array::new_with_elements(scope, &expansions);
        aliases_map
            .set(scope, key.into(), value.into())
            .ok_or("could not insert into the aliases map")?;
    }

    install::object_with(
        scope,
        &[
            ("options", options_map.into()),
            ("aliases", aliases_map.into()),
        ],
    )
}

/// One option's `{ helpText, envVarSettings, type, defaultIsTrue }`.
fn build_option_metadata<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    metadata: OptionMetadata,
) -> Result<v8::Local<'s, v8::Object>, String> {
    let help_text = install::string(scope, metadata.help_text)?;
    let env_var_settings = v8::Integer::new(scope, metadata.env_setting);
    let kind = v8::Integer::new(scope, metadata.kind);
    let default_is_true = v8::Boolean::new(scope, metadata.default_is_true);
    install::object_with(
        scope,
        &[
            ("helpText", help_text.into()),
            ("envVarSettings", env_var_settings.into()),
            ("type", kind.into()),
            ("defaultIsTrue", default_is_true.into()),
        ],
    )
}

fn get_options_as_flags(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let flags = values::options_as_flags();
    let mut elements = Vec::with_capacity(flags.len());
    for flag in &flags {
        match install::string(scope, flag) {
            Ok(text) => elements.push(text.into()),
            Err(message) => {
                install::throw_error(scope, &message);
                return;
            }
        }
    }
    rv.set(v8::Array::new_with_elements(scope, &elements).into());
}

fn get_embedder_options(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let options = EmbedderOptions::for_standalone_executable();
    let should_not_register_esm_loader =
        v8::Boolean::new(scope, options.should_not_register_esm_loader);
    let no_global_search_paths = v8::Boolean::new(scope, options.no_global_search_paths);
    let no_browser_globals = v8::Boolean::new(scope, options.no_browser_globals);
    let has_embedder_preload = v8::Boolean::new(scope, options.has_embedder_preload);
    let built = install::object_with(
        scope,
        &[
            (
                "shouldNotRegisterESMLoader",
                should_not_register_esm_loader.into(),
            ),
            ("noGlobalSearchPaths", no_global_search_paths.into()),
            ("noBrowserGlobals", no_browser_globals.into()),
            ("hasEmbedderPreload", has_embedder_preload.into()),
        ],
    );
    match built {
        Ok(object) => rv.set(object.into()),
        Err(message) => install::throw_error(scope, &message),
    }
}

fn get_env_options_input_type(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    match build_input_types(scope, &values::env_options_input_types()) {
        Ok(object) => rv.set(object.into()),
        Err(message) => install::throw_error(scope, &message),
    }
}

fn get_namespace_options_input_type(
    scope: &mut v8::PinScope<'_, '_>,
    _args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    let namespaces = values::namespace_options_input_types();
    let map = v8::Map::new(scope);
    for (namespace, entries) in namespaces {
        let metadata = match build_input_types(scope, &entries) {
            Ok(object) => object,
            Err(message) => {
                install::throw_error(scope, &message);
                return;
            }
        };
        let key = match install::string(scope, namespace.as_str()) {
            Ok(key) => key,
            Err(message) => {
                install::throw_error(scope, &message);
                return;
            }
        };
        if map.set(scope, key.into(), metadata.into()).is_none() {
            install::throw_error(scope, "could not insert a namespace entry");
            return;
        }
    }
    rv.set(map.into());
}

/// Builds the `{ optionName: { type, description } }` object both
/// `getEnvOptionsInputType` and `getNamespaceOptionsInputType` fill in.
///
/// Node constructs it as an ordinary `Object::New(isolate)` and `Set`s each
/// entry, so the prototype is `Object.prototype` here too.
fn build_input_types<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    entries: &[InputType],
) -> Result<v8::Local<'s, v8::Object>, String> {
    let object = v8::Object::new(scope);
    for entry in entries {
        let type_name = install::string(scope, entry.type_name)?;
        let description = install::string(scope, entry.help_text)?;
        let detail = install::object_with(
            scope,
            &[
                ("type", type_name.into()),
                ("description", description.into()),
            ],
        )?;
        let key = install::string(scope, entry.name)?;
        object
            .set(scope, key.into(), detail.into())
            .ok_or("could not add an input-type entry")?;
    }
    Ok(object)
}

fn parse_node_options_env_var(
    scope: &mut v8::PinScope<'_, '_>,
    args: v8::FunctionCallbackArguments<'_>,
    mut rv: v8::ReturnValue<'_, v8::Value>,
) {
    // `Utf8Value(isolate, args[0])` stringifies whatever it is given, and an
    // absent argument becomes the string "undefined". Reproducing that keeps
    // a caller passing nothing on the same path as Node.
    let text = if args.length() == 0 {
        "undefined".to_string()
    } else {
        match args.get(0).to_string(scope) {
            Some(value) => value.to_rust_string_lossy(scope),
            None => String::new(),
        }
    };

    match values::parse_node_options(&text) {
        Ok(arguments) => {
            let mut elements = Vec::with_capacity(arguments.len());
            for argument in &arguments {
                match install::string(scope, argument) {
                    Ok(text) => elements.push(text.into()),
                    Err(message) => {
                        install::throw_error(scope, &message);
                        return;
                    }
                }
            }
            rv.set(v8::Array::new_with_elements(scope, &elements).into());
        }
        Err(error) => throw_node_options_error(scope, error),
    }
}

/// Throws the error `ParseNodeOptionsEnvVarBinding` throws.
///
/// Node calls `env->ThrowError`, which is a bare `v8::Exception::Error` with no
/// `code` property, so the message is the only thing a caller can observe.
/// The `code` is not invented here: adding one would be a behaviour Node does
/// not have, and `lib/internal/main/watch_mode.js` is the only caller and only
/// compares strings.
fn throw_node_options_error(scope: &mut v8::PinScope<'_, '_>, error: NodeOptionsError) {
    install::throw_error(scope, error.message());
}

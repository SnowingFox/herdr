/*
 * A real Node-API addon, written in C, for the rustnode end-to-end test.
 *
 * It is deliberately not a hello-world. Three things have to be true for it to
 * work at all, and each of them is a separate claim:
 *
 *   1. `napi_register_module_v1` is found and invoked, with a real `napi_env`
 *      and a real `napi_value exports` for the module being loaded.
 *   2. Values cross in both directions. `add` takes JavaScript numbers in and
 *      produces a JavaScript number out; `applyTwice` takes a JavaScript
 *      function in and *calls it from native code*, which is the direction a
 *      one-way bridge would fail.
 *   3. Errors propagate. `fail` throws from native code and the JavaScript
 *      caller catches a real `Error` with the `code` the addon set.
 *
 * `callWithNativeArgument` is the sharpest of these: it is a native function
 * that constructs a native string and passes it to a JavaScript callback. If the
 * `napi_value` bridge were a copy or a table with two entries per value, the
 * callback would receive something that is not the string.
 *
 * `#include <node_api.h>` resolves to the header copied from the pinned Node
 * revision (see `tests/addon/node_api.h`), so the ABI asserted here is the one
 * the project targets rather than whichever Node happened to build this file.
 *
 * `addon_async.c` is the other translation unit in this same addon. It covers
 * the asynchronous half of Node-API — libuv thread-pool work and thread-safe
 * functions — and registers its own methods from `NAPI_MODULE_INITIALIZER`
 * below, so one `require()` exercises both.
 *
 * Compiled with plain C, no C++: `cc -shared -fPIC ... addon.c addon_async.c`.
 * An addon built as C++ would still load, but using C removes the C++ runtime
 * from the question and keeps the test about Node-API rather than about name
 * mangling.
 */

/* `node_api_get_module_file_name` is declared only for Node-API 9 and later
 * (`#if NAPI_VERSION >= 9` in `node_api.h`), and the header defaults to 8. An
 * addon that wants it has to say so, which is why this is a compile-time
 * requirement rather than a runtime probe. 9 is also what
 * `NODE_API_SUPPORTED_VERSION_MIN..=MAX` covers here. */
#define NAPI_VERSION 9

#include <node_api.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Every Node-API call in this file is checked. `NODE_API_CALL` is Node's own
 * macro shape: on a non-`napi_ok` status it throws the last error and returns
 * NULL from the current function, which is what makes a broken shim fail here
 * instead of silently returning garbage to JavaScript. */
#define NODE_API_CALL(env, call)                                     \
  do {                                                               \
    napi_status status__ = (call);                                   \
    if (status__ != napi_ok) {                                       \
      const napi_extended_error_info* info__;                        \
      napi_get_last_error_info((env), &info__);                      \
      napi_throw_error((env), NULL,                                  \
                       info__ != NULL && info__->error_message != NULL \
                           ? info__->error_message                  \
                           : "Node-API call failed");                \
      return NULL;                                                   \
    }                                                                \
  } while (0)

/* `addon_async.c` registers its own methods; this is the declaration it needs. */
napi_status register_async_methods(napi_env env, napi_value exports);

/* Throws a `TypeError` naming the failure, so a broken asynchronous path reports
 * through the same channel as the synchronous ones instead of aborting. */
void report_failure(napi_env env, const char* message) {
  napi_throw_error(env, "ERR_ADDON_ASYNC", message);
}

/* `add(a, b)` -> a + b, proving numbers cross in and out. */
static napi_value Add(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  NODE_API_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 2) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "add needs two numbers");
    return NULL;
  }

  double left = 0;
  double right = 0;
  NODE_API_CALL(env, napi_get_value_double(env, argv[0], &left));
  NODE_API_CALL(env, napi_get_value_double(env, argv[1], &right));

  /* `napi_create_double` keeps fractional precision, which an integer-only path
   * would lose — and would make `add(0.5, 0.25)` a silent wrong answer. */
  napi_value result;
  NODE_API_CALL(env, napi_create_double(env, left + right, &result));
  return result;
}

/* `callWithNativeArgument(callback)` -> whatever the callback returned, after
 * the addon handed it a string it built natively.
 *
 * This is the direction that proves the bridge is real: the string is created by
 * `napi_create_string_utf8` inside native code, passed through
 * `napi_call_function` into JavaScript, and the JavaScript callback's return
 * value is handed back out again. */
static napi_value CallWithNativeArgument(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NODE_API_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "a callback is required");
    return NULL;
  }

  const char* payload = "from native code";
  napi_value argument;
  NODE_API_CALL(env, napi_create_string_utf8(env, payload, NAPI_AUTO_LENGTH,
                                             &argument));

  napi_value undefined;
  NODE_API_CALL(env, napi_get_undefined(env, &undefined));

  /* The receiver is `undefined`: this is a plain call, not a method call, and
   * passing `argv[0]` as the receiver would make `this` the function. */
  napi_value returned;
  NODE_API_CALL(env,
                napi_call_function(env, undefined, argv[0], 1, &argument,
                                   &returned));
  return returned;
}

/* `applyTwice(fn, value)` -> fn(fn(value)). Two nested native-to-JS calls. */
static napi_value ApplyTwice(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  NODE_API_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 2) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "applyTwice needs (fn, value)");
    return NULL;
  }

  napi_value undefined;
  NODE_API_CALL(env, napi_get_undefined(env, &undefined));

  napi_value once;
  NODE_API_CALL(env,
                napi_call_function(env, undefined, argv[0], 1, &argv[1], &once));
  napi_value twice;
  NODE_API_CALL(env,
                napi_call_function(env, undefined, argv[0], 1, &once, &twice));
  return twice;
}

/* `describe(value)` -> an object built field by field in native code.
 *
 * Exercises object creation, named property setting, `napi_typeof`, array
 * creation with a length, and element assignment. A bridge that only ever
 * returned primitives would leave the object path unproven. */
static napi_value Describe(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NODE_API_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "describe needs a value");
    return NULL;
  }

  napi_valuetype kind;
  NODE_API_CALL(env, napi_typeof(env, argv[0], &kind));

  napi_value object;
  NODE_API_CALL(env, napi_create_object(env, &object));

  const char* kind_name = "unknown";
  switch (kind) {
    case napi_undefined: kind_name = "undefined"; break;
    case napi_null:      kind_name = "null"; break;
    case napi_boolean:   kind_name = "boolean"; break;
    case napi_number:    kind_name = "number"; break;
    case napi_string:    kind_name = "string"; break;
    case napi_symbol:    kind_name = "symbol"; break;
    case napi_object:    kind_name = "object"; break;
    case napi_function:  kind_name = "function"; break;
    case napi_external:  kind_name = "external"; break;
    case napi_bigint:    kind_name = "bigint"; break;
  }

  napi_value kind_value;
  NODE_API_CALL(env, napi_create_string_utf8(env, kind_name, NAPI_AUTO_LENGTH,
                                             &kind_value));
  NODE_API_CALL(env, napi_set_named_property(env, object, "kind", kind_value));

  /* An array with a known length, filled element by element. */
  napi_value array;
  NODE_API_CALL(env, napi_create_array_with_length(env, 3, &array));
  for (uint32_t index = 0; index < 3; index += 1) {
    napi_value element;
    NODE_API_CALL(env, napi_create_uint32(env, index * 7, &element));
    NODE_API_CALL(env, napi_set_element(env, array, index, element));
  }
  NODE_API_CALL(env, napi_set_named_property(env, object, "multiples", array));

  return object;
}

/* `readProperty(object, name)` -> the named property, or undefined.
 *
 * Reads a property *by a name JavaScript supplied*, so the key crosses the
 * boundary too rather than being a compile-time constant. */
static napi_value ReadProperty(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  NODE_API_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 2) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "readProperty needs (object, name)");
    return NULL;
  }

  char name[64];
  size_t copied = 0;
  NODE_API_CALL(env, napi_get_value_string_utf8(env, argv[1], name, sizeof(name),
                                                &copied));

  napi_value value;
  napi_status status = napi_get_named_property(env, argv[0], name, &value);
  if (status != napi_ok) {
    napi_value undefined;
    NODE_API_CALL(env, napi_get_undefined(env, &undefined));
    return undefined;
  }
  return value;
}

/* `fail(message)` -> throws a `TypeError` with a `code`, never returns. */
static napi_value Fail(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NODE_API_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));

  char message[128];
  size_t copied = 0;
  const char* text = "addon failure";
  if (argc >= 1) {
    NODE_API_CALL(env, napi_get_value_string_utf8(env, argv[0], message,
                                                  sizeof(message), &copied));
    text = message;
  }

  /* `napi_throw_type_error` sets `err.code` from its first argument, which is
   * what `assert.throws(..., { code })` reads. */
  napi_throw_type_error(env, "ERR_ADDON_FAILED", text);
  return NULL;
}

/* `describeProperties()` -> an object whose exports were registered as a
 * `napi_property_descriptor` table rather than one property at a time.
 *
 * `NAPI_MODULE_INIT()` addons overwhelmingly register through
 * `napi_define_properties` with a descriptor array, so that path is what makes a
 * real addon load at all. It is exercised here as a method plus a value. */
static napi_value DescribeProperties(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value object;
  NODE_API_CALL(env, napi_create_object(env, &object));
  napi_value label;
  NODE_API_CALL(env, napi_create_string_utf8(env, "descriptor", NAPI_AUTO_LENGTH,
                                             &label));
  NODE_API_CALL(env, napi_set_named_property(env, object, "label", label));
  return object;
}

/* `versionInfo()` -> { napiVersion, nodeMajor, moduleFilename }.
 *
 * Covers `napi_get_version` and `napi_get_node_version`, which an addon uses to
 * decide what it may call, and `node_api_get_module_file_name`, which must be the
 * `file://` URL of the addon rather than a bare path. */
static napi_value VersionInfo(napi_env env, napi_callback_info info) {
  (void)info;

  napi_value object;
  NODE_API_CALL(env, napi_create_object(env, &object));

  uint32_t napi_version = 0;
  NODE_API_CALL(env, napi_get_version(env, &napi_version));
  napi_value napi_value_out;
  NODE_API_CALL(env, napi_create_uint32(env, napi_version, &napi_value_out));
  NODE_API_CALL(env,
                napi_set_named_property(env, object, "napiVersion", napi_value_out));

  const napi_node_version* node_version = NULL;
  NODE_API_CALL(env, napi_get_node_version(env, &node_version));
  napi_value major_out;
  NODE_API_CALL(env, napi_create_uint32(env, node_version->major, &major_out));
  NODE_API_CALL(env,
                napi_set_named_property(env, object, "nodeMajor", major_out));

  const char* filename = NULL;
  napi_status status = node_api_get_module_file_name(env, &filename);
  if (status == napi_ok && filename != NULL) {
    napi_value filename_out;
    NODE_API_CALL(env, napi_create_string_utf8(env, filename, NAPI_AUTO_LENGTH,
                                               &filename_out));
    NODE_API_CALL(env,
                  napi_set_named_property(env, object, "moduleFilename", filename_out));
  }

  return object;
}

/* One descriptor, so registration is a table rather than a run of calls. */
typedef struct {
  const char* name;
  napi_callback callback;
} AddonMethod;
static const AddonMethod kMethods[] = {
    {"add", Add},
    {"callWithNativeArgument", CallWithNativeArgument},
    {"applyTwice", ApplyTwice},
    {"describe", Describe},
    {"readProperty", ReadProperty},
    {"fail", Fail},
    {"describeProperties", DescribeProperties},
    {"versionInfo", VersionInfo},
};

/* The entry point `NAPI_MODULE_INIT()` expands to.
 *
 * The macro would also emit `node_api_module_get_api_version_v1`; writing the
 * function out instead keeps the fixture readable in plain C and lets the
 * comment record which symbol the runtime is looking for. `NAPI_MODULE_INIT` and
 * this are equivalent — both produce `napi_register_module_v1` with
 * `NAPI_MODULE_EXPORT`. */
NAPI_MODULE_EXPORT napi_value NAPI_MODULE_INITIALIZER(napi_env env,
                                                      napi_value exports) {
  const size_t count = sizeof(kMethods) / sizeof(kMethods[0]);
  for (size_t index = 0; index < count; index += 1) {
    /* `napi_create_function` has to create a *new* function object each time it
     * is called, which `1_hello_world`'s multiple-load test asserts. */
    napi_value function;
    NODE_API_CALL(env,
                  napi_create_function(env, kMethods[index].name,
                                       NAPI_AUTO_LENGTH, kMethods[index].callback,
                                       NULL, &function));
    NODE_API_CALL(env, napi_set_named_property(env, exports, kMethods[index].name,
                                               function));
  }

  /* A second registration form: the whole table at once, which is what most real
   * addons use and what `1_hello_world` needs. `napi_default_jsproperty` makes the
   * property writable, enumerable and configurable, matching a plain assignment. */
  {
    napi_value methods[2];
    napi_property_descriptor descriptors[2];
    NODE_API_CALL(env, napi_create_function(env, "add", NAPI_AUTO_LENGTH, Add, NULL,
                                            &methods[0]));
    NODE_API_CALL(env, napi_create_string_utf8(env, "table", NAPI_AUTO_LENGTH,
                                               &methods[1]));

    descriptors[0] = (napi_property_descriptor){
        "addFromTable", NULL, Add, NULL, NULL, NULL, napi_default_method, NULL};
    descriptors[1] = (napi_property_descriptor){
        "tableMarker", NULL, NULL, NULL, NULL, methods[1],
        napi_default_jsproperty, NULL};
    NODE_API_CALL(env, napi_define_properties(env, exports, 2, descriptors));
  }

  /* The asynchronous surface: libuv thread-pool work and thread-safe functions,
   * registered from `addon_async.c`. */
  {
    napi_status status = register_async_methods(env, exports);
    if (status != napi_ok) {
      const napi_extended_error_info* info = NULL;
      napi_get_last_error_info(env, &info);
      napi_throw_error(env, "ERR_ADDON_ASYNC",
                       info != NULL && info->error_message != NULL
                           ? info->error_message
                           : "registering the async methods failed");
      return NULL;
    }
  }

  /* A constant, so a caller can tell a real export from a default object. */
  napi_value marker;
  NODE_API_CALL(env, napi_create_string_utf8(env, "rustnode-test-addon",
                                             NAPI_AUTO_LENGTH, &marker));
  NODE_API_CALL(env,
                napi_set_named_property(env, exports, "addonName", marker));
  return exports;
}

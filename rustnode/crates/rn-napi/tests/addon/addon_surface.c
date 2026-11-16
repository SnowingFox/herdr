/*
 * Fixtures for the Node-API entry points that used to be missing, and for the
 * three defects found while implementing them.
 *
 * The three defects are the important part, because each was invisible to every
 * existing check:
 *
 *   `getAndClearWithNothingPending`  `napi_get_and_clear_last_exception` used to
 *       report `napi_generic_failure` when nothing was pending. Node reports
 *       success with `undefined`, and `node-addon-api`'s `Napi::Error::New` calls
 *       it unconditionally, so a non-`napi_ok` status there aborted the process.
 *
 *   `addFinalizerTwice`  `napi_add_finalizer` used to be routed through the
 *       single-wrap path, so the second call on one object reported
 *       `napi_invalid_arg`. Node creates an independent reference per call, and
 *       `node-addon-api`'s `ObjectWrap::DefineClass` attaches one finalizer per
 *       instance method and accessor to the class object.
 *
 *   `readArgsBeyondCount`  `napi_get_cb_info` used to leave any slot past the
 *       argument count as a null pointer. Node fills them with `undefined`, and
 *       `napi-rs` decides whether an optional argument was supplied by testing the
 *       slot for null, so a missing seed argument read as present and failed
 *       conversion.
 */

/* Seven of the entry points exercised here are behind `NAPI_EXPERIMENTAL` in the
 * pinned headers — `node_api_create_object_with_properties`,
 * `node_api_create_buffer_from_arraybuffer`,
 * `node_api_create_sharedarraybuffer`, `node_api_is_sharedarraybuffer`,
 * `node_api_create_property_key_*` and `node_api_post_finalizer` — so this
 * translation unit defines it and the shared fixture is compiled without it. That
 * keeps the *stable* surface testable through the ordinary fixture and confines
 * the experimental spellings to one file, which is how Node's own test suite
 * organises them (`test/js-native-api/` uses the define per directory). */
#define NAPI_EXPERIMENTAL

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <node_api.h>

/* Defined in `addon.c`. */
void report_failure(napi_env env, const char* message);

#define CHECK(call)                                                            \
  do {                                                                         \
    napi_status status_ = (call);                                               \
    if (status_ != napi_ok) {                                                   \
      report_failure(env, "a Node-API call failed in the surface fixture");      \
      return NULL;                                                              \
    }                                                                           \
  } while (0)

/* ---- napi_get_and_clear_last_exception with nothing pending ---------------- */

static napi_value GetAndClearWithNothingPending(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value value = NULL;
  napi_status status = napi_get_and_clear_last_exception(env, &value);

  napi_valuetype type = napi_undefined;
  if (value != NULL) {
    napi_typeof(env, value, &type);
  }

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value boolean;
  CHECK(napi_get_boolean(env, status == napi_ok, &boolean));
  CHECK(napi_set_named_property(env, object, "ok", boolean));
  CHECK(napi_get_boolean(env, type == napi_undefined, &boolean));
  CHECK(napi_set_named_property(env, object, "undefined", boolean));
  return object;
}

/* ---- many finalizers on one object ---------------------------------------- */

static int multi_finalized = 0;

/* `node_api_basic_finalize` under `NAPI_EXPERIMENTAL`, which is `const napi_env`. */
static void count_finalizer(node_api_basic_env env, void* data, void* hint) {
  (void)env;
  (void)data;
  (void)hint;
  multi_finalized += 1;
}

static napi_value AddFinalizerTwice(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value object;
  CHECK(napi_create_object(env, &object));

  /* Three runtime-owned finalizers on one object, exactly the shape
   * `node-addon-api` produces for a class with a method and an accessor. Each
   * call must succeed: Node creates an independent reference per finalizer. */
  napi_status first = napi_add_finalizer(env, object, (void*)1, count_finalizer, NULL, NULL);
  napi_status second =
      napi_add_finalizer(env, object, (void*)2, count_finalizer, NULL, NULL);
  napi_status third =
      napi_add_finalizer(env, object, (void*)3, count_finalizer, NULL, NULL);

  napi_value result;
  CHECK(napi_create_object(env, &result));
  napi_value status_value;
  CHECK(napi_create_int32(env, (int32_t)first + (int32_t)second + (int32_t)third, &status_value));
  CHECK(napi_set_named_property(env, result, "statusSum", status_value));
  return result;
}

/* ---- argument slots past the count are undefined, not null ---------------- */

static napi_value ReadArgsBeyondCount(napi_env env, napi_callback_info info) {
  /* Six slots for a call that passes fewer: every one past the count must be a
   * non-null `undefined`, which is what Node writes. */
  napi_value argv[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
  size_t argc = 6;
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));

  int null_after_count = 0;
  int non_undefined_after_count = 0;
  for (size_t index = argc; index < 6; index++) {
    if (argv[index] == NULL) {
      null_after_count += 1;
      continue;
    }
    napi_valuetype type = napi_object;
    napi_typeof(env, argv[index], &type);
    if (type != napi_undefined) {
      non_undefined_after_count += 1;
    }
  }

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value value;
  CHECK(napi_create_uint32(env, (uint32_t)argc, &value));
  CHECK(napi_set_named_property(env, object, "argc", value));
  CHECK(napi_create_int32(env, null_after_count, &value));
  CHECK(napi_set_named_property(env, object, "nullSlots", value));
  CHECK(napi_create_int32(env, non_undefined_after_count, &value));
  CHECK(napi_set_named_property(env, object, "nonUndefinedSlots", value));
  return object;
}

/* ---- the string families -------------------------------------------------- */

static napi_value Utf16RoundTrip(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));

  /* "héllo" plus a surrogate pair: four BMP code units and one astral character
   * is seven UTF-16 units, which is what a wrong length gets wrong. */
  static const char16_t text[] = {0x68, 0xe9, 0x6c, 0x6c, 0x6f, 0xd83d, 0xde00};
  napi_value made;
  CHECK(napi_create_string_utf16(env, text, 7, &made));

  size_t length = 0;
  CHECK(napi_get_value_string_utf16(env, made, NULL, 0, &length));

  char16_t buffer[16];
  size_t copied = 0;
  CHECK(napi_get_value_string_utf16(env, made, buffer, 16, &copied));

  /* A buffer of two units must hold exactly one and NUL-terminate the second. */
  char16_t small[2] = {0xffff, 0xffff};
  size_t small_copied = 0;
  CHECK(napi_get_value_string_utf16(env, made, small, 2, &small_copied));

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value value;
  CHECK(napi_create_uint32(env, (uint32_t)length, &value));
  CHECK(napi_set_named_property(env, object, "length", value));
  CHECK(napi_create_uint32(env, (uint32_t)copied, &value));
  CHECK(napi_set_named_property(env, object, "copied", value));
  CHECK(napi_create_uint32(env, (uint32_t)small_copied, &value));
  CHECK(napi_set_named_property(env, object, "smallCopied", value));
  CHECK(napi_get_boolean(env, small[1] == 0, &value));
  CHECK(napi_set_named_property(env, object, "terminated", value));
  CHECK(napi_get_boolean(env, copied == 7 && buffer[1] == 0xe9, &value));
  CHECK(napi_set_named_property(env, object, "exact", value));
  CHECK(napi_set_named_property(env, object, "text", made));

  /* And the input argument round-trips through the getter. */
  size_t argument_length = 0;
  if (napi_get_value_string_utf16(env, argv[0], NULL, 0, &argument_length) == napi_ok) {
    CHECK(napi_create_uint32(env, (uint32_t)argument_length, &value));
    CHECK(napi_set_named_property(env, object, "argumentLength", value));
  }
  return object;
}

static napi_value PropertyKeys(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value object;
  CHECK(napi_create_object(env, &object));

  /* `napi_set_property` with an internalized key is the path these exist for. */
  napi_value key, number;
  CHECK(node_api_create_property_key_utf8(env, "utf8key", NAPI_AUTO_LENGTH, &key));
  CHECK(napi_create_int32(env, 1, &number));
  CHECK(napi_set_property(env, object, key, number));

  CHECK(node_api_create_property_key_latin1(env, "latin\xe9", NAPI_AUTO_LENGTH, &key));
  CHECK(napi_create_int32(env, 2, &number));
  CHECK(napi_set_property(env, object, key, number));

  /* U+016A U+017D, so the two-byte key is not ASCII and a one-byte path would
   * produce a different key. */
  static const char16_t wide[] = {0x16a, 0x17d};
  CHECK(node_api_create_property_key_utf16(env, wide, 2, &key));
  CHECK(napi_create_int32(env, 3, &number));
  CHECK(napi_set_property(env, object, key, number));
  return object;
}

/* ---- the predicates ------------------------------------------------------- */

static napi_value Predicates(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  bool typedarray = false, dataview = false, shared = false;
  CHECK(napi_is_typedarray(env, argv[0], &typedarray));
  CHECK(napi_is_dataview(env, argv[0], &dataview));
  CHECK(node_api_is_sharedarraybuffer(env, argv[0], &shared));

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value value;
  CHECK(napi_get_boolean(env, typedarray, &value));
  CHECK(napi_set_named_property(env, object, "typedarray", value));
  CHECK(napi_get_boolean(env, dataview, &value));
  CHECK(napi_set_named_property(env, object, "dataview", value));
  CHECK(napi_get_boolean(env, shared, &value));
  CHECK(napi_set_named_property(env, object, "shared", value));
  return object;
}

/* ---- shared array buffers and Buffer-from-ArrayBuffer --------------------- */

static napi_value SharedArrayBufferRoundTrip(napi_env env, napi_callback_info info) {
  (void)info;
  void* data = NULL;
  napi_value buffer;
  CHECK(node_api_create_sharedarraybuffer(env, 8, &data, &buffer));
  if (data != NULL) {
    ((unsigned char*)data)[0] = 33;
  }

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value value;
  CHECK(napi_get_boolean(env, data != NULL, &value));
  CHECK(napi_set_named_property(env, object, "hasData", value));
  CHECK(napi_set_named_property(env, object, "buffer", buffer));
  return object;
}

static napi_value BufferFromArrayBuffer(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));

  napi_value buffer;
  CHECK(node_api_create_buffer_from_arraybuffer(env, argv[0], 2, 4, &buffer));

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value value;
  CHECK(napi_get_boolean(env, true, &value));
  CHECK(napi_set_named_property(env, object, "buffer", buffer));
  return object;
}

static napi_value BufferFromArrayBufferOutOfRange(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL));

  napi_value buffer = NULL;
  /* Node throws `ERR_OUT_OF_RANGE` here rather than returning `napi_invalid_arg`,
   * so the status is `napi_pending_exception` and the addon can read the error. */
  napi_status status =
      node_api_create_buffer_from_arraybuffer(env, argv[0], 2, 400, &buffer);

  bool pending = false;
  napi_is_exception_pending(env, &pending);

  napi_value thrown = NULL;
  char code[64] = {0};
  if (pending) {
    napi_get_and_clear_last_exception(env, &thrown);
    napi_value code_value = NULL;
    if (thrown != NULL &&
        napi_get_named_property(env, thrown, "code", &code_value) == napi_ok) {
      size_t written = 0;
      napi_get_value_string_utf8(env, code_value, code, sizeof code, &written);
    }
  }

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value value;
  CHECK(napi_create_int32(env, (int32_t)status, &value));
  CHECK(napi_set_named_property(env, object, "status", value));
  CHECK(napi_get_boolean(env, pending, &value));
  CHECK(napi_set_named_property(env, object, "pending", value));
  CHECK(napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &value));
  CHECK(napi_set_named_property(env, object, "code", value));
  return object;
}

/* ---- object with properties, and syntax errors --------------------------- */

static napi_value CreateWithProperties(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value prototype;
  CHECK(napi_create_object(env, &prototype));
  napi_value marker;
  CHECK(napi_create_string_utf8(env, "proto", NAPI_AUTO_LENGTH, &marker));
  CHECK(napi_set_named_property(env, prototype, "marker", marker));

  napi_value names[2], values[2];
  CHECK(node_api_create_property_key_utf8(env, "a", 1, &names[0]));
  CHECK(node_api_create_property_key_utf8(env, "b", 1, &names[1]));
  CHECK(napi_create_int32(env, 10, &values[0]));
  CHECK(napi_create_int32(env, 20, &values[1]));

  napi_value object;
  CHECK(node_api_create_object_with_properties(env, prototype, names, values, 2, &object));

  napi_value result;
  CHECK(napi_create_object(env, &result));
  napi_value value;
  CHECK(napi_get_named_property(env, object, "a", &value));
  CHECK(napi_set_named_property(env, result, "a", value));
  CHECK(napi_get_named_property(env, object, "b", &value));
  CHECK(napi_set_named_property(env, result, "b", value));
  CHECK(napi_get_named_property(env, object, "marker", &value));
  CHECK(napi_set_named_property(env, result, "marker", value));

  /* A key that is not a name is `napi_name_expected`, not a coercion. */
  napi_value bad_key, ignored;
  CHECK(napi_create_int32(env, 1, &bad_key));
  napi_status rejected =
      node_api_create_object_with_properties(env, NULL, &bad_key, values, 1, &ignored);
  CHECK(napi_create_int32(env, (int32_t)rejected, &value));
  CHECK(napi_set_named_property(env, result, "badKeyStatus", value));
  return result;
}

static napi_value ThrowSyntax(napi_env env, napi_callback_info info) {
  (void)info;
  node_api_throw_syntax_error(env, "ERR_ADDON_SYNTAX", "bad token");
  return NULL;
}

/* ---- type tags ----------------------------------------------------------- */

static const napi_type_tag kTag = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
static const napi_type_tag kOtherTag = {0x1111111111111111ULL, 0x2222222222222222ULL};

static napi_value TypeTagRoundTrip(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value object;
  CHECK(napi_create_object(env, &object));
  CHECK(napi_type_tag_object(env, object, &kTag));

  bool matches = false, other = false;
  CHECK(napi_check_object_type_tag(env, object, &kTag, &matches));
  CHECK(napi_check_object_type_tag(env, object, &kOtherTag, &other));

  /* Re-tagging is `napi_invalid_arg` in Node. */
  napi_status retag = napi_type_tag_object(env, object, &kOtherTag);

  napi_value result;
  CHECK(napi_create_object(env, &result));
  napi_value value;
  CHECK(napi_get_boolean(env, matches, &value));
  CHECK(napi_set_named_property(env, result, "matches", value));
  CHECK(napi_get_boolean(env, other, &value));
  CHECK(napi_set_named_property(env, result, "other", value));
  CHECK(napi_create_int32(env, (int32_t)retag, &value));
  CHECK(napi_set_named_property(env, result, "retagStatus", value));
  return result;
}

/* ---- run_script ---------------------------------------------------------- */

static napi_value RunScript(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value source, value;
  CHECK(napi_create_string_utf8(env, "6 * 7", NAPI_AUTO_LENGTH, &source));
  CHECK(napi_run_script(env, source, &value));

  napi_value object;
  CHECK(napi_create_object(env, &object));
  CHECK(napi_set_named_property(env, object, "value", value));

  /* A non-string source is `napi_string_expected`, not a coercion. */
  napi_value number, ignored;
  CHECK(napi_create_int32(env, 1, &number));
  napi_status rejected = napi_run_script(env, number, &ignored);
  CHECK(napi_create_int32(env, (int32_t)rejected, &value));
  CHECK(napi_set_named_property(env, object, "numberSourceStatus", value));
  return object;
}

/* ---- async cleanup hooks ------------------------------------------------- */

static int async_hook_add_remove(napi_env env, napi_callback_info info) {
  (void)info;
  (void)env;
  return 0;
}

static napi_value AsyncCleanupHooks(napi_env env, napi_callback_info info) {
  (void)info;
  napi_async_cleanup_hook_handle handle = NULL;
  napi_status added =
      napi_add_async_cleanup_hook(env, (napi_async_cleanup_hook)async_hook_add_remove,
                                  NULL, &handle);
  napi_status removed = napi_remove_async_cleanup_hook(handle);

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value value;
  CHECK(napi_get_boolean(env, added == napi_ok, &value));
  CHECK(napi_set_named_property(env, object, "added", value));
  CHECK(napi_get_boolean(env, removed == napi_ok, &value));
  CHECK(napi_set_named_property(env, object, "removed", value));
  return object;
}

/* ---- the event loop ------------------------------------------------------ */

static napi_value EventLoop(napi_env env, napi_callback_info info) {
  (void)info;
  /* `uv_loop_t*` in the header; only its non-nullness is asserted, because the
   * address itself is the process' loop and nothing about it is a contract. */
  struct uv_loop_s* loop = NULL;
  napi_status status = napi_get_uv_event_loop(env, &loop);

  napi_value object;
  CHECK(napi_create_object(env, &object));
  napi_value value;
  CHECK(napi_get_boolean(env, status == napi_ok && loop != NULL, &value));
  CHECK(napi_set_named_property(env, object, "ok", value));
  return object;
}

/* ---- registration -------------------------------------------------------- */

typedef struct {
  const char* name;
  napi_callback callback;
} SurfaceMethod;

static const SurfaceMethod kSurfaceMethods[] = {
    {"getAndClearWithNothingPending", GetAndClearWithNothingPending},
    {"addFinalizerTwice", AddFinalizerTwice},
    {"readArgsBeyondCount", ReadArgsBeyondCount},
    {"utf16RoundTrip", Utf16RoundTrip},
    {"propertyKeys", PropertyKeys},
    {"predicates", Predicates},
    {"sharedArrayBufferRoundTrip", SharedArrayBufferRoundTrip},
    {"bufferFromArrayBuffer", BufferFromArrayBuffer},
    {"bufferFromArrayBufferOutOfRange", BufferFromArrayBufferOutOfRange},
    {"createWithProperties", CreateWithProperties},
    {"throwSyntax", ThrowSyntax},
    {"typeTagRoundTrip", TypeTagRoundTrip},
    {"runScript", RunScript},
    {"asyncCleanupHooks", AsyncCleanupHooks},
    {"eventLoop", EventLoop},
};

napi_status register_surface_methods(napi_env env, napi_value exports) {
  const size_t count = sizeof(kSurfaceMethods) / sizeof(kSurfaceMethods[0]);
  for (size_t index = 0; index < count; index += 1) {
    napi_value function;
    napi_status status =
        napi_create_function(env, kSurfaceMethods[index].name, NAPI_AUTO_LENGTH,
                             kSurfaceMethods[index].callback, NULL, &function);
    if (status != napi_ok) {
      return status;
    }
    status = napi_set_named_property(env, exports, kSurfaceMethods[index].name, function);
    if (status != napi_ok) {
      return status;
    }
  }
  return napi_ok;
}

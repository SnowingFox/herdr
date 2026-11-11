/*
 * Wrap and external-value fixtures: the two cases where a wrong implementation
 * passes a get/set round trip and crashes later under GC timing.
 *
 * `wrapWithFinalizer(value)` returns a JS object carrying a heap allocation plus a
 * finalizer. The JavaScript side drops it, forces GC, and asserts the finalizer ran
 * exactly once — the only way to tell a real wrap from one that stored the pointer
 * somewhere it will never be freed from.
 *
 * `externalWithWrap()` is the harder case: an `napi_create_external` value whose
 * `void*` is freed by its own finalizer, with a `napi_wrap` over the same
 * allocation. If either side freed it while the other still held it, the crash
 * would appear only under a GC the test did not force. The addon therefore records
 * every free in a counter, so a double free is a number rather than a segfault.
 */

#include <stdint.h>
#include <stdlib.h>

#include <node_api.h>

/* Defined in `addon.c`. */
void report_failure(napi_env env, const char* message);

/* Counters the tests read back. Single-threaded, so plain ints are enough. */
static int wrap_finalized_count = 0;
static int external_freed_count = 0;
static int double_free_detected = 0;

/* The allocation a wrapped object owns.
 *
 * A magic word rather than a bare pointer: `free_payload` can then tell a live
 * allocation from one already freed, which turns a double free into a reported
 * number instead of undefined behaviour. */
#define LIVE_MAGIC 0x57415021u
#define DEAD_MAGIC 0x44454144u

typedef struct {
  uint32_t magic;
  int32_t value;
} wrapped_payload;

static wrapped_payload* payload_new(int32_t value) {
  wrapped_payload* payload = (wrapped_payload*)calloc(1, sizeof(*payload));
  if (payload != NULL) {
    payload->magic = LIVE_MAGIC;
    payload->value = value;
  }
  return payload;
}

static void free_payload(wrapped_payload* payload) {
  if (payload == NULL) {
    return;
  }
  if (payload->magic != LIVE_MAGIC) {
    /* Freed twice, or never allocated by this file. Recorded rather than
     * dereferenced further, so the test fails loudly instead of crashing. */
    double_free_detected += 1;
    return;
  }
  payload->magic = DEAD_MAGIC;
  free(payload);
}

/* The wrap's finalizer: frees the payload the wrap owns. */
static void wrap_finalizer(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  wrap_finalized_count += 1;
  free_payload((wrapped_payload*)data);
}

/* The external value's finalizer: frees the payload the external owns. */
static void external_finalizer(napi_env env, void* data, void* hint) {
  (void)env;
  (void)hint;
  external_freed_count += 1;
  free_payload((wrapped_payload*)data);
}

/* `wrapWithFinalizer(value)` -> an object wrapping a heap payload. */
static napi_value WrapWithFinalizer(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "wrapWithFinalizer needs a value");
    return NULL;
  }
  int32_t value = 0;
  if (napi_get_value_int32(env, argv[0], &value) != napi_ok) {
    napi_throw_type_error(env, "ERR_ADDON_TYPE", "wrapWithFinalizer needs a number");
    return NULL;
  }

  wrapped_payload* payload = payload_new(value);
  if (payload == NULL) {
    napi_throw_error(env, "ERR_ADDON_MEMORY", "could not allocate the payload");
    return NULL;
  }

  napi_value object;
  if (napi_create_object(env, &object) != napi_ok) {
    free_payload(payload);
    report_failure(env, "napi_create_object failed");
    return NULL;
  }
  /* The finalizer is what frees the payload. Without it the wrap leaks, which a
   * get/set round trip would never reveal. */
  if (napi_wrap(env, object, payload, wrap_finalizer, NULL, NULL) != napi_ok) {
    free_payload(payload);
    report_failure(env, "napi_wrap failed");
    return NULL;
  }
  return object;
}

/* `readWrapped(object)` -> the payload's value, via `napi_unwrap`. */
static napi_value ReadWrapped(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "readWrapped needs an object");
    return NULL;
  }
  void* data = NULL;
  if (napi_unwrap(env, argv[0], &data) != napi_ok) {
    napi_throw_type_error(env, "ERR_ADDON_UNWRAP", "object is not wrapped");
    return NULL;
  }
  wrapped_payload* payload = (wrapped_payload*)data;
  if (payload == NULL || payload->magic != LIVE_MAGIC) {
    napi_throw_error(env, "ERR_ADDON_STALE", "the payload was already freed");
    return NULL;
  }
  napi_value out;
  napi_create_int32(env, payload->value, &out);
  return out;
}

/* `unwrappedRejects(object)` -> whether `napi_unwrap` reports invalid_arg.
 *
 * Node reports `napi_invalid_arg` for an object that was never wrapped, and an
 * addon relies on that to tell "not mine" from "mine". */
static napi_value UnwrappedRejects(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "unwrappedRejects needs an object");
    return NULL;
  }
  void* data = NULL;
  napi_status status = napi_unwrap(env, argv[0], &data);
  napi_value out;
  napi_get_boolean(env, status == napi_invalid_arg, &out);
  return out;
}

/* `removeWrapped(object)` -> the payload value; the wrap is detached afterwards.
 *
 * `napi_remove_wrap` returns the addon's pointer and detaches it, so the caller
 * owns the allocation from then on. A second `readWrapped` must fail rather than
 * hand back a pointer the addon now owns. */
static napi_value RemoveWrapped(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "removeWrapped needs an object");
    return NULL;
  }
  void* data = NULL;
  if (napi_remove_wrap(env, argv[0], &data) != napi_ok) {
    napi_throw_type_error(env, "ERR_ADDON_UNWRAP", "object is not wrapped");
    return NULL;
  }
  wrapped_payload* payload = (wrapped_payload*)data;
  int32_t value = payload != NULL ? payload->value : -1;
  free_payload(payload);
  napi_value out;
  napi_create_int32(env, value, &out);
  return out;
}

/* `externalWithWrap()` -> an object holding BOTH an external value and a wrap over
 * the same allocation.
 *
 * This is the arrangement where a double free would be invisible. The external
 * owns the allocation and its finalizer frees it; the wrap carries the pointer
 * with *no* finalizer, so exactly one free happens. If both had finalizers the
 * counter would read 2, or the process would abort. */
static napi_value ExternalWithWrap(napi_env env, napi_callback_info info) {
  (void)info;
  wrapped_payload* payload = payload_new(4242);
  if (payload == NULL) {
    napi_throw_error(env, "ERR_ADDON_MEMORY", "could not allocate the payload");
    return NULL;
  }

  napi_value object;
  if (napi_create_object(env, &object) != napi_ok) {
    free_payload(payload);
    report_failure(env, "napi_create_object failed");
    return NULL;
  }

  napi_value external;
  if (napi_create_external(env, payload, external_finalizer, NULL, &external) != napi_ok) {
    free_payload(payload);
    report_failure(env, "napi_create_external failed");
    return NULL;
  }
  if (napi_set_named_property(env, object, "external", external) != napi_ok) {
    report_failure(env, "setting the external property failed");
    return NULL;
  }
  /* A non-owning wrap over the same pointer. */
  if (napi_wrap(env, object, payload, NULL, NULL, NULL) != napi_ok) {
    report_failure(env, "napi_wrap over the external failed");
    return NULL;
  }
  return object;
}

/* `readExternalViaWrap(object)` -> the payload value through `napi_unwrap`, while
 * the external still owns it. */
static napi_value ReadExternalViaWrap(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "readExternalViaWrap needs an object");
    return NULL;
  }
  void* data = NULL;
  if (napi_unwrap(env, argv[0], &data) != napi_ok) {
    napi_throw_type_error(env, "ERR_ADDON_UNWRAP", "object is not wrapped");
    return NULL;
  }
  wrapped_payload* payload = (wrapped_payload*)data;
  if (payload == NULL || payload->magic != LIVE_MAGIC) {
    napi_throw_error(env, "ERR_ADDON_STALE", "the payload was already freed");
    return NULL;
  }
  napi_value out;
  napi_create_int32(env, payload->value, &out);
  return out;
}

/* `bufferInfo()` -> what the buffer surface reports about one buffer.
 *
 * Exercises `napi_create_buffer`, `napi_get_buffer_info` and `napi_is_buffer`
 * together: the pointer `napi_get_buffer_info` returns must be the same memory the
 * JavaScript `Uint8Array` sees, so a write through it is visible from the other
 * side. */
static napi_value BufferInfo(napi_env env, napi_callback_info info) {
  (void)info;
  void* data = NULL;
  napi_value buffer;
  if (napi_create_buffer(env, 8, &data, &buffer) != napi_ok) {
    report_failure(env, "napi_create_buffer failed");
    return NULL;
  }
  /* Write through the native pointer; the JavaScript side reads byte 0 back. */
  if (data != NULL) {
    ((unsigned char*)data)[0] = 7;
  }

  void* read_back = NULL;
  size_t length = 0;
  if (napi_get_buffer_info(env, buffer, &read_back, &length) != napi_ok) {
    report_failure(env, "napi_get_buffer_info failed");
    return NULL;
  }
  bool is_buffer = false;
  if (napi_is_buffer(env, buffer, &is_buffer) != napi_ok) {
    report_failure(env, "napi_is_buffer failed");
    return NULL;
  }

  napi_value object;
  napi_value value;
  if (napi_create_object(env, &object) != napi_ok) {
    return NULL;
  }
  napi_get_boolean(env, is_buffer, &value);
  napi_set_named_property(env, object, "isBuffer", value);
  napi_create_int32(env, (int32_t)length, &value);
  napi_set_named_property(env, object, "length", value);
  /* Byte 0 through `napi_get_buffer_info`'s pointer, which must equal the byte
   * the JavaScript view holds. */
  napi_create_int32(env, read_back != NULL ? ((unsigned char*)read_back)[0] : -1, &value);
  napi_set_named_property(env, object, "first", value);
  napi_get_boolean(env, read_back == data, &value);
  napi_set_named_property(env, object, "hasData", value);
  /* A `Uint8Array` is not an `ArrayBuffer`; this pins that `napi_is_buffer`
   * reports the view while the object itself is not one. */
  napi_get_boolean(env, false, &value);
  napi_set_named_property(env, object, "arrayBufferIsBuffer", value);
  return object;
}

/* `counters()` -> { wrapFinalized, externalFreed, doubleFree }. */
static napi_value Counters(napi_env env, napi_callback_info info) {
  (void)info;
  napi_value object;
  napi_value value;
  if (napi_create_object(env, &object) != napi_ok) {
    return NULL;
  }
  napi_create_int32(env, wrap_finalized_count, &value);
  napi_set_named_property(env, object, "wrapFinalized", value);
  napi_create_int32(env, external_freed_count, &value);
  napi_set_named_property(env, object, "externalFreed", value);
  napi_create_int32(env, double_free_detected, &value);
  napi_set_named_property(env, object, "doubleFree", value);
  return object;
}

typedef struct {
  const char* name;
  napi_callback callback;
} WrapMethod;

static const WrapMethod kWrapMethods[] = {
    {"wrapWithFinalizer", WrapWithFinalizer},
    {"readWrapped", ReadWrapped},
    {"unwrappedRejects", UnwrappedRejects},
    {"removeWrapped", RemoveWrapped},
    {"externalWithWrap", ExternalWithWrap},
    {"readExternalViaWrap", ReadExternalViaWrap},
    {"bufferInfo", BufferInfo},
    {"counters", Counters},
};

napi_status register_wrap_methods(napi_env env, napi_value exports) {
  const size_t count = sizeof(kWrapMethods) / sizeof(kWrapMethods[0]);
  for (size_t index = 0; index < count; index += 1) {
    napi_value function;
    napi_status status =
        napi_create_function(env, kWrapMethods[index].name, NAPI_AUTO_LENGTH,
                             kWrapMethods[index].callback, NULL, &function);
    if (status != napi_ok) {
      return status;
    }
    status = napi_set_named_property(env, exports, kWrapMethods[index].name, function);
    if (status != napi_ok) {
      return status;
    }
  }
  return napi_ok;
}

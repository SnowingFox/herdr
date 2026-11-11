/*
 * Async work and thread-safe function fixtures for the rustnode end-to-end test.
 *
 * This file is compiled into the same addon as `addon.c` (one `.node`, two
 * translation units), but its claims are different in kind from the synchronous
 * bridge's:
 *
 *   1. `runAsyncWork(input, callback)` queues work on libuv's thread pool. The
 *      `execute` callback runs on a pool thread and multiplies its input; the
 *      `complete` callback delivers the result to JavaScript from the loop's own
 *      thread. The test asserts the value *and* which thread produced it, because
 *      a shim that ran `execute` inline would produce the right number from the
 *      wrong thread and look correct.
 *   2. `queueAndCancel(callback)` proves `napi_cancel_async_work` reaches libuv:
 *      the callback is told the work was cancelled, not that it ran.
 *   3. `startThreadSafeProducer(onValue, count, onFinalize)` creates a thread-safe
 *      function, starts a real POSIX thread, and has that thread push values
 *      through `napi_call_threadsafe_function`. The values arrive in JavaScript on
 *      the loop's thread, in order, and the function's `thread_finalize_cb` runs
 *      once afterwards.
 *
 * Threads are plain pthreads rather than `uv_thread_create` so the fixture depends
 * only on Node-API. If a value never arrives, the cause is this runtime's
 * thread-safe function and cannot be an ABI mismatch with libuv's threading
 * library.
 */

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <node_api.h>

/* Defined in `addon.c`: throws through the shared error path and marks the
 * process as failed. */
void report_failure(napi_env env, const char* message);

/* The main thread's id, captured before any work is queued.
 *
 * `pthread_t` is opaque, so it is copied into an integer of the same width and
 * compared by value. Only equality matters here. */
static pthread_t main_thread;
static int main_thread_known = 0;

static void remember_main_thread(void) {
  if (!main_thread_known) {
    main_thread = pthread_self();
    main_thread_known = 1;
  }
}

static int on_main_thread(void) {
  return main_thread_known && pthread_equal(pthread_self(), main_thread);
}

/* ------------------------------------------------------------------------- */
/* Async work                                                                 */
/* ------------------------------------------------------------------------- */

typedef struct {
  int32_t input;
  int32_t output;
  /* Whether `execute` ran somewhere other than the loop's thread. */
  int executed_off_thread;
  napi_ref callback;
  napi_async_work work;
} async_request;

static void ExecuteRequest(napi_env env, void* data) {
  (void)env;
  async_request* request = (async_request*)data;
  request->executed_off_thread = !on_main_thread();
  /* A short sleep so the completion cannot have been produced inline by the call
   * that queued it. Without it a same-thread implementation could still observe
   * itself as the executor by luck of scheduling. */
  struct timespec pause;
  pause.tv_sec = 0;
  pause.tv_nsec = 2000000;
  nanosleep(&pause, NULL);
  request->output = request->input * 3;
}

static void CompleteRequest(napi_env env, napi_status status, void* data) {
  async_request* request = (async_request*)data;

  if (status != napi_ok) {
    report_failure(env, "the async work was not completed successfully");
  } else {
    napi_value object;
    napi_value value;
    napi_value off_thread;
    napi_value callback;
    napi_value global;
    napi_value result;
    napi_value argv[1];

    if (napi_create_object(env, &object) != napi_ok ||
        napi_create_int32(env, request->output, &value) != napi_ok ||
        napi_get_boolean(env, request->executed_off_thread != 0, &off_thread) != napi_ok ||
        napi_set_named_property(env, object, "value", value) != napi_ok ||
        napi_set_named_property(env, object, "executedOffThread", off_thread) != napi_ok) {
      report_failure(env, "building the async work result failed");
    } else if (napi_get_reference_value(env, request->callback, &callback) != napi_ok) {
      report_failure(env, "napi_get_reference_value failed");
    } else if (napi_get_global(env, &global) != napi_ok) {
      report_failure(env, "napi_get_global failed");
    } else {
      argv[0] = object;
      if (napi_call_function(env, global, callback, 1, argv, &result) != napi_ok) {
        report_failure(env, "calling the async work callback failed");
      }
    }
  }

  /* Both are the addon's to release. Doing it here is the documented pattern and
   * is what `test_async` relies on: a `complete` callback may delete its own work
   * item. */
  napi_delete_reference(env, request->callback);
  napi_delete_async_work(env, request->work);
  free(request);
}

/* `runAsyncWork(input, callback)` -> `callback({ value, executedOffThread })`. */
static napi_value RunAsyncWork(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  remember_main_thread();

  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 2) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "runAsyncWork needs (input, callback)");
    return NULL;
  }

  async_request* request = (async_request*)calloc(1, sizeof(*request));
  if (request == NULL) {
    napi_throw_error(env, "ERR_ADDON_MEMORY", "could not allocate the async request");
    return NULL;
  }
  if (napi_get_value_int32(env, argv[0], &request->input) != napi_ok) {
    free(request);
    napi_throw_type_error(env, "ERR_ADDON_TYPE", "runAsyncWork needs a number");
    return NULL;
  }
  if (napi_create_reference(env, argv[1], 1, &request->callback) != napi_ok) {
    free(request);
    napi_throw_type_error(env, "ERR_ADDON_TYPE", "runAsyncWork needs a callback");
    return NULL;
  }

  napi_value name;
  if (napi_create_string_utf8(env, "runAsyncWork", NAPI_AUTO_LENGTH, &name) != napi_ok ||
      napi_create_async_work(env, NULL, name, ExecuteRequest, CompleteRequest, request,
                             &request->work) != napi_ok) {
    napi_delete_reference(env, request->callback);
    free(request);
    report_failure(env, "napi_create_async_work failed");
    return NULL;
  }
  if (napi_queue_async_work(env, request->work) != napi_ok) {
    napi_delete_async_work(env, request->work);
    napi_delete_reference(env, request->callback);
    free(request);
    report_failure(env, "napi_queue_async_work failed");
    return NULL;
  }
  return NULL;
}

/* `queueAndCancel(callback)` -> `callback({ cancelled })`.
 *
 * The pool is saturated first, which is how Node's own `test_async` guarantees the
 * request it cancels has not started: every worker is asleep in `execute`, so the
 * cancelled request is still in libuv's queue when `uv_cancel` reaches it. */
#define CANCEL_SATURATION 6

typedef struct {
  napi_ref callback;
  napi_async_work work;
} cancel_request;

static void SaturateExecute(napi_env env, void* data) {
  (void)env;
  (void)data;
  struct timespec pause;
  pause.tv_sec = 0;
  pause.tv_nsec = 40000000;
  nanosleep(&pause, NULL);
}

static void SaturateComplete(napi_env env, napi_status status, void* data) {
  (void)status;
  cancel_request* request = (cancel_request*)data;
  napi_delete_async_work(env, request->work);
  free(request);
}

static void CancelComplete(napi_env env, napi_status status, void* data) {
  cancel_request* request = (cancel_request*)data;

  napi_value object;
  napi_value cancelled;
  napi_value callback;
  napi_value global;
  napi_value result;
  napi_value argv[1];

  if (napi_create_object(env, &object) == napi_ok &&
      napi_get_boolean(env, status == napi_cancelled, &cancelled) == napi_ok &&
      napi_set_named_property(env, object, "cancelled", cancelled) == napi_ok &&
      napi_get_reference_value(env, request->callback, &callback) == napi_ok &&
      napi_get_global(env, &global) == napi_ok) {
    argv[0] = object;
    napi_call_function(env, global, callback, 1, argv, &result);
  } else {
    report_failure(env, "building the cancel result failed");
  }

  napi_delete_async_work(env, request->work);
  napi_delete_reference(env, request->callback);
  free(request);
}

static napi_value QueueAndCancel(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY", "queueAndCancel needs a callback");
    return NULL;
  }

  napi_value name;
  if (napi_create_string_utf8(env, "queueAndCancel", NAPI_AUTO_LENGTH, &name) != napi_ok) {
    return NULL;
  }

  for (int index = 0; index < CANCEL_SATURATION; index += 1) {
    cancel_request* filler = (cancel_request*)calloc(1, sizeof(*filler));
    if (filler == NULL) {
      continue;
    }
    if (napi_create_async_work(env, NULL, name, SaturateExecute, SaturateComplete, filler,
                               &filler->work) != napi_ok ||
        napi_queue_async_work(env, filler->work) != napi_ok) {
      free(filler);
    }
  }

  cancel_request* request = (cancel_request*)calloc(1, sizeof(*request));
  if (request == NULL) {
    napi_throw_error(env, "ERR_ADDON_MEMORY", "could not allocate the cancel request");
    return NULL;
  }
  if (napi_create_reference(env, argv[0], 1, &request->callback) != napi_ok) {
    free(request);
    napi_throw_type_error(env, "ERR_ADDON_TYPE", "queueAndCancel needs a callback");
    return NULL;
  }
  if (napi_create_async_work(env, NULL, name, SaturateExecute, CancelComplete, request,
                             &request->work) != napi_ok) {
    napi_delete_reference(env, request->callback);
    free(request);
    report_failure(env, "napi_create_async_work failed for the cancelled request");
    return NULL;
  }
  if (napi_queue_async_work(env, request->work) != napi_ok) {
    napi_delete_async_work(env, request->work);
    napi_delete_reference(env, request->callback);
    free(request);
    report_failure(env, "napi_queue_async_work failed for the cancelled request");
    return NULL;
  }
  /* Best-effort: if the request did start, the cancel reports a failure and the
   * completion carries `napi_ok` instead. The JavaScript side asserts on the
   * status it is told rather than assuming the race was won. */
  napi_cancel_async_work(env, request->work);
  return NULL;
}

/* ------------------------------------------------------------------------- */
/* Thread-safe function                                                       */
/* ------------------------------------------------------------------------- */

typedef struct {
  napi_threadsafe_function function;
  napi_ref finalize_callback;
  int32_t count;
  int32_t pushed;
} producer_state;

typedef struct {
  int32_t value;
} producer_message;

/* The producer thread. It pushes `count` values, then releases its hold, which is
 * what allows the function to be torn down once the queue drains. */
static void* producer_thread(void* data) {
  producer_state* state = (producer_state*)data;
  for (int32_t index = 0; index < state->count; index += 1) {
    producer_message* message = (producer_message*)calloc(1, sizeof(*message));
    if (message == NULL) {
      break;
    }
    message->value = index;
    /* Blocking mode: a full queue makes the producer wait rather than drop the
     * value, which is what makes the received sequence complete. */
    if (napi_call_threadsafe_function(state->function, message, napi_tsfn_blocking) !=
        napi_ok) {
      free(message);
      break;
    }
    state->pushed += 1;
  }
  napi_release_threadsafe_function(state->function, napi_tsfn_release);
  return NULL;
}

/* `call_js_cb`: runs on the loop's thread with one queued value. */
static void ProducerCallJs(napi_env env, napi_value callback, void* context, void* data) {
  producer_message* message = (producer_message*)data;
  /* Teardown passes a null env and callback, which is how the addon learns the
   * value will never reach JavaScript. Freeing it is this callback's job. */
  if (env != NULL && callback != NULL) {
    napi_value value;
    napi_value undefined;
    napi_value result;
    (void)context;
    if (napi_create_int32(env, message->value, &value) == napi_ok &&
        napi_get_undefined(env, &undefined) == napi_ok) {
      napi_call_function(env, undefined, callback, 1, &value, &result);
    }
  }
  free(message);
}

/* `thread_finalize_cb`: runs once, on the loop's thread, after the last value.
 *
 * It reports how many values the producer pushed, which the test compares against
 * what JavaScript received: a finalizer that ran early, or a queue that lost
 * values, shows up as a mismatch rather than as a hang. */
static void ProducerFinalize(napi_env env, void* data, void* hint) {
  producer_state* state = (producer_state*)data;
  (void)hint;

  if (env != NULL) {
    napi_value callback;
    napi_value value;
    napi_value undefined;
    napi_value result;
    if (napi_get_reference_value(env, state->finalize_callback, &callback) == napi_ok &&
        napi_create_int32(env, state->pushed, &value) == napi_ok &&
        napi_get_undefined(env, &undefined) == napi_ok) {
      napi_call_function(env, undefined, callback, 1, &value, &result);
    } else {
      report_failure(env, "reporting the thread-safe function total failed");
    }
    napi_delete_reference(env, state->finalize_callback);
  }
  free(state);
}

/* `startThreadSafeProducer(onValue, count, onFinalize)`.
 *
 * `onValue` runs on the loop's thread for each pushed integer, in arrival order.
 * `onFinalize` runs once afterwards with the number the producer pushed. */
static napi_value StartThreadSafeProducer(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  remember_main_thread();

  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 3) {
    napi_throw_type_error(
        env, "ERR_ADDON_ARITY",
        "startThreadSafeProducer needs (onValue, count, onFinalize)");
    return NULL;
  }

  producer_state* state = (producer_state*)calloc(1, sizeof(*state));
  if (state == NULL) {
    napi_throw_error(env, "ERR_ADDON_MEMORY", "could not allocate the producer state");
    return NULL;
  }
  if (napi_get_value_int32(env, argv[1], &state->count) != napi_ok || state->count <= 0) {
    free(state);
    napi_throw_type_error(env, "ERR_ADDON_TYPE", "count must be a positive number");
    return NULL;
  }
  if (napi_create_reference(env, argv[2], 1, &state->finalize_callback) != napi_ok) {
    free(state);
    napi_throw_type_error(env, "ERR_ADDON_TYPE", "onFinalize must be a function");
    return NULL;
  }

  napi_value name;
  if (napi_create_string_utf8(env, "startThreadSafeProducer", NAPI_AUTO_LENGTH, &name) !=
      napi_ok) {
    napi_delete_reference(env, state->finalize_callback);
    free(state);
    return NULL;
  }

  /* One thread will call in, so the initial count is 1. The `onValue` function
   * travels as the TSFN's `func`, so `ProducerCallJs` receives it as `callback`
   * and the default call behaviour is not used. */
  if (napi_create_threadsafe_function(env, argv[0], NULL, name,
                                      /* max_queue_size */ 0,
                                      /* initial_thread_count */ 1, state,
                                      ProducerFinalize, NULL, ProducerCallJs,
                                      &state->function) != napi_ok) {
    napi_delete_reference(env, state->finalize_callback);
    free(state);
    report_failure(env, "napi_create_threadsafe_function failed");
    return NULL;
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, producer_thread, state) != 0) {
    napi_release_threadsafe_function(state->function, napi_tsfn_abort);
    free(state);
    napi_throw_error(env, "ERR_ADDON_THREAD", "could not start the producer thread");
    return NULL;
  }
  /* Detached: the finalizer is the join point in effect, because it runs only
   * after the producer has released and the queue has drained. */
  pthread_detach(thread);
  return NULL;
}

/* `threadSafeFunctionContext(onDone)` -> `onDone(context)`.
 *
 * Reads the TSFN's `void*` context through
 * `napi_get_threadsafe_function_context` *from the producer thread*, which is
 * where the accessor has to work. A version that only stored the value on the
 * creating thread would return null here. */
typedef struct {
  napi_threadsafe_function function;
  void* context;
  napi_ref done_callback;
} context_probe;

static void* context_probe_thread(void* data) {
  context_probe* probe = (context_probe*)data;
  void* observed = NULL;
  /* The accessor is the thing under test; a failure is reported by the finalizer
   * as a null result rather than thrown from a thread with no scope. */
  if (napi_get_threadsafe_function_context(probe->function, &observed) == napi_ok &&
      observed == probe->context) {
    probe->context = observed;
  } else {
    probe->context = NULL;
  }
  napi_release_threadsafe_function(probe->function, napi_tsfn_release);
  return NULL;
}

static void ContextProbeFinalize(napi_env env, void* data, void* hint) {
  context_probe* probe = (context_probe*)data;
  (void)hint;
  if (env != NULL) {
    napi_value callback;
    napi_value result;
    napi_value undefined;
    if (napi_get_reference_value(env, probe->done_callback, &callback) == napi_ok &&
        napi_create_int32(env, probe->context != NULL ? 1 : 0, &result) == napi_ok &&
        napi_get_undefined(env, &undefined) == napi_ok) {
      napi_value argv[1];
      napi_value returned;
      argv[0] = result;
      napi_call_function(env, undefined, callback, 1, argv, &returned);
    }
    napi_delete_reference(env, probe->done_callback);
  }
  free(probe);
}

static napi_value ThreadSafeFunctionContext(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1) {
    napi_throw_type_error(env, "ERR_ADDON_ARITY",
                          "threadSafeFunctionContext needs a callback");
    return NULL;
  }

  context_probe* probe = (context_probe*)calloc(1, sizeof(*probe));
  if (probe == NULL) {
    napi_throw_error(env, "ERR_ADDON_MEMORY", "could not allocate the probe");
    return NULL;
  }
  /* A recognisable context the producer thread can compare against. */
  probe->context = (void*)(uintptr_t)0x5A5A;
  if (napi_create_reference(env, argv[0], 1, &probe->done_callback) != napi_ok) {
    free(probe);
    napi_throw_type_error(env, "ERR_ADDON_TYPE", "a callback is required");
    return NULL;
  }

  napi_value name;
  if (napi_create_string_utf8(env, "threadSafeFunctionContext", NAPI_AUTO_LENGTH, &name) !=
      napi_ok) {
    napi_delete_reference(env, probe->done_callback);
    free(probe);
    return NULL;
  }
  /* No `func` and no `call_js_cb` would be rejected; a `call_js_cb` that only frees
   * its payload keeps the values from being delivered to a JavaScript function
   * that does not exist. */
  if (napi_create_threadsafe_function(env, NULL, NULL, name, 0, 1, probe,
                                      ContextProbeFinalize, probe->context,
                                      ProducerCallJs, &probe->function) != napi_ok) {
    napi_delete_reference(env, probe->done_callback);
    free(probe);
    report_failure(env, "napi_create_threadsafe_function failed for the context probe");
    return NULL;
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, context_probe_thread, probe) != 0) {
    napi_release_threadsafe_function(probe->function, napi_tsfn_abort);
    free(probe);
    napi_throw_error(env, "ERR_ADDON_THREAD", "could not start the probe thread");
    return NULL;
  }
  pthread_detach(thread);
  return NULL;
}

/* ------------------------------------------------------------------------- */
/* Registration                                                               */
/* ------------------------------------------------------------------------- */

typedef struct {
  const char* name;
  napi_callback callback;
} AsyncMethod;

static const AsyncMethod kAsyncMethods[] = {
    {"runAsyncWork", RunAsyncWork},
    {"queueAndCancel", QueueAndCancel},
    {"startThreadSafeProducer", StartThreadSafeProducer},
    {"threadSafeFunctionContext", ThreadSafeFunctionContext},
};

/* Registers this file's methods onto `exports`.
 *
 * A separate entry point rather than a shared table so `addon.c` keeps one way of
 * registering and this file owns its own names. */
napi_status register_async_methods(napi_env env, napi_value exports) {
  const size_t count = sizeof(kAsyncMethods) / sizeof(kAsyncMethods[0]);
  for (size_t index = 0; index < count; index += 1) {
    napi_value function;
    napi_status status =
        napi_create_function(env, kAsyncMethods[index].name, NAPI_AUTO_LENGTH,
                             kAsyncMethods[index].callback, NULL, &function);
    if (status != napi_ok) {
      return status;
    }
    status = napi_set_named_property(env, exports, kAsyncMethods[index].name, function);
    if (status != napi_ok) {
      return status;
    }
  }
  return napi_ok;
}

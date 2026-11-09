/* See rn_llhttp.h for why this translation unit exists. */

#include <stdlib.h>
#include <string.h>

#include "llhttp.h"
#include "rn_llhttp.h"

/* Holds both the parser and the settings it points at. `llhttp_init` stores
 * the settings pointer, so the two have to share a lifetime; keeping them in
 * one allocation makes that impossible to get wrong. */
struct rn_llhttp {
  llhttp_t parser;
  llhttp_settings_t settings;
  rn_llhttp_callbacks callbacks;
};

static rn_llhttp *to_wrapper(llhttp_t *parser) {
  /* `parser` is the first member, so the addresses are the same. */
  return (rn_llhttp *) parser;
}

/* llhttp reports -1 from a span callback as HPE_USER with a generated reason
 * that contains no colon, which the caller cannot split into code and reason.
 * Returning HPE_USER here and setting the reason explicitly keeps the
 * "CODE:reason" shape every other user error has. */
static int user_error(llhttp_t *parser, const char *reason) {
  llhttp_set_error_reason(parser, reason);
  return HPE_USER;
}

/* ---------------- forwarded callbacks ---------------- */

static int cb_message_begin(llhttp_t *parser) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_message_begin == NULL) return 0;
  return self->callbacks.on_message_begin(self->callbacks.user);
}

static int cb_url(llhttp_t *parser, const char *at, size_t len) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_url == NULL) return 0;
  return self->callbacks.on_url(self->callbacks.user, at, len);
}

static int cb_status(llhttp_t *parser, const char *at, size_t len) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_status == NULL) return 0;
  return self->callbacks.on_status(self->callbacks.user, at, len);
}

static int cb_header_field(llhttp_t *parser, const char *at, size_t len) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_header_field == NULL) return 0;
  return self->callbacks.on_header_field(self->callbacks.user, at, len);
}

static int cb_header_value(llhttp_t *parser, const char *at, size_t len) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_header_value == NULL) return 0;
  return self->callbacks.on_header_value(self->callbacks.user, at, len);
}

static int cb_headers_complete(llhttp_t *parser) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_headers_complete == NULL) return 0;
  /* Passed through unclamped: 1 and 2 are llhttp's own "no body" and "no body
   * plus HPE_PAUSED_UPGRADE" signals, and JavaScript returns them. */
  return self->callbacks.on_headers_complete(self->callbacks.user);
}

static int cb_body(llhttp_t *parser, const char *at, size_t len) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_body == NULL) return 0;
  return self->callbacks.on_body(self->callbacks.user, at, len);
}

static int cb_message_complete(llhttp_t *parser) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_message_complete == NULL) return 0;
  return self->callbacks.on_message_complete(self->callbacks.user);
}

static int cb_chunk_header(llhttp_t *parser) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_chunk_header == NULL) return 0;
  return self->callbacks.on_chunk_header(self->callbacks.user);
}

static int cb_chunk_complete(llhttp_t *parser) {
  rn_llhttp *self = to_wrapper(parser);
  if (self->callbacks.on_chunk_complete == NULL) return 0;
  return self->callbacks.on_chunk_complete(self->callbacks.user);
}

/* The adapter functions above read the JavaScript-facing callbacks through
 * `self->callbacks`, so they are the same table no matter which parser this
 * settings block belongs to. */
static void settings_from(llhttp_settings_t *settings) {
  llhttp_settings_init(settings);
  settings->on_message_begin = cb_message_begin;
  settings->on_url = cb_url;
  settings->on_status = cb_status;
  settings->on_header_field = cb_header_field;
  settings->on_header_value = cb_header_value;
  settings->on_headers_complete = cb_headers_complete;
  settings->on_body = cb_body;
  settings->on_message_complete = cb_message_complete;
  settings->on_chunk_header = cb_chunk_header;
  settings->on_chunk_complete = cb_chunk_complete;
}

/* ---------------- lifecycle ---------------- */

rn_llhttp *rn_llhttp_new(int type, const rn_llhttp_callbacks *callbacks) {
  rn_llhttp *self = (rn_llhttp *) malloc(sizeof(rn_llhttp));
  if (self == NULL) return NULL;
  self->callbacks = *callbacks;
  settings_from(&self->settings);
  llhttp_init(&self->parser, (llhttp_type_t) type, &self->settings);
  return self;
}

void rn_llhttp_free(rn_llhttp *self) {
  free(self);
}

void rn_llhttp_init(rn_llhttp *self, int type) {
  /* Rebuilds the settings too: a callback table left over from an earlier
   * initialisation is the same table, but rebuilding costs nothing and keeps
   * `rn_llhttp_new` and this on one path. */
  settings_from(&self->settings);
  llhttp_init(&self->parser, (llhttp_type_t) type, &self->settings);
}

/* ---------------- execution ---------------- */

int rn_llhttp_execute(rn_llhttp *self, const char *data, size_t len) {
  return (int) llhttp_execute(&self->parser, data, len);
}

int rn_llhttp_finish(rn_llhttp *self) {
  return (int) llhttp_finish(&self->parser);
}

void rn_llhttp_pause(rn_llhttp *self) {
  llhttp_pause(&self->parser);
}

void rn_llhttp_resume(rn_llhttp *self) {
  llhttp_resume(&self->parser);
}

void rn_llhttp_resume_after_upgrade(rn_llhttp *self) {
  llhttp_resume_after_upgrade(&self->parser);
}

int rn_llhttp_should_keep_alive(const rn_llhttp *self) {
  return llhttp_should_keep_alive(&self->parser);
}

int rn_llhttp_errno(const rn_llhttp *self) {
  return (int) llhttp_get_errno(&self->parser);
}

const char *rn_llhttp_error_reason(const rn_llhttp *self) {
  const char *reason = llhttp_get_error_reason(&self->parser);
  return reason == NULL ? "" : reason;
}

ptrdiff_t rn_llhttp_error_offset(const rn_llhttp *self, const char *data) {
  const char *pos = llhttp_get_error_pos(&self->parser);
  if (pos == NULL || data == NULL) return 0;
  return (ptrdiff_t) (pos - data);
}

void rn_llhttp_set_error_reason(rn_llhttp *self, const char *reason) {
  llhttp_set_error_reason(&self->parser, reason);
}

/* ---------------- generated tables ----------------
 *
 * `llhttp_errno_name` and `llhttp_method_name` call `abort()` for a value that
 * is not in their table, so they are not usable on a number that came from
 * JavaScript. These switches are generated from the same macros and return
 * NULL instead.
 */

const char *rn_llhttp_errno_name(int value) {
  switch (value) {
#define RN_ERRNO_CASE(CODE, NAME, STRING) \
  case CODE: return "HPE_" #NAME;
    HTTP_ERRNO_MAP(RN_ERRNO_CASE)
#undef RN_ERRNO_CASE
  default: return NULL;
  }
}

size_t rn_llhttp_method_count(void) {
  size_t count = 0;
#define RN_METHOD_COUNT(NUM, NAME, STRING) count++;
  HTTP_METHOD_MAP(RN_METHOD_COUNT)
#undef RN_METHOD_COUNT
  return count;
}

const char *rn_llhttp_method_at(size_t index) {
  size_t current = 0;
  const char *name = NULL;
#define RN_METHOD_AT(NUM, NAME, STRING) \
  do {                                  \
    if (current == index) name = #STRING; \
    current++;                          \
  } while (0);
  HTTP_METHOD_MAP(RN_METHOD_AT)
#undef RN_METHOD_AT
  return name;
}

size_t rn_llhttp_all_method_count(void) {
  size_t count = 0;
#define RN_ALL_COUNT(NUM, NAME, STRING) count++;
  HTTP_ALL_METHOD_MAP(RN_ALL_COUNT)
#undef RN_ALL_COUNT
  return count;
}

const char *rn_llhttp_all_method_at(size_t index) {
  size_t current = 0;
  const char *name = NULL;
#define RN_ALL_AT(NUM, NAME, STRING)     \
  do {                                   \
    if (current == index) name = #STRING; \
    current++;                           \
  } while (0);
  HTTP_ALL_METHOD_MAP(RN_ALL_AT)
#undef RN_ALL_AT
  return name;
}

/* ---------------- state accessors ---------------- */

/* llhttp's getters take a non-const `llhttp_t*` even though they only read.
 * The cast is confined to this one helper rather than repeated per accessor. */
static llhttp_t *mutable_parser(const rn_llhttp *self) {
  return (llhttp_t *) &self->parser;
}

int rn_llhttp_type(const rn_llhttp *self) {
  return (int) llhttp_get_type(mutable_parser(self));
}

int rn_llhttp_method(const rn_llhttp *self) {
  return (int) llhttp_get_method(mutable_parser(self));
}

int rn_llhttp_status_code(const rn_llhttp *self) {
  return llhttp_get_status_code(mutable_parser(self));
}

int rn_llhttp_http_major(const rn_llhttp *self) {
  return (int) llhttp_get_http_major(mutable_parser(self));
}

int rn_llhttp_http_minor(const rn_llhttp *self) {
  return (int) llhttp_get_http_minor(mutable_parser(self));
}

int rn_llhttp_upgrade(const rn_llhttp *self) {
  return (int) llhttp_get_upgrade(mutable_parser(self));
}

void rn_llhttp_set_lenient(rn_llhttp *self, unsigned flags) {
  if (flags & 0x1) llhttp_set_lenient_headers(&self->parser, 1);
  if (flags & 0x2) llhttp_set_lenient_chunked_length(&self->parser, 1);
  if (flags & 0x4) llhttp_set_lenient_keep_alive(&self->parser, 1);
  if (flags & 0x8) llhttp_set_lenient_transfer_encoding(&self->parser, 1);
  if (flags & 0x10) llhttp_set_lenient_version(&self->parser, 1);
  if (flags & 0x20) llhttp_set_lenient_data_after_close(&self->parser, 1);
  if (flags & 0x40) llhttp_set_lenient_optional_lf_after_cr(&self->parser, 1);
  if (flags & 0x80) llhttp_set_lenient_optional_crlf_after_chunk(&self->parser, 1);
  if (flags & 0x100) llhttp_set_lenient_optional_cr_before_lf(&self->parser, 1);
  if (flags & 0x200) llhttp_set_lenient_spaces_after_chunk_size(&self->parser, 1);
#if LLHTTP_VERSION_MAJOR * 1000 + LLHTTP_VERSION_MINOR >= 9004
  if (flags & 0x400) llhttp_set_lenient_header_value_relaxed(&self->parser, 1);
#endif
}

/* Kept out of the header so the "no colon" rule has one enforcement point. */
int rn_llhttp_user_error(rn_llhttp *self, const char *reason) {
  return user_error(&self->parser, reason);
}

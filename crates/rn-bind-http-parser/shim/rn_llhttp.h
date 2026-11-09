/* A minimal, stable face on llhttp for `rn-bind-http-parser`.
 *
 * Rust never sees `llhttp_t` or `llhttp_settings_t`. Both are generated
 * structs whose layout changes between llhttp releases, and a silent mismatch
 * between a Rust `#[repr(C)]` mirror and the real header would be an ABI bug
 * that only shows up as a crash or a wrong field. Everything here is pointers,
 * integers and fixed-size spans, so the surface cannot drift.
 *
 * The settings struct also lives on this side: its 22 function-pointer fields
 * are exactly the kind of thing a hand-written mirror gets wrong.
 */

#ifndef RN_LLHTTP_H_
#define RN_LLHTTP_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rn_llhttp rn_llhttp;

/* Callbacks are 1:1 with the llhttp ones this crate needs; the ones left NULL
 * here (on_method, on_version, chunk extensions, ...) have no JavaScript
 * observable effect in `src/node_http_parser.cc` either.
 *
 * Return 0 to continue, an `llhttp_errno` to stop. Do not return -1: llhttp
 * rewrites that to `HPE_USER` with a reason that has no colon in it, and the
 * caller splits user reasons at the colon. Use `rn_llhttp_user_error`.
 */
typedef struct rn_llhttp_callbacks {
  void *user;
  int (*on_message_begin)(void *user);
  int (*on_url)(void *user, const char *at, size_t length);
  int (*on_status)(void *user, const char *at, size_t length);
  int (*on_header_field)(void *user, const char *at, size_t length);
  int (*on_header_value)(void *user, const char *at, size_t length);
  int (*on_headers_complete)(void *user);
  int (*on_body)(void *user, const char *at, size_t length);
  int (*on_message_complete)(void *user);
  int (*on_chunk_header)(void *user);
  int (*on_chunk_complete)(void *user);
} rn_llhttp_callbacks;

/* Allocates and initialises a parser. Copies `callbacks`, so the caller's copy
 * may be a stack value. Returns NULL on allocation failure. */
rn_llhttp *rn_llhttp_new(int type, const rn_llhttp_callbacks *callbacks);

void rn_llhttp_free(rn_llhttp *parser);

/* Re-initialises in place, discarding any partial message and any lenient
 * flags, which is what `llhttp_init` does and what `Parser::Init` relies on. */
void rn_llhttp_init(rn_llhttp *parser, int type);

int rn_llhttp_execute(rn_llhttp *parser, const char *data, size_t len);
int rn_llhttp_finish(rn_llhttp *parser);

void rn_llhttp_pause(rn_llhttp *parser);
void rn_llhttp_resume(rn_llhttp *parser);
void rn_llhttp_resume_after_upgrade(rn_llhttp *parser);
int rn_llhttp_should_keep_alive(const rn_llhttp *parser);

int rn_llhttp_errno(const rn_llhttp *parser);
const char *rn_llhttp_error_reason(const rn_llhttp *parser);
/* `error_pos - data`, i.e. the byte offset `node_http_parser.cc` reports as
 * `bytesParsed`. Clamped to zero: llhttp leaves `error_pos` unset for an error
 * raised outside a span (the EOF path), and subtracting from a NULL `data`
 * like the C++ does is exactly the undefined behaviour that made Node report
 * a garbage `bytesParsed` there. */
ptrdiff_t rn_llhttp_error_offset(const rn_llhttp *parser, const char *data);

/* Names from the generated tables, so the JavaScript arrays can be built from
 * llhttp instead of from a copy of its method list.
 *
 * These are deliberately not `llhttp_errno_name`/`llhttp_method_name`: those
 * call `abort()` on a value outside the table, and every input to these comes
 * from JavaScript or from a parser whose error may be anything. */
const char *rn_llhttp_errno_name(int errno_value);

/* `methods` and `allMethods` as `src/node_http_parser.cc` builds them: the
 * strings of `HTTP_METHOD_MAP` then `HTTP_ALL_METHOD_MAP`. `*_count` first,
 * then `0..count` with `*_at`. Returns NULL past the end. */
size_t rn_llhttp_method_count(void);
const char *rn_llhttp_method_at(size_t index);
size_t rn_llhttp_all_method_count(void);
const char *rn_llhttp_all_method_at(size_t index);

/* Reports `reason` as an `HPE_USER` error. The reason must contain a colon,
 * because that is where `Parser::Execute` splits the JavaScript error's `code`
 * from its `reason`. Returning -1 from a callback instead makes llhttp
 * substitute a reason with no colon, which is why this exists. */
int rn_llhttp_user_error(rn_llhttp *parser, const char *reason);

int rn_llhttp_type(const rn_llhttp *parser);
int rn_llhttp_method(const rn_llhttp *parser);
int rn_llhttp_status_code(const rn_llhttp *parser);
int rn_llhttp_http_major(const rn_llhttp *parser);
int rn_llhttp_http_minor(const rn_llhttp *parser);
int rn_llhttp_upgrade(const rn_llhttp *parser);

/* `llhttp_lenient_flags` bits, ORed together. */
void rn_llhttp_set_lenient(rn_llhttp *parser, unsigned flags);

/* Records why a callback is aborting. `reason` must outlive the parser, which
 * is why callers pass string literals. */
void rn_llhttp_set_error_reason(rn_llhttp *parser, const char *reason);

#ifdef __cplusplus
}
#endif

#endif /* RN_LLHTTP_H_ */

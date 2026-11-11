#ifndef RN_QUIC_PROBE_H_
#define RN_QUIC_PROBE_H_

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Version strings, so a Rust test can prove the symbols it linked are the
 * vendored ones and not something the linker resolved from elsewhere. */
const char* rn_quic_probe_ngtcp2_version(void);
const char* rn_quic_probe_nghttp3_version(void);

/* A round-trip through each library's real code, so a successful link is not
 * the only evidence the build worked.
 *
 * ngtcp2: build a settings struct, a transport-params struct, encode the
 * params into a caller buffer and decode them back.
 * nghttp3: create a server-side connection and drive a settings frame.
 */
int rn_quic_probe_ngtcp2_roundtrip(void);
int rn_quic_probe_nghttp3_roundtrip(void);

/* Proves the OpenSSL 3.5+ QUIC TLS callbacks are linkable, which is the API
 * `deps/ngtcp2/crypto/ossl/ossl.c` binds and `src/quic/guard.h` gates on. */
int rn_quic_probe_ossl_quic_symbols(void);

#if defined(__cplusplus)
}
#endif

#endif  /* RN_QUIC_PROBE_H_ */

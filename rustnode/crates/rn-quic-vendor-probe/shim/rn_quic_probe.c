/* Build proof for the QUIC C dependencies.
 *
 * This file exists only to be compiled and linked. It calls into ngtcp2,
 * nghttp3 and OpenSSL so a successful link is evidence the three libraries were
 * built against the right headers, and so a Rust test can run each library's
 * real code rather than only checking that a symbol resolved.
 *
 * It is not a binding and nothing outside this probe crate should include it.
 */

#include "rn_quic_probe.h"

#include <string.h>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>

const char* rn_quic_probe_ngtcp2_version(void) {
  return ngtcp2_version(0)->version_str;
}

const char* rn_quic_probe_nghttp3_version(void) {
  return nghttp3_version(0)->version_str;
}

int rn_quic_probe_ngtcp2_roundtrip(void) {
  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);

  /* A value ngtcp2 itself would pick, so the encode below is not a degenerate
   * all-zero blob that a broken build could still produce. */
  params.initial_max_data = 1234567;
  params.initial_max_stream_data_bidi_local = 654321;
  params.initial_max_streams_bidi = 17;
  params.max_idle_timeout = 30000 * NGTCP2_MILLISECONDS;

  uint8_t buf[512];
  ngtcp2_ssize encoded =
      ngtcp2_transport_params_encode(buf, sizeof(buf), &params);
  if (encoded <= 0) return -1;

  ngtcp2_transport_params decoded;
  int rv = ngtcp2_transport_params_decode(&decoded, buf, (size_t)encoded);
  if (rv != 0) return -2;

  if (decoded.initial_max_data != params.initial_max_data) return -3;
  if (decoded.initial_max_stream_data_bidi_local !=
      params.initial_max_stream_data_bidi_local) return -4;
  if (decoded.initial_max_streams_bidi != params.initial_max_streams_bidi)
    return -5;
  if (settings.max_tx_udp_payload_size == 0) return -6;

  return 0;
}

int rn_quic_probe_nghttp3_roundtrip(void) {
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);

  nghttp3_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));

  nghttp3_conn* conn = NULL;
  int rv = nghttp3_conn_server_new(&conn, &callbacks, &settings, NULL, NULL);
  if (rv != 0) return -1;

  nghttp3_conn_del(conn);
  return 0;
}

int rn_quic_probe_ossl_quic_symbols(void) {
  /* These are the two OpenSSL QUIC entry points
   * `deps/ngtcp2/ngtcp2/crypto/ossl/ossl.c` binds, and both only exist from
   * OpenSSL 3.5. Taking their addresses proves the headers declared them and
   * the library defines them, without needing a live TLS session.
   *
   * `SSL_provide_quic_data` is deliberately not referenced: that is a
   * quictls/BoringSSL API and OpenSSL does not export it, so requiring it would
   * misdescribe the backend Node actually builds. */
  void* cbs = (void*)&SSL_set_quic_tls_cbs;
  if (cbs == NULL) return -1;

  void* params = (void*)&SSL_set_quic_tls_transport_params;
  if (params == NULL) return -2;

  return 0;
}

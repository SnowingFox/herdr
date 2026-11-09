/* Emits every internalBinding('constants') value from the Linux release build of
 * Node 28, computed by the same headers Node compiles against, so the Rust
 * table can be checked instead of transcribed by hand. */
/* Node compiles on Linux with _GNU_SOURCE (node.gyp common flags), which is
 * what exposes O_DIRECT and O_NOATIME from <fcntl.h>. Without it the fs table
 * would silently lose entries Node publishes. */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#include <limits.h>
#include <math.h>

#include "uv.h"
#include "zlib.h"
#include "brotli/encode.h"
#include "brotli/decode.h"
#include "zstd.h"
#include "openssl/ssl.h"
#include "openssl/opensslv.h"
#include "openssl/ec.h"

/* Same fallbacks Node applies in src/node_constants.cc for constants modern
 * OpenSSL headers hide behind OPENSSL_NO_DEPRECATED. */
#ifndef RSA_PKCS1_PADDING
#define RSA_PKCS1_PADDING 1
#endif
#ifndef RSA_SSLV23_PADDING
#define RSA_SSLV23_PADDING 2
#endif
#ifndef RSA_NO_PADDING
#define RSA_NO_PADDING 3
#endif
#ifndef RSA_PKCS1_OAEP_PADDING
#define RSA_PKCS1_OAEP_PADDING 4
#endif
#ifndef RSA_X931_PADDING
#define RSA_X931_PADDING 5
#endif
#ifndef RSA_PKCS1_PSS_PADDING
#define RSA_PKCS1_PSS_PADDING 6
#endif
#ifndef RSA_PSS_SALTLEN_DIGEST
#define RSA_PSS_SALTLEN_DIGEST -1
#endif
#ifndef RSA_PSS_SALTLEN_MAX_SIGN
#define RSA_PSS_SALTLEN_MAX_SIGN -2
#endif
#ifndef RSA_PSS_SALTLEN_AUTO
#define RSA_PSS_SALTLEN_AUTO -2
#endif
#ifndef OPENSSL_IS_BORINGSSL
#if !defined(DH_CHECK_P_NOT_PRIME)
#define DH_CHECK_P_NOT_PRIME 0x01
#endif
#if !defined(DH_CHECK_P_NOT_SAFE_PRIME)
#define DH_CHECK_P_NOT_SAFE_PRIME 0x02
#endif
#if !defined(DH_UNABLE_TO_CHECK_GENERATOR)
#define DH_UNABLE_TO_CHECK_GENERATOR 0x04
#endif
#if !defined(DH_NOT_SUITABLE_GENERATOR)
#define DH_NOT_SUITABLE_GENERATOR 0x08
#endif
#endif

#define NUM(x) printf("%s %lld\n", #x, (long long)(x))
#define STR(x) printf("%s \"%s\"\n", #x, (x))

static void signals(void) {
#ifdef SIGHUP
  NUM(SIGHUP);
#endif
#ifdef SIGINT
  NUM(SIGINT);
#endif
#ifdef SIGQUIT
  NUM(SIGQUIT);
#endif
#ifdef SIGILL
  NUM(SIGILL);
#endif
#ifdef SIGTRAP
  NUM(SIGTRAP);
#endif
#ifdef SIGABRT
  NUM(SIGABRT);
#endif
#ifdef SIGIOT
  NUM(SIGIOT);
#endif
#ifdef SIGBUS
  NUM(SIGBUS);
#endif
#ifdef SIGFPE
  NUM(SIGFPE);
#endif
#ifdef SIGKILL
  NUM(SIGKILL);
#endif
#ifdef SIGUSR1
  NUM(SIGUSR1);
#endif
#ifdef SIGSEGV
  NUM(SIGSEGV);
#endif
#ifdef SIGUSR2
  NUM(SIGUSR2);
#endif
#ifdef SIGPIPE
  NUM(SIGPIPE);
#endif
#ifdef SIGALRM
  NUM(SIGALRM);
#endif
  NUM(SIGTERM);
#ifdef SIGCHLD
  NUM(SIGCHLD);
#endif
#ifdef SIGSTKFLT
  NUM(SIGSTKFLT);
#endif
#ifdef SIGCONT
  NUM(SIGCONT);
#endif
#ifdef SIGSTOP
  NUM(SIGSTOP);
#endif
#ifdef SIGTSTP
  NUM(SIGTSTP);
#endif
#ifdef SIGBREAK
  NUM(SIGBREAK);
#endif
#ifdef SIGTTIN
  NUM(SIGTTIN);
#endif
#ifdef SIGTTOU
  NUM(SIGTTOU);
#endif
#ifdef SIGURG
  NUM(SIGURG);
#endif
#ifdef SIGXCPU
  NUM(SIGXCPU);
#endif
#ifdef SIGXFSZ
  NUM(SIGXFSZ);
#endif
#ifdef SIGVTALRM
  NUM(SIGVTALRM);
#endif
#ifdef SIGPROF
  NUM(SIGPROF);
#endif
#ifdef SIGWINCH
  NUM(SIGWINCH);
#endif
#ifdef SIGIO
  NUM(SIGIO);
#endif
#ifdef SIGPOLL
  NUM(SIGPOLL);
#endif
#ifdef SIGLOST
  NUM(SIGLOST);
#endif
#ifdef SIGPWR
  NUM(SIGPWR);
#endif
#ifdef SIGINFO
  NUM(SIGINFO);
#endif
#ifdef SIGSYS
  NUM(SIGSYS);
#endif
#ifdef SIGUNUSED
  NUM(SIGUNUSED);
#endif
}

static void errnos(void) {
  NUM(E2BIG); NUM(EACCES); NUM(EADDRINUSE); NUM(EADDRNOTAVAIL); NUM(EAFNOSUPPORT);
  NUM(EAGAIN); NUM(EALREADY); NUM(EBADF); NUM(EBADMSG); NUM(EBUSY); NUM(ECANCELED);
  NUM(ECHILD); NUM(ECONNABORTED); NUM(ECONNREFUSED); NUM(ECONNRESET); NUM(EDEADLK);
  NUM(EDESTADDRREQ); NUM(EDOM); NUM(EDQUOT); NUM(EEXIST); NUM(EFAULT); NUM(EFBIG);
  NUM(EHOSTUNREACH); NUM(EIDRM); NUM(EILSEQ); NUM(EINPROGRESS); NUM(EINTR); NUM(EINVAL);
  NUM(EIO); NUM(EISCONN); NUM(EISDIR); NUM(ELOOP); NUM(EMFILE); NUM(EMLINK); NUM(EMSGSIZE);
  NUM(EMULTIHOP); NUM(ENAMETOOLONG); NUM(ENETDOWN); NUM(ENETRESET); NUM(ENETUNREACH);
  NUM(ENFILE); NUM(ENOBUFS); NUM(ENODATA); NUM(ENODEV); NUM(ENOENT); NUM(ENOEXEC);
  NUM(ENOLCK); NUM(ENOLINK); NUM(ENOMEM); NUM(ENOMSG); NUM(ENOPROTOOPT); NUM(ENOSPC);
  NUM(ENOSR); NUM(ENOSTR); NUM(ENOSYS); NUM(ENOTCONN); NUM(ENOTDIR); NUM(ENOTEMPTY);
  NUM(ENOTSOCK); NUM(ENOTSUP); NUM(ENOTTY); NUM(ENXIO); NUM(EOPNOTSUPP); NUM(EOVERFLOW);
  NUM(EPERM); NUM(EPIPE); NUM(EPROTO); NUM(EPROTONOSUPPORT); NUM(EPROTOTYPE); NUM(ERANGE);
  NUM(EROFS); NUM(ESPIPE); NUM(ESRCH); NUM(ESTALE); NUM(ETIME); NUM(ETIMEDOUT); NUM(ETXTBSY);
  NUM(EWOULDBLOCK); NUM(EXDEV);
}

static void fs(void) {
  NUM(UV_FS_SYMLINK_DIR);
  NUM(UV_FS_SYMLINK_JUNCTION);
  NUM(O_RDONLY);
  NUM(O_WRONLY);
  NUM(O_RDWR);
  NUM(UV_DIRENT_UNKNOWN);
  NUM(UV_DIRENT_FILE);
  NUM(UV_DIRENT_DIR);
  NUM(UV_DIRENT_LINK);
  NUM(UV_DIRENT_FIFO);
  NUM(UV_DIRENT_SOCKET);
  NUM(UV_DIRENT_CHAR);
  NUM(UV_DIRENT_BLOCK);
  NUM(S_IFMT);
  NUM(S_IFREG);
  NUM(S_IFDIR);
  NUM(S_IFCHR);
#ifdef S_IFBLK
  NUM(S_IFBLK);
#endif
#ifdef S_IFIFO
  NUM(S_IFIFO);
#endif
#ifdef S_IFLNK
  NUM(S_IFLNK);
#endif
#ifdef S_IFSOCK
  NUM(S_IFSOCK);
#endif
#ifdef O_CREAT
  NUM(O_CREAT);
#endif
#ifdef O_EXCL
  NUM(O_EXCL);
#endif
  NUM(UV_FS_O_FILEMAP);
  NUM(UV_FS_O_TEMPORARY);
  NUM(UV_FS_O_SHORT_LIVED);
  NUM(UV_FS_O_SEQUENTIAL);
  NUM(UV_FS_O_RANDOM);
#ifdef O_NOCTTY
  NUM(O_NOCTTY);
#endif
#ifdef O_TRUNC
  NUM(O_TRUNC);
#endif
#ifdef O_APPEND
  NUM(O_APPEND);
#endif
#ifdef O_DIRECTORY
  NUM(O_DIRECTORY);
#endif
#ifdef O_NOATIME
  NUM(O_NOATIME);
#endif
#ifdef O_NOFOLLOW
  NUM(O_NOFOLLOW);
#endif
#ifdef O_SYNC
  NUM(O_SYNC);
#elif UV_FS_O_SYNC != 0
  NUM(UV_FS_O_SYNC);
#endif
#ifdef O_DSYNC
  NUM(O_DSYNC);
#elif UV_FS_O_DSYNC != 0
  NUM(UV_FS_O_DSYNC);
#endif
#ifdef O_SYMLINK
  NUM(O_SYMLINK);
#endif
#ifdef O_DIRECT
  NUM(O_DIRECT);
#elif UV_FS_O_DIRECT != 0
  NUM(UV_FS_O_DIRECT);
#endif
#ifdef O_NONBLOCK
  NUM(O_NONBLOCK);
#endif
#ifdef S_IRWXU
  NUM(S_IRWXU);
#endif
#ifdef S_IRUSR
  NUM(S_IRUSR);
#endif
#ifdef S_IWUSR
  NUM(S_IWUSR);
#endif
#ifdef S_IXUSR
  NUM(S_IXUSR);
#endif
#ifdef S_IRWXG
  NUM(S_IRWXG);
#endif
#ifdef S_IRGRP
  NUM(S_IRGRP);
#endif
#ifdef S_IWGRP
  NUM(S_IWGRP);
#endif
#ifdef S_IXGRP
  NUM(S_IXGRP);
#endif
#ifdef S_IRWXO
  NUM(S_IRWXO);
#endif
#ifdef S_IROTH
  NUM(S_IROTH);
#endif
#ifdef S_IWOTH
  NUM(S_IWOTH);
#endif
#ifdef S_IXOTH
  NUM(S_IXOTH);
#endif
#ifdef F_OK
  NUM(F_OK);
#endif
#ifdef R_OK
  NUM(R_OK);
#endif
#ifdef W_OK
  NUM(W_OK);
#endif
#ifdef X_OK
  NUM(X_OK);
#endif
#ifdef UV_FS_COPYFILE_EXCL
# define COPYFILE_EXCL UV_FS_COPYFILE_EXCL
  NUM(UV_FS_COPYFILE_EXCL);
  NUM(COPYFILE_EXCL);
# undef COPYFILE_EXCL
#endif
#ifdef UV_FS_COPYFILE_FICLONE
# define COPYFILE_FICLONE UV_FS_COPYFILE_FICLONE
  NUM(UV_FS_COPYFILE_FICLONE);
  NUM(COPYFILE_FICLONE);
# undef COPYFILE_FICLONE
#endif
#ifdef UV_FS_COPYFILE_FICLONE_FORCE
# define COPYFILE_FICLONE_FORCE UV_FS_COPYFILE_FICLONE_FORCE
  NUM(UV_FS_COPYFILE_FICLONE_FORCE);
  NUM(COPYFILE_FICLONE_FORCE);
# undef COPYFILE_FICLONE_FORCE
#endif
}

static void dlopen_consts(void) {
#ifdef RTLD_LAZY
  NUM(RTLD_LAZY);
#endif
#ifdef RTLD_NOW
  NUM(RTLD_NOW);
#endif
#ifdef RTLD_GLOBAL
  NUM(RTLD_GLOBAL);
#endif
#ifdef RTLD_LOCAL
  NUM(RTLD_LOCAL);
#endif
#ifdef RTLD_DEEPBIND
  NUM(RTLD_DEEPBIND);
#endif
}

static void priority(void) {
#ifdef UV_PRIORITY_LOW
  NUM(UV_PRIORITY_LOW);
#endif
#ifdef UV_PRIORITY_BELOW_NORMAL
  NUM(UV_PRIORITY_BELOW_NORMAL);
#endif
#ifdef UV_PRIORITY_NORMAL
  NUM(UV_PRIORITY_NORMAL);
#endif
#ifdef UV_PRIORITY_ABOVE_NORMAL
  NUM(UV_PRIORITY_ABOVE_NORMAL);
#endif
#ifdef UV_PRIORITY_HIGH
  NUM(UV_PRIORITY_HIGH);
#endif
#ifdef UV_PRIORITY_HIGHEST
  NUM(UV_PRIORITY_HIGHEST);
#endif
}

static void crypto(void) {
  NUM(OPENSSL_VERSION_NUMBER);
  NUM(SSL_OP_ALL);
  NUM(SSL_OP_ALLOW_NO_DHE_KEX);
  NUM(SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  NUM(SSL_OP_CIPHER_SERVER_PREFERENCE);
  NUM(SSL_OP_CISCO_ANYCONNECT);
  NUM(SSL_OP_COOKIE_EXCHANGE);
  NUM(SSL_OP_CRYPTOPRO_TLSEXT_BUG);
  NUM(SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
  NUM(SSL_OP_LEGACY_SERVER_CONNECT);
  NUM(SSL_OP_NO_COMPRESSION);
  NUM(SSL_OP_NO_ENCRYPT_THEN_MAC);
  NUM(SSL_OP_NO_QUERY_MTU);
  NUM(SSL_OP_NO_RENEGOTIATION);
  NUM(SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  NUM(SSL_OP_NO_SSLv2);
  NUM(SSL_OP_NO_SSLv3);
  NUM(SSL_OP_NO_TICKET);
  NUM(SSL_OP_NO_TLSv1);
  NUM(SSL_OP_NO_TLSv1_1);
  NUM(SSL_OP_NO_TLSv1_2);
  NUM(SSL_OP_NO_TLSv1_3);
  NUM(SSL_OP_PRIORITIZE_CHACHA);
  NUM(SSL_OP_TLS_ROLLBACK_BUG);
  NUM(DH_CHECK_P_NOT_SAFE_PRIME);
  NUM(DH_CHECK_P_NOT_PRIME);
  NUM(DH_UNABLE_TO_CHECK_GENERATOR);
  NUM(DH_NOT_SUITABLE_GENERATOR);
  NUM(RSA_PKCS1_PADDING);
  NUM(RSA_SSLV23_PADDING);
  NUM(RSA_NO_PADDING);
  NUM(RSA_PKCS1_OAEP_PADDING);
  NUM(RSA_X931_PADDING);
  NUM(RSA_PKCS1_PSS_PADDING);
  NUM(RSA_PSS_SALTLEN_DIGEST);
  NUM(RSA_PSS_SALTLEN_MAX_SIGN);
  NUM(RSA_PSS_SALTLEN_AUTO);
  NUM(TLS1_VERSION);
  NUM(TLS1_1_VERSION);
  NUM(TLS1_2_VERSION);
  NUM(TLS1_3_VERSION);
  NUM(POINT_CONVERSION_COMPRESSED);
  NUM(POINT_CONVERSION_UNCOMPRESSED);
  NUM(POINT_CONVERSION_HYBRID);
}

static void zlib_consts(void) {
  /* Node derives these in src/node_zlib.cc rather than from zlib headers, so
   * they are emitted from the same expressions Node uses. */
#define Z_MIN_CHUNK 64
#define Z_MAX_CHUNK (1.0 / 0.0) /* std::numeric_limits<double>::infinity() */
#define Z_DEFAULT_CHUNK (16 * 1024)
#define Z_MIN_MEMLEVEL 1
#define Z_MAX_MEMLEVEL 9
#define Z_DEFAULT_MEMLEVEL 8
#define Z_MIN_LEVEL -1
#define Z_MAX_LEVEL 9
#define Z_DEFAULT_LEVEL Z_DEFAULT_COMPRESSION
#define Z_MIN_WINDOWBITS 8
#define Z_MAX_WINDOWBITS 15
#define Z_DEFAULT_WINDOWBITS 15

  /* src/node_zlib.cc `enum node_zlib_mode`, published by value. */
#define MODE_NONE 0
#define MODE_DEFLATE 1
#define MODE_INFLATE 2
#define MODE_GZIP 3
#define MODE_GUNZIP 4
#define MODE_DEFLATERAW 5
#define MODE_INFLATERAW 6
#define MODE_UNZIP 7
#define MODE_BROTLI_DECODE 8
#define MODE_BROTLI_ENCODE 9
#define MODE_ZSTD_COMPRESS 10
#define MODE_ZSTD_DECOMPRESS 11

  NUM(Z_NO_FLUSH);
  NUM(Z_PARTIAL_FLUSH);
  NUM(Z_SYNC_FLUSH);
  NUM(Z_FULL_FLUSH);
  NUM(Z_FINISH);
  NUM(Z_BLOCK);
  NUM(Z_OK);
  NUM(Z_STREAM_END);
  NUM(Z_NEED_DICT);
  NUM(Z_ERRNO);
  NUM(Z_STREAM_ERROR);
  NUM(Z_DATA_ERROR);
  NUM(Z_MEM_ERROR);
  NUM(Z_BUF_ERROR);
  NUM(Z_VERSION_ERROR);
  NUM(Z_NO_COMPRESSION);
  NUM(Z_BEST_SPEED);
  NUM(Z_BEST_COMPRESSION);
  NUM(Z_DEFAULT_COMPRESSION);
  NUM(Z_FILTERED);
  NUM(Z_HUFFMAN_ONLY);
  NUM(Z_RLE);
  NUM(Z_FIXED);
  NUM(Z_DEFAULT_STRATEGY);
  NUM(ZLIB_VERNUM);

  NUM(Z_MIN_WINDOWBITS);
  NUM(Z_MAX_WINDOWBITS);
  NUM(Z_DEFAULT_WINDOWBITS);
  NUM(Z_MIN_CHUNK);
  NUM(Z_MAX_CHUNK);
  NUM(Z_DEFAULT_CHUNK);
  NUM(Z_MIN_MEMLEVEL);
  NUM(Z_MAX_MEMLEVEL);
  NUM(Z_DEFAULT_MEMLEVEL);
  NUM(Z_MIN_LEVEL);
  NUM(Z_MAX_LEVEL);
  NUM(Z_DEFAULT_LEVEL);

  NUM(MODE_DEFLATE);
  NUM(MODE_INFLATE);
  NUM(MODE_GZIP);
  NUM(MODE_GUNZIP);
  NUM(MODE_DEFLATERAW);
  NUM(MODE_INFLATERAW);
  NUM(MODE_UNZIP);
  NUM(MODE_BROTLI_DECODE);
  NUM(MODE_BROTLI_ENCODE);
  NUM(MODE_ZSTD_COMPRESS);
  NUM(MODE_ZSTD_DECOMPRESS);

  NUM(BROTLI_OPERATION_PROCESS);
  NUM(BROTLI_OPERATION_FLUSH);
  NUM(BROTLI_OPERATION_FINISH);
  NUM(BROTLI_OPERATION_EMIT_METADATA);
  NUM(BROTLI_PARAM_MODE);
  NUM(BROTLI_MODE_GENERIC);
  NUM(BROTLI_MODE_TEXT);
  NUM(BROTLI_MODE_FONT);
  NUM(BROTLI_DEFAULT_MODE);
  NUM(BROTLI_PARAM_QUALITY);
  NUM(BROTLI_MIN_QUALITY);
  NUM(BROTLI_MAX_QUALITY);
  NUM(BROTLI_DEFAULT_QUALITY);
  NUM(BROTLI_PARAM_LGWIN);
  NUM(BROTLI_MIN_WINDOW_BITS);
  NUM(BROTLI_MAX_WINDOW_BITS);
  NUM(BROTLI_LARGE_MAX_WINDOW_BITS);
  NUM(BROTLI_DEFAULT_WINDOW);
  NUM(BROTLI_PARAM_LGBLOCK);
  NUM(BROTLI_MIN_INPUT_BLOCK_BITS);
  NUM(BROTLI_MAX_INPUT_BLOCK_BITS);
  NUM(BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING);
  NUM(BROTLI_PARAM_SIZE_HINT);
  NUM(BROTLI_PARAM_LARGE_WINDOW);
  NUM(BROTLI_PARAM_NPOSTFIX);
  NUM(BROTLI_PARAM_NDIRECT);
  NUM(BROTLI_DECODER_RESULT_ERROR);
  NUM(BROTLI_DECODER_RESULT_SUCCESS);
  NUM(BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT);
  NUM(BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);
  NUM(BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION);
  NUM(BROTLI_DECODER_PARAM_LARGE_WINDOW);
#define V(PREFIX, NAME, CODE) printf("BROTLI_DECODER%s%s %d\n", #PREFIX, #NAME, (int)(CODE));
  BROTLI_DECODER_ERROR_CODES_LIST(V, )
#undef V

  NUM(ZSTD_e_continue);
  NUM(ZSTD_e_flush);
  NUM(ZSTD_e_end);
  NUM(ZSTD_fast);
  NUM(ZSTD_dfast);
  NUM(ZSTD_greedy);
  NUM(ZSTD_lazy);
  NUM(ZSTD_lazy2);
  NUM(ZSTD_btlazy2);
  NUM(ZSTD_btopt);
  NUM(ZSTD_btultra);
  NUM(ZSTD_btultra2);
  NUM(ZSTD_c_compressionLevel);
  NUM(ZSTD_c_windowLog);
  NUM(ZSTD_c_hashLog);
  NUM(ZSTD_c_chainLog);
  NUM(ZSTD_c_searchLog);
  NUM(ZSTD_c_minMatch);
  NUM(ZSTD_c_targetLength);
  NUM(ZSTD_c_strategy);
  NUM(ZSTD_c_enableLongDistanceMatching);
  NUM(ZSTD_c_ldmHashLog);
  NUM(ZSTD_c_ldmMinMatch);
  NUM(ZSTD_c_ldmBucketSizeLog);
  NUM(ZSTD_c_ldmHashRateLog);
  NUM(ZSTD_c_contentSizeFlag);
  NUM(ZSTD_c_checksumFlag);
  NUM(ZSTD_c_dictIDFlag);
  NUM(ZSTD_c_nbWorkers);
  NUM(ZSTD_c_jobSize);
  NUM(ZSTD_c_overlapLog);
  NUM(ZSTD_d_windowLogMax);
  NUM(ZSTD_CLEVEL_DEFAULT);
  NUM(ZSTD_error_no_error);
  NUM(ZSTD_error_GENERIC);
  NUM(ZSTD_error_prefix_unknown);
  NUM(ZSTD_error_version_unsupported);
  NUM(ZSTD_error_frameParameter_unsupported);
  NUM(ZSTD_error_frameParameter_windowTooLarge);
  NUM(ZSTD_error_corruption_detected);
  NUM(ZSTD_error_checksum_wrong);
  NUM(ZSTD_error_literals_headerWrong);
  NUM(ZSTD_error_dictionary_corrupted);
  NUM(ZSTD_error_dictionary_wrong);
  NUM(ZSTD_error_dictionaryCreation_failed);
  NUM(ZSTD_error_parameter_unsupported);
  NUM(ZSTD_error_parameter_combination_unsupported);
  NUM(ZSTD_error_parameter_outOfBound);
  NUM(ZSTD_error_tableLog_tooLarge);
  NUM(ZSTD_error_maxSymbolValue_tooLarge);
  NUM(ZSTD_error_maxSymbolValue_tooSmall);
  NUM(ZSTD_error_stabilityCondition_notRespected);
  NUM(ZSTD_error_stage_wrong);
  NUM(ZSTD_error_init_missing);
  NUM(ZSTD_error_memory_allocation);
  NUM(ZSTD_error_workSpace_tooSmall);
  NUM(ZSTD_error_dstSize_tooSmall);
  NUM(ZSTD_error_srcSize_wrong);
  NUM(ZSTD_error_dstBuffer_null);
  NUM(ZSTD_error_noForwardProgress_destFull);
  NUM(ZSTD_error_noForwardProgress_inputEmpty);
}

int main(void) {
  signals();
  errnos();
  fs();
  dlopen_consts();
  priority();
  crypto();
  zlib_consts();
  return 0;
}

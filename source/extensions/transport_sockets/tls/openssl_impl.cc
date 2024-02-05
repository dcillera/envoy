#include "source/extensions/transport_sockets/tls/openssl_impl.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "openssl/crypto.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"
#include "openssl/err.h"

#include <arpa/inet.h>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

const unsigned char* extract_ext_str_value(const unsigned char *data, size_t& data_len, unsigned int type) {
    // https://github.com/openssl/openssl/blob/12a765a5235f181c2f4992b615eb5f892c368e88/test/handshake_helper.c#L150
    unsigned int len, remaining = data_len;
    const unsigned char *p = data;
    if ( p && remaining > 2 ) {
        // ntohs?
        len = (*(p++) << 8);
        len += *(p++);
        if (len + 2 == remaining) {
            remaining = len;
            if (remaining > 0 && *p++ == type) {
                remaining--;
                /* Now we can finally pull out the byte array with the actual extn value. */
                if (remaining > 2) {
                    len = (*(p++) << 8);
                    len += *(p++);
                    if (len + 2 == remaining) {
                        data_len = len;
                        return p;
                    }
                }
            }
        }
    }

    data_len = 0;
    return nullptr;
}

/**
 * Retrieve SNI value
 * @param ssl
 * @return string_view of name (may be empy)
 */
absl::string_view SSL_extract_client_hello_sni_host_name(const SSL* ssl) {
    const unsigned char* p;
    size_t len;

    if ( SSL_client_hello_get0_ext(const_cast<SSL*>(ssl), TLSEXT_TYPE_server_name, &p, &len) ) {
        if ( (p = extract_ext_str_value(p, len, TLSEXT_NAMETYPE_host_name)) != nullptr ) {
            return absl::string_view(reinterpret_cast<const char *>(p), len);
        }
    }

    return absl::string_view();
}

//
//                static int ssl_ctx_client_hello_cb(SSL *ssl, int *alert, void *arg) {
//                    enum ssl_select_cert_result_t (*callback)(const SSL_CLIENT_HELLO *) = arg;
//
//                    SSL_CLIENT_HELLO client_hello;
//                    memset(&client_hello, 0, sizeof(client_hello));
//
//                    client_hello.ssl = ssl;
//                    client_hello.version = ossl.ossl_SSL_client_hello_get0_legacy_version(ssl);
//                    client_hello.random_len = ossl.ossl_SSL_client_hello_get0_random(ssl, &client_hello.random);
//                    client_hello.session_id_len = ossl.ossl_SSL_client_hello_get0_session_id(ssl, &client_hello.session_id);
//                    client_hello.cipher_suites_len = ossl.ossl_SSL_client_hello_get0_ciphers(ssl, &client_hello.cipher_suites);
//                    client_hello.compression_methods_len = ossl.ossl_SSL_client_hello_get0_compression_methods(ssl, &client_hello.compression_methods);
//
//                    int *extension_ids;
//                    size_t extension_ids_len;
//
//                    if (!ossl.ossl_SSL_client_hello_get1_extensions_present(ssl, &extension_ids, &extension_ids_len)) {
//                        *alert = SSL_AD_INTERNAL_ERROR;
//                        return ossl_SSL_CLIENT_HELLO_ERROR;
//                    }
//
//                    CBB extensions;
//                    CBB_init(&extensions, 1024);
//
//                    for (size_t i = 0; i < extension_ids_len; i++) {
//                        const unsigned char *extension_data;
//                        size_t extension_len;
//
//                        if (!ossl.ossl_SSL_client_hello_get0_ext(ssl, extension_ids[i], &extension_data, &extension_len) ||
//                            !CBB_add_u16(&extensions, extension_ids[i]) ||
//                            !CBB_add_u16(&extensions, extension_len) ||
//                            !CBB_add_bytes(&extensions, extension_data, extension_len)) {
//                            OPENSSL_free(extension_ids);
//                            CBB_cleanup(&extensions);
//                            *alert = SSL_AD_INTERNAL_ERROR;
//                            return ossl_SSL_CLIENT_HELLO_ERROR;
//                        }
//                    }
//
//                    OPENSSL_free(extension_ids);
//
//                    if (!CBB_finish(&extensions, (uint8_t**)&client_hello.extensions, &client_hello.extensions_len)) {
//                        CBB_cleanup(&extensions);
//                        *alert = SSL_AD_INTERNAL_ERROR;
//                        return ossl_SSL_CLIENT_HELLO_ERROR;
//                    }
//
//                    enum ssl_select_cert_result_t result = callback(&client_hello);
//
//                    OPENSSL_free((void*)client_hello.extensions);
//
//                    switch (result) {
//                        case ssl_select_cert_success: return ossl_SSL_CLIENT_HELLO_SUCCESS;
//                        case ssl_select_cert_retry:   return ossl_SSL_CLIENT_HELLO_RETRY;
//                        case ssl_select_cert_error:   return ossl_SSL_CLIENT_HELLO_ERROR;
//                    };
//                }
//
//void SSL_CTX_set_select_certificate_cb(SSL_CTX *ctx, enum ssl_select_cert_result_t (*cb)(const SSL_CLIENT_HELLO *)) {
//    SSL_CTX_set_client_hello_cb(ctx, ssl_ctx_client_hello_cb, cb);
//}

int SSL_CTX_set_strict_cipher_list(SSL_CTX *ctx, const char *str) {
    // OpenSSL's SSL_CTX_set_cipher_list() performs virtually no checking on str.
    // It only returns 0 (fail) if no cipher could be selected from the list at
    // all. Otherwise it returns 1 (pass) even if there is only one cipher in the
    // string that makes sense, and the rest are unsupported or even just rubbish.
    if (SSL_CTX_set_cipher_list(ctx, str) == 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    STACK_OF(SSL_CIPHER)* ciphers = reinterpret_cast<STACK_OF(SSL_CIPHER)*>(SSL_CTX_get_ciphers(ctx));
    char* dup = strdup(str);
    char* token = strtok(dup, ":+![|]");
    while (token != NULL) {
        std::string str1(token);
        bool found = false;
        for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
            const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
            std::string str2(SSL_CIPHER_get_name(cipher));
            if (str1.compare(str2) == 0) {
                found = true;
            }
        }

        if (!found && str1.compare("-ALL") && str1.compare("ALL")) {
            free(dup);
            return 0;
        }

        token = strtok(NULL, ":[]|");
    }

    free(dup);
    return 1;
}

/*
 * BoringSSL only returns: TLS1_3_VERSION, TLS1_2_VERSION, or SSL3_VERSION
 */
uint16_t SSL_CIPHER_get_min_version(const SSL_CIPHER *cipher) {
    // This logic was copied from BoringSSL's ssl_cipher.cc

    if ((SSL_CIPHER_get_kx_nid(cipher) == NID_kx_any) ||
        (SSL_CIPHER_get_auth_nid(cipher) == NID_auth_any)) {
        return TLS1_3_VERSION;
    }

    const EVP_MD *digest = SSL_CIPHER_get_handshake_digest(cipher);
    if (EVP_MD_type(digest) != NID_md5_sha1) {
        return TLS1_2_VERSION;
    }

    return SSL3_VERSION;
}

int SSL_set_ocsp_response(SSL *ssl, const uint8_t *response, size_t response_len) {
// OpenSSL takes ownership of the response buffer so we have to take a copy
   void *copy = OPENSSL_memdup(response, response_len);
   if ((copy == NULL) && response) {
     return 0;
   }
   return SSL_set_tlsext_status_ocsp_resp(ssl, copy, response_len);
}

inline bool ssl_client_hello_get_extension(const SSL_CLIENT_HELLO *client_hello,
                                           CBS *out, uint16_t extension_type) {
    CBS extensions;
    CBS_init(&extensions, client_hello->extensions.curr, client_hello->extensions.remaining);
    while (CBS_len(&extensions) != 0) {
        // Decode the next extension.
        uint16_t type;
        CBS extension;
        if (!CBS_get_u16(&extensions, &type) ||
            !CBS_get_u16_length_prefixed(&extensions, &extension)) {
            return false;
        }

        if (type == extension_type) {
            *out = extension;
            return true;
        }
    }

    return false;
}

int SSL_early_callback_ctx_extension_get(const SSL_CLIENT_HELLO *client_hello,
                                         uint16_t extension_type,
                                         const uint8_t **out_data,
                                         size_t *out_len) {
    CBS cbs;
    if (!ssl_client_hello_get_extension(client_hello, &cbs, extension_type)) {
        return 0;
    }

    *out_data = CBS_data(&cbs);
    *out_len = CBS_len(&cbs);
    return 1;
}

bssl::UniquePtr<SSL> newSsl(SSL_CTX* ctx) { return bssl::UniquePtr<SSL>(SSL_new(ctx)); }

int set_strict_cipher_list(SSL_CTX* ctx, const char* str) {
  SSL_CTX_set_cipher_list(ctx, str);

  STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(ctx);
  char* dup = strdup(str);
  char* token = std::strtok(dup, ":+![|]");
  while (token != NULL) {
    std::string str1(token);
    bool found = false;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
      const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
      std::string str2(SSL_CIPHER_get_name(cipher));
      if (str1.compare(str2) == 0) {
        found = true;
      }
    }

    if (!found && str1.compare("-ALL") && str1.compare("ALL")) {
      free(dup);
      return 0;
    }

    token = std::strtok(NULL, ":[]|");
  }

  free(dup);
  return 1;
}

STACK_OF(X509)* SSL_get_peer_full_cert_chain(const SSL* ssl) {
  STACK_OF(X509)* to_copy = SSL_get_peer_cert_chain(ssl);
  // sk_X509_dup does not increase reference counts on certs in the stack.
  STACK_OF(X509)* ret = to_copy == nullptr ? nullptr : sk_X509_dup(to_copy);
  if (ret != nullptr && SSL_is_server(ssl)) {
    X509* peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == nullptr) {
      return ret;
    }
    if (!sk_X509_insert(ret, peer_cert, 0)) {
      sk_X509_pop_free(ret, X509_free);
      return nullptr;
    }
  }

  return ret;
}

void allowRenegotiation(SSL*) {
  // SSL_set_renegotiate_mode(ssl, mode);
}

SSL_SESSION* ssl_session_from_bytes(SSL* client_ssl_socket, const SSL_CTX*,
                                    const std::string& client_session) {
  SSL_SESSION* client_ssl_session = SSL_get_session(client_ssl_socket);
  SSL_SESSION_set_app_data(client_ssl_session, client_session.data());
  return client_ssl_session;
}

int ssl_session_to_bytes(const SSL_SESSION*, uint8_t** out_data, size_t* out_len) {
  //   void *data = SSL_SESSION_get_app_data(in);
  //   *out_data = data;
  *out_data = static_cast<uint8_t*>(OPENSSL_malloc(1));
  *out_len = 1;

  return 1;
}

int should_be_single_use(const SSL_SESSION*) { return 1; }

const SSL_CIPHER *SSL_get_cipher_by_value(uint16_t value) {
    const SSL_CIPHER *result = NULL;
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if(ctx) {
        SSL *ssl = SSL_new(ctx);
        if(ssl) {
            uint16_t nvalue = htons(value);
            result = SSL_CIPHER_find(ssl, (const unsigned char*)&nvalue);
            SSL_free(ssl);
        }
        SSL_CTX_free(ctx);
    }

    return result;
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy

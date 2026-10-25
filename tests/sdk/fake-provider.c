/* SPDX-License-Identifier: Apache-2.0
 * Test-only deliberately invalid dynamic providers. NEVER installed.
 * Both targets lack a real GmSSL implementation and must fail loader admission.
 */
#define CRYPTO_TLS_BUILD_DLL 1
#include <crypto/tls.h>

uint32_t crypto_tls_abi_version(void)
{
#ifdef FAKE_FULL_WRONG_ABI
    return CRYPTO_TLS_ABI_VERSION + UINT32_C(1);
#else
    return CRYPTO_TLS_ABI_VERSION;
#endif
}

#ifdef FAKE_FULL_WRONG_ABI
crypto_tls_result crypto_tls_provider_create(
    uint32_t requested_abi, crypto_tls_provider **out_provider)
{
    (void)requested_abi;
    if (out_provider) *out_provider = NULL;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_provider_destroy(crypto_tls_provider **provider)
{
    (void)provider;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_provider_session_count(
    crypto_tls_provider *provider, uint32_t *out_count)
{
    (void)provider;
    if (out_count) *out_count = 0;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_session_create(
    crypto_tls_provider *provider, const crypto_tls_session_options *options,
    const crypto_tls_io *io, crypto_tls_session **out_session)
{
    (void)provider; (void)options; (void)io;
    if (out_session) *out_session = NULL;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_session_handshake(crypto_tls_session *session)
{
    (void)session;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_session_send(
    crypto_tls_session *session, const uint8_t *data,
    size_t len, size_t *out_sent)
{
    (void)session; (void)data; (void)len;
    if (out_sent) *out_sent = 0;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_session_receive(
    crypto_tls_session *session, uint8_t *data,
    size_t capacity, size_t *out_received)
{
    (void)session; (void)data; (void)capacity;
    if (out_received) *out_received = 0;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_session_shutdown(crypto_tls_session *session)
{
    (void)session;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_session_cancel(crypto_tls_session *session)
{
    (void)session;
    return CRYPTO_TLS_BACKEND_ERROR;
}
crypto_tls_result crypto_tls_session_destroy(crypto_tls_session **session)
{
    (void)session;
    return CRYPTO_TLS_BACKEND_ERROR;
}
#endif

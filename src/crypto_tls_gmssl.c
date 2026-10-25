/* SPDX-License-Identifier: Apache-2.0
 * Private GmSSL 3.2 adapter; never included in the installed SDK.
 */
#include <crypto/tls.h>
#include <gmssl/tls.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct crypto_tls_provider {
    atomic_uint sessions;
};

struct crypto_tls_session {
    crypto_tls_provider *owner;
    atomic_flag in_use;
    atomic_bool cancelled;
    int context_initialized;
    int connection_initialized;
    crypto_tls_io transport;
    TLS_CTX context;
    TLS_CONNECT connection;
};

/* Only the adapter owns raw TLS_CTX, TLS_CONNECT and callback state. */
static tls_ret_t bridge_send(void *user, const void *bytes, size_t len, int flags)
{
    crypto_tls_session *s = (crypto_tls_session *)user;
    int64_t n;
    (void)flags;
    if (!s || !bytes || !len || !s->transport.write
        || atomic_load_explicit(&s->cancelled, memory_order_acquire))
        return TLS_ERROR_SYSCALL;
    n = s->transport.write(s->transport.user, (const uint8_t *)bytes, len);
    if (n == CRYPTO_TLS_IO_AGAIN) return TLS_ERROR_SEND_AGAIN;
    if (n == 0) return TLS_ERROR_TCP_CLOSED;
    if (n <= 0 || (uint64_t)n > (uint64_t)len || n > INT_MAX)
        return TLS_ERROR_SYSCALL;
    return (tls_ret_t)n;
}

static tls_ret_t bridge_recv(void *user, void *bytes, size_t len, int flags)
{
    crypto_tls_session *s = (crypto_tls_session *)user;
    int64_t n;
    (void)flags;
    if (!s || !bytes || !len || !s->transport.read
        || atomic_load_explicit(&s->cancelled, memory_order_acquire))
        return TLS_ERROR_SYSCALL;
    n = s->transport.read(s->transport.user, (uint8_t *)bytes, len);
    if (n == CRYPTO_TLS_IO_AGAIN) return TLS_ERROR_RECV_AGAIN;
    if (n == 0) return TLS_ERROR_TCP_CLOSED;
    if (n <= 0 || (uint64_t)n > (uint64_t)len || n > INT_MAX)
        return TLS_ERROR_SYSCALL;
    return (tls_ret_t)n;
}

static crypto_tls_result lock_session(crypto_tls_session *s)
{
    if (!s) return CRYPTO_TLS_INVALID_ARGUMENT;
    if (atomic_flag_test_and_set_explicit(&s->in_use, memory_order_acquire))
        return CRYPTO_TLS_BUSY;
    return CRYPTO_TLS_OK;
}

static void unlock_session(crypto_tls_session *s)
{
    atomic_flag_clear_explicit(&s->in_use, memory_order_release);
}

static crypto_tls_result map_backend_result(int result)
{
    if (result == 1) return CRYPTO_TLS_OK;
    if (result == TLS_ERROR_SEND_AGAIN || result == TLS_ERROR_RECV_AGAIN)
        return CRYPTO_TLS_AGAIN;
    if (result == TLS_ERROR_TCP_CLOSED) return CRYPTO_TLS_CLOSED;
    return CRYPTO_TLS_BACKEND_ERROR;
}

static crypto_tls_result completed_handshake(TLS_CONNECT *connection)
{
    int complete = 0;
    if (tls_get_handshake_complete(connection, &complete) != 1)
        return CRYPTO_TLS_BACKEND_ERROR;
    return complete ? CRYPTO_TLS_OK : CRYPTO_TLS_AGAIN;
}

uint32_t crypto_tls_abi_version(void)
{
    return CRYPTO_TLS_ABI_VERSION;
}

crypto_tls_result crypto_tls_provider_create(
    uint32_t requested_abi, crypto_tls_provider **out_provider)
{
    crypto_tls_provider *p;
    if (!out_provider) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_provider = NULL;
    if (requested_abi != CRYPTO_TLS_ABI_VERSION)
        return CRYPTO_TLS_INVALID_ARGUMENT;
    p = (crypto_tls_provider *)calloc(1, sizeof(*p));
    if (!p) return CRYPTO_TLS_OUT_OF_MEMORY;
    atomic_init(&p->sessions, 0u);
    *out_provider = p;
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_provider_destroy(crypto_tls_provider **provider)
{
    crypto_tls_provider *p;
    if (!provider || !*provider) return CRYPTO_TLS_INVALID_ARGUMENT;
    p = *provider;
    if (atomic_load_explicit(&p->sessions, memory_order_acquire))
        return CRYPTO_TLS_BUSY;
    *provider = NULL;
    free(p);
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_provider_session_count(
    crypto_tls_provider *provider, uint32_t *out_count)
{
    if (!provider || !out_count) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_count = atomic_load_explicit(&provider->sessions, memory_order_acquire);
    return CRYPTO_TLS_OK;
}

static int valid_options(const crypto_tls_session_options *o)
{
    if (!o || o->struct_size != sizeof(*o) || o->reserved_flags != 0
        || (o->protocol != CRYPTO_TLS_1_2 && o->protocol != CRYPTO_TLS_1_3)
        || (o->role != CRYPTO_TLS_CLIENT && o->role != CRYPTO_TLS_SERVER)
        || o->verify_depth > TLS_MAX_VERIFY_DEPTH)
        return 0;
    if (o->role == CRYPTO_TLS_CLIENT) {
        if (!o->ca_file || !o->ca_file[0] || !o->hostname
            || !o->hostname[0] || strlen(o->hostname) >= 256)
            return 0;
    } else {
        if (!o->certificate_file || !o->certificate_file[0]
            || !o->private_key_file || !o->private_key_file[0])
            return 0;
    }
    return 1;
}

crypto_tls_result crypto_tls_session_create(
    crypto_tls_provider *provider, const crypto_tls_session_options *options,
    const crypto_tls_io *io, crypto_tls_session **out_session)
{
    crypto_tls_session *s;
    TLS_IO callbacks;
    int cipher;
    int group = TLS_curve_secp256r1;
    int signatures[2];
    size_t sig_count;
    int depth;
    if (!out_session) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_session = NULL;
    if (!provider || !valid_options(options)
        || !io || io->struct_size != sizeof(*io) || io->reserved != 0
        || !io->read || !io->write)
        return CRYPTO_TLS_INVALID_ARGUMENT;

    s = (crypto_tls_session *)calloc(1, sizeof(*s));
    if (!s) return CRYPTO_TLS_OUT_OF_MEMORY;
    atomic_flag_clear(&s->in_use);
    atomic_init(&s->cancelled, 0);
    s->owner = provider;
    s->transport = *io;
    depth = options->verify_depth ? (int)options->verify_depth : TLS_DEFAULT_VERIFY_DEPTH;
    cipher = options->protocol == CRYPTO_TLS_1_3
        ? TLS_cipher_aes_128_gcm_sha256
        : TLS_cipher_ecdhe_rsa_with_aes_128_gcm_sha256;
    signatures[0] = options->protocol == CRYPTO_TLS_1_3
        ? TLS_sig_rsa_pss_rsae_sha256 : TLS_sig_rsa_pkcs1_sha256;
    signatures[1] = TLS_sig_rsa_pkcs1_sha256;
    sig_count = options->protocol == CRYPTO_TLS_1_3 ? 2u : 1u;

    if (tls_ctx_init(&s->context, (int)options->protocol,
            (int)options->role) != 1)
        goto fail;
    s->context_initialized = 1;
    if (tls_ctx_set_cipher_suites(&s->context, &cipher, 1u) != 1
        || tls_ctx_set_supported_groups(&s->context, &group, 1u) != 1
        || tls_ctx_set_signature_algorithms(&s->context, signatures, sig_count) != 1)
        goto fail;
    if (options->ca_file && options->ca_file[0]
        && tls_ctx_set_ca_certificates(&s->context, options->ca_file, depth) != 1)
        goto fail;
    if (options->certificate_file && options->private_key_file
        && tls_ctx_set_certificate_and_key(&s->context,
            options->certificate_file, options->private_key_file,
            options->private_key_password ? options->private_key_password : "") != 1)
        goto fail;

    if (tls_init(&s->connection, &s->context) != 1) goto fail;
    s->connection_initialized = 1;
    if (options->role == CRYPTO_TLS_CLIENT
        && (tls_set_hostname(&s->connection, options->hostname) != 1
            || tls_set_server_name(&s->connection) != 1))
        goto fail;
    callbacks.user = s;
    callbacks.send = bridge_send;
    callbacks.recv = bridge_recv;
    if (tls_set_io(&s->connection, &callbacks) != 1)
        goto fail;

    if (atomic_fetch_add_explicit(&provider->sessions, 1u, memory_order_acq_rel)
        == UINT_MAX) {
        atomic_fetch_sub_explicit(&provider->sessions, 1u, memory_order_acq_rel);
        goto fail;
    }
    *out_session = s;
    return CRYPTO_TLS_OK;

fail:
    if (s->connection_initialized) tls_cleanup(&s->connection);
    if (s->context_initialized) tls_ctx_cleanup(&s->context);
    free(s);
    return CRYPTO_TLS_BACKEND_ERROR;
}

crypto_tls_result crypto_tls_session_handshake(crypto_tls_session *s)
{
    crypto_tls_result status = lock_session(s);
    int result;
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire)) {
        status = CRYPTO_TLS_CANCELLED;
    } else {
        status = completed_handshake(&s->connection);
        if (status == CRYPTO_TLS_AGAIN) {
            result = tls_do_handshake(&s->connection);
            status = map_backend_result(result);
            if (status == CRYPTO_TLS_OK)
                status = completed_handshake(&s->connection);
        }
        if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
            status = CRYPTO_TLS_CANCELLED;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_send(
    crypto_tls_session *s, const uint8_t *data, size_t len, size_t *out_sent)
{
    crypto_tls_result status;
    size_t n = 0;
    if (!out_sent) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_sent = 0;
    if (!data || !len) return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
        status = CRYPTO_TLS_CANCELLED;
    else if ((status = completed_handshake(&s->connection)) == CRYPTO_TLS_OK) {
        status = map_backend_result(tls_send(&s->connection, data, len, &n));
        if (status == CRYPTO_TLS_OK) {
            if (!n || n > len) status = CRYPTO_TLS_BACKEND_ERROR;
            else *out_sent = n;
        }
        if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
            status = CRYPTO_TLS_CANCELLED;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_receive(
    crypto_tls_session *s, uint8_t *data, size_t capacity,
    size_t *out_received)
{
    crypto_tls_result status;
    size_t n = 0;
    if (!out_received) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_received = 0;
    if (!data || !capacity) return CRYPTO_TLS_INVALID_ARGUMENT;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
        status = CRYPTO_TLS_CANCELLED;
    else if ((status = completed_handshake(&s->connection)) == CRYPTO_TLS_OK) {
        status = map_backend_result(tls_recv(&s->connection, data, capacity, &n));
        if (status == CRYPTO_TLS_OK) {
            if (!n || n > capacity) status = CRYPTO_TLS_BACKEND_ERROR;
            else *out_received = n;
        }
        if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
            status = CRYPTO_TLS_CANCELLED;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_shutdown(crypto_tls_session *s)
{
    crypto_tls_result status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
        status = CRYPTO_TLS_CANCELLED;
    else {
        status = map_backend_result(tls_shutdown(&s->connection));
        if (atomic_load_explicit(&s->cancelled, memory_order_acquire))
            status = CRYPTO_TLS_CANCELLED;
    }
    unlock_session(s);
    return status;
}

crypto_tls_result crypto_tls_session_cancel(crypto_tls_session *s)
{
    if (!s) return CRYPTO_TLS_INVALID_ARGUMENT;
    atomic_store_explicit(&s->cancelled, 1, memory_order_release);
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_session_destroy(crypto_tls_session **session)
{
    crypto_tls_session *s;
    crypto_tls_result status;
    if (!session || !*session) return CRYPTO_TLS_INVALID_ARGUMENT;
    s = *session;
    status = lock_session(s);
    if (status != CRYPTO_TLS_OK) return status;
    atomic_store_explicit(&s->cancelled, 1, memory_order_release);
    if (s->connection_initialized) tls_cleanup(&s->connection);
    if (s->context_initialized) tls_ctx_cleanup(&s->context);
    atomic_fetch_sub_explicit(&s->owner->sessions, 1u, memory_order_acq_rel);
    *session = NULL;
    free(s);
    return CRYPTO_TLS_OK;
}

/* SPDX-License-Identifier: Apache-2.0
 * Real shared Crypto DSO: host lease protects code during in-flight callbacks,
 * shutdown admission and concurrent TLS cancellation under source TSan.
 */
#define _POSIX_C_SOURCE 200809L
#include <crypto/loader.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef SDK_CA_FILE
#error SDK_CA_FILE is required
#endif

enum { RACE_CYCLES = 64 };

typedef struct rendezvous {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int callback_entered;
    int release_callback;
} rendezvous;

typedef struct tls_worker {
    crypto_tls_module_lease *lease; /* transferred exclusively to this worker */
    crypto_tls_session *session;    /* borrowed until main thread joins */
    crypto_tls_result result;
} tls_worker;

static int64_t stalled_send(void *user, const uint8_t *buffer, size_t len)
{
    rendezvous *gate = (rendezvous *)user;
    (void)buffer; (void)len;
    if (pthread_mutex_lock(&gate->mutex) != 0) return CRYPTO_TLS_IO_ERROR;
    gate->callback_entered = 1;
    pthread_cond_broadcast(&gate->cond);
    while (!gate->release_callback)
        pthread_cond_wait(&gate->cond, &gate->mutex);
    pthread_mutex_unlock(&gate->mutex);
    return CRYPTO_TLS_IO_AGAIN;
}

static int64_t empty_receive(void *user, uint8_t *buffer, size_t capacity)
{
    (void)user; (void)buffer; (void)capacity;
    return CRYPTO_TLS_IO_AGAIN;
}

static void *handshake_worker(void *borrowed)
{
    tls_worker *w = (tls_worker *)borrowed;
    const crypto_tls_module_api *api = NULL;
    if (crypto_tls_module_lease_api(w->lease, &api) != CRYPTO_TLS_OK
        || !api) w->result = CRYPTO_TLS_BACKEND_ERROR;
    else w->result = api->session_handshake(w->session);
    (void)crypto_tls_module_release(&w->lease);
    return NULL;
}

static int one_round(const char *native_path, int round)
{
    crypto_tls_module *module = NULL;
    crypto_tls_module_lease *main_lease = NULL, *worker_lease = NULL;
    crypto_tls_module_lease *denied = NULL;
    const crypto_tls_module_api *api = NULL;
    crypto_tls_provider *provider = NULL;
    crypto_tls_session *session = NULL;
    crypto_tls_session_options options = {
        sizeof(options), CRYPTO_TLS_1_3, CRYPTO_TLS_CLIENT, 4u,
        "localhost", SDK_CA_FILE, NULL, NULL, NULL, 0u
    };
    rendezvous gate;
    crypto_tls_io io = {
        sizeof(io), 0u, &gate, stalled_send, empty_receive
    };
    tls_worker w;
    pthread_t worker_id;
    int started = 0, okay = 0, callback_seen = 0;
    uint32_t count = 0u;

    if (pthread_mutex_init(&gate.mutex, NULL) != 0) return 10;
    if (pthread_cond_init(&gate.cond, NULL) != 0) {
        pthread_mutex_destroy(&gate.mutex);
        return 11;
    }
    gate.callback_entered = 0;
    gate.release_callback = 0;
    w.lease = NULL;
    w.session = NULL;
    w.result = CRYPTO_TLS_INVALID_ARGUMENT;

    if (crypto_tls_module_open(native_path, &module) != CRYPTO_TLS_OK
        || crypto_tls_module_acquire(module, &main_lease) != CRYPTO_TLS_OK
        || crypto_tls_module_lease_api(main_lease, &api) != CRYPTO_TLS_OK
        || !api
        || api->provider_create(CRYPTO_TLS_ABI_VERSION, &provider)
            != CRYPTO_TLS_OK
        || api->session_create(provider, &options, &io, &session)
            != CRYPTO_TLS_OK
        || crypto_tls_module_acquire(module, &worker_lease) != CRYPTO_TLS_OK)
        goto done;

    /* The TLS worker receives its OWN code lease before the host can start
     * draining. No caller holds a raw unleased GmSSL function pointer.
     */
    w.lease = worker_lease;
    worker_lease = NULL;
    w.session = session;
    if (pthread_create(&worker_id, NULL, handshake_worker, &w) != 0)
        goto done;
    started = 1;
    {
        struct timespec deadline;
        if (timespec_get(&deadline, TIME_UTC) != TIME_UTC) goto done;
        deadline.tv_sec += 10;
        pthread_mutex_lock(&gate.mutex);
        while (!gate.callback_entered) {
            if (pthread_cond_timedwait(&gate.cond, &gate.mutex, &deadline) != 0)
                break;
        }
        callback_seen = gate.callback_entered;
        pthread_mutex_unlock(&gate.mutex);
    }
    if (!callback_seen) goto done;

    /* Closing must atomically reject NEW leases, but MUST keep the native
     * image resident while an active worker holds its lease and is inside
     * a real GmSSL external I/O callback.
     */
    if (crypto_tls_module_close(module) != CRYPTO_TLS_BUSY
        || crypto_tls_module_acquire(module, &denied) != CRYPTO_TLS_CLOSED
        || denied
        || api->session_destroy(&session) != CRYPTO_TLS_BUSY
        || !session
        || api->provider_destroy(&provider) != CRYPTO_TLS_BUSY
        || !provider
        || api->provider_session_count(provider, &count) != CRYPTO_TLS_OK
        || count != 1u
        || api->session_cancel(session) != CRYPTO_TLS_OK)
        goto done;
    okay = 1;

done:
    if (started) {
        pthread_mutex_lock(&gate.mutex);
        gate.release_callback = 1;
        pthread_cond_broadcast(&gate.cond);
        pthread_mutex_unlock(&gate.mutex);
        pthread_join(worker_id, NULL);
        if (w.result != CRYPTO_TLS_CANCELLED || w.lease)
            okay = 0;
    } else if (w.lease) {
        (void)crypto_tls_module_release(&w.lease);
    }
    if (worker_lease) (void)crypto_tls_module_release(&worker_lease);
    if (session && (!api || api->session_destroy(&session) != CRYPTO_TLS_OK
                    || session))
        okay = 0;
    if (provider && (!api || api->provider_destroy(&provider) != CRYPTO_TLS_OK
                     || provider))
        okay = 0;
    if (module && main_lease && crypto_tls_module_close(module)
        != CRYPTO_TLS_BUSY) okay = 0;
    api = NULL;
    if (main_lease && crypto_tls_module_release(&main_lease) != CRYPTO_TLS_OK)
        okay = 0;
    if (module) {
        if (crypto_tls_module_close(module) != CRYPTO_TLS_OK
            || crypto_tls_module_destroy(&module) != CRYPTO_TLS_OK || module)
            okay = 0;
    }
    pthread_cond_destroy(&gate.cond);
    pthread_mutex_destroy(&gate.mutex);
    if (!okay) fprintf(stderr, "Crypto host code lease TSan round %d FAILED\n", round);
    return okay ? 0 : 1;
}

int main(int argc, char **argv)
{
    int round;
    if (argc != 2 || !argv[1] || !argv[1][0]) return 2;
    for (round = 0; round < RACE_CYCLES; ++round)
        if (one_round(argv[1], round) != 0) return 1;
    puts("Crypto host shared DSO: 64 callback-in-flight admission/drain/unload races PASS");
    return 0;
}

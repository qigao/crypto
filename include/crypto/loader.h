/* SPDX-License-Identifier: Apache-2.0
 * Host-side, provider-neutral C11 DSO admission and unload lease.
 *
 * This library does NOT link the Crypto TLS DLL/DSO or GmSSL statically.
 * Each live lease pins the loaded native image through a host-owned handle.
 */
#ifndef CRYPTO_TLS_LOADER_H
#define CRYPTO_TLS_LOADER_H
#include <crypto/tls.h>
#include <crypto/tls_ext.h>
#include <crypto/tls_peer.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct crypto_tls_module crypto_tls_module;
typedef struct crypto_tls_module_lease crypto_tls_module_lease;

/* All function pointers refer to one loaded DSO, and are valid ONLY while
 * holding a lease. Do not copy or cache them past module_release().
 * Sessions/providers created through this table must be destroyed BEFORE
 * releasing the final lease covering their lifetime.
 */
typedef struct crypto_tls_module_api {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t (*version)(void);
    crypto_tls_result (*provider_create)(
        uint32_t requested_abi, crypto_tls_provider **out_provider);
    crypto_tls_result (*provider_destroy)(crypto_tls_provider **provider);
    crypto_tls_result (*provider_session_count)(
        crypto_tls_provider *provider, uint32_t *out_count);
    crypto_tls_result (*session_create)(
        crypto_tls_provider *provider, const crypto_tls_session_options *options,
        const crypto_tls_io *io, crypto_tls_session **out_session);
    crypto_tls_result (*session_handshake)(crypto_tls_session *session);
    crypto_tls_result (*session_send)(
        crypto_tls_session *session, const uint8_t *data, size_t len,
        size_t *out_sent);
    crypto_tls_result (*session_receive)(
        crypto_tls_session *session, uint8_t *data, size_t capacity,
        size_t *out_received);
    crypto_tls_result (*session_shutdown)(crypto_tls_session *session);
    crypto_tls_result (*session_cancel)(crypto_tls_session *session);
    crypto_tls_result (*session_destroy)(crypto_tls_session **session);
    /* V1.1 extension: published atomically with the base eleven functions.
     * This pre-release host helper never admits a partial feature table.
     */
    uint32_t (*extension_version)(void);
    crypto_tls_result (*features_v1_1)(uint64_t *out_features);
    crypto_tls_result (*session_set_alpn_v1_1)(
        crypto_tls_session *session, const char *const *names, size_t count);
    crypto_tls_result (*session_get_info_v1_1)(
        crypto_tls_session *session, crypto_tls_session_info_v1_1 *out_info);
    uint32_t (*peer_version_v1_2)(void);
    crypto_tls_result (*peer_features_v1_2)(uint64_t *out_features);
    crypto_tls_result (*peer_copy_chain_v1_2)(
        crypto_tls_session *session, uint8_t *out, size_t capacity,
        size_t *out_size);
    crypto_tls_result (*peer_sha256_v1_2)(
        crypto_tls_session *session, uint8_t out[CRYPTO_TLS_PEER_SHA256_BYTES]);
    crypto_tls_result (*session_export_v1_2)(
        crypto_tls_session *session, const char *label,
        const uint8_t *context, size_t context_len, uint32_t use_context,
        uint8_t *out, size_t out_len);
} crypto_tls_module_api;

/* Explicit absolute native DSO/DLL path; no fallback library discovery.
 * Successful open validates the exported Crypto TLS ABI version and all
 * twenty required symbols (11 base + 4 v1.1 + 5 v1.2) before publishing the module handle.
 */
crypto_tls_result crypto_tls_module_open(
    const char *native_path, crypto_tls_module **out_module);

/* Acquire is atomic with closing admission: it either pins the image or
 * fails CLOSED. A lease is owned by exactly one caller; hand it to a worker
 * only when the previous owner is no longer using it.
 */
crypto_tls_result crypto_tls_module_acquire(
    crypto_tls_module *module, crypto_tls_module_lease **out_lease);
crypto_tls_result crypto_tls_module_lease_api(
    const crypto_tls_module_lease *lease, const crypto_tls_module_api **out_api);
crypto_tls_result crypto_tls_module_release(crypto_tls_module_lease **lease);

/* close() permanently rejects new leases, returns BUSY without unloading
 * while any lease exists, and may be retried after the final lease release.
 * On success, the OS loader handle is released exactly once. Concurrent
 * close callers do not unload twice. The OS may retain the image if some
 * unrelated owner holds another dynamic library reference.
 *
 * IMPORTANT: The module control block must remain allocated during ALL
 * concurrent acquire/close/release calls. The host MUST join/stop all
 * callers before module_destroy() and never use a stale module or lease
 * pointer after destruction. No API can make arbitrary stale pointers safe.
 */
crypto_tls_result crypto_tls_module_close(crypto_tls_module *module);
crypto_tls_result crypto_tls_module_destroy(crypto_tls_module **module);

#ifdef __cplusplus
}
#endif
#endif

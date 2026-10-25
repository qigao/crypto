/* SPDX-License-Identifier: Apache-2.0
 * Installed SDK proof: host loader itself has NO link dependency on Crypto TLS.
 */
#include <crypto/loader.h>
#include <stdio.h>
#include <stdint.h>

enum { RELOAD_CYCLES = 32 };

static int one_cycle(const char *library_path, int iteration)
{
    crypto_tls_module *module = NULL;
    crypto_tls_module_lease *first = NULL, *second = NULL, *denied = NULL;
    const crypto_tls_module_api *api = NULL;
    crypto_tls_provider *provider = NULL;
    uint32_t count = UINT32_MAX;
    int rc = 1;
    if (crypto_tls_module_open(library_path, &module) != CRYPTO_TLS_OK
        || !module) goto done;
    if (crypto_tls_module_destroy(&module) != CRYPTO_TLS_BUSY
        || !module) goto done;
    if (crypto_tls_module_acquire(module, &first) != CRYPTO_TLS_OK
        || crypto_tls_module_acquire(module, &second) != CRYPTO_TLS_OK
        || crypto_tls_module_lease_api(first, &api) != CRYPTO_TLS_OK)
        goto done;
    if (!api || api->struct_size != sizeof(*api)
        || api->abi_version != CRYPTO_TLS_ABI_VERSION
        || api->version() != CRYPTO_TLS_ABI_VERSION)
        goto done;
    if (api->provider_create(CRYPTO_TLS_ABI_VERSION, &provider) != CRYPTO_TLS_OK
        || !provider
        || api->provider_session_count(provider, &count) != CRYPTO_TLS_OK
        || count != 0) goto done;

    /* A pending close gates admission immediately without releasing native
     * code while either explicit borrow exists. Existing vtable still works.
     */
    if (crypto_tls_module_close(module) != CRYPTO_TLS_BUSY
        || crypto_tls_module_acquire(module, &denied) != CRYPTO_TLS_CLOSED
        || denied
        || api->provider_session_count(provider, &count) != CRYPTO_TLS_OK
        || count != 0)
        goto done;
    if (api->provider_destroy(&provider) != CRYPTO_TLS_OK
        || provider) goto done;
    if (crypto_tls_module_release(&first) != CRYPTO_TLS_OK || first
        || crypto_tls_module_close(module) != CRYPTO_TLS_BUSY)
        goto done;
    if (crypto_tls_module_release(&second) != CRYPTO_TLS_OK || second
        || crypto_tls_module_close(module) != CRYPTO_TLS_OK
        || crypto_tls_module_close(module) != CRYPTO_TLS_OK)
        goto done;
    api = NULL; /* no native calls or cached vtable past final lease */
    if (crypto_tls_module_acquire(module, &denied) != CRYPTO_TLS_CLOSED
        || denied) goto done;
    if (crypto_tls_module_destroy(&module) != CRYPTO_TLS_OK || module)
        goto done;
    rc = 0;
done:
    if (provider && api) (void)api->provider_destroy(&provider);
    if (first) (void)crypto_tls_module_release(&first);
    if (second) (void)crypto_tls_module_release(&second);
    if (module) {
        (void)crypto_tls_module_close(module);
        (void)crypto_tls_module_destroy(&module);
    }
    if (rc) fprintf(stderr, "host module lease cycle %d failed\n", iteration);
    return rc;
}

int main(int argc, char **argv)
{
    int i;
    crypto_tls_module *invalid = NULL;
    if (argc != 4 || !argv[1] || !argv[1][0]
        || !argv[2] || !argv[2][0] || !argv[3] || !argv[3][0]) return 2;
    if (crypto_tls_module_open(NULL, &invalid) != CRYPTO_TLS_INVALID_ARGUMENT
        || invalid || crypto_tls_module_open(".", &invalid)
            != CRYPTO_TLS_INVALID_ARGUMENT || invalid)
        return 3;
    /* A library exporting only one of eleven symbols is rejected; a full
     * ABI table reporting a different epoch is rejected separately. Neither
     * failed admission may publish a host control block.
     */
    if (crypto_tls_module_open(argv[2], &invalid) != CRYPTO_TLS_BACKEND_ERROR
        || invalid
        || crypto_tls_module_open(argv[3], &invalid) != CRYPTO_TLS_BACKEND_ERROR
        || invalid) return 4;
    for (i = 0; i < RELOAD_CYCLES; ++i)
        if (one_cycle(argv[1], i) != 0) return 1;
    puts("Crypto C11 TLSHost: 32 real DSO open/drain/lease/release/unload cycles PASS");
    return 0;
}

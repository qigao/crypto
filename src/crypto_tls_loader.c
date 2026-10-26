/* SPDX-License-Identifier: Apache-2.0
 * Host-side native loader; no link-time dependency on CryptoTLS or GmSSL.
 */
#include <crypto/loader.h>

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#if defined(_WIN32)
# include <windows.h>
typedef HMODULE native_library;
static native_library library_open(const char *path) { return LoadLibraryA(path); }
static int library_close(native_library value) { return FreeLibrary(value) != 0; }
static void *library_symbol(native_library value, const char *name)
{
    FARPROC entry = GetProcAddress(value, name);
    void *out = NULL;
    if (entry && sizeof(entry) == sizeof(out))
        memcpy(&out, &entry, sizeof(out));
    return out;
}
static int is_absolute(const char *p)
{
    return p && ((isalpha((unsigned char)p[0]) && p[1] == ':'
         && (p[2] == '/' || p[2] == '\\'))
         || (p[0] == '\\' && p[1] == '\\')
         || (p[0] == '/' && p[1] == '/'));
}
#else
# include <dlfcn.h>
typedef void *native_library;
static native_library library_open(const char *path)
{
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}
static int library_close(native_library value) { return dlclose(value) == 0; }
static void *library_symbol(native_library value, const char *name)
{
    return dlsym(value, name);
}
static int is_absolute(const char *p) { return p && p[0] == '/'; }
#endif

/* Admission is a SINGLE compare/exchange for gate state and count. A close
 * cannot observe zero and unload after a concurrent successful acquire.
 */
#define GATE_DRAINING UINT64_C(0x8000000000000000)
#define GATE_UNLOADING UINT64_C(0x4000000000000000)
#define GATE_CLOSED UINT64_C(0x2000000000000000)
#define GATE_FAILED UINT64_C(0x1000000000000000)
#define GATE_COUNT_MASK UINT64_C(0x0fffffffffffffff)

struct crypto_tls_module {
    _Atomic uint64_t state;
    native_library native;
    crypto_tls_module_api api;
};
struct crypto_tls_module_lease {
    crypto_tls_module *owner;
};

crypto_tls_result crypto_tls_module_open(
    const char *native_path, crypto_tls_module **out_module)
{
    crypto_tls_module *module;
    if (!out_module) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_module = NULL;
    if (!is_absolute(native_path) || !native_path[0])
        return CRYPTO_TLS_INVALID_ARGUMENT;
    module = (crypto_tls_module *)calloc(1, sizeof(*module));
    if (!module) return CRYPTO_TLS_OUT_OF_MEMORY;
    atomic_init(&module->state, UINT64_C(0));
    module->native = library_open(native_path);
    if (!module->native) goto failed;
    module->api.struct_size = (uint32_t)sizeof(module->api);
    module->api.abi_version = CRYPTO_TLS_ABI_VERSION;

    /* POSIX dlsym and Win32 GetProcAddress supply a function-address
     * representation. Copy its bytes rather than aliasing a function pointer
     * object through void**, which violates ISO C strict aliasing.
     * Unsupported function/data pointer widths fail closed.
     */
#define LOAD(field, exported) do { \
    void *address = library_symbol(module->native, exported); \
    if (!address || sizeof(address) != sizeof(module->api.field)) goto failed; \
    memcpy(&module->api.field, &address, sizeof(address)); \
} while (0)
    LOAD(version, "crypto_tls_abi_version");
    LOAD(provider_create, "crypto_tls_provider_create");
    LOAD(provider_destroy, "crypto_tls_provider_destroy");
    LOAD(provider_session_count, "crypto_tls_provider_session_count");
    LOAD(session_create, "crypto_tls_session_create");
    LOAD(session_handshake, "crypto_tls_session_handshake");
    LOAD(session_send, "crypto_tls_session_send");
    LOAD(session_receive, "crypto_tls_session_receive");
    LOAD(session_shutdown, "crypto_tls_session_shutdown");
    LOAD(session_cancel, "crypto_tls_session_cancel");
    LOAD(session_destroy, "crypto_tls_session_destroy");
    LOAD(extension_version, "crypto_tls_extension_abi_version");
    LOAD(features_v1_1, "crypto_tls_get_features_v1_1");
    LOAD(session_set_alpn_v1_1, "crypto_tls_session_set_alpn_v1_1");
    LOAD(session_get_info_v1_1, "crypto_tls_session_get_info_v1_1");
#undef LOAD

    if (module->api.version() != CRYPTO_TLS_ABI_VERSION
        || module->api.extension_version() != CRYPTO_TLS_EXTENSION_ABI_VERSION)
        goto failed;
    *out_module = module;
    return CRYPTO_TLS_OK;

failed:
    if (module->native) (void)library_close(module->native);
    free(module);
    return CRYPTO_TLS_BACKEND_ERROR;
}

crypto_tls_result crypto_tls_module_acquire(
    crypto_tls_module *module, crypto_tls_module_lease **out_lease)
{
    crypto_tls_module_lease *lease;
    uint64_t old;
    if (!out_lease) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_lease = NULL;
    if (!module) return CRYPTO_TLS_INVALID_ARGUMENT;
    lease = (crypto_tls_module_lease *)malloc(sizeof(*lease));
    if (!lease) return CRYPTO_TLS_OUT_OF_MEMORY;
    old = atomic_load_explicit(&module->state, memory_order_acquire);
    for (;;) {
        if (old & GATE_DRAINING) {
            free(lease);
            return CRYPTO_TLS_CLOSED;
        }
        if ((old & GATE_COUNT_MASK) == GATE_COUNT_MASK) {
            free(lease);
            return CRYPTO_TLS_BUSY;
        }
        if (atomic_compare_exchange_weak_explicit(
                &module->state, &old, old + UINT64_C(1),
                memory_order_acq_rel, memory_order_acquire))
            break;
    }
    lease->owner = module;
    *out_lease = lease;
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_module_lease_api(
    const crypto_tls_module_lease *lease, const crypto_tls_module_api **out_api)
{
    if (!out_api) return CRYPTO_TLS_INVALID_ARGUMENT;
    *out_api = NULL;
    if (!lease || !lease->owner) return CRYPTO_TLS_INVALID_ARGUMENT;
    /* Its successful acquire pinned this module regardless of drain state. */
    *out_api = &lease->owner->api;
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_module_release(crypto_tls_module_lease **lease)
{
    crypto_tls_module *module;
    crypto_tls_module_lease *owned;
    if (!lease || !*lease || !(*lease)->owner)
        return CRYPTO_TLS_INVALID_ARGUMENT;
    owned = *lease;
    module = owned->owner;
    *lease = NULL;
    free(owned);
    /* Do not touch module after this decrement; a closing owner may unload
     * immediately after observing the final lease count drop to zero.
     */
    (void)atomic_fetch_sub_explicit(
        &module->state, UINT64_C(1), memory_order_acq_rel);
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_module_close(crypto_tls_module *module)
{
    uint64_t old;
    if (!module) return CRYPTO_TLS_INVALID_ARGUMENT;
    (void)atomic_fetch_or_explicit(
        &module->state, GATE_DRAINING, memory_order_acq_rel);
    old = atomic_load_explicit(&module->state, memory_order_acquire);
    for (;;) {
        if (old & GATE_CLOSED) return CRYPTO_TLS_OK;
        if (old & GATE_FAILED) return CRYPTO_TLS_BACKEND_ERROR;
        if ((old & GATE_UNLOADING) || (old & GATE_COUNT_MASK))
            return CRYPTO_TLS_BUSY;
        if (atomic_compare_exchange_weak_explicit(
                &module->state, &old, old | GATE_UNLOADING,
                memory_order_acq_rel, memory_order_acquire))
            break;
    }
    /* No leases can exist now or enter later, and only this thread owns the
     * UNLOADING transition. Other dlopen handles are outside this module.
     */
    if (!library_close(module->native)) {
        atomic_store_explicit(&module->state,
            GATE_DRAINING | GATE_FAILED, memory_order_release);
        return CRYPTO_TLS_BACKEND_ERROR;
    }
    module->native = (native_library)0;
    atomic_store_explicit(&module->state,
        GATE_DRAINING | GATE_CLOSED, memory_order_release);
    return CRYPTO_TLS_OK;
}

crypto_tls_result crypto_tls_module_destroy(crypto_tls_module **out_module)
{
    crypto_tls_module *module;
    if (!out_module || !*out_module) return CRYPTO_TLS_INVALID_ARGUMENT;
    module = *out_module;
    if (atomic_load_explicit(&module->state, memory_order_acquire)
        != (GATE_DRAINING | GATE_CLOSED))
        return CRYPTO_TLS_BUSY;
    /* Required host synchronization: no callers can race this free. */
    *out_module = NULL;
    free(module);
    return CRYPTO_TLS_OK;
}

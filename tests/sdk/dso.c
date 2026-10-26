/* Installed SDK unload test. Does NOT link against Crypto or GmSSL. */
#include <crypto/tls.h>
#include <stdio.h>
#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>
typedef HMODULE module_handle;
static module_handle load_module(const char *p) { return LoadLibraryA(p); }
static void *find_symbol(module_handle m, const char *n) {
    return (void *)GetProcAddress(m,n);
}
static int unload_module(module_handle m) { return FreeLibrary(m) != 0; }
#else
#include <dlfcn.h>
typedef void *module_handle;
static module_handle load_module(const char *p) { return dlopen(p,RTLD_NOW|RTLD_LOCAL); }
static void *find_symbol(module_handle m,const char *n) { return dlsym(m,n); }
static int unload_module(module_handle m) { return dlclose(m) == 0; }
#endif

typedef uint32_t (*version_fn)(void);
typedef crypto_tls_result (*create_fn)(uint32_t,crypto_tls_provider **);
typedef crypto_tls_result (*destroy_fn)(crypto_tls_provider **);

int main(int argc,char **argv)
{
    int i;
    if (argc != 2 || !argv[1] || !argv[1][0]) return 2;
    for (i = 0; i < 16; ++i) {
        module_handle m = load_module(argv[1]);
        version_fn version;
        create_fn create;
        destroy_fn destroy;
        crypto_tls_provider *p = NULL;
        if (!m) {
            fprintf(stderr,"Crypto Provider DSO cannot be loaded, iteration %d\n",i);
            return 3;
        }
        version = (version_fn)find_symbol(m,"crypto_tls_abi_version");
        create = (create_fn)find_symbol(m,"crypto_tls_provider_create");
        destroy = (destroy_fn)find_symbol(m,"crypto_tls_provider_destroy");
        if (!version || !create || !destroy
            || find_symbol(m,"tls_do_handshake")
            || find_symbol(m,"tls_ctx_init")
            || find_symbol(m,"x509_key_generate")) return 4;
        if (version() != CRYPTO_TLS_ABI_VERSION
            || create(CRYPTO_TLS_ABI_VERSION,&p) != CRYPTO_TLS_OK || !p
            || destroy(&p) != CRYPTO_TLS_OK || p)
            return 5;
        if (!unload_module(m)) return 6;
    }
    puts("Crypto shared Provider DSO exports, independent load/unload: PASS");
    return 0;
}

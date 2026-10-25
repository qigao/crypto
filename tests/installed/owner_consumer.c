#include <crypto/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
typedef HMODULE probe_module;
static probe_module probe_open(const char *path) { return LoadLibraryA(path); }
static void *probe_symbol(probe_module p,const char *n) {
  return (void *)(uintptr_t)GetProcAddress(p,n);
}
static void probe_close(probe_module p) { if(p) FreeLibrary(p); }
#else
#include <dlfcn.h>
typedef void *probe_module;
static probe_module probe_open(const char *p) { return dlopen(p, RTLD_NOW|RTLD_LOCAL); }
static void *probe_symbol(probe_module p,const char *n) { return dlsym(p,n); }
static void probe_close(probe_module p) { if(p) dlclose(p); }
#endif

typedef void (*marker_t)(void);
typedef marker_t (*get_marker_t)(void);
typedef int (*works_t)(void);
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "owner check line %d: %s\n",__LINE__,#x); goto cleanup; } } while (0)
int main(void) {
  int rc=1;
  unsigned round;
  crypto_provider_abi_0_1_required();
  for(round=0;round<8u;++round) {
    probe_module a=probe_open(CRYPTO_PROBE_A);
    probe_module b=probe_open(CRYPTO_PROBE_B);
    get_marker_t mark_a=NULL,mark_b=NULL;
    works_t work_a=NULL,work_b=NULL;
    void *raw=NULL;
    if(!a||!b) {
      fprintf(stderr,"missing native test module A/B on round %u\n",round);
      probe_close(b);probe_close(a);return 2;
    }
    raw=probe_symbol(a,"crypto_probe_marker");
    if(sizeof(raw)!=sizeof(mark_a)) { probe_close(b);probe_close(a);return 3; }
    memcpy(&mark_a,&raw,sizeof(mark_a));
    raw=probe_symbol(b,"crypto_probe_marker");
    memcpy(&mark_b,&raw,sizeof(mark_b));
    raw=probe_symbol(a,"crypto_probe_works");
    memcpy(&work_a,&raw,sizeof(work_a));
    raw=probe_symbol(b,"crypto_probe_works");
    memcpy(&work_b,&raw,sizeof(work_b));
    if(!mark_a||!mark_b||!work_a||!work_b ||
       mark_a()!=mark_b() ||
       mark_a()!=&crypto_provider_abi_0_1_required ||
       !work_a()||!work_b()) {
      fprintf(stderr,"two native modules resolved different Provider ABI owners\n");
      probe_close(b);probe_close(a);return 4;
    }
    /* Both module entry calls quiesced before each unload. */
    probe_close(b);probe_close(a);
  }
  rc=0;
cleanup:
  return rc;
}

#include <crypto/provider.h>
#include <crypto/tls.h>
#if defined(_WIN32)
# define CRYPTO_TEST_EXPORT __declspec(dllexport)
#else
# define CRYPTO_TEST_EXPORT __attribute__((visibility("default")))
#endif

typedef void (*crypto_test_abi_marker)(void);
CRYPTO_TEST_EXPORT crypto_test_abi_marker crypto_probe_marker(void) {
  return &crypto_provider_abi_0_1_required;
}
CRYPTO_TEST_EXPORT int crypto_probe_works(void) {
  static const uint8_t abc[3] = {'a','b','c'};
  uint8_t output[CRYPTO_PROVIDER_SM3_SIZE];
  crypto_provider_abi_0_1_required();
  return crypto_provider_runtime_abi() == CRYPTO_PROVIDER_ABI_VERSION &&
         crypto_tls_abi_version() == CRYPTO_TLS_ABI_VERSION &&
         crypto_provider_sm3(abc,3,output,sizeof(output)) == CRYPTO_PROVIDER_OK;
}

CRYPTO_TEST_EXPORT uint32_t (*crypto_probe_tls_marker(void))(void) {
  return &crypto_tls_abi_version;
}

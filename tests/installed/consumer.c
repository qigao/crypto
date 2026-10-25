#include <crypto/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define CHECK(cond) do { if (!(cond)) { \
  fprintf(stderr,"C11 provider line %d: %s\n", __LINE__, #cond); \
  return __LINE__; } } while (0)
int main(void) {
  static const uint8_t expected[32] = {
    0x66,0xc7,0xf0,0xf4,0x62,0xee,0xdd,0x9d,
    0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
    0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,
    0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
  };
  uint8_t digest[32];
  size_t i;
  crypto_provider_abi_0_1_required();
  CHECK(crypto_provider_runtime_abi() == CRYPTO_PROVIDER_ABI_VERSION);
  CHECK(crypto_provider_sm3((const uint8_t*)"abc",3,digest,sizeof(digest))
        == CRYPTO_PROVIDER_OK);
  if (memcmp(digest, expected, sizeof(expected)) != 0) {
    size_t j;
    fprintf(stderr, "SM3(abc) observed=");
    for (j=0u;j<sizeof(digest);++j) fprintf(stderr, "%02x", digest[j]);
    fprintf(stderr, " expected=");
    for (j=0u;j<sizeof(expected);++j) fprintf(stderr, "%02x", expected[j]);
    fprintf(stderr, "\\n");
    return __LINE__;
  }
  memset(digest, 0x5a, sizeof(digest));
  CHECK(crypto_provider_sm3(NULL,1,digest,sizeof(digest))
        == CRYPTO_PROVIDER_INVALID_ARGUMENT);
  CHECK(crypto_provider_sm3((const uint8_t*)"abc",3,digest,31u)
        == CRYPTO_PROVIDER_INVALID_ARGUMENT);
  CHECK(crypto_provider_sm3((const uint8_t*)"abc",3,NULL,32u)
        == CRYPTO_PROVIDER_INVALID_ARGUMENT);
  for (i=0;i<sizeof(digest);++i) CHECK(digest[i]==0x5au);
  CHECK(crypto_provider_sm3(NULL,0,digest,sizeof(digest))
        == CRYPTO_PROVIDER_OK);
  return 0;
}

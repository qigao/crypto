/* Candidate-only C11 parser contract; no imported GmSSL image or old CMake target. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "tls13-compat-ccs.h"
#include "tls13-hrr-padding.h"

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "candidate parser contract at line %d: %s\n", __LINE__, #x); \
  return __LINE__; } } while (0)

int main(void)
{
  static const uint8_t good[6] = {0x14u,0x03u,0x03u,0x00u,0x01u,0x01u};
  static const uint8_t not_ccs[6] = {0x17u,0x03u,0x03u,0x00u,0x01u,0x01u};
  uint8_t copy[6];
  uint8_t zero[1024] = {0};
  unsigned int count = 0u;
  size_t i;
  CHECK(gmssl_tls13_compat_ccs_admit(not_ccs,sizeof(not_ccs),0u,0u,&count) == 0);
  CHECK(count == 0u);
  CHECK(gmssl_tls13_compat_ccs_admit(good,sizeof(good),0u,0u,&count) == 1);
  CHECK(count == 1u);
  CHECK(gmssl_tls13_compat_ccs_admit(good,sizeof(good),0u,0u,&count) == -1);
  CHECK(count == 1u);
  for (i=0u;i<sizeof(good);++i) {
    count=0u;
    memcpy(copy, good, sizeof(copy));
    copy[i] ^= 0x01u;
    CHECK(gmssl_tls13_compat_ccs_admit(copy,sizeof(copy),0u,0u,&count) == (i==0u?0:-1));
    CHECK(count==0u);
  }
  for (i=0u;i<sizeof(good);++i) {
    count=0u;
    CHECK(gmssl_tls13_compat_ccs_admit(good,i,0u,0u,&count)==-1);
    CHECK(count==0u);
  }
  count=0u;
  CHECK(gmssl_tls13_compat_ccs_admit(good,sizeof(good),1u,0u,&count)==-1);
  CHECK(gmssl_tls13_compat_ccs_admit(good,sizeof(good),0u,1u,&count)==-1);
  CHECK(gmssl_tls13_compat_ccs_admit(NULL,sizeof(good),0u,0u,&count)==-1);
  CHECK(gmssl_tls13_compat_ccs_admit(good,sizeof(good),0u,0u,NULL)==-1);
  CHECK(count==0u);
  CHECK(gmssl_tls13_hrr_padding_valid(NULL,0u)==1);
  CHECK(gmssl_tls13_hrr_padding_valid(zero,0u)==1);
  CHECK(gmssl_tls13_hrr_padding_valid(zero,sizeof(zero))==1);
  CHECK(gmssl_tls13_hrr_padding_valid(NULL,1u)==0);
  for (i=0u;i<sizeof(zero);++i) {
    zero[i]=0x80u;
    CHECK(gmssl_tls13_hrr_padding_valid(zero,sizeof(zero))==0);
    zero[i]=0u;
  }
  puts("Crypto/GmSSL port14 isolated parser candidate PASS");
  return 0;
}

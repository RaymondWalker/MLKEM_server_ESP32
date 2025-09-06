#include <stdint.h>
#include "params.h"  // for MLKEM_K
#include "api.h"     // for pqcrystals_mlkem*_ref_* prototypes

// Neutralize any command-line or header macros that rename these
#ifdef crypto_kem_keypair
#  undef crypto_kem_keypair
#endif
#ifdef crypto_kem_enc
#  undef crypto_kem_enc
#endif
#ifdef crypto_kem_dec
#  undef crypto_kem_dec
#endif

#if   MLKEM_K == 2
  #define IMPL_KEYPAIR pqcrystals_mlkem512_ref_keypair
  #define IMPL_ENC     pqcrystals_mlkem512_ref_enc
  #define IMPL_DEC     pqcrystals_mlkem512_ref_dec
#elif MLKEM_K == 3
  #define IMPL_KEYPAIR pqcrystals_mlkem768_ref_keypair
  #define IMPL_ENC     pqcrystals_mlkem768_ref_enc
  #define IMPL_DEC     pqcrystals_mlkem768_ref_dec
#elif MLKEM_K == 4
  #define IMPL_KEYPAIR pqcrystals_mlkem1024_ref_keypair
  #define IMPL_ENC     pqcrystals_mlkem1024_ref_enc
  #define IMPL_DEC     pqcrystals_mlkem1024_ref_dec
#else
  #error "Unsupported MLKEM_K"
#endif

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk)                          { return IMPL_KEYPAIR(pk, sk); }
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)           { return IMPL_ENC(ct, ss, pk); }
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)     { return IMPL_DEC(ss, ct, sk); }

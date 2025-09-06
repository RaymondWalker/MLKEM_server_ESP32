#include "mlkem_wrap.h"

// The vendor sources you copied expose these symbol names:
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int mlkem_keypair(uint8_t *pk, uint8_t *sk) { return crypto_kem_keypair(pk, sk); }
int mlkem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) { return crypto_kem_enc(ct, ss, pk); }
int mlkem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) { return crypto_kem_dec(ss, ct, sk); }

_Static_assert(MLKEM_PUB_LEN == 1184, "Expect ML-KEM-768 pubkey size");
_Static_assert(MLKEM_SEC_LEN == 2400, "Expect ML-KEM-768 seckey size");
_Static_assert(MLKEM_CT_LEN  == 1088, "Expect ML-KEM-768 ciphertext size");
_Static_assert(MLKEM_SS_LEN  ==   32, "Expect shared secret size 32");

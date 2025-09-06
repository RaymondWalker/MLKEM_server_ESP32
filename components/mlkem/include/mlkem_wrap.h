#pragma once
#include <stdint.h>
#include "params.h"  // from the vendor code you copied

// Map vendor sizes to our wrapper names
#define MLKEM_PUB_LEN (MLKEM_PUBLICKEYBYTES)
#define MLKEM_SEC_LEN (MLKEM_SECRETKEYBYTES)
#define MLKEM_CT_LEN  (MLKEM_CIPHERTEXTBYTES)
#define MLKEM_SS_LEN  (MLKEM_SSBYTES)

int mlkem_keypair(uint8_t *pk, uint8_t *sk);
int mlkem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int mlkem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

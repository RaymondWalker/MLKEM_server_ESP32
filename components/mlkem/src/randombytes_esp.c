#include <stdint.h>
#include <stddef.h>
#include "esp_random.h"   // <-- must be this header on IDF v5+

void randombytes(uint8_t *out, size_t outlen) {
  while (outlen) {
    uint32_t r = esp_random();
    size_t n = outlen < 4 ? outlen : 4;
    for (size_t i = 0; i < n; i++) out[i] = (r >> (8*i)) & 0xFF;
    out += n;
    outlen -= n;
  }
}

#pragma once

/* Force little-endian for ESP32 + satisfy common Keccak checks */
#ifndef __BYTE_ORDER__
#  define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#endif

#ifndef KeccakP1600_isLE
#  define KeccakP1600_isLE 1
#endif

#ifndef IS_LITTLE_ENDIAN
#  define IS_LITTLE_ENDIAN 1
#endif

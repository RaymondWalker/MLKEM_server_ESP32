file(GLOB_RECURSE MLKEM_SRCS "src/*.c")
idf_component_register(
 SRCS ${MLKEM_SRCS}
 INCLUDE_DIRS "include" "src"
 REQUIRES esp_system
)
# Select ML-KEM-768 (k=3)
target_compile_definitions(${COMPONENT_LIB} PRIVATE MLKEM_K=3)
# Tell Keccak we are little-endian (match what that file expects)
target_compile_definitions(${COMPONENT_LIB} PRIVATE
 KeccakP1600_isLE=1
 IS_LITTLE_ENDIAN=1234
 LITTLE_ENDIAN=1234
 BYTE_ORDER=LITTLE_ENDIAN
)
components/hybrid_kex/include/x25519mlkem768.h
# Default to ML-KEM 768 reference symbols:
target_compile_definitions(${COMPONENT_LIB} PRIVATE
)

# target_compile_definitions(${COMPONENT_LIB} PRIVATE

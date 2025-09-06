# ESP32 ML-KEM Server (SoftAP + TCP)

A minimal ESP-IDF server that performs a one-shot ML-KEM-768 key exchange over TCP
and returns the server’s shared secret. Includes a POSIX host test client.

## Features
- ESP32 SoftAP with DHCP (default SSID: `mlkem-ap`)
- Simple TCP server on port 8081
- ML-KEM-768 using embedded C implementation in `components/mlkem/`
- Host-side client in `host_test/mlkem_client.c`

## Build & Flash (ESP-IDF v5.2)
```bash
idf.py set-target esp32
idf.py build flash monitor

Host test client (Linux/macOS)

From project root:

SRCS="$(ls components/mlkem/src/*.c | grep -v -E 'randombytes_esp\\.c|mlkem_wrap\\.c|kem_shim\\.c')"
gcc -O3 -std=c11 \
  -I. -Icomponents/mlkem/include -Icomponents/mlkem/src \
  -DMLKEM_K=3 -DKeccakP1600_isLE=1 -DIS_LITTLE_ENDIAN=1234 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN \
  host_test/randombytes_posix.c host_test/mlkem_client.c $SRCS \
  -o host_test/mlkem_client
./host_test/mlkem_client 192.168.4.1 8081

Repo layout:

components/
  mlkem/                 # Embedded ML-KEM library (Apache-2.0); 
    src/
host_test/
  mlkem_client.c
  randombytes_posix.c
main/
  mlkem_server.c


Licensing

This repository: Apache-2.0 (see LICENSE).

Third-party: Apache-2.0 (see components/mlkem/ and NOTICE).
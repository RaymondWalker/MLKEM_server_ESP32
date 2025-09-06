// host_test/mlkem_client.c
// Minimal ML-KEM client for ESP32 server handshake testing.
// Adds options to intentionally cause key mismatches for negative testing.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "components/mlkem/src/kem.h"  // MLKEM_*BYTES and crypto_kem_*()

#ifndef DEFAULT_SEND_CT_LEN_HEADER
#define DEFAULT_SEND_CT_LEN_HEADER 0  
#endif

static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            return -1;
        }
        if (n == 0) {
            errno = ECONNRESET;
            perror("recv");
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static void hexdump4(const char *label, const uint8_t *b) {
    printf("%s%02x%02x%02x%02x\n", label, b[0], b[1], b[2], b[3]);
}

typedef enum { CORRUPT_NONE = 0, CORRUPT_CT, CORRUPT_PK } corrupt_t;

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
            "Usage: %s <ip> <port> [--ct-header] [--corrupt=ct|pk|none] [--flip-byte=N]\n",
            argv[0]);
        return 2;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);

    int send_ct_header = DEFAULT_SEND_CT_LEN_HEADER;
    corrupt_t corrupt = CORRUPT_NONE;
    int flip_index = 0; // which byte to flip when corrupting

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--ct-header") == 0) {
            send_ct_header = 1;
        } else if (strncmp(argv[i], "--corrupt=", 10) == 0) {
            const char *v = argv[i] + 10;
            if (strcmp(v, "ct") == 0) corrupt = CORRUPT_CT;
            else if (strcmp(v, "pk") == 0) corrupt = CORRUPT_PK;
            else if (strcmp(v, "none") == 0) corrupt = CORRUPT_NONE;
            else {
                fprintf(stderr, "Unknown --corrupt value: %s\n", v);
                return 2;
            }
        } else if (strncmp(argv[i], "--flip-byte=", 12) == 0) {
            flip_index = atoi(argv[i] + 12);
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            return 2;
        }
    }

    // --- connect ---
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        perror("inet_pton");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }
    printf("Connected to %s:%d\n", ip, port);

    // --- receive server public key: 2-byte BE length + payload ---
    uint8_t hdr[2];
    if (recv_all(sock, hdr, 2) < 0) {
        fprintf(stderr, "PK: failed to read 2-byte header\n");
        close(sock);
        return 1;
    }
    uint16_t pk_len = (uint16_t)hdr[0] << 8 | (uint16_t)hdr[1];

    if (pk_len != MLKEM_PUBLICKEYBYTES) {
        fprintf(stderr, "PK: header %u != expected %u\n", pk_len, (unsigned)MLKEM_PUBLICKEYBYTES);
        close(sock);
        return 1;
    }

    uint8_t pk[MLKEM_PUBLICKEYBYTES];
    if (recv_all(sock, pk, MLKEM_PUBLICKEYBYTES) < 0) {
        fprintf(stderr, "PK: failed to read payload\n");
        close(sock);
        return 1;
    }
    printf("PK: header %u, payload=%u\n", pk_len, (unsigned)MLKEM_PUBLICKEYBYTES);

    if (corrupt == CORRUPT_PK) {
        int idx = flip_index % MLKEM_PUBLICKEYBYTES;
        pk[idx] ^= 0x01;
        printf("Client: CORRUPTED pk at byte %d (xor 0x01)\n", idx);
    }

    // --- encapsulate ---
    uint8_t ct[MLKEM_CIPHERTEXTBYTES];
    uint8_t ss_client[MLKEM_SSBYTES];

    if (crypto_kem_enc(ct, ss_client, pk) != 0) {
        fprintf(stderr, "crypto_kem_enc failed\n");
        close(sock);
        return 1;
    }

    if (corrupt == CORRUPT_CT) {
        int idx = flip_index % MLKEM_CIPHERTEXTBYTES;
        ct[idx] ^= 0x01;
        printf("Client: CORRUPTED ct at byte %d (xor 0x01)\n", idx);
    }

    // --- send ciphertext (optionally with 2-byte big-endian header) ---
    if (send_ct_header) {
        uint8_t ct_hdr[2] = {
            (uint8_t)((MLKEM_CIPHERTEXTBYTES >> 8) & 0xFF),
            (uint8_t)(MLKEM_CIPHERTEXTBYTES & 0xFF)
        };
        printf("Client: sending CT WITH 2-byte BE length header (%u bytes)\n",
               (unsigned)MLKEM_CIPHERTEXTBYTES);
        if (send_all(sock, ct_hdr, 2) < 0 || send_all(sock, ct, MLKEM_CIPHERTEXTBYTES) < 0) {
            fprintf(stderr, "send CT (with header) failed\n");
            close(sock);
            return 1;
        }
    } else {
        printf("Client: sending CT WITHOUT length header (%u bytes)\n",
               (unsigned)MLKEM_CIPHERTEXTBYTES);
        if (send_all(sock, ct, MLKEM_CIPHERTEXTBYTES) < 0) {
            fprintf(stderr, "send CT failed\n");
            close(sock);
            return 1;
        }
    }

    // --- receive server's shared secret (32 bytes, no header) ---
    uint8_t ss_server[MLKEM_SSBYTES];
    if (recv_all(sock, ss_server, MLKEM_SSBYTES) < 0) {
        fprintf(stderr, "SS: failed to read %u bytes (server may have closed on decap error)\n",
                (unsigned)MLKEM_SSBYTES);
        close(sock);
        return 1;
    }

    // --- compare ---
    int match = memcmp(ss_client, ss_server, MLKEM_SSBYTES) == 0;
    hexdump4("client ss[0..3] = ", ss_client);
    hexdump4("server ss[0..3] = ", ss_server);

    if (match) {
        printf("shared secret MATCH ✅\n");
    } else {
        printf("shared secret MISMATCH ❌\n");
        if (corrupt == CORRUPT_NONE) {
            printf("(Note: use --corrupt=ct or --corrupt=pk to intentionally create mismatches.)\n");
        } else {
            printf("(Expected: mismatch was intentionally induced with --corrupt option.)\n");
        }
    }

    close(sock);
    return match ? 0 : 3;
}

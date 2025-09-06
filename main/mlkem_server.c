// main/mlkem_server.c

#include <string.h>
#include <errno.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "kem.h"  // MLKEM_* sizes, crypto_kem_keypair/enc/dec

// ===== App config =====
#define TAG "MLKEM-SRV"
#define TCP_PORT 8081
#define WIFI_SSID     "mlkem-ap"
#define WIFI_CHANNEL  6
#define WIFI_MAX_CONN 1

// ===== Globals: persist for lifetime =====
static uint8_t g_pk_global[MLKEM_PUBLICKEYBYTES];
static uint8_t g_sk_global[MLKEM_SECRETKEYBYTES];

// ===== Utils =====
static int recv_all(int s, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        int n = recv(s, p + got, len - got, 0);
        if (n == 0) return -1;           // peer closed
        if (n < 0) {
            if (errno == EINTR) continue;
            ESP_LOGE(TAG, "recv() failed: errno=%d", errno);
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int send_all(int s, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            ESP_LOGE(TAG, "send() failed: errno=%d", errno);
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static void dump4(const char *label, const uint8_t *b) {
    ESP_LOGI(TAG, "%s[0..3]=%02x%02x%02x%02x", label, b[0], b[1], b[2], b[3]);
}

// Accept CT either with (2-byte BE) or without a header
static int recv_ct_maybe_hdr(int s, uint8_t *ct, uint16_t expected_len) {
    uint8_t peek[2];
    int n = recv(s, peek, 2, MSG_PEEK);
    if (n == 2) {
        uint16_t be = ((uint16_t)peek[0] << 8) | peek[1];
        if (be == expected_len) {
            uint8_t hdr[2];
            if (recv_all(s, hdr, 2) != 0) return -1;
            ESP_LOGI(TAG, "CT: consumed 2-byte BE header (%u)", (unsigned)be);
        } else {
            ESP_LOGI(TAG, "CT: no header (peek=0x%02x%02x != %u)",
                     peek[0], peek[1], (unsigned)expected_len);
        }
    } else {
        ESP_LOGI(TAG, "CT: peek=%d; proceeding without header", n);
    }
    return recv_all(s, ct, expected_len);
}

// ===== Wi-Fi softAP =====
static void wifi_init_softap(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t ap = { 0 };
    snprintf((char *)ap.ap.ssid, sizeof(ap.ap.ssid), "%s", WIFI_SSID);
    ap.ap.ssid_len = strlen((const char *)ap.ap.ssid);
    ap.ap.channel = WIFI_CHANNEL;
    ap.ap.password[0] = '\0';            // open network
    ap.ap.authmode = WIFI_AUTH_OPEN;
    ap.ap.max_connection = WIFI_MAX_CONN;
    ap.ap.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "SoftAP started. SSID:%s channel:%d", WIFI_SSID, WIFI_CHANNEL);
}

// ===== TCP server =====
static void server_task(void *arg) {
    (void)arg;

    int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listen_fd < 0) {
        ESP_LOGE(TAG, "socket() failed: %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(TCP_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind() failed: %d", errno);
        goto out_close_listen;
    }
    if (listen(listen_fd, 1) < 0) {
        ESP_LOGE(TAG, "listen() failed: %d", errno);
        goto out_close_listen;
    }

    ESP_LOGI(TAG, "Listening on TCP port %d", TCP_PORT);

    while (1) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int sock = accept(listen_fd, (struct sockaddr *)&cli, &clen);
        if (sock < 0) {
            ESP_LOGE(TAG, "accept() failed: %d", errno);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        char cip[16];
        inet_ntoa_r(cli.sin_addr, cip, sizeof(cip));
        uint16_t cport = ntohs(cli.sin_port);
        ESP_LOGI(TAG, "Client %s:%u connected", cip, cport);

        // 1) Send PK with 2-byte BE header
        uint16_t pk_len = MLKEM_PUBLICKEYBYTES;               // 1184
        uint8_t  pk_hdr[2] = { (uint8_t)(pk_len >> 8), (uint8_t)(pk_len & 0xff) };
        if (send_all(sock, pk_hdr, 2) != 0 ||
            send_all(sock, g_pk_global, pk_len) != 0) {
            ESP_LOGE(TAG, "send PK failed");
            goto out_close_sock;
        }
        ESP_LOGI(TAG, "PK sent (%u bytes + 2-byte header)", (unsigned)pk_len);

        // 2) Receive CT (header optional)
        uint8_t ct[MLKEM_CIPHERTEXTBYTES];                    // 1088
        if (recv_ct_maybe_hdr(sock, ct, MLKEM_CIPHERTEXTBYTES) != 0) {
            ESP_LOGE(TAG, "recv CT failed");
            goto out_close_sock;
        }
        ESP_LOGI(TAG, "CT received (%u bytes)", (unsigned)MLKEM_CIPHERTEXTBYTES);

        // 3) Decapsulate
        uint8_t ss[MLKEM_SSBYTES];                            // 32
        if (crypto_kem_dec(ss, ct, g_sk_global) != 0) {
            ESP_LOGE(TAG, "crypto_kem_dec failed");
            goto out_close_sock;
        }
        dump4("server ss ", ss);

        // 4) Send SS (raw, no header)
        if (send_all(sock, ss, MLKEM_SSBYTES) != 0) {
            ESP_LOGE(TAG, "send SS failed");
            goto out_close_sock;
        }
        ESP_LOGI(TAG, "SS sent (%u bytes). Closing.", (unsigned)MLKEM_SSBYTES);

    out_close_sock:
        shutdown(sock, SHUT_RDWR);
        close(sock);
    }

out_close_listen:
    close(listen_fd);
    vTaskDelete(NULL);
}

void app_main(void) {
    
    esp_log_level_set(TAG, ESP_LOG_DEBUG);

    // NVS is required by Wi-Fi
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    wifi_init_softap();

    // One keypair for the server lifetime
    if (crypto_kem_keypair(g_pk_global, g_sk_global) != 0) {
        ESP_LOGE(TAG, "crypto_kem_keypair failed");
        esp_restart();
    }
    ESP_LOGI(TAG, "ML-KEM-768 keypair ready (pk=%uB, sk=%uB)",
             (unsigned)MLKEM_PUBLICKEYBYTES, (unsigned)MLKEM_SECRETKEYBYTES);

   
    const uint32_t STACK_WORDS = 6144;   // ≈ 24 KB
    xTaskCreatePinnedToCore(server_task, "kem_server", STACK_WORDS, NULL, 5, NULL, 0);

    ESP_LOGI(TAG, "Returned from app_main()");
}

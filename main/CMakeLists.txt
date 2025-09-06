idf_component_register(
    SRCS "mlkem_server.c"
    INCLUDE_DIRS "."
    REQUIRES mlkem esp_wifi nvs_flash esp_netif esp_event lwip
)
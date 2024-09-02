idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS . ../../pico-keys-sdk/src ../../pico-keys-sdk/src/fs ../../pico-keys-sdk/src/rng ../../pico-keys-sdk/src/usb  ../../pico-keys-sdk/tinycbor/src
    REQUIRES bootloader_support esp_partition esp_tinyusb zorxx__neopixel mbedtls efuse
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)

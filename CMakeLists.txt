#
# This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
# Copyright (c) 2022 Pol Henarejos.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

cmake_minimum_required(VERSION 3.13)

set(USB_VID 0x2E8A)
set(USB_PID 0x10FE)

if(ESP_PLATFORM)
    if(NOT DEFINED ENABLE_POWER_ON_RESET)
        set(ENABLE_POWER_ON_RESET 0)
    endif()
    if(NOT DEFINED ENABLE_PQC)
        set(ENABLE_PQC 0)
    endif()
    set(EXTRA_COMPONENT_DIRS
        src/fido
        pico-keys-sdk/config/esp32/components/pico-keys-sdk
        pico-keys-sdk/config/esp32/components/tinycbor
    )
    if(ENABLE_PQC)
        list(APPEND EXTRA_COMPONENT_DIRS
            pico-keys-sdk/config/esp32/components/mlkem512
            pico-keys-sdk/config/esp32/components/mlkem768
            pico-keys-sdk/config/esp32/components/mlkem1024
        )
    endif()
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
else()
    if(NOT ENABLE_EMULATION)
        set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
        include(pico_sdk_import.cmake)
    endif()

    project(pico_fido C CXX ASM)

    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)

    add_executable(pico_fido)
endif()

include(pico-keys-sdk/cmake/options.cmake)

option(ENABLE_POWER_ON_RESET "Enable/disable power cycle on reset" ON)
configure_bool_option(
    ENABLE_POWER_ON_RESET
    ENABLE_POWER_ON_RESET
    "Power cycle on reset: \t enabled"
    "Power cycle on reset: \t disabled"
)

option(ENABLE_OATH_APP "Enable/disable OATH application" ON)
configure_bool_option(
    ENABLE_OATH_APP
    ENABLE_OATH_APP
    "OATH Application: \t\t enabled"
    "OATH Application: \t\t disabled"
)

option(ENABLE_OTP_APP "Enable/disable OTP application" ON)
configure_bool_option(
    ENABLE_OTP_APP
    ENABLE_OTP_APP
    "OTP Application: \t\t enabled"
    "OTP Application: \t\t disabled"
)

if(ENABLE_OTP_APP OR ENABLE_OATH_APP)
    set(USB_ITF_CCID 1)
    set(USB_ITF_WCID 1)
else()
    set(USB_ITF_CCID 0)
endif()

set(USB_ITF_HID 1)
include(pico-keys-sdk/picokeys_sdk_import.cmake)

if(NOT ESP_PLATFORM)
    set(SOURCES ${PICOKEYS_SOURCES})
endif()

list(APPEND SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/fido.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/files.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_register.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_authenticate.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_version.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_reset.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_get_info.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_make_credential.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/known_apps.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_client_pin.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/credential.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_get_assertion.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_selection.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_cred_mgmt.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_config.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_vendor.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_large_blobs.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/management.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido/defs.c
)

if(ENABLE_OATH_APP)
    list(APPEND SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath.c
    )
endif()

if(ENABLE_OTP_APP)
    list(APPEND SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp.c
    )
endif()

SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/src/fido/version.h")
if(ESP_PLATFORM)
    project(pico_fido)
endif()

set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/src/fido
)

if(NOT ESP_PLATFORM)
    target_sources(pico_fido PUBLIC ${SOURCES})
    target_include_directories(pico_fido PUBLIC ${INCLUDES})

    set(COMMON_COMPILE_OPTIONS
        -Wall
    )
    target_compile_options(pico_fido PRIVATE ${COMMON_COMPILE_OPTIONS})

    picokeys_apply_strict_flags(
        SOURCES ${SOURCES}
        FILTER_REGEX "/src/fido/|/pico-keys-sdk/src/|/pico-keys-sdk/config/"
    )

    if(NOT MSVC)
        string(FIND ${CMAKE_C_COMPILER} ":" COMPILER_COLON)
        if(${COMPILER_COLON} GREATER_EQUAL 0)
            target_compile_options(pico_fido PRIVATE
                -Wno-error=use-after-free
            )
        endif()
    endif()

    if(ENABLE_EMULATION)
        if(NOT MSVC)
            set(EMULATION_NON_MSVC_COMPILE_OPTIONS
                -fdata-sections
                -ffunction-sections
            )
            target_compile_options(pico_fido PRIVATE ${EMULATION_NON_MSVC_COMPILE_OPTIONS})
        endif()

        if(APPLE)
            set(EMULATION_APPLE_LINK_OPTIONS
                -Wl,-dead_strip
            )
            target_link_options(pico_fido PRIVATE ${EMULATION_APPLE_LINK_OPTIONS})

            if(DEBUG_APDU)
                set(DEBUG_APDU_SANITIZER_OPTIONS
                    -fsanitize=address
                    -g
                    -O1
                    -fno-omit-frame-pointer
                )
                target_compile_options(pico_fido PRIVATE ${DEBUG_APDU_SANITIZER_OPTIONS})
                target_link_options(pico_fido PRIVATE ${DEBUG_APDU_SANITIZER_OPTIONS})
            endif()
        else()
            set(EMULATION_NON_APPLE_LINK_OPTIONS
                -Wl,--gc-sections
            )
            target_link_options(pico_fido PRIVATE ${EMULATION_NON_APPLE_LINK_OPTIONS})
        endif()

        target_link_libraries(pico_fido PRIVATE picokeys_sdk mbedtls pthread m)
    else()
        target_link_libraries(
            pico_fido
            PRIVATE
                picokeys_sdk
                pico_stdlib
                pico_multicore
                hardware_flash
                hardware_sync
                hardware_adc
                pico_unique_id
                pico_aon_timer
                tinyusb_device
                tinyusb_board
        )
        pico_add_extra_outputs(${CMAKE_PROJECT_NAME})
    endif()
endif()

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

if(ESP_PLATFORM)
set(DENABLE_POWER_ON_RESET 0)
set(EXTRA_COMPONENT_DIRS pico-keys-sdk/config/esp32/components src/fido)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
else()

if(ENABLE_EMULATION)
else()
set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
include(pico_sdk_import.cmake)
endif()

project(pico_fido C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_executable(pico_fido)
endif()

option(ENABLE_POWER_ON_RESET "Enable/disable power cycle on reset" ON)
if(ENABLE_POWER_ON_RESET)
    add_definitions(-DENABLE_POWER_ON_RESET=1)
    message(STATUS "Power cycle on reset: \t enabled")
else()
    add_definitions(-DENABLE_POWER_ON_RESET=0)
    message(STATUS "Power cycle on reset: \t disabled")
endif(ENABLE_POWER_ON_RESET)

option(ENABLE_OATH_APP "Enable/disable OATH application" ON)
if(ENABLE_OATH_APP)
    add_definitions(-DENABLE_OATH_APP=1)
    message(STATUS "OATH Application: \t\t enabled")
else()
    add_definitions(-DENABLE_OATH_APP=0)
    message(STATUS "OATH Application: \t\t disabled")
endif(ENABLE_OATH_APP)

option(ENABLE_OTP_APP "Enable/disable OTP application" ON)
if(ENABLE_OTP_APP)
    add_definitions(-DENABLE_OTP_APP=1)
    message(STATUS "OTP Application: \t\t enabled")
else()
    add_definitions(-DENABLE_OTP_APP=0)
    message(STATUS "OTP Application: \t\t disabled")
endif(ENABLE_OTP_APP)

if(ENABLE_OTP_APP OR ENABLE_OATH_APP)
    set(USB_ITF_CCID 1)
    set(USB_ITF_WCID 1)
else()
    set(USB_ITF_CCID 0)
endif()

set(USB_ITF_HID 1)
include(pico-keys-sdk/pico_keys_sdk_import.cmake)

if(NOT ESP_PLATFORM)
    set(SOURCES ${PICO_KEYS_SOURCES})
endif()

set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/fido.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/files.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/kek.c
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
if (${ENABLE_OATH_APP})
set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath.c
        )
endif()
if (${ENABLE_OTP_APP})
set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp.c
        )
endif()

SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/src/fido/version.h" 2)
if(ESP_PLATFORM)
    project(pico_fido)
endif()
set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/fido
        )
if(NOT ESP_PLATFORM)
target_sources(pico_fido PUBLIC ${SOURCES})
target_include_directories(pico_fido PUBLIC ${INCLUDES})

target_compile_options(pico_fido PUBLIC
    -Wall
    )
if (NOT MSVC)
target_compile_options(pico_fido PUBLIC
    -Werror
    )

string(FIND ${CMAKE_C_COMPILER} ":" COMPILER_COLON)
if (${COMPILER_COLON} GREATER_EQUAL 0)
        target_compile_options(pico_fido PUBLIC
        -Wno-error=use-after-free
        )
endif()
endif(NOT MSVC)

if(ENABLE_EMULATION)
    if(NOT MSVC)
    target_compile_options(pico_fido PUBLIC
            -fdata-sections
            -ffunction-sections
            )
    endif(NOT MSVC)
    if(APPLE)
    target_link_options(pico_fido PUBLIC
            -Wl,-dead_strip
            )
        if(DEBUG_APDU)
            target_compile_options(pico_fido PUBLIC
            -fsanitize=address -g -O1 -fno-omit-frame-pointer)
            target_link_options(pico_fido PUBLIC
            -fsanitize=address -g -O1 -fno-omit-frame-pointer)
        endif()
    else()
    target_link_options(pico_fido PUBLIC
            -Wl,--gc-sections
            )
    endif (APPLE)
    target_link_libraries(pico_fido PRIVATE pico_keys_sdk mbedtls pthread m)
else()
target_link_libraries(pico_fido PRIVATE pico_keys_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id pico_aon_timer tinyusb_device tinyusb_board)
pico_add_extra_outputs(${CMAKE_PROJECT_NAME})
endif()
endif()

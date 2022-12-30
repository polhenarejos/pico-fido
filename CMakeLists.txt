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

include(pico_sdk_import.cmake)

project(pico_fido C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_fido)

option(ENABLE_UP_BUTTON "Enable/disable user presence button" ON)
if(ENABLE_UP_BUTTON)
    add_definitions(-DENABLE_UP_BUTTON=1)
    message(STATUS "User presence with button: \t enabled")
else()
    add_definitions(-DENABLE_UP_BUTTON=0)
    message(STATUS "User presence with button: \t disabled")
endif(ENABLE_UP_BUTTON)

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
else()
    set(USB_ITF_CCID 0)
endif()

target_sources(pico_fido PUBLIC
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
        )
if (${ENABLE_OATH_APP})
target_sources(pico_fido PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/oath.c
        )
endif()
if (${ENABLE_OTP_APP})
target_sources(pico_fido PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/otp.c
        )
endif()

set(USB_ITF_HID 1)
include(pico-hsm-sdk/pico_hsm_sdk_import.cmake)

target_include_directories(pico_fido PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/fido
        )

target_compile_options(pico_fido PUBLIC
    -Wall
    -Werror
    )
string(FIND ${CMAKE_C_COMPILER} ":" COMPILER_COLON)
if (${COMPILER_COLON} GREATER_EQUAL 0)
        target_compile_options(pico_fido PUBLIC
        -Wno-error=use-after-free
        )
endif()

pico_add_extra_outputs(pico_fido)

target_link_libraries(pico_fido PRIVATE pico_hsm_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board)
